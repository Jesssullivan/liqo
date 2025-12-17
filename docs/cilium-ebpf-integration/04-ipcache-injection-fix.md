# IPCache Injection Fix: Detailed Design

## Overview

This document describes the implementation of Cilium IPCache injection for Liqo cross-cluster routing.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│  DOKS Cluster (Cilium eBPF)                                             │
│                                                                         │
│  ┌─────────────┐     ┌──────────────┐     ┌─────────────────────────┐  │
│  │ Liqo Fabric │────▶│ IPCache      │────▶│ Cilium BPF ipcache map  │  │
│  │ Controller  │     │ Reconciler   │     │                         │  │
│  └─────────────┘     └──────────────┘     │ 10.244.0.0/16 →         │  │
│         │                                  │   tunnel: gateway-pod   │  │
│         │                                  └─────────────────────────┘  │
│         │                                            │                  │
│         ▼                                            ▼                  │
│  ┌─────────────────┐                    ┌─────────────────────────────┐│
│  │ Configuration   │                    │ Traffic to 10.244.0.175     ││
│  │ (remote CIDRs)  │                    │ routed via Cilium eBPF to   ││
│  └─────────────────┘                    │ Liqo gateway pod            ││
│                                         └─────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ WireGuard Tunnel
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  honey-liqo Cluster (Canal)                                             │
│                                                                         │
│  ┌─────────────────────────────────────┐                               │
│  │ PostgreSQL Pod: 10.244.0.175        │                               │
│  └─────────────────────────────────────┘                               │
└─────────────────────────────────────────────────────────────────────────┘
```

## Implementation Approaches

### Approach A: CiliumNode Annotation (Recommended)

Cilium watches CiliumNode resources and can process custom CIDR allocations.

```go
// pkg/fabric/cilium/ipcache_controller.go

package cilium

import (
    "context"
    "fmt"

    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
    "k8s.io/apimachinery/pkg/runtime/schema"
    "k8s.io/client-go/dynamic"
    "k8s.io/klog/v2"
    ctrl "sigs.k8s.io/controller-runtime"
    "sigs.k8s.io/controller-runtime/pkg/client"

    networkingv1beta1 "github.com/liqotech/liqo/apis/networking/v1beta1"
)

// CiliumNodeGVR is the GVR for CiliumNode resources
var CiliumNodeGVR = schema.GroupVersionResource{
    Group:    "cilium.io",
    Version:  "v2",
    Resource: "ciliumnodes",
}

// IPCacheReconciler manages Cilium ipcache entries for Liqo remote CIDRs
type IPCacheReconciler struct {
    client.Client
    DynamicClient  dynamic.Interface
    CiliumConfig   *CiliumConfig
    LocalNodeName  string
}

// Reconcile handles Configuration changes and updates Cilium ipcache
func (r *IPCacheReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
    klog.V(4).Infof("Reconciling Configuration %s for IPCache", req.NamespacedName)

    // Get Configuration
    cfg := &networkingv1beta1.Configuration{}
    if err := r.Get(ctx, req.NamespacedName, cfg); err != nil {
        return ctrl.Result{}, client.IgnoreNotFound(err)
    }

    // Extract remote pod CIDR
    remotePodCIDR := r.getRemotePodCIDR(cfg)
    if remotePodCIDR == "" {
        return ctrl.Result{}, nil
    }

    // Get gateway pod IP (tunnel endpoint)
    gatewayIP, err := r.getGatewayPodIP(ctx, cfg)
    if err != nil {
        klog.Warningf("Gateway IP not available: %v", err)
        return ctrl.Result{Requeue: true}, nil
    }

    // Inject into Cilium ipcache via CiliumNode annotation
    if err := r.injectIPCacheEntry(ctx, remotePodCIDR, gatewayIP); err != nil {
        return ctrl.Result{}, fmt.Errorf("failed to inject ipcache entry: %w", err)
    }

    klog.Infof("Injected ipcache entry: %s via %s", remotePodCIDR, gatewayIP)
    return ctrl.Result{}, nil
}

// injectIPCacheEntry adds a remote CIDR to Cilium's routing
func (r *IPCacheReconciler) injectIPCacheEntry(ctx context.Context, cidr, tunnelEndpoint string) error {
    // Get the local CiliumNode
    ciliumNode, err := r.DynamicClient.Resource(CiliumNodeGVR).Get(ctx, r.LocalNodeName, metav1.GetOptions{})
    if err != nil {
        return fmt.Errorf("failed to get CiliumNode %s: %w", r.LocalNodeName, err)
    }

    // Add annotation for Liqo remote CIDR
    // Cilium's node manager processes these during ipcache sync
    annotations := ciliumNode.GetAnnotations()
    if annotations == nil {
        annotations = make(map[string]string)
    }

    // Format: liqo.io/remote-cidr-<hash> = {"cidr": "x.x.x.x/y", "tunnelEndpoint": "z.z.z.z"}
    annotationKey := fmt.Sprintf("liqo.io/remote-cidr-%s", hashCIDR(cidr))
    annotationValue := fmt.Sprintf(`{"cidr":"%s","tunnelEndpoint":"%s"}`, cidr, tunnelEndpoint)

    annotations[annotationKey] = annotationValue
    ciliumNode.SetAnnotations(annotations)

    _, err = r.DynamicClient.Resource(CiliumNodeGVR).Update(ctx, ciliumNode, metav1.UpdateOptions{})
    return err
}
```

### Approach B: Cilium Agent Socket API

Connect to Cilium agent's Unix socket to inject ipcache entries directly.

```go
// pkg/fabric/cilium/agent_client.go

package cilium

import (
    "context"
    "fmt"
    "net"
    "net/http"

    ciliumClient "github.com/cilium/cilium/pkg/client"
)

const (
    CiliumSocketPath = "/var/run/cilium/cilium.sock"
)

// AgentClient wraps Cilium agent API
type AgentClient struct {
    client *ciliumClient.Client
}

// NewAgentClient creates a client connected to local Cilium agent
func NewAgentClient() (*AgentClient, error) {
    httpClient := &http.Client{
        Transport: &http.Transport{
            DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
                return net.Dial("unix", CiliumSocketPath)
            },
        },
    }

    client, err := ciliumClient.NewClient("")
    if err != nil {
        return nil, fmt.Errorf("failed to create Cilium client: %w", err)
    }

    return &AgentClient{client: client}, nil
}

// UpsertIPCacheEntry adds a CIDR to ipcache with tunnel info
func (c *AgentClient) UpsertIPCacheEntry(cidr string, identity uint32, tunnelEndpoint string) error {
    // Use Cilium's ipcache API
    // This requires the fabric pod to have access to /var/run/cilium/cilium.sock

    // API call to PUT /ipcache/{cidr}
    // with body: {"identity": identity, "host-ip": tunnelEndpoint}

    return nil
}
```

### Approach C: BPF Map Direct Manipulation

Directly write to Cilium's BPF ipcache map using ebpf library.

```go
// pkg/fabric/cilium/bpf_ipcache.go

package cilium

import (
    "fmt"
    "net"

    "github.com/cilium/ebpf"
)

const (
    IPCacheMapPath = "/sys/fs/bpf/tc/globals/cilium_ipcache"
)

// BPFIPCache provides direct access to Cilium's ipcache BPF map
type BPFIPCache struct {
    ipcacheMap *ebpf.Map
}

// NewBPFIPCache opens the Cilium ipcache BPF map
func NewBPFIPCache() (*BPFIPCache, error) {
    m, err := ebpf.LoadPinnedMap(IPCacheMapPath, nil)
    if err != nil {
        return nil, fmt.Errorf("failed to load ipcache map: %w", err)
    }

    return &BPFIPCache{ipcacheMap: m}, nil
}

// UpsertCIDR adds a CIDR entry to ipcache
// Note: This requires CAP_BPF and CAP_NET_ADMIN
func (b *BPFIPCache) UpsertCIDR(cidr string, identity uint32, tunnelIP net.IP) error {
    _, ipnet, err := net.ParseCIDR(cidr)
    if err != nil {
        return err
    }

    // Build key: struct ipcache_key { __be32 lpm_key; __u32 pad; union v6addr ip6; }
    // Build value: struct remote_endpoint_info { __u32 sec_identity; ... }

    // This is complex and version-dependent - prefer Approach A or B
    return nil
}
```

## Recommended Implementation: Approach A + B Hybrid

1. **Primary**: Use CiliumNode annotations for CIDR routing hints
2. **Fallback**: Use Cilium agent socket API for direct injection
3. **Verification**: Query ipcache to confirm entries are present

## Controller Flow

```
1. Watch Configuration resources
2. On Configuration create/update:
   a. Extract remote pod CIDR from status
   b. Get gateway pod IP
   c. Inject ipcache entry
3. On Configuration delete:
   a. Remove ipcache entry
4. Periodic reconciliation:
   a. Verify ipcache entries match expected state
```

## Security Considerations

| Approach | Required Privileges | Notes |
|----------|-------------------|-------|
| CiliumNode Annotation | RBAC: get/update CiliumNode | Least privilege |
| Agent Socket | HostPath: /var/run/cilium | Requires socket access |
| BPF Map | CAP_BPF, CAP_NET_ADMIN | Most privileged |

## Testing Strategy

1. **Unit Tests**: Mock Cilium API responses
2. **Integration Tests**: Deploy on Cilium cluster, verify ipcache entries
3. **E2E Tests**: Full cross-cluster connectivity with Cilium eBPF

```go
// test/e2e/cilium_ipcache_test.go

func TestIPCacheInjection(t *testing.T) {
    // 1. Create Configuration with remote CIDR
    // 2. Wait for ipcache entry
    // 3. Verify with: cilium bpf ipcache list | grep <CIDR>
    // 4. Test cross-cluster connectivity
}
```
