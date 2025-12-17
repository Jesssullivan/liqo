# Solution Options for Cilium eBPF + Liqo Compatibility

## Overview

This document evaluates three approaches to fix cross-cluster routing when Cilium eBPF host routing is enabled.

## Option 1: Enable Legacy Host Routing

### Approach

Set `bpf.hostLegacyRouting=true` in Cilium configuration to fall back to kernel routing.

### Configuration

```yaml
# Cilium ConfigMap
apiVersion: v1
kind: ConfigMap
metadata:
  name: cilium-config
  namespace: kube-system
data:
  bpf-lb-sock-hostns-only: "false"
  enable-bpf-masquerade: "true"
  routing-mode: "native"
  # Add this line:
  bpf-host-legacy-routing: "true"
```

### Pros

- Simple configuration change
- No code changes required
- Works immediately

### Cons

- **Global impact**: Disables eBPF routing for ALL traffic
- **Performance degradation**: Loses eBPF benefits cluster-wide
- **Not applicable on managed clusters**: Cannot modify DOKS Cilium config
- **Defeats purpose of eBPF**: Why use Cilium eBPF if you disable it?

### Verdict: NOT RECOMMENDED

This approach trades performance for compatibility globally. Not suitable for production.

---

## Option 2: Cilium IPCache Injection (RECOMMENDED)

### Approach

Inject Liqo's remote pod CIDRs directly into Cilium's BPF ipcache map using the Cilium API. This tells Cilium how to route traffic to remote CIDRs without disabling eBPF.

### How Cilium IPCache Works

Cilium maintains a BPF map called `ipcache` that stores:
- IP/CIDR → Security Identity mappings
- Tunnel endpoint information for remote destinations

```bash
# View current ipcache entries
cilium bpf ipcache list
```

When Cilium receives a packet for an IP in the ipcache, it knows:
1. What identity/labels the destination has
2. How to reach it (direct or via tunnel)

### Technical Implementation

```go
// In pkg/fabric/cilium/ipcache_controller.go

// UpsertRemotePodCIDR adds a remote cluster's pod CIDR to Cilium's ipcache
func (r *IPCacheReconciler) UpsertRemotePodCIDR(ctx context.Context,
    remotePodCIDR string, tunnelEndpoint string, remoteClusterID string) error {

    // Use Cilium's ipcache API to inject the CIDR
    // This tells Cilium: "Route 10.244.0.0/16 via tunnel to gateway"

    // Option A: Via Cilium Agent REST API (if accessible)
    // Option B: Via CiliumNode resource annotation
    // Option C: Via direct BPF map manipulation (requires privileges)

    return nil
}
```

### Pros

- **Targeted**: Only affects Liqo remote CIDRs
- **No performance impact**: eBPF remains active for all other traffic
- **Dynamic**: Automatically updates when peerings change
- **Native integration**: Uses Cilium's own mechanisms

### Cons

- Requires understanding Cilium internals
- May need elevated privileges for BPF map access
- Cilium API stability concerns across versions

### Verdict: RECOMMENDED

This is the surgical fix that maintains eBPF performance while enabling Liqo routing.

---

## Option 3: Cilium Cluster Mesh Integration

### Approach

Instead of fighting Cilium's routing, integrate with Cilium Cluster Mesh for multi-cluster networking.

### How It Works

Cilium Cluster Mesh provides native multi-cluster networking:
1. Clusters share a clustermesh-apiserver
2. Pod CIDRs are automatically propagated
3. Service discovery works across clusters

### Configuration

```yaml
# Enable Cluster Mesh on both clusters
cilium clustermesh enable
cilium clustermesh connect --destination-context=remote-cluster
```

### Pros

- Native Cilium solution
- Full feature support (network policies, service discovery)
- No custom code required

### Cons

- **Requires Cilium on ALL clusters**: Won't work with heterogeneous CNIs
- **Our use case**: honey uses Canal, not Cilium
- **Complete architecture change**: Replace Liqo networking with Cluster Mesh
- **Not applicable**: Defeats purpose of Liqo as CNI-agnostic solution

### Verdict: NOT APPLICABLE

Cluster Mesh requires Cilium on all clusters, which contradicts Liqo's heterogeneous CNI support.

---

## Comparison Matrix

| Criteria | Legacy Routing | IPCache Injection | Cluster Mesh |
|----------|----------------|-------------------|--------------|
| Performance Impact | HIGH | NONE | NONE |
| Implementation Effort | LOW | MEDIUM | HIGH |
| Heterogeneous CNI Support | Yes | Yes | **No** |
| Managed Cluster Compatible | **No** | Yes | Partial |
| Dynamic Updates | N/A | Yes | Yes |
| Cilium Version Coupling | Low | Medium | High |

## Recommendation

**We recommend Option 2: IPCache Injection** for the following reasons:

1. Maintains eBPF performance for non-Liqo traffic
2. Works with managed Kubernetes (DOKS) without config changes
3. Supports heterogeneous CNI environments
4. Integrates cleanly with existing Liqo fabric architecture

## References

- [Cilium IPCache Package](https://pkg.go.dev/github.com/cilium/cilium/pkg/ipcache)
- [Cilium Routing Concepts](https://docs.cilium.io/en/stable/network/concepts/routing/)
- [Cilium Cluster Mesh](https://docs.cilium.io/en/stable/network/clustermesh/)
- [Deezer: Migrating to eBPF Routing](https://deezer.io/migrating-cilium-from-legacy-iptables-routing-to-native-ebpf-routing-in-production-84a035af1cd6)
