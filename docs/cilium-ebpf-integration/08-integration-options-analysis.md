# Cilium eBPF + Liqo Integration: Comprehensive Options Analysis

**Date**: 2025-12-17
**Branch**: `sid/cilium-doks-rke-bridge`
**Status**: Research Complete, Recommendation Ready for CERN Discussion

## Executive Summary

After extensive research into Cilium's architecture and available integration points, we've identified **four viable approaches** to resolve the Liqo + Cilium eBPF host routing incompatibility. The recommended path is a **two-phase approach**: immediate workaround via `bpf.hostLegacyRouting=true`, followed by production-grade VTEP integration.

## Problem Statement

When Cilium operates with eBPF host routing (`routing-mode: native` + `kubeProxyReplacement: true`), it bypasses the Linux kernel's routing tables. Liqo's network fabric relies on kernel policy routes to direct cross-cluster traffic through WireGuard tunnels. This architectural mismatch causes:

- Cross-cluster ClusterIP services to timeout
- `punt!` messages when accessing remote pod CIDRs
- WireGuard tunnels appear connected but pod-to-pod traffic fails

**Reference**: [GitHub Issue #2166](https://github.com/liqotech/liqo/issues/2166) - Still OPEN

## Current Implementation Status

The `sid/cilium-doks-rke-bridge` branch contains:

| Component | Status | Notes |
|-----------|--------|-------|
| `pkg/fabric/cilium/detect.go` | Working | Detects Cilium eBPF host routing |
| `pkg/fabric/cilium/ipcache_controller.go` | Partial | Stores annotations but Cilium doesn't read them |
| RBAC for CiliumNode | Working | ClusterRole + ClusterRoleBinding |
| RBAC for cilium-config | Working | Role + RoleBinding in kube-system |
| CiliumNode annotations | Created | But don't auto-populate BPF IPCache |

### Key Discovery

CiliumNode annotations **do not** automatically populate Cilium's BPF IPCache. The IPCache is populated through:
1. Cilium agent watching pod/endpoint events
2. Cilium's kvstore/etcd sync
3. Direct BPF map manipulation (privileged)
4. VTEP configuration (via ConfigMap)

---

## Integration Options Analysis

### Option 1: Legacy Host Routing (Immediate Workaround)

**Approach**: Set `bpf.hostLegacyRouting=true` in Cilium configuration

```yaml
# Helm values
bpf:
  hostLegacyRouting: true
```

| Aspect | Details |
|--------|---------|
| Complexity | **Low** |
| Performance Impact | **Moderate** - eBPF still handles most operations, but host routing falls back to kernel |
| Compatibility | **High** - Works with all Liqo features |
| Managed K8s Support | **Varies** - DOKS allows ConfigMap edits, EKS/GKE may restrict |

**Pros**:
- Immediate fix, no code changes required
- Proven to work (per Cilium docs)
- Maintains eBPF for most operations

**Cons**:
- Some performance overhead
- Requires Cilium DaemonSet restart
- May not be configurable on all managed K8s platforms

---

### Option 2: VTEP Integration (Recommended Production Fix)

**Approach**: Configure Liqo gateway pods as VXLAN Tunnel Endpoints (VTEPs)

The [Cilium VTEP Integration](https://docs.cilium.io/en/stable/network/vtep/) allows third-party VTEP devices to send/receive traffic to Cilium-managed pods directly using VXLAN. This pre-populates the IPCache with external CIDR routes.

```yaml
# cilium-config ConfigMap
data:
  enable-vtep: "true"
  vtep-endpoint: "10.109.0.89"           # Liqo gateway pod IP
  vtep-cidr: "10.244.0.0/16"             # Remote cluster pod CIDR
  vtep-mask: "255.255.0.0"
  vtep-mac: "82:36:4c:98:2e:56"          # Gateway pod MAC
```

| Aspect | Details |
|--------|---------|
| Complexity | **Medium** |
| Performance Impact | **None** - Native eBPF path |
| Compatibility | **Good** - Beta but stable |
| Requirements | Linux 5.2+, Cilium 1.12+, VNI=2 |

**Implementation Plan**:

```go
// pkg/fabric/cilium/vtep_controller.go
type VTEPReconciler struct {
    client.Client
    // Watch Configuration resources
    // Update cilium-config ConfigMap with VTEP entries
    // Trigger Cilium agent reload when entries change
}
```

**Pros**:
- Uses Cilium's native external CIDR support
- Pre-populates IPCache correctly
- No privileged container required
- Works with managed K8s

**Cons**:
- Beta status
- Requires Cilium restart on VTEP config changes
- MAC address discovery needed
- Doesn't work with IPsec encryption

---

### Option 3: CiliumExternalWorkload CRD

**Approach**: Register Liqo gateway pods as external workloads via CiliumExternalWorkload CRD

```yaml
apiVersion: cilium.io/v2
kind: CiliumExternalWorkload
metadata:
  name: liqo-gateway-honey
spec:
  ipv4-alloc-cidr: 10.244.0.0/16
```

| Aspect | Details |
|--------|---------|
| Complexity | **Medium** |
| Compatibility | **Limited** |
| Requirements | `routingMode=tunnel`, clustermesh-apiserver |

**Limitations** (from [Cilium docs](https://docs.cilium.io/en/v1.12/gettingstarted/external-workloads/)):
- Requires `routingMode=tunnel` (not compatible with native routing)
- "This feature does not work with WireGuard encryption"
- External workloads cannot be behind NAT
- Requires clustermesh-apiserver deployment

**Verdict**: Not suitable for Liqo due to NAT and WireGuard incompatibilities.

---

### Option 4: Direct IPCache BPF Map Manipulation

**Approach**: Use Cilium's privileged Unix socket or BPF syscalls to directly update IPCache

The [Cilium pkg/ipcache](https://pkg.go.dev/github.com/cilium/cilium/pkg/ipcache) package provides:

```go
// Upsert adds/updates IP->Identity mapping
func (ipc *IPCache) Upsert(ip string, hostIP net.IP, hostKey uint8, newIdentity Identity) bool

// UpsertMetadata is the recommended async API
func (ipc *IPCache) UpsertMetadata(prefix netip.Prefix, source source.Source, ...)
```

| Aspect | Details |
|--------|---------|
| Complexity | **High** |
| Performance Impact | **None** - Direct BPF access |
| Compatibility | **Excellent** |
| Requirements | CAP_BPF or privileged container |

**Implementation Approaches**:

1. **Cilium Agent Socket**: Connect to `/var/run/cilium/cilium.sock` and use gRPC API
2. **BPF Map Direct Access**: Use `cilium/ebpf` library to write to `cilium_ipcache` map
3. **Sidecar Pattern**: Deploy privileged sidecar alongside fabric controller

**Pros**:
- Most direct and flexible
- Real-time updates without restarts
- Full control over IPCache entries

**Cons**:
- Requires privileged access
- Tight coupling to Cilium internals
- API stability concerns across Cilium versions

---

### Option 5: Cilium BGP Control Plane

**Approach**: Use Cilium's BGP support to advertise Liqo remote CIDRs

```yaml
apiVersion: cilium.io/v2alpha1
kind: CiliumBGPPeeringPolicy
metadata:
  name: liqo-remote-cidrs
spec:
  virtualRouters:
  - localASN: 65000
    neighbors:
    - peerASN: 65001
      peerAddress: 10.109.0.89
```

| Aspect | Details |
|--------|---------|
| Complexity | **High** |
| Scalability | **Excellent** |
| Requirements | BGP infrastructure, Cilium 1.12+ |

**Verdict**: Overkill for most deployments, but excellent for large-scale multi-cluster.

---

## Recommendation Matrix

| Scenario | Recommended Option |
|----------|-------------------|
| **Immediate fix needed** | Option 1: `bpf.hostLegacyRouting=true` |
| **Production deployment** | Option 2: VTEP Integration |
| **Large-scale/enterprise** | Option 5: BGP Control Plane |
| **Maximum control needed** | Option 4: Direct IPCache |
| **Avoid** | Option 3: CiliumExternalWorkload |

---

## Recommended Implementation Path

### Phase 1: Immediate (This Branch)

1. **Document workaround** in Liqo installation guide:
   ```yaml
   # values.yaml for Cilium
   bpf:
     hostLegacyRouting: true
   ```

2. **Enhance detection** in `detect.go` to warn users:
   ```go
   if ciliumConfig.IsBPFHostRouting() && !ciliumConfig.IsLegacyHostRouting() {
       klog.Warning("Cilium eBPF host routing detected without legacy fallback. " +
           "Cross-cluster routing may fail. Set bpf.hostLegacyRouting=true")
   }
   ```

### Phase 2: Production (VTEP Integration)

1. **New controller**: `pkg/fabric/cilium/vtep_controller.go`
2. **Watch**: Configuration resources for remote pod CIDRs
3. **Discover**: Gateway pod MAC addresses
4. **Update**: `cilium-config` ConfigMap with VTEP entries
5. **Trigger**: Graceful Cilium agent reload

### Phase 3: Future (Direct IPCache - Optional)

For environments requiring zero-restart updates, implement direct IPCache injection via Cilium socket API.

---

## Files to Modify/Create

| File | Action | Purpose |
|------|--------|---------|
| `pkg/fabric/cilium/vtep_controller.go` | Create | VTEP configuration management |
| `pkg/fabric/cilium/detect.go` | Modify | Add legacy routing detection |
| `pkg/fabric/cilium/ipcache_controller.go` | Deprecate | Replace with VTEP approach |
| `docs/installation/cilium.md` | Create | Cilium-specific installation guide |

---

## Testing Strategy

1. **Unit Tests**: Mock Cilium ConfigMap updates
2. **Integration Tests**: Verify VTEP config propagation
3. **E2E Tests**: Cross-cluster ClusterIP connectivity
4. **Manual Verification**:
   ```bash
   # Check VTEP config applied
   kubectl get cm cilium-config -n kube-system -o yaml | grep vtep

   # Verify IPCache entries
   kubectl exec -n kube-system ds/cilium -- cilium bpf ipcache list | grep 10.244
   ```

---

## References

- [Cilium Routing Documentation](https://docs.cilium.io/en/stable/network/concepts/routing/)
- [Cilium VTEP Integration](https://docs.cilium.io/en/stable/network/vtep/)
- [Cilium IPCache Package](https://pkg.go.dev/github.com/cilium/cilium/pkg/ipcache)
- [Cilium External Workloads](https://docs.cilium.io/en/v1.12/gettingstarted/external-workloads/)
- [Liqo GitHub Issue #2166](https://github.com/liqotech/liqo/issues/2166)
- [Cilium BPF IPCache Commands](https://docs.cilium.io/en/stable/cmdref/cilium-dbg_bpf_ipcache/)
