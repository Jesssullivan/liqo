# Problem Statement: Cilium eBPF Host Routing + Liqo Fabric Incompatibility

## Issue Summary

Cross-cluster ClusterIP routing fails when the provider cluster (e.g., DOKS) uses Cilium with eBPF host routing and the consumer cluster (e.g., RKE2/Canal) hosts workloads that need to be accessed from the provider.

## Environment

| Cluster | CNI | Role | Pod CIDR | Routing Mode |
|---------|-----|------|----------|--------------|
| DOKS (blahaj) | Cilium | Provider | 10.109.0.0/16 | eBPF (BPF host routing) |
| honey-liqo | Canal (RKE2) | Consumer | 10.244.0.0/16 | Kernel (iptables) |

## Detailed Problem Analysis

### 1. Cilium eBPF Host Routing Behavior

Cilium 1.9+ introduced eBPF-based host routing that bypasses the Linux kernel's networking stack:

```
Traditional (Legacy) Routing:
  Pod → veth → kernel netfilter → routing decision → forward

eBPF Host Routing:
  Pod → veth → Cilium BPF → direct forward (bypasses kernel)
```

This provides significant performance benefits but breaks compatibility with systems that rely on kernel routing tables.

### 2. Liqo Fabric Routing Mechanism

Liqo installs policy routing rules in the Linux kernel:

```bash
# Liqo's kernel route configuration (on DOKS)
$ ip rule show
8: from all to 10.244.0.0/16 lookup 1075934518

$ ip route show table 1075934518
10.244.0.0/16 via 10.80.0.6 dev liqo.zzqp4k774g
```

These routes direct traffic destined for remote pod CIDRs through the Liqo geneve tunnel to the WireGuard gateway.

### 3. The Conflict

When Cilium eBPF processes traffic destined for `10.244.0.175` (a pod on honey):

1. Cilium eBPF intercepts the packet
2. Cilium looks up the destination in its BPF ipcache map
3. `10.244.0.175` is NOT in Cilium's ipcache (it's a remote cluster CIDR)
4. Cilium "punts" the packet (drops it or falls back to stack)
5. Even if it reaches the kernel, it may be too late in the processing

### 4. Evidence

**Fabric logs show successful Cilium detection:**
```
I1216 15:41:43.938912 Cilium detected: HostRouting=BPF, KubeProxyReplacement=true, LRPSupported=true
I1216 15:41:43.938956 Cilium eBPF host routing detected - LRP controller enabled for monitoring
I1216 15:41:43.938961 Note: CiliumLocalRedirectPolicy does not support CIDR-based routing.
```

**Test from DOKS pod to honey PostgreSQL:**
```bash
$ kubectl exec -it test-pod -- nc -zv 10.244.0.175 5432
punt!
Terminated
```

**RouteConfiguration exists but is bypassed:**
```yaml
spec:
  table:
    name: honey-liqo-node-gw
    rules:
    - dst: 10.244.0.0/16
      routes:
      - dst: 10.244.0.0/16
        gw: 10.80.0.6  # Gateway IP via geneve tunnel
```

## Impact

| Feature | Status | Notes |
|---------|--------|-------|
| WireGuard tunnel establishment | Working | Peering succeeds |
| EndpointSlice reflection | Working | Remote endpoints visible |
| Cross-cluster ClusterIP | **BROKEN** | Cilium punt behavior |
| Cross-cluster NodePort | Working | Bypasses Cilium routing |
| Pod-to-pod via pod IP | **BROKEN** | Same root cause |

## Why CiliumLocalRedirectPolicy Doesn't Solve This

Our initial approach was to use CiliumLocalRedirectPolicy (LRP) to redirect cross-cluster traffic. However:

1. **LRP only supports single IP addresses, not CIDRs**
2. We cannot create an LRP for `10.244.0.0/16`
3. LRP is designed for service mesh use cases (redirecting to sidecars)

From Cilium documentation:
> "redirectFrontend.addressMatcher.ip" must be a specific IP address

## Requirements for a Fix

1. Must work with Cilium eBPF host routing enabled (no fallback to legacy)
2. Must support CIDR-based routing for entire remote pod networks
3. Must dynamically update when peerings change
4. Should not require Cilium configuration changes on managed clusters (DOKS)
5. Should integrate cleanly with Liqo's existing fabric architecture
