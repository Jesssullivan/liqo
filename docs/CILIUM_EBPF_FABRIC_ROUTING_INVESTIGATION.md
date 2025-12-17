# Cilium eBPF + Liqo Fabric Routing Investigation

## Issue Summary

Cross-cluster ClusterIP routing fails on DOKS (Cilium eBPF host routing) when trying to reach pods on honey (RKE2/Canal).

**Symptom**: Cilium returns `punt!` and drops packets destined for remote pod CIDRs.

## Environment

| Cluster | CNI | Role | Pod CIDR |
|---------|-----|------|----------|
| DOKS (blahaj) | Cilium (eBPF host routing) | Provider | 10.109.0.0/16 |
| honey-liqo | Canal (RKE2) | Consumer | 10.244.0.0/16 |

## Root Cause Analysis

### The Problem

Cilium with `bpf.hostLegacyRouting=false` (eBPF host routing) bypasses the kernel's routing tables for local pod traffic. Liqo's fabric installs policy routing rules in the kernel, but Cilium's eBPF datapath intercepts packets before they reach the kernel stack.

### Traffic Flow (Expected)

```
DOKS pod → ClusterIP → kube-proxy (DNAT to 10.244.0.175) →
kernel routing → policy route table → Liqo fabric geneve → WireGuard → honey
```

### Traffic Flow (Actual with Cilium eBPF)

```
DOKS pod → ClusterIP → Cilium eBPF (DNAT to 10.244.0.175) →
Cilium eBPF tries to route → NO route for 10.244.0.0/16 → punt!
```

Cilium sees the destination `10.244.0.175` is not in any local CIDR it knows about and "punts" (drops) the packet.

### Why CiliumLocalRedirectPolicy Doesn't Help

Our `sid/cilium-doks-rke-bridge` branch adds CiliumLocalRedirectPolicy (LRP) support, but:

1. **LRP only supports single IPs, not CIDRs** - We cannot create an LRP for `10.244.0.0/16`
2. **LRP is for redirecting traffic to local endpoints** - Not for cross-cluster routing

From fabric logs:
```
Cilium detected: HostRouting=BPF, KubeProxyReplacement=true, LRPSupported=true
Note: CiliumLocalRedirectPolicy does not support CIDR-based routing. Liqo connectivity relies on WireGuard tunnel encapsulation.
```

## Evidence

### RouteConfiguration on DOKS (honey-liqo-node-gw)

```yaml
spec:
  table:
    name: honey-liqo-node-gw
    rules:
    - dst: 10.80.0.6/32
      routes:
      - dev: liqo.zzqp4k774g
        dst: 10.80.0.6/32
        scope: link
    - dst: 10.244.0.0/16
      routes:
      - dst: 10.244.0.0/16
        gw: 10.80.0.6      # Gateway IP via geneve
```

These kernel routes exist but Cilium eBPF bypasses them.

### Test Results

```bash
# From DOKS pod trying to reach honey PostgreSQL
$ nc -zv 10.244.0.175 5432
punt!
Terminated
```

## Potential Solutions

### Option 1: Force Kernel Routing for Remote CIDRs (Recommended)

Cilium supports `bpf.hostLegacyRouting=true` to fall back to kernel routing. We could:

1. Configure Cilium to use legacy routing for specific CIDRs
2. Or use `--direct-routing-device` to specify a device that should use kernel routing

**Pros**: Works with existing Liqo fabric
**Cons**: May impact Cilium performance

### Option 2: Cilium Node-to-Node Encryption Integration

Configure Cilium to recognize Liqo gateway IPs as valid next-hops:

1. Add static routes to Cilium's eBPF map for remote pod CIDRs
2. Point them to Liqo's geneve interface

**Pros**: Native eBPF performance
**Cons**: Requires Cilium API integration in Liqo fabric

### Option 3: Use Cilium's Native Cluster Mesh (Alternative Architecture)

If both clusters ran Cilium, we could use Cilium Cluster Mesh instead of Liqo networking.

**Pros**: Native multi-cluster support
**Cons**: Doesn't work with heterogeneous CNIs (our use case)

### Option 4: Fabric-Level Cilium Integration (Our Branch Scope)

Extend our `sid/cilium-doks-rke-bridge` work to:

1. Detect when Cilium eBPF host routing is enabled
2. Install routes directly into Cilium's BPF maps via the Cilium API
3. Or configure Cilium to exclude Liqo CIDRs from eBPF processing

## Recommended Next Steps

1. **Investigate Cilium's `bpf.hostLegacyRouting` configuration**
   - Test if enabling legacy routing for specific CIDRs resolves the issue
   - Document performance impact

2. **Explore Cilium API for route injection**
   - Review `cilium bpf ipcache` for adding remote pod CIDRs
   - Check if we can mark Liqo gateway as valid tunnel endpoint

3. **Add E2E test for cross-cluster ClusterIP**
   - Test matrix: Cilium (eBPF) ↔ Canal, Cilium ↔ Cilium, Canal ↔ Canal
   - Validate fabric routing after peering

4. **Document as part of MR**
   - This issue is in scope for the eBPF Cilium expansion work
   - NodePort workaround is temporary, not intended spec

## Temporary Workaround

Use NodePort services for cross-cluster access until fabric routing is fixed:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: postgresql-external
spec:
  type: NodePort
  ports:
  - port: 5432
    nodePort: 30432
```

Access via Tailscale: `nc -zv 100.77.196.50 30432`

## References

- Cilium eBPF Host Routing: https://docs.cilium.io/en/stable/network/concepts/routing/
- Liqo Network Fabric: https://docs.liqo.io/en/stable/advanced/network-fabric.html
- Branch: `sid/cilium-doks-rke-bridge` in `gitlab.com/tinyland/liqo`

## Date

2025-12-16
