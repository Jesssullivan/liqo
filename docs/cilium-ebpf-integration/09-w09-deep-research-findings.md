# Cilium BPF + Liqo Fabric Routing: Deep Research Findings (W09)

**Date**: 2026-02-25
**Branch**: `sid/cilium-doks-rke-bridge`
**Sprint**: W09-W14 Liqo Mail Fabric
**Status**: Research complete, Phase 1 ready for deployment

---

## 1. Executive Summary

The Cilium BPF host routing incompatibility with Liqo multi-cluster networking is a **fundamental architectural conflict**: Cilium's eBPF datapath bypasses kernel routing tables, while Liqo's fabric relies entirely on kernel ip-rules and custom routing tables for cross-cluster traffic.

This fork has explored three integration approaches (LRP, VTEP, IPCache injection), and **none of them are functional** in their current state. This document explains why each approach fails and proposes a phased solution path.

### Key Findings

- **Zero Cilium-related commits exist in upstream Liqo** (verified across all upstream branches)
- Upstream issue `liqotech/liqo#2166` remains **OPEN** since December 2023
- `hostNetwork` pods bypass Cilium eBPF entirely, which is why postfix-0 on honey can reach Civo services
- The `sid/cilium-doks-rke-bridge` branch is the most evolved and should be the base for all future work

---

## 2. The Problem in Detail

### Traffic Flow Without Cilium (Working -- honey RKE2/Canal)

```
Pod on honey -> ClusterIP -> kube-proxy (iptables DNAT to remote IP) ->
  kernel routing table -> Liqo policy route (ip rule) ->
  custom routing table -> geneve interface -> gateway pod ->
  WireGuard encapsulation -> Civo
```

### Traffic Flow With Cilium eBPF (Broken -- Civo K3s/Cilium)

```
Pod on Civo -> ClusterIP -> Cilium eBPF (DNAT to remote IP, e.g. 10.244.0.175) ->
  Cilium eBPF tries to route -> NO BPF map entry for 10.244.0.0/16 ->
  PUNT (drop)
```

The critical insight: Cilium's eBPF handles the DNAT correctly, but when it tries to forward the DNATted packet to `10.244.0.175`, it has no entry in its BPF routing maps for the remote CIDR and drops the packet.

### Why hostNetwork Pods Work

hostNetwork pods bypass Cilium's per-endpoint BPF programs (`bpf_lxc`) entirely. Traffic from hostNetwork pods enters the kernel networking stack directly and hits Liqo's policy routes. This is why postfix-0 (hostNetwork) on honey can reach Civo's postgresql-primary service.

---

## 3. Branch Analysis

### Branch: `sid/cilium-doks-rke-bridge` (RECOMMENDED BASE)

Most evolved branch with critical fixes:

| Commit | Change | Significance |
|--------|--------|-------------|
| `a0b4da14` | Fix IPCache label selector, cleanup dead LRP code | Removes non-functional LRP forge code |
| `6c8b2464` | Remove incorrect RemoteClusterID label from gateway lookup | Gateway pods only have component label |
| `10e30e68` | Use single mask value for Cilium VTEP config | Cilium expects one mask for all entries |
| `cd343cf3` | Wire up VTEP controller | Core VTEP integration |
| `9f411969` | Fix build errors and test setup | Tests compile and pass |

### Other Branches (Superseded)

- `feat/cilium-ebpf-host-routing` -- Oldest, 30+ upstream commits mixed in
- `feat/cilium-ebpf-host-routing-clean` -- Single squashed commit (`099a59fe`)
- `test/combined-cilium-rke2` -- Combined test branch (Cilium + RKE2)

---

## 4. Analysis of Each Integration Approach

### 4.1 CiliumLocalRedirectPolicy (LRP) -- ABANDONED

**File**: `pkg/fabric/cilium/lrp_controller.go`

The `Reconcile()` method now logs and returns without creating resources:

```go
klog.V(2).Infof("Cilium LRP limitation: CiliumLocalRedirectPolicy does not support CIDR-based routing ...")
return ctrl.Result{}, nil
```

**Why it fails**: LRP's `addressMatcher.ip` only accepts individual IPs, not CIDR ranges. The fork attempted to pass `10.244.0.0/16` as the IP match, which Cilium rejects. LRP is designed for local traffic redirection (e.g., node-local DNS caching), not cross-cluster routing.

**Verdict**: Dead end. Code deleted on `sid/cilium-doks-rke-bridge`.

### 4.2 VTEP (VXLAN Tunnel Endpoint) -- FUNDAMENTALLY MISMATCHED

**File**: `pkg/fabric/cilium/vtep_controller.go`

The VTEPReconciler writes to the `cilium-config` ConfigMap:

```
enable-vtep: "true"
vtep-endpoint: "<gateway-pod-IP>"
vtep-cidr: "<remote-pod-CIDR>"
vtep-mask: "<single-netmask>"
vtep-mac: "<deterministic-MAC-from-gateway-IP>"
```

**Why it cannot work as-is:**

1. **VTEP is VXLAN-only**: Cilium's BPF code in `bpf_host.c` performs VXLAN encapsulation (port 8472, VNI=2). Liqo uses **Geneve** tunnels (different protocol, different port). Cilium will VXLAN-encapsulate the packet, which the Liqo gateway does not understand.

2. **No VXLAN device created**: VTEP requires a VXLAN device on the remote endpoint with the matching MAC. The code generates a deterministic MAC (`82:36:xx:xx:xx:xx`) but never creates the corresponding VXLAN interface.

3. **ConfigMap changes require Cilium restart**: VTEP configuration is read at agent startup. The `vtep_mask` is compiled into the BPF program as a constant. Live-reload is not possible.

4. **Single mask limitation**: All VTEP entries must share the same netmask (fixed in `10e30e68`). Acceptable for `/16` pod CIDRs but limits flexibility.

**Verdict**: Correct idea (populate BPF maps with remote CIDRs) but wrong implementation. Would require a VXLAN-to-Geneve bridge adapter.

### 4.3 IPCache CiliumNode Annotation Injection -- WRONG MECHANISM

**File**: `pkg/fabric/cilium/ipcache_controller.go`

Annotates CiliumNode resources with JSON entries like:

```json
{
  "cidr": "10.244.0.0/16",
  "tunnelEndpoint": "10.109.0.42",
  "remoteClusterID": "honey-liqo",
  "identity": 2
}
```

**Why it does not work**: CiliumNode annotations are **metadata**, not data-plane configuration. Cilium reads specific fields from CiliumNode (`.spec.addresses`, `.spec.health`, `.spec.encryption`) but does NOT read arbitrary annotations into the BPF ipcache map. The BPF `cilium_ipcache` map is populated by the Cilium agent from endpoint discovery, CIDR allocations, and VTEP configuration -- not from annotations.

**Verdict**: Fundamental misunderstanding of Cilium's ipcache population mechanism. Annotations have zero effect on the BPF datapath.

---

## 5. Cilium VTEP Internals (Upstream Source Analysis)

### BPF Code Path (`bpf/bpf_host.c`)

In the `handle_ipv4_cont()` function:

```c
#ifdef ENABLE_VTEP
    struct vtep_key vkey = {};
    struct vtep_value *vtep;

    vkey.vtep_ip = ip4->daddr & CONFIG(vtep_mask);
    vtep = map_lookup_elem(&cilium_vtep_map, &vkey);
    if (!vtep)
        goto skip_vtep;

    if (vtep->vtep_mac && vtep->tunnel_endpoint) {
        eth_store_daddr(ctx, (__u8 *)&vtep->vtep_mac, 0);
        fake_info.tunnel_endpoint.ip4 = vtep->tunnel_endpoint;
        fake_info.flag_has_tunnel_ep = true;
        return __encap_and_redirect_with_nodeid(ctx, &fake_info,
                    secctx, WORLD_IPV4_ID, WORLD_IPV4_ID, ...);
    }
skip_vtep:
#endif
```

### Key Observations

1. Destination IP is masked with a single `vtep_mask` to produce the map key
2. Lookup is in `cilium_vtep_map`, a dedicated BPF map (not ipcache)
3. On match, inner packet's destination MAC is rewritten to `vtep_mac`
4. Packet is VXLAN-encapsulated with VNI=2 (world identity) via `__encap_and_redirect_with_nodeid()`
5. The mask is a compile-time constant -- changes require agent restart

### VTEP Map Population

`cilium_vtep_map` is populated by the Cilium agent at startup from ConfigMap:
- `vtep-endpoint` -> `tunnel_endpoint` field
- `vtep-cidr` -> map key (after masking)
- `vtep-mac` -> `vtep_mac` field
- `vtep-mask` -> `CONFIG(vtep_mask)` compiled into BPF

### Relevant Upstream Issues

| Issue/PR | Title | Status | Relevance |
|----------|-------|--------|-----------|
| [#17370](https://github.com/cilium/cilium/pull/17370) | VTEP integration | Merged | Original VTEP implementation |
| [#18730](https://github.com/cilium/cilium/issues/18730) | Dedicated VTEP map | Open | Discusses VTEP architecture |
| [#19339](https://github.com/cilium/cilium/issues/19339) | VTEP improvements | Open | Multi-mask support discussion |
| [liqo#2166](https://github.com/liqotech/liqo/issues/2166) | Cilium eBPF incompatibility | Open | Original Liqo issue |

---

## 6. Solution Architecture

### Phase 1: `bpf.hostLegacyRouting=true` (Immediate Unblock)

**Effort**: Configuration change only
**Risk**: Very low
**Trade-off**: eBPF performance loss for host-level routing (pod-to-pod on same node still uses eBPF)

```yaml
# Cilium ConfigMap
bpf-host-legacy-routing: "true"
```

Or via Helm:

```yaml
bpf:
  hostLegacyRouting: true
```

**Why this works**: With legacy routing enabled, Cilium passes host-level traffic to the kernel stack instead of dropping it. Liqo's policy routes are then consulted for cross-cluster routing.

**Implementation**:
```bash
KUBECONFIG=$CIVO kubectl -n kube-system edit configmap cilium-config
# Add: bpf-host-legacy-routing: "true"
KUBECONFIG=$CIVO kubectl -n kube-system rollout restart daemonset cilium
```

**Performance impact**: Minimal for a mail stack. eBPF still handles intra-node pod-to-pod and kube-proxy replacement. Only cross-node traffic falls back to kernel routing.

### Phase 2: VTEP with VXLAN-Geneve Bridge (Medium-term)

**Effort**: 1-2 weeks development
**Risk**: Medium
**Approach**: Create VXLAN devices that bridge to Liqo's Geneve tunnels

Steps:
1. Detect Cilium eBPF host routing (existing code works)
2. For each remote cluster, create a VXLAN device with the MAC from VTEP config
3. Set up routing: VXLAN device -> kernel -> Liqo geneve interface
4. Configure VTEP in Cilium ConfigMap
5. Trigger Cilium agent restart

**Open questions**:
- Does double encapsulation (VXLAN + Geneve + WireGuard) cause MTU issues?
- Can we avoid restart by using the Cilium agent API?

### Phase 3: Cilium Agent API Integration (Long-term)

**Effort**: 3-4 weeks development
**Risk**: High (internal API may change)
**Approach**: Inject routes into BPF ipcache via Cilium's Unix socket API

The Cilium agent exposes `/var/run/cilium/cilium.sock` with endpoints:
- `PUT /ipcache` -- Upsert ipcache entries
- `DELETE /ipcache` -- Remove entries

**Advantages**: Native eBPF performance, no restart, live updates
**Challenges**: Agent may overwrite entries during reconciliation, API stability, socket access required

### Alternative: `--devices` Flag

Add Liqo geneve interface to Cilium's `--devices` list. Worth testing but unlikely to solve the core issue -- the problem is routing decisions in eBPF, not interface visibility.

---

## 7. Risk Assessment

| Approach | Effort | Risk | Perf Impact | Maintenance | Recommended |
|----------|--------|------|-------------|-------------|-------------|
| Phase 1: `hostLegacyRouting` | None | Very Low | Moderate | None | **YES -- do now** |
| Phase 2: VTEP+VXLAN bridge | Medium | Medium | Low | Medium | Evaluate later |
| Phase 3: Cilium API | High | High | None | High | Future |
| `--devices` flag | Low | Low | None | None | **Test first** |

---

## 8. Recommended Next Steps

1. **Immediate**: Apply `bpf-host-legacy-routing: "true"` to Civo and test pod-to-pod from honey
2. **This week**: Test `--devices` flag approach with Liqo geneve interfaces
3. **W10-W11**: If Phase 1 unblocks mail stack, defer Phase 2/3
4. **Before Q2**: Evaluate Cilium agent API stability for Phase 3
5. **Upstream**: Consider contributing the detection code (`detect.go`) to `liqotech/liqo`

---

## 9. File Reference

| File | Purpose | Status |
|------|---------|--------|
| `pkg/fabric/cilium/detect.go` | Cilium config detection | **Working** |
| `pkg/fabric/cilium/detect_test.go` | Detection tests | **Working** |
| `pkg/fabric/cilium/vtep_controller.go` | VTEP ConfigMap management | Non-functional (VXLAN mismatch) |
| `pkg/fabric/cilium/ipcache_controller.go` | CiliumNode annotations | Non-functional (wrong mechanism) |
| `pkg/fabric/cilium/lrp_controller.go` | LRP management | **Abandoned** |
| `cmd/fabric/main.go` | Fabric DaemonSet entry point | Working |
| `pkg/fabric/internalfabric_controller.go` | Geneve interface management | Working (core) |
| `pkg/utils/network/geneve/netlink.go` | Geneve device creation | Working |
| `docs/CILIUM_EBPF_FABRIC_ROUTING_INVESTIGATION.md` | Original investigation | Superseded by this doc |

---

## 10. Supersedes

This document supersedes:
- `docs/CILIUM_EBPF_FABRIC_ROUTING_INVESTIGATION.md` (2025-12-16)
- `docs/cilium-ebpf-integration/08-integration-options-analysis.md` (2025-12-17)

Both earlier documents are retained for historical reference but contain incorrect assumptions about IPCache annotation injection that this research corrects.
