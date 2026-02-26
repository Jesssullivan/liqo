# Cilium eBPF Integration for Liqo Multi-Cluster Networking

This documentation covers the integration between Liqo's network fabric and Cilium's eBPF host routing mode.

## Table of Contents

1. [Problem Statement](./01-problem-statement.md)
2. [Architecture Analysis](./02-architecture-analysis.md)
3. [Solution Options](./03-solution-options.md)
4. [Recommended Fix: IPCache Injection](./04-ipcache-injection-fix.md) - *Superseded by 09*
5. [Canonical Implementation](./05-canonical-implementation.md) - **Liqo patterns & structure**
6. [Testing Strategy](./06-testing-strategy.md)
7. [Migration Guide](./07-migration-guide.md)
8. [Integration Options Analysis](./08-integration-options-analysis.md) - **CERN Discussion Reference**
9. [**W09 Deep Research Findings**](./09-w09-deep-research-findings.md) - **START HERE** - Comprehensive analysis superseding earlier docs

## Quick Start

If you're experiencing cross-cluster ClusterIP routing failures with Cilium eBPF host routing:

```bash
# Check if Cilium is using eBPF host routing
cilium status | grep "Host Routing"
# Output: Host Routing: BPF  <-- This means eBPF is bypassing kernel routes

# Temporary workaround: Use NodePort services
kubectl expose deployment myapp --type=NodePort --port=80
```

## Overview

When Cilium operates with `bpf.hostLegacyRouting=false` (eBPF host routing), it bypasses the Linux kernel's routing tables. This conflicts with Liqo's fabric, which installs policy routing rules in the kernel to direct cross-cluster traffic through WireGuard tunnels.

### Symptoms

- Cross-cluster ClusterIP services timeout
- `punt!` messages in Cilium logs when accessing remote pod CIDRs
- WireGuard peering shows "Connected" but pod-to-pod traffic fails
- EndpointSlices are correctly reflected but traffic doesn't flow

### Root Cause

```
Traffic Flow (Expected with kernel routing):
  Pod → ClusterIP → kube-proxy/Cilium → kernel route table → Liqo fabric → WireGuard

Traffic Flow (Actual with Cilium eBPF):
  Pod → ClusterIP → Cilium eBPF → NO route for remote CIDR → punt!
```

## Solution Summary

> **UPDATE (2026-02-25)**: IPCache annotation injection was found to be non-functional. See [09-w09-deep-research-findings.md](./09-w09-deep-research-findings.md) for the corrected analysis. The recommended immediate path is `bpf.hostLegacyRouting=true`.

| Solution | Scope | Performance Impact | Complexity | Status |
|----------|-------|-------------------|------------|--------|
| **bpf.hostLegacyRouting=true** | Global | Moderate | Low | **Recommended (Phase 1)** |
| VTEP+VXLAN bridge | Targeted | Low | Medium | Future (Phase 2) |
| Cilium Agent API | Targeted | None | High | Research (Phase 3) |
| IPCache Annotation | N/A | N/A | N/A | ~~Non-functional~~ |

## Branch

All changes are in the `sid/cilium-doks-rke-bridge` branch:
- Repository: `gitlab.com/tinyland/liqo`
- Base: Liqo v1.0.x

## References

- [Cilium Routing Documentation](https://docs.cilium.io/en/stable/network/concepts/routing/)
- [Cilium IPCache Package](https://pkg.go.dev/github.com/cilium/cilium/pkg/ipcache)
- [Cilium Tuning Guide](https://docs.cilium.io/en/stable/operations/performance/tuning/)
- [Liqo Network Fabric](https://docs.liqo.io/en/stable/advanced/network-fabric.html)
