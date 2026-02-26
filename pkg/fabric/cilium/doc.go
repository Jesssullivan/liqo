// Copyright 2019-2025 The Liqo Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package cilium provides Cilium CNI integration for Liqo multi-cluster networking.
//
// # Problem Statement
//
// Cilium with eBPF host routing enabled (bpf.hostRouting=true) bypasses kernel
// routing tables entirely. This breaks Liqo's network fabric, which relies on
// ip rules and custom routing tables to direct cross-cluster traffic through
// the WireGuard tunnel.
//
// # Current Status (W09 Research Findings)
//
// Three integration approaches were investigated; all are non-functional:
//
//   - LRP (CiliumLocalRedirectPolicy): Only supports individual IPs, not CIDRs.
//     Liqo needs CIDR-based routing for remote pod ranges. Approach abandoned;
//     controller deleted.
//
//   - IPCache (CiliumNode annotations): Annotations on CiliumNode objects do NOT
//     populate the BPF ipcache maps. The cilium-agent ignores custom annotations
//     and only populates ipcache from its own internal state. Controller retained
//     as reference code but is non-functional.
//
//   - VTEP (Virtual Tunnel Endpoint): Cilium VTEP uses VXLAN encapsulation, but
//     Liqo's network fabric uses Geneve tunnels. The encapsulation mismatch means
//     VTEP entries cannot route traffic to Liqo gateways. Controller retained as
//     reference code but is non-functional.
//
// # Phase 1 Workaround
//
// Set bpf.hostLegacyRouting=true in the Cilium Helm values. This re-enables
// kernel routing table lookups alongside eBPF, allowing Liqo's standard ip-rule
// and routing-table approach to work. This has a minor performance cost but
// provides full cross-cluster connectivity.
//
// # Working Components
//
//   - detect.go: Correctly identifies Cilium configuration, eBPF host routing
//     mode, legacy routing fallback, and VTEP state. This is production-ready.
//
// # Usage
//
// The Cilium detection is automatically enabled when liqo-fabric starts.
// If Cilium is detected with eBPF host routing and no legacy fallback,
// a warning is logged recommending bpf.hostLegacyRouting=true.
//
// # Compatibility
//
// Tested with:
//   - Cilium 1.14+ with kube-proxy replacement
//   - DigitalOcean Kubernetes (DOKS) managed Cilium
//   - Liqo v1.0.1+ with Geneve network fabric
//
// # References
//
//   - GitHub Issue #2166: https://github.com/liqotech/liqo/issues/2166
//   - Cilium VTEP Docs: https://docs.cilium.io/en/stable/network/vtep/
//   - Cilium IPCache: https://docs.cilium.io/en/stable/network/concepts/routing/
package cilium
