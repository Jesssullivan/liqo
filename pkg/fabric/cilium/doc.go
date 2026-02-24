// Copyright 2019-2026 The Liqo Authors
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
// # Problem
//
// Cilium with eBPF host routing (routing-mode: native) bypasses kernel routing
// tables entirely. This breaks Liqo's network fabric, which relies on ip rules
// and custom routing tables to direct cross-cluster traffic through WireGuard.
//
// # Solution
//
// Two integration strategies, auto-selected at startup:
//
//  1. VTEP Integration - Populates Cilium's VTEP configuration in the
//     cilium-config ConfigMap with gateway pod endpoints, remote CIDRs,
//     netmasks, and deterministic MAC addresses.
//  2. IPCache Injection - Injects remote pod CIDRs into Cilium's ipcache
//     via CiliumNode annotations.
//
// If bpf.hostLegacyRouting=true is set in Cilium, kernel routing works
// normally and no Liqo-side changes are needed.
//
// CiliumLocalRedirectPolicy (LRP) was evaluated but does not support CIDR-based
// matching, only single IPs. It cannot be used for cross-cluster pod CIDR routing.
//
// # Usage
//
// Automatically enabled when Cilium is detected (cilium-config ConfigMap exists)
// with eBPF host routing. No manual configuration required.
//
// # References
//
//   - GitHub Issue: https://github.com/liqotech/liqo/issues/2166
package cilium
