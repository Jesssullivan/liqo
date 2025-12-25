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
// # Solution
//
// This package implements CiliumLocalRedirectPolicy (LRP) support for Liqo.
// When Cilium eBPF host routing is detected:
//
//  1. The detect.go module identifies Cilium configuration from the cluster
//  2. The lrp_controller.go watches ForeignCluster resources
//  3. For each peering, an LRP is created that redirects traffic destined
//     for remote pod CIDRs to the local Liqo gateway pod
//  4. The gateway pod handles WireGuard encapsulation as normal
//
// # Usage
//
// The Cilium integration is automatically enabled when:
//   - Cilium is detected in the cluster (cilium-config ConfigMap exists)
//   - eBPF host routing is enabled (routing-mode: native or kube-proxy-replacement)
//   - CiliumLocalRedirectPolicy CRD is available
//
// No manual configuration is required. The liqo-fabric DaemonSet will
// automatically detect Cilium and create LRP resources as needed.
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
//   - Cilium LRP Docs: https://docs.cilium.io/en/stable/network/kubernetes/local-redirect-policy/
package cilium
