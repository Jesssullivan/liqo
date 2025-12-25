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

// Package cilium provides functionality to test Liqo integration with Cilium eBPF host routing.
// When Cilium operates with eBPF host routing enabled (routing-mode=native or
// kube-proxy-replacement=true), it bypasses the Linux kernel's routing tables.
// This package tests that Liqo's IPCache injection mechanism correctly enables
// cross-cluster routing in such environments.
//
// The tests verify:
// - Cilium configuration detection (eBPF host routing mode)
// - IPCache controller operation (CiliumNode annotation injection)
// - Cross-cluster ClusterIP routing via Cilium's ipcache
// - Remote pod CIDR reachability through Liqo gateway
package cilium
