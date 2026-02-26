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

// Package cilium provides Cilium CNI detection for Liqo multi-cluster networking
// compatibility with Cilium eBPF host routing.
package cilium

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CiliumConfig holds the detected Cilium configuration.
type CiliumConfig struct {
	// Detected indicates whether Cilium was detected in the cluster.
	Detected bool
	// Version is the Cilium version (if detected).
	Version string
	// HostRoutingMode is the host routing mode ("BPF" or "Legacy").
	HostRoutingMode string
	// KubeProxyReplacement indicates if kube-proxy replacement is enabled.
	KubeProxyReplacement bool
	// BPFMasqueradeEnabled indicates if BPF masquerading is enabled.
	BPFMasqueradeEnabled bool
	// LegacyHostRoutingEnabled indicates if bpf.hostLegacyRouting=true is set.
	LegacyHostRoutingEnabled bool
	// VTEPEnabled indicates if VTEP integration is already enabled.
	VTEPEnabled bool
}

// IsBPFHostRouting returns true if Cilium is using BPF host routing,
// which bypasses kernel routing tables and breaks Liqo's ip-rule based routing.
func (c *CiliumConfig) IsBPFHostRouting() bool {
	return c.Detected && c.HostRoutingMode == "BPF"
}

// NeedsVTEP returns true if this Cilium configuration requires VTEP integration
// for Liqo cross-cluster traffic. VTEP is needed when eBPF host routing is active
// and legacy host routing fallback is not enabled.
func (c *CiliumConfig) NeedsVTEP() bool {
	return c.IsBPFHostRouting() && !c.LegacyHostRoutingEnabled && !c.VTEPEnabled
}

// IsLegacyHostRoutingEnabled returns true if Cilium has legacy host routing
// fallback enabled (bpf.hostLegacyRouting=true), which allows kernel routes to work.
func (c *CiliumConfig) IsLegacyHostRoutingEnabled() bool {
	return c.LegacyHostRoutingEnabled
}

const (
	// CiliumConfigMapName is the name of the Cilium ConfigMap.
	CiliumConfigMapName = "cilium-config"
	// CiliumNamespace is the namespace where Cilium is typically installed.
	CiliumNamespace = "kube-system"
	// CiliumDaemonSetName is the name of the Cilium DaemonSet.
	CiliumDaemonSetName = "cilium"
)

// DetectCiliumConfig detects Cilium configuration from the cluster.
// This function reads the cilium-config ConfigMap and determines
// whether Cilium eBPF host routing is active (which breaks Liqo routing).
func DetectCiliumConfig(ctx context.Context, cl client.Client) (*CiliumConfig, error) {
	config := &CiliumConfig{
		Detected: false,
	}

	// Try to read the cilium-config ConfigMap
	cm := &corev1.ConfigMap{}
	err := cl.Get(ctx, types.NamespacedName{
		Name:      CiliumConfigMapName,
		Namespace: CiliumNamespace,
	}, cm)

	if err != nil {
		if apierrors.IsNotFound(err) {
			klog.V(4).Info("Cilium ConfigMap not found, Cilium not detected")
			return config, nil
		}
		return nil, fmt.Errorf("failed to get cilium-config ConfigMap: %w", err)
	}

	// Cilium detected
	config.Detected = true
	klog.V(2).Info("Cilium CNI detected in cluster")

	// Parse configuration values
	if hostRouting, ok := cm.Data["bpf-lb-sock-hostns-only"]; ok {
		// This is a proxy for eBPF mode - not direct but indicative
		klog.V(4).Infof("Cilium bpf-lb-sock-hostns-only: %s", hostRouting)
	}

	// Check for enable-bpf-masquerade
	if bpfMasq, ok := cm.Data["enable-bpf-masquerade"]; ok {
		config.BPFMasqueradeEnabled = strings.ToLower(bpfMasq) == "true"
	}

	// Check for kube-proxy-replacement
	if kpr, ok := cm.Data["kube-proxy-replacement"]; ok {
		config.KubeProxyReplacement = strings.ToLower(kpr) == "true" ||
			strings.ToLower(kpr) == "strict" ||
			strings.ToLower(kpr) == "partial"
	}

	// Check routing mode - the key indicator for eBPF host routing
	// In Cilium, routing-mode can be "native" (eBPF) or "tunnel"
	if routingMode, ok := cm.Data["routing-mode"]; ok {
		if routingMode == "native" {
			config.HostRoutingMode = "BPF"
		} else {
			config.HostRoutingMode = "Legacy"
		}
	} else {
		// Default assumption: if Cilium is present with kube-proxy replacement,
		// it's likely using BPF host routing
		if config.KubeProxyReplacement || config.BPFMasqueradeEnabled {
			config.HostRoutingMode = "BPF"
		} else {
			config.HostRoutingMode = "Legacy"
		}
	}

	// Check for legacy host routing fallback (bpf.hostLegacyRouting=true)
	if legacyRouting, ok := cm.Data["bpf-host-legacy-routing"]; ok {
		config.LegacyHostRoutingEnabled = strings.ToLower(legacyRouting) == "true"
	}

	// Check for VTEP integration
	if vtepEnabled, ok := cm.Data["enable-vtep"]; ok {
		config.VTEPEnabled = strings.ToLower(vtepEnabled) == "true"
	}

	klog.Infof("Cilium detected: HostRouting=%s, KubeProxyReplacement=%v, LegacyRouting=%v, VTEP=%v",
		config.HostRoutingMode, config.KubeProxyReplacement, config.LegacyHostRoutingEnabled,
		config.VTEPEnabled)

	return config, nil
}

// DetectAndLog detects Cilium configuration and logs the result.
func DetectAndLog(ctx context.Context, cl client.Client) (*CiliumConfig, error) {
	config, err := DetectCiliumConfig(ctx, cl)
	if err != nil {
		klog.Errorf("Failed to detect Cilium configuration: %v", err)
		return nil, err
	}

	if config.Detected {
		if config.IsBPFHostRouting() {
			if config.LegacyHostRoutingEnabled {
				klog.Info("Cilium eBPF host routing detected with legacy fallback enabled - standard Liqo routing will work")
			} else {
				klog.Warning("Cilium eBPF host routing detected WITHOUT legacy fallback. " +
					"Cross-cluster routing will fail. Set bpf.hostLegacyRouting=true in Cilium Helm values. " +
					"See pkg/fabric/cilium/doc.go for details on why programmatic approaches (IPCache, VTEP) are non-functional.")
			}
		} else {
			klog.Info("Cilium detected with legacy routing - standard Liqo routing will be used")
		}
	} else {
		klog.V(2).Info("Cilium not detected - using standard Liqo routing")
	}

	return config, nil
}
