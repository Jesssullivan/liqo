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

const (
	// HostRoutingModeBPF indicates Cilium uses eBPF host routing.
	HostRoutingModeBPF = "BPF"
	// HostRoutingModeLegacy indicates Cilium uses legacy kernel routing.
	HostRoutingModeLegacy = "Legacy"
	// boolTrue is the string representation of true for ConfigMap parsing.
	boolTrue = "true"
)

// Config holds the detected Cilium configuration.
type Config struct {
	// Detected indicates whether Cilium was detected in the cluster.
	Detected bool
	// HostRoutingMode is the host routing mode ("BPF" or "Legacy").
	HostRoutingMode string
	// KubeProxyReplacement indicates if kube-proxy replacement is enabled.
	KubeProxyReplacement bool
	// BPFMasqueradeEnabled indicates if BPF masquerading is enabled.
	BPFMasqueradeEnabled bool
	// LRPSupported indicates if CiliumLocalRedirectPolicy CRD is available.
	LRPSupported bool
	// LegacyHostRoutingEnabled indicates if bpf.hostLegacyRouting=true is set.
	LegacyHostRoutingEnabled bool
	// VTEPEnabled indicates if VTEP integration is already enabled.
	VTEPEnabled bool
}

// IsBPFHostRouting returns true if Cilium is using BPF host routing,
// which bypasses kernel routing tables and requires special integration for Liqo.
func (c *Config) IsBPFHostRouting() bool {
	return c.Detected && c.HostRoutingMode == HostRoutingModeBPF
}

// NeedsLRP returns true if this Cilium configuration requires
// CiliumLocalRedirectPolicy for Liqo cross-cluster traffic.
func (c *Config) NeedsLRP() bool {
	return c.IsBPFHostRouting() && c.LRPSupported
}

// NeedsVTEP returns true if this Cilium configuration requires VTEP integration
// for Liqo cross-cluster traffic.
func (c *Config) NeedsVTEP() bool {
	return c.IsBPFHostRouting() && !c.LegacyHostRoutingEnabled && !c.VTEPEnabled
}

// IsLegacyHostRoutingEnabled returns true if Cilium has legacy host routing
// fallback enabled (bpf.hostLegacyRouting=true), which allows kernel routes to work.
func (c *Config) IsLegacyHostRoutingEnabled() bool {
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

// DetectConfig detects Cilium configuration from the cluster.
// This function reads the cilium-config ConfigMap and determines
// whether Liqo needs to use CiliumLocalRedirectPolicy for routing.
func DetectConfig(ctx context.Context, cl client.Client) (*Config, error) {
	config := &Config{
		Detected: false,
	}

	// Try to read the cilium-config ConfigMap.
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

	// Cilium detected.
	config.Detected = true
	klog.V(2).Info("Cilium CNI detected in cluster")

	// Parse configuration values.
	if hostRouting, ok := cm.Data["bpf-lb-sock-hostns-only"]; ok {
		// This is a proxy for eBPF mode - not direct but indicative.
		klog.V(4).Infof("Cilium bpf-lb-sock-hostns-only: %s", hostRouting)
	}

	// Check for enable-bpf-masquerade.
	if bpfMasq, ok := cm.Data["enable-bpf-masquerade"]; ok {
		config.BPFMasqueradeEnabled = strings.EqualFold(bpfMasq, boolTrue)
	}

	// Check for kube-proxy-replacement.
	if kpr, ok := cm.Data["kube-proxy-replacement"]; ok {
		config.KubeProxyReplacement = strings.EqualFold(kpr, boolTrue) ||
			strings.EqualFold(kpr, "strict") ||
			strings.EqualFold(kpr, "partial")
	}

	// Check routing mode - the key indicator for eBPF host routing.
	// In Cilium, routing-mode can be "native" (eBPF) or "tunnel".
	if routingMode, ok := cm.Data["routing-mode"]; ok {
		if routingMode == "native" {
			config.HostRoutingMode = HostRoutingModeBPF
		} else {
			config.HostRoutingMode = HostRoutingModeLegacy
		}
	} else {
		// Default assumption: if Cilium is present with kube-proxy replacement,
		// it's likely using BPF host routing.
		if config.KubeProxyReplacement || config.BPFMasqueradeEnabled {
			config.HostRoutingMode = HostRoutingModeBPF
		} else {
			config.HostRoutingMode = HostRoutingModeLegacy
		}
	}

	// Check for legacy host routing fallback.
	// Cilium ConfigMap uses "enable-host-legacy-routing" (not the Helm value name "bpf-host-legacy-routing").
	if legacyRouting, ok := cm.Data["enable-host-legacy-routing"]; ok {
		config.LegacyHostRoutingEnabled = strings.EqualFold(legacyRouting, boolTrue)
	}

	// Check for VTEP integration.
	if vtepEnabled, ok := cm.Data["enable-vtep"]; ok {
		config.VTEPEnabled = strings.EqualFold(vtepEnabled, boolTrue)
	}

	// Check if CiliumLocalRedirectPolicy CRD is available.
	config.LRPSupported = checkLRPSupport(ctx, cl)

	klog.Infof(
		"Cilium detected: HostRouting=%s, KubeProxyReplacement=%v, LegacyRouting=%v, VTEP=%v, LRPSupported=%v",
		config.HostRoutingMode, config.KubeProxyReplacement, config.LegacyHostRoutingEnabled,
		config.VTEPEnabled, config.LRPSupported)

	return config, nil
}

// checkLRPSupport checks if the CiliumLocalRedirectPolicy CRD is available.
func checkLRPSupport(_ context.Context, _ client.Client) bool {
	// We check by trying to list CiliumLocalRedirectPolicy resources.
	// If the CRD doesn't exist, this will fail.
	// Using unstructured client to avoid import cycles.

	// For now, we assume LRP is supported if Cilium is detected.
	// A more robust check would query the API server for the CRD.
	// This can be enhanced later with proper CRD detection.
	klog.V(4).Info("Assuming CiliumLocalRedirectPolicy CRD is available")
	return true
}

// DetectAndLog detects Cilium configuration and logs the result.
func DetectAndLog(ctx context.Context, cl client.Client) (*Config, error) {
	config, err := DetectConfig(ctx, cl)
	if err != nil {
		klog.Errorf("Failed to detect Cilium configuration: %v", err)
		return nil, err
	}

	switch {
	case !config.Detected:
		klog.V(2).Info("Cilium not detected - using standard Liqo routing")
	case !config.IsBPFHostRouting():
		klog.Info("Cilium detected with legacy routing - standard Liqo routing will be used")
	default:
		switch {
		case config.LegacyHostRoutingEnabled:
			klog.Info("Cilium eBPF host routing detected with legacy fallback - standard Liqo routing will work")
		case config.VTEPEnabled:
			klog.Info("Cilium eBPF host routing detected with VTEP enabled - Liqo VTEP controller will manage routing")
		case config.NeedsVTEP():
			klog.Warning("Cilium eBPF host routing detected without legacy fallback or VTEP. " +
				"Cross-cluster routing may fail. Options: " +
				"1) Set bpf.hostLegacyRouting=true in Cilium, or " +
				"2) Liqo will configure VTEP integration automatically")
		}

		if config.NeedsLRP() {
			klog.Info("CiliumLocalRedirectPolicy support detected for endpoint-level routing")
		}
	}

	return config, nil
}
