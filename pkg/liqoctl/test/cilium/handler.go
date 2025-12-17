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

package cilium

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/liqotech/liqo/pkg/liqoctl/output"
	"github.com/liqotech/liqo/pkg/liqoctl/test/cilium/check"
	"github.com/liqotech/liqo/pkg/liqoctl/test/cilium/flags"
)

const (
	// CiliumConfigMapName is the name of the Cilium ConfigMap.
	CiliumConfigMapName = "cilium-config"
	// CiliumNamespace is the namespace where Cilium is installed.
	CiliumNamespace = "kube-system"
)

// Handler implements the cilium test logic.
type Handler struct {
	Options *flags.Options
	Printer *output.Printer
}

// NewHandler returns a new Handler.
func NewHandler(opts *flags.Options, printer *output.Printer) *Handler {
	return &Handler{
		Options: opts,
		Printer: printer,
	}
}

// Run executes the Cilium integration tests.
func (h *Handler) Run(ctx context.Context) error {
	h.Printer.Info.Println("Starting Cilium eBPF integration tests")

	// Step 1: Detect Cilium configuration
	ciliumConfig, err := h.detectCiliumConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to detect Cilium configuration: %w", err)
	}

	// Step 2: Check if eBPF host routing is enabled
	if !ciliumConfig.IsBPFHostRouting {
		h.Printer.Success.Println("Cilium is using legacy routing - kernel routes will work")
		if !h.Options.Force {
			h.Printer.Info.Println("Skipping IPCache tests (use --force to run anyway)")
			return nil
		}
	}

	h.Printer.Warning.Println("Cilium eBPF host routing detected - IPCache injection required")

	// Step 3: Run IPCache injection checks
	if err := check.IPCacheInjection(ctx, h.Options, h.Printer); err != nil {
		return fmt.Errorf("IPCache injection check failed: %w", err)
	}

	// Step 4: Run cross-cluster connectivity tests
	if err := check.CrossClusterConnectivity(ctx, h.Options, h.Printer); err != nil {
		return fmt.Errorf("cross-cluster connectivity check failed: %w", err)
	}

	h.Printer.Success.Println("All Cilium eBPF integration tests passed")
	return nil
}

// CiliumConfig holds detected Cilium configuration.
type CiliumConfig struct {
	Detected          bool
	RoutingMode       string
	KubeProxyReplace  string
	BPFMasquerade     bool
	IsBPFHostRouting  bool
}

// detectCiliumConfig reads Cilium configuration from the cluster.
func (h *Handler) detectCiliumConfig(ctx context.Context) (*CiliumConfig, error) {
	config := &CiliumConfig{}

	// Get Cilium ConfigMap
	cm := &corev1.ConfigMap{}
	err := h.Options.LocalClient.Get(ctx, types.NamespacedName{
		Name:      CiliumConfigMapName,
		Namespace: CiliumNamespace,
	}, cm)

	if err != nil {
		if apierrors.IsNotFound(err) {
			h.Printer.Info.Println("Cilium ConfigMap not found - Cilium not detected")
			return config, nil
		}
		return nil, err
	}

	config.Detected = true
	config.RoutingMode = cm.Data["routing-mode"]
	config.KubeProxyReplace = cm.Data["kube-proxy-replacement"]
	config.BPFMasquerade = cm.Data["enable-bpf-masquerade"] == "true"

	// Determine if eBPF host routing is enabled
	config.IsBPFHostRouting = config.RoutingMode == "native" ||
		config.KubeProxyReplace == "true" ||
		config.KubeProxyReplace == "strict" ||
		config.BPFMasquerade

	h.Printer.Info.Printf("Cilium Config: routing-mode=%s, kube-proxy-replacement=%s, bpf-masquerade=%v\n",
		config.RoutingMode, config.KubeProxyReplace, config.BPFMasquerade)

	return config, nil
}

// GetCiliumNodesWithLiqoAnnotations returns CiliumNode resources with Liqo annotations.
func GetCiliumNodesWithLiqoAnnotations(ctx context.Context, cl client.Client) ([]string, error) {
	// This would use dynamic client to list CiliumNode resources
	// and filter those with liqo.io/remote-cidr-* annotations
	return nil, fmt.Errorf("not implemented - requires dynamic client for CiliumNode CRD")
}
