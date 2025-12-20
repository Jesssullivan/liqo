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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	networkingv1beta1 "github.com/liqotech/liqo/apis/networking/v1beta1"
	"github.com/liqotech/liqo/pkg/consts"
)

const (
	// LRPControllerFinalizer is the finalizer added to Configurations for LRP cleanup.
	LRPControllerFinalizer = "liqo.io/cilium-lrp-controller"
	// LRPControllerName is the name of the LRP controller.
	LRPControllerName = "cilium-lrp-controller"
)

// LRPControllerGVR is the GroupVersionResource for CiliumLocalRedirectPolicy.
var LRPControllerGVR = schema.GroupVersionResource{
	Group:    "cilium.io",
	Version:  "v2",
	Resource: "ciliumlocalredirectpolicies",
}

// LRPReconciler manages CiliumLocalRedirectPolicy resources for Liqo peerings.
// When Cilium with eBPF host routing is detected, this controller watches
// Configuration resources and creates LRP resources to redirect traffic destined
// for remote cluster pods to the local Liqo gateway pod.
type LRPReconciler struct {
	client.Client
	Scheme         *runtime.Scheme
	EventsRecorder record.EventRecorder
	CiliumConfig   *CiliumConfig
	// DynamicClient is used for CiliumLocalRedirectPolicy operations
	// because the manager's REST mapper may not have discovered Cilium CRDs at startup.
	DynamicClient dynamic.Interface
}

// NewLRPReconciler creates a new LRPReconciler.
func NewLRPReconciler(
	cl client.Client,
	scheme *runtime.Scheme,
	recorder record.EventRecorder,
	ciliumConfig *CiliumConfig,
	cfg *rest.Config,
) (*LRPReconciler, error) {
	// Create a dynamic client for CiliumLocalRedirectPolicy operations.
	// We use the dynamic client because controller-runtime's REST mapper
	// may not have discovered the Cilium CRDs at manager startup time.
	dynClient, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}

	return &LRPReconciler{
		Client:         cl,
		Scheme:         scheme,
		EventsRecorder: recorder,
		CiliumConfig:   ciliumConfig,
		DynamicClient:  dynClient,
	}, nil
}

// +kubebuilder:rbac:groups=networking.liqo.io,resources=configurations,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=cilium.io,resources=ciliumlocalredirectpolicies,verbs=get;list;watch;create;update;patch;delete

// Reconcile handles Configuration events and manages corresponding LRP resources.
// NOTE: CiliumLocalRedirectPolicy only supports single IP addresses, not CIDRs.
// Since Liqo needs CIDR-based routing, LRP creation is currently disabled.
// WireGuard tunnel traffic works regardless because it's encapsulated UDP to the gateway pod.
func (r *LRPReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	klog.V(4).Infof("Reconciling Configuration %s for Cilium LRP", req.NamespacedName)

	// Skip if Cilium doesn't need LRP
	if r.CiliumConfig == nil || !r.CiliumConfig.NeedsLRP() {
		klog.V(4).Info("Cilium LRP not needed, skipping")
		return ctrl.Result{}, nil
	}

	// Get the Configuration
	cfg := &networkingv1beta1.Configuration{}
	if err := r.Get(ctx, req.NamespacedName, cfg); err != nil {
		if apierrors.IsNotFound(err) {
			klog.V(4).Infof("Configuration %s not found", req.NamespacedName)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("unable to get Configuration %s: %w", req.NamespacedName, err)
	}

	// Get remote cluster ID from Configuration labels
	remoteClusterID := cfg.Labels[consts.RemoteClusterID]
	if remoteClusterID == "" {
		klog.V(4).Infof("Remote cluster ID not set for Configuration %s", req.NamespacedName)
		return ctrl.Result{}, nil
	}

	// Get remote pod CIDR from Configuration status (remapped CIDR)
	remotePodCIDR := r.getRemotePodCIDR(cfg)
	if remotePodCIDR == "" {
		klog.V(4).Infof("Remote pod CIDR not yet available for Configuration %s", req.NamespacedName)
		return ctrl.Result{}, nil
	}

	// Log informational message about the limitation
	// CiliumLocalRedirectPolicy only supports single IP addresses, not CIDRs
	// However, Liqo's WireGuard tunnel works regardless because traffic is encapsulated
	klog.V(2).Infof("Cilium LRP limitation: CiliumLocalRedirectPolicy does not support CIDR-based routing (Configuration %s, CIDR: %s). "+
		"Liqo connectivity should still work via WireGuard tunnel encapsulation.", req.NamespacedName, remotePodCIDR)

	return ctrl.Result{}, nil
}

// getRemotePodCIDR extracts the remote pod CIDR from the Configuration status.
// It returns the primary (first) remapped pod CIDR if available.
func (r *LRPReconciler) getRemotePodCIDR(cfg *networkingv1beta1.Configuration) string {
	// Check status.remote.cidr.pod for remapped CIDR
	if cfg.Status.Remote == nil {
		return ""
	}
	if len(cfg.Status.Remote.CIDR.Pod) == 0 {
		return ""
	}
	// Return the primary (first) pod CIDR
	return string(cfg.Status.Remote.CIDR.Pod[0])
}

// SetupWithManager sets up the controller with the Manager.
func (r *LRPReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Only set up if Cilium needs LRP
	if r.CiliumConfig == nil || !r.CiliumConfig.NeedsLRP() {
		klog.Info("Cilium LRP not needed, skipping LRP controller setup")
		return nil
	}

	klog.Info("Setting up CiliumLocalRedirectPolicy controller for Liqo (watching Configurations)")
	return ctrl.NewControllerManagedBy(mgr).
		Named(consts.CtrlInternalFabricFabric + "-cilium-lrp").
		For(&networkingv1beta1.Configuration{}).
		Complete(r)
}
