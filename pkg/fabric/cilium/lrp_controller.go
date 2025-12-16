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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

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
}

// NewLRPReconciler creates a new LRPReconciler.
func NewLRPReconciler(
	cl client.Client,
	scheme *runtime.Scheme,
	recorder record.EventRecorder,
	ciliumConfig *CiliumConfig,
) (*LRPReconciler, error) {
	return &LRPReconciler{
		Client:         cl,
		Scheme:         scheme,
		EventsRecorder: recorder,
		CiliumConfig:   ciliumConfig,
	}, nil
}

// +kubebuilder:rbac:groups=networking.liqo.io,resources=configurations,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=cilium.io,resources=ciliumlocalredirectpolicies,verbs=get;list;watch;create;update;patch;delete

// Reconcile handles Configuration events and manages corresponding LRP resources.
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
			// Configuration deleted, LRP will be garbage collected via owner reference
			klog.V(4).Infof("Configuration %s not found, LRP will be garbage collected", req.NamespacedName)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("unable to get Configuration %s: %w", req.NamespacedName, err)
	}

	// Handle deletion
	if !cfg.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, cfg)
	}

	// Ensure finalizer is present
	if !controllerutil.ContainsFinalizer(cfg, LRPControllerFinalizer) {
		controllerutil.AddFinalizer(cfg, LRPControllerFinalizer)
		if err := r.Update(ctx, cfg); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to add finalizer to Configuration %s: %w", req.NamespacedName, err)
		}
		return ctrl.Result{Requeue: true}, nil
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

	// Ensure LRP exists for this peering
	if err := r.ensureLRP(ctx, cfg, remoteClusterID, remotePodCIDR); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to ensure LRP for Configuration %s: %w", req.NamespacedName, err)
	}

	klog.V(2).Infof("Ensured CiliumLocalRedirectPolicy for Configuration %s (ClusterID: %s, CIDR: %s)",
		req.NamespacedName, remoteClusterID, remotePodCIDR)
	return ctrl.Result{}, nil
}

// handleDeletion handles the deletion of a Configuration and cleans up LRP.
func (r *LRPReconciler) handleDeletion(ctx context.Context, cfg *networkingv1beta1.Configuration) (ctrl.Result, error) {
	klog.V(2).Infof("Handling deletion of Configuration %s/%s, cleaning up LRP", cfg.Namespace, cfg.Name)

	// Get remote cluster ID from labels
	remoteClusterID := cfg.Labels[consts.RemoteClusterID]
	if remoteClusterID != "" {
		// Delete the LRP
		lrpName := ForgeLRPName(remoteClusterID)
		lrp := &unstructured.Unstructured{}
		lrp.SetAPIVersion(LRPAPIVersion)
		lrp.SetKind(LRPKind)
		lrp.SetName(lrpName)
		lrp.SetNamespace(LiqoNamespace)

		if err := r.Delete(ctx, lrp); err != nil && !apierrors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("failed to delete LRP %s: %w", lrpName, err)
		}
		klog.Infof("Cleaned up CiliumLocalRedirectPolicy %s for deleted Configuration %s/%s",
			lrpName, cfg.Namespace, cfg.Name)
	}

	// Remove finalizer
	controllerutil.RemoveFinalizer(cfg, LRPControllerFinalizer)
	if err := r.Update(ctx, cfg); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to remove finalizer from Configuration %s/%s: %w",
			cfg.Namespace, cfg.Name, err)
	}

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

// ensureLRP ensures the CiliumLocalRedirectPolicy exists for the given Configuration.
func (r *LRPReconciler) ensureLRP(ctx context.Context, cfg *networkingv1beta1.Configuration, remoteClusterID, remotePodCIDR string) error {
	lrpName := ForgeLRPName(remoteClusterID)

	// Check if LRP already exists
	existing := &unstructured.Unstructured{}
	existing.SetAPIVersion(LRPAPIVersion)
	existing.SetKind(LRPKind)
	err := r.Get(ctx, types.NamespacedName{Name: lrpName, Namespace: LiqoNamespace}, existing)

	if err == nil {
		// LRP exists, check if it needs update
		existingCIDR, _, _ := unstructured.NestedString(existing.Object, "metadata", "annotations", "liqo.io/remote-pod-cidr")
		if existingCIDR == remotePodCIDR {
			klog.V(4).Infof("LRP %s already exists with correct CIDR", lrpName)
			return nil
		}
		klog.V(2).Infof("LRP %s exists but CIDR changed (%s -> %s), updating", lrpName, existingCIDR, remotePodCIDR)
	} else if !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to get LRP %s: %w", lrpName, err)
	}

	// Create or update LRP
	lrp := ForgeLRPForRemoteCluster(remoteClusterID, remotePodCIDR)

	// Set owner reference for garbage collection
	ownerRef := metav1.OwnerReference{
		APIVersion:         cfg.APIVersion,
		Kind:               cfg.Kind,
		Name:               cfg.Name,
		UID:                cfg.UID,
		BlockOwnerDeletion: func() *bool { b := true; return &b }(),
		Controller:         func() *bool { b := true; return &b }(),
	}
	lrp.SetOwnerReferences([]metav1.OwnerReference{ownerRef})

	if apierrors.IsNotFound(err) {
		// Create new LRP
		if err := r.Create(ctx, lrp); err != nil {
			return fmt.Errorf("failed to create LRP %s: %w", lrpName, err)
		}
		klog.Infof("Created CiliumLocalRedirectPolicy %s for remote cluster %s (CIDR: %s)",
			lrpName, remoteClusterID, remotePodCIDR)
		r.EventsRecorder.Event(cfg, "Normal", "LRPCreated",
			fmt.Sprintf("Created CiliumLocalRedirectPolicy for remote pods CIDR %s", remotePodCIDR))
	} else {
		// Update existing LRP
		if err := r.Update(ctx, lrp); err != nil {
			return fmt.Errorf("failed to update LRP %s: %w", lrpName, err)
		}
		klog.Infof("Updated CiliumLocalRedirectPolicy %s for remote cluster %s (CIDR: %s)",
			lrpName, remoteClusterID, remotePodCIDR)
		r.EventsRecorder.Event(cfg, "Normal", "LRPUpdated",
			fmt.Sprintf("Updated CiliumLocalRedirectPolicy for remote pods CIDR %s", remotePodCIDR))
	}

	return nil
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
