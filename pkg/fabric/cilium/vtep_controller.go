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
	"net"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	networkingv1beta1 "github.com/liqotech/liqo/apis/networking/v1beta1"
	"github.com/liqotech/liqo/pkg/consts"
	"github.com/liqotech/liqo/pkg/gateway"
)

const (
	// VTEPControllerFinalizer is the finalizer for VTEP cleanup
	VTEPControllerFinalizer = "liqo.io/cilium-vtep-controller"
	// VTEPControllerName is the controller name
	VTEPControllerName = "cilium-vtep-controller"

	// VTEP ConfigMap keys
	vtepEnabledKey  = "enable-vtep"
	vtepEndpointKey = "vtep-endpoint"
	vtepCIDRKey     = "vtep-cidr"
	vtepMaskKey     = "vtep-mask"
	vtepMACKey      = "vtep-mac"

	// LiqoVTEPAnnotation marks Liqo-managed VTEP entries
	LiqoVTEPAnnotation = "liqo.io/vtep-managed"
)

// VTEPEntry represents a VTEP configuration entry for Cilium
type VTEPEntry struct {
	// Endpoint is the gateway pod IP (VTEP device IP)
	Endpoint string
	// CIDR is the remote pod CIDR routed via this VTEP
	CIDR string
	// Mask is the netmask for the CIDR
	Mask string
	// MAC is the gateway pod's MAC address
	MAC string
	// RemoteClusterID identifies the remote cluster
	RemoteClusterID string
}

// VTEPReconciler manages Cilium VTEP configuration for Liqo remote CIDRs.
// When Cilium eBPF host routing is enabled, kernel routing tables are bypassed.
// This controller configures Cilium's VTEP integration to route remote pod CIDRs
// through Liqo gateway pods, enabling cross-cluster connectivity.
type VTEPReconciler struct {
	client.Client
	Scheme         *runtime.Scheme
	EventsRecorder record.EventRecorder
	CiliumConfig   *CiliumConfig
}

// NewVTEPReconciler creates a new VTEPReconciler
func NewVTEPReconciler(
	cl client.Client,
	scheme *runtime.Scheme,
	recorder record.EventRecorder,
	ciliumConfig *CiliumConfig,
) *VTEPReconciler {
	return &VTEPReconciler{
		Client:         cl,
		Scheme:         scheme,
		EventsRecorder: recorder,
		CiliumConfig:   ciliumConfig,
	}
}

// +kubebuilder:rbac:groups=networking.liqo.io,resources=configurations,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;update;patch,namespace=kube-system
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch

// Reconcile handles Configuration events and manages Cilium VTEP configuration
func (r *VTEPReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	klog.V(4).Infof("Reconciling Configuration %s for Cilium VTEP", req.NamespacedName)

	// Skip if Cilium doesn't need VTEP integration
	if r.CiliumConfig == nil || !r.CiliumConfig.IsBPFHostRouting() {
		klog.V(4).Info("Cilium eBPF host routing not detected, skipping VTEP configuration")
		return ctrl.Result{}, nil
	}

	// Get the Configuration
	cfg := &networkingv1beta1.Configuration{}
	if err := r.Get(ctx, req.NamespacedName, cfg); err != nil {
		if apierrors.IsNotFound(err) {
			// Configuration deleted - rebuild VTEP config from remaining Configurations
			return r.rebuildVTEPConfig(ctx)
		}
		return ctrl.Result{}, fmt.Errorf("unable to get Configuration: %w", err)
	}

	// Handle deletion
	if !cfg.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, cfg)
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(cfg, VTEPControllerFinalizer) {
		controllerutil.AddFinalizer(cfg, VTEPControllerFinalizer)
		if err := r.Update(ctx, cfg); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to add finalizer: %w", err)
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Rebuild VTEP configuration with all current Configurations
	return r.rebuildVTEPConfig(ctx)
}

// handleDeletion removes VTEP entries when Configuration is deleted
func (r *VTEPReconciler) handleDeletion(ctx context.Context, cfg *networkingv1beta1.Configuration) (ctrl.Result, error) {
	klog.V(2).Infof("Handling deletion of Configuration %s/%s", cfg.Namespace, cfg.Name)

	// Remove finalizer first
	controllerutil.RemoveFinalizer(cfg, VTEPControllerFinalizer)
	if err := r.Update(ctx, cfg); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to remove finalizer: %w", err)
	}

	// Rebuild VTEP config without this Configuration
	return r.rebuildVTEPConfig(ctx)
}

// rebuildVTEPConfig collects all VTEP entries from active Configurations and updates Cilium ConfigMap
func (r *VTEPReconciler) rebuildVTEPConfig(ctx context.Context) (ctrl.Result, error) {
	// List all Configurations
	configList := &networkingv1beta1.ConfigurationList{}
	if err := r.List(ctx, configList); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to list Configurations: %w", err)
	}

	// Collect VTEP entries from each Configuration
	var entries []VTEPEntry
	for _, cfg := range configList.Items {
		// Skip if being deleted
		if !cfg.DeletionTimestamp.IsZero() {
			continue
		}

		entry, err := r.buildVTEPEntry(ctx, &cfg)
		if err != nil {
			klog.V(4).Infof("Skipping Configuration %s/%s: %v", cfg.Namespace, cfg.Name, err)
			continue
		}

		entries = append(entries, *entry)
	}

	// Update Cilium ConfigMap
	if err := r.updateCiliumConfig(ctx, entries); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update Cilium config: %w", err)
	}

	if len(entries) > 0 {
		klog.Infof("Updated Cilium VTEP configuration with %d entries", len(entries))
	}

	return ctrl.Result{}, nil
}

// buildVTEPEntry creates a VTEPEntry from a Configuration resource
func (r *VTEPReconciler) buildVTEPEntry(ctx context.Context, cfg *networkingv1beta1.Configuration) (*VTEPEntry, error) {
	// Get remote cluster ID
	remoteClusterID := cfg.Labels[consts.RemoteClusterID]
	if remoteClusterID == "" {
		return nil, fmt.Errorf("remote cluster ID not set")
	}

	// Get remote pod CIDR
	if cfg.Status.Remote == nil || len(cfg.Status.Remote.CIDR.Pod) == 0 {
		return nil, fmt.Errorf("remote pod CIDR not available")
	}
	remotePodCIDR := string(cfg.Status.Remote.CIDR.Pod[0])

	// Get gateway pod IP and MAC
	gatewayIP, gatewayMAC, err := r.getGatewayPodInfo(ctx, cfg.Namespace, remoteClusterID)
	if err != nil {
		return nil, fmt.Errorf("gateway pod info not available: %w", err)
	}

	// Calculate netmask from CIDR
	_, ipNet, err := net.ParseCIDR(remotePodCIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %s: %w", remotePodCIDR, err)
	}
	mask := net.IP(ipNet.Mask).String()

	return &VTEPEntry{
		Endpoint:        gatewayIP,
		CIDR:            remotePodCIDR,
		Mask:            mask,
		MAC:             gatewayMAC,
		RemoteClusterID: remoteClusterID,
	}, nil
}

// getGatewayPodInfo retrieves the gateway pod's IP and MAC address
func (r *VTEPReconciler) getGatewayPodInfo(ctx context.Context, namespace, remoteClusterID string) (string, string, error) {
	// List gateway pods for this remote cluster
	podList := &corev1.PodList{}
	listOpts := []client.ListOption{
		client.InNamespace(namespace),
		client.MatchingLabels{
			gateway.GatewayComponentKey: gateway.GatewayComponentGateway,
			consts.RemoteClusterID:      remoteClusterID,
		},
	}

	if err := r.List(ctx, podList, listOpts...); err != nil {
		return "", "", fmt.Errorf("failed to list gateway pods: %w", err)
	}

	// Find running gateway pod
	for _, pod := range podList.Items {
		if pod.Status.Phase == corev1.PodRunning && pod.Status.PodIP != "" {
			// Get MAC address from pod annotations or generate deterministic one
			mac := r.getGatewayMAC(&pod)
			return pod.Status.PodIP, mac, nil
		}
	}

	// Fallback: try to get gateway IP from InternalFabric
	return r.getGatewayIPFromInternalFabric(ctx, namespace, remoteClusterID)
}

// getGatewayMAC retrieves or generates a MAC address for the gateway pod
func (r *VTEPReconciler) getGatewayMAC(pod *corev1.Pod) string {
	// Check for MAC annotation
	if mac, ok := pod.Annotations["liqo.io/gateway-mac"]; ok {
		return mac
	}

	// Generate deterministic MAC from pod IP
	// Format: 82:36:xx:xx:xx:xx where xx are derived from IP
	ip := net.ParseIP(pod.Status.PodIP)
	if ip == nil {
		return "82:36:00:00:00:00"
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return "82:36:00:00:00:00"
	}

	return fmt.Sprintf("82:36:%02x:%02x:%02x:%02x", ip4[0], ip4[1], ip4[2], ip4[3])
}

// getGatewayIPFromInternalFabric gets gateway IP from InternalFabric resource
func (r *VTEPReconciler) getGatewayIPFromInternalFabric(ctx context.Context, namespace, remoteClusterID string) (string, string, error) {
	internalFabric := &networkingv1beta1.InternalFabric{}
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: namespace,
		Name:      remoteClusterID,
	}, internalFabric); err != nil {
		return "", "", fmt.Errorf("failed to get InternalFabric: %w", err)
	}

	if internalFabric.Spec.GatewayIP == "" {
		return "", "", fmt.Errorf("gateway IP not set in InternalFabric")
	}

	gatewayIP := string(internalFabric.Spec.GatewayIP)
	// Generate MAC from gateway IP
	ip := net.ParseIP(gatewayIP)
	if ip == nil {
		return gatewayIP, "82:36:00:00:00:00", nil
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return gatewayIP, "82:36:00:00:00:00", nil
	}

	mac := fmt.Sprintf("82:36:%02x:%02x:%02x:%02x", ip4[0], ip4[1], ip4[2], ip4[3])
	return gatewayIP, mac, nil
}

// updateCiliumConfig updates the Cilium ConfigMap with VTEP entries
func (r *VTEPReconciler) updateCiliumConfig(ctx context.Context, entries []VTEPEntry) error {
	// Get Cilium ConfigMap
	cm := &corev1.ConfigMap{}
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: CiliumNamespace,
		Name:      CiliumConfigMapName,
	}, cm); err != nil {
		return fmt.Errorf("failed to get Cilium ConfigMap: %w", err)
	}

	// Initialize data map if nil
	if cm.Data == nil {
		cm.Data = make(map[string]string)
	}

	// Build VTEP configuration strings
	if len(entries) == 0 {
		// No entries - disable VTEP
		delete(cm.Data, vtepEnabledKey)
		delete(cm.Data, vtepEndpointKey)
		delete(cm.Data, vtepCIDRKey)
		delete(cm.Data, vtepMaskKey)
		delete(cm.Data, vtepMACKey)
	} else {
		// Enable VTEP with entries
		var endpoints, cidrs, masks, macs []string
		for _, entry := range entries {
			endpoints = append(endpoints, entry.Endpoint)
			cidrs = append(cidrs, entry.CIDR)
			masks = append(masks, entry.Mask)
			macs = append(macs, entry.MAC)
		}

		cm.Data[vtepEnabledKey] = "true"
		cm.Data[vtepEndpointKey] = strings.Join(endpoints, " ")
		cm.Data[vtepCIDRKey] = strings.Join(cidrs, " ")
		cm.Data[vtepMaskKey] = strings.Join(masks, " ")
		cm.Data[vtepMACKey] = strings.Join(macs, " ")
	}

	// Update annotation to track Liqo management
	if cm.Annotations == nil {
		cm.Annotations = make(map[string]string)
	}
	cm.Annotations[LiqoVTEPAnnotation] = "true"

	// Update ConfigMap
	if err := r.Update(ctx, cm); err != nil {
		return fmt.Errorf("failed to update Cilium ConfigMap: %w", err)
	}

	return nil
}

// SetupWithManager sets up the controller
func (r *VTEPReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.CiliumConfig == nil || !r.CiliumConfig.IsBPFHostRouting() {
		klog.Info("Cilium eBPF host routing not detected, skipping VTEP controller setup")
		return nil
	}

	klog.Info("Setting up Cilium VTEP controller for cross-cluster CIDR routing")
	return ctrl.NewControllerManagedBy(mgr).
		Named(consts.CtrlInternalFabricFabric + "-cilium-vtep").
		For(&networkingv1beta1.Configuration{}).
		Complete(r)
}
