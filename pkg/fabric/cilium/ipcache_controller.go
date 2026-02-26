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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
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
	// IPCacheControllerFinalizer is the finalizer for ipcache cleanup
	IPCacheControllerFinalizer = "liqo.io/cilium-ipcache-controller"
	// IPCacheControllerName is the controller name
	IPCacheControllerName = "cilium-ipcache-controller"
	// LiqoRemoteCIDRAnnotationPrefix is the prefix for remote CIDR annotations
	LiqoRemoteCIDRAnnotationPrefix = "liqo.io/remote-cidr-"
)

// CiliumNodeGVR is the GroupVersionResource for CiliumNode
var CiliumNodeGVR = schema.GroupVersionResource{
	Group:    "cilium.io",
	Version:  "v2",
	Resource: "ciliumnodes",
}

// RemoteCIDREntry represents a Liqo remote CIDR entry for ipcache injection
type RemoteCIDREntry struct {
	// CIDR is the remote pod CIDR (e.g., "10.244.0.0/16")
	CIDR string `json:"cidr"`
	// TunnelEndpoint is the gateway pod IP that handles traffic for this CIDR
	TunnelEndpoint string `json:"tunnelEndpoint"`
	// RemoteClusterID is the ID of the remote cluster
	RemoteClusterID string `json:"remoteClusterID"`
	// Identity is the Cilium security identity (optional, defaults to world)
	Identity uint32 `json:"identity,omitempty"`
}

// IPCacheReconciler manages Cilium ipcache entries for Liqo remote CIDRs.
// When Cilium eBPF host routing is enabled, kernel routing tables are bypassed.
// This controller injects remote pod CIDRs into Cilium's ipcache so that
// eBPF can route cross-cluster traffic correctly.
type IPCacheReconciler struct {
	client.Client
	Scheme         *runtime.Scheme
	EventsRecorder record.EventRecorder
	CiliumConfig   *CiliumConfig
	DynamicClient  dynamic.Interface
	LocalNodeName  string
}

// NewIPCacheReconciler creates a new IPCacheReconciler
func NewIPCacheReconciler(
	cl client.Client,
	scheme *runtime.Scheme,
	recorder record.EventRecorder,
	ciliumConfig *CiliumConfig,
	cfg *rest.Config,
	nodeName string,
) (*IPCacheReconciler, error) {
	dynClient, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}

	return &IPCacheReconciler{
		Client:         cl,
		Scheme:         scheme,
		EventsRecorder: recorder,
		CiliumConfig:   ciliumConfig,
		DynamicClient:  dynClient,
		LocalNodeName:  nodeName,
	}, nil
}

// +kubebuilder:rbac:groups=networking.liqo.io,resources=configurations,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=cilium.io,resources=ciliumnodes,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch

// Reconcile handles Configuration events and manages Cilium ipcache entries.
//
// FIXME: Non-functional. CiliumNode annotations have no effect on BPF datapath.
// The cilium-agent ignores custom annotations and only populates ipcache from its
// own internal state (node discovery, endpoint events, CIDR allocations). Annotating
// CiliumNode objects does not cause entries to appear in the BPF ipcache maps.
// This controller is retained as reference code for future investigation.
func (r *IPCacheReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	klog.V(4).Infof("Reconciling Configuration %s for Cilium ipcache", req.NamespacedName)

	// Skip if Cilium doesn't need ipcache injection
	if r.CiliumConfig == nil || !r.CiliumConfig.IsBPFHostRouting() {
		klog.V(4).Info("Cilium eBPF host routing not detected, skipping ipcache injection")
		return ctrl.Result{}, nil
	}

	// Get the Configuration
	cfg := &networkingv1beta1.Configuration{}
	if err := r.Get(ctx, req.NamespacedName, cfg); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("unable to get Configuration: %w", err)
	}

	// Handle deletion
	if !cfg.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, cfg)
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(cfg, IPCacheControllerFinalizer) {
		controllerutil.AddFinalizer(cfg, IPCacheControllerFinalizer)
		if err := r.Update(ctx, cfg); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to add finalizer: %w", err)
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Get remote cluster ID
	remoteClusterID := cfg.Labels[consts.RemoteClusterID]
	if remoteClusterID == "" {
		klog.V(4).Infof("Remote cluster ID not set for Configuration %s", req.NamespacedName)
		return ctrl.Result{}, nil
	}

	// Get remote pod CIDR
	remotePodCIDR := r.getRemotePodCIDR(cfg)
	if remotePodCIDR == "" {
		klog.V(4).Infof("Remote pod CIDR not yet available for Configuration %s", req.NamespacedName)
		return ctrl.Result{Requeue: true}, nil
	}

	// Get gateway pod IP (tunnel endpoint for this remote cluster)
	gatewayIP, err := r.getGatewayPodIP(ctx, cfg.Namespace, remoteClusterID)
	if err != nil {
		klog.Warningf("Gateway pod IP not available for %s: %v", remoteClusterID, err)
		return ctrl.Result{Requeue: true}, nil
	}

	// Inject ipcache entry
	entry := &RemoteCIDREntry{
		CIDR:            remotePodCIDR,
		TunnelEndpoint:  gatewayIP,
		RemoteClusterID: remoteClusterID,
		Identity:        2, // Reserved identity for world (cross-cluster traffic)
	}

	if err := r.injectIPCacheEntry(ctx, entry); err != nil {
		r.EventsRecorder.Event(cfg, corev1.EventTypeWarning, "IPCacheInjectionFailed",
			fmt.Sprintf("Failed to inject ipcache entry for %s: %v", remotePodCIDR, err))
		return ctrl.Result{}, fmt.Errorf("failed to inject ipcache entry: %w", err)
	}

	klog.Infof("Injected Cilium ipcache entry: %s via gateway %s (cluster: %s)",
		remotePodCIDR, gatewayIP, remoteClusterID)
	r.EventsRecorder.Event(cfg, corev1.EventTypeNormal, "IPCacheInjected",
		fmt.Sprintf("Injected ipcache entry: %s via %s", remotePodCIDR, gatewayIP))

	return ctrl.Result{}, nil
}

// handleDeletion removes ipcache entries when Configuration is deleted
func (r *IPCacheReconciler) handleDeletion(ctx context.Context, cfg *networkingv1beta1.Configuration) (ctrl.Result, error) {
	klog.V(2).Infof("Handling deletion of Configuration %s/%s", cfg.Namespace, cfg.Name)

	remoteClusterID := cfg.Labels[consts.RemoteClusterID]
	remotePodCIDR := r.getRemotePodCIDR(cfg)

	if remoteClusterID != "" && remotePodCIDR != "" {
		if err := r.removeIPCacheEntry(ctx, remotePodCIDR, remoteClusterID); err != nil {
			klog.Warningf("Failed to remove ipcache entry for %s: %v", remotePodCIDR, err)
			// Continue with finalizer removal even if ipcache cleanup fails
		} else {
			klog.Infof("Removed Cilium ipcache entry for %s", remotePodCIDR)
		}
	}

	// Remove finalizer
	controllerutil.RemoveFinalizer(cfg, IPCacheControllerFinalizer)
	if err := r.Update(ctx, cfg); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to remove finalizer: %w", err)
	}

	return ctrl.Result{}, nil
}

// injectIPCacheEntry adds a remote CIDR to Cilium's routing via CiliumNode annotation
func (r *IPCacheReconciler) injectIPCacheEntry(ctx context.Context, entry *RemoteCIDREntry) error {
	// Get the local CiliumNode
	ciliumNode, err := r.DynamicClient.Resource(CiliumNodeGVR).Get(ctx, r.LocalNodeName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get CiliumNode %s: %w", r.LocalNodeName, err)
	}

	// Prepare annotation
	annotations := ciliumNode.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}

	// Create annotation key based on CIDR hash
	annotationKey := LiqoRemoteCIDRAnnotationPrefix + hashCIDR(entry.CIDR)

	// Serialize entry to JSON
	entryJSON, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal entry: %w", err)
	}

	annotations[annotationKey] = string(entryJSON)
	ciliumNode.SetAnnotations(annotations)

	// Update CiliumNode
	_, err = r.DynamicClient.Resource(CiliumNodeGVR).Update(ctx, ciliumNode, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update CiliumNode: %w", err)
	}

	return nil
}

// removeIPCacheEntry removes a remote CIDR annotation from CiliumNode
func (r *IPCacheReconciler) removeIPCacheEntry(ctx context.Context, cidr, remoteClusterID string) error {
	ciliumNode, err := r.DynamicClient.Resource(CiliumNodeGVR).Get(ctx, r.LocalNodeName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil // Node gone, nothing to clean up
		}
		return fmt.Errorf("failed to get CiliumNode: %w", err)
	}

	annotations := ciliumNode.GetAnnotations()
	if annotations == nil {
		return nil
	}

	annotationKey := LiqoRemoteCIDRAnnotationPrefix + hashCIDR(cidr)
	if _, exists := annotations[annotationKey]; !exists {
		return nil
	}

	delete(annotations, annotationKey)
	ciliumNode.SetAnnotations(annotations)

	_, err = r.DynamicClient.Resource(CiliumNodeGVR).Update(ctx, ciliumNode, metav1.UpdateOptions{})
	return err
}

// getRemotePodCIDR extracts remote pod CIDR from Configuration
func (r *IPCacheReconciler) getRemotePodCIDR(cfg *networkingv1beta1.Configuration) string {
	if cfg.Status.Remote == nil {
		return ""
	}
	if len(cfg.Status.Remote.CIDR.Pod) == 0 {
		return ""
	}
	return string(cfg.Status.Remote.CIDR.Pod[0])
}

// getGatewayPodIP finds the gateway pod IP for a remote cluster
func (r *IPCacheReconciler) getGatewayPodIP(ctx context.Context, namespace, remoteClusterID string) (string, error) {
	// List gateway pods in the tenant namespace.
	// We only search by component label since the tenant namespace is unique per remote cluster.
	// Note: Gateway pods don't have consts.RemoteClusterID label, only the component label.
	podList := &corev1.PodList{}
	listOpts := []client.ListOption{
		client.InNamespace(namespace),
		client.MatchingLabels{
			gateway.GatewayComponentKey: gateway.GatewayComponentGateway,
		},
	}

	if err := r.List(ctx, podList, listOpts...); err != nil {
		return "", fmt.Errorf("failed to list gateway pods: %w", err)
	}

	// Find running gateway pod
	for _, pod := range podList.Items {
		if pod.Status.Phase == corev1.PodRunning && pod.Status.PodIP != "" {
			return pod.Status.PodIP, nil
		}
	}

	// Fallback: try to get gateway IP from InternalFabric
	return r.getGatewayIPFromInternalFabric(ctx, namespace, remoteClusterID)
}

// getGatewayIPFromInternalFabric gets gateway IP from InternalFabric resource
func (r *IPCacheReconciler) getGatewayIPFromInternalFabric(ctx context.Context, namespace, remoteClusterID string) (string, error) {
	// InternalFabric stores the gateway pod IP
	internalFabric := &networkingv1beta1.InternalFabric{}
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: namespace,
		Name:      remoteClusterID,
	}, internalFabric); err != nil {
		return "", fmt.Errorf("failed to get InternalFabric: %w", err)
	}

	if internalFabric.Spec.GatewayIP == "" {
		return "", fmt.Errorf("gateway IP not set in InternalFabric")
	}

	return string(internalFabric.Spec.GatewayIP), nil
}

// SetupWithManager sets up the controller
func (r *IPCacheReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.CiliumConfig == nil || !r.CiliumConfig.IsBPFHostRouting() {
		klog.Info("Cilium eBPF host routing not detected, skipping ipcache controller setup")
		return nil
	}

	klog.Info("Setting up Cilium ipcache controller for cross-cluster CIDR injection")
	return ctrl.NewControllerManagedBy(mgr).
		Named(consts.CtrlInternalFabricFabric + "-cilium-ipcache").
		For(&networkingv1beta1.Configuration{}).
		Complete(r)
}

// hashCIDR creates a short hash of a CIDR for use in annotation keys
func hashCIDR(cidr string) string {
	h := sha256.Sum256([]byte(cidr))
	return hex.EncodeToString(h[:8])
}
