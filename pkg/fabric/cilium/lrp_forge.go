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
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"

	"github.com/liqotech/liqo/pkg/consts"
)

const (
	// LRPAPIVersion is the API version for CiliumLocalRedirectPolicy.
	LRPAPIVersion = "cilium.io/v2"
	// LRPKind is the kind for CiliumLocalRedirectPolicy.
	LRPKind = "CiliumLocalRedirectPolicy"
	// LRPNamePrefix is the prefix for Liqo-managed LRP resources.
	LRPNamePrefix = "liqo-remote-"
	// LiqoNamespace is the namespace where Liqo components run.
	LiqoNamespace = "liqo"
	// GatewayPort is the WireGuard port used by Liqo gateway.
	GatewayPort = 51820
)

// LRPSpec defines the specification for a CiliumLocalRedirectPolicy.
type LRPSpec struct {
	// Name is the name of the LRP resource.
	Name string
	// Namespace is the namespace of the LRP resource.
	Namespace string
	// RemoteClusterID is the ID of the remote cluster.
	RemoteClusterID string
	// RemotePodCIDR is the CIDR of remote pods to redirect.
	RemotePodCIDR string
	// GatewayLabels are the labels to select the Liqo gateway pod.
	GatewayLabels map[string]string
}

// ForgeLRPName generates a unique name for the LRP based on remote cluster.
func ForgeLRPName(remoteClusterID string) string {
	// Sanitize cluster ID for Kubernetes naming conventions
	sanitized := strings.ToLower(remoteClusterID)
	sanitized = strings.ReplaceAll(sanitized, "_", "-")
	sanitized = strings.ReplaceAll(sanitized, ".", "-")

	// Truncate if necessary (max 63 chars for K8s names)
	name := LRPNamePrefix + sanitized
	if len(name) > 63 {
		name = name[:63]
	}

	return name
}

// ForgeLRP creates an unstructured CiliumLocalRedirectPolicy resource.
// This redirects traffic destined for remote pod CIDRs to the local Liqo gateway,
// allowing Liqo to handle cross-cluster routing even when Cilium eBPF bypasses
// kernel routing tables.
func ForgeLRP(spec *LRPSpec) *unstructured.Unstructured {
	lrp := &unstructured.Unstructured{}
	lrp.SetAPIVersion(LRPAPIVersion)
	lrp.SetKind(LRPKind)
	lrp.SetName(spec.Name)
	lrp.SetNamespace(spec.Namespace)

	// Set labels for identification
	lrp.SetLabels(map[string]string{
		consts.ManagedByLabelKey:   "liqo-fabric",
		"liqo.io/remote-cluster":   spec.RemoteClusterID,
		"liqo.io/component":        "cilium-lrp",
	})

	// Set annotations
	lrp.SetAnnotations(map[string]string{
		"liqo.io/remote-pod-cidr": spec.RemotePodCIDR,
		"liqo.io/description":     fmt.Sprintf("Redirects traffic for remote cluster %s pods to Liqo gateway", spec.RemoteClusterID),
	})

	// Build the LRP spec
	// CiliumLocalRedirectPolicy redirects matching traffic to a local endpoint
	// Convert GatewayLabels from map[string]string to map[string]interface{}
	// to avoid "cannot deep copy map[string]string" panic in SetNestedField
	gatewayLabelsInterface := make(map[string]interface{}, len(spec.GatewayLabels))
	for k, v := range spec.GatewayLabels {
		gatewayLabelsInterface[k] = v
	}

	lrpSpec := map[string]interface{}{
		"redirectFrontend": map[string]interface{}{
			"addressMatcher": map[string]interface{}{
				"ip": spec.RemotePodCIDR,
			},
			"toPorts": []interface{}{
				map[string]interface{}{
					"protocol": "ANY",
				},
			},
		},
		"redirectBackend": map[string]interface{}{
			"localEndpointSelector": map[string]interface{}{
				"matchLabels": gatewayLabelsInterface,
			},
			"toPorts": []interface{}{
				map[string]interface{}{
					"port":     fmt.Sprintf("%d", GatewayPort),
					"protocol": "UDP",
				},
			},
		},
	}

	if err := unstructured.SetNestedField(lrp.Object, lrpSpec, "spec"); err != nil {
		// This should never fail for valid input
		panic(fmt.Sprintf("failed to set LRP spec: %v", err))
	}

	return lrp
}

// ForgeLRPForRemoteCluster creates an LRP for a specific remote cluster.
func ForgeLRPForRemoteCluster(remoteClusterID, remotePodCIDR string) *unstructured.Unstructured {
	spec := &LRPSpec{
		Name:            ForgeLRPName(remoteClusterID),
		Namespace:       LiqoNamespace,
		RemoteClusterID: remoteClusterID,
		RemotePodCIDR:   remotePodCIDR,
		GatewayLabels: map[string]string{
			"app.kubernetes.io/component": "gateway",
			"app.kubernetes.io/name":      "liqo",
		},
	}

	return ForgeLRP(spec)
}

// ForgeOwnerReference creates an owner reference for the LRP.
func ForgeOwnerReference(ownerName string, ownerUID types.UID, ownerKind, ownerAPIVersion string) metav1.OwnerReference {
	blockOwnerDeletion := true
	controller := true

	return metav1.OwnerReference{
		APIVersion:         ownerAPIVersion,
		Kind:               ownerKind,
		Name:               ownerName,
		UID:                ownerUID,
		BlockOwnerDeletion: &blockOwnerDeletion,
		Controller:         &controller,
	}
}

// ParseRemotePodCIDRsFromForeignCluster extracts pod CIDRs from a ForeignCluster's network status.
// In Liqo v1.0.x, the network configuration is stored in the ForeignCluster status.
func ParseRemotePodCIDRsFromForeignCluster(fc map[string]interface{}) ([]string, error) {
	cidrs := []string{}

	// Try to extract from status.network.remotePodCIDR
	status, found, err := unstructured.NestedMap(fc, "status")
	if err != nil || !found {
		return cidrs, fmt.Errorf("status not found in ForeignCluster")
	}

	network, found, err := unstructured.NestedMap(status, "network")
	if err != nil || !found {
		return cidrs, nil // Network status not yet populated
	}

	// Get the remote pod CIDR
	remotePodCIDR, found, err := unstructured.NestedString(network, "remotePodCIDR")
	if err != nil || !found {
		return cidrs, nil
	}

	if remotePodCIDR != "" {
		cidrs = append(cidrs, remotePodCIDR)
	}

	return cidrs, nil
}
