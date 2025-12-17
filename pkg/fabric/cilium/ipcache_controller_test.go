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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"

	networkingv1beta1 "github.com/liqotech/liqo/apis/networking/v1beta1"
	"github.com/liqotech/liqo/pkg/consts"
	"github.com/liqotech/liqo/pkg/gateway"
)

var _ = Describe("IPCache Controller", func() {
	var (
		reconciler *IPCacheReconciler
		ciliumCfg  *CiliumConfig
	)

	BeforeEach(func() {
		ciliumCfg = &CiliumConfig{
			Detected:        true,
			HostRoutingMode: "BPF",
			LRPSupported:    true,
		}
	})

	Context("RemoteCIDREntry", func() {
		Describe("JSON serialization", func() {
			It("should serialize entry to JSON correctly", func() {
				entry := &RemoteCIDREntry{
					CIDR:            remotePodCIDR,
					TunnelEndpoint:  gatewayIP,
					RemoteClusterID: remoteClusterID,
					Identity:        2,
				}
				Expect(entry.CIDR).To(Equal(remotePodCIDR))
				Expect(entry.TunnelEndpoint).To(Equal(gatewayIP))
				Expect(entry.RemoteClusterID).To(Equal(remoteClusterID))
				Expect(entry.Identity).To(Equal(uint32(2)))
			})
		})
	})

	Context("hashCIDR", func() {
		It("should generate consistent hash for same CIDR", func() {
			hash1 := hashCIDR("10.244.0.0/16")
			hash2 := hashCIDR("10.244.0.0/16")
			Expect(hash1).To(Equal(hash2))
		})

		It("should generate different hashes for different CIDRs", func() {
			hash1 := hashCIDR("10.244.0.0/16")
			hash2 := hashCIDR("10.245.0.0/16")
			Expect(hash1).ToNot(Equal(hash2))
		})

		It("should generate 16-character hex hash", func() {
			hash := hashCIDR("10.244.0.0/16")
			Expect(len(hash)).To(Equal(16))
		})
	})

	Context("getRemotePodCIDR", func() {
		It("should return empty string when Status.Remote is nil", func() {
			reconciler = &IPCacheReconciler{}
			cfg := &networkingv1beta1.Configuration{
				Status: networkingv1beta1.ConfigurationStatus{
					Remote: nil,
				},
			}
			cidr := reconciler.getRemotePodCIDR(cfg)
			Expect(cidr).To(BeEmpty())
		})

		It("should return empty string when Pod CIDR list is empty", func() {
			reconciler = &IPCacheReconciler{}
			cfg := &networkingv1beta1.Configuration{
				Status: networkingv1beta1.ConfigurationStatus{
					Remote: &networkingv1beta1.ClusterConfigStatus{
						CIDR: networkingv1beta1.ClusterConfigCIDR{
							Pod: []networkingv1beta1.CIDR{},
						},
					},
				},
			}
			cidr := reconciler.getRemotePodCIDR(cfg)
			Expect(cidr).To(BeEmpty())
		})

		It("should return first pod CIDR when available", func() {
			reconciler = &IPCacheReconciler{}
			cfg := &networkingv1beta1.Configuration{
				Status: networkingv1beta1.ConfigurationStatus{
					Remote: &networkingv1beta1.ClusterConfigStatus{
						CIDR: networkingv1beta1.ClusterConfigCIDR{
							Pod: []networkingv1beta1.CIDR{
								networkingv1beta1.CIDR(remotePodCIDR),
								networkingv1beta1.CIDR("10.245.0.0/16"),
							},
						},
					},
				},
			}
			cidr := reconciler.getRemotePodCIDR(cfg)
			Expect(cidr).To(Equal(remotePodCIDR))
		})
	})

	Context("Gateway pod discovery", func() {
		var gatewayPod *corev1.Pod

		BeforeEach(func() {
			reconciler = &IPCacheReconciler{
				Client:       k8sClient,
				Scheme:       scheme.Scheme,
				CiliumConfig: ciliumCfg,
			}

			gatewayPod = &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "liqo-gateway-ipcache-" + remoteClusterID,
					Namespace: "liqo",
					Labels: map[string]string{
						gateway.GatewayComponentKey: gateway.GatewayComponentGateway,
						consts.RemoteClusterID:      remoteClusterID,
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "gateway",
							Image: "liqo/gateway:latest",
						},
					},
				},
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
					PodIP: gatewayIP,
				},
			}
			Expect(k8sClient.Create(ctx, gatewayPod)).To(Succeed())
		})

		AfterEach(func() {
			_ = k8sClient.Delete(ctx, gatewayPod)
		})

		Describe("getGatewayPodIP", func() {
			It("should find gateway pod IP for remote cluster", func() {
				ip, err := reconciler.getGatewayPodIP(ctx, "liqo", remoteClusterID)
				Expect(err).ToNot(HaveOccurred())
				Expect(ip).To(Equal(gatewayIP))
			})

			It("should return error when no gateway pod exists", func() {
				_, err := reconciler.getGatewayPodIP(ctx, "liqo", "non-existent-cluster")
				Expect(err).To(HaveOccurred())
			})
		})
	})

	Context("Reconciler setup", func() {
		Describe("SetupWithManager", func() {
			It("should skip setup when Cilium not detected", func() {
				r := &IPCacheReconciler{
					Client:       k8sClient,
					Scheme:       scheme.Scheme,
					CiliumConfig: nil,
				}
				Expect(r.CiliumConfig).To(BeNil())
			})

			It("should skip setup when not using BPF host routing", func() {
				cfg := &CiliumConfig{
					Detected:        true,
					HostRoutingMode: "Legacy",
				}
				r := &IPCacheReconciler{
					Client:       k8sClient,
					Scheme:       scheme.Scheme,
					CiliumConfig: cfg,
				}
				Expect(r.CiliumConfig.IsBPFHostRouting()).To(BeFalse())
			})
		})
	})

	Context("Annotation key generation", func() {
		It("should generate valid annotation key with prefix", func() {
			cidr := "10.244.0.0/16"
			hash := hashCIDR(cidr)
			annotationKey := LiqoRemoteCIDRAnnotationPrefix + hash
			Expect(annotationKey).To(HavePrefix(LiqoRemoteCIDRAnnotationPrefix))
			Expect(len(annotationKey)).To(Equal(len(LiqoRemoteCIDRAnnotationPrefix) + 16))
		})
	})
})
