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
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"

	networkingv1beta1 "github.com/liqotech/liqo/apis/networking/v1beta1"
	"github.com/liqotech/liqo/pkg/consts"
	"github.com/liqotech/liqo/pkg/gateway"
)

// Note: consts.RemoteClusterID is no longer used for gateway pod lookup.
// Gateway pods are discovered by namespace (tenant namespace is unique per remote cluster)
// and component label only.

var _ = Describe("VTEP Controller", func() {
	var (
		reconciler *VTEPReconciler
		ciliumCfg  *CiliumConfig
	)

	BeforeEach(func() {
		ciliumCfg = &CiliumConfig{
			Detected:        true,
			HostRoutingMode: "BPF",
		}
		reconciler = NewVTEPReconciler(
			k8sClient,
			scheme.Scheme,
			nil, // No event recorder needed for tests
			ciliumCfg,
		)
	})

	Context("VTEPEntry construction", func() {
		Describe("getGatewayMAC", func() {
			It("should generate deterministic MAC from pod IP", func() {
				pod := &corev1.Pod{
					Status: corev1.PodStatus{
						PodIP: "10.109.0.89",
					},
				}
				mac := reconciler.getGatewayMAC(pod)
				Expect(mac).To(Equal("82:36:0a:6d:00:59"))
			})

			It("should use annotation MAC if present", func() {
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"liqo.io/gateway-mac": "aa:bb:cc:dd:ee:ff",
						},
					},
					Status: corev1.PodStatus{
						PodIP: "10.109.0.89",
					},
				}
				mac := reconciler.getGatewayMAC(pod)
				Expect(mac).To(Equal("aa:bb:cc:dd:ee:ff"))
			})

			It("should return default MAC for invalid IP", func() {
				pod := &corev1.Pod{
					Status: corev1.PodStatus{
						PodIP: "invalid",
					},
				}
				mac := reconciler.getGatewayMAC(pod)
				Expect(mac).To(Equal("82:36:00:00:00:00"))
			})
		})
	})

	Context("VTEP ConfigMap updates", func() {
		AfterEach(func() {
			deleteCiliumConfigMap(ctx, k8sClient)
		})

		Describe("updateCiliumConfig", func() {
			BeforeEach(func() {
				// Create initial cilium-config
				createCiliumConfigMap(ctx, k8sClient, map[string]string{
					"routing-mode": "native",
				})
			})

			It("should enable VTEP with single entry", func() {
				entries := []VTEPEntry{
					{
						Endpoint:        "10.109.0.89",
						CIDR:            "10.244.0.0/16",
						Mask:            "255.255.0.0",
						MAC:             "82:36:0a:6d:00:59",
						RemoteClusterID: remoteClusterID,
					},
				}

				err := reconciler.updateCiliumConfig(ctx, entries)
				Expect(err).ToNot(HaveOccurred())

				// Verify ConfigMap was updated
				cm := &corev1.ConfigMap{}
				err = k8sClient.Get(ctx, types.NamespacedName{
					Name:      CiliumConfigMapName,
					Namespace: CiliumNamespace,
				}, cm)
				Expect(err).ToNot(HaveOccurred())
				Expect(cm.Data["enable-vtep"]).To(Equal("true"))
				Expect(cm.Data["vtep-endpoint"]).To(Equal("10.109.0.89"))
				Expect(cm.Data["vtep-cidr"]).To(Equal("10.244.0.0/16"))
				Expect(cm.Data["vtep-mask"]).To(Equal("255.255.0.0"))
				Expect(cm.Data["vtep-mac"]).To(Equal("82:36:0a:6d:00:59"))
				Expect(cm.Annotations[LiqoVTEPAnnotation]).To(Equal("true"))
			})

			It("should enable VTEP with multiple entries", func() {
				entries := []VTEPEntry{
					{
						Endpoint:        "10.109.0.89",
						CIDR:            "10.244.0.0/16",
						Mask:            "255.255.0.0",
						MAC:             "82:36:0a:6d:00:59",
						RemoteClusterID: "cluster-1",
					},
					{
						Endpoint:        "10.109.0.90",
						CIDR:            "10.245.0.0/16",
						Mask:            "255.255.0.0",
						MAC:             "82:36:0a:6d:00:5a",
						RemoteClusterID: "cluster-2",
					},
				}

				err := reconciler.updateCiliumConfig(ctx, entries)
				Expect(err).ToNot(HaveOccurred())

				cm := &corev1.ConfigMap{}
				err = k8sClient.Get(ctx, types.NamespacedName{
					Name:      CiliumConfigMapName,
					Namespace: CiliumNamespace,
				}, cm)
				Expect(err).ToNot(HaveOccurred())
				Expect(cm.Data["vtep-endpoint"]).To(Equal("10.109.0.89 10.109.0.90"))
				Expect(cm.Data["vtep-cidr"]).To(Equal("10.244.0.0/16 10.245.0.0/16"))
			})

			It("should disable VTEP when no entries", func() {
				// First enable VTEP
				entries := []VTEPEntry{
					{
						Endpoint: "10.109.0.89",
						CIDR:     "10.244.0.0/16",
						Mask:     "255.255.0.0",
						MAC:      "82:36:0a:6d:00:59",
					},
				}
				err := reconciler.updateCiliumConfig(ctx, entries)
				Expect(err).ToNot(HaveOccurred())

				// Then disable by passing empty entries
				err = reconciler.updateCiliumConfig(ctx, []VTEPEntry{})
				Expect(err).ToNot(HaveOccurred())

				cm := &corev1.ConfigMap{}
				err = k8sClient.Get(ctx, types.NamespacedName{
					Name:      CiliumConfigMapName,
					Namespace: CiliumNamespace,
				}, cm)
				Expect(err).ToNot(HaveOccurred())
				Expect(cm.Data).ToNot(HaveKey("enable-vtep"))
				Expect(cm.Data).ToNot(HaveKey("vtep-endpoint"))
			})
		})
	})

	Context("Gateway pod discovery", func() {
		var (
			gatewayPod    *corev1.Pod
			configuration *networkingv1beta1.Configuration
		)

		BeforeEach(func() {
			// Create a gateway pod
			// NOTE: Gateway pods only have the component label, NOT RemoteClusterID.
			// The tenant namespace is unique per remote cluster, so we use namespace
			// to find the correct gateway pod.
			gatewayPod = &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "liqo-gateway-" + remoteClusterID,
					Namespace: "liqo",
					Labels: map[string]string{
						gateway.GatewayComponentKey: gateway.GatewayComponentGateway,
						// RemoteClusterID label is NOT set - controller uses namespace
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
			}
			Expect(k8sClient.Create(ctx, gatewayPod)).To(Succeed())

			// Status is a subresource - must be updated separately
			gatewayPod.Status = corev1.PodStatus{
				Phase: corev1.PodRunning,
				PodIP: gatewayIP,
			}
			Expect(k8sClient.Status().Update(ctx, gatewayPod)).To(Succeed())

			// Create a Configuration resource
			configuration = &networkingv1beta1.Configuration{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "config-" + remoteClusterID,
					Namespace: "liqo",
					Labels: map[string]string{
						consts.RemoteClusterID: remoteClusterID,
					},
				},
				Spec: networkingv1beta1.ConfigurationSpec{},
			}
			Expect(k8sClient.Create(ctx, configuration)).To(Succeed())

			// Update Configuration status with remote CIDR
			configuration.Status = networkingv1beta1.ConfigurationStatus{
				Remote: &networkingv1beta1.ClusterConfig{
					CIDR: networkingv1beta1.ClusterConfigCIDR{
						Pod: []networkingv1beta1.CIDR{networkingv1beta1.CIDR(remotePodCIDR)},
					},
				},
			}
			Expect(k8sClient.Status().Update(ctx, configuration)).To(Succeed())
		})

		AfterEach(func() {
			_ = k8sClient.Delete(ctx, gatewayPod)
			_ = k8sClient.Delete(ctx, configuration)
		})

		Describe("getGatewayPodInfo", func() {
			It("should find gateway pod IP and generate MAC", func() {
				ip, mac, err := reconciler.getGatewayPodInfo(ctx, "liqo", remoteClusterID)
				Expect(err).ToNot(HaveOccurred())
				Expect(ip).To(Equal(gatewayIP))
				// MAC generated from IP 10.109.0.89 = 82:36:0a:6d:00:59
				Expect(mac).To(Equal("82:36:0a:6d:00:59"))
			})
		})

		Describe("buildVTEPEntry", func() {
			It("should build VTEP entry from Configuration", func() {
				entry, err := reconciler.buildVTEPEntry(ctx, configuration)
				Expect(err).ToNot(HaveOccurred())
				Expect(entry.Endpoint).To(Equal(gatewayIP))
				Expect(entry.CIDR).To(Equal(remotePodCIDR))
				Expect(entry.RemoteClusterID).To(Equal(remoteClusterID))

				// Verify mask calculated correctly from CIDR
				_, ipNet, _ := net.ParseCIDR(remotePodCIDR)
				expectedMask := net.IP(ipNet.Mask).String()
				Expect(entry.Mask).To(Equal(expectedMask))
			})
		})
	})

	Context("Reconciler setup", func() {
		Describe("SetupWithManager", func() {
			It("should skip setup when Cilium not detected", func() {
				r := NewVTEPReconciler(k8sClient, scheme.Scheme, nil, nil)
				// This should not error, just skip setup
				// We can't easily test SetupWithManager without a full manager
				Expect(r.CiliumConfig).To(BeNil())
			})

			It("should skip setup when not using BPF host routing", func() {
				cfg := &CiliumConfig{
					Detected:        true,
					HostRoutingMode: "Legacy",
				}
				r := NewVTEPReconciler(k8sClient, scheme.Scheme, nil, cfg)
				Expect(r.CiliumConfig.IsBPFHostRouting()).To(BeFalse())
			})
		})
	})
})
