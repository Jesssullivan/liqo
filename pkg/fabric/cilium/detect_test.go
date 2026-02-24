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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Cilium Detection", func() {
	Context("Config methods", func() {
		Describe("IsBPFHostRouting", func() {
			It("should return true when Cilium is detected with BPF host routing", func() {
				config := &Config{
					Detected:        true,
					HostRoutingMode: HostRoutingModeBPF,
				}
				Expect(config.IsBPFHostRouting()).To(BeTrue())
			})

			It("should return false when Cilium is not detected", func() {
				config := &Config{
					Detected:        false,
					HostRoutingMode: HostRoutingModeBPF,
				}
				Expect(config.IsBPFHostRouting()).To(BeFalse())
			})

			It("should return false when using legacy routing", func() {
				config := &Config{
					Detected:        true,
					HostRoutingMode: HostRoutingModeLegacy,
				}
				Expect(config.IsBPFHostRouting()).To(BeFalse())
			})
		})

		Describe("NeedsLRP", func() {
			It("should return true when BPF host routing and LRP supported", func() {
				config := &Config{
					Detected:        true,
					HostRoutingMode: HostRoutingModeBPF,
					LRPSupported:    true,
				}
				Expect(config.NeedsLRP()).To(BeTrue())
			})

			It("should return false when LRP not supported", func() {
				config := &Config{
					Detected:        true,
					HostRoutingMode: HostRoutingModeBPF,
					LRPSupported:    false,
				}
				Expect(config.NeedsLRP()).To(BeFalse())
			})
		})

		Describe("NeedsVTEP", func() {
			It("should return true when BPF routing without legacy fallback or VTEP", func() {
				config := &Config{
					Detected:                 true,
					HostRoutingMode:          "BPF",
					LegacyHostRoutingEnabled: false,
					VTEPEnabled:              false,
				}
				Expect(config.NeedsVTEP()).To(BeTrue())
			})

			It("should return false when legacy host routing is enabled", func() {
				config := &Config{
					Detected:                 true,
					HostRoutingMode:          "BPF",
					LegacyHostRoutingEnabled: true,
					VTEPEnabled:              false,
				}
				Expect(config.NeedsVTEP()).To(BeFalse())
			})

			It("should return false when VTEP is already enabled", func() {
				config := &Config{
					Detected:                 true,
					HostRoutingMode:          "BPF",
					LegacyHostRoutingEnabled: false,
					VTEPEnabled:              true,
				}
				Expect(config.NeedsVTEP()).To(BeFalse())
			})

			It("should return false when using legacy routing mode", func() {
				config := &Config{
					Detected:                 true,
					HostRoutingMode:          "Legacy",
					LegacyHostRoutingEnabled: false,
					VTEPEnabled:              false,
				}
				Expect(config.NeedsVTEP()).To(BeFalse())
			})
		})

		Describe("IsLegacyHostRoutingEnabled", func() {
			It("should return true when legacy host routing is enabled", func() {
				config := &Config{
					LegacyHostRoutingEnabled: true,
				}
				Expect(config.IsLegacyHostRoutingEnabled()).To(BeTrue())
			})

			It("should return false when legacy host routing is disabled", func() {
				config := &Config{
					LegacyHostRoutingEnabled: false,
				}
				Expect(config.IsLegacyHostRoutingEnabled()).To(BeFalse())
			})
		})
	})

	Context("DetectConfig", func() {
		AfterEach(func() {
			deleteCiliumConfigMap(ctx, k8sClient)
		})

		When("cilium-config ConfigMap does not exist", func() {
			It("should return config with Detected=false", func() {
				config, err := DetectConfig(ctx, k8sClient)
				Expect(err).ToNot(HaveOccurred())
				Expect(config.Detected).To(BeFalse())
			})
		})

		When("cilium-config ConfigMap exists with native routing", func() {
			BeforeEach(func() {
				createCiliumConfigMap(ctx, k8sClient, map[string]string{
					"routing-mode":            "native",
					"kube-proxy-replacement":  "true",
					"enable-bpf-masquerade":   "true",
					"bpf-host-legacy-routing": "false",
					"enable-vtep":             "false",
				})
			})

			It("should detect Cilium with BPF host routing", func() {
				config, err := DetectConfig(ctx, k8sClient)
				Expect(err).ToNot(HaveOccurred())
				Expect(config.Detected).To(BeTrue())
				Expect(config.HostRoutingMode).To(Equal(HostRoutingModeBPF))
				Expect(config.KubeProxyReplacement).To(BeTrue())
				Expect(config.BPFMasqueradeEnabled).To(BeTrue())
				Expect(config.LegacyHostRoutingEnabled).To(BeFalse())
				Expect(config.VTEPEnabled).To(BeFalse())
			})
		})

		When("cilium-config ConfigMap exists with tunnel routing", func() {
			BeforeEach(func() {
				createCiliumConfigMap(ctx, k8sClient, map[string]string{
					"routing-mode": "tunnel",
				})
			})

			It("should detect Cilium with legacy host routing", func() {
				config, err := DetectConfig(ctx, k8sClient)
				Expect(err).ToNot(HaveOccurred())
				Expect(config.Detected).To(BeTrue())
				Expect(config.HostRoutingMode).To(Equal(HostRoutingModeLegacy))
			})
		})

		When("cilium-config has legacy host routing enabled", func() {
			BeforeEach(func() {
				createCiliumConfigMap(ctx, k8sClient, map[string]string{
					"routing-mode":            "native",
					"bpf-host-legacy-routing": "true",
				})
			})

			It("should detect legacy host routing fallback", func() {
				config, err := DetectConfig(ctx, k8sClient)
				Expect(err).ToNot(HaveOccurred())
				Expect(config.Detected).To(BeTrue())
				Expect(config.LegacyHostRoutingEnabled).To(BeTrue())
				Expect(config.NeedsVTEP()).To(BeFalse())
			})
		})

		When("cilium-config has VTEP enabled", func() {
			BeforeEach(func() {
				createCiliumConfigMap(ctx, k8sClient, map[string]string{
					"routing-mode": "native",
					"enable-vtep":  "true",
				})
			})

			It("should detect VTEP is enabled", func() {
				config, err := DetectConfig(ctx, k8sClient)
				Expect(err).ToNot(HaveOccurred())
				Expect(config.Detected).To(BeTrue())
				Expect(config.VTEPEnabled).To(BeTrue())
				Expect(config.NeedsVTEP()).To(BeFalse())
			})
		})

		When("cilium-config implies BPF from kube-proxy replacement", func() {
			BeforeEach(func() {
				createCiliumConfigMap(ctx, k8sClient, map[string]string{
					"kube-proxy-replacement": "strict",
				})
			})

			It("should infer BPF host routing", func() {
				config, err := DetectConfig(ctx, k8sClient)
				Expect(err).ToNot(HaveOccurred())
				Expect(config.Detected).To(BeTrue())
				Expect(config.HostRoutingMode).To(Equal(HostRoutingModeBPF))
				Expect(config.KubeProxyReplacement).To(BeTrue())
			})
		})
	})

	Context("DetectAndLog", func() {
		AfterEach(func() {
			deleteCiliumConfigMap(ctx, k8sClient)
		})

		It("should detect and log when Cilium is not present", func() {
			config, err := DetectAndLog(ctx, k8sClient)
			Expect(err).ToNot(HaveOccurred())
			Expect(config.Detected).To(BeFalse())
		})

		It("should detect and log BPF host routing configuration", func() {
			createCiliumConfigMap(ctx, k8sClient, map[string]string{
				"routing-mode":           "native",
				"kube-proxy-replacement": "true",
			})

			config, err := DetectAndLog(ctx, k8sClient)
			Expect(err).ToNot(HaveOccurred())
			Expect(config.Detected).To(BeTrue())
			Expect(config.IsBPFHostRouting()).To(BeTrue())
		})
	})
})
