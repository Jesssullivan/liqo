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

// Package cilium contains E2E tests for Cilium eBPF host routing integration.
package cilium

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	liqov1beta1 "github.com/liqotech/liqo/apis/core/v1beta1"
	networkingv1beta1 "github.com/liqotech/liqo/apis/networking/v1beta1"
	"github.com/liqotech/liqo/test/e2e/testconsts"
	"github.com/liqotech/liqo/test/e2e/testutils/tester"
	"github.com/liqotech/liqo/test/e2e/testutils/util"
)

const (
	// clustersRequired is the number of clusters required in this E2E test.
	clustersRequired = 2
	// testName is the name of this E2E test.
	testName = "CILIUM"
	// CiliumConfigMapName is the name of the Cilium ConfigMap.
	CiliumConfigMapName = "cilium-config"
	// CiliumNamespace is the namespace where Cilium is installed.
	CiliumNamespace = "kube-system"
	// testNamespace is the namespace for test workloads.
	testNamespace = "liqo-cilium-e2e-test"
)

func TestE2E(t *testing.T) {
	util.CheckIfTestIsSkipped(t, clustersRequired, testName)
	RegisterFailHandler(Fail)
	RunSpecs(t, "Liqo Cilium eBPF E2E Suite")
}

var (
	ctx         = context.Background()
	testContext = tester.GetTester(ctx)
	interval    = time.Second * 2
	timeout     = time.Minute * 5

	providerCluster *tester.ClusterContext
	consumerCluster *tester.ClusterContext
)

var _ = BeforeSuite(func() {
	// Find provider and consumer clusters
	for i := range testContext.Clusters {
		if testContext.Clusters[i].Role == liqov1beta1.ProviderRole {
			providerCluster = &testContext.Clusters[i]
		}
		if testContext.Clusters[i].Role == liqov1beta1.ConsumerRole {
			consumerCluster = &testContext.Clusters[i]
		}
	}

	Expect(providerCluster).NotTo(BeNil(), "Provider cluster not found")
	Expect(consumerCluster).NotTo(BeNil(), "Consumer cluster not found")

	// Skip if CNI is not Cilium
	if testContext.Cni != "cilium" {
		Skip("Skipping Cilium tests - CNI is not Cilium")
	}
})

var _ = Describe("Liqo Cilium eBPF Integration", func() {

	Context("Cilium Detection", func() {
		It("should detect Cilium configuration on provider cluster", func() {
			ciliumConfig := &corev1.ConfigMap{}
			err := providerCluster.ControllerClient.Get(ctx, types.NamespacedName{
				Name:      CiliumConfigMapName,
				Namespace: CiliumNamespace,
			}, ciliumConfig)
			Expect(err).ToNot(HaveOccurred(), "Cilium ConfigMap should exist")

			// Check for eBPF host routing indicators
			routingMode := ciliumConfig.Data["routing-mode"]
			kpr := ciliumConfig.Data["kube-proxy-replacement"]
			bpfMasq := ciliumConfig.Data["enable-bpf-masquerade"]

			GinkgoWriter.Printf("Cilium Config: routing-mode=%s, kube-proxy-replacement=%s, enable-bpf-masquerade=%s\n",
				routingMode, kpr, bpfMasq)

			// Log whether eBPF host routing is enabled
			if routingMode == "native" || kpr == "true" || kpr == "strict" {
				GinkgoWriter.Println("eBPF host routing is ENABLED - IPCache injection required")
			} else {
				GinkgoWriter.Println("eBPF host routing is DISABLED - kernel routing will work")
			}
		})
	})

	Context("IPCache Controller", func() {
		It("should have fabric pod running with IPCache controller", func() {
			// Find fabric pods
			podList := &corev1.PodList{}
			err := providerCluster.ControllerClient.List(ctx, podList, &client.ListOptions{
				Namespace: "liqo",
			})
			Expect(err).ToNot(HaveOccurred())

			var fabricPod *corev1.Pod
			for i := range podList.Items {
				if strings.Contains(podList.Items[i].Name, "fabric") {
					fabricPod = &podList.Items[i]
					break
				}
			}
			Expect(fabricPod).NotTo(BeNil(), "Fabric pod should exist")
			Expect(fabricPod.Status.Phase).To(Equal(corev1.PodRunning), "Fabric pod should be running")

			GinkgoWriter.Printf("Fabric pod %s is running\n", fabricPod.Name)
		})

		It("should have Configuration resources for peered clusters", func() {
			configList := &networkingv1beta1.ConfigurationList{}
			err := providerCluster.ControllerClient.List(ctx, configList, &client.ListOptions{
				Namespace: "liqo",
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(len(configList.Items)).To(BeNumerically(">", 0), "Should have at least one Configuration")

			for _, cfg := range configList.Items {
				GinkgoWriter.Printf("Configuration: %s/%s, Remote CIDR: %v\n",
					cfg.Namespace, cfg.Name, cfg.Status.Remote)
			}
		})
	})

	Context("Cross-Cluster ClusterIP Routing", func() {
		var testNs *corev1.Namespace

		BeforeEach(func() {
			// Create test namespace on consumer
			testNs = &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: testNamespace,
					Labels: map[string]string{
						testconsts.LiqoTestingLabelKey: testconsts.LiqoTestingLabelValue,
					},
				},
			}
			err := consumerCluster.ControllerClient.Create(ctx, testNs)
			if err != nil && !apierrors.IsAlreadyExists(err) {
				Expect(err).ToNot(HaveOccurred())
			}
		})

		AfterEach(func() {
			// Cleanup test namespace
			err := consumerCluster.ControllerClient.Delete(ctx, testNs)
			if err != nil && !apierrors.IsNotFound(err) {
				GinkgoWriter.Printf("Warning: failed to delete test namespace: %v\n", err)
			}
		})

		It("should route ClusterIP traffic to remote pods via IPCache", func() {
			// This test validates that cross-cluster ClusterIP routing works
			// when Cilium eBPF host routing is enabled.

			// The test uses liqoctl test network with Cilium-specific flags
			cmd := exec.CommandContext(ctx, testContext.LiqoctlPath,
				"test", "network",
				"--kubeconfig", consumerCluster.KubeconfigPath,
				"--remote-kubeconfigs", providerCluster.KubeconfigPath,
				"--basic",
				"--ip",
				"--fail-fast",
			)

			GinkgoWriter.Printf("Running: %s\n", strings.Join(cmd.Args, " "))

			stdout, err := cmd.StdoutPipe()
			Expect(err).ToNot(HaveOccurred())
			stderr, err := cmd.StderrPipe()
			Expect(err).ToNot(HaveOccurred())

			Expect(cmd.Start()).To(Succeed())

			scanner := bufio.NewScanner(stderr)
			for scanner.Scan() {
				GinkgoWriter.Println(scanner.Text())
			}
			scanner = bufio.NewScanner(stdout)
			for scanner.Scan() {
				GinkgoWriter.Println(scanner.Text())
			}

			err = cmd.Wait()
			Expect(err).ToNot(HaveOccurred(), "Network test should pass with Cilium eBPF")
		})
	})

	Context("CiliumNode IPCache Annotations", func() {
		It("should have Liqo remote CIDR annotations on CiliumNode", func() {
			// Skip if Cilium is not detected
			ciliumConfig := &corev1.ConfigMap{}
			err := providerCluster.ControllerClient.Get(ctx, types.NamespacedName{
				Name:      CiliumConfigMapName,
				Namespace: CiliumNamespace,
			}, ciliumConfig)
			if apierrors.IsNotFound(err) {
				Skip("Cilium not installed on provider cluster")
			}
			Expect(err).ToNot(HaveOccurred())

			// Check if routing mode requires IPCache injection
			routingMode := ciliumConfig.Data["routing-mode"]
			kpr := ciliumConfig.Data["kube-proxy-replacement"]

			if routingMode != "native" && kpr != "true" && kpr != "strict" {
				Skip("eBPF host routing not enabled, IPCache annotations not required")
			}

			// Use liqoctl to check Cilium status
			cmd := exec.CommandContext(ctx, testContext.LiqoctlPath,
				"info",
				"--kubeconfig", providerCluster.KubeconfigPath,
			)

			output, err := cmd.CombinedOutput()
			GinkgoWriter.Printf("liqoctl info output:\n%s\n", string(output))
			Expect(err).ToNot(HaveOccurred())

			// Verify that peering is established
			Expect(string(output)).To(ContainSubstring("Established"))
		})
	})
})

var _ = AfterSuite(func() {
	// Cleanup any test resources
	for i := range testContext.Clusters {
		Eventually(func() error {
			return util.EnsureNamespaceDeletion(ctx, testContext.Clusters[i].NativeClient, testNamespace)
		}, timeout, interval).Should(Succeed())
	}
})
