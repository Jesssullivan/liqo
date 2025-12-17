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
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"

	liqov1beta1 "github.com/liqotech/liqo/apis/core/v1beta1"
	networkingv1beta1 "github.com/liqotech/liqo/apis/networking/v1beta1"
	"github.com/liqotech/liqo/pkg/utils/testutil"
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var (
	cfg       *rest.Config
	k8sClient client.Client
	testEnv   *envtest.Environment
	ctx       context.Context
	cancel    context.CancelFunc
)

const (
	timeout  = time.Second * 10
	interval = time.Millisecond * 250

	// Test cluster identifiers
	localClusterID  = "local-cluster-id"
	remoteClusterID = "remote-cluster-id"

	// Test CIDRs
	remotePodCIDR = "10.244.0.0/16"
	gatewayIP     = "10.109.0.89"

	// Test node name
	testNodeName = "test-node-1"
)

func TestCilium(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Cilium Integration Suite")
}

var _ = BeforeSuite(func() {
	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths: []string{
			filepath.Join("..", "..", "..", "deployments", "liqo", "charts", "liqo-crds", "crds"),
		},
		ErrorIfCRDPathMissing: true,
	}

	ctx, cancel = context.WithCancel(context.Background())
	testutil.LogsToGinkgoWriter()

	var err error
	cfg, err = testEnv.Start()
	Expect(err).ToNot(HaveOccurred())
	Expect(cfg).ToNot(BeNil())

	err = corev1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	err = networkingv1beta1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	err = liqov1beta1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	k8sManager, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:  scheme.Scheme,
		Metrics: server.Options{BindAddress: "0"}, // this avoids port binding collision
	})
	Expect(err).ToNot(HaveOccurred())

	k8sClient = k8sManager.GetClient()
	Expect(k8sClient).ToNot(BeNil())

	// Create kube-system namespace for cilium-config
	kubeSystemNs := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "kube-system",
		},
	}
	err = k8sClient.Create(ctx, kubeSystemNs)
	Expect(client.IgnoreAlreadyExists(err)).ToNot(HaveOccurred())

	// Create liqo namespace
	liqoNs := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "liqo",
		},
	}
	err = k8sClient.Create(ctx, liqoNs)
	Expect(client.IgnoreAlreadyExists(err)).ToNot(HaveOccurred())

	go func() {
		defer GinkgoRecover()
		err = k8sManager.Start(ctx)
		Expect(err).ToNot(HaveOccurred())
	}()
})

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	cancel()
	Expect(testEnv.Stop()).To(Succeed())
})

// Helper functions for creating test resources

// createCiliumConfigMap creates a cilium-config ConfigMap with the given data.
func createCiliumConfigMap(ctx context.Context, cl client.Client, data map[string]string) *corev1.ConfigMap {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      CiliumConfigMapName,
			Namespace: CiliumNamespace,
		},
		Data: data,
	}
	Expect(cl.Create(ctx, cm)).To(Succeed())
	return cm
}

// deleteCiliumConfigMap deletes the cilium-config ConfigMap.
func deleteCiliumConfigMap(ctx context.Context, cl client.Client) {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      CiliumConfigMapName,
			Namespace: CiliumNamespace,
		},
	}
	_ = cl.Delete(ctx, cm)
}
