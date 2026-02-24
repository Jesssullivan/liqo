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
	"context"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	liqov1beta1 "github.com/liqotech/liqo/apis/core/v1beta1"
	networkingv1beta1 "github.com/liqotech/liqo/apis/networking/v1beta1"
	"github.com/liqotech/liqo/pkg/utils/testutil"
)

var (
	cfg       *rest.Config
	k8sClient client.Client
	testEnv   *envtest.Environment
	ctx       context.Context
	cancel    context.CancelFunc
)

const (
	remoteClusterID = "remote-cluster-id"
	remotePodCIDR   = "10.244.0.0/16"
	gatewayIP       = "10.109.0.89"
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

	Expect(corev1.AddToScheme(scheme.Scheme)).To(Succeed())
	Expect(networkingv1beta1.AddToScheme(scheme.Scheme)).To(Succeed())
	Expect(liqov1beta1.AddToScheme(scheme.Scheme)).To(Succeed())

	// Use a direct (non-cached) client for deterministic test setup/teardown.
	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).ToNot(HaveOccurred())

	// Create required namespaces.
	for _, ns := range []string{"kube-system", "liqo"} {
		Expect(client.IgnoreAlreadyExists(k8sClient.Create(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: ns},
		}))).To(Succeed())
	}
})

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	cancel()
	Expect(testEnv.Stop()).To(Succeed())
})

// createCiliumConfigMap creates a cilium-config ConfigMap with the given data.
func createCiliumConfigMap(ctx context.Context, cl client.Client, data map[string]string) {
	deleteCiliumConfigMap(ctx, cl)
	Expect(cl.Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      CiliumConfigMapName,
			Namespace: CiliumNamespace,
		},
		Data: data,
	})).To(Succeed())
}

// deleteCiliumConfigMap deletes the cilium-config ConfigMap if it exists.
func deleteCiliumConfigMap(ctx context.Context, cl client.Client) {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      CiliumConfigMapName,
			Namespace: CiliumNamespace,
		},
	}
	Expect(client.IgnoreNotFound(cl.Delete(ctx, cm))).To(Succeed())
}
