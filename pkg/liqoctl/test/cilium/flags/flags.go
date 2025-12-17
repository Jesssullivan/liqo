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

// Package flags provides command-line flags for the liqoctl test cilium command.
package flags

import (
	"github.com/spf13/pflag"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Options contains the options for the cilium test command.
type Options struct {
	// LocalClient is the client for the local cluster.
	LocalClient client.Client
	// RemoteClients contains clients for remote clusters.
	RemoteClients []client.Client
	// Kubeconfig is the path to the local kubeconfig.
	Kubeconfig string
	// RemoteKubeconfigs are paths to remote kubeconfigs.
	RemoteKubeconfigs []string
	// Force runs all tests even if Cilium eBPF is not detected.
	Force bool
	// Verbose enables verbose output.
	Verbose bool
	// FailFast stops on first failure.
	FailFast bool
	// TestIPCache tests IPCache injection specifically.
	TestIPCache bool
	// TestConnectivity tests cross-cluster connectivity.
	TestConnectivity bool
	// Timeout for tests in seconds.
	Timeout int
}

// NewOptions returns a new Options with default values.
func NewOptions() *Options {
	return &Options{
		Force:            false,
		Verbose:          false,
		FailFast:         true,
		TestIPCache:      true,
		TestConnectivity: true,
		Timeout:          300,
	}
}

// AddFlags adds flags to the provided flag set.
func AddFlags(flagset *pflag.FlagSet, opts *Options) {
	flagset.StringVar(&opts.Kubeconfig, "kubeconfig", "", "Path to the local kubeconfig file")
	flagset.StringSliceVar(&opts.RemoteKubeconfigs, "remote-kubeconfigs", nil,
		"Comma-separated list of paths to remote kubeconfig files")
	flagset.BoolVar(&opts.Force, "force", false, "Run all tests even if Cilium eBPF is not detected")
	flagset.BoolVar(&opts.Verbose, "verbose", false, "Enable verbose output")
	flagset.BoolVar(&opts.FailFast, "fail-fast", true, "Stop on first failure")
	flagset.BoolVar(&opts.TestIPCache, "ipcache", true, "Test IPCache injection")
	flagset.BoolVar(&opts.TestConnectivity, "connectivity", true, "Test cross-cluster connectivity")
	flagset.IntVar(&opts.Timeout, "timeout", 300, "Test timeout in seconds")
}
