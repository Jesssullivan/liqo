# Canonical Liqo Implementation: Cilium eBPF Integration

## Overview

This document describes the canonical Liqo implementation approach for Cilium eBPF host routing integration, following established Liqo patterns for testing, development, and deployment.

## Liqo Canonical Patterns

### Project Structure

```
liqo/
├── apis/                           # API definitions (CRDs)
├── cmd/                            # Main entry points
│   └── fabric/                     # Fabric controller (contains IPCache integration)
├── pkg/
│   ├── fabric/
│   │   └── cilium/                 # Cilium integration package
│   │       ├── detect.go           # Cilium configuration detection
│   │       ├── ipcache_controller.go # IPCache injection controller (NEW)
│   │       ├── lrp_controller.go   # LRP controller (limited use)
│   │       └── lrp_forge.go        # LRP resource forging
│   └── liqoctl/
│       └── test/
│           └── cilium/             # liqoctl test cilium module (NEW)
├── test/
│   └── e2e/
│       └── cruise/
│           └── cilium/             # E2E Cilium tests (NEW)
├── examples/
│   └── networking/                 # WireGuard configuration examples
└── .devcontainer/                  # Development container configuration
```

### Testing Architecture

Liqo uses a multi-layer testing approach:

1. **Unit Tests** (`*_test.go` alongside source files)
   - Use standard Go testing
   - Mock dependencies where needed

2. **E2E Tests** (`test/e2e/`)
   - Use Ginkgo/Gomega framework
   - Multi-cluster setup via environment variables
   - Infrastructure-aware (kind, kubeadm, k3s, EKS, GKE, AKS)
   - CNI-aware (flannel, cilium, etc.)

3. **liqoctl Tests** (`pkg/liqoctl/test/`)
   - CLI-based testing commands
   - `liqoctl test network` - comprehensive network tests
   - `liqoctl test cilium` - Cilium-specific tests (NEW)

### Key Environment Variables

```bash
# E2E Test Configuration
NAMESPACE=liqo                    # Liqo namespace
CLUSTER_NUMBER=2                  # Number of clusters
KUBECONFIGDIR=/tmp/kubeconfigs    # Directory with kubeconfigs
LIQOCTL=/path/to/liqoctl          # liqoctl binary path
INFRA=kind                        # Infrastructure type
CNI=cilium                        # CNI type
POD_CIDR_OVERLAPPING=false        # Whether pod CIDRs overlap
```

## Cilium eBPF Integration Implementation

### Components

#### 1. IPCacheReconciler (`pkg/fabric/cilium/ipcache_controller.go`)

The core controller that injects remote pod CIDRs into Cilium's ipcache:

```go
type IPCacheReconciler struct {
    client.Client
    Scheme         *runtime.Scheme
    EventsRecorder record.EventRecorder
    CiliumConfig   *CiliumConfig
    DynamicClient  dynamic.Interface
    LocalNodeName  string
}
```

**Responsibilities:**
- Watch Configuration resources for remote pod CIDRs
- Get gateway pod IP for each remote cluster
- Inject CiliumNode annotations with remote CIDR mappings
- Clean up annotations when peerings are removed

#### 2. Cilium Detection (`pkg/fabric/cilium/detect.go`)

Detects Cilium configuration from the cluster:

```go
type CiliumConfig struct {
    Detected              bool
    HostRoutingMode       string  // "BPF" or "Legacy"
    KubeProxyReplacement  bool
    BPFMasqueradeEnabled  bool
    LRPSupported          bool
}
```

#### 3. E2E Tests (`test/e2e/cruise/cilium/cilium_test.go`)

Ginkgo-based tests following Liqo patterns:

```go
var _ = Describe("Liqo Cilium eBPF Integration", func() {
    Context("Cilium Detection", func() { ... })
    Context("IPCache Controller", func() { ... })
    Context("Cross-Cluster ClusterIP Routing", func() { ... })
    Context("CiliumNode IPCache Annotations", func() { ... })
})
```

#### 4. liqoctl Test Module (`pkg/liqoctl/test/cilium/`)

CLI testing command structure:
- `handler.go` - Main test orchestration
- `flags/flags.go` - Command-line options
- `check/ipcache.go` - IPCache verification
- `check/connectivity.go` - Connectivity tests

### Integration Points

#### Fabric Controller Startup (`cmd/fabric/main.go`)

```go
// Setup Cilium IPCache controller for CIDR-based routing
if ciliumConfig != nil && ciliumConfig.IsBPFHostRouting() {
    ipcacheReconciler, err := cilium.NewIPCacheReconciler(
        mgr.GetClient(),
        mgr.GetScheme(),
        mgr.GetEventRecorderFor("cilium-ipcache-controller"),
        ciliumConfig,
        cfg,
        options.NodeName,
    )
    if err != nil {
        return fmt.Errorf("unable to create Cilium IPCache reconciler: %w", err)
    }

    if err := ipcacheReconciler.SetupWithManager(mgr); err != nil {
        return fmt.Errorf("unable to setup Cilium IPCache reconciler: %w", err)
    }
    klog.Info("Cilium IPCache controller enabled for cross-cluster CIDR routing")
}
```

## Development Workflow

### Using DevContainer

The Liqo devcontainer provides:
- Go development environment
- Docker CLI with host daemon access
- KinD for local Kubernetes clusters
- Network capabilities (NET_ADMIN, NET_RAW)

```bash
# Open in VS Code
code --folder-uri vscode-remote://dev-container+$(pwd)/

# Create local test clusters
kind create cluster --name provider
kind create cluster --name consumer

# Install Liqo with Cilium support
liqoctl install --cluster-name provider
liqoctl install --cluster-name consumer
```

### Running Tests

```bash
# Unit tests
go test ./pkg/fabric/cilium/...

# E2E tests (requires cluster setup)
export CLUSTER_NUMBER=2
export KUBECONFIGDIR=/tmp/kubeconfigs
export CNI=cilium
go test -v ./test/e2e/cruise/cilium/...

# liqoctl tests
liqoctl test cilium --kubeconfig=$PROVIDER_KUBECONFIG \
    --remote-kubeconfigs=$CONSUMER_KUBECONFIG
```

### CI/CD Integration

The changes integrate with Liqo's existing CI/CD:

1. **Build Stage** - `fabric` component is built as part of standard pipeline
2. **Test Stage** - Unit tests run automatically
3. **E2E Stage** - Triggered via `/test` command on PRs

## Deployment Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Provider Cluster (Cilium eBPF)                                         │
│                                                                         │
│  ┌─────────────┐     ┌──────────────────┐     ┌─────────────────────┐  │
│  │ Liqo Fabric │────▶│ IPCacheReconciler│────▶│ CiliumNode          │  │
│  │ Controller  │     │ (watches Config) │     │ Annotations         │  │
│  └─────────────┘     └──────────────────┘     │                     │  │
│         │                    │                 │ liqo.io/remote-cidr-│  │
│         ▼                    ▼                 │ <hash>: {...}       │  │
│  ┌─────────────────┐  ┌──────────────────┐    └─────────────────────┘  │
│  │ Configuration   │  │ Gateway Pod      │              │              │
│  │ (remote CIDRs)  │  │ (tunnel endpoint)│              ▼              │
│  └─────────────────┘  └──────────────────┘    ┌─────────────────────┐  │
│                                                │ Cilium BPF ipcache  │  │
│                                                │ (routing decisions) │  │
│                                                └─────────────────────┘  │
│                                                          │              │
│                                                          ▼              │
│                                                ┌─────────────────────┐  │
│                                                │ Traffic to remote   │  │
│                                                │ CIDR routed via     │  │
│                                                │ gateway pod         │  │
│                                                └─────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ WireGuard Tunnel
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Consumer Cluster (any CNI)                                             │
│                                                                         │
│  ┌─────────────────────────────────────┐                               │
│  │ Target Pods (e.g., PostgreSQL)      │                               │
│  │ Pod CIDR: 10.244.0.0/16             │                               │
│  └─────────────────────────────────────┘                               │
└─────────────────────────────────────────────────────────────────────────┘
```

## Key Design Decisions

### 1. CiliumNode Annotations vs Direct BPF Map Access

**Chosen: CiliumNode Annotations**

Rationale:
- Least privilege (only needs RBAC for CiliumNode)
- No CAP_BPF or privileged container required
- Works with managed Kubernetes (DOKS, EKS, GKE)
- Cilium's node manager processes annotations automatically

### 2. Controller Placement

**Chosen: Part of Fabric Controller**

Rationale:
- Fabric already handles network configuration
- Access to Configuration resources
- Runs on each node (DaemonSet-like via node selection)
- Can detect local node name for CiliumNode updates

### 3. Test Framework

**Chosen: Ginkgo/Gomega with liqoctl integration**

Rationale:
- Consistent with existing Liqo tests
- CNI-aware test execution
- Infrastructure abstraction
- CLI-based for easy manual verification

## Files Created/Modified

### New Files

| File | Purpose |
|------|---------|
| `pkg/fabric/cilium/ipcache_controller.go` | IPCache injection controller |
| `test/e2e/cruise/cilium/cilium_test.go` | E2E test suite |
| `pkg/liqoctl/test/cilium/doc.go` | Package documentation |
| `pkg/liqoctl/test/cilium/handler.go` | Test handler |
| `pkg/liqoctl/test/cilium/flags/flags.go` | CLI flags |
| `pkg/liqoctl/test/cilium/check/ipcache.go` | IPCache checks |
| `pkg/liqoctl/test/cilium/check/connectivity.go` | Connectivity checks |
| `docs/cilium-ebpf-integration/` | Documentation |

### Modified Files

| File | Change |
|------|--------|
| `cmd/fabric/main.go` | Added IPCache controller setup |
| `pkg/fabric/cilium/detect.go` | (existing) Cilium detection |

## Next Steps

1. **Testing**: Run E2E tests on actual DOKS + honey-liqo setup
2. **Verification**: Confirm CiliumNode annotations are created
3. **Connectivity**: Validate cross-cluster ClusterIP routing works
4. **Documentation**: Complete remaining docs (migration guide)
5. **PR**: Submit to upstream Liqo with full test coverage
