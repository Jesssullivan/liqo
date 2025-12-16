# Cilium Compatibility E2E Test Matrix

This directory contains end-to-end tests for verifying Liqo's Cilium eBPF
host routing integration using CiliumLocalRedirectPolicy (LRP).

## Test Matrix

### Cluster Topology Scenarios

| Scenario | Provider CNI | Consumer CNI | Expected Behavior |
|----------|-------------|--------------|-------------------|
| DOKS-DOKS | Cilium eBPF | Cilium eBPF | LRP on both sides |
| DOKS-RKE2 | Cilium eBPF | Canal | LRP on DOKS only |
| RKE2-DOKS | Canal | Cilium eBPF | LRP on DOKS only |
| RKE2-RKE2 | Canal | Canal | No LRP needed |
| DOKS-K3s | Cilium eBPF | Flannel | LRP on DOKS only |

### Test Cases

#### 1. Cilium Detection Tests (`detect_test.go`)

| Test | Description | Pass Criteria |
|------|-------------|---------------|
| `TestDetectCiliumPresent` | Cilium CNI detected | `CiliumConfig.Detected == true` |
| `TestDetectCiliumAbsent` | Non-Cilium CNI | `CiliumConfig.Detected == false` |
| `TestDetectBPFHostRouting` | eBPF mode detection | `NeedsLRP() == true` when native routing |
| `TestDetectLegacyRouting` | Tunnel mode detection | `NeedsLRP() == false` when tunnel mode |
| `TestDetectKubeProxyReplacement` | KPR detection | `KubeProxyReplacement == true` |

#### 2. LRP Controller Tests (`lrp_controller_test.go`)

| Test | Description | Pass Criteria |
|------|-------------|---------------|
| `TestLRPCreatedOnPeering` | LRP created when Configuration exists | LRP resource created in liqo namespace |
| `TestLRPUpdatedOnCIDRChange` | LRP updated when CIDR changes | LRP annotation matches new CIDR |
| `TestLRPDeletedOnUnpeer` | LRP deleted when Configuration deleted | LRP resource removed |
| `TestLRPOwnerReference` | Owner reference set correctly | GC cleans up LRP on Configuration delete |
| `TestLRPSkippedNonCilium` | No LRP when Cilium not detected | No LRP resources created |

#### 3. Cross-Cluster Connectivity Tests (`connectivity_test.go`)

| Test | Description | Pass Criteria |
|------|-------------|---------------|
| `TestPodToPodCrossCluster` | Pod-to-pod across clusters | curl succeeds from consumer to provider pod |
| `TestServiceToPodCrossCluster` | Service to remote pod | DNS + service port works cross-cluster |
| `TestIngressRoutingWithLRP` | Ingress via LRP | External traffic reaches offloaded pod |
| `TestBidirectionalTraffic` | Traffic in both directions | Requests work consumer→provider and provider→consumer |
| `TestLargePayload` | Large data transfer | 100MB+ transfers complete without error |

#### 4. Failover Tests (`failover_test.go`)

| Test | Description | Pass Criteria |
|------|-------------|---------------|
| `TestLRPRecreatedAfterDelete` | LRP recreated if manually deleted | Controller reconciles and recreates |
| `TestConnectivityAfterGatewayRestart` | Traffic resumes after gateway pod restart | Connectivity restored within 60s |
| `TestLRPUpdatedAfterNetworkChange` | LRP updated on CIDR remap | LRP reflects new CIDR |

## Running Tests

### Prerequisites

1. Two clusters with established Liqo peering:
   - Provider: DOKS with Cilium (managed)
   - Consumer: RKE2/K3s with Canal/Flannel

2. Environment variables:
   ```bash
   export PROVIDER_KUBECONFIG=~/.config/liqo-cluster/kubeconfig-blahaj.yaml
   export CONSUMER_KUBECONFIG=~/.config/liqo-cluster/kubeconfig-honey-liqo.yaml
   ```

3. Liqo installed from `tinyland/liqo` GitLab registry (includes Cilium LRP support)

### Run All Tests

```bash
cd test/e2e/cilium
go test -v ./... -timeout 30m
```

### Run Specific Test Category

```bash
# Detection tests only
go test -v -run TestDetect ./...

# LRP controller tests only
go test -v -run TestLRP ./...

# Connectivity tests only
go test -v -run TestConnectivity ./...
```

### CI Integration

See `.gitlab-ci.yml` for automated test execution in GitLab CI/CD:

```yaml
e2e:cilium:
  stage: test
  image: golang:1.22
  services:
    - docker:dind
  variables:
    PROVIDER_KUBECONFIG: $DOKS_KUBECONFIG
    CONSUMER_KUBECONFIG: $RKE2_KUBECONFIG
  script:
    - cd test/e2e/cilium
    - go test -v ./... -timeout 30m
  rules:
    - if: $CI_COMMIT_BRANCH == "sid/cilium-doks-rke-bridge"
```

## Manual Verification

### Quick Connectivity Check

```bash
# From consumer cluster, test connectivity to provider
KUBECONFIG=$CONSUMER_KUBECONFIG kubectl run -it --rm test-pod \
  --image=curlimages/curl --restart=Never -- \
  curl -v http://<remote-pod-ip>:8080

# Check LRP exists on DOKS
KUBECONFIG=$PROVIDER_KUBECONFIG kubectl get ciliumlocalredirectpolicies -n liqo
```

### Verify LRP Configuration

```bash
# Check LRP details
KUBECONFIG=$PROVIDER_KUBECONFIG kubectl describe ciliumlocalredirectpolicy \
  liqo-remote-<cluster-id> -n liqo
```

## Troubleshooting

### LRP Not Created

1. Check Cilium detection:
   ```bash
   kubectl logs -n liqo deployment/liqo-fabric | grep -i cilium
   ```

2. Verify Configuration resource has status.remote.cidr.pod:
   ```bash
   kubectl get configurations -A -o yaml | grep -A5 "status:"
   ```

### Connectivity Fails with LRP

1. Check LRP is targeting correct CIDR:
   ```bash
   kubectl get ciliumlocalredirectpolicy -n liqo -o yaml
   ```

2. Verify gateway pod labels match LRP selector:
   ```bash
   kubectl get pods -n liqo -l app.kubernetes.io/component=gateway --show-labels
   ```

3. Check Cilium agent logs:
   ```bash
   kubectl logs -n kube-system -l k8s-app=cilium | grep -i redirect
   ```

## References

- [Cilium LocalRedirectPolicy Docs](https://docs.cilium.io/en/stable/network/kubernetes/local-redirect-policy/)
- [Liqo GitHub Issue #2166](https://github.com/liqotech/liqo/issues/2166)
- [CILIUM_BRIDGE_PROPOSAL.md](../../../docs/CILIUM_BRIDGE_PROPOSAL.md)
