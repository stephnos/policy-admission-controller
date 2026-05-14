# policygate

Production-style **Kubernetes validating admission webhook** in Go that enforces workload security policies with explainable deny messages, offline policy testing, and a kind demo.

```
                    ┌─────────────────┐
  kubectl apply ──► │  API server     │
                    └────────┬────────┘
                             │ AdmissionReview
                             ▼
                    ┌─────────────────┐
                    │  policygate     │  PolicyBundle (ConfigMap)
                    │  /validate TLS  │  ─► pure Go evaluator
                    └────────┬────────┘
                             │ allow / deny + reasons
                             ▼
                         etcd (if allowed)
```

## Features

- Validating webhook (`admissionregistration.k8s.io/v1`) on Pod **CREATE** and **UPDATE**
- Declarative `PolicyBundle` (YAML) with six baseline rules
- Structured, multi-rule denial messages (rule id, field path, fix hint)
- `policyctl check` — same evaluator as the webhook for CI
- Prometheus metrics: `admission_requests_total`, `admission_latency_seconds`, `policy_eval_errors_total`
- `failurePolicy: Fail` (fail closed), system namespace ignores
- kind bootstrap in under 10 minutes

## Quick start (5-minute demo)

### Offline only (no cluster)

Requires **Go 1.22+** only. Run commands **one line at a time** (do not paste the whole block).

```bash
go run ./cmd/policyctl check -f examples/bad-pod.yaml -p policies/
```

**Expected:** prints 7 violations and exits with code `1` — that means the policy correctly rejected the pod.

```bash
go run ./cmd/policyctl check -f examples/good-pod.yaml -p policies/
```

**Expected:** no output, exit code `0`.

### Full cluster demo (kind)

**Prerequisites:** Docker (running), [kind](https://kind.sigs.k8s.io/), kubectl, Go 1.22+, openssl, `envsubst` (gettext on macOS: `brew install gettext` and ensure `envsubst` is on your `PATH`).

macOS install example:

```bash
brew install kind kubectl
# Docker Desktop: https://www.docker.com/products/docker-desktop/
```

```bash
./hack/kind-up.sh
kubectl apply -f examples/bad-pod.yaml
kubectl apply -f examples/good-pod.yaml
kubectl -n policygate port-forward deploy/policygate 9090:9090
curl -s localhost:9090/metrics | grep admission_
```

### Docker pull hangs

If `docker pull` sits forever or shows `error getting credentials`, Docker Desktop’s `credsStore: desktop` helper is often the cause. `./hack/kind-up.sh` uses `hack/.docker-config` (no credential helper) for pulls. To fix all pulls: sign in via Docker Desktop (**Settings → Accounts**) or restart Docker Desktop.

### Example denial

```text
admission denied by policygate:
- rule deny-privileged (spec.containers["app"].securityContext.privileged): privileged containers are not allowed; set securityContext.privileged to false or omit it
- rule require-labels (metadata.labels["team"]): required label "team" is missing; add metadata.labels.team
...
```

## Policy rules (baseline)

| Rule | What it does |
|------|----------------|
| `deny-privileged` | Reject `securityContext.privileged: true` |
| `deny-host-network` | Reject `hostNetwork` unless namespace label `policy.example.com/host-network=allowed` |
| `require-labels` | Require `app` and `team` labels |
| `require-limits` | Require non-zero `resources.limits.cpu` and `memory` on every container |
| `image-allowlist` | Images must match allowed registry prefixes |
| `deny-latest-tag` | Reject `:latest` unless `policy.example.com/allow-latest=true` on namespace |

Edit [`policies/baseline.yaml`](policies/baseline.yaml) or the ConfigMap in [`deploy/webhook/configmap.yaml`](deploy/webhook/configmap.yaml).

## Offline exemptions

Simulate namespace labels without a cluster:

```yaml
metadata:
  annotations:
    policygate.io/namespace-labels: '{"policy.example.com/allow-latest":"true"}'
```

## Development

```bash
go test ./...
make build
make policyctl-check
```

### kind integration (manual)

Documented in CI-style flow — run once after `./hack/kind-up.sh`:

```bash
kubectl apply -f examples/bad-pod.yaml && exit 1 || true
kubectl apply -f examples/good-pod.yaml
kubectl -n policygate delete pod -l app=policygate --wait=false
sleep 3
kubectl apply -f examples/bad-pod.yaml && exit 1 || true   # still denied (fail closed)
```

### Fail-closed check

With `failurePolicy: Fail`, deleting webhook pods causes the API server to reject new Pod creates while the endpoint is unavailable.

## Layout

```
cmd/webhook/          admission server
cmd/policyctl/        offline checker
internal/policy/      bundle load + evaluator
internal/admission/   HTTP handler, metrics
internal/exemptions/  namespace helpers
deploy/webhook/       Kubernetes manifests
deploy/kind/certs/    generated TLS (gitignored)
policies/             baseline bundle
hack/kind-up.sh       kind cluster + install
docs/                 architecture + interview narrative
```

## Tradeoffs

| Topic | Choice |
|-------|--------|
| **Latency** | Every Pod pays webhook RTT + optional namespace GET; keep rules O(containers) |
| **Availability** | Fail-closed protects security; outages block Pod creates |
| **Policy rollout** | ConfigMap + rolling restart; no hot reload in v1 |
| **Scope** | Pods only; Deployments/STS are a stretch goal |
| **Engine** | Fixed rule types vs Rego — narrower but explainable and offline-testable |

See [docs/architecture.md](docs/architecture.md) and [docs/google-interview-walkthrough.md](docs/google-interview-walkthrough.md).

## Comparison

**OPA Gatekeeper / Kyverno** — general-purpose, cluster-wide governance.  
**policygate** — small, deep, interview-ready Pod baseline with matching CLI output and actionable denials.

## License

MIT
