# 10-minute interview walkthrough — policygate

## 1. Problem (30s)

Cluster operators need to **block unsafe Pod specs before etcd persistence**, with denial reasons that work for humans and CI. policygate is a validating admission webhook plus offline CLI sharing one evaluator.

## 2. Design (2m)

- **Validating only** — security baselines should not depend on mutation ordering; mutating webhooks run first and can fight each other.
- **Pure Go evaluator** — explicit rule types (`denyPrivileged`, `requireResourceLimits`, …), deterministic order, `[]Violation{Rule, Path, Message}`.
- **PolicyBundle** — versioned YAML (`policygate.io/v1`), mounted from ConfigMap for v1.
- **Fail closed** — `failurePolicy: Fail`; skip only known system namespaces.

## 3. Request path (1m)

API server → TLS → `/validate` → decode Pod → fetch namespace labels → evaluate → allow/deny. `dryRun=true` uses the same path so `kubectl apply --dry-run=server` matches production.

## 4. Tradeoffs (2m)

**Availability vs security:** Fail-closed protects the cluster during webhook outages but can halt deploys. Mitigation: multiple replicas, short timeouts, PDB, runbooks for temporary `Ignore` in disasters only.

**Latency:** Every Pod create pays one HTTPS round-trip + namespace GET. At Google scale I’d cache namespace labels and cap rule count; keep eval CPU-bound and allocation-light.

**Policy rollout:** ConfigMap change + rolling restart today; at scale, version bundles, canary namespaces, and metrics on deny rate per rule id.

## 5. Failure modes (2m)

| Failure | Effect |
|--------|--------|
| Webhook pod down | New pods denied (Fail) |
| Bad TLS / caBundle | All pod creates fail |
| Namespace API slow | Timeouts → deny |
| Policy YAML invalid | CrashLoop on deploy (fail fast) |

**Test:** delete webhook pod → `kubectl apply` bad pod still denied (apiserver cannot reach webhook → fail closed).

## 6. vs OPA / Kyverno (1m)

Gatekeeper/Kyverno win on generality. policygate wins on **actionable denials**, **offline parity**, and **small blast radius** — good for opinionated workload baselines, not replacing org-wide policy platforms.

## 7. Google-scale next steps (1m)

- Multi-replica HPA, namespace label cache with watch
- Sharded audit export to logging pipeline (not in v1)
- SLO dashboards: `admission_requests_total`, p99 `admission_latency_seconds`, `policy_eval_errors_total`
- Optional: limited Deployment/StatefulSet template evaluation behind same evaluator

## 8. Demo closing (30s)

```bash
./hack/kind-up.sh
go run ./cmd/policyctl check -f examples/bad-pod.yaml -p policies/
kubectl apply -f examples/bad-pod.yaml   # deny, ≥2 rules cited
kubectl apply -f examples/good-pod.yaml  # admit
```

Same violations offline and in-cluster — proves the evaluator is the source of truth.
