# policygate architecture

## Overview

policygate is a **validating admission webhook** that evaluates Pod create/update requests against a declarative `PolicyBundle` before objects are persisted. A shared Go evaluator powers both the in-cluster webhook and the `policyctl` offline CLI.

```
kubectl/API server
        │
        ▼
ValidatingWebhookConfiguration (failurePolicy: Fail)
        │
        ▼
policygate Service :443 → Pod(s) :8443 /validate (TLS)
        │
        ├─ decode AdmissionReview
        ├─ skip system namespaces (config)
        ├─ load namespace labels (exemptions)
        ├─ evaluate Pod against PolicyBundle
        └─ allow | deny (structured message)
```

## Why stdlib + `k8s.io/api/admission/v1` (not controller-runtime webhooks)

controller-runtime is excellent when you already run a kubebuilder operator. policygate is a **single-purpose webhook** with no reconcilers. Using `net/http` and the admission API types directly keeps the binary small, makes the request path obvious in code review, and avoids pulling in manager/cache machinery we do not use.

Tradeoff: you own TLS, server lifecycle, and scheme registration explicitly (see `internal/admission/handler.go`).

## Request flow

1. API server sends `AdmissionReview` (v1) with `request.dryRun` honored — same code path, no persistence side effects beyond the admission decision.
2. Handler decodes the embedded Pod from `request.object.raw`.
3. Namespace labels are fetched via the Kubernetes API for exemption rules (hostNetwork, `:latest` tags).
4. Evaluator runs rules in YAML declaration order; output is stable for tests.
5. Denials return `allowed: false` with a multi-line message: rule id, field path, actionable fix.

## Fail-closed vs fail-open

| Setting | Behavior |
|--------|----------|
| `failurePolicy: Fail` (default) | If the webhook is unreachable, times out, or returns an error, **the API server rejects the request**. Cluster stays safe; workload churn may stall during outages. |
| `failurePolicy: Ignore` | API server admits when the webhook fails. Use only for non-production bootstrap or disaster recovery; document the blast radius. |

policygate also **fails closed on namespace lookup errors** during exemption evaluation: if we cannot read namespace labels, we cannot prove an exemption applies.

System namespaces (`kube-system`, `policygate`, etc.) are skipped entirely via config so control-plane and the webhook itself can start.

## Exemption model

Namespace-scoped rules consult **namespace labels** at admission time:

- `policy.example.com/host-network=allowed` → permit `spec.hostNetwork: true`
- `policy.example.com/allow-latest=true` → permit `:latest` image tags

Offline checks use annotation `policygate.io/namespace-labels` (JSON object) on the Pod manifest to simulate namespace labels without a cluster.

## Policy rollout

Policies ship in a **ConfigMap** mounted at `/policies`. Today a pod restart (rolling deployment) reloads policy. Future: inotify/SIGHUP reload with version gauge `policy_bundle_info`.

For large fleets, prefer **versioned bundle names** and coordinated rollouts; deny messages include bundle metadata in logs (`bundle` field).

## Scaling sketch (5k req/s)

- Horizontal pod autoscaling on CPU/latency; **no session affinity** required.
- Keep `timeoutSeconds` ≤ 5; target p99 eval &lt; 50ms.
- Cache namespace labels in-process (TTL 30–60s) with watch-driven invalidation.
- Shard nothing — each replica is stateless; CA trust via `caBundle` on the webhook config.

## Comparison to OPA Gatekeeper / Kyverno

| | policygate | Gatekeeper/Kyverno |
|---|-----------|-------------------|
| Policy language | Fixed rule types, YAML | Rego / YAML DSL |
| Deny messages | Hand-crafted per rule | Varies; often generic |
| Offline test | `policyctl check` | Possible but heavier |
| Scope | Pod security baseline | General CRD governance |

policygate is intentionally **narrow, explainable, and testable offline** — a control-plane interview artifact, not a general policy engine.
