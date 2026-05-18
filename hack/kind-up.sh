#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER_NAME="${CLUSTER_NAME:-policygate}"
IMAGE="policygate:local"
# Avoid docker-credential-desktop hangs on public pulls (see hack/.docker-config/).
export DOCKER_CONFIG="${DOCKER_CONFIG:-${ROOT}/hack/.docker-config}"
KIND_NODE_IMAGE="${KIND_NODE_IMAGE:-kindest/node:v1.32.2}"

need() {
  command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }
}

need kind
need kubectl
need docker
need go
need openssl
need envsubst

if ! kind get clusters 2>/dev/null | grep -qx "${CLUSTER_NAME}"; then
  echo "pulling node image ${KIND_NODE_IMAGE} (DOCKER_CONFIG=${DOCKER_CONFIG})"
  docker pull "${KIND_NODE_IMAGE}"
  kind create cluster --name "${CLUSTER_NAME}" --image "${KIND_NODE_IMAGE}" --wait 300s
fi

kubectl config use-context "kind-${CLUSTER_NAME}"

echo "building image ${IMAGE}"
docker build -t "${IMAGE}" "${ROOT}"

kind load docker-image "${IMAGE}" --name "${CLUSTER_NAME}"

kubectl apply -f "${ROOT}/deploy/webhook/namespace.yaml"
kubectl apply -f "${ROOT}/deploy/webhook/rbac.yaml"
kubectl apply -f "${ROOT}/deploy/webhook/configmap.yaml"

"${ROOT}/hack/gen-certs.sh"
kubectl apply -f "${ROOT}/deploy/kind/certs/tls-secret.yaml"
kubectl apply -f "${ROOT}/deploy/webhook/deployment.yaml"
kubectl apply -f "${ROOT}/deploy/webhook/service.yaml"

kubectl rollout status deployment/policygate -n policygate --timeout=120s
kubectl apply -f "${ROOT}/deploy/kind/certs/validatingwebhook.yaml"

echo ""
echo "policygate is ready on kind cluster ${CLUSTER_NAME}"
echo "  offline: go run ./cmd/policyctl check -f examples/bad-pod.yaml -p policies/"
echo "  deny:    kubectl apply -f examples/bad-pod.yaml"
echo "  admit:   kubectl apply -f examples/good-pod.yaml"
