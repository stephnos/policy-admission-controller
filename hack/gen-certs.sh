#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ROOT}/deploy/kind/certs"
NS="policygate"
SVC="policygate"

mkdir -p "${OUT}"

openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout "${OUT}/ca.key" -out "${OUT}/ca.crt" \
  -subj "/CN=policygate-ca"

openssl req -newkey rsa:4096 -nodes \
  -keyout "${OUT}/tls.key" -out "${OUT}/tls.csr" \
  -subj "/CN=${SVC}.${NS}.svc"

cat >"${OUT}/ext.cnf" <<EOF
subjectAltName = DNS:${SVC},DNS:${SVC}.${NS},DNS:${SVC}.${NS}.svc,DNS:${SVC}.${NS}.svc.cluster.local
EOF

openssl x509 -req -in "${OUT}/tls.csr" -CA "${OUT}/ca.crt" -CAkey "${OUT}/ca.key" \
  -CAcreateserial -out "${OUT}/tls.crt" -days 3650 -sha256 -extfile "${OUT}/ext.cnf"

CA_BUNDLE_B64="$(base64 <"${OUT}/ca.crt" | tr -d '\n')"
export CA_BUNDLE_B64
envsubst <"${ROOT}/deploy/webhook/validatingwebhook.yaml" >"${OUT}/validatingwebhook.yaml"

kubectl create secret tls policygate-tls \
  --cert="${OUT}/tls.crt" --key="${OUT}/tls.key" \
  -n "${NS}" --dry-run=client -o yaml >"${OUT}/tls-secret.yaml"

echo "certs written to ${OUT}"
