#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
chart_dir="${repo_root}/deploy/helm/brownrook-idc"
cluster_name="${KIND_CLUSTER_NAME:-brownrook-idc-smoke-$$}"
namespace="${KIND_NAMESPACE:-idc}"
image_tag="brownrook-idc:smoke-$$"
local_port="${KIND_SMOKE_PORT:-18080}"
cluster_created=false
port_forward_pid=""

diagnostics() {
  if [[ "${cluster_created}" == "true" ]]; then
    kubectl --context "kind-${cluster_name}" --namespace "${namespace}" get all || true
    kubectl --context "kind-${cluster_name}" --namespace "${namespace}" describe pods || true
    kubectl --context "kind-${cluster_name}" --namespace "${namespace}" logs \
      --selector app.kubernetes.io/name=brownrook-idc --all-containers --tail=200 || true
  fi
}

cleanup() {
  local exit_code=$?
  if [[ ${exit_code} -ne 0 ]]; then
    diagnostics
  fi
  if [[ -n "${port_forward_pid}" ]]; then
    kill "${port_forward_pid}" >/dev/null 2>&1 || true
  fi
  if [[ "${cluster_created}" == "true" ]]; then
    kind delete cluster --name "${cluster_name}" >/dev/null
  fi
  exit "${exit_code}"
}
trap cleanup EXIT

for command_name in curl docker helm kind kubectl python3; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "required command not found: ${command_name}" >&2
    exit 1
  fi
done

if ! docker info >/dev/null 2>&1; then
  echo "Docker is not reachable. Start the configured Docker/Colima service and retry." >&2
  exit 1
fi

docker build --tag "${image_tag}" "${repo_root}"
kind create cluster --name "${cluster_name}" --wait 120s
cluster_created=true
kind load docker-image --name "${cluster_name}" "${image_tag}"

kubectl --context "kind-${cluster_name}" create namespace "${namespace}"
kubectl --context "kind-${cluster_name}" --namespace "${namespace}" create secret generic \
  brownrook-idc-oidc \
  --from-literal=tenant-id=00000000-0000-0000-0000-000000000000 \
  --from-literal=client-id=11111111-1111-1111-1111-111111111111

helm upgrade --install idc "${chart_dir}" \
  --kube-context "kind-${cluster_name}" \
  --namespace "${namespace}" \
  --values "${chart_dir}/values-k3s.yaml" \
  --set image.repository="${image_tag%%:*}" \
  --set image.tag="${image_tag##*:}" \
  --set image.pullPolicy=Never \
  --set replicaCount=1 \
  --set podDisruptionBudget.enabled=false \
  --set networkPolicy.enabled=false \
  --set topologySpread.enabled=false \
  --wait \
  --timeout 180s

kubectl --context "kind-${cluster_name}" --namespace "${namespace}" rollout status \
  deployment/idc-brownrook-idc --timeout=120s

kubectl --context "kind-${cluster_name}" --namespace "${namespace}" port-forward \
  service/idc-brownrook-idc "${local_port}:80" >"${TMPDIR:-/tmp}/brownrook-idc-port-forward.log" 2>&1 &
port_forward_pid=$!

health_response=""
for _ in $(seq 1 30); do
  if health_response="$(curl --fail --silent "http://127.0.0.1:${local_port}/health" 2>/dev/null)"; then
    break
  fi
  sleep 1
done

python3 -c 'import json,sys; data=json.loads(sys.argv[1]); assert data["status"] == "ok"' \
  "${health_response}"

echo "Kind smoke test passed: ${health_response}"
