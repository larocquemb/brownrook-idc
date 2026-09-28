#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
chart_dir="${repo_root}/deploy/helm/brownrook-idc"
temp_dir="$(mktemp -d)"

cleanup() {
  rm -rf "${temp_dir}"
}
trap cleanup EXIT

for command_name in helm; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "required command not found: ${command_name}" >&2
    exit 1
  fi
done

python_command="${PYTHON:-python3}"
if ! "${python_command}" -c 'import yaml' >/dev/null 2>&1; then
  if [[ -x "${repo_root}/.venv/bin/python" ]] && \
    "${repo_root}/.venv/bin/python" -c 'import yaml' >/dev/null 2>&1; then
    python_command="${repo_root}/.venv/bin/python"
  else
    echo "PyYAML is required; install the project development dependencies" >&2
    exit 1
  fi
fi

render_profile() {
  local profile_name="$1"
  local values_file="$2"
  local output_file="${temp_dir}/${profile_name}.yaml"

  helm lint "${chart_dir}" --values "${values_file}"
  helm template idc "${chart_dir}" \
    --namespace idc \
    --values "${values_file}" \
    --set ingress.enabled=true \
    --set image.repository=example.invalid/brownrook-idc \
    --set image.tag=validation \
    >"${output_file}"

  "${python_command}" "${repo_root}/scripts/validate_rendered_manifests.py" \
    "${output_file}" --profile "${profile_name}"
}

render_profile portable "${chart_dir}/values.yaml"
render_profile k3s "${chart_dir}/values-k3s.yaml"
render_profile eks "${chart_dir}/values-eks.yaml"

grep -q 'ingressClassName: traefik' "${temp_dir}/k3s.yaml"
grep -q 'topologyKey: kubernetes.io/hostname' "${temp_dir}/k3s.yaml"
grep -q 'ingressClassName: alb' "${temp_dir}/eks.yaml"
grep -q 'topologyKey: topology.kubernetes.io/zone' "${temp_dir}/eks.yaml"

helm template idc "${chart_dir}" \
  --namespace idc \
  --set autoscaling.enabled=true \
  --set podDisruptionBudget.enabled=false \
  >"${temp_dir}/autoscaling.yaml"
grep -q 'kind: HorizontalPodAutoscaler' "${temp_dir}/autoscaling.yaml"

echo "Kubernetes packaging validation passed for portable, K3s, and EKS profiles."
