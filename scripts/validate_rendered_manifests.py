#!/usr/bin/env python3
"""Offline structural checks for rendered BrownRook IDC Kubernetes manifests."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import yaml


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def find_resource(resources: list[dict[str, Any]], kind: str) -> dict[str, Any]:
    matches = [resource for resource in resources if resource.get("kind") == kind]
    require(len(matches) == 1, f"expected one {kind}, found {len(matches)}")
    return matches[0]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--profile", required=True, choices=("portable", "k3s", "eks"))
    args = parser.parse_args()

    documents = list(yaml.safe_load_all(args.manifest.read_text()))
    resources = [document for document in documents if isinstance(document, dict)]
    require(resources, "rendered manifest contains no Kubernetes resources")
    require(not any(resource.get("kind") == "Secret" for resource in resources), "Secret rendered")

    for resource in resources:
        require(bool(resource.get("apiVersion")), "resource is missing apiVersion")
        require(bool(resource.get("kind")), "resource is missing kind")
        require(bool(resource.get("metadata", {}).get("name")), "resource is missing metadata.name")

    deployment = find_resource(resources, "Deployment")
    pod_spec = deployment["spec"]["template"]["spec"]
    require(pod_spec["automountServiceAccountToken"] is False, "service account token is mounted")
    require(pod_spec["securityContext"]["runAsNonRoot"] is True, "runAsNonRoot is not enabled")

    containers = pod_spec.get("containers", [])
    require(len(containers) == 1, "expected exactly one application container")
    container = containers[0]
    security_context = container["securityContext"]
    require(security_context["allowPrivilegeEscalation"] is False, "privilege escalation allowed")
    require(security_context["readOnlyRootFilesystem"] is True, "root filesystem is writable")
    require("ALL" in security_context["capabilities"]["drop"], "Linux capabilities not dropped")
    require(container.get("startupProbe") is not None, "startup probe missing")
    require(container.get("readinessProbe") is not None, "readiness probe missing")
    require(container.get("livenessProbe") is not None, "liveness probe missing")
    require(container.get("resources", {}).get("requests"), "resource requests missing")
    require(container.get("resources", {}).get("limits"), "resource limits missing")

    env_by_name = {item["name"]: item for item in container.get("env", [])}
    for variable in ("TENANT_ID", "CLIENT_ID"):
        require(variable in env_by_name, f"{variable} missing")
        require(
            "secretKeyRef" in env_by_name[variable].get("valueFrom", {}),
            f"{variable} is not secret-backed",
        )
        require("value" not in env_by_name[variable], f"{variable} rendered as plaintext")

    expected_profile = {"portable": "portable", "k3s": "k3s", "eks": "eks-dr"}[args.profile]
    require(
        env_by_name["DEPLOYMENT_PROFILE"].get("value") == expected_profile,
        "wrong deployment profile",
    )

    expected_topology = {
        "portable": "kubernetes.io/hostname",
        "k3s": "kubernetes.io/hostname",
        "eks": "topology.kubernetes.io/zone",
    }[args.profile]
    constraints = pod_spec.get("topologySpreadConstraints", [])
    require(
        constraints and constraints[0].get("topologyKey") == expected_topology, "wrong topology key"
    )

    find_resource(resources, "Service")
    find_resource(resources, "ServiceAccount")
    find_resource(resources, "PodDisruptionBudget")
    find_resource(resources, "NetworkPolicy")

    ingress = find_resource(resources, "Ingress")
    expected_ingress_class = {"portable": None, "k3s": "traefik", "eks": "alb"}[args.profile]
    require(
        ingress["spec"].get("ingressClassName") == expected_ingress_class, "wrong ingress class"
    )


if __name__ == "__main__":
    main()
