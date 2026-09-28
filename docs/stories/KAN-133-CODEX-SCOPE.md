# KAN-133 unattended implementation scope

Jira story: [KAN-133](https://brownrook.atlassian.net/browse/KAN-133)

## Objective

Deliver the first safe, repository-local tranche of KAN-133: package the
BrownRook IDC representative application so the same release can target K3s
or EKS without modifying its shared Kubernetes templates.

## Included in this tranche

- A provider-neutral Helm application base.
- Explicit K3s and EKS values profiles.
- External secret references without plaintext credentials.
- Health probes, resource limits, topology spreading, disruption protection,
  pod hardening, and workload NetworkPolicy.
- Static rendering and offline structural validation for all profiles.
- A disposable Kind deployment and `/health` smoke test.
- CI integration and an operator deployment/rollback guide.

## Evidence required

- Existing Python tests pass.
- `make validate-k8s` passes for portable, K3s, and EKS profiles.
- `make smoke-kind` successfully deploys the image and verifies `/health` when
  a Docker service is available.
- The rendered manifests contain no Kubernetes Secret resource.
- The K3s and EKS profiles render from the same application chart.

## Deliberately deferred approval gates

The following KAN-133 acceptance criteria cannot be safely performed as an
unattended repository task and are not claimed complete by this tranche:

- Creating AWS accounts, IAM, KMS, VPC, EKS, Route 53, budgets, or other
  billable resources.
- Reading or changing the live K3s cluster.
- Selecting production storage, backup, identity, or secret providers.
- Restoring production data.
- Changing DNS or production traffic.
- Running failover, failback, teardown, or site-unavailable DR exercises.

Those actions require approved credentials, budgets, environment inputs,
maintenance windows, and explicit operational authority.
