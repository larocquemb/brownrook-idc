# Portable Kubernetes deployment

BrownRook IDC uses one Helm chart for K3s and Amazon EKS. The shared chart is
the application source of truth; platform-specific values contain only the
differences required by each target.

## Profiles

| Target | Values file | Important mapping |
| --- | --- | --- |
| Portable baseline | `values.yaml` | Secure workload defaults with no ingress |
| Brown Rook K3s | `values-k3s.yaml` | Traefik ingress class and host-level spreading |
| Amazon EKS DR | `values-eks.yaml` | Internal ALB ingress class and zone spreading |

Ingress is disabled in both platform profiles. Enabling it is an operator
decision because the host, certificate, and permitted source networks are
environment-specific. The EKS profile deliberately uses an internal ALB by
default.

## Secret contract

The chart references an existing Kubernetes Secret and never places OIDC
credentials in a manifest or Helm release value. Create it through the
approved external secret manager. This imperative example is suitable only
for a local smoke environment:

```bash
kubectl -n idc create secret generic brownrook-idc-oidc \
  --from-literal=tenant-id='<tenant UUID>' \
  --from-literal=client-id='<application UUID>'
```

The required key names can be changed through `oidc.tenantIdKey` and
`oidc.clientIdKey`.

## Render and validate

```bash
make validate-k8s
```

This lints and renders the portable, K3s, and EKS profiles and performs offline
structural checks against the rendered security, topology, and secret contract.
It does not invoke kubectl or contact a cluster.

Run the complete disposable-cluster test when Docker is available:

```bash
make smoke-kind
```

The smoke test builds the application image, creates an isolated Kind cluster,
installs the K3s profile with dummy OIDC identifiers, verifies `/health`, and
deletes the cluster. It never uses the current kubectl context.

## Install on K3s

Use an immutable image tag or digest and supply the real cluster name:

```bash
helm upgrade --install idc deploy/helm/brownrook-idc \
  --namespace idc --create-namespace \
  --values deploy/helm/brownrook-idc/values-k3s.yaml \
  --set image.tag='<git SHA>' \
  --set deployment.clusterName='brownrook-k3s'
```

Before enabling ingress, label the ingress-controller namespace to satisfy the
default NetworkPolicy or replace the selector with an approved source:

```bash
kubectl label namespace kube-system \
  network-policy.brownrook.com/idc-ingress=true
```

## Install on EKS

Use the same chart and release version with the EKS profile:

```bash
helm upgrade --install idc deploy/helm/brownrook-idc \
  --namespace idc --create-namespace \
  --values deploy/helm/brownrook-idc/values-eks.yaml \
  --set image.tag='<same git SHA>' \
  --set deployment.clusterName='<EKS cluster name>'
```

Set `networkPolicy.allowedIngressCidrs` to the approved VPC or load-balancer
source ranges before enabling the ALB ingress. Configure DNS and certificates
outside the application chart through the platform GitOps layer.

## Portability and rollback rules

- Application templates must not reference K3s-only or AWS-only APIs.
- Platform integrations belong in explicitly named values files or platform
  bootstrap repositories.
- Production releases use an immutable tag or `image.digest`.
- Roll back with `helm rollback idc <revision>` using the same target values.
- Secret values, kubeconfigs, cloud keys, and private keys must never be passed
  as committed Helm values.
- The chart does not provision EKS, Route 53, storage, backup repositories, or
  offsite dependencies. Those remain KAN-133 infrastructure work.
