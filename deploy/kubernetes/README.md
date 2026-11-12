# Farrier on Kubernetes

Manifests for EKS, GKE, AKS, OpenShift and any conformant cluster. See `/docs/deploy` for the full
walkthrough and `/docs/enterprise` for the cloud reference architectures.

| File | What it creates |
| --- | --- |
| `farrier.yaml` | Engine StatefulSet (1 replica on SQLite), ClusterIP Service, ServiceAccount without a token |
| `web.yaml` | Dashboard Deployment (2 replicas) and Service |
| `network-policy.yaml` | Only the dashboard (and a `monitoring` namespace) may reach the engine |
| `ingress.example.yaml` | Dashboard ingress with TLS and a source-range allowlist |
| `secrets.example.yaml` | The secrets to create by hand, with the commands that generate them |
| `external-secrets/*.yaml` | The same `farrier-secrets` Secret synced from AWS Secrets Manager, Google Secret Manager, Azure Key Vault or HashiCorp Vault |

```bash
kubectl create namespace farrier
kubectl apply -f external-secrets/aws.yaml     # or gcp.yaml, azure.yaml, vault.yaml; or your secrets.yaml
kubectl apply -k .
```

## Secrets from your cloud secret manager

Install the [External Secrets Operator](https://external-secrets.io) (v0.16 or later, for the
`external-secrets.io/v1` API), edit the placeholders in the file for your cloud, and apply it. Each file
creates a dedicated `farrier-external-secrets` ServiceAccount, a namespaced `SecretStore`
authenticated by the platform identity, and an `ExternalSecret` that writes `farrier-secrets` with
the keys the manifests read (`api-token`, `dashboard-password`, `master-key`). No cloud credentials
are stored in the cluster.

The secret names match what the Terraform modules in `deploy/terraform` create, so you can run the
data tier (database, bucket, keys, secrets) from a module and the workloads on your own cluster.

## Platform identity for the engine

With `FARRIER_SECRET_BACKEND=aws|gcp|azure|hashicorp` or object storage (`FARRIER_STORAGE_URL=s3://`,
`gs://`, `azblob://`) the engine itself calls cloud APIs. Give it a workload identity; never mount
static keys.

**EKS: IAM Roles for Service Accounts (or EKS Pod Identity).** Create a role trusted by the cluster's
OIDC provider for `system:serviceaccount:farrier:farrier` with the engine policy from
`deploy/terraform/aws/iam.tf` (its Secrets Manager prefix, the CMK, its S3 prefix), then annotate the
ServiceAccount. The pod identity webhook mounts its own projected token, so
`automountServiceAccountToken: false` can stay.

```yaml
metadata:
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/farrier-engine
```

**GKE: Workload Identity Federation.** Bind the Google service account (for example the engine
service account from `deploy/terraform/gcp`) to the Kubernetes one, and annotate it:

```bash
gcloud iam service-accounts add-iam-policy-binding farrier-engine@my-project.iam.gserviceaccount.com \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:my-project.svc.id.goog[farrier/farrier]"
```

```yaml
metadata:
  annotations:
    iam.gke.io/gcp-service-account: farrier-engine@my-project.iam.gserviceaccount.com
```

**AKS: Microsoft Entra Workload ID.** Enable the OIDC issuer and workload identity on the cluster,
add a federated credential on the engine's user-assigned identity for subject
`system:serviceaccount:farrier:farrier`, annotate the ServiceAccount with
`azure.workload.identity/client-id: <client id>`, and label the engine pod template with
`azure.workload.identity/use: "true"` so the webhook injects the token and `AZURE_*` variables.

**HashiCorp Vault: Kubernetes auth.** Set `FARRIER_SECRET_VAULT_ADDR`, `FARRIER_SECRET_VAULT_MOUNT`
and `FARRIER_SECRET_VAULT_ROLE` on the engine. Vault's Kubernetes auth needs a service account token,
so set `automountServiceAccountToken: true` on the engine ServiceAccount (or mount a projected token)
and bind the Vault role to `farrier/farrier`.

Apply these as a kustomize overlay rather than editing the base manifests, for example:

```yaml
# overlays/aws/kustomization.yaml
resources: [../../deploy/kubernetes]
patches:
  - target: { kind: ServiceAccount, name: farrier }
    patch: |
      - op: add
        path: /metadata/annotations
        value: { eks.amazonaws.com/role-arn: "arn:aws:iam::123456789012:role/farrier-engine" }
```

## More than one engine replica

The base StatefulSet runs one replica because SQLite has one writer. With PostgreSQL
(`FARRIER_DATABASE_URL`, see `/docs/databases`) raise `replicas`, set
`terminationGracePeriodSeconds: 45`, and give every replica the same `FARRIER_MASTER_KEY` (or the same
wrapped key plus `FARRIER_MASTER_KEY_KMS`).
