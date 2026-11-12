# Farrier on GKE (Terraform reference module)

Creates the Google Cloud side of a Farrier install on an **existing** GKE cluster. The Helm chart
(`deploy/helm/farrier`) runs the engine and dashboard; this module gives them identities, secrets,
a key, a bucket and (optionally) a database, and outputs the Helm values and Kubernetes manifests
that wire them together. It never creates a cluster, a VPC or a load balancer.

```
engine pod (KSA farrier-engine) ─Workload Identity─> <name>-engine GSA
  ├─> Secret Manager (secrets under secret_store_prefix) · Cloud KMS master-wrap · GCS bucket
  └─> Cloud SQL private IP (TLS, verify-ca)
External Secrets (KSA farrier-external-secrets) ─Workload Identity─> <name>-eso GSA
  └─> Secret Manager <name>-runtime-* (read only) ─> Kubernetes Secrets the chart reads
```

## What it creates

| Area | Resources |
| --- | --- |
| APIs | KMS, IAM Credentials, Secret Manager, Storage, SQL Admin (`enable_apis`) |
| Identity | Engine GSA `<name>-engine` and External Secrets GSA `<name>-eso`, each bound with `roles/iam.workloadIdentityUser` to `<project>.svc.id.goog[<namespace>/<KSA>]` |
| IAM | Engine: `secretAccessor` + `secretVersionAdder` (and, with `engine_can_create_secrets`, a custom create/delete role) on secrets under `secret_store_prefix` only, by IAM condition excluding `<name>-runtime-*`; `cryptoKeyEncrypterDecrypter` on `master-wrap`; `storage.objectAdmin` on the bucket. External Secrets: `secretAccessor` on each runtime secret, nothing else. |
| Keys | Key ring `<name>` with `master-wrap` (wraps the Farrier master key), 90-day rotation |
| Secrets | `<name>-runtime-api-token`, `-api-read-token`, `-db-password` (with `create_database`), `-session-secret` or `-dashboard-password` (generated), `-master-key` and `-oidc-client-secret` (you add the version) |
| Storage | GCS bucket: uniform bucket-level access, public access prevention enforced, versioning, 7-day soft delete, lifecycle (`change-packs/` deleted after 30 days, noncurrent versions after 90). Only the engine and `storage_admin_members` get a bucket-level role. |
| Database (optional) | Cloud SQL PostgreSQL 16, private IP only on `network`, `ssl_mode = ENCRYPTED_ONLY`, REGIONAL HA (toggle), backups + PITR, deletion protection, database and user `farrier` with a generated password |

Generated tokens and the database password are in Terraform state: use an encrypted backend. The
wrapped master key and the OIDC client secret are never in state.

The engine connects to Cloud SQL with `sslmode=verify-ca` against the instance's server CA, which
`kubernetes_manifests` puts in the Secret `farrier-db-ca` (mounted at `/etc/farrier/db-tls/ca.crt`).
Cloud SQL's per-instance CA does not name the private IP, so `verify-full` would fail; `verify-ca`
still pins the server to that CA.

## Prerequisites

- **Workload Identity Federation for GKE** enabled on the cluster *and* on the node pools that run
  Farrier (GKE metadata server, `--workload-metadata=GKE_METADATA`). Autopilot has both.
- **External Secrets Operator** (>= 0.17, for `external-secrets.io/v1`) installed in the cluster.
- With `create_database = true`: **private services access** already set up on `network` (an
  allocated range peered with `servicenetworking.googleapis.com`), and the cluster in that VPC.

## Inputs

| Name | Default | Notes |
| --- | --- | --- |
| `project_id` | (required) | |
| `cluster_name`, `cluster_location` | (required) | For the SecretStore's Workload Identity auth |
| `cluster_project_id` | `""` | Cluster's project, if not `project_id` (its `.svc.id.goog` pool) |
| `region` | `europe-west1` | Cloud SQL, bucket, key ring |
| `name` | `farrier` | ≤ 15 characters |
| `namespace` | `farrier` | Where the chart is installed |
| `service_account_name` | `farrier-engine` | The chart's `engine.serviceAccount.name` |
| `external_secrets_service_account_name` | `farrier-external-secrets` | Created by `kubernetes_manifests` |
| `oidc_enabled` | `false` | `true`: session secret + seeded OIDC client secret; `false`: generated dashboard password |
| `create_database`, `network` | `true`, `""` | `network` is required when creating the database |
| `db_tier`, `db_high_availability`, `db_disk_size_gb`, `db_backup_count` | `db-custom-1-3840`, `true`, `20`, `14` | |
| `secret_store_prefix`, `engine_can_create_secrets` | `farrier-`, `true` | If you change the prefix, set `FARRIER_SECRET_GCP_PREFIX` in `engine.config` too |
| `storage_prefix`, `storage_admin_members`, `force_destroy_bucket` | `farrier/`, `[]`, `false` | |
| `key_rotation_period` | `7776000s` | |
| `deletion_protection` | `true` | |

## Outputs

`helm_values` (Helm values snippet), `kubernetes_manifests` (External Secrets ServiceAccount +
SecretStore `<name>-gcp`, and the `farrier-db-ca` Secret; marked sensitive, `-raw` prints it),
`engine_service_account_email`, `external_secrets_service_account_email`, `kms_key_id`,
`bucket_name`, `master_key_secret_id`, `database_private_ip`, `dashboard_password` (sensitive).

## Deploy

```bash
cd deploy/terraform/gke/examples/minimal
terraform init
terraform apply
```

### Seed the secrets

```bash
KEY=$(terraform output -raw kms_key_id)
SECRET=$(terraform output -raw master_key_secret_id)
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode(), end='')" > master.key
gcloud kms encrypt --key "$KEY" --plaintext-file master.key --ciphertext-file master.key.enc
base64 -w0 master.key.enc | gcloud secrets versions add "$SECRET" --data-file=-
shred -u master.key master.key.enc   # after escrowing master.key per your key policy

# with oidc_enabled = true:
printf '%s' '<client secret>' | gcloud secrets versions add farrier-runtime-oidc-client-secret --data-file=-
```

External Secrets cannot sync a secret that has no version yet, so seed before installing the chart.

### Install

```bash
kubectl create namespace farrier
terraform output -raw kubernetes_manifests | kubectl apply -f -
terraform output -raw helm_values > cloud-values.yaml
helm install farrier deploy/helm/farrier -n farrier \
  -f deploy/helm/farrier/examples/values-gke.yaml -f cloud-values.yaml
```

With OIDC, set `web.auth.oidc.issuer` and `clientId` (and the dashboard's Ingress or HTTPRoute) in
your own values file. Then verify the dashboard answers on `/api/health` (for example
`kubectl -n farrier port-forward svc/farrier-web 8080:80` and `curl -fsS localhost:8080/api/health`)
and that the engine pods are ready.

## Direct principal binding instead of a GSA

Workload Identity Federation for GKE can also grant roles straight to the Kubernetes service
account (`principal://iam.googleapis.com/projects/<number>/locations/global/workloadIdentityPools/<project>.svc.id.goog/subject/ns/<namespace>/sa/<ksa>`),
with no Google service account and no `iam.gke.io/gcp-service-account` annotation. This module uses
GSAs because the chart and External Secrets' `workloadIdentity` auth expect one; to use direct
binding instead, grant the same roles to those principals and leave
`engine.serviceAccount.cloudIdentity.gcpServiceAccount` empty.

## Teardown

```bash
helm uninstall farrier -n farrier
terraform apply -var deletion_protection=false
terraform destroy
```

Key rings and keys cannot be deleted in Cloud KMS: key versions are scheduled for destruction, and
the ring name stays taken. Custom roles are soft-deleted for 7 days. The bucket is kept unless empty
or `force_destroy_bucket = true`.
