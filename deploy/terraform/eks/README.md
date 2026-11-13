# Farrier on EKS (Terraform reference module)

Creates the AWS side of a Farrier install on an **existing** EKS cluster, and hands the Helm chart
(`deploy/helm/farrier`) the values to use it. It never creates a cluster, VPC, node group or load
balancer; the chart runs the engine and web.

```
engine pods (SA farrier-engine) ─IRSA / Pod Identity─> engine role ─> Secrets Manager farrier/* (device credentials)
                                                                    ├─> KMS CMK (unwraps the master key at boot)
                                                                    ├─> S3 (SSE-KMS, versioned, TLS-only)
                                                                    └─> RDS PostgreSQL (private, CMK, TLS) ← cluster SG
External Secrets (SecretStore <name>-aws) ─> ESO role ─> <name>-runtime/* + RDS secret ─> Kubernetes Secrets
```

## What it creates

| Area | Resources |
| --- | --- |
| Identity | Engine role (IRSA trust on `system:serviceaccount:<namespace>:<service_account_name>`, or a Pod Identity association) with its Secrets Manager prefix, Encrypt/Decrypt/GenerateDataKey on the CMK, S3 on its prefix, optional Route 53 `_acme-challenge` TXT changes and `events:PutEvents` on `event_bus_arn`. External Secrets role: read-only on the runtime secrets and the RDS secret. No access keys. |
| Keys | One KMS CMK with rotation: wraps the Farrier master key; encrypts S3, Secrets Manager and RDS |
| Secrets | `<name>-runtime/api-token`, `api-read-token`, `session-secret` (OIDC) or `dashboard-password` (generated), `master-key` and `oidc-client-secret` (empty: you seed them) |
| Storage | S3 bucket as in the `aws` module: SSE-KMS, versioning, Block Public Access, BucketOwnerEnforced, TLS ≥ 1.2 only, object writes denied to every principal but the engine role and `storage_admin_principal_arns`, lifecycle rules |
| Database (`create_database`) | RDS PostgreSQL 16, CMK-encrypted, Multi-AZ, private, `rds.force_ssl=1`, password managed by RDS in Secrets Manager, 14-day backups, deletion protection; security group allows 5432 from the cluster security group and `db_allowed_cidrs` |

## Inputs

All inputs are documented in `variables.tf`; the important ones:

| Name | Default | Notes |
| --- | --- | --- |
| `cluster_name` | (required) | Existing cluster; its OIDC issuer, VPC, subnets and cluster SG are read |
| `namespace`, `service_account_name` | `farrier`, `farrier-engine` | Must match the Helm release |
| `identity` | `irsa` | `irsa` or `pod_identity` (see below) |
| `oidc_enabled` | `false` | `true`: generated session secret + seeded OIDC client secret; `false`: generated dashboard password |
| `create_database` | `true` | RDS PostgreSQL; `false` leaves the database to you (or SQLite) |
| `vpc_id`, `database_subnet_ids` | cluster's | Override when RDS should live in other (isolated) subnets |
| `db_allowed_cidrs` | `[]` | Nodes without the cluster SG (self-managed node groups, security groups for pods) |
| `db_instance_class`, `db_multi_az` | `db.t4g.medium`, `true` | |
| `route53_zone_ids` | `[]` | Zones for DNS-01 |
| `assumable_role_arns` | `[]` | Roles in other accounts the engine may assume (`aws_acm` connector `role_arn`, `cloud_inventory.aws_accounts`) |
| `event_bus_arn` | `""` | EventBridge bus, e.g. from `deploy/terraform/aws-events` |
| `secret_store_prefix`, `storage_prefix` | `farrier/` | Engine's Secrets Manager and S3 prefixes |
| `storage_admin_principal_arns` | `[]` | Roles besides the engine role that may write or delete bucket objects |
| `external_secrets_service_account_name` | `farrier-external-secrets` | IRSA only |
| `deletion_protection` | `true` | RDS |

## Outputs

`helm_values` (values file for the chart), `kubernetes_manifests` (External Secrets ServiceAccount and
SecretStore), `engine_role_arn`, `external_secrets_role_arn`, `kms_key_arn`, `bucket_name`,
`master_key_secret_arn`, `database_endpoint`, `database_secret_arn` (the last two null without a database).

## Prerequisites

- The External Secrets Operator (`external-secrets.io/v1`, ESO ≥ 0.17) in the cluster.
- `identity = "irsa"`: the cluster's IAM OIDC provider must exist:
  `eksctl utils associate-iam-oidc-provider --cluster <cluster> --approve`.
- `identity = "pod_identity"`: the `eks-pod-identity-agent` add-on.
- Pods must reach Secrets Manager, KMS, S3 and STS (NAT or VPC endpoints), and the engine your devices.

## Install

```bash
cd deploy/terraform/eks/examples/minimal     # or call the module from your own root
terraform init
terraform apply
```

### Seed the master key

The master key never passes through Terraform. Generate it on a trusted machine, wrap it with the
CMK, and store only the ciphertext:

```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode(), end='')" > master.key
aws kms encrypt --key-id "$(terraform output -raw kms_key_arn)" \
  --plaintext fileb://master.key --query CiphertextBlob --output text > master.key.wrapped
aws secretsmanager put-secret-value --secret-id "$(terraform output -raw master_key_secret_arn)" \
  --secret-string "$(cat master.key.wrapped)"
```

Escrow `master.key` offline according to your key-management policy (or destroy it: then the CMK is
the only way to unwrap it, so its deletion means losing every sealed private key), then `shred -u master.key`.

With `oidc_enabled = true`, store the client secret the same way (no wrapping):

```bash
aws secretsmanager put-secret-value --secret-id farrier-runtime/oidc-client-secret --secret-string '<client secret>'
```

### Install the chart

```bash
kubectl create namespace farrier
terraform output -raw kubernetes_manifests | kubectl apply -f -
kubectl -n farrier create secret generic farrier-db-ca \
  --from-file=ca.crt=<(curl -s https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem)
terraform output -raw helm_values > cloud-values.yaml
helm install farrier deploy/helm/farrier -n farrier \
  -f deploy/helm/farrier/examples/values-eks.yaml -f cloud-values.yaml
helm test farrier -n farrier                       # dashboard / and engine /healthz from inside
curl -fsS https://<dashboard host>/api/health      # through the ALB
```

Set the dashboard's host, ingress and (with OIDC) issuer and client ID in your own values file, after
`cloud-values.yaml`.

## IRSA or Pod Identity

With **IRSA** each identity is scoped to one ServiceAccount: the engine role to the engine's, and the
External Secrets role to `farrier-external-secrets`, which the `SecretStore` uses through
`auth.jwt`. Only that `SecretStore` can read the runtime secrets.

With **Pod Identity**, a `SecretStore` cannot name its own ServiceAccount (`auth.jwt` is IRSA-only),
so the External Secrets role is associated with the **ESO controller's** ServiceAccount
(`external_secrets_controller_namespace`/`external_secrets_controller_service_account`) and the
`SecretStore` has no `auth` block. The trade-off: any `SecretStore` served by that controller without
its own credentials (in any namespace) can read these secrets. Prefer IRSA on shared clusters.

## Operations

- **Database password rotation.** RDS rotates the managed master password every 7 days by default.
  ESO re-reads it on `secrets.externalSecrets.refreshInterval` (1h) and the engine reads the mounted
  file at every (re)connect, so no restart is needed; new connections can fail for up to one refresh
  interval after a rotation, so lower the interval if that matters.
- **Backups.** RDS automated backups and the final snapshot; S3 versioning. A backup is useless
  without the master key: keep the CMK (and any escrowed copy) for as long as the backups.

## Teardown

```bash
helm uninstall farrier -n farrier
terraform apply -var deletion_protection=false
terraform destroy
```

RDS takes a final snapshot (`<name>-final`). The bucket is kept unless it is empty or
`force_destroy_bucket = true`. Secrets and the KMS key enter their recovery / deletion windows.
