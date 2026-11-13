# Farrier on Google Cloud (Terraform reference module)

Runs Farrier on Cloud Run with Cloud SQL for PostgreSQL, Cloud Storage, Secret Manager and Cloud KMS,
behind a global external Application Load Balancer with Cloud CDN and Cloud Armor. The engine has
internal ingress only.

```
Internet ─HTTPS─> global external ALB (Cloud Armor, TLS 1.2+ MODERN policy, managed cert)
                     ├─ /_next/static/*, /assets/*  ─> backend with Cloud CDN ─┐
                     └─ everything else             ─> backend, no CDN ────────┴─> Cloud Run web
                                                                (ingress: load balancer only)
Cloud Run web ─Direct VPC egress─> Cloud Run engine (ingress: internal only, min 1, CPU always allocated)
Cloud Run engine ─Direct VPC egress─> Cloud SQL (private IP, TLS) · devices · Cloud NAT ─> ACME CAs
                 └─> GCS (CMEK, versioned) · Secret Manager · Cloud KMS (unwraps the master key)
```

## What it creates

| Area | Resources |
| --- | --- |
| APIs | Run, SQL Admin, Secret Manager, KMS, Compute, Service Networking, Artifact Registry (`enable_apis`) |
| Images | An Artifact Registry **remote repository** proxying `ghcr.io` (Cloud Run cannot pull from ghcr.io directly) |
| Network (optional) | `create_network = true`: VPC, subnet with Private Google Access and flow logs, Cloud Router + Cloud NAT. Otherwise you bring them. Private services access for Cloud SQL (`create_private_service_access`). |
| Compute | Cloud Run engine: `INGRESS_TRAFFIC_INTERNAL_ONLY`, min 1 instance, CPU always allocated (the renewal loop runs in the background), Direct VPC egress. Cloud Run web: `INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER`, Direct VPC egress (all traffic, so its calls to the engine are internal). |
| Edge | Global external ALB (EXTERNAL_MANAGED), Google-managed certificate for `domains`, SSL policy MODERN / TLS 1.2, HTTP→HTTPS redirect, Cloud CDN only on the static backend, Cloud Armor (per-IP rate limit or an allowlist) |
| Database | Cloud SQL PostgreSQL 16, Enterprise edition, private IP only (no public IP), `ssl_mode = ENCRYPTED_ONLY`, REGIONAL HA (toggle), backups + PITR, deletion protection, optional CMEK (`db_cmek`) |
| Keys | Key ring with `master-wrap` (wraps the Farrier master key), `storage` (bucket CMEK), optional `cloudsql`, 90-day rotation |
| Secrets | `<name>-runtime-api-token`, `-api-read-token`, `-db-password`, `-db-server-ca`, `-session-secret` or `-dashboard-password` (generated), `-master-key` and `-oidc-client-secret` (you add the version) |
| Storage | GCS bucket: uniform bucket-level access, public access prevention enforced, CMEK, versioning, 7-day soft delete, lifecycle (`change-packs/` deleted after 30 days, noncurrent versions after 90) |
| IAM | Engine SA: `secretAccessor` on its runtime secrets; `secretAccessor` + `secretVersionAdder` (and, with `engine_can_create_secrets`, a custom create/delete role) on secrets under `secret_store_prefix` only, by IAM condition; `storage.objectAdmin` on the bucket; `cryptoKeyEncrypterDecrypter` on `master-wrap`; optional `dns.admin` on listed Cloud DNS zones. Web SA: `secretAccessor` on its own secrets only. |

The engine connects to Cloud SQL with `sslmode=verify-ca` against the instance's server CA, mounted
from Secret Manager at `/etc/farrier/db/server-ca.pem`. (Cloud SQL's per-instance CA does not name the
private IP, so `verify-full` would fail; `verify-ca` still pins the server to that CA.)

## Configuration the containers receive

Engine: `FARRIER_DATABASE_URL`, `FARRIER_DATABASE_PASSWORD`, `FARRIER_MASTER_KEY` (wrapped) +
`FARRIER_MASTER_KEY_KMS=gcp-kms:projects/…/cryptoKeys/master-wrap`, `FARRIER_API_TOKEN`,
`FARRIER_API_READ_TOKEN`, `FARRIER_SECRET_BACKEND=gcp`, `FARRIER_SECRET_GCP_PROJECT`,
`FARRIER_STORAGE_URL=gs://<bucket>/farrier`.

Web: `FARRIER_API_URL` (the engine's `run.app` URL), `NEXT_PUBLIC_SITE_URL`, the API tokens,
`FARRIER_TRUSTED_PROXY_HOPS=2` (the load balancer appends the client and its own address to
`X-Forwarded-For`), and either OIDC settings (`FARRIER_OIDC_REDIRECT_URI=<site>/auth/callback` included) + `FARRIER_SESSION_SECRET` + `FARRIER_OIDC_CLIENT_SECRET`, or `FARRIER_DASHBOARD_PASSWORD`.

Identity is the service account attached to each Cloud Run service. There are no keys. The engine's
service account is the only principal with a bucket-level role on the objects bucket (backups
included); keep project-level Owner, Editor and Storage Admin to break-glass admins, since `farrier
restore` trusts a backup's rows (backups are HMAC-signed; unsigned ones need `--allow-unsigned`).

## Inputs

| Name | Default | Notes |
| --- | --- | --- |
| `project_id` | (required) | |
| `region` | `europe-west1` | |
| `domains` | (required) | Dashboard hostnames |
| `name` | `farrier` | ≤ 15 characters |
| `farrier_version` | `0.2.0` | |
| `engine_image`, `web_image` | `""` | Override (Artifact Registry or Docker Hub) |
| `create_network`, `network_id`, `subnetwork_id` | `false`, `""`, `""` | Bring your own network |
| `create_private_service_access` | `true` | `false` if the VPC already peers with Service Networking |
| `engine_vpc_egress` | `ALL_TRAFFIC` | Engine egress through your VPC (one NAT IP to allowlist) |
| `engine_min_instances`, `engine_max_instances` | `1`, `3` | |
| `db_tier`, `db_high_availability`, `db_cmek` | `db-custom-1-3840`, `true`, `false` | |
| `enable_cloud_armor`, `allowed_source_ranges`, `rate_limit_per_minute` | `true`, `[]`, `1200` | |
| `dns_managed_zones` | `[]` | Cloud DNS zones for DNS-01 |
| `oidc_issuer`, `oidc_client_id`, `oidc_scopes`, `web_extra_env` | | SSO |
| `secrets_seeded` | `false` | Services are created only once this is `true` |
| `deletion_protection` | `true` | Cloud SQL and Cloud Run |

## Outputs

`dashboard_url`, `lb_ip_address`, `engine_internal_url`, `bucket`, `storage_url`,
`master_wrap_key_id`, `secret_ids`, `master_key_secret_id`, `engine_service_account`,
`database_private_ip`, `dashboard_password` (sensitive; only without OIDC).

## Apply

```bash
cd deploy/terraform/gcp/examples/minimal
terraform init
terraform apply                    # 1. everything except the Cloud Run services
```

Point the A record of each domain at `lb_ip_address`. The certificate becomes active once DNS
resolves (usually 15-60 minutes).

### Seed the secrets

```bash
KEY=$(terraform output -raw master_wrap_key_id)
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode(), end='')" > master.key
gcloud kms encrypt --key "$KEY" --plaintext-file master.key --ciphertext-file master.key.enc
base64 -w0 master.key.enc | gcloud secrets versions add farrier-runtime-master-key --data-file=-
shred -u master.key master.key.enc   # after escrowing master.key per your key policy

# with OIDC on:
printf '%s' '<client secret>' | gcloud secrets versions add farrier-runtime-oidc-client-secret --data-file=-
```

Register `https://<domain>/auth/callback` (redirect) and `https://<domain>/auth/signin?signed_out=1`
(sign-out redirect) with your identity provider.

```bash
terraform apply -var secrets_seeded=true    # 2. start the engine and web services
```

## Bring your own network

Set `network_id` and `subnetwork_id` (in `region`). The subnet needs:

- **Private Google Access**, so the web service's VPC egress reaches the engine's `run.app` URL internally.
- **Cloud NAT** (or another egress path) for ACME CAs, DNS APIs and your OIDC issuer.
- **Routes to your devices' management networks** (Cloud VPN, Interconnect, peering), and firewall
  rules allowing the subnet range to reach them.
- Free addresses for Direct VPC egress (Cloud Run uses about two per instance, for scaling headroom).

If the VPC already has private services access, set `create_private_service_access = false`.

**GKE instead of Cloud Run**: use `deploy/kubernetes` with Workload Identity (see
`deploy/kubernetes/README.md`) and keep the Cloud SQL, GCS, KMS and Secret Manager parts of this
module by setting `secrets_seeded = false` permanently, binding the module's engine service account
to the Kubernetes service account with `roles/iam.workloadIdentityUser`.

## Cost notes

Defaults, roughly: engine min 1 instance with CPU always allocated (~$45/month for 1 vCPU/1 GiB), web
min 1 (~$10-15/month idle), Cloud SQL `db-custom-1-3840` REGIONAL (~$100/month), global load balancer
forwarding rules (~$18/month each, two), Cloud Armor policy ($5/month + $1/rule), Cloud NAT if
created, KMS keys (cents), Secret Manager (cents). For a lab: `db_high_availability = false`,
`web_min_instances = 0`, `enable_cloud_armor = false`.

## Operations

- **Upgrades**: change `farrier_version`; Cloud Run rolls a new revision. The engine finishes its cycle
  on `SIGTERM` (`--grace 20`).
- **Database password**: rotating it means a new `random_password` (taint it) and a new Cloud Run
  revision; the engine reads `FARRIER_DATABASE_PASSWORD` at start.
- **Server CA rotation**: when you rotate the Cloud SQL server CA, re-apply so `db-server-ca` gets the new certificate.

## Teardown

```bash
terraform apply -var deletion_protection=false -var secrets_seeded=false
terraform destroy
```

Key rings and keys cannot be deleted in Cloud KMS: key versions are scheduled for destruction, and
the ring name stays taken. Custom roles are soft-deleted for 7 days. The bucket is kept unless empty
or `force_destroy_bucket = true`.
