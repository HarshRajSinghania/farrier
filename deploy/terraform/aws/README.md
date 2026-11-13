# Farrier on AWS (Terraform reference module)

Runs Farrier on ECS Fargate with RDS PostgreSQL, S3, Secrets Manager and one customer-managed KMS
key, behind CloudFront. The engine has no public address and no public load balancer.

```
Internet ─HTTPS─> CloudFront ─VPC origin─> internal ALB (web) ─> web tasks (Fargate)
                  (caches /_next/static/*, /assets/* only)                │ FARRIER_API_URL
                                              internal ALB (engine) <─────┘ (web SG only)
                                                      │
                                              engine tasks ×2 ─> RDS PostgreSQL (private, CMK, TLS)
                                                      ├──────> S3 (SSE-KMS, versioned, TLS-only)
                                                      ├──────> Secrets Manager farrier/* (device credentials)
                                                      ├──────> KMS (unwraps the master key at boot)
                                                      └──────> your devices, ACME CAs, Route 53
```

## What it creates

| Area | Resources |
| --- | --- |
| Network (optional) | `create_vpc = true`: VPC, 2-4 private and public subnets, one NAT gateway. Otherwise none: you bring the VPC. |
| Compute | ECS cluster (Container Insights), engine service (`engine_desired_count`, default 2) and web service (2), Fargate ARM64, read-only root filesystems, all Linux capabilities dropped, no public IPs, deployment circuit breaker with rollback |
| Load balancing | Two **internal** ALBs. Web ALB accepts only the CloudFront origin-facing prefix list; engine ALB accepts only the web tasks' security group (plus `engine_api_allowed_cidrs`). Optional HTTPS on the engine ALB. |
| Edge | CloudFront with a VPC origin, HTTP/2+3, managed security headers, optional WAF (`web_acl_arn`), custom domains with TLSv1.2_2021 minimum |
| Database | RDS PostgreSQL 16, encrypted with the CMK, Multi-AZ (toggle), not publicly accessible, `rds.force_ssl=1`, password generated and stored in Secrets Manager by RDS, 14-day backups, deletion protection, final snapshot |
| Keys | One KMS CMK with rotation: wraps the Farrier master key; encrypts S3, Secrets Manager, RDS and CloudWatch Logs |
| Secrets | `<name>-runtime/api-token`, `api-read-token`, `session-secret` or `dashboard-password` (generated), `master-key` and `oidc-client-secret` (empty: you seed them) |
| Storage | S3 bucket: SSE-KMS with the CMK and bucket keys, versioning, all four Block Public Access settings, BucketOwnerEnforced, TLS-only (and TLS ≥ 1.2) bucket policy that also denies object writes and deletes to every principal but the engine task role and `storage_admin_principal_arns` (backups are restored as trusted rows; they are also HMAC-signed, and `farrier restore` needs `--allow-unsigned` for unsigned ones), lifecycle (`change-packs/` expire after 30 days, noncurrent versions after 90, incomplete uploads after 7) |
| IAM | Per-service execution and task roles. Engine: its Secrets Manager prefix only, Encrypt/Decrypt/GenerateDataKey on the CMK, S3 on its prefix only, optional Route 53 `_acme-challenge` TXT changes on listed zones. Web: read its own secrets only. |
| Logs | CloudWatch log groups per service, KMS-encrypted, `log_retention_days` (90) |

## Configuration the containers receive

Engine: `FARRIER_DATABASE_URL` (`sslmode=verify-full` against the RDS CA bundle, fetched over verified
TLS by a short-lived init container), `FARRIER_DATABASE_PASSWORD` (from the RDS-managed secret),
`FARRIER_MASTER_KEY` (the **wrapped** key from Secrets Manager) and `FARRIER_MASTER_KEY_KMS=aws-kms:<key arn>`,
`FARRIER_API_TOKEN`, `FARRIER_API_READ_TOKEN`, `FARRIER_SECRET_BACKEND=aws`, `FARRIER_SECRET_AWS_REGION`,
`FARRIER_SECRET_AWS_PREFIX`, `FARRIER_STORAGE_URL=s3://<bucket>/farrier`, `FARRIER_STORAGE_KMS_KEY`.

Web: `FARRIER_API_URL` (engine ALB), `NEXT_PUBLIC_SITE_URL`, `FARRIER_API_TOKEN`, `FARRIER_API_READ_TOKEN`,
`FARRIER_TRUSTED_PROXY_HOPS=2` (CloudFront and the ALB each append to `X-Forwarded-For`), and either the
OIDC settings (`FARRIER_OIDC_REDIRECT_URI=<site>/auth/callback` included) plus `FARRIER_SESSION_SECRET` and `FARRIER_OIDC_CLIENT_SECRET`, or
`FARRIER_DASHBOARD_PASSWORD`.

All AWS access uses the task roles. There are no access keys.

## Inputs

The most used inputs (all are documented in `variables.tf`):

| Name | Default | Notes |
| --- | --- | --- |
| `name` | `farrier` | Prefix for every resource |
| `farrier_version` | `0.2.0` | Image tag for `ghcr.io/gagankarthik/farrier` and `farrier-web` |
| `engine_image`, `web_image` | `""` | Override with a mirrored image or a digest pin |
| `create_vpc` | `false` | Or give `vpc_id` + `private_subnet_ids` |
| `vpc_id`, `private_subnet_ids`, `database_subnet_ids` | | Bring your own network |
| `engine_desired_count` | `2` | Leader election makes extra tasks safe |
| `engine_egress_cidrs` | `["0.0.0.0/0"]` | Narrow to your device networks + egress proxy |
| `domain_names`, `cloudfront_certificate_arn` | `[]`, `""` | Custom hostname (ACM cert in us-east-1) |
| `web_acl_arn` | `""` | WAFv2 web ACL (CLOUDFRONT scope) |
| `engine_certificate_arn`, `engine_domain_name` | `""` | HTTPS between web and engine |
| `db_instance_class`, `db_multi_az`, `db_iam_auth` | `db.t4g.medium`, `true`, `false` | |
| `route53_zone_ids` | `[]` | Zones for DNS-01 |
| `assumable_role_arns` | `[]` | Roles in other accounts the engine may assume (`aws_acm` connector `role_arn`, `cloud_inventory.aws_accounts`) |
| `oidc_issuer`, `oidc_client_id`, `oidc_scopes`, `web_extra_env` | | SSO; empty issuer = generated Basic-auth password |
| `storage_admin_principal_arns` | `[]` | Roles besides the engine task role that may write or delete bucket objects (the bucket policy denies everyone else; list your Terraform role to use `force_destroy_bucket`) |
| `secrets_seeded` | `false` | Services start only once this is `true` |
| `deletion_protection` | `true` | RDS and ALBs |

## Outputs

`dashboard_url`, `cloudfront_domain_name`, `engine_internal_url`, `engine_alb_dns_name`, `bucket`,
`storage_url`, `kms_key_arn`, `secret_arns`, `master_key_secret_arn`, `database_endpoint`, `vpc_id`,
`dashboard_password` (sensitive; only without OIDC).

## Apply

```bash
cd deploy/terraform/aws/examples/minimal     # or call the module from your own root
terraform init
terraform apply                              # 1. everything except the ECS services
```

### Seed the secrets

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

With OIDC on, store the client secret the same way (no wrapping):

```bash
aws secretsmanager put-secret-value --secret-id farrier-runtime/oidc-client-secret --secret-string '<client secret>'
```

Register `https://<dashboard host>/auth/callback` as the redirect URI and
`https://<dashboard host>/auth/signin?signed_out=1` as the sign-out redirect URI.

```bash
terraform apply -var secrets_seeded=true     # 2. start the engine and web services
```

Moving from SQLite? Run `farrier db migrate --to "<FARRIER_DATABASE_URL>"` from a host that can reach
RDS, with the same master key, before step 2.

## Bring your own network

Set `create_vpc = false` (the default) and pass:

- `vpc_id`: the VPC must have an internet gateway attached. CloudFront VPC origins require one, even though no traffic flows through it.
- `private_subnet_ids`: at least two AZs. They need outbound HTTPS (NAT gateway, egress proxy, or VPC endpoints for Secrets Manager, KMS, S3, CloudWatch Logs plus a route to `ghcr.io` or your registry mirror) and routes to your devices' management networks (Transit Gateway, Direct Connect, site-to-site VPN).
- `database_subnet_ids` (optional): isolated subnets for RDS.

Narrow `engine_egress_cidrs` to your device networks and egress proxy once you know them.

## Cost notes

Rough on-demand cost in us-east-1 for the defaults: 4 Fargate ARM tasks (~$35/month), RDS
db.t4g.medium Multi-AZ (~$100/month), two ALBs (~$35/month), one NAT gateway if `create_vpc`
(~$33/month plus data), KMS key ($1/month), Secrets Manager (~$0.40 per secret), CloudFront and S3
by usage. For a lab, set `db_multi_az = false`, `db_instance_class = "db.t4g.micro"`,
`engine_desired_count = 1`, `web_desired_count = 1`.

## Operations

- **Database password rotation.** RDS rotates the managed master password on a schedule (7 days by
  default). The engine reads `FARRIER_DATABASE_PASSWORD` at start, so redeploy after a rotation
  (`aws ecs update-service --cluster farrier --service farrier-engine --force-new-deployment`), for
  example from an EventBridge rule on the secret's `RotationSucceeded` event, or lengthen the rotation
  schedule on the managed secret.
- **Upgrades.** Change `farrier_version` and apply. ECS rolls tasks; the engine finishes its cycle
  and releases the leader lock on `SIGTERM` (`--grace 20`, `stopTimeout` 45s).
- **Backups.** RDS automated backups and the final snapshot; S3 versioning. A backup is useless
  without the master key: keep the CMK (and any escrowed copy) for as long as the backups.
- **ALB access logs and VPC flow logs** are not enabled by this module; turn them on with your
  organisation's log bucket.

## Teardown

```bash
terraform apply -var deletion_protection=false -var secrets_seeded=false
terraform destroy
```

RDS takes a final snapshot (`<name>-final`); delete it by hand when no longer needed. The bucket is
kept unless it is empty or `force_destroy_bucket = true`. Secrets enter a 30-day recovery window
(`secret_recovery_window_days`) and the KMS key a 30-day deletion window, so re-creating with the
same `name` within that time needs a different name or a restore.
