# Farrier on Azure (Terraform reference module)

Runs Farrier on Azure Container Apps with PostgreSQL Flexible Server, Key Vault, a Storage Account
and user-assigned managed identities, behind Azure Front Door Standard. The engine has no external
ingress.

```
Internet ─HTTPS─> Front Door Standard ─┬─ /_next/static/*, /assets/*  (cached)
                                       └─ /*                           (not cached) ─> web app (external ingress)
Container Apps environment (VNet-integrated)
  web app ─> engine app (ingress limited to the environment, 2 replicas)
  engine ─> PostgreSQL Flexible Server (delegated subnet, private DNS, TLS verify-full)
         ─> Blob storage (private endpoint, CMK) · Key Vault ×2 (private endpoints)
         ─> your devices (VNet routes, VPN/ExpressRoute) · ACME CAs
```

## What it creates

| Area | Resources |
| --- | --- |
| Resource group | `<name>-rg`, unless `resource_group_name` is given |
| Network (optional) | `create_vnet = true`: VNet with a `/23` Container Apps subnet (delegated), a PostgreSQL subnet (delegated) and a private-endpoint subnet. Private DNS zones for PostgreSQL, Key Vault and Blob, linked to the VNet (`create_private_dns_zones`). |
| Compute | Container Apps environment (workload profiles, zone-redundant, logs to Log Analytics). Engine app: ingress `external_enabled = false`, HTTPS only, min 2 replicas. Web app: external ingress, HTTPS only. Both run as user-assigned identities. |
| Edge | Front Door Standard: endpoint, origin group with `/api/health` probe, a cached route for `/_next/static/*` and `/assets/*`, an uncached catch-all, HTTP→HTTPS redirect, HTTPS-only to the origin with certificate name check, optional custom domain with managed certificate (TLS 1.2 minimum) |
| Database | PostgreSQL 16 Flexible Server, private access only (`public_network_access_enabled = false`), TLS required, zone-redundant HA (toggle), 14-day backups, optional geo-redundant backups, encrypted at rest |
| Key Vault | Two vaults, RBAC mode, purge protection, 90-day soft delete, firewall deny (except `admin_allowed_ips`), private endpoints. **runtime**: app secrets + `master-wrap` and `storage-cmk` keys. **store**: device credentials the engine writes (`FARRIER_SECRET_AZURE_VAULT_URL`). |
| Storage | StorageV2, HTTPS only, TLS 1.2, no public blob access, shared keys disabled (Entra ID only), public network access disabled (private endpoint), infrastructure encryption, CMK from Key Vault (auto-rotating key), versioning, 14-day soft delete, lifecycle (`change-packs/` deleted after 30 days, versions after 90) |
| Identity and RBAC | Engine: Secrets User on its four runtime secrets, Secrets Officer on the store vault, Crypto User on `master-wrap`, Storage Blob Data Contributor on the `objects` container, optional DNS Zone Contributor on `dns_zone_ids`. Web: Secrets User on its own secrets only. Storage: Crypto Service Encryption User on `storage-cmk`. Deployer: Key Vault Administrator on both vaults. |
| Logs | Log Analytics workspace (`log_retention_days`, 90) |

## Configuration the containers receive

Engine: `FARRIER_DATABASE_URL` (`sslmode=verify-full` with the system CA bundle: Azure's server
certificates chain to public roots), `FARRIER_DATABASE_PASSWORD`, `FARRIER_MASTER_KEY` (wrapped) +
`FARRIER_MASTER_KEY_KMS=azure-kv:https://<vault>.vault.azure.net/keys/master-wrap`, `FARRIER_API_TOKEN`,
`FARRIER_API_READ_TOKEN`, `FARRIER_SECRET_BACKEND=azure`, `FARRIER_SECRET_AZURE_VAULT_URL`,
`FARRIER_STORAGE_URL=azblob://<account>/objects/farrier`, `AZURE_CLIENT_ID` (selects the managed identity).

Web: `FARRIER_API_URL` (the engine's internal FQDN), `NEXT_PUBLIC_SITE_URL`, the API tokens,
`FARRIER_REQUIRE_HEADER=X-Azure-FDID:<Front Door profile GUID>`, `FARRIER_TRUSTED_PROXY_HOPS=2`, and
either OIDC settings (`FARRIER_OIDC_REDIRECT_URI=<site>/auth/callback` included) + `FARRIER_SESSION_SECRET` + `FARRIER_OIDC_CLIENT_SECRET`, or
`FARRIER_DASHBOARD_PASSWORD`. Secrets are Key Vault references resolved by Container Apps with each
app's identity.

## Inputs

| Name | Default | Notes |
| --- | --- | --- |
| `name` | `farrier` | ≤ 12 characters (Key Vault and storage names derive from it) |
| `location` | `westeurope` | |
| `resource_group_name` | `""` | Existing group, or create `<name>-rg` |
| `farrier_version` | `0.1.0` | |
| `engine_image`, `web_image` | `""` | Mirror or digest pin |
| `admin_allowed_ips` | `[]` | Terraform runner IPs allowed through the Key Vault firewalls |
| `create_vnet`, `vnet_id`, `container_apps_subnet_id`, `postgres_subnet_id`, `private_endpoint_subnet_id` | | Bring your own network |
| `create_private_dns_zones`, `private_dns_zone_ids` | `true`, `{}` | Central DNS in hub-and-spoke |
| `engine_min_replicas`, `engine_max_replicas` | `2`, `3` | |
| `db_sku_name`, `db_high_availability`, `db_geo_redundant_backup` | `GP_Standard_D2ds_v5`, `true`, `false` | |
| `custom_domain` | `""` | Front Door custom domain |
| `dns_zone_ids` | `[]` | Azure DNS zones for DNS-01 |
| `oidc_issuer`, `oidc_client_id`, `oidc_scopes`, `web_extra_env` | | Entra ID or any OIDC provider |
| `secrets_seeded` | `false` | Apps and routes are created only once this is `true` |

## Outputs

`dashboard_url`, `frontdoor_endpoint_hostname`, `custom_domain_validation_token`,
`engine_internal_url`, `resource_group_name`, `runtime_key_vault_name`, `store_key_vault_url`,
`master_wrap_key_id`, `secret_ids`, `storage_account`, `storage_url`, `postgres_fqdn`,
`engine_principal_id`, `dashboard_password` (sensitive; only without OIDC).

## Apply

Configure the provider with `storage_use_azuread = true` (shared keys are disabled) and register
the resource providers (see `examples/minimal`). Terraform must reach the Key Vault data plane: run it
inside the VNet, or list its egress IP in `admin_allowed_ips`.

```bash
cd deploy/terraform/azure/examples/minimal
terraform init
terraform apply                    # 1. everything except the apps and Front Door routes
```

### Seed the secrets

```bash
VAULT=$(terraform output -raw runtime_key_vault_name)
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode(), end='')" > master.key
az keyvault key encrypt --vault-name "$VAULT" --name master-wrap --algorithm RSA-OAEP-256 \
  --data-type plaintext --value "$(cat master.key)" --query result -o tsv > master.key.wrapped
az keyvault secret set --vault-name "$VAULT" --name master-key --file master.key.wrapped
shred -u master.key master.key.wrapped   # after escrowing master.key per your key policy

# with OIDC on:
az keyvault secret set --vault-name "$VAULT" --name oidc-client-secret --value '<client secret>'
```

In Entra ID, register a web app with redirect URI `https://<dashboard host>/auth/callback` and
front-channel sign-out `https://<dashboard host>/auth/signin?signed_out=1`; use app roles and
`FARRIER_OIDC_ROLE_CLAIM=roles`.

```bash
terraform apply -var secrets_seeded=true    # 2. start the apps and add the Front Door routes
```

## Bring your own network

Set `create_vnet = false` and pass `vnet_id` plus three subnets:

- `container_apps_subnet_id`: delegated to `Microsoft.App/environments`, `/27` or larger (`/23` gives room to scale). Needs outbound internet (NAT gateway or firewall) for ACME CAs, `ghcr.io` and your OIDC issuer, and routes to your devices' management networks.
- `postgres_subnet_id`: delegated to `Microsoft.DBforPostgreSQL/flexibleServers`, nothing else in it.
- `private_endpoint_subnet_id`: for the Key Vault and Blob private endpoints.

With central private DNS zones, set `create_private_dns_zones = false` and pass
`private_dns_zone_ids = { postgres = …, vault = …, blob = … }`.

## Limits and hardening notes

- **Front Door Standard cannot reach private origins.** The web app therefore has a public
  Container Apps endpoint (TLS only), locked to Front Door twice: its ingress allows only the
  `AzureFrontDoor.Backend` IPv4 ranges (read from the service tag at plan time, so re-apply now and
  then to pick up new ranges), and the web app gets `FARRIER_REQUIRE_HEADER=X-Azure-FDID:<profile
  GUID>`, refusing anything that did not pass through this Front Door profile. For a private origin,
  move to Front Door **Premium** with a Private Link origin and an internal environment. The engine is
  never exposed either way.
- `FARRIER_TRUSTED_PROXY_HOPS=2` (Front Door, then the Container Apps ingress, append to
  `X-Forwarded-For`). Override it in `web_extra_env` if you add a proxy.
- Only the engine identity has a data role on the objects container (backups included); shared keys
  are off. Don't grant others `Storage Blob Data Contributor` there: `farrier restore` trusts a
  backup's rows (backups are HMAC-signed; unsigned ones need `--allow-unsigned`).
- Container Apps does not offer a read-only root filesystem setting; the images still run as UID 10001.
- PostgreSQL is encrypted at rest with service-managed keys. A customer-managed key needs a
  `customer_managed_key` block with a second identity (and a geo-backup key if geo-redundant).
- The `master-wrap` key is not auto-rotated: rotating it means re-wrapping the master key.

## Cost notes

Defaults, roughly: Container Apps consumption for 3 always-on replicas at 0.5 vCPU/1 GiB
(~$90/month), PostgreSQL `GP_Standard_D2ds_v5` zone-redundant (~$280/month; `B_Standard_B1ms` without
HA is ~$15/month for a lab), Front Door Standard (~$35/month + traffic), Key Vault and storage by
operations, private endpoints (~$7/month each, three), Log Analytics by ingestion.

## Teardown

```bash
terraform apply -var secrets_seeded=false
terraform destroy
```

Key Vaults stay soft-deleted for 90 days with purge protection on, so their names (which include a
random suffix) cannot be reused in that time. Soft-deleted blobs and versions expire on their own.
