# Farrier on AKS: the Azure side (Terraform reference module)

Creates what the Helm chart (`deploy/helm/farrier`) needs from Azure next to an **existing** AKS
cluster with the OIDC issuer and Workload Identity enabled: two workload identities, Key Vaults,
a storage account and, optionally, PostgreSQL Flexible Server. It never creates a cluster, a VNet
or any ingress. Its outputs are a Helm values file and the External Secrets Operator (ESO) objects.

```
ESO (SecretStore <name>-azure, workload identity) ─> runtime Key Vault ─> Kubernetes Secrets ─> engine, web
engine (workload identity) ─> store Key Vault (device credentials) · master-wrap key (unwrap)
                           ─> Blob container · PostgreSQL (delegated subnet, private DNS, TLS verify-full)
```

## What it creates

| Area | Resources |
| --- | --- |
| Identity | `<name>-engine`, federated with `system:serviceaccount:<namespace>:<service_account_name>`; `<name>-external-secrets`, federated with `<namespace>/<external_secrets_service_account_name>`. Issuer: the cluster's OIDC issuer URL. |
| RBAC | Engine: Secrets Officer on the store vault, Crypto User on `master-wrap`, Storage Blob Data Contributor on the `objects` container, optional DNS Zone Contributor on `dns_zone_ids`. ESO: Secrets User on the runtime vault (it holds only Farrier's runtime secrets). Deployer: Key Vault Administrator on both vaults. |
| Key Vault | Two vaults, RBAC mode, purge protection, 90-day soft delete, firewall deny except `admin_allowed_ips`, `cluster_subnet_ids` and `cluster_egress_ips`. **runtime**: generated `api-token`, `api-read-token`, `db-password`, `dashboard-password` or `session-secret`; `master-key` and `oidc-client-secret` you store; keys `master-wrap` and `storage-cmk`. **store**: device credentials the engine writes. |
| Storage | StorageV2, HTTPS only, TLS 1.2, no public blob access, shared keys disabled, firewall deny except the cluster, infrastructure encryption, CMK, versioning, 14-day soft delete, lifecycle (`change-packs/` after 30 days, versions after 90) |
| Database (`create_database`) | PostgreSQL 16 Flexible Server in `database_subnet_id`, private access only, TLS required, zone-redundant HA (toggle), 14-day backups, database `farrier`. Private DNS zone created and linked to `vnet_id` unless `private_dns_zone_id` is given. |

## Important inputs

| Name | Default | Notes |
| --- | --- | --- |
| `name`, `location`, `resource_group_name` | `farrier`, `westeurope`, required | Existing resource group for the new resources |
| `cluster_name`, `cluster_resource_group_name` | required | Read for the OIDC issuer URL |
| `namespace`, `service_account_name`, `external_secrets_service_account_name` | `farrier`, `farrier-engine`, `farrier-external-secrets` | Must match the Helm release |
| `cluster_subnet_ids`, `cluster_egress_ips` | `[]` | How the cluster reaches Key Vault and Blob. Storage IP rules ignore same-region traffic, so list the node subnets (with the `Microsoft.KeyVault` and `Microsoft.Storage` service endpoints) |
| `admin_allowed_ips` | `[]` | Terraform runner IPs for the Key Vault data plane |
| `oidc_enabled` | `false` | `true`: `web.auth.mode=oidc`; set `web.auth.oidc.issuer`, `clientId`, `redirectUri` in your own values |
| `create_database`, `database_subnet_id`, `database_cidrs`, `vnet_id`, `private_dns_zone_id` | `true`, … | `database_cidrs` = the delegated subnet's CIDR (engine NetworkPolicy) |
| `db_sku_name`, `db_high_availability`, `db_backup_retention_days`, `db_geo_redundant_backup` | `GP_Standard_D2ds_v5`, `true`, `14`, `false` | |
| `storage_replication`, `storage_prefix`, `dns_zone_ids` | `ZRS`, `farrier/`, `[]` | |

## Outputs

`helm_values` (YAML for the chart), `kubernetes_manifests` (ESO ServiceAccount + SecretStore),
`engine_client_id`, `external_secrets_client_id`, `runtime_key_vault_name`, `runtime_key_vault_uri`,
`store_key_vault_uri`, `master_key_id`, `storage_account_name`, `storage_url`, `database_fqdn`
(null without a database), `dashboard_password` (sensitive; only without OIDC).

## Install

Prerequisites: ESO (>= 0.17, `external-secrets.io/v1`) in the cluster, and

```bash
az aks update -g <cluster rg> -n <cluster> --enable-oidc-issuer --enable-workload-identity
```

Configure the provider with `storage_use_azuread = true` (shared keys are disabled); see
`examples/minimal`.

```bash
cd deploy/terraform/aks/examples/minimal
terraform init
terraform apply
```

Store the wrapped master key (and, with OIDC, the client secret):

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

Then the ESO objects and the chart:

```bash
kubectl create namespace farrier
terraform output -raw kubernetes_manifests | kubectl apply -f -
terraform output -raw helm_values > cloud-values.yaml
helm install farrier deploy/helm/farrier -n farrier \
  -f deploy/helm/farrier/examples/values-aks.yaml -f cloud-values.yaml
```

Verify: `kubectl -n farrier get externalsecrets` shows `SecretSynced`, and the dashboard's
`/api/health` answers through your Ingress (or `kubectl -n farrier port-forward svc/farrier-web 8080:80`
and `curl http://localhost:8080/api/health`).

## Notes

- The engine and ESO reach Key Vault and Blob on their public endpoints through the firewalls
  (service endpoints or egress IPs), because the chart's engine NetworkPolicy allows 443 to the
  internet but not to private ranges. Private endpoints would need extra egress rules.
- Only the engine identity has a data role on the objects container (backups included); shared keys
  are off. Don't grant others `Storage Blob Data Contributor` there: `farrier restore` trusts a
  backup's rows (backups are HMAC-signed; unsigned ones need `--allow-unsigned`).
- The `master-wrap` key is not auto-rotated: rotating it means re-wrapping the master key.
- Key Vaults stay soft-deleted for 90 days after `terraform destroy` (purge protection).
