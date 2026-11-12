# helm_values and kubernetes_manifests are the contract with deploy/helm/farrier: pass helm_values
# as a second -f after examples/values-aks.yaml, and kubectl apply kubernetes_manifests first.

locals {
  # Chart key (secrets.externalSecrets.remoteRefs.<key>) -> Key Vault secret name.
  remote_ref_secrets = {
    apiToken          = "api-token"
    apiReadToken      = "api-read-token"
    masterKey         = "master-key"
    databasePassword  = "db-password"
    dashboardPassword = "dashboard-password"
    oidcClientSecret  = "oidc-client-secret"
    sessionSecret     = "session-secret"
  }
  remote_ref_keys = concat(
    ["apiToken", "apiReadToken", "masterKey"],
    var.create_database ? ["databasePassword"] : [],
    local.oidc_enabled ? ["oidcClientSecret", "sessionSecret"] : ["dashboardPassword"],
  )

  secret_store_name = "${var.name}-azure"

  helm_engine = merge(
    {
      serviceAccount = { name = var.service_account_name, cloudIdentity = { azureClientId = azurerm_user_assigned_identity.engine.client_id } }
      masterKey      = { kms = "azure-kv:${azurerm_key_vault_key.master_wrap.versionless_id}" }
      secretBackend  = { type = "azure", azure = { vaultUrl = azurerm_key_vault.this["store"].vault_uri } }
      storage        = { url = local.storage_url }
      config         = { AZURE_TENANT_ID = local.tenant_id }
    },
    { for k, v in { networkPolicy = { database = { cidrs = var.database_cidrs } } } : k => v if var.create_database },
  )

  helm_values = merge(
    {
      cloud = { provider = "aks", identity = "workload-identity" }
      web   = { auth = { mode = local.oidc_enabled ? "oidc" : "basic" } }
      secrets = {
        mode = "externalSecrets"
        externalSecrets = {
          secretStoreRef = { name = local.secret_store_name, kind = "SecretStore" }
          remoteRefs     = { for k in local.remote_ref_keys : k => { key = local.remote_ref_secrets[k] } }
        }
      }
      engine = local.helm_engine
    },
    { for k, v in { database = { type = "postgresql", url = local.database_url } } : k => v if var.create_database },
  )

  kubernetes_manifests = [
    {
      apiVersion = "v1"
      kind       = "ServiceAccount"
      metadata = {
        name      = var.external_secrets_service_account_name
        namespace = var.namespace
        annotations = {
          "azure.workload.identity/client-id" = azurerm_user_assigned_identity.external_secrets.client_id
          "azure.workload.identity/tenant-id" = local.tenant_id
        }
      }
    },
    {
      apiVersion = "external-secrets.io/v1"
      kind       = "SecretStore"
      metadata = {
        name      = local.secret_store_name
        namespace = var.namespace
      }
      spec = {
        provider = {
          azurekv = {
            authType          = "WorkloadIdentity"
            vaultUrl          = azurerm_key_vault.this["runtime"].vault_uri
            serviceAccountRef = { name = var.external_secrets_service_account_name }
          }
        }
      }
    },
  ]
}

output "helm_values" {
  description = "Values for deploy/helm/farrier (YAML). Pass as a second -f after examples/values-aks.yaml."
  value       = yamlencode(local.helm_values)
}

output "kubernetes_manifests" {
  description = "ESO ServiceAccount and SecretStore (multi-document YAML). kubectl apply before helm install."
  value       = join("---\n", [for m in local.kubernetes_manifests : yamlencode(m)])
}

output "engine_client_id" {
  description = "Client ID of the engine identity (engine.serviceAccount.cloudIdentity.azureClientId)."
  value       = azurerm_user_assigned_identity.engine.client_id
}

output "external_secrets_client_id" {
  description = "Client ID of the External Secrets Operator identity."
  value       = azurerm_user_assigned_identity.external_secrets.client_id
}

output "runtime_key_vault_name" {
  description = "Key Vault holding the runtime secrets and the master-wrap key. Store master-key (and oidc-client-secret) here."
  value       = azurerm_key_vault.this["runtime"].name
}

output "runtime_key_vault_uri" {
  description = "Runtime Key Vault URI (the SecretStore's vaultUrl)."
  value       = azurerm_key_vault.this["runtime"].vault_uri
}

output "store_key_vault_uri" {
  description = "Key Vault for device credentials (engine.secretBackend.azure.vaultUrl)."
  value       = azurerm_key_vault.this["store"].vault_uri
}

output "master_key_id" {
  description = "Versionless Key Vault key that wraps the master key."
  value       = azurerm_key_vault_key.master_wrap.versionless_id
}

output "storage_account_name" {
  description = "Storage account for change packs, backups and audit exports."
  value       = azurerm_storage_account.this.name
}

output "storage_url" {
  description = "FARRIER_STORAGE_URL given to the engine."
  value       = local.storage_url
}

output "database_fqdn" {
  description = "PostgreSQL server FQDN (private DNS); null when create_database = false."
  value       = one(azurerm_postgresql_flexible_server.this[*].fqdn)
}

output "dashboard_password" {
  description = "Generated Basic-auth password (only when OIDC is off)."
  value       = local.oidc_enabled ? null : random_password.dashboard_password[0].result
  sensitive   = true
}
