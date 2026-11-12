# Two Key Vaults, both RBAC mode, purge protection, 90-day soft delete, public access denied except
# admin_allowed_ips, private endpoints for the apps:
#
#   runtime  the apps' own secrets and the master-key wrapping key. Each identity is granted only
#            the secrets it needs.
#   store    FARRIER_SECRET_AZURE_VAULT_URL: device credentials the engine writes from the dashboard.
#            The engine is Secrets Officer here and nowhere else.

locals {
  key_vaults = {
    runtime = "kv-${local.short}-${local.suffix}"
    store   = "kvs-${local.short}-${local.suffix}"
  }
}

resource "azurerm_key_vault" "this" {
  for_each = local.key_vaults

  name                          = each.value
  location                      = var.location
  resource_group_name           = local.resource_group_name
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "standard"
  rbac_authorization_enabled    = true
  purge_protection_enabled      = true
  soft_delete_retention_days    = 90
  public_network_access_enabled = true
  tags                          = local.tags

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
    ip_rules       = var.admin_allowed_ips
  }
}

resource "azurerm_private_endpoint" "vault" {
  for_each = local.key_vaults

  name                = "${each.value}-pe"
  location            = var.location
  resource_group_name = local.resource_group_name
  subnet_id           = local.private_endpoint_subnet_id
  tags                = local.tags

  private_service_connection {
    name                           = "${each.value}-pe"
    private_connection_resource_id = azurerm_key_vault.this[each.key].id
    subresource_names              = ["vault"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "vault"
    private_dns_zone_ids = [local.dns_zone_vault]
  }
}

# Terraform's own identity manages keys and secrets.
resource "azurerm_role_assignment" "deployer_kv_admin" {
  for_each = local.key_vaults

  scope                = azurerm_key_vault.this[each.key].id
  role_definition_name = "Key Vault Administrator"
  principal_id         = data.azurerm_client_config.current.object_id
}

# Azure RBAC takes a while to propagate to Key Vault's data plane.
resource "time_sleep" "rbac" {
  create_duration = "90s"

  depends_on = [azurerm_role_assignment.deployer_kv_admin]
}

# ---------------------------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------------------------

# Wraps the Farrier master key (FARRIER_MASTER_KEY_KMS=azure-kv:<vault>/keys/master-wrap).
# No automatic rotation: the engine unwraps with the versionless key, which uses the latest
# version, so rotate it only together with re-wrapping the master key.
resource "azurerm_key_vault_key" "master_wrap" {
  name         = "master-wrap"
  key_vault_id = azurerm_key_vault.this["runtime"].id
  key_type     = "RSA"
  key_size     = 3072
  key_opts     = ["wrapKey", "unwrapKey", "encrypt", "decrypt"]
  tags         = local.tags

  depends_on = [time_sleep.rbac]
}

# Customer-managed key for the storage account (versionless, so rotation is picked up).
resource "azurerm_key_vault_key" "storage" {
  name         = "storage-cmk"
  key_vault_id = azurerm_key_vault.this["runtime"].id
  key_type     = "RSA"
  key_size     = 3072
  key_opts     = ["wrapKey", "unwrapKey"]
  tags         = local.tags

  rotation_policy {
    expire_after         = "P2Y"
    notify_before_expiry = "P30D"

    automatic {
      time_before_expiry = "P60D"
    }
  }

  depends_on = [time_sleep.rbac]
}

# ---------------------------------------------------------------------------------------------
# Runtime secrets
# ---------------------------------------------------------------------------------------------
# Generated here (in Terraform state: use an encrypted backend): api-token, api-read-token,
# db-password, session-secret or dashboard-password. Stored by you (never in state): master-key
# (the wrapped key) and oidc-client-secret.

resource "random_password" "api_token" {
  length  = 48
  special = false
}

resource "random_password" "api_read_token" {
  length  = 48
  special = false
}

resource "random_password" "session_secret" {
  count = local.oidc_enabled ? 1 : 0

  length  = 64
  special = false
}

resource "random_password" "dashboard_password" {
  count = local.oidc_enabled ? 0 : 1

  length  = 32
  special = false
}

locals {
  generated_secret_names = concat(
    ["api-token", "api-read-token", "db-password"],
    local.oidc_enabled ? ["session-secret"] : ["dashboard-password"],
  )
  generated_secret_values = {
    "api-token"          = random_password.api_token.result
    "api-read-token"     = random_password.api_read_token.result
    "db-password"        = random_password.db.result
    "session-secret"     = local.oidc_enabled ? random_password.session_secret[0].result : ""
    "dashboard-password" = local.oidc_enabled ? "" : random_password.dashboard_password[0].result
  }

  seeded_secret_names = concat(["master-key"], local.oidc_enabled ? ["oidc-client-secret"] : [])

  runtime_vault_id  = azurerm_key_vault.this["runtime"].id
  runtime_vault_uri = azurerm_key_vault.this["runtime"].vault_uri

  # Versionless secret URLs (Container Apps always fetches the latest version) and ARM scopes.
  secret_urls = merge(
    { for k, s in azurerm_key_vault_secret.generated : k => s.versionless_id },
    { for k in local.seeded_secret_names : k => "${local.runtime_vault_uri}secrets/${k}" },
  )
  secret_scopes = merge(
    { for k, s in azurerm_key_vault_secret.generated : k => s.resource_versionless_id },
    { for k in local.seeded_secret_names : k => "${local.runtime_vault_id}/secrets/${k}" },
  )

  engine_secret_names = ["api-token", "api-read-token", "db-password", "master-key"]
  web_secret_names = concat(
    ["api-token", "api-read-token"],
    local.oidc_enabled ? ["session-secret", "oidc-client-secret"] : ["dashboard-password"],
  )
}

resource "azurerm_key_vault_secret" "generated" {
  for_each = toset(local.generated_secret_names)

  name         = each.key
  value        = local.generated_secret_values[each.key]
  key_vault_id = local.runtime_vault_id
  content_type = "text/plain"
  tags         = local.tags

  depends_on = [time_sleep.rbac]
}
