# Two user-assigned managed identities, each federated with exactly one Kubernetes ServiceAccount
# through the cluster's OIDC issuer (Azure Workload Identity). No client secrets.

# --- Engine -----------------------------------------------------------------------------------

resource "azurerm_user_assigned_identity" "engine" {
  name                = "${var.name}-engine"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = local.tags
}

resource "azurerm_federated_identity_credential" "engine" {
  name                      = "${var.name}-engine"
  user_assigned_identity_id = azurerm_user_assigned_identity.engine.id
  audience                  = ["api://AzureADTokenExchange"]
  issuer                    = local.oidc_issuer_url
  subject                   = "system:serviceaccount:${var.namespace}:${var.service_account_name}"
}

# The engine never reads the runtime vault: its secrets arrive as Kubernetes Secrets from ESO.
resource "azurerm_role_assignment" "engine_store_officer" {
  scope                = azurerm_key_vault.this["store"].id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = azurerm_user_assigned_identity.engine.principal_id
}

resource "azurerm_role_assignment" "engine_master_wrap" {
  scope                = azurerm_key_vault_key.master_wrap.resource_versionless_id
  role_definition_name = "Key Vault Crypto User"
  principal_id         = azurerm_user_assigned_identity.engine.principal_id
}

# The only data-plane grant on the objects container (change packs, backups, audit exports).
# Shared keys are off, so nobody else can write a backup without being granted a data role here
# first. Keep it that way: `farrier restore` trusts a backup's rows, though backups are also
# HMAC-signed and unsigned ones need --allow-unsigned.
resource "azurerm_role_assignment" "engine_blob" {
  scope                = azurerm_storage_container.objects.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.engine.principal_id
}

resource "azurerm_role_assignment" "engine_dns" {
  for_each = toset(var.dns_zone_ids)

  scope                = each.value
  role_definition_name = "DNS Zone Contributor"
  principal_id         = azurerm_user_assigned_identity.engine.principal_id
}

# --- External Secrets Operator ----------------------------------------------------------------

resource "azurerm_user_assigned_identity" "external_secrets" {
  name                = "${var.name}-external-secrets"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = local.tags
}

resource "azurerm_federated_identity_credential" "external_secrets" {
  name                      = "${var.name}-external-secrets"
  user_assigned_identity_id = azurerm_user_assigned_identity.external_secrets.id
  audience                  = ["api://AzureADTokenExchange"]
  issuer                    = local.oidc_issuer_url
  subject                   = "system:serviceaccount:${var.namespace}:${var.external_secrets_service_account_name}"
}

# ESO syncs every runtime secret (engine's and web's), so it reads the whole runtime vault. That
# vault holds nothing else: device credentials live in the store vault, which ESO cannot read.
# Vault scope (rather than per secret) also covers master-key and oidc-client-secret, which you
# store after the apply.
resource "azurerm_role_assignment" "external_secrets_runtime" {
  scope                = azurerm_key_vault.this["runtime"].id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.external_secrets.principal_id
}
