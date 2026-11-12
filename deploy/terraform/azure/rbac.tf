# Least-privilege role assignments for the user-assigned managed identities. No client secrets.

# --- Engine -----------------------------------------------------------------------------------

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

# Secrets you seed exist only once secrets_seeded = true, so these grants wait for it.
resource "azurerm_role_assignment" "engine_secrets" {
  for_each = var.secrets_seeded ? toset(local.engine_secret_names) : toset([])

  scope                = local.secret_scopes[each.key]
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.engine.principal_id
}

# --- Web --------------------------------------------------------------------------------------

resource "azurerm_role_assignment" "web_secrets" {
  for_each = var.secrets_seeded ? toset(local.web_secret_names) : toset([])

  scope                = local.secret_scopes[each.key]
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.web.principal_id
}

resource "time_sleep" "app_rbac" {
  create_duration = "60s"

  depends_on = [
    azurerm_role_assignment.engine_secrets,
    azurerm_role_assignment.web_secrets,
    azurerm_role_assignment.engine_master_wrap,
  ]
}
