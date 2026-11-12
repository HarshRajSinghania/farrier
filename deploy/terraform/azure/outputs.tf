output "dashboard_url" {
  description = "Dashboard URL (through Front Door)."
  value       = "${local.site_url}/dashboard"
}

output "frontdoor_endpoint_hostname" {
  description = "Front Door endpoint hostname (CNAME your custom_domain here)."
  value       = azurerm_cdn_frontdoor_endpoint.web.host_name
}

output "custom_domain_validation_token" {
  description = "Create TXT _dnsauth.<custom_domain> with this value to validate the managed certificate."
  value       = var.custom_domain != "" ? azurerm_cdn_frontdoor_custom_domain.web[0].validation_token : null
}

output "engine_internal_url" {
  description = "Engine URL (FARRIER_API_URL), reachable only inside the Container Apps environment."
  value       = var.secrets_seeded ? "https://${azurerm_container_app.engine[0].ingress[0].fqdn}" : null
}

output "resource_group_name" {
  description = "Resource group in use."
  value       = local.resource_group_name
}

output "runtime_key_vault_name" {
  description = "Key Vault holding the runtime secrets and the master-wrap key. Store master-key (and oidc-client-secret) here."
  value       = azurerm_key_vault.this["runtime"].name
}

output "store_key_vault_url" {
  description = "Key Vault for device credentials (FARRIER_SECRET_AZURE_VAULT_URL)."
  value       = azurerm_key_vault.this["store"].vault_uri
}

output "master_wrap_key_id" {
  description = "Versionless Key Vault key that wraps the master key."
  value       = azurerm_key_vault_key.master_wrap.versionless_id
}

output "secret_ids" {
  description = "Versionless Key Vault secret URLs by name (values are not output)."
  value       = local.secret_urls
}

output "storage_account" {
  description = "Storage account for change packs, backups and audit exports."
  value       = azurerm_storage_account.this.name
}

output "storage_url" {
  description = "FARRIER_STORAGE_URL given to the engine."
  value       = local.storage_url
}

output "postgres_fqdn" {
  description = "PostgreSQL server FQDN (private DNS)."
  value       = azurerm_postgresql_flexible_server.this.fqdn
}

output "engine_principal_id" {
  description = "Engine managed identity principal ID."
  value       = azurerm_user_assigned_identity.engine.principal_id
}

output "dashboard_password" {
  description = "Generated Basic-auth password (only when OIDC is off)."
  value       = local.oidc_enabled ? null : random_password.dashboard_password[0].result
  sensitive   = true
}
