# Storage account for change packs, backups and audit exports (FARRIER_STORAGE_URL=azblob://...).
# HTTPS only, TLS 1.2, no anonymous or shared-key access, no public network access (private
# endpoint), versioning, CMK from Key Vault, lifecycle rules.

resource "azurerm_role_assignment" "storage_cmk" {
  scope                = azurerm_key_vault_key.storage.resource_versionless_id
  role_definition_name = "Key Vault Crypto Service Encryption User"
  principal_id         = azurerm_user_assigned_identity.storage.principal_id
}

resource "time_sleep" "storage_cmk" {
  create_duration = "60s"

  depends_on = [azurerm_role_assignment.storage_cmk]
}

resource "azurerm_storage_account" "this" {
  name                              = "st${local.short}${local.suffix}"
  location                          = var.location
  resource_group_name               = local.resource_group_name
  account_kind                      = "StorageV2"
  account_tier                      = "Standard"
  account_replication_type          = var.storage_replication
  https_traffic_only_enabled        = true
  min_tls_version                   = "TLS1_2"
  allow_nested_items_to_be_public   = false
  shared_access_key_enabled         = false
  default_to_oauth_authentication   = true
  public_network_access_enabled     = false
  infrastructure_encryption_enabled = true
  tags                              = local.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.storage.id]
  }

  customer_managed_key {
    key_vault_key_id          = azurerm_key_vault_key.storage.versionless_id
    user_assigned_identity_id = azurerm_user_assigned_identity.storage.id
  }

  blob_properties {
    versioning_enabled = true

    delete_retention_policy {
      days = 14
    }

    container_delete_retention_policy {
      days = 14
    }
  }

  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }

  depends_on = [time_sleep.storage_cmk]
}

resource "azurerm_storage_container" "objects" {
  name                  = "objects"
  storage_account_id    = azurerm_storage_account.this.id
  container_access_type = "private"
}

resource "azurerm_storage_management_policy" "this" {
  storage_account_id = azurerm_storage_account.this.id

  rule {
    name    = "change-packs-expire-30d"
    enabled = true

    filters {
      prefix_match = ["${azurerm_storage_container.objects.name}/${var.storage_prefix}change-packs/"]
      blob_types   = ["blockBlob"]
    }

    actions {
      base_blob {
        delete_after_days_since_modification_greater_than = 30
      }
    }
  }

  rule {
    name    = "noncurrent-versions-expire-90d"
    enabled = true

    filters {
      blob_types = ["blockBlob"]
    }

    actions {
      version {
        delete_after_days_since_creation = 90
      }
    }
  }
}

resource "azurerm_private_endpoint" "blob" {
  name                = "${azurerm_storage_account.this.name}-blob-pe"
  location            = var.location
  resource_group_name = local.resource_group_name
  subnet_id           = local.private_endpoint_subnet_id
  tags                = local.tags

  private_service_connection {
    name                           = "${azurerm_storage_account.this.name}-blob-pe"
    private_connection_resource_id = azurerm_storage_account.this.id
    subresource_names              = ["blob"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "blob"
    private_dns_zone_ids = [local.dns_zone_blob]
  }
}
