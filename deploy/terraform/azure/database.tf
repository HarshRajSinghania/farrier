# PostgreSQL Flexible Server with private access (VNet integration): no public endpoint, TLS
# required (the server default), encrypted at rest with service-managed keys.

resource "random_password" "db" {
  length  = 40
  special = false
}

resource "azurerm_postgresql_flexible_server" "this" {
  name                          = "${var.name}-pg-${local.suffix}"
  location                      = var.location
  resource_group_name           = local.resource_group_name
  version                       = "16"
  sku_name                      = var.db_sku_name
  storage_mb                    = var.db_storage_mb
  auto_grow_enabled             = true
  delegated_subnet_id           = local.postgres_subnet_id
  private_dns_zone_id           = local.dns_zone_postgres
  public_network_access_enabled = false
  administrator_login           = "farrier"
  administrator_password        = random_password.db.result
  backup_retention_days         = var.db_backup_retention_days
  geo_redundant_backup_enabled  = var.db_geo_redundant_backup
  zone                          = "1"
  tags                          = local.tags

  authentication {
    password_auth_enabled         = true
    active_directory_auth_enabled = false
  }

  dynamic "high_availability" {
    for_each = var.db_high_availability ? [1] : []

    content {
      mode = "ZoneRedundant"
    }
  }

  lifecycle {
    ignore_changes = [zone]
  }

  depends_on = [azurerm_private_dns_zone_virtual_network_link.postgres]
}

resource "azurerm_postgresql_flexible_server_database" "farrier" {
  name      = "farrier"
  server_id = azurerm_postgresql_flexible_server.this.id
  charset   = "UTF8"
  collation = "en_US.utf8"
}

resource "azurerm_postgresql_flexible_server_configuration" "log_connections" {
  name      = "log_connections"
  server_id = azurerm_postgresql_flexible_server.this.id
  value     = "on"
}
