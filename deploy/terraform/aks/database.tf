# PostgreSQL Flexible Server with private access (VNet integration): no public endpoint, TLS
# required (the server default), encrypted at rest with service-managed keys. Optional
# (create_database).

resource "random_password" "db" {
  count = var.create_database ? 1 : 0

  length  = 40
  special = false
}

resource "azurerm_private_dns_zone" "postgres" {
  count = var.create_database && var.private_dns_zone_id == "" ? 1 : 0

  name                = "${var.name}.private.postgres.database.azure.com"
  resource_group_name = var.resource_group_name
  tags                = local.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "postgres" {
  count = var.create_database && var.private_dns_zone_id == "" ? 1 : 0

  name                = "${var.name}-postgres"
  private_dns_zone_id = azurerm_private_dns_zone.postgres[0].id
  virtual_network_id  = var.vnet_id
  tags                = local.tags

  lifecycle {
    precondition {
      condition     = var.vnet_id != ""
      error_message = "Set vnet_id (the cluster's VNet) or pass an existing private_dns_zone_id."
    }
  }
}

resource "azurerm_postgresql_flexible_server" "this" {
  count = var.create_database ? 1 : 0

  name                          = "${var.name}-pg-${local.suffix}"
  location                      = var.location
  resource_group_name           = var.resource_group_name
  version                       = "16"
  sku_name                      = var.db_sku_name
  storage_mb                    = var.db_storage_mb
  auto_grow_enabled             = true
  delegated_subnet_id           = var.database_subnet_id
  private_dns_zone_id           = coalesce(var.private_dns_zone_id, one(azurerm_private_dns_zone.postgres[*].id))
  public_network_access_enabled = false
  administrator_login           = "farrier"
  administrator_password        = random_password.db[0].result
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

    precondition {
      condition     = var.database_subnet_id != ""
      error_message = "create_database = true needs database_subnet_id (a subnet delegated to Microsoft.DBforPostgreSQL/flexibleServers)."
    }

    precondition {
      condition     = length(var.database_cidrs) > 0
      error_message = "create_database = true needs database_cidrs (the delegated subnet's CIDR) for the engine NetworkPolicy."
    }
  }

  depends_on = [azurerm_private_dns_zone_virtual_network_link.postgres]
}

resource "azurerm_postgresql_flexible_server_database" "farrier" {
  count = var.create_database ? 1 : 0

  name      = "farrier"
  server_id = azurerm_postgresql_flexible_server.this[0].id
  charset   = "UTF8"
  collation = "en_US.utf8"
}

resource "azurerm_postgresql_flexible_server_configuration" "log_connections" {
  count = var.create_database ? 1 : 0

  name      = "log_connections"
  server_id = azurerm_postgresql_flexible_server.this[0].id
  value     = "on"
}

locals {
  database_url = var.create_database ? format(
    "postgresql://farrier@%s:5432/farrier?sslmode=verify-full&sslrootcert=/etc/ssl/certs/ca-certificates.crt",
    azurerm_postgresql_flexible_server.this[0].fqdn,
  ) : null
}
