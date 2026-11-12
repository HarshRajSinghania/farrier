# Farrier on Azure: Container Apps (engine internal, web external), PostgreSQL Flexible Server
# (private access), Key Vault (RBAC), Storage (CMK), user-assigned managed identities, Front Door.
#
#   Internet ─HTTPS─> Front Door Standard ─(caches /_next/static/*, /assets/* only)─> web app
#   web app ─> engine app (ingress limited to the Container Apps environment)
#   engine ─> PostgreSQL (delegated subnet, private DNS, TLS) · Blob and Key Vault (private endpoints)
#          └─> your devices (VNet routes) · ACME CAs
#
# The engine has no external ingress.

data "azurerm_client_config" "current" {}

resource "random_string" "suffix" {
  length  = 6
  upper   = false
  special = false
}

locals {
  short  = replace(var.name, "-", "")
  suffix = random_string.suffix.result
  tags   = merge({ app = "farrier", deployment = var.name }, var.tags)

  engine_image = var.engine_image != "" ? var.engine_image : "ghcr.io/gagankarthik/farrier:${var.farrier_version}"
  web_image    = var.web_image != "" ? var.web_image : "ghcr.io/gagankarthik/farrier-web:${var.farrier_version}"

  resource_group_name = var.resource_group_name != "" ? var.resource_group_name : azurerm_resource_group.this[0].name

  vnet_id                    = var.create_vnet ? azurerm_virtual_network.this[0].id : var.vnet_id
  container_apps_subnet_id   = var.create_vnet ? azurerm_subnet.container_apps[0].id : var.container_apps_subnet_id
  postgres_subnet_id         = var.create_vnet ? azurerm_subnet.postgres[0].id : var.postgres_subnet_id
  private_endpoint_subnet_id = var.create_vnet ? azurerm_subnet.private_endpoints[0].id : var.private_endpoint_subnet_id

  dns_zone_postgres = var.create_private_dns_zones ? azurerm_private_dns_zone.postgres[0].id : lookup(var.private_dns_zone_ids, "postgres", "")
  dns_zone_vault    = var.create_private_dns_zones ? azurerm_private_dns_zone.vault[0].id : lookup(var.private_dns_zone_ids, "vault", "")
  dns_zone_blob     = var.create_private_dns_zones ? azurerm_private_dns_zone.blob[0].id : lookup(var.private_dns_zone_ids, "blob", "")

  oidc_enabled = var.oidc_issuer != ""
}

resource "azurerm_resource_group" "this" {
  count = var.resource_group_name == "" ? 1 : 0

  name     = "${var.name}-rg"
  location = var.location
  tags     = local.tags
}

# ---------------------------------------------------------------------------------------------
# Optional VNet (create_vnet = true)
# ---------------------------------------------------------------------------------------------

resource "azurerm_virtual_network" "this" {
  count = var.create_vnet ? 1 : 0

  name                = "${var.name}-vnet"
  location            = var.location
  resource_group_name = local.resource_group_name
  address_space       = [var.vnet_cidr]
  tags                = local.tags
}

resource "azurerm_subnet" "container_apps" {
  count = var.create_vnet ? 1 : 0

  name                 = "container-apps"
  resource_group_name  = local.resource_group_name
  virtual_network_name = azurerm_virtual_network.this[0].name
  address_prefixes     = [cidrsubnet(var.vnet_cidr, 7, 0)]

  delegation {
    name = "aca"

    service_delegation {
      name    = "Microsoft.App/environments"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

resource "azurerm_subnet" "postgres" {
  count = var.create_vnet ? 1 : 0

  name                 = "postgres"
  resource_group_name  = local.resource_group_name
  virtual_network_name = azurerm_virtual_network.this[0].name
  address_prefixes     = [cidrsubnet(var.vnet_cidr, 8, 2)]

  delegation {
    name = "postgres"

    service_delegation {
      name    = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

resource "azurerm_subnet" "private_endpoints" {
  count = var.create_vnet ? 1 : 0

  name                 = "private-endpoints"
  resource_group_name  = local.resource_group_name
  virtual_network_name = azurerm_virtual_network.this[0].name
  address_prefixes     = [cidrsubnet(var.vnet_cidr, 8, 3)]
}

# ---------------------------------------------------------------------------------------------
# Private DNS
# ---------------------------------------------------------------------------------------------

resource "azurerm_private_dns_zone" "postgres" {
  count = var.create_private_dns_zones ? 1 : 0

  name                = "${var.name}.private.postgres.database.azure.com"
  resource_group_name = local.resource_group_name
  tags                = local.tags
}

resource "azurerm_private_dns_zone" "vault" {
  count = var.create_private_dns_zones ? 1 : 0

  name                = "privatelink.vaultcore.azure.net"
  resource_group_name = local.resource_group_name
  tags                = local.tags
}

resource "azurerm_private_dns_zone" "blob" {
  count = var.create_private_dns_zones ? 1 : 0

  name                = "privatelink.blob.core.windows.net"
  resource_group_name = local.resource_group_name
  tags                = local.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "postgres" {
  count = var.create_private_dns_zones ? 1 : 0

  name                = "${var.name}-postgres"
  private_dns_zone_id = azurerm_private_dns_zone.postgres[0].id
  virtual_network_id  = local.vnet_id
  tags                = local.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "vault" {
  count = var.create_private_dns_zones ? 1 : 0

  name                = "${var.name}-vault"
  private_dns_zone_id = azurerm_private_dns_zone.vault[0].id
  virtual_network_id  = local.vnet_id
  tags                = local.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "blob" {
  count = var.create_private_dns_zones ? 1 : 0

  name                = "${var.name}-blob"
  private_dns_zone_id = azurerm_private_dns_zone.blob[0].id
  virtual_network_id  = local.vnet_id
  tags                = local.tags
}

# ---------------------------------------------------------------------------------------------
# Logs and identities
# ---------------------------------------------------------------------------------------------

resource "azurerm_log_analytics_workspace" "this" {
  name                = "${var.name}-logs"
  location            = var.location
  resource_group_name = local.resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days
  tags                = local.tags
}

resource "azurerm_user_assigned_identity" "engine" {
  name                = "${var.name}-engine"
  location            = var.location
  resource_group_name = local.resource_group_name
  tags                = local.tags
}

resource "azurerm_user_assigned_identity" "web" {
  name                = "${var.name}-web"
  location            = var.location
  resource_group_name = local.resource_group_name
  tags                = local.tags
}

resource "azurerm_user_assigned_identity" "storage" {
  name                = "${var.name}-storage-cmk"
  location            = var.location
  resource_group_name = local.resource_group_name
  tags                = local.tags
}
