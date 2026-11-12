# ---------------------------------------------------------------------------------------------
# General
# ---------------------------------------------------------------------------------------------

variable "name" {
  description = "Name prefix (Key Vault and storage account names are derived from it and limited to 24 characters)."
  type        = string
  default     = "farrier"

  validation {
    condition     = can(regex("^[a-z][a-z0-9]{0,10}[a-z0-9]$", replace(var.name, "-", "")))
    error_message = "name must be 2-12 lowercase letters or digits (hyphens are dropped), starting with a letter."
  }
}

variable "location" {
  description = "Azure region."
  type        = string
  default     = "westeurope"
}

variable "resource_group_name" {
  description = "Existing resource group to deploy into. Empty creates <name>-rg."
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags added to every resource."
  type        = map(string)
  default     = {}
}

variable "farrier_version" {
  description = "Farrier release to run. Selects ghcr.io/gagankarthik/farrier:<version> and farrier-web:<version>."
  type        = string
  default     = "0.1.0"

  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+(-[0-9A-Za-z.-]+)?$", var.farrier_version))
    error_message = "farrier_version must be a SemVer version such as 0.1.0."
  }
}

variable "engine_image" {
  description = "Override the engine image (mirror or digest pin). Empty uses ghcr.io/gagankarthik/farrier:<farrier_version>."
  type        = string
  default     = ""
}

variable "web_image" {
  description = "Override the web image. Empty uses ghcr.io/gagankarthik/farrier-web:<farrier_version>."
  type        = string
  default     = ""
}

variable "secrets_seeded" {
  description = "Set to true after you have stored the wrapped master key (secret master-key) and, with OIDC, the client secret (oidc-client-secret) in the runtime Key Vault. Until then the container apps and Front Door routes are not created."
  type        = bool
  default     = false
}

variable "admin_allowed_ips" {
  description = "Public IPs/CIDRs (your Terraform runner, admin workstation) allowed through the Key Vault firewalls. Key Vault denies all other public traffic; the apps use private endpoints. Leave empty only if Terraform runs inside the VNet."
  type        = list(string)
  default     = []
}

# ---------------------------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------------------------

variable "create_vnet" {
  description = "Create a VNet with the three subnets this module needs. Leave false to bring your own."
  type        = bool
  default     = false
}

variable "vnet_cidr" {
  description = "Address space of the VNet created when create_vnet = true."
  type        = string
  default     = "10.40.0.0/16"
}

variable "vnet_id" {
  description = "Your VNet (when create_vnet = false). Private DNS zones are linked to it."
  type        = string
  default     = ""
}

variable "container_apps_subnet_id" {
  description = "Subnet for the Container Apps environment, delegated to Microsoft.App/environments, /27 or larger (/23 recommended)."
  type        = string
  default     = ""
}

variable "postgres_subnet_id" {
  description = "Subnet delegated to Microsoft.DBforPostgreSQL/flexibleServers."
  type        = string
  default     = ""
}

variable "private_endpoint_subnet_id" {
  description = "Subnet for the Key Vault and Blob private endpoints."
  type        = string
  default     = ""
}

variable "create_private_dns_zones" {
  description = "Create and link the private DNS zones (PostgreSQL, privatelink.vaultcore.azure.net, privatelink.blob.core.windows.net). Set false in hub-and-spoke setups with central zones, and pass their IDs."
  type        = bool
  default     = true
}

variable "private_dns_zone_ids" {
  description = "Existing zone IDs when create_private_dns_zones = false: keys postgres, vault, blob."
  type        = map(string)
  default     = {}
}

# ---------------------------------------------------------------------------------------------
# Compute
# ---------------------------------------------------------------------------------------------

variable "zone_redundant" {
  description = "Zone-redundant Container Apps environment."
  type        = bool
  default     = true
}

variable "engine_min_replicas" {
  description = "Engine replicas (minimum). Every replica serves the API; one holds the leader lock."
  type        = number
  default     = 2

  validation {
    condition     = var.engine_min_replicas >= 1
    error_message = "The engine is not request-driven: keep at least one replica."
  }
}

variable "engine_max_replicas" {
  description = "Engine replicas (maximum)."
  type        = number
  default     = 3
}

variable "web_min_replicas" {
  description = "Web replicas (minimum)."
  type        = number
  default     = 1
}

variable "web_max_replicas" {
  description = "Web replicas (maximum)."
  type        = number
  default     = 5
}

# ---------------------------------------------------------------------------------------------
# Edge
# ---------------------------------------------------------------------------------------------

variable "custom_domain" {
  description = "Optional dashboard hostname on Front Door with a managed certificate. Create the TXT validation record from output custom_domain_validation_token and a CNAME to frontdoor_endpoint_hostname."
  type        = string
  default     = ""
}

# ---------------------------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------------------------

variable "db_sku_name" {
  description = "PostgreSQL Flexible Server SKU. High availability needs General Purpose or Memory Optimized."
  type        = string
  default     = "GP_Standard_D2ds_v5"
}

variable "db_storage_mb" {
  description = "Storage in MB."
  type        = number
  default     = 32768
}

variable "db_high_availability" {
  description = "Zone-redundant standby."
  type        = bool
  default     = true
}

variable "db_backup_retention_days" {
  description = "Backup retention (7-35 days)."
  type        = number
  default     = 14

  validation {
    condition     = var.db_backup_retention_days >= 7 && var.db_backup_retention_days <= 35
    error_message = "db_backup_retention_days must be between 7 and 35."
  }
}

variable "db_geo_redundant_backup" {
  description = "Geo-redundant backups (forces a new server when changed)."
  type        = bool
  default     = false
}

# ---------------------------------------------------------------------------------------------
# Storage, logs, DNS
# ---------------------------------------------------------------------------------------------

variable "storage_replication" {
  description = "Storage account replication."
  type        = string
  default     = "ZRS"

  validation {
    condition     = contains(["LRS", "ZRS", "GRS", "GZRS", "RAGRS", "RAGZRS"], var.storage_replication)
    error_message = "storage_replication must be LRS, ZRS, GRS, GZRS, RAGRS or RAGZRS."
  }
}

variable "storage_prefix" {
  description = "Blob prefix inside the objects container for change packs, backups and audit exports."
  type        = string
  default     = "farrier/"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9/_.-]*/$", var.storage_prefix))
    error_message = "storage_prefix must end with a slash, e.g. farrier/."
  }
}

variable "log_retention_days" {
  description = "Log Analytics retention."
  type        = number
  default     = 90

  validation {
    condition     = var.log_retention_days >= 30 && var.log_retention_days <= 730
    error_message = "log_retention_days must be between 30 and 730."
  }
}

variable "dns_zone_ids" {
  description = "Azure DNS zone IDs the engine may change records in (DNS-01). Grants DNS Zone Contributor on each."
  type        = list(string)
  default     = []
}

# ---------------------------------------------------------------------------------------------
# Dashboard sign-in
# ---------------------------------------------------------------------------------------------

variable "oidc_issuer" {
  description = "OpenID Connect issuer URL, e.g. https://login.microsoftonline.com/<tenant>/v2.0. Empty falls back to a generated Basic-auth password."
  type        = string
  default     = ""

  validation {
    condition     = var.oidc_issuer == "" || startswith(var.oidc_issuer, "https://")
    error_message = "oidc_issuer must be an https:// URL."
  }
}

variable "oidc_client_id" {
  description = "OIDC client (application) ID."
  type        = string
  default     = ""
}

variable "oidc_scopes" {
  description = "OIDC scopes. Entra ID rejects \"groups\"."
  type        = string
  default     = "openid profile email"
}

variable "web_extra_env" {
  description = "Extra non-secret environment for the web app (e.g. FARRIER_OIDC_ROLE_CLAIM = roles)."
  type        = map(string)
  default     = {}
}

variable "engine_extra_env" {
  description = "Extra non-secret environment for the engine."
  type        = map(string)
  default     = {}
}
