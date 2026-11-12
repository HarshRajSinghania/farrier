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
  description = "Azure region for the new resources (normally the cluster's region)."
  type        = string
  default     = "westeurope"
}

variable "resource_group_name" {
  description = "Existing resource group for the identities, Key Vaults, storage account and database."
  type        = string

  validation {
    condition     = var.resource_group_name != ""
    error_message = "resource_group_name is required."
  }
}

variable "tags" {
  description = "Tags added to every resource."
  type        = map(string)
  default     = {}
}

variable "admin_allowed_ips" {
  description = "Public IPs/CIDRs (your Terraform runner, admin workstation) allowed through the Key Vault firewalls. Key Vault denies all other public traffic except cluster_subnet_ids and cluster_egress_ips."
  type        = list(string)
  default     = []
}

# ---------------------------------------------------------------------------------------------
# Cluster (existing AKS cluster with the OIDC issuer and Workload Identity enabled)
# ---------------------------------------------------------------------------------------------

variable "cluster_name" {
  description = "Existing AKS cluster. Its OIDC issuer URL is the issuer of the federated credentials."
  type        = string
}

variable "cluster_resource_group_name" {
  description = "Resource group of the AKS cluster."
  type        = string
}

variable "namespace" {
  description = "Kubernetes namespace Farrier is installed into (helm install -n)."
  type        = string
  default     = "farrier"

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$", var.namespace))
    error_message = "namespace must be a valid Kubernetes namespace name (DNS-1123 label)."
  }
}

variable "service_account_name" {
  description = "Engine ServiceAccount (engine.serviceAccount.name). The engine identity trusts exactly <namespace>/<service_account_name>."
  type        = string
  default     = "farrier-engine"

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$", var.service_account_name))
    error_message = "service_account_name must be a valid Kubernetes name."
  }
}

variable "external_secrets_service_account_name" {
  description = "ServiceAccount the External Secrets Operator SecretStore authenticates as (rendered in output kubernetes_manifests)."
  type        = string
  default     = "farrier-external-secrets"

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$", var.external_secrets_service_account_name))
    error_message = "external_secrets_service_account_name must be a valid Kubernetes name."
  }
}

variable "cluster_subnet_ids" {
  description = "AKS node (and pod) subnets allowed through the Key Vault and storage firewalls. Each needs the Microsoft.KeyVault and Microsoft.Storage service endpoints. Storage IP rules do not apply to traffic from the same region, so a same-region cluster must be listed here."
  type        = list(string)
  default     = []
}

variable "cluster_egress_ips" {
  description = "Public egress IPs of the cluster (load balancer outbound or NAT gateway), allowed through the Key Vault and storage firewalls when the subnets have no service endpoints."
  type        = list(string)
  default     = []
}

# ---------------------------------------------------------------------------------------------
# Dashboard sign-in
# ---------------------------------------------------------------------------------------------

variable "oidc_enabled" {
  description = "Dashboard single sign-on (web.auth.mode=oidc): generates session-secret and expects you to store oidc-client-secret. False generates dashboard-password (web.auth.mode=basic). Set web.auth.oidc.issuer/clientId in your own values."
  type        = bool
  default     = false
}

# ---------------------------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------------------------

variable "create_database" {
  description = "Create a PostgreSQL Flexible Server (VNet-integrated). False leaves the chart's database settings to you (e.g. sqlite for a lab)."
  type        = bool
  default     = true
}

variable "database_subnet_id" {
  description = "Subnet delegated to Microsoft.DBforPostgreSQL/flexibleServers, in a VNet the cluster can reach. Required when create_database = true."
  type        = string
  default     = ""
}

variable "database_cidrs" {
  description = "Address prefixes of database_subnet_id, for the engine NetworkPolicy (engine.networkPolicy.database.cidrs)."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for c in var.database_cidrs : can(cidrhost(c, 0))])
    error_message = "database_cidrs must be CIDRs such as 10.20.2.0/24."
  }
}

variable "vnet_id" {
  description = "VNet the PostgreSQL private DNS zone is linked to (the cluster's VNet) when private_dns_zone_id is empty."
  type        = string
  default     = ""
}

variable "private_dns_zone_id" {
  description = "Existing private DNS zone for the server (*.private.postgres.database.azure.com), e.g. a central zone in hub-and-spoke. Empty creates <name>.private.postgres.database.azure.com and links it to vnet_id."
  type        = string
  default     = ""
}

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
# Storage and DNS
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

variable "dns_zone_ids" {
  description = "Azure DNS zone IDs the engine may change records in (DNS-01). Grants DNS Zone Contributor on each."
  type        = list(string)
  default     = []
}
