# ---------------------------------------------------------------------------------------------
# General
# ---------------------------------------------------------------------------------------------

variable "project_id" {
  description = "Google Cloud project for the service accounts, secrets, keys, bucket and database."
  type        = string
}

variable "region" {
  description = "Region for Cloud SQL, the bucket and the key ring."
  type        = string
  default     = "europe-west1"
}

variable "name" {
  description = "Name prefix for every resource. Lowercase letters, digits and hyphens."
  type        = string
  default     = "farrier"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,14}$", var.name))
    error_message = "name must be 2-15 characters: lowercase letters, digits and hyphens, starting with a letter (service account IDs are limited to 30 characters)."
  }
}

variable "labels" {
  description = "Labels added to every resource that supports them."
  type        = map(string)
  default     = {}
}

variable "enable_apis" {
  description = "Enable the required Google APIs in the project."
  type        = bool
  default     = true
}

variable "deletion_protection" {
  description = "Deletion protection on Cloud SQL. Turn off only to tear down."
  type        = bool
  default     = true
}

# ---------------------------------------------------------------------------------------------
# Cluster (existing, with Workload Identity Federation for GKE enabled)
# ---------------------------------------------------------------------------------------------

variable "cluster_name" {
  description = "Name of the existing GKE cluster (for the External Secrets SecretStore)."
  type        = string
}

variable "cluster_location" {
  description = "Region or zone of the existing GKE cluster."
  type        = string
}

variable "cluster_project_id" {
  description = "Project of the GKE cluster, whose workload identity pool (<project>.svc.id.goog) the Kubernetes service accounts belong to. Empty means project_id."
  type        = string
  default     = ""
}

variable "namespace" {
  description = "Kubernetes namespace Farrier is installed into."
  type        = string
  default     = "farrier"

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$", var.namespace))
    error_message = "namespace must be a DNS label."
  }
}

variable "service_account_name" {
  description = "Kubernetes service account of the engine (the chart's engine.serviceAccount.name)."
  type        = string
  default     = "farrier-engine"

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$", var.service_account_name))
    error_message = "service_account_name must be a DNS label."
  }
}

variable "external_secrets_service_account_name" {
  description = "Kubernetes service account the External Secrets SecretStore authenticates as (created by the kubernetes_manifests output)."
  type        = string
  default     = "farrier-external-secrets"

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$", var.external_secrets_service_account_name))
    error_message = "external_secrets_service_account_name must be a DNS label."
  }
}

# ---------------------------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------------------------

variable "create_database" {
  description = "Create a Cloud SQL for PostgreSQL instance (private IP on network). False leaves the database to you."
  type        = bool
  default     = true
}

variable "network" {
  description = "VPC of the cluster (projects/<p>/global/networks/<n> or its self link) for Cloud SQL's private IP. Private services access must already be set up on it. Required when create_database = true."
  type        = string
  default     = ""
}

variable "db_tier" {
  description = "Cloud SQL machine tier (Enterprise edition)."
  type        = string
  default     = "db-custom-1-3840"
}

variable "db_high_availability" {
  description = "REGIONAL availability (a standby in another zone)."
  type        = bool
  default     = true
}

variable "db_disk_size_gb" {
  description = "Initial disk size; grows automatically."
  type        = number
  default     = 20
}

variable "db_backup_count" {
  description = "Automated backups to keep."
  type        = number
  default     = 14
}

# ---------------------------------------------------------------------------------------------
# Secrets, storage, keys
# ---------------------------------------------------------------------------------------------

variable "secret_store_prefix" {
  description = "Secret Manager name prefix under which the engine may read and add versions (device credentials entered in the dashboard). The module's own runtime secrets use <name>-runtime- and are excluded. The engine's default FARRIER_SECRET_GCP_PREFIX is farrier-; if you change this, set that too (engine.config)."
  type        = string
  default     = "farrier-"
}

variable "engine_can_create_secrets" {
  description = "Also let the engine create and delete secrets under secret_store_prefix (a custom role, conditioned on the prefix). Without it, pre-create the secrets the engine writes to."
  type        = bool
  default     = true
}

variable "storage_prefix" {
  description = "Object prefix inside the bucket for change packs, backups and audit exports."
  type        = string
  default     = "farrier/"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9/_.-]*/$", var.storage_prefix))
    error_message = "storage_prefix must end with a slash, e.g. farrier/."
  }
}

variable "storage_admin_members" {
  description = "Extra principals (e.g. group:farrier-admins@example.com) given roles/storage.objectAdmin on the bucket, next to the engine. Keep this to break-glass admins: `farrier restore` trusts a backup's rows."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for m in var.storage_admin_members : can(regex("^(user|group|serviceAccount|domain|principal|principalSet):.+", m))])
    error_message = "storage_admin_members must be IAM member strings such as group:admins@example.com."
  }
}

variable "force_destroy_bucket" {
  description = "Allow terraform destroy to delete a non-empty bucket."
  type        = bool
  default     = false
}

variable "key_rotation_period" {
  description = "Cloud KMS automatic rotation period."
  type        = string
  default     = "7776000s"
}

# ---------------------------------------------------------------------------------------------
# Dashboard sign-in
# ---------------------------------------------------------------------------------------------

variable "oidc_enabled" {
  description = "The dashboard uses OIDC single sign-on: a generated session secret plus an OIDC client secret you add to Secret Manager. False generates a Basic-auth dashboard password. Set issuer and client ID in your Helm values (web.auth.oidc)."
  type        = bool
  default     = false
}
