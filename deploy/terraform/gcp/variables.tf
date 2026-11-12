# ---------------------------------------------------------------------------------------------
# General
# ---------------------------------------------------------------------------------------------

variable "project_id" {
  description = "Google Cloud project to deploy into."
  type        = string
}

variable "region" {
  description = "Region for Cloud Run, Cloud SQL, the bucket and the key ring."
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
  description = "Override the engine image (Artifact Registry or Docker Hub; Cloud Run cannot pull from ghcr.io directly). Empty pulls ghcr.io/gagankarthik/farrier:<farrier_version> through the module's Artifact Registry remote repository."
  type        = string
  default     = ""
}

variable "web_image" {
  description = "Override the web image (see engine_image)."
  type        = string
  default     = ""
}

variable "secrets_seeded" {
  description = "Set to true after you have added the wrapped master key (and the OIDC client secret, if OIDC is on) to Secret Manager. Until then the Cloud Run services are not created."
  type        = bool
  default     = false
}

variable "deletion_protection" {
  description = "Deletion protection on Cloud SQL and the Cloud Run services. Turn off only to tear down."
  type        = bool
  default     = true
}

# ---------------------------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------------------------

variable "create_network" {
  description = "Create a VPC, a subnet with Private Google Access, and Cloud NAT. Leave false to use your own through network_id and subnetwork_id."
  type        = bool
  default     = false
}

variable "subnet_cidr" {
  description = "Primary range of the subnet created when create_network = true. Direct VPC egress uses addresses from it."
  type        = string
  default     = "10.40.0.0/24"
}

variable "network_id" {
  description = "Your VPC network (projects/<p>/global/networks/<n>) when create_network = false."
  type        = string
  default     = ""
}

variable "subnetwork_id" {
  description = "Your subnet in var.region (projects/<p>/regions/<r>/subnetworks/<s>) for Direct VPC egress. It needs Private Google Access, Cloud NAT (ACME CAs, OIDC issuer) and routes to your devices' management networks."
  type        = string
  default     = ""
}

variable "create_private_service_access" {
  description = "Allocate a range and peer the VPC with Service Networking for Cloud SQL private IP. Set false if your network already has private services access."
  type        = bool
  default     = true
}

variable "engine_vpc_egress" {
  description = "Direct VPC egress mode for the engine: ALL_TRAFFIC (through your VPC and Cloud NAT: one egress IP to allowlist on devices) or PRIVATE_RANGES_ONLY."
  type        = string
  default     = "ALL_TRAFFIC"

  validation {
    condition     = contains(["ALL_TRAFFIC", "PRIVATE_RANGES_ONLY"], var.engine_vpc_egress)
    error_message = "engine_vpc_egress must be ALL_TRAFFIC or PRIVATE_RANGES_ONLY."
  }
}

# ---------------------------------------------------------------------------------------------
# Compute
# ---------------------------------------------------------------------------------------------

variable "engine_min_instances" {
  description = "Engine minimum instances. At least 1: the renewal loop runs in the background, with CPU always allocated."
  type        = number
  default     = 1

  validation {
    condition     = var.engine_min_instances >= 1
    error_message = "engine_min_instances must be at least 1 (the engine is not request-driven)."
  }
}

variable "engine_max_instances" {
  description = "Engine maximum instances. Every instance serves the API; one holds the leader lock."
  type        = number
  default     = 3
}

variable "engine_cpu" {
  description = "Engine CPU limit."
  type        = string
  default     = "1"
}

variable "engine_memory" {
  description = "Engine memory limit."
  type        = string
  default     = "1Gi"
}

variable "web_min_instances" {
  description = "Web minimum instances (0 allows scale to zero with a cold start)."
  type        = number
  default     = 1
}

variable "web_max_instances" {
  description = "Web maximum instances."
  type        = number
  default     = 10
}

# ---------------------------------------------------------------------------------------------
# Edge
# ---------------------------------------------------------------------------------------------

variable "domains" {
  description = "Hostnames for the dashboard. A Google-managed certificate is issued for them once their DNS points at the load balancer IP (output lb_ip_address). The first is NEXT_PUBLIC_SITE_URL."
  type        = list(string)

  validation {
    condition     = length(var.domains) > 0
    error_message = "Give at least one hostname for the dashboard."
  }
}

variable "enable_cloud_armor" {
  description = "Attach a Cloud Armor policy to the load balancer backends (per-IP rate limiting, optional allowlist)."
  type        = bool
  default     = true
}

variable "allowed_source_ranges" {
  description = "If set (max 10 CIDRs), Cloud Armor allows only these client ranges and denies everything else. Empty allows all, with rate limiting."
  type        = list(string)
  default     = []

  validation {
    condition     = length(var.allowed_source_ranges) <= 10
    error_message = "Cloud Armor accepts up to 10 ranges in one rule."
  }
}

variable "rate_limit_per_minute" {
  description = "Requests per minute per client IP before Cloud Armor answers 429 (when allowed_source_ranges is empty)."
  type        = number
  default     = 1200
}

# ---------------------------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------------------------

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

variable "db_cmek" {
  description = "Encrypt Cloud SQL with a Cloud KMS key from this module. The Cloud SQL service agent (service-<number>@gcp-sa-cloud-sql.iam.gserviceaccount.com) must already exist: run `gcloud beta services identity create --service=sqladmin.googleapis.com` once."
  type        = bool
  default     = false
}

# ---------------------------------------------------------------------------------------------
# Secrets, storage, keys
# ---------------------------------------------------------------------------------------------

variable "secret_store_prefix" {
  description = "Secret Manager name prefix under which the engine may read and add versions (device credentials entered in the dashboard). The module's own runtime secrets use <name>-runtime- and are excluded."
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

variable "dns_managed_zones" {
  description = "Cloud DNS managed zone names (in this project) the engine may change records in for DNS-01."
  type        = list(string)
  default     = []
}

# ---------------------------------------------------------------------------------------------
# Dashboard sign-in
# ---------------------------------------------------------------------------------------------

variable "oidc_issuer" {
  description = "OpenID Connect issuer URL. Setting it turns on SSO; you add the client secret to Secret Manager yourself. Empty falls back to a generated Basic-auth password."
  type        = string
  default     = ""

  validation {
    condition     = var.oidc_issuer == "" || startswith(var.oidc_issuer, "https://")
    error_message = "oidc_issuer must be an https:// URL."
  }
}

variable "oidc_client_id" {
  description = "OIDC client ID."
  type        = string
  default     = ""
}

variable "oidc_scopes" {
  description = "OIDC scopes. Google rejects \"groups\"."
  type        = string
  default     = "openid profile email"
}

variable "web_extra_env" {
  description = "Extra non-secret environment for the web app."
  type        = map(string)
  default     = {}
}

variable "engine_extra_env" {
  description = "Extra non-secret environment for the engine."
  type        = map(string)
  default     = {}
}
