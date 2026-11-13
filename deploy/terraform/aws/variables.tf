# ---------------------------------------------------------------------------------------------
# General
# ---------------------------------------------------------------------------------------------

variable "name" {
  description = "Name prefix for every resource. Lowercase letters, digits and hyphens."
  type        = string
  default     = "farrier"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,19}$", var.name))
    error_message = "name must be 2-20 characters: lowercase letters, digits and hyphens, starting with a letter."
  }
}

variable "tags" {
  description = "Tags added to every resource."
  type        = map(string)
  default     = {}
}

variable "farrier_version" {
  description = "Farrier release to run. Selects ghcr.io/gagankarthik/farrier:<version> and farrier-web:<version>."
  type        = string
  default     = "0.2.0"

  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+(-[0-9A-Za-z.-]+)?$", var.farrier_version))
    error_message = "farrier_version must be a SemVer version such as 0.2.0."
  }
}

variable "engine_image" {
  description = "Override the engine image (for a mirrored registry or a digest pin, e.g. 123.dkr.ecr...amazonaws.com/farrier@sha256:...). Empty uses ghcr.io/gagankarthik/farrier:<farrier_version>."
  type        = string
  default     = ""
}

variable "web_image" {
  description = "Override the web image. Empty uses ghcr.io/gagankarthik/farrier-web:<farrier_version>."
  type        = string
  default     = ""
}

variable "secrets_seeded" {
  description = "Set to true after you have put the wrapped master key (and the OIDC client secret, if OIDC is on) into Secrets Manager. Until then the ECS services are not created, so nothing crash-loops on a missing secret."
  type        = bool
  default     = false
}

variable "deletion_protection" {
  description = "Deletion protection on the database and load balancers. Turn off only to tear down."
  type        = bool
  default     = true
}

# ---------------------------------------------------------------------------------------------
# Network (bring your own VPC by default)
# ---------------------------------------------------------------------------------------------

variable "create_vpc" {
  description = "Create a new VPC (public subnets for the NAT gateway, private subnets for everything else). Leave false to use your own VPC through vpc_id and private_subnet_ids."
  type        = bool
  default     = false
}

variable "vpc_cidr" {
  description = "CIDR of the VPC created when create_vpc = true."
  type        = string
  default     = "10.40.0.0/16"

  validation {
    condition     = can(cidrnetmask(var.vpc_cidr))
    error_message = "vpc_cidr must be a valid IPv4 CIDR block."
  }
}

variable "az_count" {
  description = "Availability zones to span when create_vpc = true."
  type        = number
  default     = 2

  validation {
    condition     = var.az_count >= 2 && var.az_count <= 4
    error_message = "az_count must be between 2 and 4."
  }
}

variable "vpc_id" {
  description = "Your VPC (when create_vpc = false). It must have an internet gateway attached: CloudFront VPC origins require one, although no traffic is routed through it."
  type        = string
  default     = ""
}

variable "private_subnet_ids" {
  description = "Your private subnets (when create_vpc = false), in at least two AZs, with outbound access through a NAT gateway or proxy (ACME CAs) and routes to your devices' management networks. Engine, web, internal load balancers and the database go here."
  type        = list(string)
  default     = []
}

variable "database_subnet_ids" {
  description = "Optional separate subnets for RDS. Empty uses private_subnet_ids."
  type        = list(string)
  default     = []
}

variable "engine_egress_cidrs" {
  description = "Where the engine may connect: ACME CAs, DNS APIs, your devices. Narrow it to your management networks plus a proxy if you have an egress proxy."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "engine_api_allowed_cidrs" {
  description = "Extra private CIDRs allowed to call the engine API on its internal load balancer (CI runners, automation). The web service is always allowed. Never 0.0.0.0/0."
  type        = list(string)
  default     = []

  validation {
    condition     = !contains(var.engine_api_allowed_cidrs, "0.0.0.0/0")
    error_message = "The engine API is never public: remove 0.0.0.0/0."
  }
}

# ---------------------------------------------------------------------------------------------
# Compute
# ---------------------------------------------------------------------------------------------

variable "cpu_architecture" {
  description = "Fargate CPU architecture. Both images are multi-arch; ARM64 (Graviton) is cheaper."
  type        = string
  default     = "ARM64"

  validation {
    condition     = contains(["ARM64", "X86_64"], var.cpu_architecture)
    error_message = "cpu_architecture must be ARM64 or X86_64."
  }
}

variable "engine_desired_count" {
  description = "Engine tasks. Every task serves the API; one holds the PostgreSQL leader lock and runs the renewal loop."
  type        = number
  default     = 2

  validation {
    condition     = var.engine_desired_count >= 1 && var.engine_desired_count <= 10
    error_message = "engine_desired_count must be between 1 and 10."
  }
}

variable "engine_cpu" {
  description = "Engine task CPU units (1024 = 1 vCPU)."
  type        = number
  default     = 512
}

variable "engine_memory" {
  description = "Engine task memory in MiB."
  type        = number
  default     = 1024
}

variable "web_desired_count" {
  description = "Web tasks. Stateless; scale freely."
  type        = number
  default     = 2

  validation {
    condition     = var.web_desired_count >= 1
    error_message = "web_desired_count must be at least 1."
  }
}

variable "web_cpu" {
  description = "Web task CPU units."
  type        = number
  default     = 256
}

variable "web_memory" {
  description = "Web task memory in MiB."
  type        = number
  default     = 512
}

variable "engine_certificate_arn" {
  description = "Optional ACM certificate for an HTTPS listener on the internal engine load balancer. Requires engine_domain_name, which you point at the load balancer in a private hosted zone. Without it, web-to-engine traffic is HTTP inside the VPC (the API token still travels in it)."
  type        = string
  default     = ""
}

variable "engine_domain_name" {
  description = "Private DNS name for the engine (e.g. farrier-engine.corp.internal) matching engine_certificate_arn."
  type        = string
  default     = ""
}

# ---------------------------------------------------------------------------------------------
# Edge (CloudFront)
# ---------------------------------------------------------------------------------------------

variable "domain_names" {
  description = "Custom hostnames for the dashboard (CloudFront aliases). The first one becomes NEXT_PUBLIC_SITE_URL. Empty uses the *.cloudfront.net name."
  type        = list(string)
  default     = []
}

variable "cloudfront_certificate_arn" {
  description = "ACM certificate in us-east-1 covering domain_names. Required when domain_names is set; enables the TLSv1.2_2021 minimum protocol."
  type        = string
  default     = ""
}

variable "web_acl_arn" {
  description = "Optional WAFv2 web ACL (scope CLOUDFRONT, in us-east-1) to associate with the distribution."
  type        = string
  default     = ""
}

variable "cloudfront_price_class" {
  description = "CloudFront price class."
  type        = string
  default     = "PriceClass_100"

  validation {
    condition     = contains(["PriceClass_All", "PriceClass_200", "PriceClass_100"], var.cloudfront_price_class)
    error_message = "cloudfront_price_class must be PriceClass_All, PriceClass_200 or PriceClass_100."
  }
}

# ---------------------------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------------------------

variable "db_engine_version" {
  description = "RDS PostgreSQL major (or major.minor) version."
  type        = string
  default     = "16"
}

variable "db_instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.t4g.medium"
}

variable "db_allocated_storage" {
  description = "Initial storage in GiB."
  type        = number
  default     = 20
}

variable "db_max_allocated_storage" {
  description = "Storage autoscaling ceiling in GiB."
  type        = number
  default     = 100
}

variable "db_multi_az" {
  description = "Run a synchronous standby in a second AZ."
  type        = bool
  default     = true
}

variable "db_iam_auth" {
  description = "Enable IAM database authentication on the instance (for human/break-glass access; the engine uses the managed password)."
  type        = bool
  default     = false
}

variable "db_username" {
  description = "Master user name. The password is generated and kept in Secrets Manager by RDS."
  type        = string
  default     = "farrier"
}

variable "db_backup_retention_days" {
  description = "Automated backup retention in days."
  type        = number
  default     = 14

  validation {
    condition     = var.db_backup_retention_days >= 1 && var.db_backup_retention_days <= 35
    error_message = "db_backup_retention_days must be between 1 and 35."
  }
}

# ---------------------------------------------------------------------------------------------
# Secrets, storage, keys, logs
# ---------------------------------------------------------------------------------------------

variable "secret_store_prefix" {
  description = "Secrets Manager name prefix the engine may create and read (FARRIER_SECRET_AWS_PREFIX). Device credentials entered in the dashboard land here."
  type        = string
  default     = "farrier/"

  validation {
    condition     = can(regex("^[A-Za-z0-9/_+=.@-]+/$", var.secret_store_prefix))
    error_message = "secret_store_prefix must end with a slash, e.g. farrier/."
  }
}

variable "secret_recovery_window_days" {
  description = "Days a deleted Secrets Manager secret can be restored (0 deletes immediately)."
  type        = number
  default     = 30
}

variable "storage_prefix" {
  description = "Key prefix inside the bucket for change packs, backups and audit exports."
  type        = string
  default     = "farrier/"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9/_.-]*/$", var.storage_prefix))
    error_message = "storage_prefix must end with a slash, e.g. farrier/."
  }
}

variable "storage_admin_principal_arns" {
  description = "IAM role/user ARNs (besides the engine task role) allowed to write or delete objects in the bucket, e.g. a break-glass admin role. The bucket policy denies object writes to everyone else, including the principal running Terraform, so force_destroy_bucket needs it listed here."
  type        = list(string)
  default     = []
}

variable "force_destroy_bucket" {
  description = "Allow terraform destroy to delete a non-empty bucket. Keep false in production."
  type        = bool
  default     = false
}

variable "kms_deletion_window_days" {
  description = "Waiting period before the CMK is deleted after a destroy."
  type        = number
  default     = 30

  validation {
    condition     = var.kms_deletion_window_days >= 7 && var.kms_deletion_window_days <= 30
    error_message = "kms_deletion_window_days must be between 7 and 30."
  }
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention."
  type        = number
  default     = 90

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "log_retention_days must be a value CloudWatch Logs accepts (e.g. 30, 90, 365)."
  }
}

variable "route53_zone_ids" {
  description = "Route 53 hosted zones the engine may write _acme-challenge TXT records in (DNS-01). Empty grants no Route 53 access."
  type        = list(string)
  default     = []
}

variable "acm_acme_endpoint_arns" {
  description = "ACM managed ACME endpoints whose directory URL and EAB key the engine may read (issuers.json preset aws-acm with acm_eab_arn). Empty grants no ACM access."
  type        = list(string)
  default     = []
}

variable "assumable_role_arns" {
  description = "IAM roles, usually in other accounts, the engine may sts:AssumeRole into (aws_acm connector role_arn, cloud_inventory aws_accounts). Each role must trust the engine role. Empty grants none."
  type        = list(string)
  default     = []
}

# ---------------------------------------------------------------------------------------------
# Dashboard sign-in
# ---------------------------------------------------------------------------------------------

variable "oidc_issuer" {
  description = "OpenID Connect issuer URL. Setting it turns on SSO (recommended); the client secret is then seeded into Secrets Manager by you. Empty falls back to a generated Basic-auth password."
  type        = string
  default     = ""

  validation {
    condition     = var.oidc_issuer == "" || startswith(var.oidc_issuer, "https://")
    error_message = "oidc_issuer must be an https:// URL."
  }
}

variable "oidc_client_id" {
  description = "OIDC client ID (not secret)."
  type        = string
  default     = ""
}

variable "oidc_scopes" {
  description = "OIDC scopes. Google and Entra ID reject \"groups\": use \"openid profile email\" with them."
  type        = string
  default     = "openid profile email groups"
}

variable "web_extra_env" {
  description = "Extra non-secret environment for the web app, e.g. FARRIER_OIDC_ADMIN_GROUPS, FARRIER_OIDC_ROLE_CLAIM."
  type        = map(string)
  default     = {}
}

variable "engine_extra_env" {
  description = "Extra non-secret environment for the engine."
  type        = map(string)
  default     = {}
}
