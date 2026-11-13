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

variable "deletion_protection" {
  description = "Deletion protection on the database. Turn off only to tear down."
  type        = bool
  default     = true
}

# ---------------------------------------------------------------------------------------------
# Cluster and workload identity
# ---------------------------------------------------------------------------------------------

variable "cluster_name" {
  description = "Name of the existing EKS cluster Farrier is installed into. The module reads its OIDC issuer, VPC, subnets and cluster security group; it never creates or changes the cluster."
  type        = string

  validation {
    condition     = length(var.cluster_name) > 0
    error_message = "cluster_name is required."
  }
}

variable "namespace" {
  description = "Kubernetes namespace of the Helm release."
  type        = string
  default     = "farrier"

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$", var.namespace))
    error_message = "namespace must be a DNS-1123 label."
  }
}

variable "service_account_name" {
  description = "Engine ServiceAccount name (Helm value engine.serviceAccount.name). The IAM role trusts exactly this account."
  type        = string
  default     = "farrier-engine"

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$", var.service_account_name))
    error_message = "service_account_name must be a DNS-1123 subdomain."
  }
}

variable "identity" {
  description = "How pods get AWS credentials: irsa (IAM roles for service accounts; needs the cluster's IAM OIDC provider) or pod_identity (EKS Pod Identity; needs the eks-pod-identity-agent add-on)."
  type        = string
  default     = "irsa"

  validation {
    condition     = contains(["irsa", "pod_identity"], var.identity)
    error_message = "identity must be irsa or pod_identity."
  }
}

variable "external_secrets_service_account_name" {
  description = "ServiceAccount the External Secrets SecretStore authenticates as (irsa only). Created by kubernetes_manifests in namespace."
  type        = string
  default     = "farrier-external-secrets"

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$", var.external_secrets_service_account_name))
    error_message = "external_secrets_service_account_name must be a DNS-1123 subdomain."
  }
}

variable "external_secrets_controller_namespace" {
  description = "Namespace of the External Secrets Operator controller (pod_identity only: the ESO role is associated with the controller's ServiceAccount)."
  type        = string
  default     = "external-secrets"
}

variable "external_secrets_controller_service_account" {
  description = "ServiceAccount of the External Secrets Operator controller (pod_identity only)."
  type        = string
  default     = "external-secrets"
}

# ---------------------------------------------------------------------------------------------
# Dashboard sign-in
# ---------------------------------------------------------------------------------------------

variable "oidc_enabled" {
  description = "The dashboard uses SSO (web.auth.mode=oidc): a session secret is generated and an empty oidc-client-secret is created for you to seed. False generates a Basic-auth dashboard password instead. Configure the issuer and client ID in your Helm values."
  type        = bool
  default     = false
}

# ---------------------------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------------------------

variable "create_database" {
  description = "Create an RDS PostgreSQL instance for the engine (needed for more than one engine replica)."
  type        = bool
  default     = true
}

variable "vpc_id" {
  description = "VPC for the database security group. Empty uses the cluster's VPC."
  type        = string
  default     = ""
}

variable "database_subnet_ids" {
  description = "Subnets for RDS, in at least two AZs. Empty uses the cluster's subnets (prefer private or isolated subnets here if the cluster also has public ones)."
  type        = list(string)
  default     = []
}

variable "db_allowed_cidrs" {
  description = "Extra CIDRs allowed to reach PostgreSQL on 5432, e.g. node subnets of self-managed node groups that do not carry the cluster security group, or pod CIDRs with security groups for pods. The cluster security group is always allowed."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for c in var.db_allowed_cidrs : can(cidrnetmask(c)) && c != "0.0.0.0/0"])
    error_message = "db_allowed_cidrs must be IPv4 CIDR blocks, and never 0.0.0.0/0."
  }
}

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
# Secrets, storage, keys, integrations
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
  description = "IAM role/user ARNs (besides the engine role) allowed to write or delete objects in the bucket, e.g. a break-glass admin role. The bucket policy denies object writes to everyone else, including the principal running Terraform, so force_destroy_bucket needs it listed here."
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

variable "event_bus_arn" {
  description = "Optional EventBridge bus the engine publishes certificate events to (e.g. the aws-events module's bus). Empty grants no EventBridge access."
  type        = string
  default     = ""

  validation {
    condition     = var.event_bus_arn == "" || can(regex("^arn:aws[a-z-]*:events:", var.event_bus_arn))
    error_message = "event_bus_arn must be an EventBridge event bus ARN."
  }
}
