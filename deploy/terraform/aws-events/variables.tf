variable "name_prefix" {
  description = "Prefix for every resource name (bus, functions, queues, roles)."
  type        = string
  default     = "farrier"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,30}$", var.name_prefix))
    error_message = "name_prefix must be 2-31 characters: lowercase letters, digits and hyphens, starting with a letter."
  }
}

variable "engine_role_arn" {
  description = "IAM role the Farrier engine runs as (IRSA, ECS task or EC2 instance role). It is the only principal allowed to put events on the bus."
  type        = string

  validation {
    condition     = can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:role/.+$", var.engine_role_arn))
    error_message = "engine_role_arn must be an IAM role ARN."
  }
}

variable "attach_engine_policy" {
  description = "Attach the events:PutEvents policy to engine_role_arn. Set false if the role is managed elsewhere and attach output engine_put_events_policy_arn yourself."
  type        = bool
  default     = false
}

# --------------------------------------------------------------------------- artifacts

variable "acm_import_zip" {
  description = "Path to acm_import.zip from functions/aws/acm_import/build.sh. null disables the ACM import function and its rule."
  type        = string
  default     = null

  validation {
    condition     = var.acm_import_zip == null || endswith(coalesce(var.acm_import_zip, "x.zip"), ".zip")
    error_message = "acm_import_zip must be a .zip file."
  }
}

variable "notify_router_zip" {
  description = "Path to notify_router.zip from functions/aws/notify_router/build.sh. null disables the notify router and its rule."
  type        = string
  default     = null

  validation {
    condition     = var.notify_router_zip == null || endswith(coalesce(var.notify_router_zip, "x.zip"), ".zip")
    error_message = "notify_router_zip must be a .zip file."
  }
}

# --------------------------------------------------------------------------- where Farrier exports material

variable "chain_bucket_name" {
  description = "S3 bucket Farrier writes certificate chains to (the bucket in chain_ref)."
  type        = string
  default     = null

  validation {
    condition     = var.chain_bucket_name == null || can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", coalesce(var.chain_bucket_name, "ok")))
    error_message = "chain_bucket_name must be a valid S3 bucket name."
  }
}

variable "chain_key_prefix" {
  description = "Key prefix of chain objects inside chain_bucket_name, e.g. \"prod/\". The ACM function may read only below it."
  type        = string
  default     = ""

  validation {
    condition     = !startswith(var.chain_key_prefix, "/") && !strcontains(var.chain_key_prefix, "*")
    error_message = "chain_key_prefix must not start with / or contain wildcards."
  }
}

variable "key_secret_prefix" {
  description = "Secrets Manager name prefix of exported private keys. The ACM function may read only secrets below it."
  type        = string
  default     = "farrier/keys/"

  validation {
    condition     = can(regex("^[A-Za-z0-9/_+=.@-]+/$", var.key_secret_prefix))
    error_message = "key_secret_prefix must be a secret name prefix ending in /, without wildcards."
  }
}

variable "kms_key_arns" {
  description = "Customer managed KMS keys that encrypt the key secrets, chain objects or notification secrets. Decrypt is allowed only via Secrets Manager and S3."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for k in var.kms_key_arns : can(regex("^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-f-]+$", k))])
    error_message = "kms_key_arns must contain KMS key ARNs (not aliases)."
  }
}

# --------------------------------------------------------------------------- acm_import

variable "acm_certificate_arns" {
  description = "ACM certificate ARNs the import function may modify. Empty means any certificate in this account and region (required for acm:new)."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for a in var.acm_certificate_arns : can(regex("^arn:aws[a-z-]*:acm:[a-z0-9-]+:[0-9]{12}:certificate/[0-9a-f-]{36}$", a))])
    error_message = "acm_certificate_arns must contain ACM certificate ARNs."
  }
}

variable "acm_name_pattern" {
  description = "Optional glob on endpoint names to import without an acm: tag, e.g. \"*-public-lb\"."
  type        = string
  default     = null
}

variable "acm_discovery" {
  description = "Let acm:new find the certificate imported for an endpoint earlier (needs acm:ListCertificates on *). Disable to require acm:<arn> tags."
  type        = bool
  default     = true
}

# --------------------------------------------------------------------------- notify_router

variable "notify_sinks" {
  description = "Sinks the notify router delivers to."
  type        = list(string)
  default     = ["slack"]

  validation {
    condition     = length(var.notify_sinks) > 0 && alltrue([for s in var.notify_sinks : contains(["slack", "webhook"], s)])
    error_message = "notify_sinks must be a non-empty subset of [\"slack\", \"webhook\"]."
  }
}

variable "slack_webhook_secret_arn" {
  description = "Secrets Manager secret whose value is the Slack incoming-webhook URL. Required when notify_sinks contains slack."
  type        = string
  default     = null

  validation {
    condition     = var.slack_webhook_secret_arn == null || can(regex("^arn:aws[a-z-]*:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:.+$", coalesce(var.slack_webhook_secret_arn, "x")))
    error_message = "slack_webhook_secret_arn must be a Secrets Manager secret ARN."
  }
}

variable "webhook_url" {
  description = "HTTPS endpoint for the generic webhook sink."
  type        = string
  default     = null

  validation {
    condition     = var.webhook_url == null || startswith(coalesce(var.webhook_url, "https://"), "https://")
    error_message = "webhook_url must use https://."
  }
}

variable "webhook_secret_arn" {
  description = "Secrets Manager secret holding the HMAC-SHA256 key for X-Farrier-Signature. Required when notify_sinks contains webhook."
  type        = string
  default     = null

  validation {
    condition     = var.webhook_secret_arn == null || can(regex("^arn:aws[a-z-]*:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:.+$", coalesce(var.webhook_secret_arn, "x")))
    error_message = "webhook_secret_arn must be a Secrets Manager secret ARN."
  }
}

variable "dashboard_url" {
  description = "Farrier dashboard base URL, linked from notifications."
  type        = string
  default     = null

  validation {
    condition     = var.dashboard_url == null || startswith(coalesce(var.dashboard_url, "https://"), "https://")
    error_message = "dashboard_url must use https://."
  }
}

# --------------------------------------------------------------------------- delivery, runtime, operations

variable "event_max_age_seconds" {
  description = "How long EventBridge and Lambda keep retrying an event before it goes to the DLQ."
  type        = number
  default     = 3600

  validation {
    condition     = var.event_max_age_seconds >= 60 && var.event_max_age_seconds <= 21600
    error_message = "event_max_age_seconds must be between 60 and 21600 (Lambda's async limit)."
  }
}

variable "event_retry_attempts" {
  description = "EventBridge retries when it cannot invoke the function (throttling, service errors)."
  type        = number
  default     = 8

  validation {
    condition     = var.event_retry_attempts >= 0 && var.event_retry_attempts <= 185
    error_message = "event_retry_attempts must be between 0 and 185."
  }
}

variable "lambda_retry_attempts" {
  description = "Lambda async retries when the function raises. Then the event goes to the DLQ."
  type        = number
  default     = 2

  validation {
    condition     = contains([0, 1, 2], var.lambda_retry_attempts)
    error_message = "lambda_retry_attempts must be 0, 1 or 2."
  }
}

variable "lambda_runtime" {
  description = "Lambda Python runtime."
  type        = string
  default     = "python3.12"

  validation {
    condition     = can(regex("^python3\\.(1[2-9])$", var.lambda_runtime))
    error_message = "lambda_runtime must be python3.12 or newer."
  }
}

variable "lambda_architecture" {
  description = "Lambda architecture. The artifacts are pure Python, so either works."
  type        = string
  default     = "arm64"

  validation {
    condition     = contains(["arm64", "x86_64"], var.lambda_architecture)
    error_message = "lambda_architecture must be arm64 or x86_64."
  }
}

variable "lambda_timeout_seconds" {
  description = "Function timeout."
  type        = number
  default     = 60

  validation {
    condition     = var.lambda_timeout_seconds >= 10 && var.lambda_timeout_seconds <= 900
    error_message = "lambda_timeout_seconds must be between 10 and 900."
  }
}

variable "lambda_memory_mb" {
  description = "Function memory."
  type        = number
  default     = 256

  validation {
    condition     = var.lambda_memory_mb >= 128 && var.lambda_memory_mb <= 10240
    error_message = "lambda_memory_mb must be between 128 and 10240."
  }
}

variable "lambda_reserved_concurrency" {
  description = "Reserved concurrency per function; caps blast radius and API rate. -1 means unreserved."
  type        = number
  default     = 5

  validation {
    condition     = var.lambda_reserved_concurrency == -1 || var.lambda_reserved_concurrency >= 1
    error_message = "lambda_reserved_concurrency must be -1 or at least 1."
  }
}

variable "log_level" {
  description = "Function log level."
  type        = string
  default     = "INFO"

  validation {
    condition     = contains(["DEBUG", "INFO", "WARNING", "ERROR"], var.log_level)
    error_message = "log_level must be DEBUG, INFO, WARNING or ERROR."
  }
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for the functions."
  type        = number
  default     = 90

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "log_retention_days must be a value CloudWatch Logs accepts (1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, ...)."
  }
}

variable "log_kms_key_arn" {
  description = "Optional KMS key for the log groups. Its key policy must allow the CloudWatch Logs service principal."
  type        = string
  default     = null
}

variable "dlq_retention_seconds" {
  description = "How long dead-lettered events are kept."
  type        = number
  default     = 1209600

  validation {
    condition     = var.dlq_retention_seconds >= 60 && var.dlq_retention_seconds <= 1209600
    error_message = "dlq_retention_seconds must be between 60 and 1209600 (14 days)."
  }
}

variable "alarm_topic_arn" {
  description = "SNS topic for DLQ, error and failed-invocation alarms. null creates the alarms without actions."
  type        = string
  default     = null

  validation {
    condition     = var.alarm_topic_arn == null || can(regex("^arn:aws[a-z-]*:sns:[a-z0-9-]+:[0-9]{12}:.+$", coalesce(var.alarm_topic_arn, "x")))
    error_message = "alarm_topic_arn must be an SNS topic ARN."
  }
}

variable "tags" {
  description = "Tags added to every resource."
  type        = map(string)
  default     = {}
}
