data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  account   = data.aws_caller_identity.current.account_id
  region    = data.aws_region.current.name
  partition = data.aws_partition.current.partition

  tags = merge({ "farrier:component" = "events", "managed-by" = "terraform" }, var.tags)

  # The EventBridge source Farrier publishes with; detail-type is the CloudEvent type.
  event_source = "farrier"

  key_secret_arn_prefix = "arn:${local.partition}:secretsmanager:${local.region}:${local.account}:secret:${var.key_secret_prefix}"
  chain_object_arns     = var.chain_bucket_name == null ? [] : ["arn:${local.partition}:s3:::${var.chain_bucket_name}/${var.chain_key_prefix}*"]
  acm_certificate_arns = length(var.acm_certificate_arns) > 0 ? var.acm_certificate_arns : [
    "arn:${local.partition}:acm:${local.region}:${local.account}:certificate/*",
  ]

  # Everything the two functions have in common is driven from this map.
  all_functions = {
    acm_import = {
      enabled     = var.acm_import_zip != null
      zip         = var.acm_import_zip
      handler     = "acm_import.handler.handler"
      description = "Imports renewed Farrier certificates into ACM"
      event_types = tolist(["dev.farrier.renewal.done"])
      environment = tomap({
        ACM_NAME_PATTERN = var.acm_name_pattern
        ACM_DISCOVERY    = tostring(var.acm_discovery)
        ALLOWED_REF_PREFIXES = join(",", compact([
          var.chain_bucket_name == null ? null : "s3://${var.chain_bucket_name}/${var.chain_key_prefix}",
          "aws-sm:${local.key_secret_arn_prefix}",
        ]))
        LOG_LEVEL = var.log_level
      })
    }
    notify_router = {
      enabled     = var.notify_router_zip != null
      zip         = var.notify_router_zip
      handler     = "notify_router.handler.handler"
      description = "Routes failed, rolled back and manual Farrier renewals to Slack and webhooks"
      event_types = tolist(["dev.farrier.renewal.failed", "dev.farrier.renewal.rolled_back", "dev.farrier.renewal.awaiting_manual"])
      environment = tomap({
        NOTIFY_SINKS             = join(",", var.notify_sinks)
        SLACK_WEBHOOK_SECRET_ARN = var.slack_webhook_secret_arn
        WEBHOOK_URL              = var.webhook_url
        WEBHOOK_SECRET_ARN       = var.webhook_secret_arn
        IDEMPOTENCY_TABLE        = "${var.name_prefix}-notify-dedupe"
        FARRIER_DASHBOARD_URL    = var.dashboard_url
        LOG_LEVEL                = var.log_level
      })
    }
  }
  functions = { for k, v in local.all_functions : k => v if v.enabled }

  function_names = { for k in keys(local.functions) : k => "${var.name_prefix}-${replace(k, "_", "-")}" }
}

# --------------------------------------------------------------------------- the bus

resource "aws_cloudwatch_event_bus" "this" {
  name = var.name_prefix
  tags = local.tags
}

data "aws_iam_policy_document" "put_events" {
  statement {
    sid       = "FarrierEnginePutEvents"
    actions   = ["events:PutEvents"]
    resources = [aws_cloudwatch_event_bus.this.arn]

    # The engine may only publish as "farrier"; nothing else can impersonate it.
    condition {
      test     = "StringEquals"
      variable = "events:source"
      values   = [local.event_source]
    }
  }
}

# Resource policy on the bus: names the engine role as the only external publisher.
# Same-account callers also need the identity policy below.
data "aws_iam_policy_document" "bus" {
  statement {
    sid       = "FarrierEnginePutEvents"
    actions   = ["events:PutEvents"]
    resources = [aws_cloudwatch_event_bus.this.arn]

    principals {
      type        = "AWS"
      identifiers = [var.engine_role_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "events:source"
      values   = [local.event_source]
    }
  }
}

resource "aws_cloudwatch_event_bus_policy" "this" {
  event_bus_name = aws_cloudwatch_event_bus.this.name
  policy         = data.aws_iam_policy_document.bus.json
}

resource "aws_iam_policy" "engine_put_events" {
  name        = "${var.name_prefix}-engine-put-events"
  description = "Lets the Farrier engine publish renewal events to the ${var.name_prefix} bus"
  policy      = data.aws_iam_policy_document.put_events.json
  tags        = local.tags
}

resource "aws_iam_role_policy_attachment" "engine_put_events" {
  count      = var.attach_engine_policy ? 1 : 0
  role       = element(split("/", var.engine_role_arn), length(split("/", var.engine_role_arn)) - 1)
  policy_arn = aws_iam_policy.engine_put_events.arn
}

# --------------------------------------------------------------------------- rules and targets

resource "aws_cloudwatch_event_rule" "this" {
  for_each = local.functions

  name           = "${local.function_names[each.key]}-rule"
  description    = "Farrier ${join(", ", each.value.event_types)} -> ${local.function_names[each.key]}"
  event_bus_name = aws_cloudwatch_event_bus.this.name
  event_pattern = jsonencode({
    source        = [local.event_source]
    "detail-type" = each.value.event_types
  })
  tags = local.tags
}

resource "aws_cloudwatch_event_target" "this" {
  for_each = local.functions

  rule           = aws_cloudwatch_event_rule.this[each.key].name
  event_bus_name = aws_cloudwatch_event_bus.this.name
  target_id      = each.key
  arn            = aws_lambda_function.this[each.key].arn

  # Retries when EventBridge cannot invoke the function at all.
  retry_policy {
    maximum_event_age_in_seconds = var.event_max_age_seconds
    maximum_retry_attempts       = var.event_retry_attempts
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq[each.key].arn
  }
}

resource "aws_lambda_permission" "events" {
  for_each = local.functions

  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.this[each.key].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.this[each.key].arn
}

# --------------------------------------------------------------------------- dead-letter queues

# One DLQ per function receives both EventBridge delivery failures and Lambda
# async failures (the function raised on every attempt). Each message is the
# original event plus failure metadata; redrive after fixing the cause.
resource "aws_sqs_queue" "dlq" {
  for_each = local.functions

  name                      = "${local.function_names[each.key]}-dlq"
  message_retention_seconds = var.dlq_retention_seconds
  sqs_managed_sse_enabled   = true
  tags                      = local.tags
}

data "aws_iam_policy_document" "dlq" {
  for_each = local.functions

  statement {
    sid       = "EventBridgeDeadLetter"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq[each.key].arn]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.this[each.key].arn]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["sqs:*"]
    resources = [aws_sqs_queue.dlq[each.key].arn]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_sqs_queue_policy" "dlq" {
  for_each = local.functions

  queue_url = aws_sqs_queue.dlq[each.key].id
  policy    = data.aws_iam_policy_document.dlq[each.key].json
}

# --------------------------------------------------------------------------- functions

resource "aws_cloudwatch_log_group" "this" {
  for_each = local.functions

  name              = "/aws/lambda/${local.function_names[each.key]}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.log_kms_key_arn
  tags              = local.tags
}

resource "aws_lambda_function" "this" {
  for_each = local.functions

  function_name                  = local.function_names[each.key]
  description                    = each.value.description
  role                           = aws_iam_role.this[each.key].arn
  filename                       = each.value.zip
  source_code_hash               = filebase64sha256(each.value.zip)
  handler                        = each.value.handler
  runtime                        = var.lambda_runtime
  architectures                  = [var.lambda_architecture]
  timeout                        = var.lambda_timeout_seconds
  memory_size                    = var.lambda_memory_mb
  reserved_concurrent_executions = var.lambda_reserved_concurrency

  environment {
    variables = { for k, v in each.value.environment : k => v if v != null && v != "" }
  }

  logging_config {
    log_format = "Text" # the functions already write one JSON object per line
    log_group  = aws_cloudwatch_log_group.this[each.key].name
  }

  tags = local.tags

  depends_on = [aws_iam_role_policy.this]
}

# Retries when the function raises (TransientError after in-process retries, or
# PermanentError for poison events), then dead-letter.
resource "aws_lambda_function_event_invoke_config" "this" {
  for_each = local.functions

  function_name                = aws_lambda_function.this[each.key].function_name
  maximum_retry_attempts       = var.lambda_retry_attempts
  maximum_event_age_in_seconds = var.event_max_age_seconds

  destination_config {
    on_failure {
      destination = aws_sqs_queue.dlq[each.key].arn
    }
  }
}

# --------------------------------------------------------------------------- notify_router dedupe table

resource "aws_dynamodb_table" "notify_dedupe" {
  count = contains(keys(local.functions), "notify_router") ? 1 : 0

  name         = "${var.name_prefix}-notify-dedupe"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"

  attribute {
    name = "pk"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = local.tags
}
