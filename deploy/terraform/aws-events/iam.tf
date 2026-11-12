# One role per function, each with only what that function calls.

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account]
    }
  }
}

resource "aws_iam_role" "this" {
  for_each = local.functions

  name                 = "${local.function_names[each.key]}-role"
  description          = "Execution role for ${local.function_names[each.key]}"
  assume_role_policy   = data.aws_iam_policy_document.lambda_assume.json
  max_session_duration = 3600
  tags                 = local.tags
}

# --------------------------------------------------------------------------- acm_import

data "aws_iam_policy_document" "acm_import" {
  count = contains(keys(local.functions), "acm_import") ? 1 : 0

  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.this["acm_import"].arn}:*"]
  }

  statement {
    sid = "ManageCertificates"
    actions = [
      "acm:ImportCertificate",
      "acm:AddTagsToCertificate",
      "acm:DescribeCertificate",
      "acm:ListTagsForCertificate",
    ]
    resources = local.acm_certificate_arns
  }

  dynamic "statement" {
    # ListCertificates has no resource-level permissions; it is only needed to find
    # the certificate an "acm:new" endpoint was imported into on an earlier renewal.
    for_each = var.acm_discovery ? [1] : []
    content {
      sid       = "DiscoverCertificates"
      actions   = ["acm:ListCertificates"]
      resources = ["*"]
    }
  }

  statement {
    sid       = "ReadChains"
    actions   = ["s3:GetObject"]
    resources = local.chain_object_arns
  }

  statement {
    sid       = "ReadExportedKeys"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = ["${local.key_secret_arn_prefix}*"]
  }

  dynamic "statement" {
    for_each = length(var.kms_key_arns) > 0 ? [1] : []
    content {
      sid       = "DecryptViaSecretsManagerAndS3"
      actions   = ["kms:Decrypt"]
      resources = var.kms_key_arns

      condition {
        test     = "StringEquals"
        variable = "kms:ViaService"
        values   = ["secretsmanager.${local.region}.amazonaws.com", "s3.${local.region}.amazonaws.com"]
      }
    }
  }

  statement {
    sid       = "DeadLetter"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq["acm_import"].arn]
  }
}

# --------------------------------------------------------------------------- notify_router

data "aws_iam_policy_document" "notify_router" {
  count = contains(keys(local.functions), "notify_router") ? 1 : 0

  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.this["notify_router"].arn}:*"]
  }

  dynamic "statement" {
    for_each = length(compact([var.slack_webhook_secret_arn, var.webhook_secret_arn])) > 0 ? [1] : []
    content {
      sid       = "ReadSinkCredentials"
      actions   = ["secretsmanager:GetSecretValue"]
      resources = compact([var.slack_webhook_secret_arn, var.webhook_secret_arn])
    }
  }

  dynamic "statement" {
    for_each = length(var.kms_key_arns) > 0 ? [1] : []
    content {
      sid       = "DecryptViaSecretsManager"
      actions   = ["kms:Decrypt"]
      resources = var.kms_key_arns

      condition {
        test     = "StringEquals"
        variable = "kms:ViaService"
        values   = ["secretsmanager.${local.region}.amazonaws.com"]
      }
    }
  }

  statement {
    sid       = "Deduplicate"
    actions   = ["dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem"]
    resources = [aws_dynamodb_table.notify_dedupe[0].arn]
  }

  statement {
    sid       = "DeadLetter"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq["notify_router"].arn]
  }
}

locals {
  function_policies = merge(
    length(data.aws_iam_policy_document.acm_import) > 0 ? { acm_import = data.aws_iam_policy_document.acm_import[0].json } : {},
    length(data.aws_iam_policy_document.notify_router) > 0 ? { notify_router = data.aws_iam_policy_document.notify_router[0].json } : {},
  )
}

resource "aws_iam_role_policy" "this" {
  for_each = local.functions

  name   = "${local.function_names[each.key]}-policy"
  role   = aws_iam_role.this[each.key].id
  policy = local.function_policies[each.key]

  # Checked here because this is the first function resource to be created.
  lifecycle {
    precondition {
      condition     = each.key != "acm_import" || var.chain_bucket_name != null
      error_message = "acm_import needs chain_bucket_name."
    }
    precondition {
      condition     = each.key != "notify_router" || !contains(var.notify_sinks, "slack") || var.slack_webhook_secret_arn != null
      error_message = "The slack sink needs slack_webhook_secret_arn."
    }
    precondition {
      condition     = each.key != "notify_router" || !contains(var.notify_sinks, "webhook") || (var.webhook_url != null && var.webhook_secret_arn != null)
      error_message = "The webhook sink needs webhook_url and webhook_secret_arn."
    }
  }
}
