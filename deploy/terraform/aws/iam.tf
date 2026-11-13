# Least-privilege roles. Execution roles pull logs and inject secrets at task start; task roles are
# what the running containers can do. No static access keys anywhere.

data "aws_iam_policy_document" "ecs_tasks_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

# ---------------------------------------------------------------------------------------------
# Execution roles (one per service, so the web service can never be handed the master key)
# ---------------------------------------------------------------------------------------------

data "aws_iam_policy_document" "engine_execution" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.engine.arn}:*"]
  }

  statement {
    sid       = "InjectSecrets"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = local.engine_secret_arns
  }

  statement {
    sid       = "DecryptSecrets"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.app.arn]
  }
}

resource "aws_iam_role" "engine_execution" {
  name               = "${var.name}-engine-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
  tags               = local.tags
}

resource "aws_iam_role_policy" "engine_execution" {
  name   = "execution"
  role   = aws_iam_role.engine_execution.id
  policy = data.aws_iam_policy_document.engine_execution.json
}

data "aws_iam_policy_document" "web_execution" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.web.arn}:*"]
  }

  statement {
    sid       = "InjectSecrets"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = local.web_secret_arns
  }

  statement {
    sid       = "DecryptSecrets"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.app.arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${local.region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "web_execution" {
  name               = "${var.name}-web-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
  tags               = local.tags
}

resource "aws_iam_role_policy" "web_execution" {
  name   = "execution"
  role   = aws_iam_role.web_execution.id
  policy = data.aws_iam_policy_document.web_execution.json
}

# ---------------------------------------------------------------------------------------------
# Engine task role
# ---------------------------------------------------------------------------------------------

data "aws_iam_policy_document" "engine_task" {
  statement {
    sid = "SecretStorePrefix"
    actions = [
      "secretsmanager:CreateSecret",
      "secretsmanager:DeleteSecret",
      "secretsmanager:DescribeSecret",
      "secretsmanager:GetSecretValue",
      "secretsmanager:PutSecretValue",
      "secretsmanager:RestoreSecret",
      "secretsmanager:TagResource",
      "secretsmanager:UpdateSecret",
    ]
    resources = ["arn:${local.partition}:secretsmanager:${local.region}:${local.account_id}:secret:${var.secret_store_prefix}*"]
  }

  statement {
    sid = "AppKey"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey",
    ]
    resources = [aws_kms_key.app.arn]
  }

  statement {
    sid       = "ListOwnPrefix"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.objects.arn]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["${var.storage_prefix}*"]
    }
  }

  statement {
    sid = "ObjectsOwnPrefix"
    actions = [
      "s3:AbortMultipartUpload",
      "s3:DeleteObject",
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:PutObject",
    ]
    resources = ["${aws_s3_bucket.objects.arn}/${var.storage_prefix}*"]
  }

  dynamic "statement" {
    for_each = length(var.route53_zone_ids) > 0 ? [1] : []

    content {
      sid       = "AcmeChallengeRecords"
      actions   = ["route53:ChangeResourceRecordSets"]
      resources = [for z in var.route53_zone_ids : "arn:${local.partition}:route53:::hostedzone/${z}"]

      condition {
        test     = "ForAllValues:StringLike"
        variable = "route53:ChangeResourceRecordSetsNormalizedRecordNames"
        values   = ["_acme-challenge.*"]
      }

      condition {
        test     = "ForAllValues:StringEquals"
        variable = "route53:ChangeResourceRecordSetsRecordTypes"
        values   = ["TXT"]
      }
    }
  }

  dynamic "statement" {
    for_each = length(var.route53_zone_ids) > 0 ? [1] : []

    content {
      sid       = "AcmeChallengeRead"
      actions   = ["route53:ListResourceRecordSets", "route53:GetHostedZone"]
      resources = [for z in var.route53_zone_ids : "arn:${local.partition}:route53:::hostedzone/${z}"]
    }
  }

  dynamic "statement" {
    for_each = length(var.route53_zone_ids) > 0 ? [1] : []

    content {
      sid       = "AcmeChallengePropagation"
      actions   = ["route53:GetChange"]
      resources = ["arn:${local.partition}:route53:::change/*"]
    }
  }

  dynamic "statement" {
    for_each = length(var.acm_acme_endpoint_arns) > 0 ? [1] : []

    content {
      sid       = "AcmManagedAcme"
      actions   = ["acm:DescribeAcmeEndpoint", "acm:GetAcmeExternalAccountBindingCredentials"]
      resources = flatten([for a in var.acm_acme_endpoint_arns : [a, "${a}/*"]])
    }
  }
}

resource "aws_iam_role" "engine_task" {
  name               = "${var.name}-engine-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
  tags               = local.tags
}

resource "aws_iam_role_policy" "engine_task" {
  name   = "engine"
  role   = aws_iam_role.engine_task.id
  policy = data.aws_iam_policy_document.engine_task.json
}

# ---------------------------------------------------------------------------------------------
# Web task role: read its own secrets, nothing else
# ---------------------------------------------------------------------------------------------

data "aws_iam_policy_document" "web_task" {
  statement {
    sid       = "OwnSecrets"
    actions   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
    resources = local.web_secret_arns
  }

  statement {
    sid       = "DecryptOwnSecrets"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.app.arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${local.region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "web_task" {
  name               = "${var.name}-web-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
  tags               = local.tags
}

resource "aws_iam_role_policy" "web_task" {
  name   = "web"
  role   = aws_iam_role.web_task.id
  policy = data.aws_iam_policy_document.web_task.json
}
