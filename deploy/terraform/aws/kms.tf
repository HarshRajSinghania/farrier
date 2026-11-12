# One customer-managed key for the deployment: it wraps the Farrier master key, and encrypts the
# S3 bucket, the Secrets Manager secrets, the RDS storage and the CloudWatch log groups.

data "aws_iam_policy_document" "kms" {
  statement {
    sid       = "AccountAdministration"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid = "CloudWatchLogs"
    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*",
    ]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["logs.${local.region}.amazonaws.com"]
    }

    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:/ecs/${var.name}/*"]
    }
  }
}

resource "aws_kms_key" "app" {
  description             = "${var.name}: Farrier master-key wrap, S3, Secrets Manager, RDS, logs"
  enable_key_rotation     = true
  deletion_window_in_days = var.kms_deletion_window_days
  policy                  = data.aws_iam_policy_document.kms.json
  tags                    = local.tags
}

resource "aws_kms_alias" "app" {
  name          = "alias/${var.name}"
  target_key_id = aws_kms_key.app.key_id
}
