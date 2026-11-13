# Two least-privilege roles, both assumed through workload identity (no static access keys):
#
# * engine: what the running engine calls (its Secrets Manager prefix, the CMK, its S3 prefix,
#   optional Route 53 and EventBridge). It never reads the runtime secrets: ESO injects them.
# * external-secrets: read-only on the runtime secrets and the RDS secret, for the SecretStore.

# ---------------------------------------------------------------------------------------------
# Trust policies
# ---------------------------------------------------------------------------------------------

# IRSA: the cluster's IAM OIDC provider vouches for one ServiceAccount in one namespace.
data "aws_iam_policy_document" "irsa_assume" {
  for_each = local.irsa ? {
    engine           = "system:serviceaccount:${var.namespace}:${var.service_account_name}"
    external_secrets = "system:serviceaccount:${var.namespace}:${var.external_secrets_service_account_name}"
  } : {}

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [data.aws_iam_openid_connect_provider.this[0].arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_issuer_host}:sub"
      values   = [each.value]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_issuer_host}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

# EKS Pod Identity: the eks-pod-identity-agent assumes the role; which pods get it is decided by
# the aws_eks_pod_identity_association resources below.
data "aws_iam_policy_document" "pod_identity_assume" {
  statement {
    actions = ["sts:AssumeRole", "sts:TagSession"]

    principals {
      type        = "Service"
      identifiers = ["pods.eks.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

locals {
  engine_assume_role_policy           = local.irsa ? data.aws_iam_policy_document.irsa_assume["engine"].json : data.aws_iam_policy_document.pod_identity_assume.json
  external_secrets_assume_role_policy = local.irsa ? data.aws_iam_policy_document.irsa_assume["external_secrets"].json : data.aws_iam_policy_document.pod_identity_assume.json
}

# ---------------------------------------------------------------------------------------------
# Engine role
# ---------------------------------------------------------------------------------------------

data "aws_iam_policy_document" "engine" {
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
    for_each = var.event_bus_arn != "" ? [1] : []

    content {
      sid       = "PublishEvents"
      actions   = ["events:PutEvents"]
      resources = [var.event_bus_arn]
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

  dynamic "statement" {
    for_each = length(var.assumable_role_arns) > 0 ? [1] : []

    content {
      sid       = "CrossAccountRoles"
      actions   = ["sts:AssumeRole"]
      resources = var.assumable_role_arns
    }
  }
}

resource "aws_iam_role" "engine" {
  name               = "${var.name}-engine"
  description        = "Farrier engine (${var.identity}: ${var.namespace}/${var.service_account_name} on ${var.cluster_name})"
  assume_role_policy = local.engine_assume_role_policy
  tags               = local.tags
}

resource "aws_iam_role_policy" "engine" {
  name   = "engine"
  role   = aws_iam_role.engine.id
  policy = data.aws_iam_policy_document.engine.json
}

resource "aws_eks_pod_identity_association" "engine" {
  count = local.irsa ? 0 : 1

  cluster_name    = var.cluster_name
  namespace       = var.namespace
  service_account = var.service_account_name
  role_arn        = aws_iam_role.engine.arn
  tags            = local.tags
}

# ---------------------------------------------------------------------------------------------
# External Secrets role: read the runtime secrets, nothing else
# ---------------------------------------------------------------------------------------------

data "aws_iam_policy_document" "external_secrets" {
  statement {
    sid       = "ReadRuntimeSecrets"
    actions   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
    resources = local.external_secrets_arns
  }

  statement {
    sid       = "DecryptRuntimeSecrets"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.app.arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${local.region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "external_secrets" {
  name               = "${var.name}-external-secrets"
  description        = "External Secrets Operator: read the Farrier runtime secrets (${var.identity})"
  assume_role_policy = local.external_secrets_assume_role_policy
  tags               = local.tags
}

resource "aws_iam_role_policy" "external_secrets" {
  name   = "external-secrets"
  role   = aws_iam_role.external_secrets.id
  policy = data.aws_iam_policy_document.external_secrets.json
}

# A SecretStore's auth.jwt (per-store ServiceAccount) works only with IRSA. With Pod Identity the
# role goes to the ESO controller itself and the SecretStore has no auth block, so every
# SecretStore that controller serves without its own auth can read these secrets too.
resource "aws_eks_pod_identity_association" "external_secrets" {
  count = local.irsa ? 0 : 1

  cluster_name    = var.cluster_name
  namespace       = var.external_secrets_controller_namespace
  service_account = var.external_secrets_controller_service_account
  role_arn        = aws_iam_role.external_secrets.arn
  tags            = local.tags
}
