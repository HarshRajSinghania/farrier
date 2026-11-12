locals {
  # Remote references for the chart's ExternalSecrets. Null entries are dropped below.
  remote_refs = {
    apiToken          = { key = aws_secretsmanager_secret.generated["api-token"].name }
    apiReadToken      = { key = aws_secretsmanager_secret.generated["api-read-token"].name }
    masterKey         = { key = aws_secretsmanager_secret.seeded["master-key"].name }
    databasePassword  = var.create_database ? { key = local.db_secret_arn, property = "password" } : null
    dashboardPassword = local.oidc_enabled ? null : { key = aws_secretsmanager_secret.generated["dashboard-password"].name }
    oidcClientSecret  = local.oidc_enabled ? { key = aws_secretsmanager_secret.seeded["oidc-client-secret"].name } : null
    sessionSecret     = local.oidc_enabled ? { key = aws_secretsmanager_secret.generated["session-secret"].name } : null
  }

  helm_values = {
    cloud = {
      provider = "eks"
      identity = local.irsa ? "irsa" : "pod-identity"
    }
    web = {
      auth = { mode = local.oidc_enabled ? "oidc" : "basic" }
    }
    database = var.create_database ? {
      type = "postgresql"
      url  = local.database_url
      tls  = { existingSecret = "farrier-db-ca" }
    } : null
    secrets = {
      mode = "externalSecrets"
      externalSecrets = {
        secretStoreRef = { name = local.secret_store_name, kind = "SecretStore" }
        remoteRefs     = { for k, v in local.remote_refs : k => v if v != null }
      }
    }
    engine = {
      # The EKS example values set an IRSA role ARN; Pod Identity needs it explicitly empty.
      serviceAccount = {
        name          = var.service_account_name
        cloudIdentity = { awsRoleArn = local.irsa ? aws_iam_role.engine.arn : "" }
      }
      masterKey = { kms = "aws-kms:${aws_kms_key.app.arn}" }
      secretBackend = {
        type = "aws"
        aws  = { region = local.region, prefix = var.secret_store_prefix }
      }
      storage = {
        url    = local.storage_url
        kmsKey = aws_kms_key.app.arn
      }
      config = { AWS_REGION = local.region }
      networkPolicy = var.create_database ? {
        database = { cidrs = [for s in data.aws_subnet.database : s.cidr_block] }
      } : null
    }
  }

  external_secrets_service_account = {
    apiVersion = "v1"
    kind       = "ServiceAccount"
    metadata = {
      name      = var.external_secrets_service_account_name
      namespace = var.namespace
      labels    = { "app.kubernetes.io/part-of" = "farrier" }
      annotations = {
        "eks.amazonaws.com/role-arn" = aws_iam_role.external_secrets.arn
      }
    }
  }

  secret_store_aws = {
    service = "SecretsManager"
    region  = local.region
    auth = local.irsa ? {
      jwt = { serviceAccountRef = { name = var.external_secrets_service_account_name } }
    } : null
  }

  secret_store = {
    apiVersion = "external-secrets.io/v1"
    kind       = "SecretStore"
    metadata = {
      name      = local.secret_store_name
      namespace = var.namespace
      labels    = { "app.kubernetes.io/part-of" = "farrier" }
    }
    spec = {
      provider = {
        aws = { for k, v in local.secret_store_aws : k => v if v != null }
      }
    }
  }

  kubernetes_documents = [
    for d in [local.irsa ? local.external_secrets_service_account : null, local.secret_store] : yamlencode(d) if d != null
  ]
}

output "helm_values" {
  description = "Helm values for the chart, to pass after deploy/helm/farrier/examples/values-eks.yaml: terraform output -raw helm_values > cloud-values.yaml"
  value = yamlencode({
    for k, v in merge(local.helm_values, {
      engine = { for ek, ev in local.helm_values.engine : ek => ev if ev != null }
    }) : k => v if v != null
  })
}

output "kubernetes_manifests" {
  description = "External Secrets ServiceAccount (irsa only) and SecretStore <name>-aws: terraform output -raw kubernetes_manifests | kubectl apply -f -"
  value       = join("---\n", local.kubernetes_documents)
}

output "engine_role_arn" {
  description = "IAM role the engine pods assume (IRSA annotation or Pod Identity association)."
  value       = aws_iam_role.engine.arn
}

output "external_secrets_role_arn" {
  description = "IAM role the External Secrets SecretStore uses to read the runtime secrets."
  value       = aws_iam_role.external_secrets.arn
}

output "kms_key_arn" {
  description = "Customer-managed key: wraps the master key; encrypts S3, Secrets Manager and RDS."
  value       = aws_kms_key.app.arn
}

output "bucket_name" {
  description = "S3 bucket for change packs, backups and audit exports."
  value       = aws_s3_bucket.objects.bucket
}

output "master_key_secret_arn" {
  description = "Seed the KMS-wrapped master key here before installing the chart."
  value       = aws_secretsmanager_secret.seeded["master-key"].arn
}

output "database_endpoint" {
  description = "RDS endpoint (private). Null when create_database = false."
  value       = var.create_database ? aws_db_instance.this[0].address : null
}

output "database_secret_arn" {
  description = "RDS-managed secret holding the master password (JSON property \"password\"). Null when create_database = false."
  value       = local.db_secret_arn
}
