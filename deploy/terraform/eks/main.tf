# Farrier on an existing EKS cluster: the AWS side only. The Helm chart (deploy/helm/farrier) runs
# the engine and web; this module creates what they use, and the workload identities to use it:
#
#   engine pods (ServiceAccount <service_account_name>) ──IRSA / Pod Identity──> engine role
#       ──> Secrets Manager <secret_store_prefix>*, KMS (unwraps the master key), S3, RDS
#   External Secrets Operator (SecretStore <name>-aws) ──> ESO role ──> <name>-runtime/* secrets
#
# It never creates a cluster, VPC or node group, and no AWS access keys exist anywhere.

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

data "aws_eks_cluster" "this" {
  name = var.cluster_name
}

# IRSA needs the cluster's IAM OIDC provider; it must already exist
# (eksctl utils associate-iam-oidc-provider --cluster <name> --approve).
data "aws_iam_openid_connect_provider" "this" {
  count = local.irsa ? 1 : 0

  url = local.oidc_issuer
}

data "aws_subnet" "database" {
  for_each = var.create_database ? toset(local.database_subnet_ids) : toset([])

  id = each.value
}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.region

  tags = merge({ "app.kubernetes.io/part-of" = "farrier", "farrier:deployment" = var.name }, var.tags)

  irsa             = var.identity == "irsa"
  oidc_issuer      = data.aws_eks_cluster.this.identity[0].oidc[0].issuer
  oidc_issuer_host = trimprefix(local.oidc_issuer, "https://")

  vpc_id                    = var.vpc_id != "" ? var.vpc_id : data.aws_eks_cluster.this.vpc_config[0].vpc_id
  database_subnet_ids       = length(var.database_subnet_ids) > 0 ? var.database_subnet_ids : tolist(data.aws_eks_cluster.this.vpc_config[0].subnet_ids)
  cluster_security_group_id = data.aws_eks_cluster.this.vpc_config[0].cluster_security_group_id

  oidc_enabled = var.oidc_enabled

  # Values for the web app and engine (never device credentials) live under <name>-runtime/,
  # outside the engine's own store prefix, so the engine's IAM grant on its prefix never covers them.
  runtime_prefix = "${var.name}-runtime/"

  secret_store_name = "${var.name}-aws"

  database_url = var.create_database ? format(
    "postgresql://%s@%s:%d/farrier?sslmode=verify-full&sslrootcert=/etc/farrier/db-tls/ca.crt",
    var.db_username, aws_db_instance.this[0].address, aws_db_instance.this[0].port,
  ) : null
  storage_url = "s3://${aws_s3_bucket.objects.bucket}/${trimsuffix(var.storage_prefix, "/")}"
}
