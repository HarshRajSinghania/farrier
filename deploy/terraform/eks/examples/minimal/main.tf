# Minimal Farrier on an existing EKS cluster (IRSA, Basic-auth dashboard, RDS PostgreSQL).
#
#   terraform init && terraform apply
#   (seed the wrapped master key, apply kubernetes_manifests, create farrier-db-ca; see ../../README.md)
#   terraform output -raw helm_values > cloud-values.yaml
#   helm install farrier deploy/helm/farrier -n farrier \
#     -f deploy/helm/farrier/examples/values-eks.yaml -f cloud-values.yaml

terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # Keep state encrypted and access-controlled: it holds the generated API tokens.
  # backend "s3" {
  #   bucket       = "my-terraform-state"
  #   key          = "farrier-eks/terraform.tfstate"
  #   region       = "eu-west-1"
  #   encrypt      = true
  #   use_lockfile = true
  # }
}

provider "aws" {
  region = "eu-west-1"
}

module "farrier" {
  source = "../.."

  name         = "farrier"
  cluster_name = "my-cluster"

  # Private subnets for RDS (default: the cluster's subnets).
  database_subnet_ids = ["subnet-0aaaaaaaaaaaaaaaa", "subnet-0bbbbbbbbbbbbbbbb"]

  route53_zone_ids = ["Z0123456789ABCDEFGHIJ"]

  tags = {
    owner = "platform-team"
  }
}

output "helm_values" {
  value = module.farrier.helm_values
}

output "kubernetes_manifests" {
  value = module.farrier.kubernetes_manifests
}

output "master_key_secret_arn" {
  value = module.farrier.master_key_secret_arn
}

output "kms_key_arn" {
  value = module.farrier.kms_key_arn
}
