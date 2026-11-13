# Minimal Farrier on AWS in an existing VPC, with SSO.
#
#   terraform init && terraform apply                       # 1. infrastructure, empty secrets
#   (seed the wrapped master key and OIDC client secret; see ../../README.md)
#   terraform apply -var secrets_seeded=true                # 2. start the services

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
  #   key          = "farrier/terraform.tfstate"
  #   region       = "eu-west-1"
  #   encrypt      = true
  #   use_lockfile = true
  # }
}

provider "aws" {
  region = "eu-west-1"
}

variable "secrets_seeded" {
  type    = bool
  default = false
}

module "farrier" {
  source = "../.."

  name            = "farrier"
  farrier_version = "0.2.0"

  vpc_id             = "vpc-0123456789abcdef0"
  private_subnet_ids = ["subnet-0aaaaaaaaaaaaaaaa", "subnet-0bbbbbbbbbbbbbbbb"]

  oidc_issuer    = "https://login.example.com/realms/corp"
  oidc_client_id = "farrier"
  web_extra_env = {
    FARRIER_OIDC_ADMIN_GROUPS = "pki-admins"
  }

  route53_zone_ids = ["Z0123456789ABCDEFGHIJ"]
  secrets_seeded   = var.secrets_seeded

  tags = {
    owner = "platform-team"
  }
}

output "dashboard_url" {
  value = module.farrier.dashboard_url
}

output "master_key_secret_arn" {
  value = module.farrier.master_key_secret_arn
}

output "kms_key_arn" {
  value = module.farrier.kms_key_arn
}
