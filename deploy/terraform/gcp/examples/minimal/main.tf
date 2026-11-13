# Minimal Farrier on Google Cloud, with a new VPC and Google sign-in.
#
#   terraform init && terraform apply                       # 1. infrastructure, empty secrets
#   (seed the wrapped master key and OIDC client secret; see ../../README.md)
#   terraform apply -var secrets_seeded=true                # 2. start the services

terraform {
  required_version = ">= 1.6"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 8.0"
    }
  }

  # State holds the generated tokens and database password: keep it in an encrypted bucket.
  # backend "gcs" {
  #   bucket = "my-terraform-state"
  #   prefix = "farrier"
  # }
}

provider "google" {
  project = "my-project"
  region  = "europe-west1"
}

variable "secrets_seeded" {
  type    = bool
  default = false
}

module "farrier" {
  source = "../.."

  project_id      = "my-project"
  region          = "europe-west1"
  farrier_version = "0.2.0"

  create_network = true
  domains        = ["farrier.example.com"]

  oidc_issuer    = "https://accounts.google.com"
  oidc_client_id = "1234567890-abc.apps.googleusercontent.com"
  oidc_scopes    = "openid profile email"

  secrets_seeded = var.secrets_seeded
}

output "dashboard_url" {
  value = module.farrier.dashboard_url
}

output "lb_ip_address" {
  value = module.farrier.lb_ip_address
}

output "master_wrap_key_id" {
  value = module.farrier.master_wrap_key_id
}
