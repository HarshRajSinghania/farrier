# Minimal Farrier on an existing GKE cluster, with Cloud SQL and Basic-auth sign-in.
#
#   terraform init && terraform apply
#   (seed the wrapped master key; see ../../README.md)
#   terraform output -raw kubernetes_manifests | kubectl apply -f -
#   terraform output -raw helm_values > cloud-values.yaml
#   helm install farrier deploy/helm/farrier -n farrier \
#     -f deploy/helm/farrier/examples/values-gke.yaml -f cloud-values.yaml

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
  #   prefix = "farrier-gke"
  # }
}

provider "google" {
  project = "my-project"
  region  = "europe-west1"
}

module "farrier" {
  source = "../.."

  project_id = "my-project"
  region     = "europe-west1"

  cluster_name     = "my-cluster"
  cluster_location = "europe-west1"
  network          = "projects/my-project/global/networks/my-vpc"
}

output "helm_values" {
  value = module.farrier.helm_values
}

output "kubernetes_manifests" {
  value     = module.farrier.kubernetes_manifests
  sensitive = true
}

output "kms_key_id" {
  value = module.farrier.kms_key_id
}

output "master_key_secret_id" {
  value = module.farrier.master_key_secret_id
}
