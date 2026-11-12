# Farrier on an existing GKE cluster: the Google Cloud side only. The Helm chart
# (deploy/helm/farrier) runs the engine and dashboard; this module creates what they use.
#
#   engine pod (KSA <service_account_name>) ─Workload Identity─> engine GSA
#     └─> Secret Manager (store prefix) · Cloud KMS (unwraps the master key) · GCS bucket
#     └─> Cloud SQL private IP (TLS, verify-ca)
#   External Secrets (KSA <external_secrets_service_account_name>) ─Workload Identity─> ESO GSA
#     └─> Secret Manager <name>-runtime-* (read only) ─> Kubernetes Secrets for the chart
#
# It never creates a cluster, a VPC or a load balancer.

data "google_project" "this" {
  project_id = var.project_id
}

locals {
  labels = merge({ app = "farrier", deployment = var.name }, var.labels)

  cluster_project_id = var.cluster_project_id != "" ? var.cluster_project_id : var.project_id
  workload_pool      = "${local.cluster_project_id}.svc.id.goog"

  runtime_prefix    = "${var.name}-runtime-"
  secret_store_name = "${var.name}-gcp"
  db_ca_secret_name = "farrier-db-ca"

  database_ip  = var.create_database ? google_sql_database_instance.this[0].private_ip_address : null
  database_url = var.create_database ? "postgresql://farrier@${local.database_ip}:5432/farrier?sslmode=verify-ca&sslrootcert=/etc/farrier/db-tls/ca.crt" : null
  storage_url  = "gs://${google_storage_bucket.objects.name}/${trimsuffix(var.storage_prefix, "/")}"

  apis = concat(
    [
      "cloudkms.googleapis.com",
      "iamcredentials.googleapis.com",
      "secretmanager.googleapis.com",
      "storage.googleapis.com",
    ],
    var.create_database ? ["sqladmin.googleapis.com"] : [],
  )
}

resource "google_project_service" "apis" {
  for_each = var.enable_apis ? toset(local.apis) : toset([])

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}
