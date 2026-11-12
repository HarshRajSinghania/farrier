# Farrier on Google Cloud: Cloud Run (engine + web), Cloud SQL PostgreSQL, GCS, Secret Manager,
# Cloud KMS, external HTTPS load balancer with Cloud CDN (static paths only) and Cloud Armor.
#
#   Internet ─HTTPS─> global external ALB (+ Cloud Armor) ─> Cloud Run web (ingress: LB only)
#                       └─ /_next/static/*, /assets/* ─> CDN-enabled backend (same service)
#   Cloud Run web ─(Direct VPC egress)─> Cloud Run engine (ingress: internal only, min 1, CPU always on)
#   engine ─(Direct VPC egress)─> Cloud SQL private IP, devices, Cloud NAT ─> ACME CAs
#
# The engine has no external ingress at all.

data "google_project" "this" {
  project_id = var.project_id
}

locals {
  labels = merge({ app = "farrier", deployment = var.name }, var.labels)

  ar_host      = "${var.region}-docker.pkg.dev"
  ghcr_mirror  = "${local.ar_host}/${var.project_id}/${google_artifact_registry_repository.ghcr.repository_id}"
  engine_image = var.engine_image != "" ? var.engine_image : "${local.ghcr_mirror}/gagankarthik/farrier:${var.farrier_version}"
  web_image    = var.web_image != "" ? var.web_image : "${local.ghcr_mirror}/gagankarthik/farrier-web:${var.farrier_version}"

  network_id    = var.create_network ? google_compute_network.this[0].id : var.network_id
  subnetwork_id = var.create_network ? google_compute_subnetwork.this[0].id : var.subnetwork_id

  oidc_enabled   = var.oidc_issuer != ""
  runtime_prefix = "${var.name}-runtime-"
  site_url       = "https://${var.domains[0]}"

  db_ca_dir    = "/etc/farrier/db"
  database_url = "postgresql://farrier@${google_sql_database_instance.this.private_ip_address}:5432/farrier?sslmode=verify-ca&sslrootcert=${local.db_ca_dir}/server-ca.pem"
  storage_url  = "gs://${google_storage_bucket.objects.name}/${trimsuffix(var.storage_prefix, "/")}"

  apis = [
    "artifactregistry.googleapis.com",
    "cloudkms.googleapis.com",
    "compute.googleapis.com",
    "run.googleapis.com",
    "secretmanager.googleapis.com",
    "servicenetworking.googleapis.com",
    "sqladmin.googleapis.com",
  ]
}

resource "google_project_service" "apis" {
  for_each = var.enable_apis ? toset(local.apis) : toset([])

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

# Cloud Run cannot pull from ghcr.io directly: a remote repository proxies and caches it.
resource "google_artifact_registry_repository" "ghcr" {
  project       = var.project_id
  location      = var.region
  repository_id = "${var.name}-ghcr"
  description   = "Pull-through cache of ghcr.io for Farrier images"
  format        = "DOCKER"
  mode          = "REMOTE_REPOSITORY"
  labels        = local.labels

  remote_repository_config {
    description = "ghcr.io"

    docker_repository {
      custom_repository {
        uri = "https://ghcr.io"
      }
    }
  }

  depends_on = [google_project_service.apis]
}

# ---------------------------------------------------------------------------------------------
# Optional network (create_network = true)
# ---------------------------------------------------------------------------------------------

resource "google_compute_network" "this" {
  count = var.create_network ? 1 : 0

  project                 = var.project_id
  name                    = var.name
  auto_create_subnetworks = false

  depends_on = [google_project_service.apis]
}

resource "google_compute_subnetwork" "this" {
  count = var.create_network ? 1 : 0

  project                  = var.project_id
  name                     = "${var.name}-${var.region}"
  region                   = var.region
  network                  = google_compute_network.this[0].id
  ip_cidr_range            = var.subnet_cidr
  private_ip_google_access = true

  log_config {
    aggregation_interval = "INTERVAL_5_MIN"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_router" "this" {
  count = var.create_network ? 1 : 0

  project = var.project_id
  name    = var.name
  region  = var.region
  network = google_compute_network.this[0].id
}

resource "google_compute_router_nat" "this" {
  count = var.create_network ? 1 : 0

  project                            = var.project_id
  name                               = var.name
  router                             = google_compute_router.this[0].name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# Private services access, for Cloud SQL's private IP.
resource "google_compute_global_address" "psa" {
  count = var.create_private_service_access ? 1 : 0

  project       = var.project_id
  name          = "${var.name}-psa"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 20
  network       = local.network_id
}

resource "google_service_networking_connection" "psa" {
  count = var.create_private_service_access ? 1 : 0

  network                 = local.network_id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.psa[0].name]

  depends_on = [google_project_service.apis]
}
