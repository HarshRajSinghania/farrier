# Cloud Run services. Created once secrets_seeded = true (Cloud Run refuses a revision whose secret
# has no version yet).

locals {
  engine_env = merge({
    FARRIER_DATA               = "/data"
    FARRIER_DATABASE_URL       = local.database_url
    FARRIER_MASTER_KEY_KMS     = "gcp-kms:${google_kms_crypto_key.master_wrap.id}"
    FARRIER_SECRET_BACKEND     = "gcp"
    FARRIER_SECRET_GCP_PROJECT = var.project_id
    FARRIER_STORAGE_URL        = local.storage_url
  }, var.engine_extra_env)

  engine_secret_env = {
    FARRIER_API_TOKEN         = "api-token"
    FARRIER_API_READ_TOKEN    = "api-read-token"
    FARRIER_MASTER_KEY        = "master-key"
    FARRIER_DATABASE_PASSWORD = "db-password"
  }

  web_oidc_env = {
    FARRIER_OIDC_ISSUER                   = var.oidc_issuer
    FARRIER_OIDC_CLIENT_ID                = var.oidc_client_id
    FARRIER_OIDC_SCOPES                   = var.oidc_scopes
    FARRIER_OIDC_REDIRECT_URI             = "${local.site_url}/auth/callback"
    FARRIER_OIDC_POST_LOGOUT_REDIRECT_URI = "${local.site_url}/auth/signin?signed_out=1"
  }

  web_env = merge(
    { NEXT_PUBLIC_SITE_URL = local.site_url },
    local.oidc_enabled ? local.web_oidc_env : {},
    var.web_extra_env,
  )

  web_secret_env = merge(
    {
      FARRIER_API_TOKEN      = "api-token"
      FARRIER_API_READ_TOKEN = "api-read-token"
    },
    local.oidc_enabled ? {
      FARRIER_SESSION_SECRET     = "session-secret"
      FARRIER_OIDC_CLIENT_SECRET = "oidc-client-secret"
    } : {},
    local.oidc_enabled ? {} : {
      FARRIER_DASHBOARD_PASSWORD = "dashboard-password"
    },
  )
}

resource "google_cloud_run_v2_service" "engine" {
  count = var.secrets_seeded ? 1 : 0

  project              = var.project_id
  name                 = "${var.name}-engine"
  location             = var.region
  ingress              = "INGRESS_TRAFFIC_INTERNAL_ONLY"
  invoker_iam_disabled = true
  deletion_protection  = var.deletion_protection
  labels               = local.labels

  template {
    service_account                  = google_service_account.engine.email
    execution_environment            = "EXECUTION_ENVIRONMENT_GEN2"
    max_instance_request_concurrency = 80
    timeout                          = "300s"

    scaling {
      min_instance_count = var.engine_min_instances
      max_instance_count = var.engine_max_instances
    }

    vpc_access {
      egress = var.engine_vpc_egress

      network_interfaces {
        network    = local.network_id
        subnetwork = local.subnetwork_id
      }
    }

    volumes {
      name = "db-ca"

      secret {
        secret       = google_secret_manager_secret.runtime["db-server-ca"].secret_id
        default_mode = 292

        items {
          version = "latest"
          path    = "server-ca.pem"
        }
      }
    }

    containers {
      image   = local.engine_image
      command = ["farrier"]
      args    = ["serve", "--host", "0.0.0.0", "--port", "8740", "--grace", "20"]

      ports {
        container_port = 8740
      }

      resources {
        limits = {
          cpu    = var.engine_cpu
          memory = var.engine_memory
        }
        cpu_idle          = false
        startup_cpu_boost = true
      }

      dynamic "env" {
        for_each = local.engine_env

        content {
          name  = env.key
          value = env.value
        }
      }

      dynamic "env" {
        for_each = local.engine_secret_env

        content {
          name = env.key

          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.runtime[env.value].secret_id
              version = "latest"
            }
          }
        }
      }

      volume_mounts {
        name       = "db-ca"
        mount_path = local.db_ca_dir
      }

      startup_probe {
        period_seconds    = 5
        failure_threshold = 24

        http_get {
          path = "/healthz"
          port = 8740
        }
      }

      liveness_probe {
        period_seconds    = 30
        failure_threshold = 3

        http_get {
          path = "/healthz"
          port = 8740
        }
      }
    }
  }

  depends_on = [
    google_secret_manager_secret_iam_member.engine_runtime,
    google_secret_manager_secret_version.generated,
    google_sql_user.farrier,
  ]
}

resource "google_cloud_run_v2_service" "web" {
  count = var.secrets_seeded ? 1 : 0

  project              = var.project_id
  name                 = "${var.name}-web"
  location             = var.region
  ingress              = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
  invoker_iam_disabled = true
  deletion_protection  = var.deletion_protection
  labels               = local.labels

  template {
    service_account       = google_service_account.web.email
    execution_environment = "EXECUTION_ENVIRONMENT_GEN2"

    scaling {
      min_instance_count = var.web_min_instances
      max_instance_count = var.web_max_instances
    }

    # All egress through the VPC, so calls to the engine's run.app URL count as internal traffic.
    vpc_access {
      egress = "ALL_TRAFFIC"

      network_interfaces {
        network    = local.network_id
        subnetwork = local.subnetwork_id
      }
    }

    containers {
      image = local.web_image

      ports {
        container_port = 3000
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
        startup_cpu_boost = true
      }

      env {
        name  = "FARRIER_API_URL"
        value = google_cloud_run_v2_service.engine[0].uri
      }

      dynamic "env" {
        for_each = local.web_env

        content {
          name  = env.key
          value = env.value
        }
      }

      dynamic "env" {
        for_each = local.web_secret_env

        content {
          name = env.key

          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.runtime[env.value].secret_id
              version = "latest"
            }
          }
        }
      }

      startup_probe {
        period_seconds    = 5
        failure_threshold = 12

        http_get {
          path = "/api/health"
          port = 3000
        }
      }

      liveness_probe {
        period_seconds = 30

        http_get {
          path = "/api/health"
          port = 3000
        }
      }
    }
  }

  depends_on = [google_secret_manager_secret_iam_member.web_runtime]
}
