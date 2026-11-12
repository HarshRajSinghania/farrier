# Runtime secrets in Secret Manager, named <name>-runtime-*. External Secrets syncs them into
# the Kubernetes Secrets the chart reads.
#
# * Generated here: API tokens, session secret or dashboard password, database password. These
#   are in Terraform state: use an encrypted backend.
# * Seeded by you: the KMS-wrapped master key and the OIDC client secret. Never in state.

resource "random_password" "api_token" {
  length  = 48
  special = false
}

resource "random_password" "api_read_token" {
  length  = 48
  special = false
}

resource "random_password" "session_secret" {
  count = var.oidc_enabled ? 1 : 0

  length  = 64
  special = false
}

resource "random_password" "dashboard_password" {
  count = var.oidc_enabled ? 0 : 1

  length  = 32
  special = false
}

locals {
  generated_secret_names = concat(
    ["api-token", "api-read-token"],
    var.oidc_enabled ? ["session-secret"] : ["dashboard-password"],
    var.create_database ? ["db-password"] : [],
  )
  generated_secret_values = {
    "api-token"          = random_password.api_token.result
    "api-read-token"     = random_password.api_read_token.result
    "db-password"        = var.create_database ? random_password.db[0].result : ""
    "session-secret"     = var.oidc_enabled ? random_password.session_secret[0].result : ""
    "dashboard-password" = var.oidc_enabled ? "" : random_password.dashboard_password[0].result
  }

  seeded_secret_names = concat(["master-key"], var.oidc_enabled ? ["oidc-client-secret"] : [])
  all_secret_names    = concat(local.generated_secret_names, local.seeded_secret_names)
}

resource "google_secret_manager_secret" "runtime" {
  for_each = toset(local.all_secret_names)

  project   = var.project_id
  secret_id = "${local.runtime_prefix}${each.key}"
  labels    = local.labels

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "generated" {
  for_each = toset(local.generated_secret_names)

  secret      = google_secret_manager_secret.runtime[each.key].id
  secret_data = local.generated_secret_values[each.key]
}
