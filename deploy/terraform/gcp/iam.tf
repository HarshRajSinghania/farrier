# Service accounts with least privilege. Cloud Run uses them as the runtime identity: no keys.

resource "google_service_account" "engine" {
  project      = var.project_id
  account_id   = "${var.name}-engine"
  display_name = "Farrier engine"
}

resource "google_service_account" "web" {
  project      = var.project_id
  account_id   = "${var.name}-web"
  display_name = "Farrier web"
}

# --- Engine -----------------------------------------------------------------------------------

resource "google_secret_manager_secret_iam_member" "engine_runtime" {
  for_each = toset(local.engine_secret_names)

  project   = var.project_id
  secret_id = google_secret_manager_secret.runtime[each.key].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.engine.member
}

locals {
  secret_name_root = "projects/${data.google_project.this.number}/secrets/"
  engine_store_condition = join(" && ", [
    "resource.name.startsWith(\"${local.secret_name_root}${var.secret_store_prefix}\")",
    "!resource.name.startsWith(\"${local.secret_name_root}${local.runtime_prefix}\")",
  ])
}

resource "google_project_iam_member" "engine_store_access" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = google_service_account.engine.member

  condition {
    title       = "farrier-secret-store"
    description = "Secrets under the Farrier store prefix, excluding runtime secrets"
    expression  = local.engine_store_condition
  }
}

resource "google_project_iam_member" "engine_store_add_versions" {
  project = var.project_id
  role    = "roles/secretmanager.secretVersionAdder"
  member  = google_service_account.engine.member

  condition {
    title       = "farrier-secret-store"
    description = "Secrets under the Farrier store prefix, excluding runtime secrets"
    expression  = local.engine_store_condition
  }
}

resource "google_project_iam_custom_role" "secret_store" {
  count = var.engine_can_create_secrets ? 1 : 0

  project     = var.project_id
  role_id     = "${replace(var.name, "-", "_")}_secret_store"
  title       = "Farrier secret store (${var.name})"
  description = "Create, describe and delete secrets; granted only under the store prefix."
  permissions = [
    "secretmanager.secrets.create",
    "secretmanager.secrets.delete",
    "secretmanager.secrets.get",
    "secretmanager.secrets.update",
  ]
}

resource "google_project_iam_member" "engine_store_manage" {
  count = var.engine_can_create_secrets ? 1 : 0

  project = var.project_id
  role    = google_project_iam_custom_role.secret_store[0].name
  member  = google_service_account.engine.member

  condition {
    title       = "farrier-secret-store"
    description = "Secrets under the Farrier store prefix, excluding runtime secrets"
    expression  = local.engine_store_condition
  }
}

# The only grant on the objects bucket (change packs, backups, audit exports): nobody else gets a
# bucket-level write role. Project-level Owner, Editor and Storage Admin still inherit write, so
# keep those to break-glass admins. `farrier restore` trusts a backup's rows; backups are also
# HMAC-signed and unsigned ones need --allow-unsigned.
resource "google_storage_bucket_iam_member" "engine_objects" {
  bucket = google_storage_bucket.objects.name
  role   = "roles/storage.objectAdmin"
  member = google_service_account.engine.member
}

resource "google_kms_crypto_key_iam_member" "engine_master_wrap" {
  crypto_key_id = google_kms_crypto_key.master_wrap.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = google_service_account.engine.member
}

resource "google_dns_managed_zone_iam_member" "engine_dns" {
  for_each = toset(var.dns_managed_zones)

  project      = var.project_id
  managed_zone = each.value
  role         = "roles/dns.admin"
  member       = google_service_account.engine.member
}

# --- Web --------------------------------------------------------------------------------------

resource "google_secret_manager_secret_iam_member" "web_runtime" {
  for_each = toset(local.web_secret_names)

  project   = var.project_id
  secret_id = google_secret_manager_secret.runtime[each.key].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.web.member
}
