# Cloud KMS. Key rings cannot be deleted: re-creating with the same name after a destroy reuses it.

resource "google_kms_key_ring" "this" {
  project  = var.project_id
  name     = var.name
  location = var.region

  depends_on = [google_project_service.apis]
}

# Wraps the Farrier master key (FARRIER_MASTER_KEY_KMS=gcp-kms:<this key>).
resource "google_kms_crypto_key" "master_wrap" {
  name            = "master-wrap"
  key_ring        = google_kms_key_ring.this.id
  purpose         = "ENCRYPT_DECRYPT"
  rotation_period = var.key_rotation_period
  labels          = local.labels
}

# Default CMEK for the bucket.
resource "google_kms_crypto_key" "storage" {
  name            = "storage"
  key_ring        = google_kms_key_ring.this.id
  purpose         = "ENCRYPT_DECRYPT"
  rotation_period = var.key_rotation_period
  labels          = local.labels
}

# Optional CMEK for Cloud SQL.
resource "google_kms_crypto_key" "sql" {
  count = var.db_cmek ? 1 : 0

  name            = "cloudsql"
  key_ring        = google_kms_key_ring.this.id
  purpose         = "ENCRYPT_DECRYPT"
  rotation_period = var.key_rotation_period
  labels          = local.labels
}

data "google_storage_project_service_account" "gcs" {
  project = var.project_id
}

resource "google_kms_crypto_key_iam_member" "gcs" {
  crypto_key_id = google_kms_crypto_key.storage.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${data.google_storage_project_service_account.gcs.email_address}"
}

resource "google_kms_crypto_key_iam_member" "sql" {
  count = var.db_cmek ? 1 : 0

  crypto_key_id = google_kms_crypto_key.sql[0].id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.this.number}@gcp-sa-cloud-sql.iam.gserviceaccount.com"
}
