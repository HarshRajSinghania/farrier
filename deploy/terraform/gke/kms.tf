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
