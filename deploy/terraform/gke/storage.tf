# GCS bucket for change packs, backups and audit exports (FARRIER_STORAGE_URL).

resource "google_storage_bucket" "objects" {
  project                     = var.project_id
  name                        = "${var.project_id}-${var.name}-objects"
  location                    = var.region
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = var.force_destroy_bucket
  labels                      = local.labels

  versioning {
    enabled = true
  }

  soft_delete_policy {
    retention_duration_seconds = 604800
  }

  lifecycle_rule {
    condition {
      age            = 30
      matches_prefix = ["${var.storage_prefix}change-packs/"]
    }
    action {
      type = "Delete"
    }
  }

  lifecycle_rule {
    condition {
      days_since_noncurrent_time = 90
    }
    action {
      type = "Delete"
    }
  }

  depends_on = [google_project_service.apis]
}
