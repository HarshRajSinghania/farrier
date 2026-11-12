# Cloud SQL for PostgreSQL: private IP only, TLS required, backups with point-in-time recovery.

resource "random_id" "sql" {
  byte_length = 3
}

resource "google_sql_database_instance" "this" {
  project             = var.project_id
  name                = "${var.name}-${random_id.sql.hex}"
  region              = var.region
  database_version    = "POSTGRES_16"
  deletion_protection = var.deletion_protection
  encryption_key_name = var.db_cmek ? google_kms_crypto_key.sql[0].id : null

  settings {
    tier                        = var.db_tier
    edition                     = "ENTERPRISE"
    availability_type           = var.db_high_availability ? "REGIONAL" : "ZONAL"
    disk_type                   = "PD_SSD"
    disk_size                   = var.db_disk_size_gb
    disk_autoresize             = true
    deletion_protection_enabled = var.deletion_protection
    user_labels                 = local.labels

    ip_configuration {
      ipv4_enabled    = false
      private_network = local.network_id
      ssl_mode        = "ENCRYPTED_ONLY"
    }

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      start_time                     = "03:00"
      transaction_log_retention_days = 7

      backup_retention_settings {
        retained_backups = var.db_backup_count
      }
    }

    maintenance_window {
      day  = 7
      hour = 4
    }

    insights_config {
      query_insights_enabled = true
    }

    database_flags {
      name  = "log_connections"
      value = "on"
    }
  }

  depends_on = [
    google_service_networking_connection.psa,
    google_kms_crypto_key_iam_member.sql,
  ]
}

resource "google_sql_database" "farrier" {
  project  = var.project_id
  name     = "farrier"
  instance = google_sql_database_instance.this.name
}

# The password is generated here (so it is in Terraform state: use an encrypted backend) and handed
# to the engine through Secret Manager.
resource "random_password" "db" {
  length  = 40
  special = false
}

resource "google_sql_user" "farrier" {
  project  = var.project_id
  name     = "farrier"
  instance = google_sql_database_instance.this.name
  password = random_password.db.result
}
