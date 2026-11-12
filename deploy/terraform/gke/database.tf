# Optional Cloud SQL for PostgreSQL (create_database): private IP only, TLS required, backups with
# point-in-time recovery. The VPC's private services access must already exist.

resource "random_id" "sql" {
  count = var.create_database ? 1 : 0

  byte_length = 3
}

resource "google_sql_database_instance" "this" {
  count = var.create_database ? 1 : 0

  project             = var.project_id
  name                = "${var.name}-${random_id.sql[0].hex}"
  region              = var.region
  database_version    = "POSTGRES_16"
  deletion_protection = var.deletion_protection

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
      private_network = var.network
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

  lifecycle {
    precondition {
      condition     = var.network != ""
      error_message = "Set network (the cluster's VPC, with private services access) when create_database = true."
    }
  }

  depends_on = [google_project_service.apis]
}

resource "google_sql_database" "farrier" {
  count = var.create_database ? 1 : 0

  project  = var.project_id
  name     = "farrier"
  instance = google_sql_database_instance.this[0].name
}

# The password is generated here (so it is in Terraform state: use an encrypted backend) and handed
# to the engine through Secret Manager and External Secrets.
resource "random_password" "db" {
  count = var.create_database ? 1 : 0

  length  = 40
  special = false
}

resource "google_sql_user" "farrier" {
  count = var.create_database ? 1 : 0

  project  = var.project_id
  name     = "farrier"
  instance = google_sql_database_instance.this[0].name
  password = random_password.db[0].result
}
