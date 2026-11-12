output "dashboard_url" {
  description = "Dashboard URL."
  value       = "${local.site_url}/dashboard"
}

output "lb_ip_address" {
  description = "Load balancer IP. Point the A records of var.domains here; the managed certificate is issued once they resolve."
  value       = google_compute_global_address.web.address
}

output "engine_internal_url" {
  description = "Engine URL (FARRIER_API_URL). Internal ingress only: reachable from the VPC, not the internet."
  value       = var.secrets_seeded ? google_cloud_run_v2_service.engine[0].uri : null
}

output "bucket" {
  description = "GCS bucket for change packs, backups and audit exports."
  value       = google_storage_bucket.objects.name
}

output "storage_url" {
  description = "FARRIER_STORAGE_URL given to the engine."
  value       = local.storage_url
}

output "master_wrap_key_id" {
  description = "Cloud KMS key that wraps the master key."
  value       = google_kms_crypto_key.master_wrap.id
}

output "secret_ids" {
  description = "Secret Manager secret IDs by name (values are not output)."
  value       = { for k, s in google_secret_manager_secret.runtime : k => s.secret_id }
}

output "master_key_secret_id" {
  description = "Add the wrapped master key as a version of this secret before setting secrets_seeded = true."
  value       = google_secret_manager_secret.runtime["master-key"].secret_id
}

output "engine_service_account" {
  description = "Engine runtime identity (grant it access to device networks' firewall rules by service account, if you use them)."
  value       = google_service_account.engine.email
}

output "database_private_ip" {
  description = "Cloud SQL private IP."
  value       = google_sql_database_instance.this.private_ip_address
}

output "dashboard_password" {
  description = "Generated Basic-auth password (only when OIDC is off)."
  value       = local.oidc_enabled ? null : random_password.dashboard_password[0].result
  sensitive   = true
}
