output "dashboard_url" {
  description = "Dashboard URL (through CloudFront)."
  value       = "${local.site_url}/dashboard"
}

output "cloudfront_domain_name" {
  description = "CloudFront hostname. Point your domain_names at it (CNAME or Route 53 alias)."
  value       = aws_cloudfront_distribution.web.domain_name
}

output "engine_internal_url" {
  description = "Private URL of the engine API (FARRIER_API_URL). Reachable only from the web tasks and engine_api_allowed_cidrs."
  value       = local.engine_url
}

output "engine_alb_dns_name" {
  description = "DNS name of the internal engine ALB (alias engine_domain_name to it in a private hosted zone when using HTTPS)."
  value       = aws_lb.engine.dns_name
}

output "bucket" {
  description = "S3 bucket for change packs, backups and audit exports."
  value       = aws_s3_bucket.objects.bucket
}

output "storage_url" {
  description = "FARRIER_STORAGE_URL given to the engine."
  value       = local.storage_url
}

output "kms_key_arn" {
  description = "Customer-managed key: wraps the master key; encrypts S3, Secrets Manager, RDS and logs."
  value       = aws_kms_key.app.arn
}

output "secret_arns" {
  description = "Secrets Manager ARNs by name (values are not output)."
  value       = merge(local.secret_arns, { "database" = local.db_secret_arn })
}

output "master_key_secret_arn" {
  description = "Seed the KMS-wrapped master key here before setting secrets_seeded = true."
  value       = local.secret_arns["master-key"]
}

output "database_endpoint" {
  description = "RDS endpoint (private)."
  value       = aws_db_instance.this.address
}

output "vpc_id" {
  description = "VPC in use."
  value       = local.vpc_id
}

output "dashboard_password" {
  description = "Generated Basic-auth password (only when OIDC is off). Also in Secrets Manager."
  value       = local.oidc_enabled ? null : random_password.dashboard_password[0].result
  sensitive   = true
}
