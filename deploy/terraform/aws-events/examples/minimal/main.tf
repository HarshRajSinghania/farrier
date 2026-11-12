# Minimal use: both functions, Slack notifications, alarms to an existing SNS topic.
#
#   ./functions/aws/acm_import/build.sh && ./functions/aws/notify_router/build.sh
#   cd deploy/terraform/aws-events/examples/minimal && terraform init && terraform apply

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40, < 7.0"
    }
  }
}

provider "aws" {
  region = "eu-west-1"
}

module "farrier_events" {
  source = "../.."

  engine_role_arn      = "arn:aws:iam::123456789012:role/farrier-engine"
  attach_engine_policy = true

  acm_import_zip    = "${path.module}/../../../../../functions/dist/acm_import.zip"
  notify_router_zip = "${path.module}/../../../../../functions/dist/notify_router.zip"

  chain_bucket_name = "acme-farrier-certs"
  chain_key_prefix  = "prod/"
  key_secret_prefix = "farrier/keys/"
  kms_key_arns      = ["arn:aws:kms:eu-west-1:123456789012:key/11111111-2222-3333-4444-555555555555"]

  notify_sinks             = ["slack"]
  slack_webhook_secret_arn = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:farrier/slack-webhook-AbCdEf"
  dashboard_url            = "https://farrier.example.com"

  alarm_topic_arn = "arn:aws:sns:eu-west-1:123456789012:ops-alerts"

  tags = { environment = "prod" }
}

output "event_bus_name" {
  value = module.farrier_events.event_bus_name
}

output "dlq_urls" {
  value = module.farrier_events.dlq_urls
}
