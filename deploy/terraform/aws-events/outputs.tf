output "event_bus_name" {
  description = "Set the engine's EventBridge bus to this name."
  value       = aws_cloudwatch_event_bus.this.name
}

output "event_bus_arn" {
  description = "ARN of the Farrier event bus."
  value       = aws_cloudwatch_event_bus.this.arn
}

output "event_source" {
  description = "The EventBridge Source the engine must use."
  value       = local.event_source
}

output "engine_put_events_policy_arn" {
  description = "Managed policy granting events:PutEvents on the bus (source farrier only). Attach to the engine role if attach_engine_policy is false."
  value       = aws_iam_policy.engine_put_events.arn
}

output "engine_put_events_policy_json" {
  description = "The same policy as JSON, for roles managed outside Terraform."
  value       = data.aws_iam_policy_document.put_events.json
}

output "function_arns" {
  description = "Lambda ARNs by function key."
  value       = { for k, f in aws_lambda_function.this : k => f.arn }
}

output "function_role_arns" {
  description = "Execution role ARNs by function key (add them to KMS key policies if your CMK requires it)."
  value       = { for k, r in aws_iam_role.this : k => r.arn }
}

output "dlq_urls" {
  description = "Dead-letter queue URLs by function key."
  value       = { for k, q in aws_sqs_queue.dlq : k => q.url }
}

output "dlq_arns" {
  description = "Dead-letter queue ARNs by function key."
  value       = { for k, q in aws_sqs_queue.dlq : k => q.arn }
}

output "rule_arns" {
  description = "EventBridge rule ARNs by function key."
  value       = { for k, r in aws_cloudwatch_event_rule.this : k => r.arn }
}

output "notify_dedupe_table" {
  description = "DynamoDB table the notify router deduplicates with, if enabled."
  value       = try(aws_dynamodb_table.notify_dedupe[0].name, null)
}
