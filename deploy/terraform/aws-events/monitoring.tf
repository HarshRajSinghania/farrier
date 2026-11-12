locals {
  alarm_actions = var.alarm_topic_arn == null ? [] : [var.alarm_topic_arn]
}

# Anything on a DLQ is an event that needs a human: page on the first one.
resource "aws_cloudwatch_metric_alarm" "dlq_not_empty" {
  for_each = local.functions

  alarm_name          = "${local.function_names[each.key]}-dlq-not-empty"
  alarm_description   = "Farrier events failed permanently for ${local.function_names[each.key]}. Inspect, fix, then redrive the DLQ."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = aws_sqs_queue.dlq[each.key].name }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
  tags                = local.tags
}

resource "aws_cloudwatch_metric_alarm" "function_errors" {
  for_each = local.functions

  alarm_name          = "${local.function_names[each.key]}-errors"
  alarm_description   = "${local.function_names[each.key]} raised errors (retries are in progress; the DLQ alarm fires if they run out)."
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.this[each.key].function_name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 3
  datapoints_to_alarm = 2
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
  tags                = local.tags
}

resource "aws_cloudwatch_metric_alarm" "failed_invocations" {
  for_each = local.functions

  alarm_name          = "${local.function_names[each.key]}-failed-invocations"
  alarm_description   = "EventBridge could not invoke ${local.function_names[each.key]}."
  namespace           = "AWS/Events"
  metric_name         = "FailedInvocations"
  dimensions          = { EventBusName = aws_cloudwatch_event_bus.this.name, RuleName = aws_cloudwatch_event_rule.this[each.key].name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_actions
  tags                = local.tags
}
