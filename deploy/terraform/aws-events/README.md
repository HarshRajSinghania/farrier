# Farrier events on AWS (`aws-events`)

Creates the EventBridge side of [Farrier renewal events](../../../events/README.md) and the
two shipped Lambdas from [`functions/aws`](../../../functions/README.md). It is independent
of `deploy/terraform/aws` (the engine itself): you only pass the engine's IAM role ARN.

```
Farrier engine ──PutEvents (source=farrier)──▶ bus "farrier"
                                                 ├─ rule: detail-type dev.farrier.renewal.done
                                                 │     └▶ Lambda acm_import ──▶ ACM
                                                 └─ rule: failed | rolled_back | awaiting_manual
                                                       └▶ Lambda notify_router ──▶ Slack / webhook
     each target: EventBridge retries + DLQ, Lambda async retries (2) + on-failure DLQ
```

## What it creates

| Resource | Notes |
| --- | --- |
| EventBridge bus `<prefix>` | Resource policy: only `engine_role_arn` may `PutEvents`, and only with `Source = "farrier"` |
| IAM policy `<prefix>-engine-put-events` | Identity policy for the engine role (attached when `attach_engine_policy = true`) |
| Rule + target per function | Retry policy (`event_max_age_seconds`, `event_retry_attempts`) and a DLQ |
| Lambda per function | Python 3.12, arm64, reserved concurrency 5, env from variables |
| `aws_lambda_function_event_invoke_config` | `lambda_retry_attempts` (2), then on-failure destination = DLQ |
| SQS DLQ per function | SSE-SQS, 14-day retention, TLS-only, only its rule may send |
| CloudWatch log group per function | `log_retention_days`, optional KMS |
| DynamoDB table `<prefix>-notify-dedupe` | Per-(event, sink) dedupe for notify_router, TTL `expires_at` |
| Alarms | DLQ not empty, function errors, EventBridge failed invocations, to `alarm_topic_arn` |

A function is created only when its zip is set (`acm_import_zip`, `notify_router_zip`).

## Least privilege

| Role | Allowed |
| --- | --- |
| Engine | `events:PutEvents` on this bus, condition `events:source = farrier` |
| acm_import | `acm:ImportCertificate`, `AddTagsToCertificate`, `DescribeCertificate`, `ListTagsForCertificate` on `acm_certificate_arns` (default: certificates in this account and region); `acm:ListCertificates` on `*` only if `acm_discovery` (the action has no resource-level permissions); `s3:GetObject` on `<chain_bucket_name>/<chain_key_prefix>*`; `secretsmanager:GetSecretValue` on `secret:<key_secret_prefix>*`; `kms:Decrypt` on `kms_key_arns` via Secrets Manager and S3 only; `sqs:SendMessage` to its DLQ; its own log group |
| notify_router | `secretsmanager:GetSecretValue` on the Slack and webhook secrets only; `kms:Decrypt` via Secrets Manager; `dynamodb:PutItem/UpdateItem/DeleteItem` on the dedupe table; `sqs:SendMessage` to its DLQ; its own log group |

The ACM function also refuses references outside the configured bucket prefix and secret
prefix (`ALLOWED_REF_PREFIXES`), so a forged event cannot steer it elsewhere even if IAM is
loosened. To pin it to specific certificates, list them in `acm_certificate_arns` and tag
the endpoints `acm:<arn>` (set `acm_discovery = false` to drop `ListCertificates`).

If your CMK key policy does not delegate to IAM, add the roles in output
`function_role_arns` to it.

## Usage

```hcl
module "farrier_events" {
  source = "./deploy/terraform/aws-events"

  engine_role_arn      = "arn:aws:iam::123456789012:role/farrier-engine"
  attach_engine_policy = true

  acm_import_zip    = "functions/dist/acm_import.zip"
  notify_router_zip = "functions/dist/notify_router.zip"

  chain_bucket_name = "acme-farrier-certs"
  chain_key_prefix  = "prod/"
  kms_key_arns      = ["arn:aws:kms:eu-west-1:123456789012:key/…"]

  slack_webhook_secret_arn = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:farrier/slack-webhook-AbCdEf"
  alarm_topic_arn          = "arn:aws:sns:eu-west-1:123456789012:ops-alerts"
}
```

Build the zips first (`functions/aws/*/build.sh`, offline). A complete example is in
`examples/minimal`.

### Inputs

| Name | Default | Description |
| --- | --- | --- |
| `engine_role_arn` | required | Role the engine runs as |
| `name_prefix` | `farrier` | Prefix for every name; also the bus name |
| `attach_engine_policy` | `false` | Attach the PutEvents policy to the engine role |
| `acm_import_zip`, `notify_router_zip` | `null` | Artifacts; `null` disables that function |
| `chain_bucket_name`, `chain_key_prefix` | `null`, `""` | Where Farrier writes chains (required for acm_import) |
| `key_secret_prefix` | `farrier/keys/` | Secret name prefix of exported keys |
| `kms_key_arns` | `[]` | CMKs protecting keys, chains and sink secrets |
| `acm_certificate_arns` | `[]` | Certificates acm_import may modify; empty = account and region |
| `acm_name_pattern` | `null` | Glob on endpoint names to import without a tag |
| `acm_discovery` | `true` | Allow `acm:new` to find earlier imports |
| `notify_sinks` | `["slack"]` | `slack`, `webhook` |
| `slack_webhook_secret_arn` | `null` | Secret whose value is the Slack webhook URL |
| `webhook_url`, `webhook_secret_arn` | `null` | Generic webhook and its HMAC key secret |
| `dashboard_url` | `null` | Link in notifications |
| `event_max_age_seconds` | `3600` | Retry window before dead-lettering |
| `event_retry_attempts` | `8` | EventBridge delivery retries |
| `lambda_retry_attempts` | `2` | Lambda async retries after the function raises |
| `lambda_runtime`, `lambda_architecture` | `python3.12`, `arm64` | |
| `lambda_timeout_seconds`, `lambda_memory_mb` | `60`, `256` | |
| `lambda_reserved_concurrency` | `5` | `-1` for unreserved |
| `log_level`, `log_retention_days`, `log_kms_key_arn` | `INFO`, `90`, `null` | |
| `dlq_retention_seconds` | `1209600` | 14 days |
| `alarm_topic_arn` | `null` | SNS topic for alarms |
| `tags` | `{}` | Added to every resource |

All inputs are validated; cross-input requirements (a chain bucket for acm_import, a secret
for each sink) are checked as preconditions at plan time.

### Outputs

`event_bus_name`, `event_bus_arn`, `event_source`, `engine_put_events_policy_arn`,
`engine_put_events_policy_json`, `function_arns`, `function_role_arns`, `dlq_urls`,
`dlq_arns`, `rule_arns`, `notify_dedupe_table`.

## Operating the DLQs

A message on a DLQ is an event that failed every retry: a permanent error (invalid event,
missing `private_key_ref`, fingerprint mismatch, access denied) or a transient one that
outlasted `event_max_age_seconds`. The function's log line for it has `"dlq_bound": true`
and the event id. Fix the cause, then redrive:

```bash
aws sqs start-message-move-task --source-arn "$(terraform output -json dlq_arns | jq -r .acm_import)"
```

Lambda on-failure messages wrap the original EventBridge event in `requestPayload`; replaying
it with `aws events put-events` (Source `farrier`, the same DetailType and Detail) is
equivalent. Replays are safe because the functions are idempotent.

## Google Cloud equivalent

Not a module; the shape to build with your own Terraform or `gcloud`:

1. **Topic.** `google_pubsub_topic.farrier_renewals`, with a CMEK if you require one. Grant
   the engine's service account `roles/pubsub.publisher` on this topic only.
2. **Dead letters.** A second topic `farrier-renewals-dlq` plus a subscription on it to
   inspect and replay.
3. **Function.** Deploy `cert_manager_import.zip` as a 2nd gen function (`python312`, entry
   point `on_renewal_event`) with an Eventarc Pub/Sub trigger on the topic and
   `retry_policy = "RETRY_POLICY_RETRY"`. On the subscription Eventarc creates, set a
   `dead_letter_policy` (`max_delivery_attempts = 5`) to the DLQ topic and grant the
   Pub/Sub service agent publisher on the DLQ and subscriber on the subscription.
4. **Identity.** A dedicated service account with `roles/certificatemanager.editor`,
   `roles/secretmanager.secretAccessor` on the key secrets only (IAM condition
   `resource.name.startsWith("projects/P/secrets/farrier-key-")`),
   `roles/storage.objectViewer` on the chain bucket, and `roles/eventarc.eventReceiver` +
   `roles/run.invoker` for the trigger.
5. **Alerting.** A Cloud Monitoring alert on
   `pubsub.googleapis.com/subscription/num_undelivered_messages > 0` for the DLQ
   subscription, and on function error logs with `jsonPayload.dlq_bound = true`.

## Azure equivalent

1. **Topic.** An Event Grid custom topic with `input_schema = "CloudEventSchemaV1_0"`. Grant
   the engine's managed identity **EventGrid Data Sender** on the topic and disable local
   (key) auth.
2. **Function.** A Linux Python 3.12 Function App (Flex Consumption or Premium) with a
   system-assigned identity; publish `keyvault_import.zip` with remote build.
3. **Subscription.** An Event Grid event subscription from the topic to the function
   (`azure_function_endpoint`), `event_delivery_schema = "CloudEventSchemaV1_0"`, an
   advanced filter `type` in `dev.farrier.renewal.done`, `retry_policy { max_delivery_attempts = 10, event_time_to_live = 1440 }`
   and a `storage_blob_dead_letter_destination` container.
4. **Identity.** The function's identity gets **Key Vault Certificates Officer** on the
   target vault, **Key Vault Secrets User** scoped to the exported key secrets, and
   **Storage Blob Data Reader** on the chain container. Use RBAC-mode vaults.
5. **Alerting.** Azure Monitor alerts on the topic's `DeadLetteredCount` and
   `DeliveryAttemptFailCount`, and on function failures.

