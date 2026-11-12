# Farrier event functions

Serverless functions that react to [Farrier renewal events](../events/README.md).

| Function | Cloud | Trigger | Does |
| --- | --- | --- | --- |
| `aws/acm_import` | AWS Lambda | EventBridge, `dev.farrier.renewal.done` | Imports the new certificate into ACM, rotating in place |
| `aws/notify_router` | AWS Lambda | EventBridge, `failed` / `rolled_back` / `awaiting_manual` | Posts to Slack and signed webhooks; pluggable sinks |
| `gcp/cert_manager_import` | Cloud Functions 2nd gen | Pub/Sub | Creates or updates a self-managed Certificate Manager certificate |
| `azure/keyvault_import` | Azure Functions (Python v2) | Event Grid (CloudEvents schema) | Imports a PFX into Key Vault certificates |

Shared code lives in `common/`:

- `farrier_events`: the event model and validator, reference parsing, structured logging
  with redaction, retry with jittered backoff, idempotency helpers, PEM helpers and
  transport unwrapping. Standard library only.
- `farrier_aws`: boto3 error translation and a Secrets Manager reader, for the Lambdas.

## Design

Every function is split the same way:

- `core.py`: pure logic. It parses the event, decides, and calls **ports** (small
  `Protocol`s such as `ChainStore`, `SecretStore`, `CertificateManager`).
- `adapters.py`: thin cloud adapters implementing the ports. Each method is one API call
  plus error translation into `TransientError` (retry) or `PermanentError` (dead-letter).
  SDK retries are switched off; `RetryPolicy` (full-jitter exponential backoff) is the one
  place retries happen.
- `handler.py` / `main.py` / `function_app.py`: the platform entrypoint. It builds the
  adapters once per container and calls `core.handle`.

Rules every function follows:

- **Idempotent.** Delivery is at least once. The import functions compare the target
  certificate's fingerprint with the event's and skip duplicates before touching the key;
  a newer `renewal.id` on the target marks the event stale. The notify router keeps a
  lease-based record per `(event id, sink)` in DynamoDB.
- **Verify before deploying.** The chain's leaf must hash to the event's
  `fingerprint_sha256`; a chain object that contains a private key is refused.
- **No secrets in logs or errors.** Logs are one JSON object per line. Every value passes
  through a redactor that strips PEM blocks, Slack webhook URLs and secret-named fields,
  and SDK error messages (which can echo parameters) are replaced with the operation name
  and error code. Tests assert that no PEM, key or webhook URL reaches captured output.
- **Fail loudly.** Handlers raise. Transient errors are retried in process, then by the
  platform; permanent errors (invalid event, missing reference, wrong cloud, fingerprint
  mismatch, access denied) raise immediately so bounded retries run out and the event lands
  on the dead-letter queue. Log lines carry `dlq_bound: true|false`.

## acm_import (AWS)

Selects endpoints by tag:

- `acm:new`: import as a new certificate the first time, then re-import into the same
  certificate (found by its `farrier:endpoint-id` tag) on every later renewal;
- `acm:<certificate ARN>`: re-import into that ARN, so ALB, NLB, CloudFront and API Gateway
  associations keep working;
- no tag but the endpoint name matches `ACM_NAME_PATTERN` (glob): as `acm:new`.

It reads the chain from S3 (`chain_ref`) and the key from Secrets Manager
(`private_key_ref`), splits leaf and intermediates, and calls `ImportCertificate`. New
imports are tagged in the same call; re-imports are tagged afterwards with
`farrier:managed`, `farrier:endpoint-id`, `farrier:endpoint-name`, `farrier:renewal-id`
and `farrier:fingerprint-sha256`. The fingerprint tag is written last, so a crash between
import and tagging re-imports identical material on retry, which is harmless.

Environment: `ACM_NAME_PATTERN`, `ACM_DISCOVERY` (default `true`), `ALLOWED_REF_PREFIXES`,
`LOG_LEVEL`.

**Dead letters.** EventBridge retries delivery (`retry_policy`), then Lambda retries a
failed invocation twice. After that the event goes to the function's SQS DLQ, which alarms
on the first message. Each DLQ message holds the original event and the error. Fix the
cause, then redrive with `aws sqs start-message-move-task` or replay the event on the bus.

## notify_router (AWS)

Turns `failed`, `rolled_back` and `awaiting_manual` events into messages. Sinks are listed
in `NOTIFY_SINKS`:

- `slack`: Slack incoming webhook. The URL is the credential, so it lives in Secrets
  Manager (`SLACK_WEBHOOK_SECRET_ARN`) and is never logged.
- `webhook`: POSTs the CloudEvent (`Content-Type: application/cloudevents+json`) to
  `WEBHOOK_URL` with:
  - `X-Farrier-Event-Id`: the event id, for receiver-side dedupe;
  - `X-Farrier-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256(key, "<t>." + body)>`, key
    from `WEBHOOK_SECRET_ARN`. Receivers recompute the MAC, compare in constant time and
    reject timestamps older than five minutes (`sinks.verify` is a reference
    implementation).

Each sink is called at most once per event: when one sink fails the event is redelivered
and only the failed sink runs again. Redirects are not followed.

### Adding ServiceNow, Jira or anything else

Write a sink and register a factory. For example, a ServiceNow incident:

```python
# notify_router/sinks.py
class ServiceNowSink:
    name = "servicenow"

    def __init__(self, instance: str, credentials: Callable[[], str], http: HttpPoster) -> None:
        _require_https(instance, "SERVICENOW_INSTANCE")
        self._url = instance.rstrip("/") + "/api/now/table/incident"
        self._credentials, self._http = credentials, http

    def send(self, n: Notification) -> None:
        body = json.dumps(
            {
                "short_description": n.title,
                "description": n.text + "\n" + "\n".join(f"{k}: {v}" for k, v in n.fields),
                "urgency": {"critical": "1", "high": "2", "warning": "3"}[n.severity],
                "correlation_id": n.event_id,  # lets ServiceNow dedupe too
            }
        ).encode()
        token = base64.b64encode(self._credentials().encode()).decode()  # "user:password" secret
        headers = {"Content-Type": "application/json", "Authorization": f"Basic {token}"}
        check_status(self._http.post(self._url, body, headers), self.name)


SINK_FACTORIES["servicenow"] = lambda env, rt: ServiceNowSink(
    _require(env, "SERVICENOW_INSTANCE", "servicenow"),
    rt.secret(_require(env, "SERVICENOW_SECRET_ARN", "servicenow")),
    rt.http,
)
```

Jira is the same shape (`POST /rest/api/3/issue` with an API token). Then add the secret ARN
to the function's IAM policy, set `NOTIFY_SINKS=slack,servicenow`, and add a test with a
fake `HttpPoster` like the ones in `aws/notify_router/tests`.

## cert_manager_import (Google Cloud)

Selects endpoints by `gcp-cm:<certificate-id>` (in `GCP_CM_PROJECT` / `GCP_CM_LOCATION`,
default `global`), `gcp-cm:projects/<p>/locations/<l>/certificates/<id>`, or
`GCP_CM_NAME_PATTERN` (certificate id `farrier-<endpoint name>`). It reads the chain from
GCS and the key from Secret Manager, then creates the certificate (`POST
…/certificates?certificateId=`) or updates it in place (`PATCH …?updateMask=selfManaged,labels`)
and waits for the long-running operation. Labels `farrier-fp-a` and `farrier-fp-b` hold
the two halves of the fingerprint (label values are capped at 63 characters). Existing
labels are preserved; Google-managed certificates are refused.

All Google APIs are called over REST through one `HttpClient` port backed by
`google.auth.transport.requests.AuthorizedSession`.

The service account needs `roles/certificatemanager.editor` (or a custom role with
`certificatemanager.certs.get/create/update` and `certificatemanager.operations.get`),
`roles/secretmanager.secretAccessor` on the key secrets only (use an IAM condition on the
secret name prefix), and `roles/storage.objectViewer` on the chain bucket.

## keyvault_import (Azure)

Selects endpoints by `akv:<certificate-name>` (in `KEYVAULT_URL`),
`akv:<vault-name>/<certificate-name>`, or `AKV_NAME_PATTERN` (name `farrier-<endpoint name>`).
It reads the chain from Blob Storage and the key from a Key Vault secret, checks that the key
matches the leaf, builds an unencrypted PFX and imports it as a new version of the Key Vault
certificate. App Gateway, Front Door and App Service pick up the new version when they
reference the certificate by its versionless id. Duplicate detection hashes the current
version's DER (`cer`), so it does not depend on tags.

The function's managed identity needs **Key Vault Certificates Officer** on the target vault,
**Key Vault Secrets User** on the key secrets (scope the role assignment to the secret, or
use a dedicated vault for exported keys), and **Storage Blob Data Reader** on the chain
container.

## Building

```bash
./aws/acm_import/build.sh             # -> functions/dist/acm_import.zip
./aws/notify_router/build.sh          # -> functions/dist/notify_router.zip
./gcp/cert_manager_import/build.sh    # -> functions/dist/cert_manager_import.zip
./azure/keyvault_import/build.sh      # -> functions/dist/keyvault_import.zip
make build                            # all four
```

Each script runs `tools/package.py`, which copies the function and the shared packages into
a reproducible zip (sorted entries, fixed timestamps), with no network access. Third-party
packages are not bundled: boto3 ships with the Lambda runtime, and Cloud Functions and Azure
Functions install `requirements.txt` during their remote build.

| Artifact | Layout | Entrypoint |
| --- | --- | --- |
| `acm_import.zip` | `acm_import/`, `farrier_events/`, `farrier_aws/` | `acm_import.handler.handler` |
| `notify_router.zip` | `notify_router/`, `farrier_events/`, `farrier_aws/` | `notify_router.handler.handler` |
| `cert_manager_import.zip` | `main.py`, `requirements.txt`, `cert_manager_import/`, `farrier_events/` | `on_renewal_event` |
| `keyvault_import.zip` | `function_app.py`, `host.json`, `requirements.txt`, `keyvault_import/`, `farrier_events/` | `farrier_keyvault_import` |

Deploy the Lambdas with `deploy/terraform/aws-events`. For Google Cloud:

```bash
unzip -d build/cmi dist/cert_manager_import.zip
gcloud functions deploy farrier-cert-manager-import --gen2 --runtime=python312 \
  --region=europe-west1 --source=build/cmi --entry-point=on_renewal_event \
  --trigger-topic=farrier-renewals --retry \
  --service-account=farrier-cmi@PROJECT.iam.gserviceaccount.com \
  --set-env-vars='^;^GCP_CM_PROJECT=PROJECT;ALLOWED_REF_PREFIXES=gs://acme-certs/farrier/,gcp-sm:projects/PROJECT/secrets/farrier-key-'
```

For Azure, publish `dist/keyvault_import.zip` with
`az functionapp deployment source config-zip --build-remote true`, then subscribe the
function to the topic (see `deploy/terraform/aws-events/README.md` for both clouds).

## Testing

```bash
python -m pytest -q functions     # from the repository root
```

`functions/pytest.ini` puts `common`, `aws`, `gcp`, `azure` and `testkit` on the path and
uses importlib mode, so these tests do not interfere with the engine's `tests/` suite. They
use fakes for every cloud call and need no network, credentials or cloud SDKs. The
`cryptography` package (an engine dependency) generates real test certificates.
`ruff.toml` holds the lint settings for this tree.
