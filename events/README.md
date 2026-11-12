# Farrier renewal events

Farrier publishes an event every time a renewal changes state. This directory is the
source of truth for that contract:

| File | What it is |
| --- | --- |
| `schema/renewal-event.schema.json` | JSON Schema (draft 2020-12) for the event |
| `examples/renewal-done.json` | A `done` event with chain and key references |
| `examples/renewal-failed.json` | A `failed` event before any certificate was issued |

The consumers in `functions/` validate against the same rules with
`functions/common/farrier_events` (a dependency-free validator kept in step with the schema
by its tests).

## The envelope

Events are [CloudEvents 1.0](https://github.com/cloudevents/spec/blob/v1.0.2/cloudevents/spec.md)
in JSON structured mode.

| Attribute | Value |
| --- | --- |
| `specversion` | `"1.0"` |
| `id` | A UUID, unique per event. Redeliveries keep the same `id`. |
| `source` | `farrier://<instance-id>`, the publishing Farrier instance |
| `type` | `dev.farrier.renewal.<state>` |
| `time` | RFC 3339, UTC (`Z`), when the state changed |
| `subject` | The endpoint name |
| `datacontenttype` | `"application/json"` |
| `data` | The payload below |

States: `planned`, `issued`, `deploying`, `verifying`, `done`, `failed`, `rolled_back`,
`awaiting_manual`, `cancelled`. `type` always matches `data.renewal.state`.

## The payload

```json
{
  "schema_version": 1,
  "endpoint": {"id": 12, "name": "www-lb", "host": "10.20.1.10", "port": 443, "connector": "f5", "tags": ["prod", "acm:new"]},
  "renewal": {"id": 2041, "state": "done", "reason": "due", "not_after": "2027-02-10T09:29:59Z", "fingerprint_sha256": "4f2c…"},
  "certificate": {"names": ["www.example.com"], "issuer": "CN=R11,O=Let's Encrypt,C=US", "chain_ref": "s3://farrier-certs/prod/2041/fullchain.pem"},
  "private_key_ref": "aws-sm:arn:aws:secretsmanager:eu-west-1:123456789012:secret:farrier/keys/2041-AbCdEf"
}
```

- `renewal.fingerprint_sha256` is the lowercase hex SHA-256 of the new leaf certificate's
  DER encoding. Consumers use it to check that the chain they fetched is the certificate
  the event announced, and to detect duplicates.
- `renewal.not_after`, `renewal.fingerprint_sha256` and `certificate` are `null` until a
  certificate is issued (`planned`, and `failed` or `cancelled` before issuance). From
  `issued` on they are always set.
- `certificate.chain_ref` points to the full chain, leaf first, PEM. It is `null` when chain
  export is not configured.
- `private_key_ref` is set only when the operator enabled key export for that endpoint;
  otherwise `null`.
- `endpoint.tags` are the operator's tags. Functions use prefixed tags to opt endpoints in:
  `acm:`, `gcp-cm:`, `akv:`.

### References, never secrets

Events never carry key material or certificates, only references to where they are stored:

| Reference | Form |
| --- | --- |
| AWS Secrets Manager | `aws-sm:arn:aws:secretsmanager:<region>:<account>:secret:<name>` |
| Google Secret Manager | `gcp-sm:projects/<project>/secrets/<secret>/versions/<version>` |
| Azure Key Vault | `azure-kv:https://<vault>.vault.azure.net/secrets/<name>[/<version>]` |
| Amazon S3 | `s3://<bucket>/<key>` |
| Google Cloud Storage | `gs://<bucket>/<object>` |
| Azure Blob Storage | `azblob://<account>/<container>/<blob>` |

The referenced secret holds the unencrypted PEM private key (PKCS#8 or traditional). Reading
it needs the consumer's own cloud identity and IAM permission, so an event that leaks, is
logged or lands in a dead-letter queue discloses nothing usable.

## Versioning

`data.schema_version` is the payload's major version. Within a major version Farrier only
makes additive changes: new optional properties, new `reason` values, new tag conventions.
It never removes or renames a property or changes its type or meaning. Consumers must
therefore ignore properties they do not know. New states are a breaking change and come with
a new major version.

A breaking change bumps `schema_version` and Farrier publishes both versions side by side
for at least one minor release, so consumers can move at their own pace. A consumer that
receives a major version it does not support fails the event permanently (it goes to the
dead-letter queue) rather than guessing.

## Delivery semantics

Delivery is **at least once**. Every transport retries, and Farrier itself retries a publish
that timed out, so the same event can arrive more than once and, rarely, out of order.
Handlers must therefore:

1. **Deduplicate on `id`**, not on the transport's message id (EventBridge and Pub/Sub assign
   a new one when a publish is retried). Where the side effect can be observed, prefer
   natural idempotency: the shipped functions compare the target certificate's fingerprint
   with the event's and skip if it already matches.
2. **Ignore stale events**: if the target already carries a higher `renewal.id`, skip.
3. **Fail loudly**: raise on error so the platform retries. Errors that retrying cannot fix
   (invalid event, missing reference, fingerprint mismatch) still raise; bounded retries run
   out and the event lands on the dead-letter queue for a human.

## Transports

The same CloudEvent is delivered over three transports.

### AWS EventBridge

Farrier calls `PutEvents` on a custom bus (default `farrier`) with:

| PutEvents field | Value |
| --- | --- |
| `Source` | `"farrier"` |
| `DetailType` | the CloudEvent `type`, e.g. `dev.farrier.renewal.done` |
| `Detail` | the whole CloudEvent, as JSON |
| `EventBusName` | the bus |

Rules match on `source` and `detail-type`:

```json
{ "source": ["farrier"], "detail-type": ["dev.farrier.renewal.done"] }
```

A Lambda target receives the EventBridge envelope; the CloudEvent is `event["detail"]`.
`deploy/terraform/aws-events` creates the bus, rules, DLQs and the shipped functions.

### Google Cloud Pub/Sub

Farrier publishes to a topic (default `farrier-renewals`):

| Pub/Sub field | Value |
| --- | --- |
| `data` | the CloudEvent JSON (UTF-8) |
| attribute `ce-type` | the CloudEvent `type` |
| attribute `ce-id` | the CloudEvent `id` |
| attribute `ce-source` | the CloudEvent `source` |

Subscriptions can filter on attributes, e.g. `attributes."ce-type" = "dev.farrier.renewal.done"`.
A Cloud Function (2nd gen) with a Pub/Sub trigger receives the message in
`cloud_event.data["message"]`; `data` is base64.

### Azure Event Grid

Farrier publishes to an Event Grid custom topic whose input schema is **CloudEvents v1.0**,
so the event is delivered unchanged. Subscriptions filter on `type`
(`dev.farrier.renewal.done`). An Azure Function with an Event Grid trigger receives the
fields through the binding (`id`, `event_type`, `subject`, `event_time`, `get_json()` for
`data`).
