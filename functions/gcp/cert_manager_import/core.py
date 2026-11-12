"""Upload a renewed certificate to Google Certificate Manager (self-managed).

Selection
    * tag ``gcp-cm:<certificate-id>`` -- that certificate in ``GCP_CM_PROJECT`` /
      ``GCP_CM_LOCATION`` (default ``global``);
    * tag ``gcp-cm:projects/<p>/locations/<l>/certificates/<id>`` -- fully qualified;
    * no tag, endpoint name matches ``GCP_CM_NAME_PATTERN`` -- certificate id
      ``farrier-<endpoint name>`` in the default project and location.

The certificate is created on the first renewal and updated in place
(``PATCH ...?updateMask=selfManaged,labels``) afterwards, so certificate maps
and load balancers that reference it pick up the new material.

Idempotency
    Labels hold the leaf fingerprint (split over ``farrier-fp-a`` and
    ``farrier-fp-b``: label values are capped at 63 characters) and the renewal
    id. Matching fingerprint: skip. Newer renewal id: stale event, skip. Labels
    are written in the same request as the material, so they cannot drift.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from functools import partial
from typing import Any, Protocol

from farrier_events import (
    GcpSecretRef,
    GcsObjectRef,
    Logger,
    PermanentError,
    RenewalEvent,
    RetryPolicy,
    TransientError,
    ensure_allowed,
    parse_event,
    parse_object_ref,
    parse_secret_ref,
)
from farrier_events.pem import verify_leaf
from farrier_events.transports import from_pubsub

TAG_PREFIX = "gcp-cm"
LABEL_MANAGED = "farrier-managed"
LABEL_ENDPOINT_ID = "farrier-endpoint-id"
LABEL_RENEWAL_ID = "farrier-renewal-id"
LABEL_FP_A = "farrier-fp-a"
LABEL_FP_B = "farrier-fp-b"

_CERT_ID = re.compile(r"^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$")
_FULL_NAME = re.compile(
    r"^projects/(?P<project>[a-z0-9-]+)/locations/(?P<location>[a-z0-9-]+)/certificates/(?P<id>[a-z][a-z0-9-]{0,62})$"
)


# --------------------------------------------------------------------------- ports


class SecretReader(Protocol):
    def access(self, ref: GcpSecretRef) -> str: ...


class ChainReader(Protocol):
    def read_text(self, ref: GcsObjectRef) -> str: ...


class CertificateManager(Protocol):
    def get(self, name: str) -> Mapping[str, Any] | None: ...
    def create(self, parent: str, certificate_id: str, body: Mapping[str, Any]) -> Mapping[str, Any]: ...
    def patch(self, name: str, body: Mapping[str, Any], update_mask: str) -> Mapping[str, Any]: ...
    def get_operation(self, name: str) -> Mapping[str, Any]: ...


@dataclass(frozen=True, slots=True)
class Deps:
    secrets: SecretReader
    chains: ChainReader
    cm: CertificateManager


@dataclass(frozen=True, slots=True)
class Config:
    project: str
    location: str = "global"
    name_pattern: str | None = None
    allowed_prefixes: tuple[str, ...] = ()
    retry: RetryPolicy = RetryPolicy()
    operation_polls: int = 20
    poll_interval_s: float = 3.0
    sleep: Callable[[float], None] | None = None  # None: use retry.sleep


# --------------------------------------------------------------------------- pure helpers


def certificate_id_for(endpoint_name: str) -> str:
    slug = re.sub(r"[^a-z0-9-]+", "-", endpoint_name.lower()).strip("-")
    cid = f"farrier-{slug}"[:63].rstrip("-")
    if not _CERT_ID.match(cid):
        raise PermanentError("cannot derive a Certificate Manager id from the endpoint name")
    return cid


def resolve_target(event: RenewalEvent, config: Config) -> str | None:
    """Full resource name of the target certificate, or None if not selected."""
    values = event.endpoint.tag_values(TAG_PREFIX)
    if len(values) > 1:
        raise PermanentError("endpoint has more than one gcp-cm: tag")
    if values:
        value = values[0]
        if _FULL_NAME.match(value):
            return value
        if _CERT_ID.match(value):
            return f"projects/{config.project}/locations/{config.location}/certificates/{value}"
        raise PermanentError("gcp-cm: tag must be a certificate id or full resource name")
    if config.name_pattern and fnmatch.fnmatchcase(event.endpoint.name, config.name_pattern):
        cid = certificate_id_for(event.endpoint.name)
        return f"projects/{config.project}/locations/{config.location}/certificates/{cid}"
    return None


def farrier_labels(event: RenewalEvent) -> dict[str, str]:
    fp = event.renewal.fingerprint_sha256
    assert fp is not None
    return {
        LABEL_MANAGED: "true",
        LABEL_ENDPOINT_ID: str(event.endpoint.id),
        LABEL_RENEWAL_ID: str(event.renewal.id),
        LABEL_FP_A: fp[:32],
        LABEL_FP_B: fp[32:],
    }


def labelled_fingerprint(labels: Mapping[str, str]) -> str | None:
    a, b = labels.get(LABEL_FP_A), labels.get(LABEL_FP_B)
    return a + b if a and b else None


def skip_reason(existing: Mapping[str, Any], event: RenewalEvent) -> str | None:
    labels = existing.get("labels") or {}
    if labelled_fingerprint(labels) == event.renewal.fingerprint_sha256:
        return "already-current"
    current = str(labels.get(LABEL_RENEWAL_ID, ""))
    if current.isdigit() and int(current) > event.renewal.id:
        return "stale-event"
    return None


_TRANSIENT_RPC_CODES = {4, 8, 10, 13, 14}  # DEADLINE_EXCEEDED, RESOURCE_EXHAUSTED, ABORTED, INTERNAL, UNAVAILABLE


def operation_result(op: Mapping[str, Any]) -> bool:
    """True when done and successful; False while running; raises on error."""
    if not op.get("done"):
        return False
    error = op.get("error")
    if error:
        code = int(error.get("code", 2))
        cls = TransientError if code in _TRANSIENT_RPC_CODES else PermanentError
        raise cls(f"certificatemanager operation failed with code {code}")
    return True


@dataclass(frozen=True, slots=True)
class Outcome:
    action: str  # created | updated | skipped
    reason: str | None = None
    certificate: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"action": self.action, "reason": self.reason, "certificate": self.certificate}


# --------------------------------------------------------------------------- orchestration


def process(event: RenewalEvent, deps: Deps, config: Config, log: Logger) -> Outcome:
    if event.state != "done":
        return Outcome("skipped", "state-not-done")
    name = resolve_target(event, config)
    if name is None:
        return Outcome("skipped", "not-selected")
    cert = event.certificate
    assert cert is not None and event.renewal.fingerprint_sha256 is not None
    if cert.chain_ref is None or event.private_key_ref is None:
        raise PermanentError("event lacks chain_ref or private_key_ref; enable chain and key export")
    ensure_allowed(cert.chain_ref, config.allowed_prefixes)
    ensure_allowed(event.private_key_ref, config.allowed_prefixes)
    chain_ref, key_ref = parse_object_ref(cert.chain_ref), parse_secret_ref(event.private_key_ref)
    if not isinstance(chain_ref, GcsObjectRef) or not isinstance(key_ref, GcpSecretRef):
        raise PermanentError("cert_manager_import reads chains from gs:// and keys from gcp-sm: only")

    def retried[R](fn: Callable[[], R]) -> R:
        return config.retry.run(fn, log)

    existing = retried(lambda: deps.cm.get(name))
    if existing is not None:
        if "selfManaged" not in existing and "managed" in existing:
            raise PermanentError("target is a Google-managed certificate; it cannot be updated with uploaded material")
        reason = skip_reason(existing, event)
        if reason:
            return Outcome("skipped", reason, name)

    fullchain = retried(lambda: deps.chains.read_text(chain_ref))
    leaf, intermediates = verify_leaf(fullchain, event.renewal.fingerprint_sha256)
    private_key = retried(lambda: deps.secrets.access(key_ref))
    material = {"pemCertificate": leaf + intermediates, "pemPrivateKey": private_key}
    labels = {**((existing or {}).get("labels") or {}), **farrier_labels(event)}

    if existing is None:
        parent, _, cid = name.rpartition("/certificates/")
        body = {
            "description": f"Managed by Farrier (endpoint {event.endpoint.id})",
            "selfManaged": material,
            "labels": labels,
        }
        op = retried(lambda: deps.cm.create(parent, cid, body))
        action = "created"
    else:
        op = retried(lambda: deps.cm.patch(name, {"selfManaged": material, "labels": labels}, "selfManaged,labels"))
        action = "updated"
    _wait(op, deps, config)
    return Outcome(action, None, name)


def _wait(op: Mapping[str, Any], deps: Deps, config: Config) -> None:
    sleep = config.sleep or config.retry.sleep
    for _ in range(config.operation_polls):
        if operation_result(op):
            return
        sleep(config.poll_interval_s)
        op_name = str(op["name"])
        op = config.retry.run(partial(deps.cm.get_operation, op_name))
    if operation_result(op):
        return
    # Still running: redeliver. The next attempt sees the new labels and skips, or re-applies.
    raise TransientError("certificatemanager operation did not finish in time")


def handle(message: Mapping[str, Any], deps: Deps, config: Config, log: Logger) -> dict[str, Any]:
    """``message`` is the Pub/Sub message from the Eventarc CloudEvent."""
    try:
        event = parse_event(from_pubsub(message))
    except PermanentError as exc:
        log.error("rejected event", error_type=type(exc).__name__, error=str(exc), dlq_bound=True)
        raise
    elog = log.bind(**event.log_context())
    try:
        outcome = process(event, deps, config, elog)
    except PermanentError as exc:
        elog.error("upload failed permanently", error_type=type(exc).__name__, error=str(exc), dlq_bound=True)
        raise
    except Exception as exc:
        elog.error("upload failed, will be retried", error_type=type(exc).__name__, error=str(exc), dlq_bound=False)
        raise
    elog.info("certificate manager " + outcome.action, **outcome.as_dict())
    return outcome.as_dict()
