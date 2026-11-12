"""Import a renewed certificate into AWS Certificate Manager.

Pure decision logic; every AWS call goes through the ports below so tests run
against fakes. The Lambda entrypoint (``handler.py``) wires the boto3 adapters.

Which endpoints are imported
    * tag ``acm:new`` -- import as a new ACM certificate the first time, then
      re-import into that same certificate (found by its ``farrier:endpoint-id``
      tag) on every later renewal;
    * tag ``acm:<certificate ARN>`` -- re-import into that ARN, rotating in
      place so load balancers and CloudFront keep their association;
    * no tag, but the endpoint name matches ``ACM_NAME_PATTERN`` -- as ``acm:new``.

Idempotency
    The target certificate carries ``farrier:fingerprint-sha256``. If it already
    equals the event's fingerprint the event is a duplicate and is skipped; if
    its ``farrier:renewal-id`` is newer than the event's, the event is stale and
    is skipped. Tags are written in the same call as a new import, and after a
    re-import; a crash in between re-imports the same material on retry, which
    is harmless.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from farrier_events import (
    AwsSecretRef,
    Logger,
    PermanentError,
    RenewalEvent,
    RetryPolicy,
    S3ObjectRef,
    ensure_allowed,
    parse_event,
    parse_object_ref,
    parse_secret_ref,
)
from farrier_events.pem import verify_leaf
from farrier_events.transports import from_eventbridge

TAG_PREFIX = "acm"
TAG_ENDPOINT_ID = "farrier:endpoint-id"
TAG_ENDPOINT_NAME = "farrier:endpoint-name"
TAG_RENEWAL_ID = "farrier:renewal-id"
TAG_FINGERPRINT = "farrier:fingerprint-sha256"
TAG_MANAGED = "farrier:managed"

_ACM_ARN = re.compile(r"^arn:aws[a-z-]*:acm:(?P<region>[a-z0-9-]+):\d{12}:certificate/[0-9a-f-]{36}$")
_TAG_VALUE_UNSAFE = re.compile(r"[^\w .:/=+\-@]")


# --------------------------------------------------------------------------- ports


class ChainStore(Protocol):
    def get_text(self, ref: S3ObjectRef) -> str: ...


class SecretStore(Protocol):
    def get_secret(self, ref: AwsSecretRef) -> str: ...


class CertificateManager(Protocol):
    def find_by_endpoint(self, endpoint_id: int) -> str | None: ...
    def get_tags(self, arn: str) -> dict[str, str]: ...
    def import_certificate(
        self, *, certificate: str, private_key: str, chain: str, arn: str | None, tags: Mapping[str, str] | None
    ) -> str: ...
    def add_tags(self, arn: str, tags: Mapping[str, str]) -> None: ...


@dataclass(frozen=True, slots=True)
class Deps:
    chains: ChainStore
    secrets: SecretStore
    acm: CertificateManager


@dataclass(frozen=True, slots=True)
class Config:
    region: str
    name_pattern: str | None = None
    allowed_prefixes: tuple[str, ...] = ()
    discovery: bool = True
    retry: RetryPolicy = RetryPolicy()


# --------------------------------------------------------------------------- pure helpers


@dataclass(frozen=True, slots=True)
class Target:
    arn: str | None  # None: import as new, or into the certificate already tagged for this endpoint


def resolve_target(event: RenewalEvent, config: Config) -> Target | None:
    values = event.endpoint.tag_values(TAG_PREFIX)
    if len(values) > 1:
        raise PermanentError("endpoint has more than one acm: tag")
    if values:
        value = values[0]
        if value == "new":
            return Target(arn=None)
        m = _ACM_ARN.match(value)
        if not m:
            raise PermanentError("acm: tag must be 'acm:new' or 'acm:<certificate ARN>'")
        if m["region"] != config.region:
            raise PermanentError("acm: tag ARN is in a different region from this function")
        return Target(arn=value)
    if config.name_pattern and fnmatch.fnmatchcase(event.endpoint.name, config.name_pattern):
        return Target(arn=None)
    return None


def tag_value(value: str) -> str:
    return _TAG_VALUE_UNSAFE.sub("_", value)[:256]


def farrier_tags(event: RenewalEvent) -> dict[str, str]:
    assert event.renewal.fingerprint_sha256 is not None
    return {
        TAG_MANAGED: "true",
        TAG_ENDPOINT_ID: str(event.endpoint.id),
        TAG_ENDPOINT_NAME: tag_value(event.endpoint.name),
        TAG_RENEWAL_ID: str(event.renewal.id),
        TAG_FINGERPRINT: event.renewal.fingerprint_sha256,
    }


def skip_reason(existing_tags: Mapping[str, str], event: RenewalEvent) -> str | None:
    if existing_tags.get(TAG_FINGERPRINT) == event.renewal.fingerprint_sha256:
        return "already-current"
    current = existing_tags.get(TAG_RENEWAL_ID, "")
    if current.isdigit() and int(current) > event.renewal.id:
        return "stale-event"
    return None


@dataclass(frozen=True, slots=True)
class Outcome:
    action: str  # imported | reimported | skipped
    reason: str | None = None
    certificate_arn: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"action": self.action, "reason": self.reason, "certificate_arn": self.certificate_arn}


# --------------------------------------------------------------------------- orchestration


def process(event: RenewalEvent, deps: Deps, config: Config, log: Logger) -> Outcome:
    if event.state != "done":
        return Outcome("skipped", "state-not-done")
    target = resolve_target(event, config)
    if target is None:
        return Outcome("skipped", "not-selected")

    cert = event.certificate
    assert cert is not None and event.renewal.fingerprint_sha256 is not None  # guaranteed for "done"
    if cert.chain_ref is None:
        raise PermanentError("event has no chain_ref; enable chain export for this endpoint")
    if event.private_key_ref is None:
        raise PermanentError("event has no private_key_ref; enable key export for this endpoint")
    ensure_allowed(cert.chain_ref, config.allowed_prefixes)
    ensure_allowed(event.private_key_ref, config.allowed_prefixes)
    chain_ref = parse_object_ref(cert.chain_ref)
    key_ref = parse_secret_ref(event.private_key_ref)
    if not isinstance(chain_ref, S3ObjectRef):
        raise PermanentError("acm_import reads chains from s3:// only")
    if not isinstance(key_ref, AwsSecretRef):
        raise PermanentError("acm_import reads keys from aws-sm: only")

    def retried[R](fn: Callable[[], R]) -> R:
        return config.retry.run(fn, log)

    arn = target.arn
    if arn is None and config.discovery:
        arn = retried(lambda: deps.acm.find_by_endpoint(event.endpoint.id))
    if arn is not None:
        existing = retried(lambda: deps.acm.get_tags(arn))
        reason = skip_reason(existing, event)
        if reason:
            return Outcome("skipped", reason, arn)

    fullchain = retried(lambda: deps.chains.get_text(chain_ref))
    leaf, intermediates = verify_leaf(fullchain, event.renewal.fingerprint_sha256)
    private_key = retried(lambda: deps.secrets.get_secret(key_ref))

    tags = farrier_tags(event)
    if arn is None:
        new_arn = retried(
            lambda: deps.acm.import_certificate(
                certificate=leaf, private_key=private_key, chain=intermediates, arn=None, tags=tags
            )
        )
        return Outcome("imported", None, new_arn)

    retried(
        lambda: deps.acm.import_certificate(
            certificate=leaf, private_key=private_key, chain=intermediates, arn=arn, tags=None
        )
    )
    retried(lambda: deps.acm.add_tags(arn, tags))  # fingerprint tag last: it marks the import complete
    return Outcome("reimported", None, arn)


def handle(envelope: Mapping[str, Any], deps: Deps, config: Config, log: Logger) -> dict[str, Any]:
    """Entry point shared by the Lambda handler and tests.

    Returns a summary on success or skip; raises on failure so EventBridge /
    Lambda async retries run and, once exhausted, the event lands on the DLQ.
    """
    try:
        event = parse_event(from_eventbridge(envelope))
    except PermanentError as exc:
        log.error("rejected event", error_type=type(exc).__name__, error=str(exc), dlq_bound=True)
        raise
    elog = log.bind(**event.log_context())
    try:
        outcome = process(event, deps, config, elog)
    except PermanentError as exc:
        elog.error("import failed permanently", error_type=type(exc).__name__, error=str(exc), dlq_bound=True)
        raise
    except Exception as exc:
        elog.error("import failed, will be retried", error_type=type(exc).__name__, error=str(exc), dlq_bound=False)
        raise
    elog.info("acm import " + outcome.action, **outcome.as_dict())
    return outcome.as_dict()
