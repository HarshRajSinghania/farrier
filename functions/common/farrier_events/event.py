"""Typed model and validator for the Farrier renewal event.

The JSON Schema in ``events/schema/renewal-event.schema.json`` is the contract.
This module is a dependency-free validator that enforces the same rules (a test
keeps the two in step), plus the cross-field checks JSON Schema cannot express
cleanly (``type`` must match ``data.renewal.state``).

Unknown properties are ignored: within a schema major version Farrier only adds
optional fields, so a consumer built against version 1 keeps working.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .errors import InvalidEvent

SPEC_VERSION = "1.0"
TYPE_PREFIX = "dev.farrier.renewal."
SUPPORTED_SCHEMA_VERSION = 1
STATES: tuple[str, ...] = (
    "planned",
    "issued",
    "deploying",
    "verifying",
    "done",
    "failed",
    "rolled_back",
    "awaiting_manual",
    "cancelled",
)
# States in which a certificate has been issued and the event must describe it.
ISSUED_STATES: frozenset[str] = frozenset({"issued", "deploying", "verifying", "done"})
# States that need a human. The notify router reacts to these.
ATTENTION_STATES: frozenset[str] = frozenset({"failed", "rolled_back", "awaiting_manual"})

_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$")
_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")
_SOURCE = re.compile(r"^farrier://[A-Za-z0-9._~-]+$")
_OBJECT_REF = re.compile(r"^(s3|gs|azblob)://\S+$")
_SECRET_REF = re.compile(r"^(aws-sm:arn:aws[a-z-]*:secretsmanager:|gcp-sm:projects/|azure-kv:https://)\S+$")
MAX_EVENT_BYTES = 256 * 1024  # EventBridge's entry limit; anything larger is not ours.


def event_type(state: str) -> str:
    return TYPE_PREFIX + state


@dataclass(frozen=True, slots=True)
class Endpoint:
    id: int
    name: str
    host: str
    port: int
    connector: str
    tags: tuple[str, ...]

    def tag_values(self, prefix: str) -> list[str]:
        """Values of tags shaped ``<prefix>:<value>``, e.g. ``acm:new``."""
        lead = prefix + ":"
        return [t[len(lead) :] for t in self.tags if t.startswith(lead) and len(t) > len(lead)]


@dataclass(frozen=True, slots=True)
class Renewal:
    id: int
    state: str
    reason: str
    not_after: datetime | None
    fingerprint_sha256: str | None


@dataclass(frozen=True, slots=True)
class Certificate:
    names: tuple[str, ...]
    issuer: str
    chain_ref: str | None


@dataclass(frozen=True, slots=True)
class RenewalEvent:
    id: str
    source: str
    type: str
    time: datetime
    subject: str
    schema_version: int
    endpoint: Endpoint
    renewal: Renewal
    certificate: Certificate | None
    private_key_ref: str | None

    @property
    def state(self) -> str:
        return self.renewal.state

    def log_context(self) -> dict[str, Any]:
        """Identifiers safe to put on every log line."""
        return {
            "event_id": self.id,
            "event_type": self.type,
            "endpoint_id": self.endpoint.id,
            "endpoint_name": self.endpoint.name,
            "renewal_id": self.renewal.id,
        }


# --------------------------------------------------------------------------- validation


class _Checker:
    """Collects problems as ``path: rule`` strings. Never echoes values."""

    def __init__(self) -> None:
        self.problems: list[str] = []

    def fail(self, path: str, rule: str) -> None:
        self.problems.append(f"{path}: {rule}")

    def obj(self, value: Any, path: str, required: tuple[str, ...]) -> Mapping[str, Any] | None:
        if not isinstance(value, Mapping):
            self.fail(path, "must be an object")
            return None
        for key in required:
            if key not in value:
                self.fail(f"{path}.{key}", "is required")
        return value

    def string(self, value: Any, path: str, *, pattern: re.Pattern[str] | None = None, nullable: bool = False) -> None:
        if value is None and nullable:
            return
        if not isinstance(value, str) or not value:
            self.fail(path, "must be a non-empty string" + (" or null" if nullable else ""))
        elif pattern is not None and not pattern.match(value):
            self.fail(path, "has an invalid format")

    def integer(self, value: Any, path: str, *, minimum: int, maximum: int | None = None) -> None:
        if not isinstance(value, int) or isinstance(value, bool):
            self.fail(path, "must be an integer")
        elif value < minimum or (maximum is not None and value > maximum):
            self.fail(path, f"must be between {minimum} and {maximum}" if maximum else f"must be >= {minimum}")

    def timestamp(self, value: Any, path: str, *, nullable: bool = False) -> None:
        if value is None and nullable:
            return
        if not isinstance(value, str) or not _TIMESTAMP.match(value):
            self.fail(path, "must be an RFC 3339 timestamp" + (" or null" if nullable else ""))
            return
        try:
            _parse_time(value)
        except ValueError:
            self.fail(path, "is not a real date and time")

    def string_list(self, value: Any, path: str, *, min_items: int = 0) -> None:
        if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
            self.fail(path, "must be an array of non-empty strings")
        elif len(value) < min_items:
            self.fail(path, f"must have at least {min_items} item(s)")


def _parse_time(value: str) -> datetime:
    # fromisoformat handles "Z" and offsets on 3.11+, but only up to 6 fractional digits.
    head, dot, tail = value.partition(".")
    if dot:
        digits = re.match(r"\d+", tail)
        frac = digits.group(0) if digits else ""
        value = f"{head}.{frac[:6].ljust(6, '0')}{tail[len(frac) :]}"
    return datetime.fromisoformat(value)


def validate(raw: Any) -> list[str]:
    """Return every problem with ``raw``; an empty list means it is valid."""
    c = _Checker()
    ev = c.obj(raw, "$", ("specversion", "id", "source", "type", "time", "subject", "datacontenttype", "data"))
    if ev is None:
        return c.problems
    if "specversion" in ev and ev["specversion"] != SPEC_VERSION:
        c.fail("$.specversion", "must be '1.0'")
    if "id" in ev:
        c.string(ev["id"], "$.id")
        if isinstance(ev["id"], str) and len(ev["id"]) > 128:
            c.fail("$.id", "must be at most 128 characters")
    if "source" in ev:
        c.string(ev["source"], "$.source", pattern=_SOURCE)
    type_state: str | None = None
    if "type" in ev:
        t = ev["type"]
        if not isinstance(t, str) or not t.startswith(TYPE_PREFIX) or t[len(TYPE_PREFIX) :] not in STATES:
            c.fail("$.type", "must be dev.farrier.renewal.<state> with a known state")
        else:
            type_state = t[len(TYPE_PREFIX) :]
    if "time" in ev:
        c.timestamp(ev["time"], "$.time")
    if "subject" in ev:
        c.string(ev["subject"], "$.subject")
    if "datacontenttype" in ev and ev["datacontenttype"] != "application/json":
        c.fail("$.datacontenttype", "must be 'application/json'")
    if "data" in ev:
        _validate_data(c, ev["data"], type_state)
    return c.problems


def _validate_data(c: _Checker, raw: Any, type_state: str | None) -> None:
    data = c.obj(raw, "$.data", ("schema_version", "endpoint", "renewal", "certificate", "private_key_ref"))
    if data is None:
        return
    if "schema_version" in data:
        sv = data["schema_version"]
        if not isinstance(sv, int) or isinstance(sv, bool):
            c.fail("$.data.schema_version", "must be an integer")
        elif sv != SUPPORTED_SCHEMA_VERSION:
            c.fail(
                "$.data.schema_version", f"unsupported major version (this consumer handles {SUPPORTED_SCHEMA_VERSION})"
            )

    ep = (
        c.obj(data.get("endpoint"), "$.data.endpoint", ("id", "name", "host", "port", "connector", "tags"))
        if "endpoint" in data
        else None
    )
    if ep is not None:
        if "id" in ep:
            c.integer(ep["id"], "$.data.endpoint.id", minimum=1)
        for key in ("name", "host", "connector"):
            if key in ep:
                c.string(ep[key], f"$.data.endpoint.{key}")
        if "port" in ep:
            c.integer(ep["port"], "$.data.endpoint.port", minimum=1, maximum=65535)
        if "tags" in ep:
            c.string_list(ep["tags"], "$.data.endpoint.tags")

    state: str | None = None
    rn = (
        c.obj(data.get("renewal"), "$.data.renewal", ("id", "state", "reason", "not_after", "fingerprint_sha256"))
        if "renewal" in data
        else None
    )
    if rn is not None:
        if "id" in rn:
            c.integer(rn["id"], "$.data.renewal.id", minimum=1)
        if "state" in rn:
            if rn["state"] not in STATES:
                c.fail("$.data.renewal.state", "must be a known state")
            else:
                state = rn["state"]
        if "reason" in rn:
            c.string(rn["reason"], "$.data.renewal.reason")
        issued = state in ISSUED_STATES
        if "not_after" in rn:
            c.timestamp(rn["not_after"], "$.data.renewal.not_after", nullable=not issued)
        if "fingerprint_sha256" in rn:
            c.string(
                rn["fingerprint_sha256"], "$.data.renewal.fingerprint_sha256", pattern=_FINGERPRINT, nullable=not issued
            )
    if state is not None and type_state is not None and state != type_state:
        c.fail("$.type", "does not match data.renewal.state")

    if "certificate" in data:
        cert = data["certificate"]
        if cert is None:
            if state in ISSUED_STATES:
                c.fail("$.data.certificate", f"is required once the renewal is {state}")
        else:
            co = c.obj(cert, "$.data.certificate", ("names", "issuer", "chain_ref"))
            if co is not None:
                if "names" in co:
                    c.string_list(co["names"], "$.data.certificate.names", min_items=1)
                if "issuer" in co and not isinstance(co["issuer"], str):
                    c.fail("$.data.certificate.issuer", "must be a string")
                if "chain_ref" in co:
                    c.string(co["chain_ref"], "$.data.certificate.chain_ref", pattern=_OBJECT_REF, nullable=True)
    if "private_key_ref" in data:
        c.string(data["private_key_ref"], "$.data.private_key_ref", pattern=_SECRET_REF, nullable=True)


# --------------------------------------------------------------------------- parsing


def parse_event(raw: Mapping[str, Any] | str | bytes) -> RenewalEvent:
    """Validate and convert a CloudEvent into a :class:`RenewalEvent`.

    Raises :class:`InvalidEvent` (a ``PermanentError``) listing every problem.
    """
    if isinstance(raw, (str, bytes, bytearray)):
        if len(raw) > MAX_EVENT_BYTES:
            raise InvalidEvent([f"$: larger than {MAX_EVENT_BYTES} bytes"])
        try:
            raw = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            raise InvalidEvent(["$: is not valid JSON"]) from None
    problems = validate(raw)
    if problems:
        raise InvalidEvent(problems)
    assert isinstance(raw, Mapping)
    d = raw["data"]
    ep, rn, cert = d["endpoint"], d["renewal"], d["certificate"]
    return RenewalEvent(
        id=raw["id"],
        source=raw["source"],
        type=raw["type"],
        time=_parse_time(raw["time"]),
        subject=raw["subject"],
        schema_version=d["schema_version"],
        endpoint=Endpoint(
            id=ep["id"],
            name=ep["name"],
            host=ep["host"],
            port=ep["port"],
            connector=ep["connector"],
            tags=tuple(ep["tags"]),
        ),
        renewal=Renewal(
            id=rn["id"],
            state=rn["state"],
            reason=rn["reason"],
            not_after=_parse_time(rn["not_after"]) if rn["not_after"] else None,
            fingerprint_sha256=rn["fingerprint_sha256"],
        ),
        certificate=None
        if cert is None
        else Certificate(names=tuple(cert["names"]), issuer=cert["issuer"], chain_ref=cert["chain_ref"]),
        private_key_ref=d["private_key_ref"],
    )
