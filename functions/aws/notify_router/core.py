"""Route renewals that need a human to chat, webhooks and ticketing systems.

Reacts to ``failed``, ``rolled_back`` and ``awaiting_manual``. Each configured
sink receives the event at most once per event id (best effort, see below):
the idempotency key is ``<event id>:<sink name>``, so when one sink fails and
the event is redelivered, sinks that already succeeded are not called again.

"At most once per sink" holds as long as the store is durable (DynamoDB in
production). A crash between a sink accepting the message and ``complete``
being recorded lets the lease expire and the message is sent again: receivers
that must not duplicate should dedupe on the ``X-Farrier-Event-Id`` header.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from functools import partial
from typing import Any, Protocol

from farrier_events import (
    ATTENTION_STATES,
    IdempotencyStore,
    Logger,
    PermanentError,
    RenewalEvent,
    RetryPolicy,
    TransientError,
    parse_event,
    run_once,
)
from farrier_events.transports import from_eventbridge

SEVERITY = {"failed": "critical", "rolled_back": "high", "awaiting_manual": "warning"}
HEADLINE = {
    "failed": "Renewal failed",
    "rolled_back": "Renewal rolled back",
    "awaiting_manual": "Renewal needs a manual step",
}


@dataclass(frozen=True, slots=True)
class Notification:
    """What every sink renders. Built only from non-secret event fields."""

    event_id: str
    state: str
    severity: str
    title: str
    text: str
    fields: tuple[tuple[str, str], ...]
    link: str | None
    cloudevent: Mapping[str, Any] = field(repr=False)


class Sink(Protocol):
    name: str

    def send(self, notification: Notification) -> None:
        """Deliver or raise TransientError / PermanentError."""


def build_notification(event: RenewalEvent, raw: Mapping[str, Any], dashboard_url: str | None) -> Notification:
    ep, rn = event.endpoint, event.renewal
    title = f"{HEADLINE[event.state]}: {ep.name}"
    fields: list[tuple[str, str]] = [
        ("Endpoint", f"{ep.name} ({ep.host}:{ep.port})"),
        ("Connector", ep.connector),
        ("Renewal", f"#{rn.id} ({rn.reason})"),
        ("State", event.state),
    ]
    if event.certificate is not None:
        fields.append(("Names", ", ".join(event.certificate.names[:10])))
    if ep.tags:
        fields.append(("Tags", ", ".join(ep.tags[:20])))
    text = {
        "failed": "Farrier could not renew this certificate. The current certificate stays in place.",
        "rolled_back": "The new certificate failed verification and Farrier restored the previous one.",
        "awaiting_manual": "This renewal is waiting for an operator to finish a manual step.",
    }[event.state]
    link = f"{dashboard_url.rstrip('/')}/dashboard/renewals" if dashboard_url else None
    return Notification(
        event_id=event.id,
        state=event.state,
        severity=SEVERITY[event.state],
        title=title,
        text=text,
        fields=tuple(fields),
        link=link,
        cloudevent=raw,
    )


def check_status(status: int, sink: str) -> None:
    """HTTP status to error class. 2xx is success."""
    if 200 <= status < 300:
        return
    if status == 429 or status >= 500 or status == 408:
        raise TransientError(f"{sink}: HTTP {status}")
    raise PermanentError(f"{sink}: HTTP {status}")


@dataclass(frozen=True, slots=True)
class Config:
    states: frozenset[str] = ATTENTION_STATES
    dashboard_url: str | None = None
    retry: RetryPolicy = RetryPolicy(attempts=3)
    lease_seconds: int = 300


@dataclass(frozen=True, slots=True)
class Deps:
    sinks: Sequence[Sink]
    store: IdempotencyStore


@dataclass(frozen=True, slots=True)
class Result:
    sent: tuple[str, ...]
    duplicate: tuple[str, ...]
    failed: tuple[tuple[str, str], ...]  # (sink, error type)


def process(event: RenewalEvent, raw: Mapping[str, Any], deps: Deps, config: Config, log: Logger) -> Result | None:
    if event.state not in config.states:
        return None
    notification = build_notification(event, raw, config.dashboard_url)
    sent: list[str] = []
    duplicate: list[str] = []
    failed: list[tuple[str, BaseException]] = []
    for sink in deps.sinks:
        slog = log.bind(sink=sink.name)

        def deliver(sink: Sink = sink, slog: Logger = slog) -> None:
            config.retry.run(partial(sink.send, notification), slog)

        try:
            ran, _ = run_once(deps.store, f"{event.id}:{sink.name}", deliver, lease_seconds=config.lease_seconds)
        except (TransientError, PermanentError) as exc:
            slog.error("sink failed", error_type=type(exc).__name__, error=str(exc))
            failed.append((sink.name, exc))
            continue
        (sent if ran else duplicate).append(sink.name)

    result = Result(tuple(sent), tuple(duplicate), tuple((n, type(e).__name__) for n, e in failed))
    if failed:
        # Any transient failure: redeliver (succeeded sinks are skipped next time).
        # Only permanent failures: no point retrying, send the event to the DLQ.
        if any(isinstance(e, TransientError) for _, e in failed):
            raise TransientError("sinks failed: " + ", ".join(n for n, _ in failed))
        raise PermanentError("sinks failed permanently: " + ", ".join(n for n, _ in failed))
    return result


def handle(envelope: Mapping[str, Any], deps: Deps, config: Config, log: Logger) -> dict[str, Any]:
    try:
        raw = from_eventbridge(envelope)
        event = parse_event(raw)
    except PermanentError as exc:
        log.error("rejected event", error_type=type(exc).__name__, error=str(exc), dlq_bound=True)
        raise
    elog = log.bind(**event.log_context())
    try:
        result = process(event, raw, deps, config, elog)
    except PermanentError as exc:
        elog.error("notification failed permanently", error_type=type(exc).__name__, error=str(exc), dlq_bound=True)
        raise
    except Exception as exc:
        elog.error(
            "notification failed, will be retried", error_type=type(exc).__name__, error=str(exc), dlq_bound=False
        )
        raise
    if result is None:
        elog.info("ignored state", state=event.state)
        return {"action": "skipped", "reason": "state-not-routed"}
    summary = {"action": "notified", "sent": list(result.sent), "duplicate": list(result.duplicate)}
    elog.info("notifications delivered", **summary)
    return summary
