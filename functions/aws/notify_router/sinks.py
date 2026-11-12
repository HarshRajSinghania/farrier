"""Notification sinks.

A sink is any object with a ``name`` and ``send(notification)`` that raises
``TransientError`` (retry) or ``PermanentError`` (give up) on failure. Sinks
render a :class:`~notify_router.core.Notification`; they never see secrets
other than their own delivery credential, which they must not log or put in
exception messages.

Adding ServiceNow, Jira, PagerDuty, ...: write a class like ``WebhookSink``,
then register a factory in ``SINK_FACTORIES`` keyed by the name operators put
in ``NOTIFY_SINKS``. See this function's README for a ServiceNow example.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from collections.abc import Callable, Mapping
from typing import Any, Protocol
from urllib.parse import urlsplit

from farrier_events import PermanentError

from .core import Notification, Sink, check_status

SIGNATURE_HEADER = "X-Farrier-Signature"
EVENT_ID_HEADER = "X-Farrier-Event-Id"


class HttpPoster(Protocol):
    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> int:
        """POST and return the status. Raise TransientError on network failure."""


# --------------------------------------------------------------------------- signing


def sign(secret: bytes, timestamp: int, body: bytes) -> str:
    """``X-Farrier-Signature`` value: ``t=<unix seconds>,v1=<hex HMAC-SHA256>``.

    The MAC covers ``"<timestamp>." + body`` so a captured request cannot be
    replayed later with a fresh timestamp. Receivers recompute it, compare with
    ``hmac.compare_digest`` and reject timestamps older than a few minutes.
    """
    mac = hmac.new(secret, f"{timestamp}.".encode("ascii") + body, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={mac}"


def verify(secret: bytes, header: str, body: bytes, *, now: int, tolerance_s: int = 300) -> bool:
    """Reference verifier for receivers (also used by the tests)."""
    try:
        parts = dict(p.split("=", 1) for p in header.split(","))
        ts = int(parts["t"])
        given = parts["v1"]
    except (KeyError, ValueError):
        return False
    if abs(now - ts) > tolerance_s:
        return False
    expected = sign(secret, ts, body).split("v1=", 1)[1]
    return hmac.compare_digest(expected, given)


def _require_https(url: str, what: str) -> None:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
        raise PermanentError(f"{what} must be an https:// URL without credentials")


# --------------------------------------------------------------------------- Slack


def _slack_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def slack_payload(n: Notification) -> dict[str, Any]:
    icon = {"critical": ":red_circle:", "high": ":large_orange_circle:", "warning": ":large_yellow_circle:"}[n.severity]
    blocks: list[dict[str, Any]] = [
        {"type": "header", "text": {"type": "plain_text", "text": n.title[:150]}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"{icon} {_slack_escape(n.text)}"}},
        {
            "type": "section",
            "fields": [{"type": "mrkdwn", "text": f"*{k}*\n{_slack_escape(v)}"} for k, v in n.fields[:10]],
        },
    ]
    if n.link:
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {"type": "button", "text": {"type": "plain_text", "text": "Open renewals"}, "url": n.link}
                ],
            }
        )
    return {"text": _slack_escape(n.title), "blocks": blocks}


class SlackSink:
    """Slack incoming webhook. The webhook URL *is* the credential: it is read
    from Secrets Manager on first use and never logged."""

    name = "slack"

    def __init__(self, webhook_url: Callable[[], str], http: HttpPoster) -> None:
        self._webhook_url = webhook_url
        self._http = http

    def send(self, notification: Notification) -> None:
        url = self._webhook_url()
        _require_https(url, "Slack webhook")
        body = json.dumps(slack_payload(notification), separators=(",", ":")).encode()
        status = self._http.post(url, body, {"Content-Type": "application/json"})
        check_status(status, self.name)


# --------------------------------------------------------------------------- generic webhook


class WebhookSink:
    """POSTs the CloudEvent (structured mode) to any HTTPS endpoint, signed."""

    name = "webhook"

    def __init__(
        self,
        url: str,
        secret: Callable[[], str],
        http: HttpPoster,
        clock: Callable[[], float] = time.time,
    ) -> None:
        _require_https(url, "WEBHOOK_URL")
        self._url = url
        self._secret = secret
        self._http = http
        self._clock = clock

    def send(self, notification: Notification) -> None:
        body = json.dumps(notification.cloudevent, separators=(",", ":"), sort_keys=True).encode()
        headers = {
            "Content-Type": "application/cloudevents+json",
            EVENT_ID_HEADER: notification.event_id,
            SIGNATURE_HEADER: sign(self._secret().encode(), int(self._clock()), body),
        }
        check_status(self._http.post(self._url, body, headers), self.name)


# --------------------------------------------------------------------------- registry


class Runtime(Protocol):
    """What factories may use to build a sink."""

    http: HttpPoster

    def secret(self, arn: str) -> Callable[[], str]:
        """A lazy, cached reader for a Secrets Manager secret."""


def _require(env: Mapping[str, str], key: str, sink: str) -> str:
    value = env.get(key, "").strip()
    if not value:
        raise PermanentError(f"sink {sink!r} needs {key}")
    return value


SINK_FACTORIES: dict[str, Callable[[Mapping[str, str], Runtime], Sink]] = {
    "slack": lambda env, rt: SlackSink(rt.secret(_require(env, "SLACK_WEBHOOK_SECRET_ARN", "slack")), rt.http),
    "webhook": lambda env, rt: WebhookSink(
        _require(env, "WEBHOOK_URL", "webhook"),
        rt.secret(_require(env, "WEBHOOK_SECRET_ARN", "webhook")),
        rt.http,
    ),
}


def build_sinks(env: Mapping[str, str], runtime: Runtime) -> list[Sink]:
    names = [n.strip() for n in env.get("NOTIFY_SINKS", "").split(",") if n.strip()]
    if not names:
        raise PermanentError("NOTIFY_SINKS is empty")
    unknown = [n for n in names if n not in SINK_FACTORIES]
    if unknown:
        raise PermanentError("unknown sinks: " + ", ".join(unknown))
    return [SINK_FACTORIES[n](env, runtime) for n in dict.fromkeys(names)]
