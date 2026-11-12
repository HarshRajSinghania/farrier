from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import pytest
from farrier_events import (
    InMemoryIdempotencyStore,
    PermanentError,
    RetryPolicy,
    TransientError,
    get_logger,
    parse_event,
)
from farrier_testkit import NoSleep, assert_no_secrets, eventbridge, make_event
from notify_router.adapters import DynamoDbIdempotencyStore
from notify_router.core import Config, Deps, Notification, build_notification, check_status, handle
from notify_router.sinks import (
    EVENT_ID_HEADER,
    SIGNATURE_HEADER,
    SlackSink,
    WebhookSink,
    build_sinks,
    sign,
    slack_payload,
    verify,
)

SLACK_URL = "https://hooks.slack.com/services/T0000/B0000/s3cr3tPathToken"
HMAC_SECRET = "whsec_test_0123456789"
LOG = get_logger("test-notify")


def failed_event(**kw: Any) -> dict:
    ev = make_event("failed", **kw)
    ev["data"]["certificate"] = None
    ev["data"]["renewal"]["fingerprint_sha256"] = None
    ev["data"]["renewal"]["not_after"] = None
    ev["data"]["private_key_ref"] = None
    return ev


@dataclass
class FakeHttp:
    statuses: list[int] = field(default_factory=list)
    requests: list[tuple[str, bytes, dict]] = field(default_factory=list)

    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> int:
        self.requests.append((url, body, dict(headers)))
        return self.statuses.pop(0) if self.statuses else 200


@dataclass
class RecordingSink:
    name: str
    errors: list[Exception] = field(default_factory=list)
    sent: list[Notification] = field(default_factory=list)

    def send(self, notification: Notification) -> None:
        if self.errors:
            raise self.errors.pop(0)
        self.sent.append(notification)


@pytest.fixture
def sleep() -> NoSleep:
    return NoSleep()


@pytest.fixture
def config(sleep: NoSleep) -> Config:
    return Config(dashboard_url="https://farrier.example.com/", retry=RetryPolicy(attempts=3, sleep=sleep))


def run(ev: dict, deps: Deps, config: Config) -> dict:
    return handle(eventbridge(ev), deps, config, LOG)


# --------------------------------------------------------------------------- HMAC


def test_hmac_signature_known_answer() -> None:
    # Expected value computed independently:
    #   printf '%s' '1700000000.{"id":"evt-1","type":"dev.farrier.renewal.failed"}' \
    #     | openssl dgst -sha256 -hmac 'whsec_test_0123456789'
    body = b'{"id":"evt-1","type":"dev.farrier.renewal.failed"}'
    assert sign(HMAC_SECRET.encode(), 1700000000, body) == (
        "t=1700000000,v1=b701d6af57e051c39ea8ca74c217de8fd19aae6e32c7aedf16fbabdca0496542"
    )


def test_verify_accepts_valid_and_rejects_tampered_or_old() -> None:
    body = b'{"a":1}'
    header = sign(b"k", 1000, body)
    assert verify(b"k", header, body, now=1100)
    assert not verify(b"k", header, b'{"a":2}', now=1100)
    assert not verify(b"other", header, body, now=1100)
    assert not verify(b"k", header, body, now=1000 + 301)
    assert not verify(b"k", "garbage", body, now=1000)


def test_webhook_sink_sends_signed_cloudevent() -> None:
    http = FakeHttp()
    sink = WebhookSink("https://hooks.example.com/farrier", lambda: HMAC_SECRET, http, clock=lambda: 1700000000.9)
    ev = failed_event()
    n = build_notification(parse_event(ev), ev, None)
    sink.send(n)
    url, body, headers = http.requests[0]
    assert url == "https://hooks.example.com/farrier"
    assert json.loads(body) == ev
    assert headers["Content-Type"] == "application/cloudevents+json"
    assert headers[EVENT_ID_HEADER] == ev["id"]
    assert verify(HMAC_SECRET.encode(), headers[SIGNATURE_HEADER], body, now=1700000000)


def test_webhook_requires_https() -> None:
    with pytest.raises(PermanentError):
        WebhookSink("http://hooks.example.com", lambda: "k", FakeHttp())


# --------------------------------------------------------------------------- Slack


def test_slack_payload_escapes_and_links() -> None:
    ev = failed_event(endpoint_name="<script>&")
    n = build_notification(parse_event(ev), ev, "https://farrier.example.com/")
    payload = slack_payload(n)
    mrkdwn = json.dumps(payload["blocks"][2]) + payload["text"]  # plain_text blocks render literally
    assert "<script>" not in mrkdwn and "&lt;script&gt;&amp;" in mrkdwn
    assert payload["blocks"][-1]["elements"][0]["url"] == "https://farrier.example.com/dashboard/renewals"


def test_slack_sink_reads_url_lazily_and_classifies_status() -> None:
    http = FakeHttp(statuses=[200, 503, 404])
    reads = []
    sink = SlackSink(lambda: reads.append(1) or SLACK_URL, http)
    ev = failed_event()
    n = build_notification(parse_event(ev), ev, None)
    sink.send(n)
    with pytest.raises(TransientError):
        sink.send(n)
    with pytest.raises(PermanentError):
        sink.send(n)
    assert http.requests[0][0] == SLACK_URL and len(reads) == 3


@pytest.mark.parametrize(
    ("status", "error"),
    [
        (200, None),
        (204, None),
        (429, TransientError),
        (502, TransientError),
        (408, TransientError),
        (400, PermanentError),
        (403, PermanentError),
    ],
)
def test_check_status(status: int, error: type[Exception] | None) -> None:
    if error is None:
        check_status(status, "s")
    else:
        with pytest.raises(error):
            check_status(status, "s")


# --------------------------------------------------------------------------- routing and idempotency


def test_only_attention_states_are_routed(config: Config) -> None:
    sink = RecordingSink("rec")
    deps = Deps(sinks=[sink], store=InMemoryIdempotencyStore())
    assert run(make_event("done"), deps, config)["action"] == "skipped"
    for state in ("failed", "rolled_back", "awaiting_manual"):
        ev = failed_event(event_id=f"id-{state}")
        ev["type"] = f"dev.farrier.renewal.{state}"
        ev["data"]["renewal"]["state"] = state
        assert run(ev, deps, config)["action"] == "notified"
    assert [n.severity for n in sink.sent] == ["critical", "high", "warning"]


def test_same_event_twice_notifies_once(config: Config) -> None:
    sink = RecordingSink("rec")
    deps = Deps(sinks=[sink], store=InMemoryIdempotencyStore())
    ev = failed_event()
    assert run(ev, deps, config)["sent"] == ["rec"]
    assert run(ev, deps, config) == {"action": "notified", "sent": [], "duplicate": ["rec"]}
    assert len(sink.sent) == 1


def test_partial_failure_raises_and_retry_only_hits_failed_sink(config: Config, sleep: NoSleep) -> None:
    ok = RecordingSink("ok")
    flaky = RecordingSink("flaky", errors=[TransientError("503")] * 3)
    deps = Deps(sinks=[ok, flaky], store=InMemoryIdempotencyStore())
    ev = failed_event()
    with pytest.raises(TransientError):
        run(ev, deps, config)
    assert len(ok.sent) == 1 and len(sleep.calls) == 2  # in-process retries happened
    out = run(ev, deps, config)  # platform redelivery
    assert out["sent"] == ["flaky"] and out["duplicate"] == ["ok"]
    assert len(ok.sent) == 1 and len(flaky.sent) == 1


def test_only_permanent_failures_raise_permanent_for_dlq(config: Config) -> None:
    deps = Deps(sinks=[RecordingSink("bad", errors=[PermanentError("403")])], store=InMemoryIdempotencyStore())
    with pytest.raises(PermanentError):
        run(failed_event(), deps, config)


def test_build_sinks_registry() -> None:
    class Runtime:
        http = FakeHttp()

        def secret(self, arn: str):
            return lambda: "value"

    env = {
        "NOTIFY_SINKS": "slack, webhook,slack",
        "SLACK_WEBHOOK_SECRET_ARN": "arn:s",
        "WEBHOOK_URL": "https://x.example",
        "WEBHOOK_SECRET_ARN": "arn:h",
    }
    assert [s.name for s in build_sinks(env, Runtime())] == ["slack", "webhook"]
    with pytest.raises(PermanentError, match="unknown"):
        build_sinks({"NOTIFY_SINKS": "pager"}, Runtime())
    with pytest.raises(PermanentError, match="WEBHOOK_URL"):
        build_sinks({"NOTIFY_SINKS": "webhook"}, Runtime())


def test_no_secrets_in_logs(config: Config, capsys) -> None:
    http = FakeHttp(statuses=[500, 500, 500])
    deps = Deps(
        sinks=[SlackSink(lambda: SLACK_URL, http), WebhookSink("https://h.example", lambda: HMAC_SECRET, FakeHttp())],
        store=InMemoryIdempotencyStore(),
    )
    with pytest.raises(TransientError):
        run(failed_event(), deps, config)
    out = capsys.readouterr().out
    assert "sink failed" in out
    assert_no_secrets(out, SLACK_URL, "s3cr3tPathToken", HMAC_SECRET)


# --------------------------------------------------------------------------- DynamoDB store against a stub client


class ConditionalCheckFailed(Exception):
    response = {"Error": {"Code": "ConditionalCheckFailedException"}, "ResponseMetadata": {"HTTPStatusCode": 400}}


class StubDynamo:
    def __init__(self) -> None:
        self.items: dict[str, dict] = {}

    def put_item(self, **kw: Any) -> None:
        key = kw["Item"]["pk"]["S"]
        now = int(kw["ExpressionAttributeValues"][":now"]["N"])
        cur = self.items.get(key)
        if cur and not (cur["status"]["S"] == "inflight" and int(cur["lease_until"]["N"]) < now):
            raise ConditionalCheckFailed()
        self.items[key] = kw["Item"]

    def update_item(self, **kw: Any) -> None:
        self.items[kw["Key"]["pk"]["S"]]["status"] = {"S": "done"}

    def delete_item(self, **kw: Any) -> None:
        key = kw["Key"]["pk"]["S"]
        if self.items.get(key, {}).get("status", {}).get("S") != "inflight":
            raise ConditionalCheckFailed()
        del self.items[key]


def test_dynamodb_store_lease_semantics() -> None:
    now = [1000.0]
    store = DynamoDbIdempotencyStore(StubDynamo(), "t", clock=lambda: now[0])
    assert store.claim("k", lease_seconds=60)
    assert not store.claim("k", lease_seconds=60)
    now[0] += 61
    assert store.claim("k", lease_seconds=60)
    store.complete("k")
    store.release("k")  # conditional delete on a completed key is ignored
    now[0] += 10_000
    assert not store.claim("k", lease_seconds=60)
