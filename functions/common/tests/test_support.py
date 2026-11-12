"""Retry, idempotency, logging, PEM helpers and transports."""

from __future__ import annotations

import base64
import json

import pytest
from farrier_events import (
    InMemoryIdempotencyStore,
    InvalidEvent,
    PermanentError,
    RetryPolicy,
    TransientError,
    backoff_delays,
    get_logger,
    redact,
    retry,
    run_once,
)
from farrier_events.pem import fingerprint_sha256, leaf_and_chain, split_certificates, verify_leaf
from farrier_events.transports import from_eventbridge, from_eventgrid, from_pubsub
from farrier_testkit import NoSleep, assert_no_secrets, eventbridge, make_event, material

# --------------------------------------------------------------------------- retry


def test_backoff_is_capped_full_jitter() -> None:
    assert backoff_delays(5, 0.5, 2.0, lambda: 1.0) == [0.5, 1.0, 2.0, 2.0]
    assert backoff_delays(3, 0.5, 2.0, lambda: 0.0) == [0.0, 0.0]
    assert backoff_delays(1, 0.5, 2.0, lambda: 1.0) == []


def test_retry_recovers_from_transient_errors() -> None:
    calls, sleep = [], NoSleep()

    @retry(attempts=4, base_delay=1.0, max_delay=8.0, sleep=sleep, rng=lambda: 1.0)
    def flaky() -> str:
        calls.append(1)
        if len(calls) < 3:
            raise TransientError("throttled")
        return "ok"

    assert flaky() == "ok"
    assert len(calls) == 3
    assert sleep.calls == [1.0, 2.0]


def test_retry_gives_up_after_attempts_and_reraises() -> None:
    sleep = NoSleep()
    policy = RetryPolicy(attempts=3, sleep=sleep)
    with pytest.raises(TransientError):
        policy.run(lambda: (_ for _ in ()).throw(TransientError("down")))
    assert len(sleep.calls) == 2


def test_retry_does_not_retry_permanent_errors() -> None:
    calls, sleep = [], NoSleep()

    def broken() -> None:
        calls.append(1)
        raise PermanentError("bad input")

    with pytest.raises(PermanentError):
        RetryPolicy(sleep=sleep).run(broken)
    assert calls == [1] and sleep.calls == []


def test_retry_rejects_zero_attempts() -> None:
    with pytest.raises(ValueError):
        retry(attempts=0)


# --------------------------------------------------------------------------- idempotency


def test_run_once_skips_duplicates() -> None:
    store, calls = InMemoryIdempotencyStore(), []
    assert run_once(store, "evt-1", lambda: calls.append(1) or "a") == (True, "a")
    assert run_once(store, "evt-1", lambda: calls.append(1) or "b") == (False, None)
    assert calls == [1]


def test_run_once_releases_on_failure_so_retry_can_run() -> None:
    store = InMemoryIdempotencyStore()

    def fail() -> None:
        raise TransientError("x")

    with pytest.raises(TransientError):
        run_once(store, "evt-2", fail)
    assert run_once(store, "evt-2", lambda: "ok") == (True, "ok")


def test_expired_lease_can_be_reclaimed_but_live_one_cannot() -> None:
    now = [0.0]
    store = InMemoryIdempotencyStore(clock=lambda: now[0])
    assert store.claim("k", lease_seconds=60)
    assert not store.claim("k", lease_seconds=60)  # another attempt in flight
    now[0] = 61.0
    assert store.claim("k", lease_seconds=60)  # previous attempt crashed
    store.complete("k")
    now[0] = 10_000.0
    assert not store.claim("k", lease_seconds=60)
    store.release("k")  # releasing a completed key is a no-op
    assert not store.claim("k", lease_seconds=60)


# --------------------------------------------------------------------------- logging


def test_logger_emits_one_json_object_per_line(capsys: pytest.CaptureFixture[str]) -> None:
    log = get_logger("test-json").bind(event_id="e1")
    log.info("hello", endpoint_id=12)
    line = capsys.readouterr().out.strip()
    entry = json.loads(line)
    assert entry["msg"] == "hello" and entry["event_id"] == "e1" and entry["endpoint_id"] == 12
    assert entry["level"] == "info" and entry["ts"].endswith("Z")


def test_logger_redacts_pem_secret_fields_and_webhook_urls(capsys: pytest.CaptureFixture[str]) -> None:
    m = material()
    log = get_logger("test-redact")
    log.info(
        "careless " + m.key_pem,
        chain=m.fullchain,
        private_key=m.key_pem,
        webhook_url="https://hooks.slack.com/services/T000/B000/XXXX",
        note="see https://hooks.slack.com/services/T111/B111/YYYY",
        nested={"password": "hunter2", "items": [m.leaf_pem]},
        private_key_ref="aws-sm:arn:aws:secretsmanager:eu-west-1:123456789012:secret:farrier/keys/1",
    )
    try:
        raise PermanentError("boom " + m.key_pem)
    except PermanentError:
        log.error("with exception", exc_info=True)
    out = capsys.readouterr().out
    assert_no_secrets(out, m.key_pem, m.leaf_pem, "hunter2", "XXXX", "YYYY")
    assert "farrier/keys/1" in out  # references are not secrets


def test_redact_is_pure_and_handles_bytes() -> None:
    value = {"pfx": b"\x30\x82", "ok": 1, "token": "t"}
    assert redact(value) == {"pfx": "[REDACTED]", "ok": 1, "token": "[REDACTED]"}
    assert value["token"] == "t"
    assert redact(b"abc") == "<3 bytes>"


# --------------------------------------------------------------------------- PEM


def test_split_and_fingerprint_chain() -> None:
    m = material()
    certs = split_certificates(m.fullchain)
    assert len(certs) == 2
    assert fingerprint_sha256(certs[0]) == m.fingerprint
    leaf, chain = verify_leaf(m.fullchain, m.fingerprint)
    assert fingerprint_sha256(leaf) == m.fingerprint and "BEGIN CERTIFICATE" in chain


def test_verify_leaf_rejects_mismatch() -> None:
    m = material()
    with pytest.raises(PermanentError, match="fingerprint"):
        verify_leaf(m.fullchain, "0" * 64)


def test_chain_containing_a_key_is_refused() -> None:
    m = material()
    with pytest.raises(PermanentError, match="private key"):
        leaf_and_chain(m.fullchain + m.key_pem)
    with pytest.raises(PermanentError, match="no PEM"):
        leaf_and_chain("hello")


# --------------------------------------------------------------------------- transports


def test_eventbridge_unwrap() -> None:
    ev = make_event()
    assert from_eventbridge(eventbridge(ev)) is ev
    bad = eventbridge(ev) | {"source": "someone-else"}
    with pytest.raises(InvalidEvent):
        from_eventbridge(bad)
    with pytest.raises(InvalidEvent):
        from_eventbridge(eventbridge(ev) | {"detail-type": "dev.farrier.renewal.failed"})


def test_pubsub_unwrap_checks_attributes() -> None:
    ev = make_event()
    data = base64.b64encode(json.dumps(ev).encode()).decode()
    assert from_pubsub({"data": data, "attributes": {"ce-type": ev["type"], "ce-id": ev["id"]}}) == ev
    with pytest.raises(InvalidEvent):
        from_pubsub({"data": data, "attributes": {"ce-id": "other"}})
    with pytest.raises(InvalidEvent):
        from_pubsub({"data": "!!!"})


def test_eventgrid_rebuilds_envelope() -> None:
    ev = make_event()
    rebuilt = from_eventgrid(
        id=ev["id"], type=ev["type"], subject=ev["subject"], time=ev["time"], source=ev["source"], data=ev["data"]
    )
    assert rebuilt == ev
