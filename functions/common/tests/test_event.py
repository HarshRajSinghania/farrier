from __future__ import annotations

import copy
import json

import pytest
from farrier_events import STATES, InvalidEvent, PermanentError, event_type, parse_event, validate
from farrier_testkit import SCHEMA_PATH, example, make_event

SCHEMA = json.loads(SCHEMA_PATH.read_text())


# --------------------------------------------------------------------------- good events


@pytest.mark.parametrize("name", ["renewal-done.json", "renewal-failed.json"])
def test_examples_are_valid(name: str) -> None:
    assert validate(example(name)) == []


def test_parse_done_event_into_typed_model() -> None:
    ev = parse_event(example("renewal-done.json"))
    assert ev.state == "done"
    assert ev.endpoint.id == 12 and ev.endpoint.port == 443
    assert ev.endpoint.tags == ("prod", "acm:new")
    assert ev.endpoint.tag_values("acm") == ["new"]
    assert ev.renewal.not_after is not None and ev.renewal.not_after.tzinfo is not None
    assert ev.certificate is not None and ev.certificate.names == ("www.example.com",)
    assert ev.private_key_ref is not None and ev.private_key_ref.startswith("aws-sm:")


def test_parse_accepts_json_text_and_bytes() -> None:
    raw = json.dumps(example("renewal-failed.json"))
    assert parse_event(raw).state == "failed"
    assert parse_event(raw.encode()).certificate is None


def test_unknown_fields_are_ignored_for_forward_compatibility() -> None:
    ev = example("renewal-done.json")
    ev["data"]["new_optional_thing"] = {"x": 1}
    ev["data"]["endpoint"]["site"] = "dc1"
    ev["traceparent"] = "00-abc-def-01"
    assert validate(ev) == []


def test_nanosecond_timestamps_parse() -> None:
    ev = example("renewal-done.json")
    ev["time"] = "2026-11-12T09:30:00.123456789+02:00"
    assert parse_event(ev).time.microsecond == 123456


@pytest.mark.parametrize("state", STATES)
def test_every_state_round_trips(state: str) -> None:
    ev = make_event(state)
    if state not in ("issued", "deploying", "verifying", "done"):
        ev["data"]["certificate"] = None
        ev["data"]["renewal"]["fingerprint_sha256"] = None
        ev["data"]["renewal"]["not_after"] = None
    assert parse_event(ev).type == event_type(state)


# --------------------------------------------------------------------------- bad events


def _mutate(path: list[str | int], value: object = ..., delete: bool = False) -> dict:
    ev = copy.deepcopy(example("renewal-done.json"))
    target = ev
    for p in path[:-1]:
        target = target[p]
    if delete:
        del target[path[-1]]
    else:
        target[path[-1]] = value
    return ev


BAD = [
    (_mutate(["specversion"], "0.3"), "$.specversion"),
    (_mutate(["id"], ""), "$.id"),
    (_mutate(["source"], "https://example.com"), "$.source"),
    (_mutate(["type"], "dev.farrier.renewal.exploded"), "$.type"),
    (_mutate(["type"], "dev.farrier.renewal.failed"), "$.type: does not match"),
    (_mutate(["time"], "12/11/2026"), "$.time"),
    (_mutate(["time"], "2026-13-40T99:00:00Z"), "$.time: is not a real"),
    (_mutate(["datacontenttype"], "text/plain"), "$.datacontenttype"),
    (_mutate(["data"], delete=True), "$.data: is required"),
    (_mutate(["data", "schema_version"], 2), "$.data.schema_version: unsupported"),
    (_mutate(["data", "schema_version"], True), "$.data.schema_version: must be an integer"),
    (_mutate(["data", "endpoint", "port"], 70000), "$.data.endpoint.port"),
    (_mutate(["data", "endpoint", "id"], "12"), "$.data.endpoint.id"),
    (_mutate(["data", "endpoint", "tags"], "prod"), "$.data.endpoint.tags"),
    (_mutate(["data", "renewal", "fingerprint_sha256"], "ABC"), "$.data.renewal.fingerprint_sha256"),
    (_mutate(["data", "renewal", "fingerprint_sha256"], None), "$.data.renewal.fingerprint_sha256"),
    (_mutate(["data", "certificate"], None), "$.data.certificate: is required once"),
    (_mutate(["data", "certificate", "chain_ref"], "ftp://x/y"), "$.data.certificate.chain_ref"),
    (_mutate(["data", "private_key_ref"], "-----BEGIN PRIVATE KEY-----"), "$.data.private_key_ref"),
    (_mutate(["data", "private_key_ref"], delete=True), "$.data.private_key_ref: is required"),
]


@pytest.mark.parametrize(("event", "expected"), BAD, ids=[e for _, e in BAD])
def test_bad_events_are_rejected_with_a_path(event: dict, expected: str) -> None:
    problems = validate(event)
    assert any(p.startswith(expected) for p in problems), problems
    with pytest.raises(InvalidEvent) as info:
        parse_event(event)
    assert isinstance(info.value, PermanentError)


@pytest.mark.parametrize(
    "raw", [None, [], "not json", b"\xff\xfe", "x" * (256 * 1024 + 1)], ids=["none", "list", "text", "bytes", "huge"]
)
def test_non_objects_are_rejected(raw: object) -> None:
    with pytest.raises(InvalidEvent):
        parse_event(raw)  # type: ignore[arg-type]


def test_problems_never_echo_values() -> None:
    secret = "-----BEGIN PRIVATE KEY-----MIIEvQ"
    problems = validate(_mutate(["data", "private_key_ref"], secret))
    assert problems and all("BEGIN" not in p for p in problems)


# --------------------------------------------------------------------------- schema file stays in step


def test_schema_states_match_code() -> None:
    assert tuple(SCHEMA["$defs"]["state"]["enum"]) == STATES
    assert SCHEMA["properties"]["type"]["enum"] == [event_type(s) for s in STATES]


def test_schema_required_fields_match_code() -> None:
    assert SCHEMA["required"] == ["specversion", "id", "source", "type", "time", "subject", "datacontenttype", "data"]
    defs = SCHEMA["$defs"]
    assert defs["data"]["required"] == ["schema_version", "endpoint", "renewal", "certificate", "private_key_ref"]
    assert defs["endpoint"]["required"] == ["id", "name", "host", "port", "connector", "tags"]
    assert defs["renewal"]["required"] == ["id", "state", "reason", "not_after", "fingerprint_sha256"]
    assert defs["certificate"]["required"] == ["names", "issuer", "chain_ref"]
    assert SCHEMA["$schema"] == "https://json-schema.org/draft/2020-12/schema"


def test_schema_agrees_with_validator_when_jsonschema_is_installed() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    validator = jsonschema.Draft202012Validator(SCHEMA)
    for name in ("renewal-done.json", "renewal-failed.json"):
        assert not list(validator.iter_errors(example(name)))
    for event, _ in BAD:
        if (
            event.get("data", {}).get("schema_version") is True
            or "time" in event
            and event["time"].startswith("2026-13")
        ):
            continue  # JSON Schema treats booleans as non-integers too, but cannot check calendar validity
        if event.get("type") == "dev.farrier.renewal.failed":
            continue  # cross-field rule only the code validator enforces
        assert list(validator.iter_errors(event)), event
