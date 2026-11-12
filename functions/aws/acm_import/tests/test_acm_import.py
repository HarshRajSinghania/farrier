from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import pytest
from acm_import.adapters import AcmAdapter, S3ChainStore
from acm_import.core import (
    TAG_FINGERPRINT,
    TAG_RENEWAL_ID,
    Config,
    Deps,
    handle,
    resolve_target,
)
from farrier_aws import SecretsManagerStore, translate
from farrier_events import (
    AwsSecretRef,
    InvalidEvent,
    PermanentError,
    RetryPolicy,
    S3ObjectRef,
    TransientError,
    get_logger,
    parse_event,
)
from farrier_testkit import NoSleep, assert_no_secrets, eventbridge, make_event, material

ARN = "arn:aws:acm:eu-west-1:123456789012:certificate/0f0e0d0c-1111-2222-3333-444455556666"
OTHER_REGION_ARN = "arn:aws:acm:us-east-1:123456789012:certificate/0f0e0d0c-1111-2222-3333-444455556666"


# --------------------------------------------------------------------------- fakes


@dataclass
class FakeChains:
    text: str
    calls: int = 0
    failures: list[Exception] = field(default_factory=list)

    def get_text(self, ref: S3ObjectRef) -> str:
        self.calls += 1
        if self.failures:
            raise self.failures.pop(0)
        assert ref == S3ObjectRef("farrier-certs", "prod/2041/fullchain.pem")
        return self.text


@dataclass
class FakeSecrets:
    value: str
    calls: int = 0

    def get_secret(self, ref: AwsSecretRef) -> str:
        self.calls += 1
        assert ref.arn.endswith("secret:farrier/keys/2041-AbCdEf")
        return self.value


@dataclass
class FakeAcm:
    certs: dict[str, dict[str, Any]] = field(default_factory=dict)  # arn -> {"tags":..., "material":...}
    imports: list[dict[str, Any]] = field(default_factory=list)
    fail_add_tags: int = 0
    next_id: int = 1

    def find_by_endpoint(self, endpoint_id: int) -> str | None:
        for arn, c in self.certs.items():
            if c["tags"].get("farrier:endpoint-id") == str(endpoint_id):
                return arn
        return None

    def get_tags(self, arn: str) -> dict[str, str]:
        if arn not in self.certs:
            raise PermanentError("acm:ListTagsForCertificate failed: ResourceNotFoundException (HTTP 400)")
        return dict(self.certs[arn]["tags"])

    def import_certificate(
        self, *, certificate: str, private_key: str, chain: str, arn: str | None, tags: Mapping[str, str] | None
    ) -> str:
        self.imports.append({"arn": arn, "tags": tags, "certificate": certificate, "chain": chain})
        if arn is None:
            arn = f"arn:aws:acm:eu-west-1:123456789012:certificate/00000000-0000-0000-0000-{self.next_id:012d}"
            self.next_id += 1
            self.certs[arn] = {"tags": dict(tags or {})}
        else:
            assert tags is None, "ACM rejects tags on re-import"
        self.certs[arn]["material"] = certificate
        return arn

    def add_tags(self, arn: str, tags: Mapping[str, str]) -> None:
        if self.fail_add_tags:
            self.fail_add_tags -= 1
            raise TransientError("acm:AddTagsToCertificate failed: ThrottlingException (HTTP 400)")
        self.certs[arn]["tags"].update(tags)


@pytest.fixture
def m():
    return material()


@pytest.fixture
def deps(m) -> Deps:
    return Deps(chains=FakeChains(m.fullchain), secrets=FakeSecrets(m.key_pem), acm=FakeAcm())


@pytest.fixture
def sleep() -> NoSleep:
    return NoSleep()


@pytest.fixture
def config(sleep: NoSleep) -> Config:
    return Config(region="eu-west-1", retry=RetryPolicy(attempts=3, sleep=sleep))


LOG = get_logger("test-acm")


def run(ev: dict, deps: Deps, config: Config) -> dict:
    return handle(eventbridge(ev), deps, config, LOG)


# --------------------------------------------------------------------------- selection


def test_target_resolution(config: Config) -> None:
    def target(**kw: Any):
        return resolve_target(parse_event(make_event(**kw)), config)

    assert target(tags=["prod"]) is None
    assert target(tags=["acm:new"]).arn is None
    assert target(tags=[f"acm:{ARN}"]).arn == ARN
    pattern = Config(region="eu-west-1", name_pattern="www-*")
    assert resolve_target(parse_event(make_event(tags=[])), pattern).arn is None
    for bad in (["acm:new", f"acm:{ARN}"], ["acm:not-an-arn"], [f"acm:{OTHER_REGION_ARN}"]):
        with pytest.raises(PermanentError):
            target(tags=bad)


def test_non_done_and_unselected_events_are_skipped(deps: Deps, config: Config, m) -> None:
    ev = make_event("deploying", tags=["acm:new"], fingerprint=m.fingerprint)
    assert run(ev, deps, config)["reason"] == "state-not-done"
    assert run(make_event(tags=["prod"], fingerprint=m.fingerprint), deps, config)["reason"] == "not-selected"
    assert deps.acm.imports == [] and deps.secrets.calls == 0


# --------------------------------------------------------------------------- import paths


def test_new_import_tags_certificate_in_the_same_call(deps: Deps, config: Config, m) -> None:
    out = run(make_event(tags=["acm:new"], fingerprint=m.fingerprint), deps, config)
    assert out["action"] == "imported"
    imp = deps.acm.imports[0]
    assert imp["arn"] is None
    assert imp["tags"][TAG_FINGERPRINT] == m.fingerprint
    assert imp["tags"]["farrier:endpoint-id"] == "12" and imp["tags"][TAG_RENEWAL_ID] == "2041"
    assert imp["certificate"].count("BEGIN CERTIFICATE") == 1  # leaf only
    assert imp["chain"].count("BEGIN CERTIFICATE") == 1  # intermediates separately


def test_reimport_into_tagged_arn_rotates_in_place(deps: Deps, config: Config, m) -> None:
    deps.acm.certs[ARN] = {"tags": {TAG_FINGERPRINT: "a" * 64, TAG_RENEWAL_ID: "2000"}}
    out = run(make_event(tags=[f"acm:{ARN}"], fingerprint=m.fingerprint), deps, config)
    assert out == {"action": "reimported", "reason": None, "certificate_arn": ARN}
    assert deps.acm.imports[0]["arn"] == ARN and deps.acm.imports[0]["tags"] is None
    assert deps.acm.certs[ARN]["tags"][TAG_FINGERPRINT] == m.fingerprint


def test_second_renewal_with_acm_new_reuses_arn(m) -> None:
    acm = FakeAcm()
    acm.certs[ARN] = {
        "tags": {
            "farrier:managed": "true",
            "farrier:endpoint-id": "12",
            TAG_RENEWAL_ID: "2000",
            TAG_FINGERPRINT: "c" * 64,
        }
    }
    deps = Deps(chains=FakeChains(m.fullchain), secrets=FakeSecrets(m.key_pem), acm=acm)
    out = run(make_event(tags=["acm:new"], fingerprint=m.fingerprint), deps, Config(region="eu-west-1"))
    assert out["action"] == "reimported" and out["certificate_arn"] == ARN
    assert len(acm.certs) == 1


# --------------------------------------------------------------------------- idempotency


def test_same_event_twice_imports_once(deps: Deps, config: Config, m) -> None:
    ev = make_event(tags=["acm:new"], fingerprint=m.fingerprint)
    assert run(ev, deps, config)["action"] == "imported"
    second = run(ev, deps, config)
    assert second["action"] == "skipped" and second["reason"] == "already-current"
    assert len(deps.acm.imports) == 1
    assert deps.secrets.calls == 1  # the duplicate never touched the key


def test_stale_event_is_skipped(deps: Deps, config: Config, m) -> None:
    deps.acm.certs[ARN] = {"tags": {TAG_FINGERPRINT: "d" * 64, TAG_RENEWAL_ID: "3000"}}
    out = run(make_event(tags=[f"acm:{ARN}"], fingerprint=m.fingerprint), deps, config)
    assert out["reason"] == "stale-event" and deps.acm.imports == []


def test_crash_between_reimport_and_tagging_recovers_on_redelivery(deps: Deps, m, sleep: NoSleep) -> None:
    deps.acm.certs[ARN] = {"tags": {TAG_FINGERPRINT: "e" * 64}}
    deps.acm.fail_add_tags = 1
    ev = make_event(tags=[f"acm:{ARN}"], fingerprint=m.fingerprint)
    with pytest.raises(TransientError):
        run(ev, deps, Config(region="eu-west-1", retry=RetryPolicy(attempts=1, sleep=sleep)))
    assert (
        run(ev, deps, Config(region="eu-west-1", retry=RetryPolicy(attempts=1, sleep=sleep)))["action"] == "reimported"
    )
    assert run(ev, deps, Config(region="eu-west-1"))["reason"] == "already-current"
    assert len(deps.acm.imports) == 2  # harmless repeat of identical material, then stable


# --------------------------------------------------------------------------- retries and DLQ-bound errors


def test_transient_errors_are_retried_in_process(deps: Deps, config: Config, m, sleep: NoSleep) -> None:
    deps.chains.failures = [TransientError("s3:GetObject failed: SlowDown (HTTP 503)")] * 2
    assert run(make_event(tags=["acm:new"], fingerprint=m.fingerprint), deps, config)["action"] == "imported"
    assert deps.chains.calls == 3 and len(sleep.calls) == 2


def test_exhausted_transient_errors_raise_for_platform_retry(deps: Deps, config: Config, m) -> None:
    deps.chains.failures = [TransientError("down")] * 5
    with pytest.raises(TransientError):
        run(make_event(tags=["acm:new"], fingerprint=m.fingerprint), deps, config)
    assert deps.acm.imports == []


@pytest.mark.parametrize(
    "event",
    [
        make_event(tags=["acm:new"], private_key_ref=None),
        make_event(tags=["acm:new"], chain_ref=None),
        make_event(tags=["acm:new"], chain_ref="gs://bucket/x.pem"),
        make_event(tags=["acm:new"], private_key_ref="gcp-sm:projects/p/secrets/s/versions/1"),
        make_event(tags=["acm:new"], fingerprint="f" * 64),  # chain leaf does not match the event
    ],
    ids=["no-key-ref", "no-chain-ref", "wrong-chain-cloud", "wrong-key-cloud", "fingerprint-mismatch"],
)
def test_poison_events_raise_permanent_errors(deps: Deps, config: Config, event: dict) -> None:
    with pytest.raises(PermanentError):
        run(event, deps, config)
    assert deps.acm.imports == []


def test_malformed_event_raises_invalid_event(deps: Deps, config: Config) -> None:
    ev = make_event()
    ev["data"]["schema_version"] = 99
    with pytest.raises(InvalidEvent):
        run(ev, deps, config)


def test_disallowed_prefix_is_refused(deps: Deps, m, sleep: NoSleep) -> None:
    cfg = Config(region="eu-west-1", allowed_prefixes=("s3://other/",), retry=RetryPolicy(sleep=sleep))
    with pytest.raises(PermanentError):
        run(make_event(tags=["acm:new"], fingerprint=m.fingerprint), deps, cfg)


# --------------------------------------------------------------------------- no secrets in logs


def test_no_pem_or_key_in_logs_on_success_or_failure(deps: Deps, config: Config, m, capsys) -> None:
    run(make_event(tags=["acm:new"], fingerprint=m.fingerprint), deps, config)
    deps.acm.fail_add_tags = 10
    deps.acm.certs[ARN] = {"tags": {}}
    with pytest.raises(TransientError):
        run(make_event(tags=[f"acm:{ARN}"], fingerprint=m.fingerprint), deps, config)
    out = capsys.readouterr().out
    assert '"msg":"acm import imported"' in out and "will be retried" in out
    assert_no_secrets(out, m.key_pem, m.leaf_pem, m.intermediate_pem)


# --------------------------------------------------------------------------- adapters against stub clients


class ClientError(Exception):
    def __init__(self, code: str, status: int) -> None:
        super().__init__(f"An error occurred ({code}) with secret value hunter2")
        self.response = {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}}


class EndpointConnectionError(Exception):
    pass


def test_error_translation_drops_messages_and_classifies() -> None:
    assert isinstance(translate(ClientError("ThrottlingException", 400), "op"), TransientError)
    assert isinstance(translate(ClientError("InternalFailure", 500), "op"), TransientError)
    assert isinstance(translate(ClientError("AccessDeniedException", 400), "op"), PermanentError)
    assert isinstance(translate(EndpointConnectionError(), "op"), TransientError)
    assert isinstance(translate(ValueError("x"), "op"), PermanentError)
    assert "hunter2" not in str(translate(ClientError("ValidationException", 400), "op"))


class StubAcmClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def import_certificate(self, **kw: Any) -> dict:
        self.calls.append(("import_certificate", kw))
        return {"CertificateArn": kw.get("CertificateArn", ARN)}

    def list_tags_for_certificate(self, **kw: Any) -> dict:
        return {"Tags": [{"Key": "farrier:managed", "Value": "true"}, {"Key": "farrier:endpoint-id", "Value": "12"}]}

    def get_paginator(self, name: str) -> Any:
        assert name == "list_certificates"

        class P:
            def paginate(self, **kw: Any):
                assert "EC_prime256v1" in kw["Includes"]["keyTypes"]  # ACM lists only RSA_2048 by default
                yield {
                    "CertificateSummaryList": [
                        {"CertificateArn": "x", "Type": "AMAZON_ISSUED"},
                        {"CertificateArn": ARN, "Type": "IMPORTED"},
                    ]
                }

        return P()

    def add_tags_to_certificate(self, **kw: Any) -> None:
        self.calls.append(("add_tags_to_certificate", kw))


def test_acm_adapter_shapes_requests() -> None:
    client = StubAcmClient()
    acm = AcmAdapter(client)
    assert acm.find_by_endpoint(12) == ARN
    acm.import_certificate(certificate="L", private_key="K", chain="", arn=None, tags={"a": "b"})
    acm.import_certificate(certificate="L", private_key="K", chain="C", arn=ARN, tags={"a": "b"})
    new, re = client.calls[0][1], client.calls[1][1]
    assert new["Tags"] == [{"Key": "a", "Value": "b"}] and "CertificateChain" not in new
    assert "Tags" not in re and re["CertificateArn"] == ARN and re["CertificateChain"] == b"C"


def test_s3_and_secrets_adapters() -> None:
    class Body:
        def read(self, n: int) -> bytes:
            return b"-----BEGIN CERTIFICATE-----"

    class S3:
        def get_object(self, **kw: Any) -> dict:
            return {"ContentLength": 27, "Body": Body()}

    class SM:
        def get_secret_value(self, **kw: Any) -> dict:
            if kw["SecretId"] == "boom":
                raise ClientError("ThrottlingException", 400)
            return {"SecretBinary": b"KEY"}

    assert S3ChainStore(S3()).get_text(S3ObjectRef("b", "k")).startswith("-----BEGIN")
    assert SecretsManagerStore(SM()).get_secret("arn") == "KEY"
    with pytest.raises(TransientError):
        SecretsManagerStore(SM()).get_secret("boom")
