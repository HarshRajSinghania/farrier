from __future__ import annotations

import datetime as dt
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import pytest
from farrier_events import (
    AzureBlobRef,
    AzureKeyVaultSecretRef,
    PermanentError,
    RetryPolicy,
    TransientError,
    get_logger,
    parse_event,
)
from farrier_testkit import NoSleep, assert_no_secrets, make_event, material
from keyvault_import.adapters import classify_status
from keyvault_import.core import (
    TAG_RENEWAL_ID,
    Config,
    Deps,
    ExistingCertificate,
    build_pfx,
    certificate_name_for,
    envelope_from_binding,
    handle,
    resolve_target,
)

VAULT = "https://acme-kv.vault.azure.net"
KEY_REF = "azure-kv:https://acme-kv.vault.azure.net/secrets/farrier-key-2041"
CHAIN_REF = "azblob://acmecerts/farrier/2041/fullchain.pem"
LOG = get_logger("test-azure")


@dataclass
class FakeSecrets:
    value: str
    calls: int = 0

    def get_secret(self, ref: AzureKeyVaultSecretRef) -> str:
        self.calls += 1
        assert ref == AzureKeyVaultSecretRef(VAULT, "farrier-key-2041", None)
        return self.value


@dataclass
class FakeBlobs:
    text: str
    failures: list[Exception] = field(default_factory=list)

    def read_text(self, ref: AzureBlobRef) -> str:
        if self.failures:
            raise self.failures.pop(0)
        assert ref == AzureBlobRef("acmecerts", "farrier", "2041/fullchain.pem")
        return self.text


@dataclass
class FakeVault:
    certs: dict[tuple[str, str], ExistingCertificate] = field(default_factory=dict)
    imports: list[tuple[str, str, bytes, Mapping[str, str]]] = field(default_factory=list)

    def get(self, vault_url: str, name: str) -> ExistingCertificate | None:
        return self.certs.get((vault_url, name))

    def import_pfx(self, vault_url: str, name: str, pfx: bytes, tags: Mapping[str, str]) -> str:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import pkcs12

        bundle = pkcs12.load_pkcs12(pfx, None)
        assert bundle.key is not None and bundle.cert is not None
        der = bundle.cert.certificate.public_bytes(serialization.Encoding.DER)
        self.imports.append((vault_url, name, pfx, dict(tags)))
        self.certs[(vault_url, name)] = ExistingCertificate(der=der, tags=dict(tags))
        return f"{vault_url}/certificates/{name}/v{len(self.imports)}"


@pytest.fixture
def m():
    return material()


@pytest.fixture
def sleep() -> NoSleep:
    return NoSleep()


@pytest.fixture
def deps(m) -> Deps:
    return Deps(secrets=FakeSecrets(m.key_pem), chains=FakeBlobs(m.fullchain), vault=FakeVault())


def cfg(sleep: NoSleep, **kw: Any) -> Config:
    return Config(vault_url=VAULT, retry=RetryPolicy(attempts=3, sleep=sleep), **kw)


def az_event(m, **kw: Any) -> dict:
    return make_event(chain_ref=CHAIN_REF, private_key_ref=KEY_REF, fingerprint=m.fingerprint, **kw)


def binding(ev: dict) -> dict:
    """What function_app.py builds from func.EventGridEvent."""
    return envelope_from_binding(
        id=ev["id"],
        event_type=ev["type"],
        subject=ev["subject"],
        event_time=dt.datetime(2026, 11, 12, 9, 30),  # naive, as some bindings deliver
        topic=ev["source"],
        data=ev["data"],
    )


def test_binding_envelope_validates() -> None:
    env = binding(make_event())
    assert env["time"] == "2026-11-12T09:30:00Z"
    assert parse_event(env).id == make_event()["id"]
    other = envelope_from_binding(
        id="x",
        event_type="dev.farrier.renewal.done",
        subject="s",
        event_time="2026-11-12T09:30:00Z",
        topic="/subscriptions/1/resourceGroups/rg/providers/Microsoft.EventGrid/topics/farrier",
        data={},
    )
    assert other["source"] == "farrier://event-grid"


def test_target_resolution(sleep: NoSleep) -> None:
    c = cfg(sleep, name_pattern="www-*")
    t = resolve_target(parse_event(make_event(tags=["akv:www-cert"])), c)
    assert (t.vault_url, t.name) == (VAULT, "www-cert")
    t = resolve_target(parse_event(make_event(tags=["akv:other-kv/www-cert"])), c)
    assert t.vault_url == "https://other-kv.vault.azure.net"
    assert resolve_target(parse_event(make_event(tags=[])), c).name == "farrier-www-lb"
    with pytest.raises(PermanentError):
        resolve_target(parse_event(make_event(tags=["akv:bad name!"])), c)
    with pytest.raises(PermanentError):
        resolve_target(parse_event(make_event(tags=["akv:x"])), Config(vault_url=None))
    assert certificate_name_for("www.example lb") == "farrier-www-example-lb"


def test_import_builds_valid_pfx_and_tags(deps: Deps, m, sleep: NoSleep) -> None:
    out = handle(binding(az_event(m, tags=["akv:www-cert"])), deps, cfg(sleep), LOG)
    assert out["action"] == "imported" and out["certificate_id"].startswith(f"{VAULT}/certificates/www-cert/")
    _, _, pfx, tags = deps.vault.imports[0]
    assert tags["farrier-fingerprint-sha256"] == m.fingerprint and tags[TAG_RENEWAL_ID] == "2041"


def test_same_event_twice_imports_once_by_certificate_hash(deps: Deps, m, sleep: NoSleep) -> None:
    ev = binding(az_event(m, tags=["akv:www-cert"]))
    handle(ev, deps, cfg(sleep), LOG)
    second = handle(ev, deps, cfg(sleep), LOG)
    assert second["reason"] == "already-current"
    assert len(deps.vault.imports) == 1 and deps.secrets.calls == 1


def test_stale_event_skipped(deps: Deps, m, sleep: NoSleep) -> None:
    deps.vault.certs[(VAULT, "www-cert")] = ExistingCertificate(der=b"old", tags={TAG_RENEWAL_ID: "5000"})
    assert handle(binding(az_event(m, tags=["akv:www-cert"])), deps, cfg(sleep), LOG)["reason"] == "stale-event"


def test_mismatched_key_is_rejected(m) -> None:
    other = material("other.example.com")
    with pytest.raises(PermanentError, match="does not match"):
        build_pfx(m.leaf_pem, m.intermediate_pem, other.key_pem, "x")
    with pytest.raises(PermanentError, match="unencrypted PEM"):
        build_pfx(m.leaf_pem, m.intermediate_pem, "not a key", "x")


def test_transient_then_permanent(deps: Deps, m, sleep: NoSleep) -> None:
    deps.chains.failures = [TransientError("503")]
    assert handle(binding(az_event(m, tags=["akv:www-cert"])), deps, cfg(sleep), LOG)["action"] == "imported"
    with pytest.raises(PermanentError):
        handle(binding(make_event(tags=["akv:www-cert"], fingerprint=m.fingerprint)), deps, cfg(sleep), LOG)


def test_status_classification() -> None:
    assert classify_status(None) is TransientError
    assert classify_status(503) is TransientError and classify_status(429) is TransientError
    assert classify_status(403) is PermanentError


def test_no_secrets_in_logs(deps: Deps, m, sleep: NoSleep, capsys) -> None:
    handle(binding(az_event(m, tags=["akv:www-cert"])), deps, cfg(sleep), LOG)
    deps.secrets.value = material("other.example.com").key_pem
    deps.vault.certs.clear()
    with pytest.raises(PermanentError):
        handle(binding(az_event(m, tags=["akv:www-cert"])), deps, cfg(sleep), LOG)
    assert_no_secrets(capsys.readouterr().out, m.key_pem, deps.secrets.value, m.leaf_pem)
