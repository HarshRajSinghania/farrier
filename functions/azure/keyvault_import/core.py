"""Import a renewed certificate into Azure Key Vault (certificates).

Application Gateway, Front Door and App Service reference Key Vault
certificates by versionless id, so importing a new version rotates them
without touching the listener.

Selection
    * tag ``akv:<certificate-name>`` -- that certificate in ``KEYVAULT_URL``;
    * tag ``akv:<vault-name>/<certificate-name>`` -- another vault in the same cloud;
    * no tag, endpoint name matches ``AKV_NAME_PATTERN`` -- ``farrier-<endpoint name>``
      in ``KEYVAULT_URL``.

Idempotency
    Key Vault returns the current version's DER (``cer``); its SHA-256 is
    compared with the event fingerprint, so a duplicate is detected from the
    certificate itself, not from a tag that could drift. A newer
    ``farrier-renewal-id`` tag marks a stale event.
"""

from __future__ import annotations

import fnmatch
import hashlib
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from farrier_events import (
    AzureBlobRef,
    AzureKeyVaultSecretRef,
    Logger,
    PermanentError,
    RenewalEvent,
    RetryPolicy,
    ensure_allowed,
    parse_event,
    parse_object_ref,
    parse_secret_ref,
)
from farrier_events.pem import verify_leaf
from farrier_events.transports import from_eventgrid

TAG_PREFIX = "akv"
TAG_MANAGED = "farrier-managed"
TAG_ENDPOINT_ID = "farrier-endpoint-id"
TAG_RENEWAL_ID = "farrier-renewal-id"
TAG_FINGERPRINT = "farrier-fingerprint-sha256"

_NAME = re.compile(r"^[0-9A-Za-z-]{1,127}$")
_VAULT = re.compile(r"^[a-zA-Z][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]$")


# --------------------------------------------------------------------------- ports


@dataclass(frozen=True, slots=True)
class ExistingCertificate:
    der: bytes | None
    tags: Mapping[str, str]


class SecretReader(Protocol):
    def get_secret(self, ref: AzureKeyVaultSecretRef) -> str: ...


class ChainReader(Protocol):
    def read_text(self, ref: AzureBlobRef) -> str: ...


class KeyVaultCertificates(Protocol):
    def get(self, vault_url: str, name: str) -> ExistingCertificate | None: ...
    def import_pfx(self, vault_url: str, name: str, pfx: bytes, tags: Mapping[str, str]) -> str: ...


@dataclass(frozen=True, slots=True)
class Deps:
    secrets: SecretReader
    chains: ChainReader
    vault: KeyVaultCertificates


@dataclass(frozen=True, slots=True)
class Config:
    vault_url: str | None  # https://<vault>.vault.azure.net
    name_pattern: str | None = None
    allowed_prefixes: tuple[str, ...] = ()
    retry: RetryPolicy = RetryPolicy()


# --------------------------------------------------------------------------- pure helpers


@dataclass(frozen=True, slots=True)
class Target:
    vault_url: str
    name: str


def certificate_name_for(endpoint_name: str) -> str:
    slug = re.sub(r"[^0-9A-Za-z-]+", "-", endpoint_name).strip("-")
    name = f"farrier-{slug}"[:127].rstrip("-")
    if not _NAME.match(name):
        raise PermanentError("cannot derive a Key Vault certificate name from the endpoint name")
    return name


def _vault_suffix(vault_url: str) -> str:
    host = vault_url.removeprefix("https://")
    return host.split(".", 1)[1] if "." in host else "vault.azure.net"


def resolve_target(event: RenewalEvent, config: Config) -> Target | None:
    values = event.endpoint.tag_values(TAG_PREFIX)
    if len(values) > 1:
        raise PermanentError("endpoint has more than one akv: tag")
    if values:
        vault, sep, name = values[0].rpartition("/")
        if not _NAME.match(name):
            raise PermanentError("akv: tag must be akv:<certificate-name> or akv:<vault>/<certificate-name>")
        if sep:
            if not _VAULT.match(vault):
                raise PermanentError("akv: tag vault name is invalid")
            suffix = _vault_suffix(config.vault_url) if config.vault_url else "vault.azure.net"
            return Target(f"https://{vault.lower()}.{suffix}", name)
        if not config.vault_url:
            raise PermanentError("akv:<name> needs KEYVAULT_URL to be set")
        return Target(config.vault_url, name)
    if config.name_pattern and fnmatch.fnmatchcase(event.endpoint.name, config.name_pattern):
        if not config.vault_url:
            raise PermanentError("AKV_NAME_PATTERN needs KEYVAULT_URL to be set")
        return Target(config.vault_url, certificate_name_for(event.endpoint.name))
    return None


def skip_reason(existing: ExistingCertificate, event: RenewalEvent) -> str | None:
    if existing.der is not None and hashlib.sha256(existing.der).hexdigest() == event.renewal.fingerprint_sha256:
        return "already-current"
    current = existing.tags.get(TAG_RENEWAL_ID, "")
    if current.isdigit() and int(current) > event.renewal.id:
        return "stale-event"
    return None


def build_pfx(leaf_pem: str, chain_pem: str, key_pem: str, friendly_name: str) -> bytes:
    """PKCS#12 bundle with no password (Key Vault encrypts it at rest).

    Checks that the key belongs to the leaf certificate: Key Vault would accept
    a mismatched pair and the gateway would fail TLS handshakes later.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.hazmat.primitives.serialization import pkcs12

    try:
        key = serialization.load_pem_private_key(key_pem.encode("ascii"), password=None)
    except (ValueError, TypeError):
        raise PermanentError("private key is not an unencrypted PEM key") from None
    if not isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise PermanentError("Key Vault certificates need an RSA or EC key")
    leaf = x509.load_pem_x509_certificate(leaf_pem.encode("ascii"))
    cas = x509.load_pem_x509_certificates(chain_pem.encode("ascii")) if chain_pem.strip() else []
    spki = serialization.PublicFormat.SubjectPublicKeyInfo
    if key.public_key().public_bytes(serialization.Encoding.DER, spki) != leaf.public_key().public_bytes(
        serialization.Encoding.DER, spki
    ):
        raise PermanentError("private key does not match the leaf certificate")
    return pkcs12.serialize_key_and_certificates(
        friendly_name.encode("utf-8"),
        key,
        leaf,
        cas or None,
        serialization.NoEncryption(),
    )


def farrier_tags(event: RenewalEvent) -> dict[str, str]:
    assert event.renewal.fingerprint_sha256 is not None
    return {
        TAG_MANAGED: "true",
        TAG_ENDPOINT_ID: str(event.endpoint.id),
        TAG_RENEWAL_ID: str(event.renewal.id),
        TAG_FINGERPRINT: event.renewal.fingerprint_sha256,
    }


@dataclass(frozen=True, slots=True)
class Outcome:
    action: str  # imported | skipped
    reason: str | None = None
    certificate_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"action": self.action, "reason": self.reason, "certificate_id": self.certificate_id}


# --------------------------------------------------------------------------- orchestration


def process(event: RenewalEvent, deps: Deps, config: Config, log: Logger) -> Outcome:
    if event.state != "done":
        return Outcome("skipped", "state-not-done")
    target = resolve_target(event, config)
    if target is None:
        return Outcome("skipped", "not-selected")
    cert = event.certificate
    assert cert is not None and event.renewal.fingerprint_sha256 is not None
    if cert.chain_ref is None or event.private_key_ref is None:
        raise PermanentError("event lacks chain_ref or private_key_ref; enable chain and key export")
    ensure_allowed(cert.chain_ref, config.allowed_prefixes)
    ensure_allowed(event.private_key_ref, config.allowed_prefixes)
    chain_ref, key_ref = parse_object_ref(cert.chain_ref), parse_secret_ref(event.private_key_ref)
    if not isinstance(chain_ref, AzureBlobRef) or not isinstance(key_ref, AzureKeyVaultSecretRef):
        raise PermanentError("keyvault_import reads chains from azblob:// and keys from azure-kv: only")

    def retried[R](fn: Callable[[], R]) -> R:
        return config.retry.run(fn, log)

    existing = retried(lambda: deps.vault.get(target.vault_url, target.name))
    if existing is not None:
        reason = skip_reason(existing, event)
        if reason:
            return Outcome("skipped", reason, f"{target.vault_url}/certificates/{target.name}")

    fullchain = retried(lambda: deps.chains.read_text(chain_ref))
    leaf, intermediates = verify_leaf(fullchain, event.renewal.fingerprint_sha256)
    key_pem = retried(lambda: deps.secrets.get_secret(key_ref))
    pfx = build_pfx(leaf, intermediates, key_pem, target.name)
    cert_id = retried(lambda: deps.vault.import_pfx(target.vault_url, target.name, pfx, farrier_tags(event)))
    return Outcome("imported", None, cert_id)


def envelope_from_binding(
    *, id: str, event_type: str, subject: str | None, event_time: Any, topic: str | None, data: Any
) -> dict[str, Any]:
    """Rebuild the CloudEvent from the Azure Functions Event Grid binding."""
    if isinstance(event_time, datetime):
        aware = event_time if event_time.tzinfo else event_time.replace(tzinfo=UTC)
        time: Any = aware.astimezone(UTC).isoformat().replace("+00:00", "Z")
    else:
        time = event_time
    # The binding surfaces the CloudEvent source as ``topic``; if the host gives us
    # the Azure topic path instead, keep the event valid with a neutral source.
    source = topic if isinstance(topic, str) and topic.startswith("farrier://") else "farrier://event-grid"
    return from_eventgrid(id=id, type=event_type, subject=subject, time=time, source=source, data=data)


def handle(envelope: Mapping[str, Any], deps: Deps, config: Config, log: Logger) -> dict[str, Any]:
    try:
        event = parse_event(envelope)
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
    elog.info("key vault " + outcome.action, **outcome.as_dict())
    return outcome.as_dict()
