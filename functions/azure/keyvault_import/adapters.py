"""Thin Azure SDK adapters (azure-identity, azure-keyvault-*, azure-storage-blob).

SDK imports are deferred so the unit tests run without the Azure libraries.
Each method is one SDK call plus error translation; the SDK's own retry policy
is limited to a single attempt so ``RetryPolicy`` owns retrying.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from functools import cache
from typing import Any

from farrier_events import AzureBlobRef, AzureKeyVaultSecretRef, PermanentError, TransientError

from .core import ExistingCertificate

MAX_CHAIN_BYTES = 64 * 1024
_SDK_OPTIONS = {"retry_total": 0, "connection_timeout": 5, "read_timeout": 20}


def classify_status(status: int | None) -> type[TransientError] | type[PermanentError]:
    if status is None or status in (408, 429) or status >= 500:
        return TransientError
    return PermanentError


@contextmanager
def _azure(operation: str) -> Iterator[None]:
    try:
        yield
    except (TransientError, PermanentError):
        raise
    except Exception as exc:
        # azure-core: HttpResponseError has .status_code; ServiceRequestError /
        # ServiceResponseError (network) have none and are transient. The SDK
        # message is dropped: it can contain request URLs.
        status = getattr(exc, "status_code", None)
        name = type(exc).__name__
        if status is None and name not in ("ServiceRequestError", "ServiceResponseError", "ServiceRequestTimeoutError"):
            raise PermanentError(f"{operation} failed: {name}") from None
        raise classify_status(status)(f"{operation} failed: {name} (HTTP {status or '-'})") from None


@cache
def _credential() -> Any:
    from azure.identity import DefaultAzureCredential

    return DefaultAzureCredential(exclude_interactive_browser_credential=True)


class KeyVaultSecretReader:
    def get_secret(self, ref: AzureKeyVaultSecretRef) -> str:
        from azure.keyvault.secrets import SecretClient

        client = SecretClient(ref.vault_url, _credential(), **_SDK_OPTIONS)
        with _azure("keyvault.secrets.get"):
            value = client.get_secret(ref.name, ref.version).value
        if not value:
            raise PermanentError("key secret is empty")
        return str(value)


class BlobChainReader:
    def read_text(self, ref: AzureBlobRef) -> str:
        from azure.storage.blob import BlobClient

        blob = BlobClient(ref.account_url, ref.container, ref.blob, credential=_credential(), **_SDK_OPTIONS)
        with _azure("storage.blob.download"):
            props = blob.get_blob_properties()
            if props.size > MAX_CHAIN_BYTES:
                raise PermanentError("chain blob is larger than 64 KiB")
            data = blob.download_blob().readall()
        try:
            return bytes(data).decode("ascii")
        except UnicodeDecodeError:
            raise PermanentError("chain blob is not ASCII PEM") from None


class KeyVaultCertificateStore:
    def _client(self, vault_url: str) -> Any:
        from azure.keyvault.certificates import CertificateClient

        return CertificateClient(vault_url, _credential(), **_SDK_OPTIONS)

    def get(self, vault_url: str, name: str) -> ExistingCertificate | None:
        from azure.core.exceptions import ResourceNotFoundError

        with _azure("keyvault.certificates.get"):
            try:
                cert = self._client(vault_url).get_certificate(name)
            except ResourceNotFoundError:
                return None  # first renewal for this certificate
        cer = getattr(cert, "cer", None)
        return ExistingCertificate(der=bytes(cer) if cer else None, tags=dict(cert.properties.tags or {}))

    def import_pfx(self, vault_url: str, name: str, pfx: bytes, tags: Mapping[str, str]) -> str:
        from azure.keyvault.certificates import CertificateContentType, CertificatePolicy

        policy = CertificatePolicy(
            issuer_name="Unknown",  # externally issued
            content_type=CertificateContentType.pkcs12,
            exportable=True,  # Application Gateway reads the PFX through the secret
        )
        with _azure("keyvault.certificates.import"):
            cert = self._client(vault_url).import_certificate(name, pfx, policy=policy, tags=dict(tags), enabled=True)
        return str(cert.id)
