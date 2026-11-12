"""Where secret values entered in the dashboard live.

Farrier keeps an index (table ``secrets``: name -> backend + external reference, never a value) and
hands the value to a backend. Configs reference a secret as ``vault:NAME``; resolution goes through the
index to whichever backend holds it, so secrets written under one backend keep resolving after the
default changes.

    FARRIER_SECRET_BACKEND = local (default) | aws | gcp | azure | hashicorp

    local      sealed with the master key in Farrier's own database
    aws        AWS Secrets Manager      FARRIER_SECRET_AWS_REGION, FARRIER_SECRET_AWS_PREFIX (farrier/),
                                        FARRIER_SECRET_AWS_KMS_KEY (optional CMK for new secrets)
    gcp        Google Secret Manager    FARRIER_SECRET_GCP_PROJECT, FARRIER_SECRET_GCP_PREFIX (farrier-)
    azure      Azure Key Vault          FARRIER_SECRET_AZURE_VAULT_URL, FARRIER_SECRET_AZURE_PREFIX (farrier-)
    hashicorp  Vault / OpenBao KV v2    FARRIER_SECRET_VAULT_ADDR, FARRIER_SECRET_VAULT_MOUNT (secret),
                                        FARRIER_SECRET_VAULT_PREFIX (farrier/), FARRIER_SECRET_VAULT_NAMESPACE,
                                        FARRIER_SECRET_VAULT_CACERT

Cloud backends authenticate with the platform identity (farrier.cloud_auth). Reads are cached in memory
for at most 60 seconds; values are never logged or written anywhere else. Configs may also hold external
references to secrets the organisation already keeps (aws-sm:, gcp-sm:, azure-kv:, hcvault:); see
farrier.secret_backends.external.
"""
from __future__ import annotations

import importlib
import os
import threading
import time

CACHE_SECONDS = 60
CLOUD = ("aws", "gcp", "azure")          # backends whose references can travel in events
_LAZY = {"aws": "aws:AwsSecretsManager", "gcp": "gcp:GoogleSecretManager", "azure": "azure:AzureKeyVault",
         "hashicorp": "hashicorp:HashiCorpVault"}


class SecretBackend:
    name = ""
    scheme = ""          # external reference scheme, e.g. "aws-sm"
    writable = True

    def put(self, name: str, value: str) -> str:
        """Store (or add a new version of) a value; return the reference to keep in the index."""
        raise NotImplementedError

    def get(self, ref: str) -> str | None:
        """The value for a reference, or None if it is gone."""
        raise NotImplementedError

    def delete(self, ref: str) -> None:
        raise NotImplementedError

    def describe(self) -> dict:
        """{kind, location} for the dashboard: where values go, never a credential."""
        raise NotImplementedError

    def external(self, ref: str) -> str:
        """The index reference as an external reference (``aws-sm:arn:...``) another system can read."""
        return f"{self.scheme}:{ref}"

    def owns(self, body: str) -> bool:
        """True when an external reference body lies under this backend's configured location and prefix."""
        return False


class CachedBackend(SecretBackend):
    """Reads are cached in memory for CACHE_SECONDS; writes and deletes drop the entry."""

    def __init__(self):
        self._cache: dict[str, tuple[str, float]] = {}
        self._cache_lock = threading.Lock()

    def get(self, ref: str) -> str | None:
        now = time.monotonic()
        with self._cache_lock:
            hit = self._cache.get(ref)
            if hit and now - hit[1] < CACHE_SECONDS:
                return hit[0]
        value = self._fetch(ref)
        with self._cache_lock:
            if value is None:
                self._cache.pop(ref, None)
            else:
                self._cache[ref] = (value, now)
        return value

    def put(self, name: str, value: str) -> str:
        ref = self._store(name, value)
        self._forget(ref)
        return ref

    def delete(self, ref: str) -> None:
        self._forget(ref)
        self._remove(ref)

    def _forget(self, ref: str) -> None:
        with self._cache_lock:
            self._cache.pop(ref, None)

    def _fetch(self, ref: str) -> str | None:
        raise NotImplementedError

    def _store(self, name: str, value: str) -> str:
        raise NotImplementedError

    def _remove(self, ref: str) -> None:
        raise NotImplementedError


class LocalBackend(SecretBackend):
    """Values sealed under the master key (farrier.vault.Vault) in table ``secret_values``."""

    name = "local"
    scheme = "vault"

    def __init__(self, store, **_):
        self.store = store

    def put(self, name: str, value: str) -> str:
        ref = name
        sealed = self.store.vault.seal(value)
        with self.store.transaction():
            if not self.store._run("UPDATE secret_values SET value_sealed=? WHERE ref=?", (sealed, ref))[1]:
                self.store.x("INSERT INTO secret_values(ref, value_sealed) VALUES (?,?)", (ref, sealed))
        return ref

    def get(self, ref: str) -> str | None:
        row = self.store.q1("SELECT value_sealed FROM secret_values WHERE ref=?", (ref,))
        return self.store.vault.open(row["value_sealed"]) if row else None

    def delete(self, ref: str) -> None:
        self.store.x("DELETE FROM secret_values WHERE ref=?", (ref,))

    def describe(self) -> dict:
        return {"kind": "local", "location": f"Farrier database ({self.store.backend}), sealed with the master key"}


BACKENDS = {"local": LocalBackend}
KNOWN = ("local", *_LAZY)


def backend_class(kind: str) -> type[SecretBackend]:
    if kind in BACKENDS:
        return BACKENDS[kind]
    if kind in _LAZY:
        module, cls = _LAZY[kind].split(":")
        return getattr(importlib.import_module(f"{__name__}.{module}"), cls)
    raise ValueError(f"unknown FARRIER_SECRET_BACKEND {kind!r}; known: {', '.join(KNOWN)}")


def configured() -> str:
    return (os.environ.get("FARRIER_SECRET_BACKEND") or "local").strip().lower()


def make_backend(kind: str, store, strict: bool = True) -> SecretBackend:
    """A backend instance. ``strict`` (the configured default backend) checks every required setting now,
    so a misconfiguration stops startup with the setting's name; non-strict instances serve secrets that
    an earlier configuration wrote and take what they need from the stored reference."""
    return backend_class(kind)(store, strict=strict)
