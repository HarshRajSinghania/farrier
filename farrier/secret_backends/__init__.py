"""Where secret values entered in the dashboard live.

Farrier keeps an index (table ``secrets``: name -> backend + external reference, never a value) and
hands the value to a backend. Configs reference a secret as ``vault:NAME``; resolution goes through the
index to whichever backend holds it, so secrets written under one backend keep resolving after the
default changes.

    FARRIER_SECRET_BACKEND = local (default) | aws | gcp | azure | hashicorp

Only ``local`` is implemented: values sealed with the master key in Farrier's own database (fine for
testing and small installs). Enterprises keep secrets in their own manager; a backend for AWS Secrets
Manager, Google Secret Manager, Azure Key Vault or HashiCorp Vault implements SecretBackend, reads its
own env settings, and registers in BACKENDS. No schema change is needed.
"""
from __future__ import annotations

import os

PLANNED = ("aws", "gcp", "azure", "hashicorp")


class SecretBackend:
    name = ""
    writable = True

    def put(self, name: str, value: str) -> str:
        """Store (or replace) a value; return the reference to keep in the index."""
        raise NotImplementedError

    def get(self, ref: str) -> str | None:
        """The value for a reference, or None if it is gone."""
        raise NotImplementedError

    def delete(self, ref: str) -> None:
        raise NotImplementedError

    def describe(self) -> dict:
        """{kind, location} for the dashboard: where values go, never a credential."""
        raise NotImplementedError


class LocalBackend(SecretBackend):
    """Values sealed under the master key (farrier.vault.Vault) in table ``secret_values``."""

    name = "local"

    def __init__(self, store):
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


def configured() -> str:
    return (os.environ.get("FARRIER_SECRET_BACKEND") or "local").strip().lower()


def make_backend(kind: str, store) -> SecretBackend:
    if kind in BACKENDS:
        return BACKENDS[kind](store)
    if kind in PLANNED:
        raise ValueError(f"FARRIER_SECRET_BACKEND={kind} is not available in this version; use local")
    raise ValueError(f"unknown FARRIER_SECRET_BACKEND {kind!r}; known: local, {', '.join(PLANNED)}")
