"""Secrets entered in the dashboard: write-only, referenced from configs as ``vault:NAME``.

The ``secrets`` table is an index (name -> backend + reference, never a value); the value itself goes to
the configured backend (farrier.secret_backends; default "local" = sealed in this database). Resolution
of vault:NAME uses the backend recorded for that name, so changing the default never strands a secret.
Nothing here returns a value to the API: ``list`` gives names and metadata, ``get`` is for the engine.
"""
from __future__ import annotations

import re

from .db import now_iso
from .secret_backends import configured, make_backend

NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
MAX_BYTES = 16 * 1024


class SecretStore:
    def __init__(self, store, backend: str | None = None):
        self.store = store
        self.backend = make_backend(backend or configured(), store)
        self._others: dict = {self.backend.name: self.backend}

    def _backend(self, kind: str):
        if kind not in self._others:
            self._others[kind] = make_backend(kind, self.store)
        return self._others[kind]

    def put(self, name: str, value: str) -> bool:
        """Write through the configured backend and index it. Returns True when the secret is new."""
        if not NAME.match(name or ""):
            raise ValueError("secret name must be 1-64 of A-Z a-z 0-9 _ . - (starting with a letter or digit)")
        if not isinstance(value, str) or not value:
            raise ValueError("value must be a non-empty string")
        if len(value.encode()) > MAX_BYTES:
            raise ValueError("value is larger than 16 KB")
        if not self.backend.writable:
            raise ValueError(f"the {self.backend.name} secret backend is read-only")
        old = self.store.q1("SELECT backend, ref FROM secrets WHERE name=?", (name,))
        ref = self.backend.put(name, value)
        t = now_iso()
        with self.store.transaction():
            if old:
                self.store.x("UPDATE secrets SET backend=?, ref=?, updated_at=? WHERE name=?",
                             (self.backend.name, ref, t, name))
            else:
                self.store.x("INSERT INTO secrets(name, backend, ref, created_at, updated_at) VALUES (?,?,?,?,?)",
                             (name, self.backend.name, ref, t, t))
        if old and (old["backend"], old["ref"]) != (self.backend.name, ref):
            try:   # moved to another backend: drop the old copy
                self._backend(old["backend"]).delete(old["ref"])
            except Exception:  # noqa: BLE001
                pass
        return old is None

    def get(self, name: str) -> str | None:
        row = self.store.q1("SELECT backend, ref FROM secrets WHERE name=?", (name,))
        return self._backend(row["backend"]).get(row["ref"]) if row else None

    def exists(self, name: str) -> bool:
        return self.store.q1("SELECT name FROM secrets WHERE name=?", (name,)) is not None

    def delete(self, name: str) -> bool:
        row = self.store.q1("SELECT backend, ref FROM secrets WHERE name=?", (name,))
        if not row:
            return False
        self._backend(row["backend"]).delete(row["ref"])
        self.store.x("DELETE FROM secrets WHERE name=?", (name,))
        return True

    def list(self) -> list[dict]:
        rows = self.store.q("SELECT name, backend, created_at, updated_at FROM secrets ORDER BY name")
        out = []
        for r in rows:
            try:
                loc = self._backend(r["backend"]).describe()["location"]
            except ValueError:
                loc = None
            out.append(r | {"location": loc})
        return out

    def describe(self) -> dict:
        d = self.backend.describe()
        return {"backend": self.backend.name, "location": d["location"], "writable": self.backend.writable}
