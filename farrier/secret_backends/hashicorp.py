"""HashiCorp Vault / OpenBao, KV version 2. The index keeps ``<mount>/<prefix><name>``; the value is the
field ``value`` of that secret.

External references: ``hcvault:<mount>/<path>`` (or ``<mount>/data/<path>``, as the HTTP API spells it),
optionally ``#<field>`` (default ``value``). They are always read from FARRIER_SECRET_VAULT_ADDR; a
reference never names a server.

put: write (a new version). get: the latest version. delete: delete the metadata (every version).
"""
from __future__ import annotations

import os
import re

from ..cloud_auth.hashicorp import VaultAuth
from ..cloud_auth.http import CloudConfigError, CloudError, client_with_ca, json_body, request
from . import CachedBackend

SEGMENT = re.compile(r"^[A-Za-z0-9_.@+=-]+$")


def _clean(path: str, what: str) -> str:
    segs = path.strip("/").split("/")
    if not segs or any(not SEGMENT.match(s) or s in (".", "..") for s in segs):
        raise ValueError(f"{what} {path!r} is not a valid Vault path")
    return "/".join(segs)


class HashiCorpVault(CachedBackend):
    name = "hashicorp"
    scheme = "hcvault"

    def __init__(self, store=None, *, strict: bool = True, env=None, http=None):
        super().__init__()
        env = os.environ if env is None else env
        self.addr = (env.get("FARRIER_SECRET_VAULT_ADDR") or env.get("VAULT_ADDR") or "").rstrip("/") or None
        self.mount = _clean(env.get("FARRIER_SECRET_VAULT_MOUNT") or "secret", "FARRIER_SECRET_VAULT_MOUNT")
        self.prefix = env.get("FARRIER_SECRET_VAULT_PREFIX", "farrier/").lstrip("/")
        self.namespace = env.get("FARRIER_SECRET_VAULT_NAMESPACE") or None
        if strict and not self.addr:
            raise CloudConfigError("FARRIER_SECRET_VAULT_ADDR is not set: e.g. https://vault.internal:8200")
        if self.addr and not self.addr.startswith(("https://", "http://")):
            raise CloudConfigError("FARRIER_SECRET_VAULT_ADDR must be an https:// URL")
        self.http = http or client_with_ca(env.get("FARRIER_SECRET_VAULT_CACERT"))
        self.auth = VaultAuth(self.addr or "", self.namespace, env, self.http)

    def parse(self, ref: str) -> tuple[str, str, str]:
        """(mount, path, field)."""
        ref, _, field = ref.partition("#")
        if "/data/" in ref:
            mount, path = ref.split("/data/", 1)
        elif ref.startswith(self.mount + "/"):
            mount, path = self.mount, ref[len(self.mount) + 1:]
        else:
            mount, _, path = ref.partition("/")
        return _clean(mount, "Vault mount"), _clean(path, "Vault path"), field or "value"

    def _req(self, method: str, url: str, what: str, **kw):
        if not self.addr:
            raise CloudConfigError("FARRIER_SECRET_VAULT_ADDR is not set")
        for attempt in (0, 1):
            try:
                return request(method, url, what=f"Vault {what}", http=self.http, headers=self.auth.headers(), **kw)
            except CloudError as e:
                if e.status != 403 or attempt:
                    raise
                self.auth.invalidate()          # an expired login token: log in again once

    def _store(self, name: str, value: str) -> str:
        path = _clean(self.prefix + name, "FARRIER_SECRET_VAULT_PREFIX + name")
        self._req("POST", f"{self.addr}/v1/{self.mount}/data/{path}", "write", json={"data": {"value": value}})
        return f"{self.mount}/{path}"

    def _fetch(self, ref: str) -> str | None:
        mount, path, field = self.parse(ref)
        r = self._req("GET", f"{self.addr}/v1/{mount}/data/{path}", "read", allow=(404,))
        if r.status_code == 404:
            return None
        data = (json_body(r, "Vault read").get("data") or {}).get("data") or {}
        v = data.get(field)
        return None if v is None else str(v)

    def _remove(self, ref: str) -> None:
        mount, path, _ = self.parse(ref)
        self._req("DELETE", f"{self.addr}/v1/{mount}/metadata/{path}", "delete", allow=(404,))

    def describe(self) -> dict:
        ns = f" (namespace {self.namespace})" if self.namespace else ""
        return {"kind": "hashicorp", "location": f"Vault {self.addr or '(address not set)'}{ns}, KV v2 mount "
                                                 f"{self.mount}, prefix {self.prefix}"}

    def owns(self, body: str) -> bool:
        mount, path, _ = self.parse(body)
        return mount == self.mount and path.startswith(self.prefix)
