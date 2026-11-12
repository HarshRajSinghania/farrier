"""Azure Key Vault secrets. The index keeps ``https://<vault>/secrets/<name>``; the Key Vault name is
FARRIER_SECRET_AZURE_PREFIX + the name, with every character other than A-Z a-z 0-9 escaped reversibly
(``-`` + two hex digits: ``cf-token`` -> ``cf-2dtoken``), because Key Vault names allow only [0-9a-zA-Z-].

put: set secret (a new version). A name that is soft-deleted is recovered first, so soft-delete is
honoured rather than purged. delete: delete secret (soft-delete keeps it recoverable for the vault's
retention period).
"""
from __future__ import annotations

import os
import re
from urllib.parse import urlsplit

from ..cloud_auth import azure
from ..cloud_auth import http as cloud_http
from ..cloud_auth.http import CloudConfigError, CloudError, json_body, request
from . import CachedBackend

API_VERSION = "7.4"
VAULT_SUFFIXES = (".vault.azure.net", ".vault.azure.cn", ".vault.usgovcloudapi.net", ".vault.microsoftazure.de")
NAME = re.compile(r"^[0-9A-Za-z-]{1,127}$")
VERSION = re.compile(r"^[0-9a-f]{32}$")


def encode(name: str) -> str:
    return "".join(c if c.isascii() and c.isalnum() else f"-{ord(c):02x}" for c in name)


def decode(kv_name: str) -> str:
    return re.sub(r"-([0-9a-f]{2})", lambda m: chr(int(m.group(1), 16)), kv_name)


def vault_origin(url: str, setting: str = "FARRIER_SECRET_AZURE_VAULT_URL") -> str:
    """https://<vault>.vault.azure.net, refusing any other host (a bearer token is sent there)."""
    p = urlsplit(url.strip())
    host = (p.hostname or "").lower()
    if p.scheme != "https" or p.port or p.username or not host.endswith(VAULT_SUFFIXES):
        raise CloudConfigError(f"{setting} must be https://<vault>.vault.azure.net (got a different host or scheme)")
    return f"https://{host}"


def parse(ref: str) -> tuple[str, str, str | None]:
    """(vault origin, secret name, version or None) of https://<vault>/secrets/<name>[/<version>]."""
    origin = vault_origin(ref, "azure-kv reference")
    seg = [s for s in urlsplit(ref).path.split("/") if s]
    if len(seg) not in (2, 3) or seg[0] != "secrets" or not NAME.match(seg[1]) \
            or (len(seg) == 3 and not VERSION.match(seg[2])):
        raise ValueError("azure-kv reference must be https://<vault>.vault.azure.net/secrets/<name>[/<version>]")
    return origin, seg[1], seg[2] if len(seg) == 3 else None


class AzureKeyVault(CachedBackend):
    name = "azure"
    scheme = "azure-kv"
    parse = staticmethod(parse)

    def __init__(self, store=None, *, strict: bool = True, env=None, http=None, tokens=None):
        super().__init__()
        env = os.environ if env is None else env
        url = env.get("FARRIER_SECRET_AZURE_VAULT_URL")
        self.vault = vault_origin(url) if url else None
        self.prefix = env.get("FARRIER_SECRET_AZURE_PREFIX", "farrier-")
        self.http = http
        self.tokens = tokens or (azure.default_provider() if env is os.environ else azure.AzureTokenProvider(env, http))
        if strict and not self.vault:
            raise CloudConfigError("FARRIER_SECRET_AZURE_VAULT_URL is not set: e.g. https://<vault>.vault.azure.net")
        if not re.fullmatch(r"[0-9A-Za-z-]*", self.prefix):
            raise CloudConfigError("FARRIER_SECRET_AZURE_PREFIX may only use A-Z a-z 0-9 -")

    def _req(self, method: str, url: str, what: str, **kw):
        h = {"Authorization": f"Bearer {self.tokens.token(azure.VAULT_SCOPE)}"}
        kw.setdefault("params", {})["api-version"] = API_VERSION
        return request(method, url, what=f"Azure Key Vault {what}", http=self.http, headers=h, **kw)

    def _store(self, name: str, value: str) -> str:
        if not self.vault:
            raise CloudConfigError("FARRIER_SECRET_AZURE_VAULT_URL is not set")
        kv = self.prefix + encode(name)
        if not NAME.match(kv):
            raise ValueError(f"secret name {name!r} is too long for Azure Key Vault once escaped")
        url = f"{self.vault}/secrets/{kv}"
        body = {"value": value, "tags": {"managed-by": "farrier"}}
        for attempt in range(6):
            try:
                self._req("PUT", url, "set secret", json=body)
                return url
            except CloudError as e:
                if e.status != 409:
                    raise
                if attempt == 0 and e.code == "ObjectIsDeletedButRecoverable":
                    self._req("POST", f"{self.vault}/deletedsecrets/{kv}/recover", "recover deleted secret")
                elif attempt == 5:
                    raise
                cloud_http.sleep(1 + attempt)        # recovery completes asynchronously
        raise AssertionError("unreachable")

    def _fetch(self, ref: str) -> str | None:
        origin, name, version = parse(ref)
        r = self._req("GET", f"{origin}/secrets/{name}" + (f"/{version}" if version else ""), "get secret",
                      allow=(404,))
        if r.status_code == 404:
            return None
        return json_body(r, "Key Vault get").get("value")

    def _remove(self, ref: str) -> None:
        origin, name, _ = parse(ref)
        self._req("DELETE", f"{origin}/secrets/{name}", "delete secret", allow=(404,))

    def describe(self) -> dict:
        return {"kind": "azure", "location": f"Azure Key Vault {self.vault or '(not set)'}, prefix {self.prefix}"}

    def owns(self, body: str) -> bool:
        origin, name, _ = parse(body)
        return origin == self.vault and name.startswith(self.prefix)
