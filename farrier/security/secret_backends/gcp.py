"""Google Secret Manager. The index keeps ``projects/<p>/secrets/<id>``; the id is
FARRIER_SECRET_GCP_PREFIX + the name, with characters Secret Manager does not allow escaped reversibly
(``_`` + two hex digits, so ``a.b`` -> ``a_2eb`` and ``a_b`` -> ``a_5fb`` never collide).

put: addVersion, creating the secret first (automatic replication) when it does not exist.
get: versions/latest:access. delete: deletes the secret and its versions.
"""
from __future__ import annotations

import base64
import os
import re

from farrier.security.cloud_auth import google
from farrier.security.cloud_auth.http import CloudConfigError, json_body, request
from farrier.security.secret_backends import CachedBackend

API = "https://secretmanager.googleapis.com/v1"
REF = re.compile(r"^projects/(?P<project>[a-z][a-z0-9-]{4,28}[a-z0-9]|\d+)/secrets/(?P<id>[A-Za-z0-9_-]{1,255})"
                 r"(?:/versions/(?P<version>latest|\d+))?$")
_KEEP = re.compile(r"[A-Za-z0-9-]")


def encode(name: str) -> str:
    return "".join(c if _KEEP.match(c) else f"_{ord(c):02x}" for c in name)


def decode(sid: str) -> str:
    return re.sub(r"_([0-9a-f]{2})", lambda m: chr(int(m.group(1), 16)), sid)


class GoogleSecretManager(CachedBackend):
    name = "gcp"
    scheme = "gcp-sm"

    def __init__(self, store=None, *, strict: bool = True, env=None, http=None, tokens=None):
        super().__init__()
        env = os.environ if env is None else env
        self.project = env.get("FARRIER_SECRET_GCP_PROJECT") or env.get("GOOGLE_CLOUD_PROJECT") or None
        self.prefix = env.get("FARRIER_SECRET_GCP_PREFIX", "farrier-")
        self.http = http
        self.tokens = tokens or (google.default_provider() if env is os.environ else google.GoogleTokenProvider(env, http))
        if strict and not self.project:
            raise CloudConfigError("FARRIER_SECRET_GCP_PROJECT is not set: name the Google Cloud project that holds "
                                   "Farrier's secrets")
        if not re.fullmatch(r"[A-Za-z0-9_-]*", self.prefix):
            raise CloudConfigError("FARRIER_SECRET_GCP_PREFIX may only use A-Z a-z 0-9 _ -")

    @staticmethod
    def parse(ref: str) -> re.Match:
        m = REF.match(ref)
        if not m:
            raise ValueError("gcp-sm reference must be projects/<project>/secrets/<id>[/versions/<n|latest>]")
        return m

    def _req(self, method: str, url: str, what: str, **kw):
        h = {"Authorization": f"Bearer {self.tokens.token(google.CLOUD_PLATFORM)}"}
        return request(method, url, what=f"Google Secret Manager {what}", http=self.http, headers=h, **kw)

    def _store(self, name: str, value: str) -> str:
        if not self.project:
            raise CloudConfigError("FARRIER_SECRET_GCP_PROJECT is not set")
        secret = f"projects/{self.project}/secrets/{self.prefix}{encode(name)}"
        body = {"payload": {"data": base64.b64encode(value.encode()).decode()}}
        r = self._req("POST", f"{API}/{secret}:addVersion", "addVersion", json=body, allow=(404,))
        if r.status_code == 404:
            self._req("POST", f"{API}/projects/{self.project}/secrets", "create secret", allow=(409,),
                      params={"secretId": f"{self.prefix}{encode(name)}"},
                      json={"replication": {"automatic": {}}, "labels": {"managed-by": "farrier"}})
            self._req("POST", f"{API}/{secret}:addVersion", "addVersion", json=body)
        return secret

    def _fetch(self, ref: str) -> str | None:
        m = self.parse(ref)
        version = f"projects/{m['project']}/secrets/{m['id']}/versions/{m['version'] or 'latest'}"
        r = self._req("GET", f"{API}/{version}:access", "access", allow=(404,))
        if r.status_code == 404:
            return None
        return base64.b64decode(json_body(r, "Secret Manager access")["payload"]["data"]).decode()

    def _remove(self, ref: str) -> None:
        m = self.parse(ref)
        self._req("DELETE", f"{API}/projects/{m['project']}/secrets/{m['id']}", "delete", allow=(404,))

    def external(self, ref: str) -> str:
        return f"gcp-sm:{ref}" if "/versions/" in ref else f"gcp-sm:{ref}/versions/latest"

    def describe(self) -> dict:
        return {"kind": "gcp", "location": f"Google Secret Manager project {self.project or '(not set)'}, "
                                           f"prefix {self.prefix}"}

    def owns(self, body: str) -> bool:
        m = self.parse(body)
        return m["project"] == self.project and m["id"].startswith(self.prefix)
