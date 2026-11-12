"""HashiCorp Vault / OpenBao tokens.

Source, first match wins:

  1. VAULT_TOKEN
  2. FARRIER_SECRET_VAULT_TOKEN_FILE (e.g. a Vault Agent sink; re-read on every use, the agent rotates it)
  3. Kubernetes auth: FARRIER_SECRET_VAULT_ROLE with the pod's service-account token
     (FARRIER_SECRET_VAULT_K8S_TOKEN_FILE, default /var/run/secrets/kubernetes.io/serviceaccount/token)
     posted to auth/<FARRIER_SECRET_VAULT_AUTH_MOUNT, default kubernetes>/login. The token is renewed
     (auth/token/renew-self) once a third of its TTL is left, and re-issued by a new login when renewal is
     refused or the lease is not renewable.
"""
from __future__ import annotations

import os
import threading
import time

from farrier.security.cloud_auth.http import (
    CloudConfigError,
    CloudError,
    json_body,
    request,
)

K8S_TOKEN = "/var/run/secrets/kubernetes.io/serviceaccount/token"


class VaultAuth:
    def __init__(self, addr: str, namespace: str | None = None, env=None, http=None):
        self.addr = addr.rstrip("/")
        self.namespace = namespace
        self.env = os.environ if env is None else env
        self.http = http
        self._lock = threading.Lock()
        self._token: str | None = None
        self._expires = 0.0
        self._ttl = 0
        self._renewable = False

    def headers(self, token: str | None = None) -> dict:
        h = {"X-Vault-Token": token or self.token()}
        if self.namespace:
            h["X-Vault-Namespace"] = self.namespace
        return h

    def token(self) -> str:
        e = self.env
        if e.get("VAULT_TOKEN"):
            return e["VAULT_TOKEN"]
        if e.get("FARRIER_SECRET_VAULT_TOKEN_FILE"):
            try:
                with open(e["FARRIER_SECRET_VAULT_TOKEN_FILE"]) as f:
                    return f.read().strip()
            except OSError as err:
                raise CloudConfigError(f"FARRIER_SECRET_VAULT_TOKEN_FILE cannot be read ({type(err).__name__})") from None
        if not e.get("FARRIER_SECRET_VAULT_ROLE"):
            raise CloudConfigError("no Vault credentials: set FARRIER_SECRET_VAULT_ROLE (Kubernetes auth), "
                                   "FARRIER_SECRET_VAULT_TOKEN_FILE or VAULT_TOKEN")
        with self._lock:
            now = time.time()
            if self._token and now < self._expires - max(30, self._ttl / 3):
                return self._token
            if self._token and self._renewable and now < self._expires:
                try:
                    self._renew()
                    return self._token
                except CloudError:
                    pass                      # fall through to a fresh login
            self._login()
            return self._token

    def invalidate(self) -> None:
        """Forget a login token the server refused (403), so the next call logs in again."""
        with self._lock:
            self._token = None

    def _set(self, auth: dict) -> None:
        if not auth.get("client_token"):
            raise CloudError("Vault login returned no client_token")
        self._token = auth["client_token"]
        self._ttl = int(auth.get("lease_duration") or 3600)
        self._expires = time.time() + self._ttl
        self._renewable = bool(auth.get("renewable"))

    def _login(self) -> None:
        e = self.env
        path = e.get("FARRIER_SECRET_VAULT_K8S_TOKEN_FILE") or K8S_TOKEN
        try:
            with open(path) as f:
                jwt = f.read().strip()
        except OSError as err:
            raise CloudConfigError(f"FARRIER_SECRET_VAULT_K8S_TOKEN_FILE ({path}) cannot be read "
                                   f"({type(err).__name__})") from None
        mount = (e.get("FARRIER_SECRET_VAULT_AUTH_MOUNT") or "kubernetes").strip("/")
        h = {"X-Vault-Namespace": self.namespace} if self.namespace else {}
        r = request("POST", f"{self.addr}/v1/auth/{mount}/login", what="Vault Kubernetes login", http=self.http,
                    json={"role": e["FARRIER_SECRET_VAULT_ROLE"], "jwt": jwt}, headers=h)
        self._set(json_body(r, "Vault login").get("auth") or {})

    def _renew(self) -> None:
        r = request("POST", f"{self.addr}/v1/auth/token/renew-self", what="Vault token renewal", http=self.http,
                    headers=self.headers(self._token), json={}, retries=1)
        self._set(json_body(r, "Vault renewal").get("auth") or {})
