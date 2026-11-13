"""Azure: Microsoft Entra ID access tokens without azure-identity.

Source, first that applies wins:

  1. Workload identity (AKS): AZURE_FEDERATED_TOKEN_FILE + AZURE_CLIENT_ID + AZURE_TENANT_ID
     -> client-credentials grant with the projected token as client assertion (re-read on every refresh)
  2. Managed identity
       - App Service / Container Apps / Functions: IDENTITY_ENDPOINT + IDENTITY_HEADER
       - VMs, VM scale sets: IMDS at 169.254.169.254 (AZURE_CLIENT_ID selects a user-assigned identity)
  3. Service principal: AZURE_CLIENT_SECRET + AZURE_CLIENT_ID + AZURE_TENANT_ID (also used when IMDS
     cannot be reached, so a developer machine with a secret still works)

AZURE_AUTHORITY_HOST changes the login host (sovereign clouds). Tokens are cached per scope until 5
minutes before they expire. Scopes: Key Vault https://vault.azure.net/.default, Blob storage
https://storage.azure.com/.default, Event Grid https://eventgrid.azure.net/.default,
Resource Manager https://management.azure.com/.default.
"""
from __future__ import annotations

import os
import threading
import time

from farrier.security.cloud_auth.http import (
    CloudConfigError,
    CloudError,
    TokenCache,
    json_body,
    request,
)

AUTHORITY = "https://login.microsoftonline.com"
IMDS = "http://169.254.169.254/metadata/identity/oauth2/token"
VAULT_SCOPE = "https://vault.azure.net/.default"
STORAGE_SCOPE = "https://storage.azure.com/.default"
EVENTGRID_SCOPE = "https://eventgrid.azure.net/.default"
ARM_SCOPE = "https://management.azure.com/.default"
ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


def token_url(authority: str, tenant: str) -> str:
    return f"{authority.rstrip('/')}/{tenant}/oauth2/v2.0/token"


def client_credentials_form(client_id: str, client_secret: str, scope: str) -> dict:
    """The form a service principal posts to the v2.0 token endpoint."""
    return {"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret,
            "scope": scope}


def client_assertion_form(client_id: str, assertion: str, scope: str) -> dict:
    return {"grant_type": "client_credentials", "client_id": client_id, "client_assertion_type": ASSERTION_TYPE,
            "client_assertion": assertion, "scope": scope}


def token_expiry(j: dict) -> float:
    """Absolute expiry from either expires_in (Entra ID) or expires_on (managed identity)."""
    if j.get("expires_on"):
        try:
            return float(j["expires_on"])
        except (TypeError, ValueError):
            pass
    return time.time() + int(j.get("expires_in", 3600))


class AzureTokenProvider:
    def __init__(self, env=None, http=None):
        self.env = os.environ if env is None else env
        self.http = http
        self._cache = TokenCache(margin=300)

    def token(self, scope: str) -> str:
        return self._cache.get(scope, lambda: self._fetch(scope))

    def clear(self) -> None:
        self._cache.clear()

    @property
    def authority(self) -> str:
        return (self.env.get("AZURE_AUTHORITY_HOST") or AUTHORITY).rstrip("/")

    def _fetch(self, scope: str) -> tuple[str, float]:
        e = self.env
        if e.get("AZURE_FEDERATED_TOKEN_FILE"):
            for k in ("AZURE_CLIENT_ID", "AZURE_TENANT_ID"):
                if not e.get(k):
                    raise CloudConfigError(f"AZURE_FEDERATED_TOKEN_FILE is set but {k} is not (workload identity)")
            try:
                with open(e["AZURE_FEDERATED_TOKEN_FILE"]) as f:
                    assertion = f.read().strip()
            except OSError as err:
                raise CloudConfigError(f"AZURE_FEDERATED_TOKEN_FILE cannot be read ({type(err).__name__})") from None
            return self._entra(client_assertion_form(e["AZURE_CLIENT_ID"], assertion, scope), "workload identity")
        resource = scope.removesuffix("/.default")
        if e.get("IDENTITY_ENDPOINT") and e.get("IDENTITY_HEADER"):
            params = {"api-version": "2019-08-01", "resource": resource}
            if e.get("AZURE_CLIENT_ID"):
                params["client_id"] = e["AZURE_CLIENT_ID"]
            r = request("GET", e["IDENTITY_ENDPOINT"], what="Azure managed identity (IDENTITY_ENDPOINT)",
                        http=self.http, params=params, headers={"X-IDENTITY-HEADER": e["IDENTITY_HEADER"]})
            j = json_body(r, "managed identity token")
            return j["access_token"], token_expiry(j)
        try:
            params = {"api-version": "2018-02-01", "resource": resource}
            if e.get("AZURE_CLIENT_ID"):
                params["client_id"] = e["AZURE_CLIENT_ID"]
            r = request("GET", IMDS, what="Azure managed identity (IMDS)", http=self.http, retries=2,
                        params=params, headers={"Metadata": "true"})
            j = json_body(r, "managed identity token")
            return j["access_token"], token_expiry(j)
        except CloudError as imds_error:
            if e.get("AZURE_CLIENT_SECRET") and e.get("AZURE_CLIENT_ID") and e.get("AZURE_TENANT_ID"):
                return self._entra(client_credentials_form(e["AZURE_CLIENT_ID"], e["AZURE_CLIENT_SECRET"], scope),
                                   "service principal (AZURE_CLIENT_SECRET)")
            raise CloudConfigError("no Azure identity: use AKS workload identity (AZURE_FEDERATED_TOKEN_FILE, "
                                   "AZURE_CLIENT_ID, AZURE_TENANT_ID), a managed identity, or set AZURE_CLIENT_ID, "
                                   f"AZURE_TENANT_ID and AZURE_CLIENT_SECRET ({imds_error})") from None

    def _entra(self, form: dict, what: str) -> tuple[str, float]:
        r = request("POST", token_url(self.authority, self.env["AZURE_TENANT_ID"]), what=f"Azure token: {what}",
                    http=self.http, data=form)
        j = json_body(r, "Azure token")
        return j["access_token"], token_expiry(j)


_default: AzureTokenProvider | None = None
_lock = threading.Lock()


def default_provider() -> AzureTokenProvider:
    global _default
    with _lock:
        if _default is None:
            _default = AzureTokenProvider()
        return _default
