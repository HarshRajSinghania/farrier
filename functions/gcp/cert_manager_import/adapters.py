"""REST adapters for Certificate Manager, Secret Manager and Cloud Storage.

All three go through one ``HttpClient`` port. In production that is
``google.auth.transport.requests.AuthorizedSession`` (OAuth from the function's
service account); tests use a fake. The adapters only build URLs, translate
status codes and decode payloads.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import quote

from farrier_events import GcpSecretRef, GcsObjectRef, PermanentError, TransientError

CERTMANAGER = "https://certificatemanager.googleapis.com/v1"
SECRETMANAGER = "https://secretmanager.googleapis.com/v1"
STORAGE = "https://storage.googleapis.com/storage/v1"
MAX_CHAIN_BYTES = 64 * 1024
TIMEOUT_S = (5, 20)


@dataclass(frozen=True, slots=True)
class HttpResponse:
    status: int
    body: bytes

    def json(self) -> Any:
        try:
            return json.loads(self.body or b"{}")
        except ValueError:
            raise TransientError("response body is not JSON") from None


class HttpClient(Protocol):
    def request(
        self, method: str, url: str, *, params: Mapping[str, str] | None = None, json: Any = None
    ) -> HttpResponse: ...


def raise_for_status(resp: HttpResponse, operation: str) -> None:
    """Never includes the response body: it can echo resource names and be large."""
    if 200 <= resp.status < 300:
        return
    if resp.status in (408, 429) or resp.status >= 500:
        raise TransientError(f"{operation}: HTTP {resp.status}")
    if resp.status == 409:
        # A duplicate delivery created it concurrently: the retry re-reads, then skips or patches.
        raise TransientError(f"{operation}: HTTP 409 conflict")
    raise PermanentError(f"{operation}: HTTP {resp.status}")


class AuthorizedSessionClient:
    """``HttpClient`` over google-auth. Imported lazily so tests need no Google libraries."""

    def __init__(self) -> None:
        import google.auth
        from google.auth.transport.requests import AuthorizedSession

        credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
        self._session = AuthorizedSession(credentials)

    def request(
        self, method: str, url: str, *, params: Mapping[str, str] | None = None, json: Any = None
    ) -> HttpResponse:
        import requests

        try:
            resp = self._session.request(
                method, url, params=params, json=json, timeout=TIMEOUT_S, allow_redirects=False
            )
        except (requests.ConnectionError, requests.Timeout) as exc:
            raise TransientError(f"{method} request failed: {type(exc).__name__}") from None
        return HttpResponse(resp.status_code, resp.content)


class RestCertificateManager:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def get(self, name: str) -> Mapping[str, Any] | None:
        resp = self._http.request("GET", f"{CERTMANAGER}/{name}")
        if resp.status == 404:
            return None
        raise_for_status(resp, "certificatemanager.certificates.get")
        return resp.json()

    def create(self, parent: str, certificate_id: str, body: Mapping[str, Any]) -> Mapping[str, Any]:
        resp = self._http.request(
            "POST", f"{CERTMANAGER}/{parent}/certificates", params={"certificateId": certificate_id}, json=body
        )
        raise_for_status(resp, "certificatemanager.certificates.create")
        return resp.json()

    def patch(self, name: str, body: Mapping[str, Any], update_mask: str) -> Mapping[str, Any]:
        resp = self._http.request("PATCH", f"{CERTMANAGER}/{name}", params={"updateMask": update_mask}, json=body)
        raise_for_status(resp, "certificatemanager.certificates.patch")
        return resp.json()

    def get_operation(self, name: str) -> Mapping[str, Any]:
        resp = self._http.request("GET", f"{CERTMANAGER}/{name}")
        raise_for_status(resp, "certificatemanager.operations.get")
        return resp.json()


class RestSecretManager:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def access(self, ref: GcpSecretRef) -> str:
        resp = self._http.request("GET", f"{SECRETMANAGER}/{ref.name}:access")
        raise_for_status(resp, "secretmanager.versions.access")
        try:
            return base64.b64decode(resp.json()["payload"]["data"]).decode("ascii")
        except (KeyError, ValueError, UnicodeDecodeError):
            raise PermanentError("secret payload is not ASCII PEM") from None


class RestStorage:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def read_text(self, ref: GcsObjectRef) -> str:
        url = f"{STORAGE}/b/{quote(ref.bucket, safe='')}/o/{quote(ref.name, safe='')}"
        resp = self._http.request("GET", url, params={"alt": "media"})
        raise_for_status(resp, "storage.objects.get")
        if len(resp.body) > MAX_CHAIN_BYTES:
            raise PermanentError("chain object is larger than 64 KiB")
        try:
            return resp.body.decode("ascii")
        except UnicodeDecodeError:
            raise PermanentError("chain object is not ASCII PEM") from None
