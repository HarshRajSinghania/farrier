"""Google Cloud: OAuth access tokens without google-auth.

Source, first match wins:

  1. GOOGLE_APPLICATION_CREDENTIALS pointing at
       - a service-account key  -> signed JWT exchanged at its token_uri (RFC 7523)
       - an external_account    -> workload identity federation: the subject token (credential_source
         file or url) is exchanged at STS (RFC 8693), then, if service_account_impersonation_url is set,
         for a service-account token
       - an authorized_user     -> refresh-token grant (developer machines)
  2. the metadata server (GKE Workload Identity, GCE, Cloud Run): metadata.google.internal
     (GCE_METADATA_HOST overrides), header Metadata-Flavor: Google

Tokens are cached per scope set until 5 minutes before they expire.
"""
from __future__ import annotations

import base64
import json
import os
import threading
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from farrier.security.cloud_auth.http import (
    CloudConfigError,
    CloudError,
    TokenCache,
    json_body,
    request,
)

CLOUD_PLATFORM = "https://www.googleapis.com/auth/cloud-platform"
DNS_SCOPE = "https://www.googleapis.com/auth/ndev.clouddns.readwrite"
TOKEN_URI = "https://oauth2.googleapis.com/token"
STS_URI = "https://sts.googleapis.com/v1/token"


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def service_account_jwt(sa: dict, now: int, scope: str = DNS_SCOPE) -> str:
    """The RFC 7523 assertion a service-account key signs to obtain an access token."""
    header = {"alg": "RS256", "typ": "JWT"}
    if sa.get("private_key_id"):
        header["kid"] = sa["private_key_id"]
    aud = sa.get("token_uri", TOKEN_URI)
    claims = {"iss": sa["client_email"], "scope": scope, "aud": aud, "iat": now, "exp": now + 3600}
    signing_input = f"{_b64u(json.dumps(header, separators=(',', ':')).encode())}." \
                    f"{_b64u(json.dumps(claims, separators=(',', ':')).encode())}"
    key = serialization.load_pem_private_key(sa["private_key"].encode(), None)
    sig = key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input}.{_b64u(sig)}"


def jwt_bearer_form(sa: dict, scope: str, now: int | None = None) -> dict:
    return {"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": service_account_jwt(sa, int(now if now is not None else time.time()), scope)}


class GoogleTokenProvider:
    def __init__(self, env=None, http=None):
        self.env = os.environ if env is None else env
        self.http = http
        self._cache = TokenCache(margin=300)
        self._info: dict | None = None

    def token(self, scope: str = CLOUD_PLATFORM) -> str:
        return self._cache.get(scope, lambda: self._fetch(scope))

    def clear(self) -> None:
        self._cache.clear()
        self._info = None

    # ---- sources ---------------------------------------------------------------------------------
    def _credentials_file(self) -> dict | None:
        path = self.env.get("GOOGLE_APPLICATION_CREDENTIALS")
        if not path:
            return None
        if self._info is None:
            try:
                with open(path) as f:
                    self._info = json.load(f)
            except (OSError, ValueError) as e:
                raise CloudConfigError(f"GOOGLE_APPLICATION_CREDENTIALS ({path}) is not a readable credentials "
                                       f"JSON file ({type(e).__name__})") from None
        return self._info

    def _fetch(self, scope: str) -> tuple[str, float]:
        info = self._credentials_file()
        if info is None:
            return self._metadata(scope)
        kind = info.get("type")
        if kind == "service_account":
            j = json_body(request("POST", info.get("token_uri", TOKEN_URI), what="Google service-account token",
                                  http=self.http, data=jwt_bearer_form(info, scope)), "Google token")
        elif kind == "external_account":
            j = self._external(info, scope)
        elif kind == "authorized_user":
            j = json_body(request("POST", info.get("token_uri", TOKEN_URI), what="Google user token", http=self.http,
                                  data={"grant_type": "refresh_token", "refresh_token": info["refresh_token"],
                                        "client_id": info["client_id"], "client_secret": info["client_secret"]}),
                          "Google token")
        else:
            raise CloudConfigError(f"GOOGLE_APPLICATION_CREDENTIALS has unsupported type {kind!r} (expected "
                                   "service_account, external_account or authorized_user)")
        if "access_token" not in j:
            raise CloudError("Google token endpoint returned no access_token")
        return j["access_token"], time.time() + int(j.get("expires_in", 3600))

    def _subject_token(self, src: dict) -> str:
        if src.get("environment_id"):
            raise CloudConfigError("GOOGLE_APPLICATION_CREDENTIALS: external_account with an AWS/environment "
                                   "credential_source is not supported; use a file or url credential_source")
        if src.get("file"):
            try:
                with open(src["file"]) as f:
                    raw = f.read()
            except OSError as e:
                raise CloudConfigError(f"external_account credential_source.file cannot be read "
                                       f"({type(e).__name__})") from None
        elif src.get("url"):
            raw = request("GET", src["url"], what="workload identity subject token", http=self.http,
                          headers=src.get("headers") or {}).text
        else:
            raise CloudConfigError("GOOGLE_APPLICATION_CREDENTIALS: external_account needs credential_source.file "
                                   "or credential_source.url")
        fmt = src.get("format") or {}
        if fmt.get("type") == "json":
            return str(json.loads(raw)[fmt["subject_token_field_name"]])
        return raw.strip()

    def _external(self, info: dict, scope: str) -> dict:
        form = {"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "audience": info["audience"], "scope": CLOUD_PLATFORM,
                "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "subject_token_type": info["subject_token_type"],
                "subject_token": self._subject_token(info.get("credential_source") or {})}
        j = json_body(request("POST", info.get("token_url", STS_URI), what="Google STS token exchange",
                              http=self.http, data=form), "Google STS")
        imp = info.get("service_account_impersonation_url")
        if not imp:
            return j
        k = json_body(request("POST", imp, what="Google service-account impersonation", http=self.http,
                              headers={"Authorization": f"Bearer {j['access_token']}"},
                              json={"scope": [scope], "lifetime": "3600s"}), "impersonation")
        exp = k.get("expireTime")
        from datetime import datetime
        left = int(datetime.fromisoformat(exp.replace("Z", "+00:00")).timestamp() - time.time()) if exp else 3600
        return {"access_token": k["accessToken"], "expires_in": left}

    def _metadata(self, scope: str) -> tuple[str, float]:
        host = self.env.get("GCE_METADATA_HOST") or "metadata.google.internal"
        url = f"http://{host}/computeMetadata/v1/instance/service-accounts/default/token"
        try:
            r = request("GET", url, what="Google metadata server token", http=self.http, retries=2,
                        params={"scopes": scope}, headers={"Metadata-Flavor": "Google"})
        except CloudError as e:
            raise CloudConfigError("no Google credentials: run on GKE/GCE/Cloud Run with a service account, or set "
                                   f"GOOGLE_APPLICATION_CREDENTIALS ({e})") from None
        j = json_body(r, "Google metadata token")
        return j["access_token"], time.time() + int(j.get("expires_in", 3600))

    def project(self) -> str | None:
        """GOOGLE_CLOUD_PROJECT, else the credentials file's project, else the metadata server's."""
        p = self.env.get("GOOGLE_CLOUD_PROJECT") or self.env.get("GCLOUD_PROJECT")
        if p:
            return p
        info = self._credentials_file()
        if info:
            return info.get("project_id") or info.get("quota_project_id")
        host = self.env.get("GCE_METADATA_HOST") or "metadata.google.internal"
        try:
            return request("GET", f"http://{host}/computeMetadata/v1/project/project-id", http=self.http, retries=1,
                           what="Google metadata project", headers={"Metadata-Flavor": "Google"}).text.strip()
        except CloudError:
            return None


_default: GoogleTokenProvider | None = None
_lock = threading.Lock()


def default_provider() -> GoogleTokenProvider:
    global _default
    with _lock:
        if _default is None:
            _default = GoogleTokenProvider()
        return _default
