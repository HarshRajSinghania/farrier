"""AWS: SigV4 signing and the credential chain, without boto3.

Credentials, first match wins (platform identity first; long-lived keys only when set explicitly):

  1. AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY [+ AWS_SESSION_TOKEN]
  2. IRSA: AWS_WEB_IDENTITY_TOKEN_FILE + AWS_ROLE_ARN -> STS AssumeRoleWithWebIdentity
     (AWS_ROLE_SESSION_NAME optional; the token file is re-read on every refresh, kubelet rotates it)
  3. ECS task role / EKS Pod Identity: AWS_CONTAINER_CREDENTIALS_RELATIVE_URI or _FULL_URI, with
     AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE (or _TOKEN) as the Authorization header when set
  4. EC2 instance profile through IMDSv2 (AWS_EC2_METADATA_DISABLED=true skips it)

Temporary credentials are cached until 5 minutes before they expire.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import threading
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

from .http import CloudConfigError, CloudError, TokenCache, json_body, request

STS_NS = {"s": "https://sts.amazonaws.com/doc/2011-06-15/"}
IMDS = "http://169.254.169.254"
ECS_HOST = "http://169.254.170.2"
REGION = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d$")


# ---- SigV4 ---------------------------------------------------------------------------------------
def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def signing_key(secret_key: str, date: str, region: str, service: str) -> bytes:
    k = _hmac(("AWS4" + secret_key).encode(), date)
    k = _hmac(k, region)
    k = _hmac(k, service)
    return _hmac(k, "aws4_request")


def sigv4_headers(method: str, url: str, headers: dict, body: bytes, access_key: str, secret_key: str,
                  region: str, service: str, amz_date: str | None = None, session_token: str | None = None) -> dict:
    """Return `headers` plus X-Amz-Date, [X-Amz-Security-Token] and Authorization (AWS SigV4)."""
    amz_date = amz_date or datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    parts = urlsplit(url)
    out = dict(headers)
    out["X-Amz-Date"] = amz_date
    if session_token:
        out["X-Amz-Security-Token"] = session_token
    canon_h = {k.lower().strip(): " ".join(str(v).split()) for k, v in out.items()}
    canon_h["host"] = parts.netloc
    signed = ";".join(sorted(canon_h))
    q = sorted(parse_qsl(parts.query, keep_blank_values=True))
    canon_q = "&".join(f"{quote(k, safe='-_.~')}={quote(v, safe='-_.~')}" for k, v in q)
    creq = "\n".join([method, quote(parts.path or "/", safe="/-_.~%"), canon_q,
                      "".join(f"{k}:{canon_h[k]}\n" for k in sorted(canon_h)), signed,
                      out.get("x-amz-content-sha256") or hashlib.sha256(body).hexdigest()])
    scope = f"{amz_date[:8]}/{region}/{service}/aws4_request"
    sts = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(creq.encode()).hexdigest()])
    sig = hmac.new(signing_key(secret_key, amz_date[:8], region, service), sts.encode(), hashlib.sha256).hexdigest()
    out["Authorization"] = f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed}, Signature={sig}"
    return out


# ---- credentials ---------------------------------------------------------------------------------
@dataclass(frozen=True)
class AwsCredentials:
    access_key: str
    secret_key: str = field(repr=False)
    token: str | None = field(default=None, repr=False)
    expires: float | None = None
    source: str = "env"


def _epoch(iso: str | None) -> float | None:
    if not iso:
        return None
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


class AwsCredentialProvider:
    def __init__(self, env=None, http=None):
        self.env = os.environ if env is None else env
        self.http = http
        self._cache = TokenCache(margin=300)

    def get(self) -> AwsCredentials:
        return self._cache.get("creds", self._resolve)

    def clear(self) -> None:
        self._cache.clear()

    def _resolve(self) -> tuple[AwsCredentials, float | None]:
        e = self.env
        if e.get("AWS_ACCESS_KEY_ID") and e.get("AWS_SECRET_ACCESS_KEY"):
            return AwsCredentials(e["AWS_ACCESS_KEY_ID"], e["AWS_SECRET_ACCESS_KEY"],
                                  e.get("AWS_SESSION_TOKEN") or None), None
        if e.get("AWS_WEB_IDENTITY_TOKEN_FILE") and e.get("AWS_ROLE_ARN"):
            c = self._web_identity()
        elif e.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") or e.get("AWS_CONTAINER_CREDENTIALS_FULL_URI"):
            c = self._container()
        elif str(e.get("AWS_EC2_METADATA_DISABLED", "")).lower() != "true":
            c = self._imds()
        else:
            raise CloudConfigError("no AWS credentials: run with IRSA/EKS Pod Identity, an ECS task role or an "
                                   "EC2 instance profile, or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
        return c, c.expires

    def _web_identity(self) -> AwsCredentials:
        e = self.env
        try:
            with open(e["AWS_WEB_IDENTITY_TOKEN_FILE"]) as f:
                token = f.read().strip()
        except OSError as err:
            raise CloudConfigError(f"AWS_WEB_IDENTITY_TOKEN_FILE cannot be read ({type(err).__name__})") from None
        region = e.get("AWS_REGION") or e.get("AWS_DEFAULT_REGION")
        host = f"https://sts.{region}.amazonaws.com/" if region else "https://sts.amazonaws.com/"
        form = {"Action": "AssumeRoleWithWebIdentity", "Version": "2011-06-15", "RoleArn": e["AWS_ROLE_ARN"],
                "RoleSessionName": e.get("AWS_ROLE_SESSION_NAME") or "farrier", "WebIdentityToken": token,
                "DurationSeconds": "3600"}
        r = request("POST", host, what="STS AssumeRoleWithWebIdentity (AWS_ROLE_ARN)", http=self.http,
                    content=urlencode(form).encode(),
                    headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/xml"})
        c = ET.fromstring(r.content).find(".//s:Credentials", STS_NS)
        if c is None:
            raise CloudError("STS AssumeRoleWithWebIdentity returned no credentials")
        get = lambda k: c.findtext(f"s:{k}", namespaces=STS_NS)  # noqa: E731
        return AwsCredentials(get("AccessKeyId"), get("SecretAccessKey"), get("SessionToken"),
                              _epoch(get("Expiration")), "web-identity")

    def _container(self) -> AwsCredentials:
        e = self.env
        url = e.get("AWS_CONTAINER_CREDENTIALS_FULL_URI") or ECS_HOST + e["AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"]
        headers = {}
        if e.get("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"):
            try:
                with open(e["AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"]) as f:
                    headers["Authorization"] = f.read().strip()
            except OSError as err:
                raise CloudConfigError("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE cannot be read "
                                       f"({type(err).__name__})") from None
        elif e.get("AWS_CONTAINER_AUTHORIZATION_TOKEN"):
            headers["Authorization"] = e["AWS_CONTAINER_AUTHORIZATION_TOKEN"]
        j = json_body(request("GET", url, what="ECS/EKS container credentials", http=self.http, headers=headers),
                      "container credentials")
        return AwsCredentials(j["AccessKeyId"], j["SecretAccessKey"], j.get("Token"), _epoch(j.get("Expiration")),
                              "container")

    def _imds(self) -> AwsCredentials:
        base = (self.env.get("AWS_EC2_METADATA_SERVICE_ENDPOINT") or IMDS).rstrip("/")
        what = "EC2 instance metadata (IMDSv2)"
        tok = request("PUT", f"{base}/latest/api/token", what=what, http=self.http, retries=2,
                      headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"}).text
        h = {"X-aws-ec2-metadata-token": tok}
        role = request("GET", f"{base}/latest/meta-data/iam/security-credentials/", what=what, http=self.http,
                       headers=h).text.strip().splitlines()
        if not role:
            raise CloudConfigError("this EC2 instance has no instance profile; attach an IAM role")
        j = json_body(request("GET", f"{base}/latest/meta-data/iam/security-credentials/{role[0]}", what=what,
                              http=self.http, headers=h), what)
        return AwsCredentials(j["AccessKeyId"], j["SecretAccessKey"], j.get("Token"), _epoch(j.get("Expiration")),
                              "imds")


_default: AwsCredentialProvider | None = None
_default_lock = threading.Lock()


def default_provider() -> AwsCredentialProvider:
    global _default
    with _default_lock:
        if _default is None:
            _default = AwsCredentialProvider()
        return _default


def region_for(setting: str, value: str | None, env=None) -> str:
    """The configured region, else AWS_REGION / AWS_DEFAULT_REGION; an error names ``setting``."""
    env = os.environ if env is None else env
    region = (value or env.get("AWS_REGION") or env.get("AWS_DEFAULT_REGION") or "").strip()
    if not region:
        raise CloudConfigError(f"{setting} is not set (nor AWS_REGION): name the AWS region, e.g. eu-west-1")
    if not REGION.match(region):
        raise CloudConfigError(f"{setting}={region!r} is not an AWS region name")
    return region


def signed_request(method: str, url: str, *, service: str, region: str, what: str, body: bytes = b"",
                   headers: dict | None = None, creds: AwsCredentialProvider | None = None, http=None, **kw):
    """Sign with the current credentials and send (retries re-use the signature: valid for 15 minutes)."""
    c = (creds or default_provider()).get()
    h = sigv4_headers(method, url, headers or {}, body, c.access_key, c.secret_key, region, service,
                      session_token=c.token)
    return request(method, url, what=what, http=http, content=body or None, headers=h, **kw)


def json_call(service: str, target: str, payload: dict, *, region: str, what: str, endpoint: str | None = None,
              creds: AwsCredentialProvider | None = None, http=None, allow=()) -> dict:
    """An AWS JSON-1.1 protocol call (Secrets Manager, KMS, EventBridge). Raises CloudError with ``code``."""
    url = endpoint or f"https://{service}.{region}.amazonaws.com/"
    prefix = {"secretsmanager": "secretsmanager", "kms": "TrentService", "events": "AWSEvents"}[service]
    body = json.dumps(payload).encode()
    r = signed_request("POST", url, service=service, region=region, what=what, body=body, creds=creds, http=http,
                       headers={"Content-Type": "application/x-amz-json-1.1", "X-Amz-Target": f"{prefix}.{target}"},
                       allow=allow)
    return json_body(r, what) if r.content else {}
