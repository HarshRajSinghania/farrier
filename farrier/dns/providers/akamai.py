"""Akamai Edge DNS (Config DNS API v2) with EdgeGrid (EG1-HMAC-SHA256) request signing.
credentials (from .edgerc): host, client_token, client_secret, access_token"""
from __future__ import annotations

import base64
import hashlib
import hmac
import uuid
from datetime import UTC, datetime
from urllib.parse import urlsplit

from ..base import RRsetProvider, Zone, norm, quote_txt, unquote_txt

MAX_BODY = 131072


def _b64_hmac(key: bytes, msg: str) -> str:
    return base64.b64encode(hmac.new(key, msg.encode(), hashlib.sha256).digest()).decode()


def edgegrid_authorization(method: str, url: str, body: bytes, client_token: str, client_secret: str,
                           access_token: str, timestamp: str | None = None, nonce: str | None = None) -> str:
    timestamp = timestamp or datetime.now(UTC).strftime("%Y%m%dT%H:%M:%S+0000")
    nonce = nonce or str(uuid.uuid4())
    auth = f"EG1-HMAC-SHA256 client_token={client_token};access_token={access_token};timestamp={timestamp};nonce={nonce};"
    parts = urlsplit(url)
    content_hash = ""
    if method == "POST" and body:
        content_hash = base64.b64encode(hashlib.sha256(body[:MAX_BODY]).digest()).decode()
    path = parts.path + (f"?{parts.query}" if parts.query else "")
    data = "\t".join([method, parts.scheme, parts.netloc, path, "", content_hash, auth])
    signing_key = _b64_hmac(client_secret.encode(), timestamp)
    return auth + "signature=" + _b64_hmac(signing_key.encode(), data)


class Akamai(RRsetProvider):
    name = "akamai"
    required = ("host", "client_token", "client_secret", "access_token")

    def _call(self, method, path, json_body=None, allow=()):
        import json as _json
        host = self.secret("host").removeprefix("https://").rstrip("/")
        url = f"https://{host}{path}"
        body = _json.dumps(json_body).encode() if json_body is not None else b""
        headers = {"Authorization": edgegrid_authorization(method, url, body, self.secret("client_token"),
                                                           self.secret("client_secret"), self.secret("access_token"))}
        if body:
            headers["Content-Type"] = "application/json"
        return self.request(method, url, headers=headers, content=body or None, allow=allow)

    def list_zones(self) -> list[Zone]:
        j = self._call("GET", "/config-dns/v2/zones?showAll=true&types=primary").json()
        return [Zone(norm(z["zone"]), norm(z["zone"])) for z in j.get("zones", [])]

    def _path(self, zone, fqdn):
        return f"/config-dns/v2/zones/{zone.name}/names/{fqdn}/types/TXT"

    def _get(self, zone, fqdn):
        r = self._call("GET", self._path(zone, fqdn), allow=(404,))
        return [] if r.status_code == 404 else [unquote_txt(v) for v in r.json().get("rdata", [])]

    def _put(self, zone, fqdn, values, current):
        body = {"name": fqdn, "type": "TXT", "ttl": self.ttl, "rdata": [quote_txt(v) for v in values]}
        self._call("PUT" if current else "POST", self._path(zone, fqdn), body)

    def _remove(self, zone, fqdn, current):
        self._call("DELETE", self._path(zone, fqdn), allow=(404,))
