"""OVHcloud DNS (API 1.0). Requests are signed: "$1$" + SHA1(AS+CK+METHOD+URL+BODY+TS), with the
timestamp taken from the server clock (/auth/time) so local clock drift does not break signing.

credentials: application_key, application_secret, consumer_key
options:     endpoint: ovh-eu (default) | ovh-ca | ovh-us | a full https URL
"""
from __future__ import annotations

import hashlib
import json
import time

from ..base import RecordProvider, Zone, norm, relative, unquote_txt

ENDPOINTS = {"ovh-eu": "https://eu.api.ovh.com/1.0", "ovh-ca": "https://ca.api.ovh.com/1.0",
             "ovh-us": "https://api.us.ovhcloud.com/1.0"}


def ovh_signature(app_secret: str, consumer_key: str, method: str, url: str, body: str, ts: int) -> str:
    raw = "+".join([app_secret, consumer_key, method, url, body, str(ts)])
    return "$1$" + hashlib.sha1(raw.encode()).hexdigest()


class OVH(RecordProvider):
    name = "ovh"
    required = ("application_key", "application_secret", "consumer_key")
    options_known = ("endpoint",)
    _delta: int | None = None

    @property
    def base(self) -> str:
        ep = self.opts.get("endpoint", "ovh-eu")
        return ENDPOINTS.get(ep, ep).rstrip("/")

    def _call(self, method, path, payload=None, allow=()):
        if self._delta is None:
            self._delta = int(self.request("GET", f"{self.base}/auth/time").text) - int(time.time())
        url = self.base + path
        body = json.dumps(payload) if payload is not None else ""
        ts = int(time.time()) + self._delta
        headers = {"X-Ovh-Application": self.secret("application_key"),
                   "X-Ovh-Consumer": self.secret("consumer_key"), "X-Ovh-Timestamp": str(ts),
                   "X-Ovh-Signature": ovh_signature(self.secret("application_secret"), self.secret("consumer_key"),
                                                    method, url, body, ts)}
        if body:
            headers["Content-Type"] = "application/json"
        return self.request(method, url, headers=headers, content=body.encode() if body else None, allow=allow)

    def list_zones(self) -> list[Zone]:
        return [Zone(norm(z), norm(z)) for z in self._call("GET", "/domain/zone").json()]

    def _records(self, zone, fqdn):
        sub = relative(fqdn, zone.name)
        ids = self._call("GET", f"/domain/zone/{zone.name}/record?fieldType=TXT&subDomain={sub}").json()
        out = []
        for rid in ids:
            r = self._call("GET", f"/domain/zone/{zone.name}/record/{rid}").json()
            out.append((str(rid), unquote_txt(r.get("target", ""))))
        return out

    def _create(self, zone, fqdn, value):
        self._call("POST", f"/domain/zone/{zone.name}/record",
                   {"fieldType": "TXT", "subDomain": relative(fqdn, zone.name), "target": value, "ttl": self.ttl})
        self._call("POST", f"/domain/zone/{zone.name}/refresh")

    def _delete(self, zone, fqdn, record_id):
        self._call("DELETE", f"/domain/zone/{zone.name}/record/{record_id}", allow=(404,))
        self._call("POST", f"/domain/zone/{zone.name}/refresh")
