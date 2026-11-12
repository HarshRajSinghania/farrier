"""Google Cloud DNS. A service-account JSON key is exchanged for an OAuth token with a signed JWT (RFC 7523).

credentials: service_account  (file:/path/to/key.json, or env: holding the JSON)
options:     project (default: project_id from the key)
"""
from __future__ import annotations

import json
import time

from farrier.dns.base import (
    DnsConfigError,
    DnsError,
    RRsetProvider,
    Zone,
    norm,
    quote_txt,
    unquote_txt,
)
from farrier.security.cloud_auth.google import DNS_SCOPE as SCOPE
from farrier.security.cloud_auth.google import (
    TOKEN_URI,
    jwt_bearer_form,
    service_account_jwt,
)

API = "https://dns.googleapis.com/dns/v1"
__all__ = ["Google", "SCOPE", "service_account_jwt"]   # the JWT signer lives in farrier.cloud_auth.google


class Google(RRsetProvider):
    name = "google"
    required = ("service_account",)
    options_known = ("project",)
    _token: tuple[str, float] | None = None

    def _sa(self) -> dict:
        try:
            sa = json.loads(self.secret("service_account"))
            self._redact.add(sa["private_key"])
            return sa
        except (ValueError, KeyError, TypeError):
            raise DnsConfigError(f"dns account {self.account!r}: service_account is not a service-account JSON key") from None

    def _project(self, sa=None) -> str:
        return self.opts.get("project") or (sa or self._sa()).get("project_id") or ""

    def _bearer(self) -> str:
        if self._token and self._token[1] > time.time() + 120:
            return self._token[0]
        sa = self._sa()
        r = self.request("POST", sa.get("token_uri", TOKEN_URI), data=jwt_bearer_form(sa, SCOPE))
        j = r.json()
        self._redact.add(j["access_token"])
        self._token = (j["access_token"], time.time() + int(j.get("expires_in", 3600)))
        return self._token[0]

    def _call(self, method, path, **kw):
        project = self._project()
        if not project:
            raise DnsConfigError(f"dns account {self.account!r}: no Google Cloud project configured")
        return self.request(method, f"{API}/projects/{project}{path}",
                            headers={"Authorization": f"Bearer {self._bearer()}"}, **kw)

    def list_zones(self) -> list[Zone]:
        zones, token = [], None
        while True:
            j = self._call("GET", "/managedZones", params={"pageToken": token} if token else None).json()
            zones += [Zone(norm(z["dnsName"]), z["name"]) for z in j.get("managedZones", [])
                      if z.get("visibility", "public") == "public"]
            token = j.get("nextPageToken")
            if not token:
                return zones

    def zone_id(self, name: str) -> str:
        j = self._call("GET", "/managedZones", params={"dnsName": norm(name) + "."}).json()
        for z in j.get("managedZones", []):
            if z.get("visibility", "public") == "public":
                return z["name"]
        raise DnsError(f"{self.label}: no public managed zone for {name}")

    def _get(self, zone, fqdn):
        j = self._call("GET", f"/managedZones/{zone.id}/rrsets", params={"name": fqdn + ".", "type": "TXT"}).json()
        for rs in j.get("rrsets", []):
            if norm(rs["name"]) == fqdn and rs["type"] == "TXT":
                self._ttls[fqdn] = rs.get("ttl", self.ttl)
                return [unquote_txt(v) for v in rs.get("rrdatas", [])]
        return []

    def _rrset(self, fqdn, values, ttl):
        return {"name": fqdn + ".", "type": "TXT", "ttl": ttl, "rrdatas": [quote_txt(v) for v in values]}

    def _change(self, zone, fqdn, additions, deletions):
        body = {"kind": "dns#change"}
        if additions:
            body["additions"] = [self._rrset(fqdn, additions, self.ttl)]
        if deletions:  # deletions must match the live rrset exactly (atomic compare-and-swap)
            body["deletions"] = [self._rrset(fqdn, deletions, self._ttls.get(fqdn, self.ttl))]
        self._call("POST", f"/managedZones/{zone.id}/changes", json=body)

    def _put(self, zone, fqdn, values, current):
        self._change(zone, fqdn, values, current)

    def _remove(self, zone, fqdn, current):
        self._change(zone, fqdn, [], current)
