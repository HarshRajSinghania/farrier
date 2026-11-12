"""Cloudflare (API v4). Credentials: api_token (scoped "Zone.DNS:Edit"), or legacy api_key + email."""
from __future__ import annotations

from farrier.dns.base import DnsError, RecordProvider, Zone, norm, unquote_txt

API = "https://api.cloudflare.com/client/v4"


class Cloudflare(RecordProvider):
    name = "cloudflare"
    optional = ("api_token", "api_key", "email")
    default_ttl = 120

    def _headers(self) -> dict:
        if self.has_secret("api_token"):
            return {"Authorization": f"Bearer {self.secret('api_token')}"}
        return {"X-Auth-Email": self.secret("email"), "X-Auth-Key": self.secret("api_key")}

    def _call(self, method, path, **kw):
        r = self.request(method, API + path, headers=self._headers(), **kw)
        j = r.json()
        if not j.get("success", False):
            codes = ",".join(str(e.get("code")) for e in j.get("errors", []))
            raise DnsError(f"{self.label}: {method} {path} failed (errors {codes})")
        return j

    def list_zones(self) -> list[Zone]:
        zones, page = [], 1
        while True:
            j = self._call("GET", "/zones", params={"per_page": 50, "page": page})
            zones += [Zone(norm(z["name"]), z["id"]) for z in j["result"]]
            if page >= j.get("result_info", {}).get("total_pages", 1):
                return zones
            page += 1

    def zone_id(self, name: str) -> str:
        j = self._call("GET", "/zones", params={"name": norm(name)})
        if not j["result"]:
            raise DnsError(f"{self.label}: zone {name} not found")
        return j["result"][0]["id"]

    def _records(self, zone, fqdn):
        j = self._call("GET", f"/zones/{zone.id}/dns_records", params={"type": "TXT", "name": fqdn, "per_page": 100})
        return [(r["id"], unquote_txt(r["content"])) for r in j["result"] if norm(r["name"]) == fqdn]

    def _create(self, zone, fqdn, value):
        self._call("POST", f"/zones/{zone.id}/dns_records",
                   json={"type": "TXT", "name": fqdn, "content": value, "ttl": self.ttl})

    def _delete(self, zone, fqdn, record_id):
        self._call("DELETE", f"/zones/{zone.id}/dns_records/{record_id}")
