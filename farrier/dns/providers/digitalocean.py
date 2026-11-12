"""DigitalOcean DNS (API v2). credentials: api_token."""
from __future__ import annotations

from farrier.dns.base import RecordProvider, Zone, norm, relative, unquote_txt

API = "https://api.digitalocean.com/v2"


class DigitalOcean(RecordProvider):
    name = "digitalocean"
    required = ("api_token",)
    default_ttl = 30  # DigitalOcean's minimum

    def _h(self):
        return {"Authorization": f"Bearer {self.secret('api_token')}"}

    def list_zones(self) -> list[Zone]:
        zones, url = [], f"{API}/domains?per_page=200"
        while url:
            j = self.request("GET", url, headers=self._h()).json()
            zones += [Zone(norm(d["name"]), norm(d["name"])) for d in j.get("domains", [])]
            url = j.get("links", {}).get("pages", {}).get("next")
        return zones

    def _records(self, zone, fqdn):
        rel = relative(fqdn, zone.name) or "@"
        out, url = [], f"{API}/domains/{zone.name}/records"
        params = {"type": "TXT", "name": fqdn, "per_page": 200}
        while url:
            j = self.request("GET", url, headers=self._h(), params=params).json()
            out += [(str(r["id"]), unquote_txt(r["data"])) for r in j.get("domain_records", [])
                    if r.get("type") == "TXT" and r.get("name") == rel]
            url, params = j.get("links", {}).get("pages", {}).get("next"), None
        return out

    def _create(self, zone, fqdn, value):
        self.request("POST", f"{API}/domains/{zone.name}/records", headers=self._h(),
                     json={"type": "TXT", "name": relative(fqdn, zone.name) or "@", "data": value, "ttl": self.ttl})

    def _delete(self, zone, fqdn, record_id):
        self.request("DELETE", f"{API}/domains/{zone.name}/records/{record_id}", headers=self._h(), allow=(404,))
