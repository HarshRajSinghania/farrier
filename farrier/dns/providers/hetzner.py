"""Hetzner DNS Console (legacy API at dns.hetzner.com; Hetzner is migrating zones into Hetzner Cloud DNS,
see hetzner_cloud). credentials: api_token."""
from __future__ import annotations

from ..base import DnsError, RecordProvider, Zone, norm, relative, unquote_txt

API = "https://dns.hetzner.com/api/v1"


class Hetzner(RecordProvider):
    name = "hetzner"
    required = ("api_token",)

    def _h(self):
        return {"Auth-API-Token": self.secret("api_token")}

    def list_zones(self) -> list[Zone]:
        zones, page = [], 1
        while True:
            j = self.request("GET", f"{API}/zones", headers=self._h(), params={"page": page, "per_page": 100}).json()
            zones += [Zone(norm(z["name"]), z["id"]) for z in j.get("zones", [])]
            if page >= j.get("meta", {}).get("pagination", {}).get("last_page", 1):
                return zones
            page += 1

    def zone_id(self, name):
        j = self.request("GET", f"{API}/zones", headers=self._h(), params={"name": norm(name)}).json()
        for z in j.get("zones", []):
            if norm(z["name"]) == norm(name):
                return z["id"]
        raise DnsError(f"{self.label}: zone {name} not found")

    def _records(self, zone, fqdn):
        rel = relative(fqdn, zone.name) or "@"
        j = self.request("GET", f"{API}/records", headers=self._h(), params={"zone_id": zone.id}).json()
        return [(r["id"], unquote_txt(r["value"])) for r in j.get("records", [])
                if r["type"] == "TXT" and r["name"] == rel]

    def _create(self, zone, fqdn, value):
        self.request("POST", f"{API}/records", headers=self._h(), json={
            "zone_id": zone.id, "type": "TXT", "name": relative(fqdn, zone.name) or "@", "value": value, "ttl": self.ttl})

    def _delete(self, zone, fqdn, record_id):
        self.request("DELETE", f"{API}/records/{record_id}", headers=self._h(), allow=(404,))
