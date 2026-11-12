"""Scaleway Domains & DNS (domain/v2beta1). credentials: secret_key (IAM API key secret)."""
from __future__ import annotations

from ..base import Provider, Zone, norm, quote_txt, relative, unquote_txt

API = "https://api.scaleway.com/domain/v2beta1"


class Scaleway(Provider):
    name = "scaleway"
    required = ("secret_key",)

    def _h(self):
        return {"X-Auth-Token": self.secret("secret_key")}

    def list_zones(self) -> list[Zone]:
        zones, page = [], 1
        while True:
            j = self.request("GET", f"{API}/dns-zones", headers=self._h(), params={"page": page, "page_size": 100}).json()
            for z in j.get("dns_zones", []):
                name = norm(f"{z['subdomain']}.{z['domain']}" if z.get("subdomain") else z["domain"])
                zones.append(Zone(name, name))
            if page * 100 >= j.get("total_count", 0):
                return zones
            page += 1

    def _values(self, zone, rel):
        j = self.request("GET", f"{API}/dns-zones/{zone.name}/records", headers=self._h(),
                         params={"name": rel, "type": "TXT", "page_size": 100}).json()
        return [unquote_txt(r["data"]) for r in j.get("records", []) if r.get("name", "") == rel]

    def _patch(self, zone, change):
        self.request("PATCH", f"{API}/dns-zones/{zone.name}/records", headers=self._h(),
                     json={"changes": [change], "return_all_records": False})

    def present(self, fqdn, value):
        zone = self.find_zone(fqdn)
        rel = relative(fqdn, zone.name)
        with self.lock(fqdn):
            if value in self._values(zone, rel):
                return
            self._patch(zone, {"add": {"records": [{"name": rel, "type": "TXT", "data": quote_txt(value),
                                                    "ttl": self.ttl, "priority": 0}]}})

    def cleanup(self, fqdn, value):
        zone = self.find_zone(fqdn)
        rel = relative(fqdn, zone.name)
        with self.lock(fqdn):
            if value in self._values(zone, rel):
                self._patch(zone, {"delete": {"id_fields": {"name": rel, "type": "TXT", "data": quote_txt(value)}}})
