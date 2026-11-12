"""Hetzner Cloud DNS (api.hetzner.cloud/v1/zones), the successor of dns.hetzner.com. It is a distinct
RRset API with atomic add_records / remove_records actions, so concurrent orders never clobber each other.
credentials: api_token (a Hetzner Cloud project token with read/write)."""
from __future__ import annotations

from farrier.dns.base import Provider, Zone, norm, quote_txt, relative

API = "https://api.hetzner.cloud/v1"


class HetznerCloud(Provider):
    name = "hetzner-cloud"
    required = ("api_token",)

    def _h(self):
        return {"Authorization": f"Bearer {self.secret('api_token')}"}

    def list_zones(self) -> list[Zone]:
        zones, page = [], 1
        while True:
            j = self.request("GET", f"{API}/zones", headers=self._h(), params={"page": page, "per_page": 50}).json()
            zones += [Zone(norm(z["name"]), str(z["id"])) for z in j.get("zones", [])]
            nxt = j.get("meta", {}).get("pagination", {}).get("next_page")
            if not nxt:
                return zones
            page = nxt

    def _rrset_url(self, fqdn):
        zone = self.find_zone(fqdn)
        return f"{API}/zones/{zone.id or zone.name}/rrsets/{relative(fqdn, zone.name) or '@'}/TXT"

    def present(self, fqdn, value):
        self.request("POST", f"{self._rrset_url(fqdn)}/actions/add_records", headers=self._h(),
                     json={"ttl": self.ttl, "records": [{"value": quote_txt(value)}]})

    def cleanup(self, fqdn, value):
        self.request("POST", f"{self._rrset_url(fqdn)}/actions/remove_records", headers=self._h(),
                     json={"records": [{"value": quote_txt(value)}]}, allow=(404,))
