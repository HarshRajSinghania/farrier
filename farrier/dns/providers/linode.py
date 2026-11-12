"""Linode (Akamai Cloud) DNS Manager (API v4). credentials: api_token."""
from __future__ import annotations

from farrier.dns.base import RecordProvider, Zone, norm, relative, unquote_txt

API = "https://api.linode.com/v4"


class Linode(RecordProvider):
    name = "linode"
    required = ("api_token",)
    default_ttl = 300  # Linode rounds TTLs up to an allowed set; 300 is the smallest

    def _h(self):
        return {"Authorization": f"Bearer {self.secret('api_token')}"}

    def _pages(self, url):
        page, out = 1, []
        while True:
            j = self.request("GET", url, headers=self._h(), params={"page": page, "page_size": 500}).json()
            out += j.get("data", [])
            if page >= j.get("pages", 1):
                return out
            page += 1

    def list_zones(self) -> list[Zone]:
        return [Zone(norm(d["domain"]), str(d["id"])) for d in self._pages(f"{API}/domains")]

    def zone_id(self, name):
        return self._zone_id_from_list(name)

    def _records(self, zone, fqdn):
        rel = relative(fqdn, zone.name)
        return [(str(r["id"]), unquote_txt(r["target"])) for r in self._pages(f"{API}/domains/{zone.id}/records")
                if r["type"] == "TXT" and r["name"] == rel]

    def _create(self, zone, fqdn, value):
        self.request("POST", f"{API}/domains/{zone.id}/records", headers=self._h(),
                     json={"type": "TXT", "name": relative(fqdn, zone.name), "target": value, "ttl_sec": self.ttl})

    def _delete(self, zone, fqdn, record_id):
        self.request("DELETE", f"{API}/domains/{zone.id}/records/{record_id}", headers=self._h(), allow=(404,))
