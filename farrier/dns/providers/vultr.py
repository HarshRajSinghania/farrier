"""Vultr DNS (API v2). credentials: api_key."""
from __future__ import annotations

from farrier.dns.base import (
    RecordProvider,
    Zone,
    norm,
    quote_txt,
    relative,
    unquote_txt,
)

API = "https://api.vultr.com/v2"


class Vultr(RecordProvider):
    name = "vultr"
    required = ("api_key",)
    default_ttl = 120

    def _h(self):
        return {"Authorization": f"Bearer {self.secret('api_key')}"}

    def _pages(self, url, key):
        out, cursor = [], None
        while True:
            params = {"per_page": 500, **({"cursor": cursor} if cursor else {})}
            j = self.request("GET", url, headers=self._h(), params=params).json()
            out += j.get(key, [])
            cursor = j.get("meta", {}).get("links", {}).get("next")
            if not cursor:
                return out

    def list_zones(self) -> list[Zone]:
        return [Zone(norm(d["domain"]), norm(d["domain"])) for d in self._pages(f"{API}/domains", "domains")]

    def _records(self, zone, fqdn):
        rel = relative(fqdn, zone.name)
        return [(r["id"], unquote_txt(r["data"])) for r in self._pages(f"{API}/domains/{zone.name}/records", "records")
                if r["type"] == "TXT" and r["name"] == rel]

    def _create(self, zone, fqdn, value):
        self.request("POST", f"{API}/domains/{zone.name}/records", headers=self._h(),
                     json={"type": "TXT", "name": relative(fqdn, zone.name), "data": quote_txt(value), "ttl": self.ttl})

    def _delete(self, zone, fqdn, record_id):
        self.request("DELETE", f"{API}/domains/{zone.name}/records/{record_id}", headers=self._h(), allow=(404,))
