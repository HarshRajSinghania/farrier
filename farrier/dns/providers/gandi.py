"""Gandi LiveDNS (API v5). credentials: api_token (Personal Access Token) or legacy api_key."""
from __future__ import annotations

from farrier.dns.base import RRsetProvider, Zone, norm, quote_txt, relative, unquote_txt

API = "https://api.gandi.net/v5/livedns"


class Gandi(RRsetProvider):
    name = "gandi"
    optional = ("api_token", "api_key")
    default_ttl = 300  # LiveDNS minimum

    def _h(self):
        if self.has_secret("api_token"):
            return {"Authorization": f"Bearer {self.secret('api_token')}"}
        return {"Authorization": f"Apikey {self.secret('api_key')}"}

    def list_zones(self) -> list[Zone]:
        return [Zone(norm(d["fqdn"]), norm(d["fqdn"]))
                for d in self.request("GET", f"{API}/domains", headers=self._h()).json()]

    def _url(self, zone, fqdn):
        return f"{API}/domains/{zone.name}/records/{relative(fqdn, zone.name) or '@'}/TXT"

    def _get(self, zone, fqdn):
        r = self.request("GET", self._url(zone, fqdn), headers=self._h(), allow=(404,))
        return [] if r.status_code == 404 else [unquote_txt(v) for v in r.json().get("rrset_values", [])]

    def _put(self, zone, fqdn, values, current):
        self.request("PUT", self._url(zone, fqdn), headers=self._h(),
                     json={"rrset_values": [quote_txt(v) for v in values], "rrset_ttl": max(self.ttl, 300)})

    def _remove(self, zone, fqdn, current):
        self.request("DELETE", self._url(zone, fqdn), headers=self._h(), allow=(404,))
