"""deSEC (desec.io). RRset API; zone discovery via ?owns_qname. credentials: api_token.
deSEC enforces a 3600 s minimum TTL and rate-limits writes (429 + Retry-After, retried by the base class)."""
from __future__ import annotations

from ..base import DnsError, RRsetProvider, Zone, norm, quote_txt, relative, unquote_txt

API = "https://desec.io/api/v1"


class Desec(RRsetProvider):
    name = "desec"
    required = ("api_token",)
    default_ttl = 3600

    def _h(self):
        return {"Authorization": f"Token {self.secret('api_token')}"}

    def list_zones(self) -> list[Zone]:
        return [Zone(norm(d["name"]), norm(d["name"]))
                for d in self.request("GET", f"{API}/domains/", headers=self._h()).json()]

    def find_zone(self, fqdn):
        if self.zones:
            return super().find_zone(fqdn)
        j = self.request("GET", f"{API}/domains/", headers=self._h(), params={"owns_qname": norm(fqdn)}).json()
        if not j:
            raise DnsError(f"{self.label}: no domain in this account owns {fqdn}")
        return Zone(norm(j[0]["name"]), norm(j[0]["name"]))

    def _url(self, zone, fqdn):
        return f"{API}/domains/{zone.name}/rrsets/{relative(fqdn, zone.name) or '@'}/TXT/"

    def _get(self, zone, fqdn):
        r = self.request("GET", self._url(zone, fqdn), headers=self._h(), allow=(404,))
        return [] if r.status_code == 404 else [unquote_txt(v) for v in r.json().get("records", [])]

    def _put(self, zone, fqdn, values, current):
        self.request("PUT", self._url(zone, fqdn), headers=self._h(), json={
            "subname": relative(fqdn, zone.name), "type": "TXT", "ttl": max(self.ttl, 3600),
            "records": [quote_txt(v) for v in values]})

    def _remove(self, zone, fqdn, current):
        self.request("DELETE", self._url(zone, fqdn), headers=self._h(), allow=(404,))
