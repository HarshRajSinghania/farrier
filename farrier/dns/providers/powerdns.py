"""PowerDNS Authoritative HTTP API. credentials: api_key.
options: api_url (e.g. http://pdns:8081, required), server_id (default "localhost")."""
from __future__ import annotations

from urllib.parse import quote

from farrier.dns.base import (
    DnsConfigError,
    RRsetProvider,
    Zone,
    norm,
    quote_txt,
    unquote_txt,
)


class PowerDNS(RRsetProvider):
    name = "powerdns"
    required = ("api_key",)
    options_known = ("api_url", "server_id")

    @property
    def base(self):
        url = self.opts.get("api_url")
        if not url:
            raise DnsConfigError(f"dns account {self.account!r}: options.api_url is required for powerdns")
        return f"{url.rstrip('/')}/api/v1/servers/{self.opts.get('server_id', 'localhost')}"

    def _h(self):
        return {"X-API-Key": self.secret("api_key")}

    def list_zones(self) -> list[Zone]:
        return [Zone(norm(z["name"]), z["id"]) for z in self.request("GET", f"{self.base}/zones", headers=self._h()).json()]

    def zone_id(self, name):
        return norm(name) + "."

    def _zone_url(self, zone):
        return f"{self.base}/zones/{quote(zone.id or zone.name + '.', safe='')}"

    def _get(self, zone, fqdn):
        # rrset_name/rrset_type filters (4.x) keep the response small; older servers ignore them
        j = self.request("GET", self._zone_url(zone), headers=self._h(),
                         params={"rrset_name": fqdn + ".", "rrset_type": "TXT"}).json()
        for rs in j.get("rrsets", []):
            if norm(rs["name"]) == fqdn and rs["type"] == "TXT":
                return [unquote_txt(r["content"]) for r in rs.get("records", [])]
        return []

    def _patch(self, zone, rrset):
        self.request("PATCH", self._zone_url(zone), headers=self._h(), json={"rrsets": [rrset]})

    def _put(self, zone, fqdn, values, current):
        self._patch(zone, {"name": fqdn + ".", "type": "TXT", "ttl": self.ttl, "changetype": "REPLACE",
                           "records": [{"content": quote_txt(v), "disabled": False} for v in values]})

    def _remove(self, zone, fqdn, current):
        self._patch(zone, {"name": fqdn + ".", "type": "TXT", "changetype": "DELETE"})
