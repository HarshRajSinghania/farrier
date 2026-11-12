"""NS1 (IBM NS1 Connect) API v1. credentials: api_key.   options: endpoint (default https://api.nsone.net/v1)"""
from __future__ import annotations

from farrier.dns.base import RRsetProvider, Zone, norm


class NS1(RRsetProvider):
    name = "ns1"
    required = ("api_key",)
    options_known = ("endpoint",)

    @property
    def base(self):
        return self.opts.get("endpoint", "https://api.nsone.net/v1").rstrip("/")

    def _h(self):
        return {"X-NSONE-Key": self.secret("api_key")}

    def list_zones(self) -> list[Zone]:
        return [Zone(norm(z["zone"]), norm(z["zone"])) for z in self.request("GET", f"{self.base}/zones", headers=self._h()).json()]

    def _url(self, zone, fqdn):
        return f"{self.base}/zones/{zone.name}/{fqdn}/TXT"

    def _get(self, zone, fqdn):
        r = self.request("GET", self._url(zone, fqdn), headers=self._h(), allow=(404,))
        if r.status_code == 404:
            return []
        return ["".join(a.get("answer", [])) for a in r.json().get("answers", [])]

    def _put(self, zone, fqdn, values, current):
        body = {"zone": zone.name, "domain": fqdn, "type": "TXT", "ttl": self.ttl,
                "answers": [{"answer": [v]} for v in values]}
        # NS1: PUT creates a record, POST updates an existing one
        self.request("POST" if current else "PUT", self._url(zone, fqdn), headers=self._h(), json=body)

    def _remove(self, zone, fqdn, current):
        self.request("DELETE", self._url(zone, fqdn), headers=self._h(), allow=(404,))
