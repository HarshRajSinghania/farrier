"""Infomaniak DNS (api.infomaniak.com, v1 domain API). credentials: api_token (scope "domain:read/write")."""
from __future__ import annotations

from farrier.dns.base import DnsError, RecordProvider, norm, relative, unquote_txt

API = "https://api.infomaniak.com"


class Infomaniak(RecordProvider):
    name = "infomaniak"
    required = ("api_token",)
    default_ttl = 300

    def _h(self):
        return {"Authorization": f"Bearer {self.secret('api_token')}"}

    def _data(self, r):
        j = r.json()
        if j.get("result") != "success":
            raise DnsError(f"{self.label}: API error {j.get('error', {}).get('code', 'unknown')}")
        return j.get("data")

    def zone_id(self, name):
        data = self._data(self.request("GET", f"{API}/1/product", headers=self._h(),
                                       params={"service_name": "domain", "customer_name": norm(name)}))
        for p in data or []:
            if norm(p.get("customer_name", "")) == norm(name):
                return str(p["id"])
        raise DnsError(f"{self.label}: domain {name} not found in this account")

    def _records(self, zone, fqdn):
        rel = relative(fqdn, zone.name)
        data = self._data(self.request("GET", f"{API}/1/domain/{zone.id}/dns/record", headers=self._h()))
        return [(str(r["id"]), unquote_txt(r["target"])) for r in data or []
                if r.get("type") == "TXT" and norm(r.get("source", "")) in (rel, fqdn)]

    def _create(self, zone, fqdn, value):
        self._data(self.request("POST", f"{API}/1/domain/{zone.id}/dns/record", headers=self._h(), json={
            "source": relative(fqdn, zone.name), "type": "TXT", "target": value, "ttl": self.ttl}))

    def _delete(self, zone, fqdn, record_id):
        self.request("DELETE", f"{API}/1/domain/{zone.id}/dns/record/{record_id}", headers=self._h(), allow=(404,))
