"""Dynu (API v2). credentials: api_key."""
from __future__ import annotations

from ..base import DnsError, RecordProvider, Zone, norm, relative, unquote_txt

API = "https://api.dynu.com/v2"


class Dynu(RecordProvider):
    name = "dynu"
    required = ("api_key",)
    default_ttl = 300

    def _h(self):
        return {"API-Key": self.secret("api_key"), "Accept": "application/json"}

    def find_zone(self, fqdn):
        if self.zones:
            return super().find_zone(fqdn)
        j = self.request("GET", f"{API}/dns/getroot/{norm(fqdn)}", headers=self._h()).json()
        if "id" not in j:
            raise DnsError(f"{self.label}: no Dynu domain contains {fqdn}")
        return Zone(norm(j["domainName"]), str(j["id"]))

    def zone_id(self, name):
        j = self.request("GET", f"{API}/dns/getroot/{norm(name)}", headers=self._h()).json()
        if norm(j.get("domainName", "")) != norm(name):
            raise DnsError(f"{self.label}: zone {name} not found")
        return str(j["id"])

    def _records(self, zone, fqdn):
        rel = relative(fqdn, zone.name)
        j = self.request("GET", f"{API}/dns/{zone.id}/record", headers=self._h()).json()
        return [(str(r["id"]), unquote_txt(r.get("textData", ""))) for r in j.get("dnsRecords", [])
                if r.get("recordType") == "TXT" and (r.get("nodeName") or "") == rel]

    def _create(self, zone, fqdn, value):
        self.request("POST", f"{API}/dns/{zone.id}/record", headers=self._h(), json={
            "nodeName": relative(fqdn, zone.name), "recordType": "TXT", "textData": value, "ttl": self.ttl, "state": True})

    def _delete(self, zone, fqdn, record_id):
        self.request("DELETE", f"{API}/dns/{zone.id}/record/{record_id}", headers=self._h(), allow=(404,))
