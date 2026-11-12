"""Porkbun (API v3). Keys travel in the JSON body (Porkbun's design), never in the URL.
credentials: api_key, secret_api_key. API access must be enabled per domain in the Porkbun UI."""
from __future__ import annotations

from ..base import DnsError, RecordProvider, Zone, norm, relative, unquote_txt

API = "https://api.porkbun.com/api/json/v3"


class Porkbun(RecordProvider):
    name = "porkbun"
    required = ("api_key", "secret_api_key")
    default_ttl = 600  # Porkbun minimum

    def _post(self, path, extra=None):
        body = {"apikey": self.secret("api_key"), "secretapikey": self.secret("secret_api_key"), **(extra or {})}
        j = self.request("POST", API + path, json=body).json()
        if j.get("status") != "SUCCESS":
            raise DnsError(f"{self.label}: {path.split('/')[1]} failed: {self.redact(str(j.get('message', '')))[:200]}")
        return j

    def list_zones(self) -> list[Zone]:
        return [Zone(norm(d["domain"]), norm(d["domain"])) for d in self._post("/domain/listAll").get("domains", [])]

    def _records(self, zone, fqdn):
        j = self._post(f"/dns/retrieveByNameType/{zone.name}/TXT/{relative(fqdn, zone.name)}")
        return [(str(r["id"]), unquote_txt(r["content"])) for r in j.get("records", []) if norm(r["name"]) == fqdn]

    def _create(self, zone, fqdn, value):
        self._post(f"/dns/create/{zone.name}", {"name": relative(fqdn, zone.name), "type": "TXT",
                                                "content": value, "ttl": str(max(self.ttl, 600))})

    def _delete(self, zone, fqdn, record_id):
        self._post(f"/dns/delete/{zone.name}/{record_id}")
