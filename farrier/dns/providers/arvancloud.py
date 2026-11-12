"""ArvanCloud CDN DNS (API 4.0). credentials: api_key (the "Apikey ..." machine-user key)."""
from __future__ import annotations

from farrier.dns.base import RecordProvider, Zone, norm, relative

API = "https://napi.arvancloud.ir/cdn/4.0"


class ArvanCloud(RecordProvider):
    name = "arvancloud"
    required = ("api_key",)
    default_ttl = 120

    def _h(self):
        key = self.secret("api_key")
        return {"Authorization": key if key.lower().startswith("apikey ") else f"Apikey {key}"}

    def list_zones(self) -> list[Zone]:
        zones, page = [], 1
        while True:
            j = self.request("GET", f"{API}/domains", headers=self._h(), params={"page": page, "per_page": 100}).json()
            zones += [Zone(norm(d["domain"]), norm(d["domain"])) for d in j.get("data", [])]
            if page >= j.get("meta", {}).get("last_page", 1):
                return zones
            page += 1

    def _records(self, zone, fqdn):
        rel = relative(fqdn, zone.name) or "@"
        j = self.request("GET", f"{API}/domains/{zone.name}/dns-records", headers=self._h(),
                         params={"type": "txt", "search": rel}).json()
        out = []
        for r in j.get("data", []):
            val = r.get("value", {})
            text = val.get("text") if isinstance(val, dict) else None
            if r.get("type", "").lower() == "txt" and r.get("name") == rel and text is not None:
                out.append((r["id"], text))
        return out

    def _create(self, zone, fqdn, value):
        self.request("POST", f"{API}/domains/{zone.name}/dns-records", headers=self._h(), json={
            "type": "txt", "name": relative(fqdn, zone.name) or "@", "value": {"text": value}, "ttl": self.ttl})

    def _delete(self, zone, fqdn, record_id):
        self.request("DELETE", f"{API}/domains/{zone.name}/dns-records/{record_id}", headers=self._h(), allow=(404,))
