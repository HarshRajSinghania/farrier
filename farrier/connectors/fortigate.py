"""Fortinet FortiGate via the FortiOS REST API (SSL-VPN, admin GUI, or any cmdb cert reference).

config:
  url          https://fortigate-mgmt.example.com
  api_token    "env:FGT_TOKEN"   (REST API admin with vpn/system write)
  vdom         optional
  bind         "sslvpn" | "admin" | {"path": "/api/v2/cmdb/<table>[/<mkey>]", "field": "<attr>"}
  verify_tls   True | False | path
"""
from __future__ import annotations

import base64

from farrier.connectors.base import Bundle, Connector, check

BINDINGS = {
    "sslvpn": {"path": "/api/v2/cmdb/vpn.ssl/settings", "field": "servercert"},
    "admin": {"path": "/api/v2/cmdb/system/global", "field": "admin-server-cert"},
}


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


class FortiGateConnector(Connector):
    kind = "fortigate"
    required = ("url", "api_token", "bind")

    def _client(self):
        params = {"vdom": self.cfg["vdom"]} if self.cfg.get("vdom") else None
        return self.http(headers={"Authorization": f"Bearer {self.cfg['api_token']}"}, params=params)

    def _binding(self) -> dict:
        bind = self.cfg["bind"]
        return BINDINGS[bind] if isinstance(bind, str) else bind

    def deploy(self, b: Bundle) -> dict:
        bind = self._binding()
        name = b.short_name(35)  # FortiOS certificate names are limited to 35 chars
        with self._client() as c:
            cur = check(c.get(bind["path"]), "read binding").json()
            results = cur.get("results", {})
            if isinstance(results, list):
                results = results[0] if results else {}
            prev = results.get(bind["field"])
            if b.chain_pem.strip():
                r = c.post("/api/v2/monitor/vpn-certificate/ca/import",
                           json={"import_method": "file", "file_content": _b64(b.chain_pem), "scope": "global"})
                if r.status_code >= 400 and "exist" not in r.text.lower():
                    check(r, "import CA chain")
            check(c.post("/api/v2/monitor/vpn-certificate/local/import", json={
                "type": "regular", "certname": name, "scope": "global",
                "file_content": _b64(b.cert_pem), "key_file_content": _b64(b.key_pem)}), "import certificate")
            check(c.put(bind["path"], json={bind["field"]: name}), "bind certificate")
        return {"path": bind["path"], "field": bind["field"], "previous": prev}

    def rollback(self, token: dict) -> None:
        with self._client() as c:
            check(c.put(token["path"], json={token["field"]: token["previous"]}), "rollback binding")
