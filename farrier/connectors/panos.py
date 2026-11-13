"""Palo Alto Networks PAN-OS (firewalls, GlobalProtect portals/gateways) via the XML API.

Flow: import keypair (encrypted PEM) under a new name -> point the SSL/TLS service profile
at it -> commit. Rollback points the profile back and commits.

config:
  url          https://fw-mgmt.example.com
  api_key      "env:PANOS_KEY"
  profile      SSL/TLS service profile name
  profile_xpath  optional override; default /config/shared/ssl-tls-service-profile/entry[@name='<profile>']
  verify_tls   True | False | path
"""
from __future__ import annotations

import secrets
import xml.etree.ElementTree as ET

from cryptography.hazmat.primitives import serialization

from farrier.connectors.base import Bundle, Connector, DeployError, check
from farrier.core.x509util import load_key


class PanOSConnector(Connector):
    kind = "panos"
    required = ("url", "api_key", "profile")

    def _xpath(self) -> str:
        return self.cfg.get("profile_xpath") or \
            f"/config/shared/ssl-tls-service-profile/entry[@name='{self.cfg['profile']}']"

    def _call(self, c, params: dict, files=None, what="api") -> ET.Element:
        r = check(c.post("/api/", params={**params, "key": self.cfg["api_key"]}, files=files), what)
        root = ET.fromstring(r.text)
        if root.get("status") != "success":
            msg = " ".join(t.strip() for t in root.itertext() if t.strip())
            raise DeployError(f"{what}: {msg[:500]}")
        return root

    def _set_cert(self, c, name: str):
        self._call(c, {"type": "config", "action": "set", "xpath": self._xpath(),
                       "element": f"<certificate>{name}</certificate>"}, what="set profile certificate")
        self._call(c, {"type": "commit", "cmd": "<commit></commit>"}, what="commit")

    def deploy(self, b: Bundle) -> dict:
        name = b.short_name(63)
        passphrase = secrets.token_urlsafe(24)
        enc_key = load_key(b.key_pem).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(passphrase.encode())).decode()
        with self.http() as c:
            cur = self._call(c, {"type": "config", "action": "get", "xpath": self._xpath() + "/certificate"},
                             what="read profile")
            el = cur.find(".//certificate")
            prev = el.text if el is not None else None
            self._call(c, {"type": "import", "category": "keypair", "certificate-name": name,
                           "format": "pem", "passphrase": passphrase},
                       files={"file": ("bundle.pem", (enc_key + b.fullchain_pem).encode())}, what="import keypair")
            self._set_cert(c, name)
        return {"previous": prev}

    def rollback(self, token: dict) -> None:
        if not token.get("previous"):
            raise DeployError("no previous certificate recorded; cannot roll back")
        with self.http() as c:
            self._set_cert(c, token["previous"])
