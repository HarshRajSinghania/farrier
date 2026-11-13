"""Citrix ADC / NetScaler via the NITRO REST API.

Flow: upload the new key, certificate and intermediate as files -> update the existing certkey in
place to point at them (every vserver bound to it switches at once, nothing is unbound) -> link the
intermediate -> save the config. Rollback points the certkey back at its previous files and link.

config:
  url          https://adc-mgmt.example.com (the NSIP or SNIP with management access)
  username     a system user allowed to manage SSL certificates and save the config
  password     "env:ADC_PASSWORD"
  certkey      the certkey name bound to your vservers, e.g. "app1_cert"
  verify_tls   True | False | "/path/to/mgmt-ca.pem"
"""
from __future__ import annotations

import base64

from farrier.connectors.base import Bundle, Connector, check

SSL_DIR = "/nsconfig/ssl/"


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


class CitrixConnector(Connector):
    kind = "citrix"
    required = ("url", "username", "password", "certkey")

    def _client(self):
        return self.http(headers={"X-NITRO-USER": self.cfg["username"], "X-NITRO-PASS": self.cfg["password"],
                                  "Content-Type": "application/json"})

    @staticmethod
    def _upload(c, filename: str, pem: str):
        check(c.post("/nitro/v1/config/systemfile", json={"systemfile": {
            "filename": filename, "filelocation": SSL_DIR, "filecontent": _b64(pem), "fileencoding": "BASE64"}}),
            f"upload {filename}")

    def _link(self, c, certkey: str, ca: str | None):
        c.post("/nitro/v1/config/sslcertkey?action=unlink", json={"sslcertkey": {"certkey": certkey}})  # none: fine
        if ca:
            check(c.post("/nitro/v1/config/sslcertkey?action=link",
                         json={"sslcertkey": {"certkey": certkey, "linkcertkeyname": ca}}), "link intermediate")

    def _update(self, c, cert: str, key: str):
        check(c.post("/nitro/v1/config/sslcertkey?action=update", json={"sslcertkey": {
            "certkey": self.cfg["certkey"], "cert": cert, "key": key, "nodomaincheck": True}}), "update certkey")

    @staticmethod
    def _existing_ca(c, pem: str) -> str | None:
        """The certkey that already holds this intermediate (the ADC refuses a duplicate), matched by serial."""
        from cryptography import x509
        serial = format(x509.load_pem_x509_certificate(pem.encode()).serial_number, "X").lstrip("0")
        for ck in (check(c.get("/nitro/v1/config/sslcertkey"), "list certkeys").json().get("sslcertkey") or []):
            if str(ck.get("serial", "")).replace(":", "").upper().lstrip("0") == serial:
                return ck["certkey"]
        return None

    def _save(self, c):
        check(c.post("/nitro/v1/config/nsconfig?action=save", json={"nsconfig": {}}), "save config")

    def deploy(self, b: Bundle) -> dict:
        name = b.short_name(37)   # 40-char file names minus the ".crt" / "_ca" we add
        with self._client() as c:
            cur = check(c.get(f"/nitro/v1/config/sslcertkey/{self.cfg['certkey']}"), "read certkey").json()
            prev = (cur.get("sslcertkey") or [{}])[0]
            self._upload(c, f"{name}.crt", b.cert_pem)
            self._upload(c, f"{name}.key", b.key_pem)
            ca = None
            if b.chain_pem.strip():
                ca = f"{name}_ca"
                first = b.chain_pem.split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n"
                self._upload(c, f"{ca}.crt", first.lstrip())
                r = c.post("/nitro/v1/config/sslcertkey", json={"sslcertkey": {"certkey": ca, "cert": f"{ca}.crt"}})
                if r.status_code >= 400 and "exist" in r.text.lower():
                    ca = self._existing_ca(c, first) or check(r, "add intermediate certkey")
                else:
                    check(r, "add intermediate certkey")
            self._update(c, f"{name}.crt", f"{name}.key")
            self._link(c, self.cfg["certkey"], ca)
            self._save(c)
        return {"cert": prev.get("cert"), "key": prev.get("key"), "link": prev.get("linkcertkeyname")}

    def rollback(self, token: dict) -> None:
        with self._client() as c:
            self._update(c, token["cert"], token["key"])
            self._link(c, self.cfg["certkey"], token.get("link"))
            self._save(c)
