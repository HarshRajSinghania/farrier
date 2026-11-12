"""Java keystores (Tomcat, Jetty, WebLogic, Kafka, Elasticsearch, vendor Java apps).

Writes a PKCS#12 keystore, the default keystore type since Java 9 and readable by
`keytool -storetype PKCS12` everywhere. Use format "pkcs12-legacy" (3DES/SHA1) for
JREs older than 8u301 that cannot read AES-encrypted PKCS#12.

config:
  path            keystore file, e.g. /opt/tomcat/conf/tls.p12
  password        keystore + key password, e.g. "env:TOMCAT_KS_PASS"
  alias           entry alias the app is configured to use (default "tomcat")
  format          "pkcs12" | "pkcs12-legacy"
  reload_command  e.g. "systemctl restart tomcat"  (most Java apps need a restart)
"""
from __future__ import annotations

import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from farrier.connectors.base import Bundle, Connector, DeployError
from farrier.core.x509util import load_key, split_pem_chain


def build_pkcs12(b: Bundle, alias: str, password: str, legacy: bool = False) -> bytes:
    key = load_key(b.key_pem)
    cert = x509.load_pem_x509_certificate(b.cert_pem.encode())
    cas = [x509.load_pem_x509_certificate(c.encode()) for c in split_pem_chain(b.chain_pem)]
    if legacy:
        enc = (serialization.PrivateFormat.PKCS12.encryption_builder().kdf_rounds(50000)
               .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
               .hmac_hash(hashes.SHA1()).build(password.encode()))
    else:
        enc = serialization.BestAvailableEncryption(password.encode())
    return pkcs12.serialize_key_and_certificates(alias.encode(), key, cert, cas or None, enc)


class KeystoreConnector(Connector):
    kind = "keystore"
    required = ("path", "password")

    def deploy(self, b: Bundle) -> dict:
        path = Path(self.cfg["path"])
        data = build_pkcs12(b, self.cfg.get("alias", "tomcat"), self.cfg["password"],
                            legacy=self.cfg.get("format") == "pkcs12-legacy")
        backup = None
        if path.exists():
            backup = str(path.with_name(path.name + f".farrier-bak-{b.renewal_id}"))
            Path(backup).write_bytes(path.read_bytes())
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".farrier-new")
        tmp.write_bytes(data)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, path)
        token = {"path": str(path), "backup": backup}
        try:
            self.run(self.cfg.get("reload_command"))
        except DeployError:
            self.rollback(token)
            raise
        return token

    def rollback(self, token: dict) -> None:
        if token.get("backup") and Path(token["backup"]).exists():
            os.replace(token["backup"], token["path"])
        self.run(self.cfg.get("reload_command"))
