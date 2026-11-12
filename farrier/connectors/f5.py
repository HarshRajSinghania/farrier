"""F5 BIG-IP via iControl REST.

Flow: upload key/cert/chain -> install as new crypto objects (never overwrite the live ones)
-> repoint the client-ssl profile's certKeyChain -> save sys config. Rollback repoints the
profile to the previous objects. Old objects are left in place for audit/cleanup.

config:
  url          https://bigip-mgmt.example.com
  username     admin user with Certificate Manager + profile edit rights
  password     "env:F5_PASSWORD"
  profile      client-ssl profile full path, e.g. /Common/clientssl_app1
  partition    default "Common"
  verify_tls   True | False | "/path/to/mgmt-ca.pem"
"""
from __future__ import annotations

from farrier.connectors.base import Bundle, Connector, DeployError, check


def _tm(path: str) -> str:
    return path.replace("/", "~")


class F5Connector(Connector):
    kind = "f5"
    required = ("url", "username", "password", "profile")

    def _client(self):
        return self.http(auth=(self.cfg["username"], self.cfg["password"]))

    def _upload(self, c, filename: str, data: bytes):
        check(c.post(f"/mgmt/shared/file-transfer/uploads/{filename}", content=data, headers={
            "Content-Type": "application/octet-stream",
            "Content-Range": f"0-{len(data) - 1}/{len(data)}"}), f"upload {filename}")

    def _install(self, c, kind: str, name: str, filename: str):
        check(c.post(f"/mgmt/tm/sys/crypto/{kind}", json={
            "command": "install", "name": name,
            "from-local-file": f"/var/config/rest/downloads/{filename}"}), f"install {kind} {name}")

    def deploy(self, b: Bundle) -> dict:
        part = self.cfg.get("partition", "Common")
        obj = b.object_name
        key_name, crt_name, chain_name = f"{obj}.key", f"{obj}.crt", f"{obj}_chain.crt"
        with self._client() as c:
            prof_url = f"/mgmt/tm/ltm/profile/client-ssl/{_tm(self.cfg['profile'])}"
            before = check(c.get(prof_url), "read profile").json()
            prev_chain = before.get("certKeyChain", [])

            self._upload(c, key_name, b.key_pem.encode())
            self._upload(c, crt_name, b.cert_pem.encode())
            self._install(c, "key", key_name, key_name)
            self._install(c, "cert", crt_name, crt_name)
            entry = {"name": "default", "cert": f"/{part}/{crt_name}", "key": f"/{part}/{key_name}"}
            if b.chain_pem.strip():
                self._upload(c, chain_name, b.chain_pem.encode())
                self._install(c, "cert", chain_name, chain_name)
                entry["chain"] = f"/{part}/{chain_name}"

            # keep any non-default entries (e.g. a second RSA/ECDSA pair) untouched
            others = [e for e in prev_chain if e.get("name") != "default"]
            check(c.patch(prof_url, json={"certKeyChain": [entry, *others]}), "update profile")
            check(c.post("/mgmt/tm/sys/config", json={"command": "save"}), "save config")
        return {"profile": self.cfg["profile"], "certKeyChain": prev_chain}

    def rollback(self, token: dict) -> None:
        if not token.get("certKeyChain"):
            raise DeployError("no previous certKeyChain recorded; cannot roll back")
        with self._client() as c:
            prof_url = f"/mgmt/tm/ltm/profile/client-ssl/{_tm(token['profile'])}"
            keep = [{k: v for k, v in e.items() if k in ("name", "cert", "key", "chain", "passphrase")}
                    for e in token["certKeyChain"]]
            check(c.patch(prof_url, json={"certKeyChain": keep}), "rollback profile")
            check(c.post("/mgmt/tm/sys/config", json={"command": "save"}), "save config")
