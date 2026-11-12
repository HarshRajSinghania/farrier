"""For boxes with no usable API: VPN concentrators, old appliances, anything behind a CAB.

Farrier does everything except the last click: issues the cert, builds a change pack
(PEM + PFX + a device-specific runbook), optionally opens the ticket, then watches the
endpoint. The renewal closes itself when the new certificate is seen live.

config:
  runbook   "generic" | "cisco-asa" | "citrix-adc" | "windows-iis" | "vmware-vcenter"
  ticket    optional {"url": ..., "headers": {...}, "template": {...}, "ref_field": "result.number"}
            template values may use {summary} {description} {due} {endpoint} {renewal_id}
"""
from __future__ import annotations

import json
import secrets
from pathlib import Path

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from ..storage.packs import pack_store
from ..vault import resolve_secret
from ..x509util import load_key, split_pem_chain
from .base import Bundle, Connector, check

RUNBOOKS = {
    "generic": """1. Import `bundle.pfx` (passphrase in `passphrase.txt`) or `fullchain.pem` + `key.pem`
   into the device's certificate store under the name `{obj}`.
2. Point the TLS service at `{obj}`.
3. Apply / restart the service if the device requires it.
4. Nothing else to do: Farrier is watching {addr} and closes this change automatically
   when it sees certificate fingerprint `{fp_short}...` live.""",
    "cisco-asa": """1. ASDM > Configuration > Device Management > Certificate Management > Identity Certificates > Add.
   Trustpoint name `{obj}`, "Import the identity certificate from a file", choose `bundle.pfx`,
   passphrase from `passphrase.txt`.
   CLI alternative: `crypto ca import {obj} pkcs12 <passphrase>` and paste base64 of bundle.pfx.
2. `ssl trust-point {obj} outside` (repeat per interface serving AnyConnect/WebVPN).
3. `write memory`. No reload required; new sessions pick it up.
4. Farrier verifies {addr} and closes the change on its own.""",
    "citrix-adc": """1. Upload `fullchain.pem` and `key.pem` to /nsconfig/ssl/ as `{obj}.crt` / `{obj}.key`.
2. `add ssl certKey {obj} -cert {obj}.crt -key {obj}.key`
3. `unbind ssl vserver <vs> -certkeyName <old>` then `bind ssl vserver <vs> -certkeyName {obj}`
4. `save ns config`. Farrier verifies {addr} and closes the change on its own.""",
    "windows-iis": """1. Copy `bundle.pfx` to the server. Run (elevated):
   `Import-PfxCertificate -FilePath bundle.pfx -CertStoreLocation Cert:\\LocalMachine\\My -Password (ConvertTo-SecureString '<passphrase>' -AsPlainText -Force)`
2. IIS Manager > Site > Bindings > https > select the new certificate (friendly name `{obj}`).
3. Farrier verifies {addr} and closes the change on its own.""",
    "vmware-vcenter": """1. vSphere Client > Administration > Certificates > Certificate Management > Machine SSL > Actions > Import and Replace.
2. "Replace with external CA certificate (requires private key)": `cert.pem`, `key.pem`, chain `chain.pem`.
3. Services restart automatically (~10 min). Farrier verifies {addr} and closes the change on its own.""",
}


def _fmt(obj, ctx: dict):
    if isinstance(obj, str):
        return obj.format(**ctx)
    if isinstance(obj, dict):
        return {k: _fmt(v, ctx) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_fmt(v, ctx) for v in obj]
    return obj


def _dig(d, path: str):
    for part in path.split("."):
        d = d[int(part)] if isinstance(d, list) else d[part]
    return d


class ManualConnector(Connector):
    kind = "manual"
    automated = False

    def pack_dir(self, renewal_id: int) -> Path:
        """Where a local pack lives (without FARRIER_STORAGE_URL); see farrier.storage.packs."""
        return self.data_dir / "packs" / str(renewal_id)

    @property
    def packs(self):
        return pack_store(self.data_dir)

    def deploy(self, b: Bundle, *, addr: str = "", fingerprint: str = "", due: str = "") -> dict:
        passphrase = secrets.token_urlsafe(18)
        cas = [x509.load_pem_x509_certificate(c.encode()) for c in split_pem_chain(b.chain_pem)]
        pfx = pkcs12.serialize_key_and_certificates(
            b.object_name.encode(), load_key(b.key_pem), x509.load_pem_x509_certificate(b.cert_pem.encode()),
            cas or None, serialization.BestAvailableEncryption(passphrase.encode()))
        files = {"cert.pem": b.cert_pem, "chain.pem": b.chain_pem, "fullchain.pem": b.fullchain_pem,
                 "key.pem": b.key_pem, "passphrase.txt": passphrase + "\n", "bundle.pfx": pfx}
        steps = RUNBOOKS.get(self.cfg.get("runbook", "generic"), RUNBOOKS["generic"]).format(
            obj=b.object_name, addr=addr, fp_short=fingerprint[:16])
        summary = f"Install renewed TLS certificate on {b.name}"
        runbook = (f"# {summary}\n\n- Endpoint: `{addr}`\n- Install before: **{due}**\n"
                   f"- New cert expires: {b.not_after}\n- SHA-256: `{fingerprint}`\n\n## Steps\n\n{steps}\n")
        files["RUNBOOK.md"] = runbook
        where = self.packs.write(b.renewal_id, files)

        ticket_ref = None
        t = self.raw.get("ticket")
        if t:
            ctx = {"summary": summary, "description": runbook, "due": due, "endpoint": b.name,
                   "renewal_id": b.renewal_id}
            body = _fmt(t.get("template", {"summary": "{summary}", "description": "{description}"}), ctx)
            headers = {k: resolve_secret(v) for k, v in t.get("headers", {}).items()}
            r = check(httpx.post(t["url"], json=body, headers=headers, timeout=30), "open ticket")
            try:
                ticket_ref = str(_dig(r.json(), t.get("ref_field", "id")))
            except (KeyError, IndexError, ValueError, json.JSONDecodeError):
                ticket_ref = r.headers.get("Location")
        return {"pack_dir": where, "ticket_ref": ticket_ref}

    def cleanup(self, renewal_id: int):
        self.packs.delete(renewal_id)

    def rollback(self, token: dict) -> None:
        pass  # nothing was changed on the device by us
