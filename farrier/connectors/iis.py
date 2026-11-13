"""Microsoft IIS over OpenSSH (built into Windows Server 2019 and later), with PowerShell.

Flow: the certificate, key and chain travel as a password-protected PFX inside a PowerShell script on
stdin (never on a command line) -> Import-PfxCertificate into LocalMachine\\My -> the site's https binding
switches to the new thumbprint. Rollback switches the binding back; the old certificate stays in the store.

config:
  ssh          "Administrator@iis01.corp.example" (the system ssh client, key-based auth)
  site         IIS site name, e.g. "Default Web Site"
  port         https binding port (default 443)
  host_header  optional, for SNI bindings
"""
from __future__ import annotations

import base64
import re
import secrets
import subprocess

from cryptography import x509
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, load_pem_private_key, pkcs12

from farrier.connectors.base import Bundle, Connector, DeployError

THUMB = re.compile(r"^[0-9A-Fa-f]{40}$")


def _q(s) -> str:
    """A PowerShell single-quoted literal."""
    return "'" + str(s).replace("'", "''") + "'"


class IISConnector(Connector):
    kind = "iis"
    required = ("ssh", "site")

    def _binding(self) -> str:
        args = f"-Name {_q(self.cfg['site'])} -Protocol https -Port {int(self.cfg.get('port', 443))}"
        if self.cfg.get("host_header"):
            args += f" -HostHeader {_q(self.cfg['host_header'])}"
        return ("Import-Module WebAdministration\n"
                f"$b = Get-WebBinding {args}\n"
                "if (-not $b) { throw 'no matching https binding on the site' }\n")

    def _ps(self, script: str) -> str:
        p = subprocess.run(["ssh", "-o", "BatchMode=yes", self.cfg["ssh"],
                            "powershell -NoProfile -NonInteractive -Command -"],
                           input="$ErrorActionPreference = 'Stop'\n" + script, capture_output=True, text=True,
                           timeout=180)
        if p.returncode != 0:
            raise DeployError(f"iis on {self.cfg['ssh']}: {(p.stderr or p.stdout).strip()[-1500:]}")
        return p.stdout

    def deploy(self, b: Bundle) -> dict:
        password = secrets.token_urlsafe(24)
        chain = x509.load_pem_x509_certificates(b.chain_pem.encode()) if b.chain_pem.strip() else None
        pfx = pkcs12.serialize_key_and_certificates(
            b.object_name.encode(), load_pem_private_key(b.key_pem.encode(), None),
            x509.load_pem_x509_certificate(b.cert_pem.encode()), chain, BestAvailableEncryption(password.encode()))
        out = self._ps(
            f"$bytes = [Convert]::FromBase64String('{base64.b64encode(pfx).decode()}')\n"
            "$tmp = [IO.Path]::GetTempFileName()\n"
            "[IO.File]::WriteAllBytes($tmp, $bytes)\n"
            f"try {{ $c = Import-PfxCertificate -FilePath $tmp -CertStoreLocation Cert:\\LocalMachine\\My "
            f"-Password (ConvertTo-SecureString {_q(password)} -AsPlainText -Force) }} "
            "finally { Remove-Item $tmp -Force }\n"
            + self._binding() +
            "$prev = $b.certificateHash\n"
            "$b.AddSslCertificate(($c | Select-Object -First 1).Thumbprint, 'My')\n"
            "Write-Output \"FARRIER_PREVIOUS=$prev\"\n")
        prev = next((ln.split("=", 1)[1].strip() for ln in out.splitlines() if ln.startswith("FARRIER_PREVIOUS=")), "")
        return {"previous": prev if THUMB.match(prev) else None}

    def rollback(self, token: dict) -> None:
        prev = token.get("previous")
        if not prev or not THUMB.match(prev):
            raise DeployError("no previous certificate recorded for this binding; nothing to roll back to")
        self._ps(self._binding() + f"$b.AddSslCertificate({_q(prev)}, 'My')\n")
