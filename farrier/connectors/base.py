from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

import httpx

from farrier.security.vault import resolve_secret


@dataclass
class Bundle:
    name: str           # endpoint name, used to derive object names on devices
    renewal_id: int
    key_pem: str
    cert_pem: str
    chain_pem: str
    not_after: str

    @property
    def fullchain_pem(self) -> str:
        return self.cert_pem + self.chain_pem

    @property
    def object_name(self) -> str:
        """Unique per renewal so a new cert never overwrites the one in use before switch-over."""
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in self.name)
        return f"farrier_{safe}_{self.not_after[:10].replace('-', '')}_{self.renewal_id}"


class DeployError(Exception):
    pass


class Connector:
    kind = "base"
    automated = True          # False -> a human installs it; we only verify
    required: tuple[str, ...] = ()

    def __init__(self, config: dict, data_dir: Path):
        missing = [k for k in self.required if k not in config]
        if missing:
            raise ValueError(f"{self.kind} connector missing config: {', '.join(missing)}")
        self.raw = config
        self.cfg = {k: resolve_secret(v) for k, v in config.items()}
        self.data_dir = Path(data_dir)

    def deploy(self, b: Bundle) -> dict:
        """Install and activate. Return a JSON-able rollback token."""
        raise NotImplementedError

    def rollback(self, token: dict) -> None:
        raise NotImplementedError

    # helpers
    def run(self, command: str | None, timeout: int = 300):
        if not command:
            return
        p = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=timeout)
        if p.returncode != 0:
            raise DeployError(f"command failed ({p.returncode}): {command}\n{p.stderr.strip()[-2000:]}")

    def http(self, **kw) -> httpx.Client:
        verify = self.cfg.get("verify_tls", True)  # True | False | path to CA bundle for the mgmt plane
        if self.transport is not None:
            kw["transport"] = self.transport
        return httpx.Client(base_url=self.cfg["url"].rstrip("/"), verify=verify,
                            timeout=self.cfg.get("timeout", 60), **kw)

    transport = None  # tests inject an httpx.MockTransport here


def check(resp: httpx.Response, what: str) -> httpx.Response:
    if resp.status_code >= 400:
        raise DeployError(f"{what}: HTTP {resp.status_code} {resp.text[:500]}")
    return resp
