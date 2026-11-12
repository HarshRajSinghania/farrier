"""PEM files on a host (nginx, HAProxy, Apache, Postfix, appliances with a shell), local or over SSH.

config:
  cert_path, key_path            required
  chain_path, fullchain_path     optional
  combined_path                  optional: key+cert+chain in one file (HAProxy)
  reload_command                 e.g. "systemctl reload nginx" (runs on the target when ssh is set)
  test_command                   optional pre-reload check, e.g. "nginx -t"
  ssh                            optional "user@host" (uses the system ssh/scp; key-based auth)
"""
from __future__ import annotations

import os
import shlex
import subprocess
import tempfile
from pathlib import Path

from farrier.connectors.base import Bundle, Connector, DeployError


class FilesConnector(Connector):
    kind = "files"
    required = ("cert_path", "key_path")
    local_paths = ("cert_path", "key_path", "chain_path", "fullchain_path", "combined_path")

    def _targets(self, b: Bundle) -> dict[str, str]:
        t = {self.cfg["cert_path"]: b.cert_pem, self.cfg["key_path"]: b.key_pem}
        if self.cfg.get("chain_path"):
            t[self.cfg["chain_path"]] = b.chain_pem
        if self.cfg.get("fullchain_path"):
            t[self.cfg["fullchain_path"]] = b.fullchain_pem
        if self.cfg.get("combined_path"):
            t[self.cfg["combined_path"]] = b.key_pem + b.fullchain_pem
        return t

    def _ssh(self, cmd: str):
        p = subprocess.run(["ssh", "-o", "BatchMode=yes", self.cfg["ssh"], cmd],
                           capture_output=True, text=True, timeout=120)
        if p.returncode != 0:
            raise DeployError(f"ssh {cmd!r}: {p.stderr.strip()}")

    def _exec(self, command: str | None):
        if not command:
            return
        if self.cfg.get("ssh"):
            self._ssh(command)
        else:
            self.run(command)

    def deploy(self, b: Bundle) -> dict:
        backups: dict[str, str | None] = {}
        suffix = f".farrier-bak-{b.renewal_id}"
        targets = self._targets(b)
        if self.cfg.get("ssh"):
            for path, content in targets.items():
                q = shlex.quote(path)
                self._ssh(f"if [ -f {q} ]; then cp -p {q} {q}{suffix}; fi")
                backups[path] = path + suffix
                with tempfile.NamedTemporaryFile("w", delete=False, suffix=".pem") as f:
                    f.write(content)
                try:
                    p = subprocess.run(["scp", "-q", "-o", "BatchMode=yes", f.name, f"{self.cfg['ssh']}:{path}.new"],
                                       capture_output=True, text=True, timeout=120)
                    if p.returncode:
                        raise DeployError(f"scp {path}: {p.stderr.strip()}")
                finally:
                    os.unlink(f.name)
                mode = "600" if "PRIVATE KEY" in content else "644"
                self._ssh(f"chmod {mode} {q}.new && mv -f {q}.new {q}")
        else:
            for path, content in targets.items():
                p = Path(path)
                p.parent.mkdir(parents=True, exist_ok=True)
                if p.exists():
                    bak = p.with_name(p.name + suffix)
                    bak.write_bytes(p.read_bytes())
                    backups[path] = str(bak)
                else:
                    backups[path] = None
                tmp = p.with_name(p.name + ".farrier-new")
                tmp.write_text(content)
                if "PRIVATE KEY" in content:
                    try:
                        os.chmod(tmp, 0o600)
                    except OSError:
                        pass
                os.replace(tmp, p)
        token = {"backups": backups}
        try:
            self._exec(self.cfg.get("test_command"))
            self._exec(self.cfg.get("reload_command"))
        except DeployError:
            self.rollback(token)
            raise
        return token

    def rollback(self, token: dict) -> None:
        for path, bak in token.get("backups", {}).items():
            if self.cfg.get("ssh"):
                if bak:
                    qb = shlex.quote(bak)
                    self._ssh(f"if [ -f {qb} ]; then cp -p {qb} {shlex.quote(path)}; fi")
            elif bak and Path(bak).exists():
                os.replace(bak, path)
            elif bak is None:
                Path(path).unlink(missing_ok=True)  # we created it; remove it
        self._exec(self.cfg.get("reload_command"))
