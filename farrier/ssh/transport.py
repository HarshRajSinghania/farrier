"""Running commands on a host over SSH, the way farrier.connectors.files does: the system ``ssh`` binary.

The private key is resolved from its secret reference at the moment of use, written to an owner-only
file in a private temporary directory for the life of one connection, and deleted afterwards; it is
never on a command line or in a log. Host keys are checked against keys Farrier pinned (see
farrier.ssh.collect): they are written to a throwaway known_hosts file under a fixed alias, and ssh runs
with StrictHostKeyChecking=yes and no other known_hosts, so a changed host key fails the connection.
"""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

ALIAS = "farrier-target"


@dataclass
class CommandResult:
    rc: int
    stdout: bytes
    stderr: str

    @property
    def ok(self) -> bool:
        return self.rc == 0


class TransportError(Exception):
    pass


class HostKeyMismatch(TransportError):
    """The host presented a key that differs from the pinned one. Never accepted silently."""


class Transport(Protocol):
    def run(self, script: str, stdin: bytes | None = None, sudo: bool = False,
            timeout: float = 60.0) -> CommandResult: ...

    def close(self) -> None: ...


def wrap(script: str, sudo: bool) -> str:
    """The remote command: a POSIX sh script, optionally through non-interactive sudo."""
    inner = "sh -c " + shlex.quote(script)
    return f"sudo -n -- {inner}" if sudo else inner


def _write_private(path: Path, data: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", newline="\n") as f:
        f.write(data if data.endswith("\n") else data + "\n")


class SSHBinaryTransport:
    def __init__(self, host: str, port: int, username: str, private_key: str,
                 known_keys: list[tuple[str, str]], connect_timeout: float = 10.0):
        """``known_keys``: (key type, base64 blob) pairs the host must present one of."""
        if not known_keys:
            raise TransportError("no pinned host key; refusing to connect")
        exe = shutil.which("ssh")
        if not exe:
            raise TransportError("the ssh client is not installed on the Farrier host")
        self.exe, self.host, self.port, self.username = exe, host, port, username
        self.connect_timeout = connect_timeout
        self._dir = Path(tempfile.mkdtemp(prefix="farrier-ssh-"))
        try:
            os.chmod(self._dir, 0o700)
        except OSError:
            pass
        self._key = self._dir / "id"
        self._kh = self._dir / "known_hosts"
        self._empty = self._dir / "empty"
        try:
            _write_private(self._key, private_key)
            _write_private(self._kh, "".join(f"{ALIAS} {t} {b}\n" for t, b in known_keys))
            _write_private(self._empty, "")
        except BaseException:
            self.close()
            raise
        self._algs = ",".join(dict.fromkeys(
            a for t, _ in known_keys for a in (("rsa-sha2-512", "rsa-sha2-256") if t == "ssh-rsa" else (t,))))

    def _argv(self, remote: str) -> list[str]:
        opts = {"BatchMode": "yes", "StrictHostKeyChecking": "yes", "UserKnownHostsFile": str(self._kh),
                "GlobalKnownHostsFile": str(self._empty), "HostKeyAlias": ALIAS, "HostKeyAlgorithms": self._algs,
                "UpdateHostKeys": "no", "IdentitiesOnly": "yes", "IdentityAgent": "none",
                "PasswordAuthentication": "no", "KbdInteractiveAuthentication": "no",
                "ConnectTimeout": str(int(self.connect_timeout)), "ServerAliveInterval": "15",
                "ServerAliveCountMax": "2", "LogLevel": "ERROR"}
        argv = [self.exe, "-F", "none", "-T", "-i", str(self._key), "-p", str(self.port), "-l", self.username]
        for k, v in opts.items():
            argv += ["-o", f"{k}={v}"]
        return argv + ["--", self.host, remote]

    def run(self, script: str, stdin: bytes | None = None, sudo: bool = False,
            timeout: float = 60.0) -> CommandResult:
        try:
            p = subprocess.run(self._argv(wrap(script, sudo)), input=stdin if stdin is not None else b"",
                               capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise TransportError(f"ssh to {self.host}:{self.port} timed out after {timeout:.0f}s") from None
        err = p.stderr.decode("utf-8", "replace").strip()
        if p.returncode == 255 and ("IDENTIFICATION HAS CHANGED" in err or "Host key verification failed" in err):
            raise HostKeyMismatch(f"{self.host}:{self.port} host key does not match the pinned key")
        if p.returncode == 255:
            raise TransportError(f"ssh to {self.host}:{self.port} failed: {err[-300:]}")
        return CommandResult(p.returncode, p.stdout, err[-2000:])

    def close(self) -> None:
        shutil.rmtree(self._dir, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
