"""Encrypts private keys and connector secrets at rest.

The master key comes from FARRIER_MASTER_KEY, or is generated once into
<data_dir>/master.key (chmod 600 where the OS supports it).
"""
from __future__ import annotations

import os
from pathlib import Path

from cryptography.fernet import Fernet


def _write_private(path: Path, data: bytes) -> None:
    """Write a secret file readable by the owner only (0600 where the OS supports it), atomically."""
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)


def master_key(data_dir: Path) -> bytes:
    """FARRIER_MASTER_KEY, else <data_dir>/master.key (generated once, owner-only)."""
    env = os.environ.get("FARRIER_MASTER_KEY")
    if env:
        return env.encode()
    path = Path(data_dir) / "master.key"
    if not path.exists():
        _write_private(path, Fernet.generate_key())
    return path.read_bytes().strip()


def save_private_key(path: Path, key, data_dir: Path) -> None:
    """Store a private key (ACME account, private CA) as PKCS#8 encrypted under the master key."""
    from cryptography.hazmat.primitives import serialization

    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.BestAvailableEncryption(master_key(data_dir)))
    _write_private(Path(path), pem)


def load_private_key(path: Path, data_dir: Path):
    """Load a key written by save_private_key. A plaintext key from an older version is
    encrypted in place on first load."""
    from cryptography.hazmat.primitives import serialization

    data = Path(path).read_bytes()
    try:
        return serialization.load_pem_private_key(data, master_key(data_dir))
    except TypeError:  # not encrypted: written before keys were sealed
        key = serialization.load_pem_private_key(data, None)
        save_private_key(path, key, data_dir)
        return key


class Vault:
    def __init__(self, data_dir: Path):
        self._f = Fernet(master_key(data_dir))

    def seal(self, text: str | None) -> str | None:
        return None if text is None else self._f.encrypt(text.encode()).decode()

    def open(self, token: str | None) -> str | None:
        return None if token is None else self._f.decrypt(token.encode()).decode()


# Farrier's own credentials. A connector config is partly attacker-controllable (anyone with an
# API token can set a device URL), so it must never be able to read these and send them away.
INTERNAL_ENV = {"FARRIER_MASTER_KEY", "FARRIER_API_TOKEN", "FARRIER_API_READ_TOKEN"}
# Directories whose files are never readable as secrets (the data dir: master.key, the database).
PROTECTED_DIRS: set[Path] = set()


class SecretRefused(ValueError):
    """A secret reference that the guardrails do not allow."""


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def check_secret_ref(value) -> None:
    """Raise SecretRefused if `value` is a reference Farrier must not resolve.

    Always refused: Farrier's own credentials and files in the data directory.
    Optional allowlists for hosted deployments:
      FARRIER_SECRET_ENV_PREFIX  env refs must start with it (e.g. FARRIER_SECRET_)
      FARRIER_SECRET_DIRS        file refs must sit under one of these (os.pathsep-separated)
    """
    if not isinstance(value, str):
        return
    if value.startswith("env:"):
        name = value[4:]
        if name in INTERNAL_ENV:
            raise SecretRefused(f"env:{name} is one of Farrier's own credentials and cannot be used by a connector")
        prefix = os.environ.get("FARRIER_SECRET_ENV_PREFIX")
        if prefix and not name.startswith(prefix):
            raise SecretRefused(f"env:{name} is outside FARRIER_SECRET_ENV_PREFIX ({prefix})")
    elif value.startswith("file:"):
        path = Path(value[5:]).expanduser().resolve()
        for root in PROTECTED_DIRS:
            if _inside(path, root):
                raise SecretRefused(f"file:{path} is inside Farrier's data directory")
        allowed = [Path(d).expanduser().resolve() for d in os.environ.get("FARRIER_SECRET_DIRS", "").split(os.pathsep) if d]
        if allowed and not any(_inside(path, d) for d in allowed):
            raise SecretRefused(f"file:{path} is outside FARRIER_SECRET_DIRS")


def check_secret_refs(obj) -> None:
    """check_secret_ref over every string in a nested config."""
    if isinstance(obj, dict):
        for v in obj.values():
            check_secret_refs(v)
    elif isinstance(obj, list):
        for v in obj:
            check_secret_refs(v)
    else:
        check_secret_ref(obj)


def resolve_secret(value):
    """Connector configs reference secrets as "env:NAME" or "file:/path" rather than inline."""
    if not isinstance(value, str):
        return value
    check_secret_ref(value)
    if value.startswith("env:"):
        name = value[4:]
        if name not in os.environ:
            raise KeyError(f"secret env var {name} is not set")
        return os.environ[name]
    if value.startswith("file:"):
        return Path(value[5:]).read_text().strip()
    return value
