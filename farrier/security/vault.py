"""Encrypts private keys and connector secrets at rest.

The master key comes from FARRIER_MASTER_KEY, from a KMS-wrapped blob (FARRIER_MASTER_KEY_KMS), or is
generated once into <data_dir>/master.key (chmod 600 where the OS supports it). See master_key.
"""
from __future__ import annotations

import json
import os
import re
import threading
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


WRAPPED_FILE = "master.key.wrapped"
_unwrapped: dict[str, bytes] = {}       # wrapped blob -> key, process memory only
_kms_lock = threading.Lock()


def master_key(data_dir: Path) -> bytes:
    """The Fernet master key. Precedence, first that is set wins:

    1. FARRIER_MASTER_KEY_KMS    envelope encryption: aws-kms:<key ARN> | gcp-kms:projects/.../cryptoKeys/<k>
                                 | azure-kv:https://<vault>.vault.azure.net/keys/<name>. Then
         + FARRIER_MASTER_KEY    is the wrapped key: the base64 KMS ciphertext of the Fernet key (what the
                                 deploy modules create; shared by every replica). Unwrapped once per process.
         alone                   the wrapped key lives in <data_dir>/master.key.wrapped: on first boot a key is
                                 generated, wrapped and only the ciphertext written; every boot unwraps it. A
                                 plaintext <data_dir>/master.key left from before is adopted: wrapped, the blob
                                 written and checked, then the plaintext file deleted.
                                 The plaintext key is never written to disk.
    2. FARRIER_MASTER_KEY        (without _KMS) the key itself, e.g. injected from a secret manager
    3. <data_dir>/master.key     generated once, owner-only

    Errors name the setting: an unknown KMS reference, a blob wrapped by a different key than
    FARRIER_MASTER_KEY_KMS names, or a KMS that refuses (permissions, key disabled) stop startup.
    """
    env = os.environ.get("FARRIER_MASTER_KEY")
    if os.environ.get("FARRIER_MASTER_KEY_KMS"):
        return _kms_master_key(Path(data_dir), os.environ["FARRIER_MASTER_KEY_KMS"].strip(), env)
    if env:
        return env.encode()
    path = Path(data_dir) / "master.key"
    if not path.exists():
        _write_private(path, Fernet.generate_key())
    return path.read_bytes().strip()


def _kms_master_key(data_dir: Path, spec: str, wrapped: str | None) -> bytes:
    from farrier.security import kms
    kms.parse(spec)
    with _kms_lock:
        path = data_dir / WRAPPED_FILE
        raw, source = None, ""
        if wrapped and wrapped.strip():
            raw, source = wrapped.strip(), "FARRIER_MASTER_KEY"
        elif path.exists():
            raw, source = path.read_text(), str(path)
        if raw:
            if raw in _unwrapped:
                return _unwrapped[raw]
            try:
                blob = json.loads(raw) if raw.startswith("{") else {"kms": spec, "ciphertext": raw}
                if not isinstance(blob, dict) or "ciphertext" not in blob:
                    raise ValueError
            except ValueError:
                raise ValueError(f"{source} is not a wrapped master key (base64 KMS ciphertext)") from None
            if blob.get("kms") != spec:
                raise ValueError(f"{source} was wrapped with {blob.get('kms')}, but FARRIER_MASTER_KEY_KMS is "
                                 f"{spec}; set FARRIER_MASTER_KEY_KMS back to the key that wrapped it")
            key = kms.unwrap(blob).strip()
            try:
                Fernet(key)                     # a wrong or corrupted key fails here, not on first decrypt
            except ValueError:
                raise ValueError(f"{source}: FARRIER_MASTER_KEY_KMS unwrapped something that is not a Fernet "
                                 "key") from None
            _unwrapped[raw] = key
            return key
        plain = data_dir / "master.key"
        key = plain.read_bytes().strip() if plain.exists() else Fernet.generate_key()
        blob = json.dumps(kms.wrap(spec, key), sort_keys=True)
        if kms.unwrap(json.loads(blob)) != key:
            raise ValueError("FARRIER_MASTER_KEY_KMS: the KMS did not give back the key it wrapped")
        _write_private(path, blob.encode())
        if plain.exists():
            plain.unlink()                      # adopted: the key now exists only wrapped
        _unwrapped[blob] = key
        return key


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
INTERNAL_ENV = {"FARRIER_MASTER_KEY", "FARRIER_API_TOKEN", "FARRIER_API_READ_TOKEN", "FARRIER_MCP_TOKEN",
                "FARRIER_DATABASE_PASSWORD", "FARRIER_DATABASE_URL", "FARRIER_MASTER_KEY_KMS", "FARRIER_LEADER_KEY"}
# The host's ambient cloud credentials: Farrier's own identity, never a connector's.
AMBIENT_ENV = {"AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_ACCESS_KEY_ID", "AZURE_CLIENT_SECRET",
               "AZURE_CLIENT_CERTIFICATE_PASSWORD", "GOOGLE_APPLICATION_CREDENTIALS", "VAULT_TOKEN",
               "ACTIONS_ID_TOKEN_REQUEST_TOKEN"}
# Env vars naming token files Farrier itself reads (workload identity, Vault login); those files are refused.
TOKEN_FILE_ENV = ("FARRIER_SECRET_VAULT_TOKEN_FILE", "FARRIER_SECRET_VAULT_K8S_TOKEN_FILE", "AWS_WEB_IDENTITY_TOKEN_FILE",
                  "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "AZURE_FEDERATED_TOKEN_FILE", "GOOGLE_APPLICATION_CREDENTIALS")
# Process, kernel and device files, and the pod's service-account token: never a connector secret.
SYSTEM_DIRS = ("/proc", "/sys", "/dev", "/var/run/secrets/kubernetes.io", "/run/secrets/kubernetes.io")
# Directories whose files are never readable as secrets (the data dir: master.key, the database).
PROTECTED_DIRS: set[Path] = set()


class SecretRefused(ValueError):
    """A secret reference that the guardrails do not allow."""


# References a config may hold instead of a secret. "vault:NAME" names a secret stored, sealed under the
# master key, in the database (farrier.secrets_store); it is resolved through the lookup registered here.
# External references (aws-sm:, gcp-sm:, azure-kv:, hcvault:) name secrets in the organisation's own
# secret manager; see farrier.secret_backends.external.
EXTERNAL_PREFIXES = ("aws-sm:", "gcp-sm:", "azure-kv:", "hcvault:")
REF_PREFIXES = ("env:", "file:", "vault:", *EXTERNAL_PREFIXES)
VAULT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_vault_lookup = None


def set_vault_lookup(fn) -> None:
    """Register how vault:NAME is resolved: ``fn(name) -> str | None`` (the engine's secret store)."""
    global _vault_lookup
    _vault_lookup = fn


def is_ref(value) -> bool:
    """True for a non-empty env:/file:/vault: or external (aws-sm: gcp-sm: azure-kv: hcvault:) reference."""
    return isinstance(value, str) and any(value.startswith(p) and len(value) > len(p) for p in REF_PREFIXES)


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def check_secret_ref(value) -> None:
    """Raise SecretRefused if `value` is a reference Farrier must not resolve.

    Always refused, whatever the allowlists say: Farrier's own variables (FARRIER_*, except user secrets under
    FARRIER_SECRET_ENV_PREFIX when it starts with FARRIER_, else under FARRIER_SECRET_), the host's ambient cloud
    credentials (AWS_SECRET_ACCESS_KEY, VAULT_TOKEN, ...), files in the data directory, under /proc, /sys, /dev
    or the Kubernetes service-account directory, and the token files Farrier itself logs in with.
    Optional allowlists for hosted deployments:
      FARRIER_SECRET_ENV_PREFIX  env refs must start with it (e.g. FARRIER_SECRET_)
      FARRIER_SECRET_DIRS        file refs must sit under one of these (os.pathsep-separated)
      FARRIER_SECRET_EXTERNAL_PREFIXES  external refs must start with one of these (comma-separated);
                                 unset: only refs under the configured secret backend's prefix
    """
    if not isinstance(value, str):
        return
    if value.startswith(EXTERNAL_PREFIXES):
        from farrier.security.secret_backends import external
        try:
            external.check(value)
        except ValueError as e:
            raise SecretRefused(str(e)) from None
    elif value.startswith("vault:"):
        if not VAULT_NAME.match(value[6:]):
            raise SecretRefused(f"{value!r} is not a valid vault reference (vault:NAME, NAME 1-64 of A-Z a-z 0-9 _ . -)")
    elif value.startswith("env:"):
        name = value[4:]
        prefix = os.environ.get("FARRIER_SECRET_ENV_PREFIX")
        user = prefix if prefix and prefix.startswith("FARRIER_") else "FARRIER_SECRET_"
        if name in INTERNAL_ENV or name in AMBIENT_ENV or (name.startswith("FARRIER_") and not name.startswith(user)):
            raise SecretRefused(f"env:{name} is one of Farrier's own credentials and cannot be used by a connector")
        if prefix and not name.startswith(prefix):
            raise SecretRefused(f"env:{name} is outside FARRIER_SECRET_ENV_PREFIX ({prefix})")
    elif value.startswith("file:"):
        path = Path(value[5:]).expanduser().resolve()
        for root in PROTECTED_DIRS:
            if _inside(path, root):
                raise SecretRefused(f"file:{path} is inside Farrier's data directory")
        if any(_inside(path, Path(d).resolve()) for d in SYSTEM_DIRS):
            raise SecretRefused(f"file:{path} is a system or service-account file")
        own = [Path(os.environ[k]).expanduser().resolve() for k in TOKEN_FILE_ENV if os.environ.get(k)]
        if path in own:
            raise SecretRefused(f"file:{path} is one of Farrier's own credential files")
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
    """Connector configs reference secrets as "env:NAME", "file:/path", "vault:NAME" or an external
    reference (aws-sm:, gcp-sm:, azure-kv:, hcvault:) rather than inline."""
    if not isinstance(value, str):
        return value
    check_secret_ref(value)
    if value.startswith(EXTERNAL_PREFIXES):
        from farrier.security.secret_backends import external
        found = external.resolve(value)
        if found is None:
            raise KeyError(f"secret {value.split(':', 1)[0]} reference does not exist (or has no value)")
        return found
    if value.startswith("vault:"):
        found = _vault_lookup(value[6:]) if _vault_lookup else None
        if found is None:
            raise KeyError(f"secret vault:{value[6:]} is not set")
        return found
    if value.startswith("env:"):
        name = value[4:]
        if name not in os.environ:
            raise KeyError(f"secret env var {name} is not set")
        return os.environ[name]
    if value.startswith("file:"):
        return Path(value[5:]).read_text().strip()
    return value
