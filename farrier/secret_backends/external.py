"""External secret references: secrets the organisation already keeps, referenced from any config.

    aws-sm:<secret ARN or name>                         AWS Secrets Manager
    gcp-sm:projects/<p>/secrets/<id>[/versions/<v>]     Google Secret Manager
    azure-kv:https://<vault>.vault.azure.net/secrets/<name>[/<version>]
    hcvault:<mount>/<path>[#field]                      HashiCorp Vault / OpenBao KV v2

They resolve through the same adapters as the secret backends (and the same platform identity), and
only when allowed:

    FARRIER_SECRET_EXTERNAL_PREFIXES   comma-separated reference prefixes that may be resolved, e.g.
                                       aws-sm:arn:aws:secretsmanager:eu-west-1:123456789012:secret:certs/
    unset (default)                    only references under the configured backend's own location and
                                       prefix (FARRIER_SECRET_BACKEND=local: none)

A connector config is partly attacker-controllable, so the allowlist keeps it from reading arbitrary
secrets with Farrier's identity. Structural checks always apply: an azure-kv URL must be a Key Vault
host (the bearer token is sent there) and hcvault references always go to FARRIER_SECRET_VAULT_ADDR.
"""
from __future__ import annotations

import os
import threading

from . import backend_class, configured

SCHEMES = {"aws-sm": "aws", "gcp-sm": "gcp", "azure-kv": "azure", "hcvault": "hashicorp"}
_adapters: dict = {}
_lock = threading.Lock()


def scheme_of(value) -> str | None:
    if not isinstance(value, str):
        return None
    scheme, sep, rest = value.partition(":")
    return scheme if sep and rest and scheme in SCHEMES else None


def adapter(kind: str):
    """A non-strict backend instance per kind, shared by every external reference of that kind."""
    with _lock:
        if kind not in _adapters:
            _adapters[kind] = backend_class(kind)(None, strict=False)
        return _adapters[kind]


def reset() -> None:
    with _lock:
        _adapters.clear()


def check(value: str) -> None:
    """Raise ValueError (with the setting to change) unless the reference is well formed and allowed."""
    scheme = scheme_of(value)
    if not scheme:
        raise ValueError(f"{value.split(':', 1)[0]}: reference is empty")
    body = value[len(scheme) + 1:]
    a = adapter(SCHEMES[scheme])
    a.parse(body)                      # well formed, or ValueError
    allowed = [p.strip() for p in os.environ.get("FARRIER_SECRET_EXTERNAL_PREFIXES", "").split(",") if p.strip()]
    if allowed:
        if not any(value.startswith(p) for p in allowed):
            raise ValueError(f"{scheme}: reference is outside FARRIER_SECRET_EXTERNAL_PREFIXES")
        return
    if configured() != SCHEMES[scheme]:
        raise ValueError(f"{scheme}: references are allowed only under the configured secret backend "
                         f"(FARRIER_SECRET_BACKEND={configured()}); list allowed prefixes in "
                         "FARRIER_SECRET_EXTERNAL_PREFIXES")
    if not a.owns(body):
        raise ValueError(f"{scheme}: reference is outside the configured backend's prefix; list allowed prefixes "
                         "in FARRIER_SECRET_EXTERNAL_PREFIXES")


def resolve(value: str) -> str | None:
    """The secret's current value (cached for at most 60 s), or None when it does not exist."""
    scheme = scheme_of(value)
    return adapter(SCHEMES[scheme]).get(value[len(scheme) + 1:])
