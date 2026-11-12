"""SSH access profiles: the credential and host list collection logs in with, edited in the dashboard.

Stored like other dashboard configuration (config_items, kind "ssh_access"; every replica sees a change
through the config version). A profile never holds a key: ``private_key`` is a secret reference
(vault:NAME, env:, file: or an external secret manager), resolved only when a connection is made.

    {"username": "farrier", "private_key": "vault:ssh-fleet", "port": 22,
     "hosts": ["web1.internal", "10.0.4.0/28", "bastion:2222"], "sudo": false,
     "known_hosts_policy": "tofu" | "strict"}
"""
from __future__ import annotations

import re

from farrier.core.discovery import expand_targets
from farrier.security.vault import SecretRefused, check_secret_ref, is_ref

KIND = "ssh_access"
APPROVED_KIND, APPROVED_NAME = "ssh_approved_keys", "default"
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
USERNAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}$")
FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
POLICIES = ("tofu", "strict")
MAX_HOSTS = 4096
_FIELDS = {"username", "private_key", "port", "hosts", "sudo", "known_hosts_policy"}


class Invalid(ValueError):
    pass


def expand_hosts(items: list[str] | str, default_port: int = 22) -> list[tuple[str, int]]:
    """Targets in discovery syntax (host, host:port, CIDR, CIDR:port|port), validated by
    farrier.core.discovery.expand_targets; items without a port get ``default_port``. No SNI forms."""
    if isinstance(items, str):
        items = items.replace(",", " ").split()
    out: list[tuple[str, int]] = []
    for item in items:
        if not isinstance(item, str) or not item.strip():
            raise Invalid("each host must be a non-empty string")
        item = item.strip()
        if "@" in item:
            raise Invalid(f"{item!r}: name@address is TLS SNI syntax and does not apply to SSH")
        explicit = item.count(":") == 1
        try:
            expanded = expand_targets(item, limit=MAX_HOSTS)
        except ValueError as e:
            raise Invalid(str(e)) from None
        out += [(h, p if explicit else default_port) for h, p, _ in expanded]
        if len(out) > MAX_HOSTS:
            raise Invalid(f"more than {MAX_HOSTS} hosts; split the range")
    return list(dict.fromkeys(out))


def validate(body) -> dict:
    if not isinstance(body, dict):
        raise Invalid("body must be a JSON object")
    unknown = set(body) - _FIELDS - {"name"}
    if unknown:
        raise Invalid(f"unknown fields: {', '.join(sorted(unknown))}")
    username = body.get("username")
    if not isinstance(username, str) or not USERNAME.match(username):
        raise Invalid("username must be a POSIX user name")
    key = body.get("private_key")
    if not is_ref(key):
        raise Invalid("private_key must be a secret reference (vault:NAME, env:NAME, file:/path or an external "
                      "secret manager reference), never the key itself")
    try:
        check_secret_ref(key)
    except SecretRefused as e:
        raise Invalid(f"private_key: {e}") from None
    port = body.get("port", 22)
    if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
        raise Invalid("port must be 1-65535")
    hosts = body.get("hosts")
    if not isinstance(hosts, list) or not hosts:
        raise Invalid("hosts must be a non-empty list of hosts, host:port or CIDR ranges")
    expand_hosts(hosts, port)
    sudo = body.get("sudo", False)
    if not isinstance(sudo, bool):
        raise Invalid("sudo must be true or false")
    policy = body.get("known_hosts_policy", "tofu")
    if policy not in POLICIES:
        raise Invalid("known_hosts_policy must be tofu or strict")
    return {"username": username, "private_key": key, "port": port, "hosts": [h.strip() for h in hosts],
            "sudo": sudo, "known_hosts_policy": policy}


def view(name: str, cfg: dict) -> dict:
    """What the API returns: the secret *reference* is shown (it is not a secret), never a value."""
    return {"name": name, **{k: cfg.get(k) for k in sorted(_FIELDS)}}


def profiles(items) -> dict[str, dict]:
    return items.all(KIND)


def approved_fingerprints(items) -> set[str]:
    return set((items.get(APPROVED_KIND, APPROVED_NAME) or {}).get("fingerprints") or [])


def validate_approved(body) -> dict:
    fps = body.get("fingerprints") if isinstance(body, dict) else None
    if not isinstance(fps, list) or not all(isinstance(f, str) and FINGERPRINT.match(f) for f in fps):
        raise Invalid("fingerprints must be a list of OpenSSH SHA256:... fingerprints")
    return {"fingerprints": sorted(set(fps))}
