"""Issuance policy: which names, issuers and key types an endpoint may get a certificate for.

settings.json:
  "policy": {
    "default":  {"allowed_names": ["*.example.com", "example.com"], "key_types": ["ec256", "ec384", "rsa3072"]},
    "payments": {"allowed_names": ["*.pay.example.com"], "allowed_issuers": ["digicert"]}
  }
An endpoint follows its project's rules, else "default"; no policy at all allows everything, as before.
"*.example.com" matches every name below example.com (one or more labels), and the wildcard name
"*.example.com" itself; it does not match example.com. Checked before every issuance; a violation fails
the renewal with a "policy:" reason, so alert rules and the activity log show it.
"""
from __future__ import annotations

from fnmatch import fnmatchcase

KEYS = {"allowed_names", "allowed_issuers", "key_types"}


def rules_for(policy: dict | None, project: str | None) -> dict | None:
    if not policy:
        return None
    return policy.get(project or "default") or policy.get("default")


def name_allowed(name: str, patterns: list[str]) -> bool:
    return any(fnmatchcase(name.lower(), p.lower()) for p in patterns)


def violations(rules: dict | None, names: list[str], issuer: str, key_type: str) -> list[str]:
    """Human-readable reasons this issuance breaks the rules (empty: allowed)."""
    if not rules:
        return []
    out = []
    if (allowed := rules.get("allowed_names")) is not None:
        bad = [n for n in names if not name_allowed(n, allowed)]
        if bad:
            out.append(f"names not allowed: {', '.join(bad)}")
    if (allowed := rules.get("allowed_issuers")) is not None and issuer not in allowed:
        out.append(f"issuer {issuer!r} not allowed (allowed: {', '.join(allowed)})")
    if (allowed := rules.get("key_types")) is not None and key_type not in allowed:
        out.append(f"key type {key_type} not allowed (allowed: {', '.join(allowed)})")
    return out


def validate(policy) -> None:
    """Raise ValueError for a malformed policy block, at engine start rather than at renewal time."""
    if policy is None:
        return
    if not isinstance(policy, dict):
        raise ValueError('settings.json "policy" must be an object of project name -> rules')
    for project, rules in policy.items():
        if not isinstance(rules, dict) or set(rules) - KEYS:
            raise ValueError(f"policy {project!r}: rules are an object with {', '.join(sorted(KEYS))}")
        for k, v in rules.items():
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                raise ValueError(f"policy {project!r}: {k} must be a list of strings")
