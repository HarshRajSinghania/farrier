"""Configuration as the dashboard sees it: a read view of the effective config (never a secret value),
and a validated update of the planner settings in <data>/settings.json.

CAs and DNS accounts stay file-only on purpose: editing them over HTTP would mean accepting credential
references and hook commands, which the API guardrails refuse.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from urllib.parse import urlparse

from farrier.security.vault import REF_PREFIXES

# key -> (type, min, max, label); the only settings the API may change
EDITABLE: dict[str, tuple[type, float, float]] = {
    "horizon_days": (int, 1, 60),
    "safety_days": (int, 0, 30),
    "manual_daily_cap": (int, 0, 10_000),
    "auto_daily_cap": (int, 1, 100_000),
    "verify_max_attempts": (int, 1, 50),
    "scan_timeout": (float, 1, 60),
    "verify_chain_and_names": (bool, 0, 1),
    "verify_all_addresses": (bool, 0, 1),
}
_lock = threading.Lock()


def _ref(v) -> str | None:
    """A secret as the dashboard may see it: its env:/file: reference, or only that it is set."""
    if v in (None, ""):
        return None
    return v if isinstance(v, str) and v.startswith(REF_PREFIXES) else "set (inline)"


def _read(path: Path) -> tuple[dict, str | None]:
    if not path.exists():
        return {}, None
    try:
        data = json.loads(path.read_text())
        return (data, None) if isinstance(data, dict) else ({}, f"{path.name} must be a JSON object")
    except ValueError as e:
        return {}, f"{path.name} is not valid JSON: {e}"


def view(engine) -> dict:
    data = Path(engine.data_dir)
    from farrier.issuers import PRESETS

    raw, err = _read(data / "issuers.json")
    issuers = []
    for name, c in (raw or {"default": {"type": "local_ca"}}).items():
        c = c if isinstance(c, dict) else {}
        preset = c.get("preset")
        url = c.get("directory_url") or (PRESETS.get(str(preset).lower(), {}) or {}).get("directory_url")
        issuers.append({
            "name": name,
            "type": c.get("type") or ("acme" if preset else "acme" if url else "local_ca"),
            "preset": preset,
            "directory": urlparse(url).hostname if url else None,
            "email": c.get("email"),
            "dns": c.get("dns") or ("hook" if c.get("dns_hook") else None),
            "eab": _ref(c.get("eab_kid")),
        })

    dns_raw, dns_err = _read(data / "dns.json")
    dns = [{
        "name": name,
        "provider": acc.get("provider"),
        "zones": acc.get("zones") or [],
        "credentials": {k: _ref(v) for k, v in (acc.get("credentials") or {}).items()},
    } for name, acc in dns_raw.items() if isinstance(acc, dict) and "provider" in acc]

    # webhook and chat URLs are secrets in themselves: show the kind and the events only
    notifiers = [{"type": n.get("type", "webhook"), "events": n.get("events") or ["failed", "rolled_back", "awaiting_manual"]}
                 for n in (engine.settings.get("notifiers") or []) if isinstance(n, dict)]

    return {
        "settings": {k: engine.settings.get(k) for k in EDITABLE},
        "limits": {k: {"min": lo, "max": hi, "type": t.__name__} for k, (t, lo, hi) in EDITABLE.items()},
        "issuers": issuers, "issuers_error": err,
        "dns_accounts": dns, "dns_error": dns_err,
        "notifiers": notifiers,
        "engine": {**engine.status(), "data_dir": str(data), "mcp_writes": os.environ.get("FARRIER_MCP_ALLOW_WRITES") == "1"},
    }


def update_settings(engine, changes: dict) -> dict:
    """Validate, save to settings.json (atomically, keeping every other key) and apply live."""
    if not isinstance(changes, dict) or not changes:
        raise ValueError("send an object of settings to change")
    clean = {}
    for k, v in changes.items():
        if k not in EDITABLE:
            raise ValueError(f"{k!r} can't be changed here; editable: {', '.join(EDITABLE)}")
        t, lo, hi = EDITABLE[k]
        if t is bool:
            if not isinstance(v, bool):
                raise ValueError(f"{k} must be true or false")
        else:
            if isinstance(v, bool) or not isinstance(v, (int, float)) or (t is int and int(v) != v):
                raise ValueError(f"{k} must be {'a whole number' if t is int else 'a number'}")
            if not lo <= v <= hi:
                raise ValueError(f"{k} must be between {lo:g} and {hi:g}")
            v = t(v)
        clean[k] = v
    path = Path(engine.data_dir) / "settings.json"
    with _lock:
        current, err = _read(path)
        if err:
            raise ValueError(f"fix settings.json by hand first: {err}")
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps({**current, **clean}, indent=2) + "\n")
        os.replace(tmp, path)
        engine.settings.update(clean)
    return clean
