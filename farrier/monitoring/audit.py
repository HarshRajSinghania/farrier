"""Tamper-evident activity log and the compliance report.

Every event (who renewed, approved, deployed, rolled back, changed config) is sealed into a hash chain:
chain = SHA-256(previous chain || id, time, endpoint, renewal, level, message). The leader seals new rows
each tick, in id order, so replicas never race. Changing or deleting a sealed row breaks the chain from
that row on, which verify() reports. export() ends with the head of the chain signed (HMAC-SHA256 under a
key derived from the master key): keep exports elsewhere (a SIEM, a WORM bucket) and a truncated log is
detectable too, because its head no longer matches the one you kept.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from collections import Counter
from datetime import timedelta

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from farrier.core import policy
from farrier.db.store import parse_dt
from farrier.security.vault import master_key

GENESIS = "0" * 64
PURPOSE = b"farrier-audit-v1"
FIELDS = ("id", "at", "endpoint_id", "renewal_id", "level", "message")


def _link(prev: str, row: dict) -> str:
    body = json.dumps([row[f] for f in FIELDS], separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(f"{prev}|{body}".encode()).hexdigest()


def seal(store, limit: int = 5000) -> int:
    """Chain up to ``limit`` unsealed events (leader only). Returns how many were sealed."""
    last = store.q1("SELECT id, chain FROM events WHERE chain IS NOT NULL ORDER BY id DESC LIMIT 1")
    prev, after = (last["chain"], last["id"]) if last else (GENESIS, 0)
    rows = store.q(f"SELECT {', '.join(FIELDS)} FROM events WHERE chain IS NULL AND id > ? ORDER BY id LIMIT ?",
                   (after, limit))
    for row in rows:
        prev = _link(prev, row)
        store.x("UPDATE events SET chain=? WHERE id=? AND chain IS NULL", (prev, row["id"]))
    return len(rows)


def verify(store) -> dict:
    """{"ok", "sealed", "unsealed", "head", "first_bad_id"}: recompute the whole chain."""
    prev, n, bad = GENESIS, 0, None
    for row in store.q(f"SELECT {', '.join(FIELDS)}, chain FROM events WHERE chain IS NOT NULL ORDER BY id"):
        prev = _link(prev, row)
        n += 1
        if not hmac.compare_digest(prev, row["chain"]):
            bad = row["id"]
            break
    unsealed = store.q1("SELECT COUNT(*) AS n FROM events WHERE chain IS NULL")["n"]
    return {"ok": bad is None, "sealed": n, "unsealed": unsealed, "head": None if bad else (prev if n else None),
            "first_bad_id": bad}


def _key(store) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=PURPOSE).derive(master_key(store.data_dir))


def export(store) -> bytes:
    """JSON lines of every sealed event, then {"farrier_audit_head", "rows", "signature"}."""
    lines, head, n = [], GENESIS, 0
    for row in store.q(f"SELECT {', '.join(FIELDS)}, chain FROM events WHERE chain IS NOT NULL ORDER BY id"):
        lines.append(json.dumps(row, ensure_ascii=False))
        head, n = row["chain"], n + 1
    sig = hmac.new(_key(store), f"{head}|{n}".encode(), hashlib.sha256).hexdigest()
    lines.append(json.dumps({"farrier_audit_head": head, "rows": n, "signature": sig}))
    return ("\n".join(lines) + "\n").encode()


def check_export(store, data: bytes) -> dict:
    """Verify an export file on its own: every link, and the signature over its head."""
    *rows, last = [json.loads(x) for x in data.decode().splitlines() if x.strip()]
    prev = GENESIS
    for row in rows:
        prev = _link(prev, row)
        if prev != row["chain"]:
            return {"ok": False, "first_bad_id": row["id"]}
    sig = hmac.new(_key(store), f"{prev}|{len(rows)}".encode(), hashlib.sha256).hexdigest()
    ok = last.get("farrier_audit_head") == prev and hmac.compare_digest(sig, str(last.get("signature")))
    return {"ok": ok, "rows": len(rows), "head": prev, "first_bad_id": None if ok else "signature"}


# ---- compliance report ---------------------------------------------------------------------------------
def compliance(engine, now=None) -> dict:
    """Per project: coverage, expiry risk, failures, 47-day readiness, weak keys; and the audit chain status."""
    now = now or policy.utcnow()
    from farrier.connectors import is_automated
    eps = [e for e in engine.store.endpoints() if e["enabled"]]
    since = (now - timedelta(days=30)).isoformat(timespec="seconds")
    failed = Counter(r["endpoint_id"] for r in engine.store.q(
        "SELECT endpoint_id FROM renewals WHERE state IN ('failed', 'rolled_back') AND updated_at >= ?", (since,)))
    projects: dict[str, Counter] = {}
    for e in eps:
        c = projects.setdefault(e["project"], Counter())
        c["endpoints"] += 1
        c["automated"] += is_automated(e["connector"])
        na, nb = parse_dt(e["not_after"]), parse_dt(e["not_before"])
        if na is None:
            c["no_certificate_seen"] += 1
            continue
        days = (na - now).total_seconds() / 86400
        c["expired"] += days < 0
        c["expiring_7d"] += 0 <= days < 7
        c["expiring_30d"] += 0 <= days < 30
        if nb is not None and (na - nb).days > policy.max_lifetime_days(now):
            c["longer_than_public_maximum"] += 1
        c["failed_renewals_30d"] += failed.get(e["id"], 0)
    from farrier.crypto import service as crypto
    cs = crypto.summary(engine.store)
    out = {}
    for name, c in sorted(projects.items()):
        out[name] = dict(c) | {"automated_pct": round(100 * c["automated"] / c["endpoints"], 1) if c["endpoints"] else 0}
    return {"generated_at": now.isoformat(timespec="seconds"), "max_public_lifetime_days": policy.max_lifetime_days(now),
            "projects": out, "crypto": {"assets": cs["total"], "pqc_status": cs["by_status"], "weak": cs["weak"]},
            "audit": verify(engine.store)}
