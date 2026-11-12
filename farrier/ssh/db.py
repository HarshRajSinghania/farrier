"""Storage for the SSH inventory (tables from migration 6). Thin: SQL in, plain dicts out."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime

from farrier.db.store import now_iso, parse_dt


# ---- hosts ------------------------------------------------------------------------------------------
def save_host(store, host: str, port: int, banner: str | None, data: dict, pqc_kex: bool,
              error: str | None, project_id: int | None = None) -> int:
    """A new host goes to ``project_id`` (default: the default project); a known one keeps its project."""
    body, t = json.dumps(data, sort_keys=True), now_iso()
    with store.transaction():
        row = store.q1("SELECT id FROM ssh_hosts WHERE host=? AND port=?", (host, port))
        if row:
            store.x("UPDATE ssh_hosts SET banner=?, data=?, pqc_kex=?, error=?, observed_at=? WHERE id=?",
                    (banner, body, int(pqc_kex), error, t, row["id"]))
            return row["id"]
        pid = project_id if project_id is not None else store.default_project_id()
        return store.x("INSERT INTO ssh_hosts(host, port, banner, data, pqc_kex, error, observed_at, project_id) "
                       "VALUES (?,?,?,?,?,?,?,?)", (host, port, banner, body, int(pqc_kex), error, t, pid))


def _host(r: dict) -> dict:
    return {k: v for k, v in r.items() if k != "data"} | json.loads(r["data"]) | {"pqc_kex": bool(r["pqc_kex"])}


def hosts(store) -> list[dict]:
    return [_host(r) for r in store.q("SELECT * FROM ssh_hosts ORDER BY host, port")]


def host(store, hid: int) -> dict | None:
    r = store.q1("SELECT * FROM ssh_hosts WHERE id=?", (hid,))
    return _host(r) if r else None


def host_by_addr(store, host_: str, port: int) -> dict | None:
    r = store.q1("SELECT * FROM ssh_hosts WHERE host=? AND port=?", (host_, port))
    return _host(r) if r else None


def set_host_accounts(store, host_: str, port: int, accounts: list[str]) -> None:
    """Remember a host's account names (learned by collection) for fleet-wide orphan detection."""
    with store.transaction():
        r = store.q1("SELECT id, data FROM ssh_hosts WHERE host=? AND port=?", (host_, port))
        if r:
            data = json.loads(r["data"]) | {"accounts": accounts}
            store.x("UPDATE ssh_hosts SET data=? WHERE id=?", (json.dumps(data, sort_keys=True), r["id"]))


# ---- host-key pins ----------------------------------------------------------------------------------
def pins(store, host_: str, port: int) -> list[dict]:
    return store.q("SELECT key_type, key_b64, fingerprint, source, pinned_at FROM ssh_host_pins "
                   "WHERE host=? AND port=? ORDER BY key_type", (host_, port))


def add_pins(store, host_: str, port: int, keys: list, source: str) -> None:
    """``keys``: PublicKey objects. Existing pins are never overwritten here."""
    t = now_iso()
    with store.transaction():
        have = {p["key_type"] for p in pins(store, host_, port)}
        for k in keys:
            if k.type not in have:
                store.x("INSERT INTO ssh_host_pins(host, port, key_type, key_b64, fingerprint, source, pinned_at) "
                        "VALUES (?,?,?,?,?,?,?)", (host_, port, k.type, k.b64, k.fingerprint_sha256, source, t))


def replace_pins(store, host_: str, port: int, keys: list, source: str) -> None:
    with store.transaction():
        store.x("DELETE FROM ssh_host_pins WHERE host=? AND port=?", (host_, port))
        add_pins(store, host_, port, keys, source)


# ---- authorized keys --------------------------------------------------------------------------------
def key_uid(host_: str, port: int, user: str, path: str, line_sha256: str) -> str:
    return hashlib.sha256(f"{host_}\0{port}\0{user}\0{path}\0{line_sha256}".encode()).hexdigest()[:40]


def sync_host_keys(store, host_: str, port: int, access: str, rows: list[dict],
                   keep_paths: frozenset[str] = frozenset(), project_id: int | None = None) -> dict:
    """Make the stored keys for host:port exactly ``rows`` (from one successful collection).
    Each row: username, path, line_sha256, fingerprint, data (dict). Keeps first_seen for keys still present;
    keys in ``keep_paths`` (files that exist but could not be read this time) are left as they were."""
    t = now_iso()
    added = 0
    pid = project_id if project_id is not None else store.default_project_id()   # the collecting profile's
    with store.transaction():
        existing = {r["uid"]: r for r in store.q("SELECT id, uid, path FROM ssh_keys WHERE host=? AND port=?",
                                                 (host_, port))}
        seen = set()
        for r in rows:
            uid = key_uid(host_, port, r["username"], r["path"], r["line_sha256"])
            if uid in seen:
                continue        # the same line twice in one file: one inventory entry
            seen.add(uid)
            body = json.dumps(r["data"], sort_keys=True)
            if uid in existing:
                store.x("UPDATE ssh_keys SET data=?, access=?, last_seen=?, project_id=? WHERE uid=?",
                        (body, access, t, pid, uid))
            else:
                added += 1
                store.x("INSERT INTO ssh_keys(uid, host, port, access, username, path, line_sha256, data, fingerprint, "
                        "first_seen, last_seen, project_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                        (uid, host_, port, access, r["username"], r["path"], r["line_sha256"], body, r["fingerprint"], t,
                         t, pid))
        gone = [r["id"] for u, r in existing.items() if u not in seen and r["path"] not in keep_paths]
        for kid in gone:
            store.x("DELETE FROM ssh_keys WHERE id=?", (kid,))
    return {"keys": len(seen), "added": added, "removed": len(gone)}


def _key(r: dict) -> dict:
    return {k: v for k, v in r.items() if k != "data"} | json.loads(r["data"])


def keys(store) -> list[dict]:
    return [_key(r) for r in store.q("SELECT * FROM ssh_keys ORDER BY host, port, username, path, id")]


def key(store, kid: int) -> dict | None:
    r = store.q1("SELECT * FROM ssh_keys WHERE id=?", (kid,))
    return _key(r) if r else None


def set_key_findings(store, kid: int, findings: list[dict]) -> None:
    with store.transaction():
        r = store.q1("SELECT data FROM ssh_keys WHERE id=?", (kid,))
        if r:
            data = json.loads(r["data"]) | {"findings": findings}
            store.x("UPDATE ssh_keys SET data=? WHERE id=?", (json.dumps(data, sort_keys=True), kid))


def delete_key(store, kid: int) -> None:
    store.x("DELETE FROM ssh_keys WHERE id=?", (kid,))


# ---- periodic runs ----------------------------------------------------------------------------------
def last_run(store, kind: str) -> datetime | None:
    r = store.q1("SELECT last_run_at FROM ssh_runs WHERE kind=?", (kind,))
    return parse_dt(r["last_run_at"]) if r else None


def mark_run(store, kind: str) -> None:
    t = now_iso()
    with store.transaction():
        if not store._run("UPDATE ssh_runs SET last_run_at=? WHERE kind=?", (t, kind))[1]:
            store.x("INSERT INTO ssh_runs(kind, last_run_at) VALUES (?,?)", (kind, t))
