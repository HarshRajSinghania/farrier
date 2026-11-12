"""``farrier backup --to <storage url>`` and ``farrier restore --from <object url>``.

A backup is one JSON-lines object, ``backups/farrier-backup-<UTC timestamp>.jsonl`` under the storage URL:

    {"farrier_backup": 1, "created_at": ..., "schema_version": N, "database": "<backend>"}
    {"table": "endpoints", "row": {...}}
    ...

Every table is read inside one snapshot transaction, so the export is consistent even while renewals
run. Rows are copied as stored: sealed private keys and sealed secret values stay sealed (restoring needs
the same master key), JSON columns stay JSON text. Secrets held by a cloud secret backend are not in the
database at all; the backup keeps their index references.

The last line signs everything before it: ``{"farrier_signature": "<hex HMAC-SHA256>"}``, keyed with
HKDF-SHA256(master key, info "farrier-backup-v1"). ``restore`` refuses a missing or wrong signature (whoever can
write the backup bucket could otherwise plant connector commands) unless ``allow_unsigned``; even then, rows
that carry command keys need FARRIER_ALLOW_API_COMMANDS, as they would through the API.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from datetime import UTC, datetime

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from farrier.db.store import CONFIG_TABLES, TABLES, Store
from farrier.security.vault import master_key
from farrier.storage import ObjectStorage, from_url

FORMAT = 1
SIG_PURPOSE = b"farrier-backup-v1"


def _mac(store: Store, body: bytes) -> str:
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=SIG_PURPOSE).derive(master_key(store.data_dir))
    return hmac.new(key, body, hashlib.sha256).hexdigest()


def _cell(v):
    return {"$b64": base64.b64encode(bytes(v)).decode()} if isinstance(v, (bytes, bytearray, memoryview)) else v


def _uncell(v):
    return base64.b64decode(v["$b64"]) if isinstance(v, dict) and set(v) == {"$b64"} else v


def export_lines(store: Store) -> list[bytes]:
    with store.snapshot():
        head = {"farrier_backup": FORMAT, "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
                "schema_version": store.schema_version(), "database": store.backend}
        lines = [json.dumps(head, sort_keys=True).encode()]
        for t in CONFIG_TABLES + TABLES:
            order = " ORDER BY id" if t in TABLES else ""
            for r in store._run(f"SELECT * FROM {t}{order}", (), fetch=True):
                lines.append(json.dumps({"table": t, "row": {k: _cell(v) for k, v in r.items()}},
                                        sort_keys=True, default=str).encode())
    return lines


def backup(store: Store, storage: ObjectStorage) -> str:
    """Write a backup object; return its URL."""
    key = f"backups/farrier-backup-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.jsonl"
    body = b"\n".join(export_lines(store)) + b"\n"
    sig = json.dumps({"farrier_signature": _mac(store, body)}).encode()
    return storage.put(key, body + sig + b"\n", "application/x-ndjson")


def _verify(store: Store, data: bytes, allow_unsigned: bool) -> tuple[bytes, bool]:
    """(body, signed). Raises on a missing or bad signature unless allow_unsigned."""
    body, _, last = data.rstrip().rpartition(b"\n")
    try:
        sig = json.loads(last).get("farrier_signature")
    except (ValueError, AttributeError):
        sig = None
    if isinstance(sig, str) and hmac.compare_digest(sig, _mac(store, body + b"\n")):
        return body, True
    if allow_unsigned:
        return (data if sig is None else body), False
    raise ValueError("the backup's signature is " + ("wrong (another master key, or the file was changed)"
                     if sig is not None else "missing (an old or altered backup)")
                     + "; pass --allow-unsigned only if you trust this file")


def _columns(store: Store, table: str) -> set[str]:
    with store._lock:
        cur = store.conn.cursor()
        cur.execute(store.dialect.translate(f"SELECT * FROM {table} WHERE 1=0"))
        cols = {c[0] for c in cur.description}
        cur.fetchall()
    return cols


def _commands(row: dict) -> list[str]:
    from farrier.api.app import _command_keys
    found = []
    for col in ("connector_config", "body"):        # endpoints, config_items
        v = row.get(col)
        try:
            found += _command_keys(json.loads(v) if isinstance(v, str) else v)
        except ValueError:
            pass
    return found


def restore(store: Store, data: bytes, allow_unsigned: bool = False) -> dict[str, int]:
    """Load a signed backup into an empty database (ids kept). Returns rows per table."""
    data, signed = _verify(store, data, allow_unsigned)
    allow_commands = os.environ.get("FARRIER_ALLOW_API_COMMANDS", "").lower() in ("1", "true", "yes")
    lines = [ln for ln in data.splitlines() if ln.strip()]
    if not lines:
        raise ValueError("the backup is empty")
    head = json.loads(lines[0])
    if head.get("farrier_backup") != FORMAT:
        raise ValueError("not a Farrier backup (or a newer format)")
    if head.get("schema_version", 0) > store.schema_version():
        raise ValueError(f"the backup is from schema version {head['schema_version']}; upgrade Farrier first")
    for t in TABLES + CONFIG_TABLES:
        if store._run(f"SELECT COUNT(*) AS n FROM {t}", (), fetch="one")["n"]:
            raise ValueError(f"destination table {t} is not empty; restore into a new database")
    counts: dict[str, int] = {}
    known = {t: _columns(store, t) for t in TABLES + CONFIG_TABLES}
    with store.transaction():
        for ln in lines[1:]:
            rec = json.loads(ln)
            t, row = rec["table"], {k: _uncell(v) for k, v in rec["row"].items()}
            if t not in TABLES + CONFIG_TABLES:
                raise ValueError(f"unknown table {t!r} in backup")
            cols = list(row)
            if bad := [c for c in cols if c not in known[t]]:
                raise ValueError(f"unknown column(s) {bad!r} for table {t} in backup")
            if not signed and not allow_commands and (found := _commands(row)):
                raise ValueError(f"unsigned backup row in {t} sets command keys {found}; "
                                 "set FARRIER_ALLOW_API_COMMANDS=1 to restore it")
            store._run(f"INSERT INTO {t}({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
                       tuple(row[c] for c in cols))
            counts[t] = counts.get(t, 0) + 1
        for t in TABLES:
            store.dialect.fix_sequence(store, t)
    return counts


def split_object_url(url: str) -> tuple[ObjectStorage, str]:
    """``s3://bucket/prefix/farrier-backup-x.jsonl`` -> (store for s3://bucket/prefix, key)."""
    parent, _, key = url.rstrip("/").rpartition("/")
    if not key or "://" not in parent:
        raise ValueError("--from must be the URL of a backup object, e.g. s3://bucket/prefix/farrier-backup-....jsonl")
    if parent.endswith(":/"):               # file:///name.jsonl
        parent += "/"
    return from_url(parent), key
