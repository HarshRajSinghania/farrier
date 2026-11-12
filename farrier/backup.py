"""``farrier backup --to <storage url>`` and ``farrier restore --from <object url>``.

A backup is one JSON-lines object, ``backups/farrier-backup-<UTC timestamp>.jsonl`` under the storage URL:

    {"farrier_backup": 1, "created_at": ..., "schema_version": N, "database": "<backend>"}
    {"table": "endpoints", "row": {...}}
    ...

Every table is read inside one snapshot transaction, so the export is consistent even while renewals
run. Rows are copied as stored: sealed private keys and sealed secret values stay sealed (restoring needs
the same master key), JSON columns stay JSON text. Secrets held by a cloud secret backend are not in the
database at all; the backup keeps their index references.
"""
from __future__ import annotations

import base64
import json
from datetime import UTC, datetime

from .db import CONFIG_TABLES, TABLES, Store
from .storage import ObjectStorage, from_url

FORMAT = 1


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
    return storage.put(key, b"\n".join(export_lines(store)) + b"\n", "application/x-ndjson")


def restore(store: Store, data: bytes) -> dict[str, int]:
    """Load a backup into an empty database (ids kept). Returns rows per table."""
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
    with store.transaction():
        for ln in lines[1:]:
            rec = json.loads(ln)
            t, row = rec["table"], {k: _uncell(v) for k, v in rec["row"].items()}
            if t not in TABLES + CONFIG_TABLES:
                raise ValueError(f"unknown table {t!r} in backup")
            cols = list(row)
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
