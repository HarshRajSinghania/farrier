"""Persistence for crypto assets (migration 5): latest result per target, plus history."""
from __future__ import annotations

import json

from farrier.crypto.analysis import asset_view, classify
from farrier.db.store import now_iso

HISTORY_PER_ASSET = 100


def save_result(store, result: dict) -> int:
    """Upsert the asset for ``result['target']`` and append the result to its history. Returns the asset id."""
    status = classify(result)["status"]
    body = json.dumps(result, sort_keys=True, default=str)
    observed = result.get("observed_at") or now_iso()
    kind = result.get("kind", "tls")
    with store.transaction():
        row = store.q1("SELECT id FROM crypto_assets WHERE kind=? AND target=?", (kind, result["target"]))
        if row:
            aid = row["id"]
            store.x("UPDATE crypto_assets SET status=?, result=?, observed_at=? WHERE id=?",
                    (status, body, observed, aid))
        else:
            aid = store.x("""INSERT INTO crypto_assets(kind, target, host, port, sni, status, result, observed_at,
                             created_at) VALUES (?,?,?,?,?,?,?,?,?)""",
                          (kind, result["target"], result["host"], result["port"], result.get("sni"), status, body,
                           observed, now_iso()))
        store.x("INSERT INTO crypto_scans(asset_id, observed_at, status, result) VALUES (?,?,?,?)",
                (aid, observed, status, body))
        store.x("""DELETE FROM crypto_scans WHERE asset_id=? AND id NOT IN (
                     SELECT id FROM (SELECT id FROM crypto_scans WHERE asset_id=? ORDER BY id DESC LIMIT ?) AS keep)""",
                (aid, aid, HISTORY_PER_ASSET))
    return aid


def endpoint_ids(store) -> dict[tuple[str, int, str], int]:
    return {(e["host"], e["port"], e["sni"] or ""): e["id"]
            for e in store.q("SELECT id, host, port, sni FROM endpoints")}


def tls_assets(store) -> list[dict]:
    """Every stored TLS asset in the API shape, linked to its inventory endpoint when there is one."""
    eps = endpoint_ids(store)
    out = []
    for r in store.q("SELECT id, host, port, sni, result FROM crypto_assets WHERE kind='tls' ORDER BY target"):
        out.append(asset_view(r["id"], json.loads(r["result"]), eps.get((r["host"], r["port"], r["sni"] or ""))))
    return out


def raw_results(store) -> list[tuple[int, dict]]:
    """(asset id, latest probe result) for every TLS asset: for the CBOM."""
    return [(r["id"], json.loads(r["result"]))
            for r in store.q("SELECT id, result FROM crypto_assets WHERE kind='tls' ORDER BY target")]


def history(store, asset_id: int, limit: int = 20) -> list[dict]:
    return [{"observed_at": r["observed_at"], "status": r["status"]}
            for r in store.q("SELECT observed_at, status FROM crypto_scans WHERE asset_id=? ORDER BY id DESC LIMIT ?",
                             (asset_id, limit))]


def last_scanned(store) -> dict[tuple[str, int, str], str]:
    """(host, port, sni or '') -> observed_at of the latest TLS probe."""
    return {(r["host"], r["port"], r["sni"] or ""): r["observed_at"]
            for r in store.q("SELECT host, port, sni, observed_at FROM crypto_assets WHERE kind='tls'")}
