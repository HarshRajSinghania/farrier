"""Crypto discovery operations: scan targets, re-scan the inventory, and read assets (TLS + SSH)."""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

from farrier.crypto import repository
from farrier.crypto.analysis import asset_view, summarize
from farrier.crypto.cbom import build_cbom
from farrier.crypto.probe import probe_tls
from farrier.db.store import parse_dt

MAX_TARGETS = 4096          # per request, same limit as discovery
MAX_WORKERS = 16            # each target costs up to seven sequential handshakes
RESCAN_BATCH = 256          # endpoints re-probed per tick at most; the rest wait for the next tick

log = logging.getLogger(__name__)


def probe_many(targets: list[tuple[str, int, str | None]], timeout: float, workers: int = MAX_WORKERS) -> list[dict]:
    if not targets:
        return []
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(targets)))) as pool:
        return list(pool.map(lambda t: probe_tls(t[0], t[1], t[2], timeout), targets))


def scan_targets(store, targets: list[tuple[str, int, str | None]], timeout: float = 5.0,
                 workers: int = MAX_WORKERS, project_id: int | None = None, allowed=None) -> dict:
    """Probe, store, and summarise what was just scanned. New assets go to ``project_id``; with
    ``allowed(project id) -> bool``, a target that belongs to another project (its asset or its inventory
    endpoint) is probed but neither stored nor reported."""
    if len(targets) > MAX_TARGETS:
        raise ValueError(f"{len(targets)} targets; split the range (max {MAX_TARGETS} per request)")
    results = probe_many(targets, timeout, workers)
    eps = repository.endpoint_ids(store)
    views = []
    by_asset, by_ep = repository.owners(store) if allowed is not None else ({}, {})
    for r in results:
        row = store.q1("SELECT id FROM crypto_assets WHERE kind='tls' AND target=?", (r["target"],))
        if allowed is not None:
            owner = by_asset.get(row["id"]) if row else by_ep.get((r["host"], r["port"], r["sni"] or ""))
            if owner is not None and not allowed(owner):
                continue
        if r.get("error") and not row:
            continue        # nothing listening and never seen: don't fill the inventory with dead addresses
        aid = repository.save_result(store, r, project_id)
        views.append(asset_view(aid, r, eps.get((r["host"], r["port"], r["sni"] or ""))))
    return summarize(views) | {"scanned": len(targets), "stored": len(views)}


def rescan_due(engine, now: datetime | None = None) -> int:
    """Re-probe inventory endpoints whose crypto result is older than ``crypto_scan_hours`` (leader only:
    called from the engine tick). Only endpoints whose last TLS handshake succeeded are probed, so dead
    hosts cost nothing here. Returns how many were probed."""
    from farrier.core.runners import runner_of
    hours = float(engine.settings.get("crypto_scan_hours", 24) or 0)
    if hours <= 0:
        return 0
    now = now or datetime.now().astimezone()
    cutoff = now - timedelta(hours=hours)
    seen = repository.last_scanned(engine.store)
    due = []
    for e in engine.store.endpoints():
        if not e["enabled"] or not e["fingerprint"] or e["scan_error"] or runner_of(e):
            continue   # behind a runner: the engine can't reach it (shortcut: no crypto probe via runners yet)
        last = parse_dt(seen.get((e["host"], e["port"], e["sni"] or "")))
        if last is None or last <= cutoff:
            due.append((last is not None, last, (e["host"], e["port"], e["sni"])))
    due.sort(key=lambda d: (d[0], d[1] or now))        # never-scanned first, then the stalest
    targets = [t for *_, t in due[:RESCAN_BATCH]]
    timeout = float(engine.settings.get("scan_timeout", 5.0))
    pids = {(e["host"], e["port"], e["sni"] or ""): e["project_id"] for e in engine.store.endpoints()}
    for r in probe_many(targets, timeout, workers=8):
        repository.save_result(engine.store, r, pids.get((r["host"], r["port"], r.get("sni") or "")))
    return len(targets)


def ssh_assets(store) -> list[dict]:
    """SSH assets from farrier.ssh when that package (and its tables) exist; [] otherwise."""
    try:
        from farrier.ssh import ssh_crypto_assets  # type: ignore[attr-defined]
    except ImportError:
        return []
    try:
        return [a | {"kind": "ssh"} for a in ssh_crypto_assets(store)]
    except Exception as e:  # noqa: BLE001 - missing tables or an SSH-side bug must not break crypto reports
        log.warning("ssh_crypto_assets failed: %s: %s", type(e).__name__, e)
        return []


def all_assets(store) -> list[dict]:
    return repository.tls_assets(store) + ssh_assets(store)


def summary(store) -> dict:
    return summarize(all_assets(store))


def cbom(store) -> dict:
    from farrier import __version__
    return build_cbom(all_assets(store), dict(repository.raw_results(store)), version=__version__)
