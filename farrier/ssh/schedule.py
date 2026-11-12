"""Leader-only periodic SSH re-scan and collection.

Engine._tick (leader only) calls ``run_due`` every cycle. When a run is due it starts on a background
thread so a slow fleet never holds up renewals, and at most one SSH run per process is in flight. Last-run
times live in the database, so a new leader after failover keeps the schedule.

Settings (settings.json): ssh_scan_hours (24), ssh_collect_hours (24), 0 disables either;
ssh_scan_targets: extra discovery targets in discovery syntax (default port 22).
Re-scan covers every host already in the SSH inventory, every host of every access profile and
ssh_scan_targets.
"""
from __future__ import annotations

import threading
from datetime import datetime, timedelta

from farrier.ssh import access, collect, db, scan

_running = threading.Lock()


def _due(store, kind: str, hours: float, now: datetime) -> bool:
    if not hours or hours <= 0:
        return False
    last = db.last_run(store, kind)
    return last is None or now - last >= timedelta(hours=hours)


def scan_targets(engine) -> list[tuple[str, int]]:
    targets = [(h["host"], h["port"]) for h in db.hosts(engine.store)]
    for p in access.profiles(engine.items).values():
        try:
            targets += access.expand_hosts(p["hosts"], p["port"])
        except access.Invalid:
            continue
    extra = engine.settings.get("ssh_scan_targets")
    if extra:
        try:
            targets += access.expand_hosts(extra, 22)
        except access.Invalid as e:
            engine.store.log(f"ssh_scan_targets ignored: {e}", level="warning")
    return list(dict.fromkeys(targets))[:access.MAX_HOSTS]


def _run(engine, do_scan: bool, do_collect: bool) -> None:
    try:
        if do_scan:
            targets = scan_targets(engine)
            if targets:
                r = scan.scan(engine.store, targets)
                engine.store.log(f"ssh periodic scan: {r['ssh']} of {r['scanned']} targets answered")
            db.mark_run(engine.store, "scan")
        if do_collect:
            r = collect.collect(engine.store, engine.items)
            if r["hosts"]:
                engine.store.log(f"ssh periodic collection: {r['ok']} of {r['hosts']} hosts, {r['keys']} keys")
    except Exception as e:  # noqa: BLE001 - a background job must report, not die silently
        engine.store.log(f"ssh periodic run failed: {type(e).__name__}: {e}", level="error")
    finally:
        _running.release()


def run_due(engine, now: datetime, background: bool = True) -> str | None:
    """Start whatever is due. Returns "scan", "collect", "scan+collect" or None."""
    s = engine.settings
    do_scan = _due(engine.store, "scan", float(s.get("ssh_scan_hours", 24)), now) and bool(scan_targets(engine))
    do_collect = (_due(engine.store, "collect", float(s.get("ssh_collect_hours", 24)), now)
                  and bool(access.profiles(engine.items)))
    if not (do_scan or do_collect) or not _running.acquire(blocking=False):
        return None
    what = "+".join(k for k, v in (("scan", do_scan), ("collect", do_collect)) if v)
    if background:
        try:
            threading.Thread(target=_run, args=(engine, do_scan, do_collect), daemon=True, name="farrier-ssh").start()
        except BaseException:
            _running.release()          # the thread never ran, so its finally never will
            raise
    else:
        _run(engine, do_scan, do_collect)
    return what
