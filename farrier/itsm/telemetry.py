"""The leader's per-tick telemetry for observability channels.

  datadog  every tick: farrier.certificate.days_left (gauge, per endpoint) and farrier.renewals.failed
           (count of renewals that ended failed / rolled_back since the last successful submit; the
           watermark is kept in alert_state, so failover neither loses nor double-counts much)
  splunk   once a day: an inventory snapshot, one HEC event per endpoint with its certificate fields

"Once a day" uses alert_state (rule ``~itsm:<channel>``), the same cross-replica claim alert rules use:
a restart or a failover does not resend the day's snapshot. A failed snapshot is retried about an hour
later.
"""
from __future__ import annotations

from contextlib import closing
from datetime import timedelta

from farrier.db.store import parse_dt
from farrier.itsm import adapter_for
from farrier.itsm.base import as_bool
from farrier.itsm.datadog import COUNT, GAUGE, tag


def _state_key(name: str) -> str:
    return f"~itsm:{name}"


def _env(ep: dict, default: str | None) -> str | None:
    for t in ep.get("tags") or []:
        for sep in (":", "="):
            if isinstance(t, str) and t.startswith("env" + sep):
                return t[4:]
    return default


def days_left_series(endpoints: list[dict], now, default_env: str | None) -> list[dict]:
    ts = int(now.timestamp())
    out = []
    for e in endpoints:
        na = parse_dt(e.get("not_after"))
        if not e.get("enabled") or not na:
            continue
        tags = [tag("endpoint", e["name"]), tag("connector", e.get("connector")), tag("issuer", e.get("issuer"))]
        if (env := _env(e, default_env)):
            tags.append(tag("env", env))
        out.append({"metric": "farrier.certificate.days_left", "type": GAUGE,
                    "points": [{"timestamp": ts, "value": round((na - now) / timedelta(days=1), 2)}],
                    "tags": tags, "resources": [{"type": "host", "name": str(e.get("host"))}]})
    return out


def _watermark(store, name: str) -> str | None:
    r = store.q1("SELECT fired_at FROM alert_state WHERE rule=? AND subject='failed-watermark'", (_state_key(name),))
    return r["fired_at"] if r else None


def _set_state(store, name: str, subject: str, at: str) -> None:
    if not store._run("UPDATE alert_state SET fired_at=? WHERE rule=? AND subject=?", (at, _state_key(name), subject))[1]:
        store.x("INSERT INTO alert_state(rule, subject, fired_at) VALUES (?,?,?)", (_state_key(name), subject, at))


def datadog_metrics(engine, cfg: dict, now, transport=None) -> int:
    store, name = engine.store, cfg["name"]
    series = days_left_series(store.endpoints(), now, cfg.get("env"))
    t = now.isoformat(timespec="seconds")
    since = _watermark(store, name)
    failed = 0
    if since:
        failed = store.q1("SELECT COUNT(*) AS n FROM renewals WHERE state IN ('failed','rolled_back') "
                          "AND updated_at >= ? AND updated_at < ?", (since, t))["n"]   # [since, t): each counted once
    ftags = [tag("env", cfg["env"])] if cfg.get("env") else []
    series.append({"metric": "farrier.renewals.failed", "type": COUNT,
                   "points": [{"timestamp": int(now.timestamp()), "value": failed}], "tags": ftags})
    with closing(adapter_for(cfg, transport=transport)) as a:
        a.submit_series(series)
    _set_state(store, name, "failed-watermark", t)
    return len(series)


def inventory_events(a, endpoints: list[dict], now) -> list[dict]:
    day = now.strftime("%Y-%m-%d")
    out = []
    for e in endpoints:
        na = parse_dt(e.get("not_after"))
        ev = {"kind": "inventory", "id": f"inventory-{e['id']}-{day}", "snapshot_date": day,
              "endpoint": e["name"], "host": e["host"], "port": e["port"], "connector": e.get("connector"),
              "issuer": e.get("issuer"), "owner": e.get("owner"), "tags": e.get("tags") or [],
              "enabled": bool(e.get("enabled")), "names": e.get("sans") or [],
              "certificate": None if not e.get("fingerprint") else {
                  "fingerprint_sha256": e.get("fingerprint"), "subject_cn": e.get("subject_cn"),
                  "issuer": e.get("cert_issuer"), "not_before": e.get("not_before"), "not_after": e.get("not_after"),
                  "days_left": round((na - now) / timedelta(days=1), 2) if na else None},
              "observed_at": e.get("observed_at"), "scan_error": e.get("scan_error")}
        out.append(a.wrap(ev, now.timestamp()))
    return out


def splunk_inventory(engine, cfg: dict, now, transport=None) -> int:
    name = cfg["name"]
    if not engine.alerts.claim(_state_key(name), "inventory", 23, now):
        return 0
    try:
        with closing(adapter_for(cfg, transport=transport)) as a:
            events = inventory_events(a, engine.store.endpoints(), now)
            if events:
                a.send_events(events)
    except Exception:
        # try again in about an hour rather than tomorrow
        _set_state(engine.store, name, "inventory", (now - timedelta(hours=22)).isoformat(timespec="seconds"))
        raise
    return len(events)


def run(engine, channels: list[dict], now, transport=None) -> dict:
    from farrier.monitoring.notify import failure_detail
    out = {}
    for cfg in channels:
        name, kind = cfg.get("name"), cfg.get("type")
        if not name:
            continue
        try:
            if kind == "datadog" and as_bool(cfg.get("metrics"), True):
                out[name] = datadog_metrics(engine, cfg, now, transport)
            elif kind == "splunk" and as_bool(cfg.get("inventory"), True):
                out[name] = splunk_inventory(engine, cfg, now, transport)
        except Exception as e:  # noqa: BLE001 - one broken channel must not stop the others
            engine.store.log(f"{kind} telemetry on alert channel {name} failed: {failure_detail(e)}"[:500],
                             level="warning")
    return out
