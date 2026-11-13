"""`farrier explain` / GET /api/endpoints/{id}/explain: why an endpoint's next renewal is when it is.

Uses the planner's own maths (Engine.schedule), so the answer is what plan() would do now, plus the gates a
planned renewal still has to pass (approval, issuance policy, runner group) and the last failure.
"""
from __future__ import annotations

from datetime import timedelta

from farrier.connectors import is_automated
from farrier.core import approvals, issuance_policy, policy, reasons
from farrier.core.engine import discovered
from farrier.core.runners import runner_of
from farrier.core.scheduler import zone
from farrier.db.store import parse_dt

RENEWAL_COLS = "id, state, reason, scheduled_for, deadline, attempts, error, ticket_ref, created_at, updated_at"


def _iso(d):
    return d.isoformat(timespec="seconds") if d else None


def explain(engine, ep: dict, now=None) -> dict:
    now = now or policy.utcnow()
    S = engine.store
    last_obs = S.q1("SELECT fingerprint, not_after, not_before, error FROM observations WHERE endpoint_id=? "
                    "ORDER BY observed_at DESC, id DESC LIMIT 1", (ep["id"],))   # this endpoint's only, not the inventory
    row = {**ep, **{k: (last_obs or {}).get(k) for k in ("fingerprint", "not_after", "not_before")},
           "scan_error": (last_obs or {}).get("error")}
    obs = S.latest_cert_observation(ep["id"])
    group = runner_of(ep)
    out = {
        "endpoint": {"id": ep["id"], "name": ep["name"], "host": ep["host"], "port": ep["port"],
                     "project": ep.get("project"), "connector": ep["connector"],
                     "automated": is_automated(ep["connector"]), "issuer": ep["issuer"] or "default",
                     "enabled": bool(ep["enabled"]), "runner_group": group},
        "now": _iso(now),
        "certificate": None, "schedule": None, "open_renewal": None, "approval": None, "policy": None,
        "runner": None, "last_failure": None, "blockers": [], "next": {"at": None, "summary": ""},
    }
    blockers = out["blockers"]
    if obs:
        na = parse_dt(obs["not_after"])
        out["certificate"] = {"fingerprint": obs["fingerprint"], "subject_cn": obs["subject_cn"],
                              "not_before": obs["not_before"], "not_after": obs["not_after"],
                              "days_left": round(policy.days_left(na, now), 1)}
    if row.get("scan_error") and not row.get("fingerprint"):
        blockers.append(f"the last scan failed ({row['scan_error']}); nothing is planned until a handshake succeeds")

    # gates a planned renewal passes before any key or CA request
    mode = approvals.mode_for(engine.settings, ep)
    names = engine.names(ep)
    issuer_name = ep["issuer"] if ep["issuer"] in engine.issuers else "default"
    bad = issuance_policy.violations(issuance_policy.rules_for(engine.settings.get("policy"), ep.get("project")),
                                     names, issuer_name, ep["key_type"])
    out["policy"] = {"names": names, "issuer": issuer_name, "key_type": ep["key_type"], "allowed": not bad,
                     "violations": bad}
    if bad:
        blockers.append("issuance policy: " + "; ".join(bad) + " [POLICY_DENIED]")
    if group:
        g = engine.runners.group_status(group)
        out["runner"] = g or {"group": group, "online": False, "token": False, "pending_jobs": 0}
        if not out["runner"]["online"]:
            blockers.append(f"runner group {group} is offline (last seen {out['runner'].get('last_seen') or 'never'})"
                            " [DEPLOY_RUNNER_OFFLINE]")

    open_r = S.q1(f"SELECT {RENEWAL_COLS} FROM renewals WHERE endpoint_id=? AND state IN "
                  "('planned','issued','deploying','verifying','awaiting_manual') ORDER BY id DESC LIMIT 1", (ep["id"],))
    rec = engine.approvals.get(open_r["id"]) if open_r else None
    out["approval"] = {"mode": mode, "state": rec["state"] if rec else None,
                       "overdue": bool(rec and rec.get("overdue")), "ticket": (rec or {}).get("ticket")}
    if open_r:
        out["open_renewal"] = reasons.annotate(open_r, rec)
    last = S.q1(f"SELECT {RENEWAL_COLS} FROM renewals WHERE endpoint_id=? AND state IN ('failed','rolled_back') "
                "ORDER BY id DESC LIMIT 1", (ep["id"],))
    if last:
        out["last_failure"] = reasons.annotate(last)

    if obs and row.get("fingerprint"):
        s = engine.schedule(row, now, engine.open_load(), beyond_horizon=True)
        w = ep.get("window") or {}
        tz = zone(w) if w else None
        horizon = engine.settings["horizon_days"]
        retry = s["backoff"]
        out["schedule"] = {
            "observed_lifetime_days": max(1, (s["not_after"] - s["not_before"]).days),
            "max_lifetime_days": policy.max_lifetime_days(now), "lifetime_days": s["lifetime_days"],
            "lead_days": ep["lead_days"], "renew_before_days": s["renew_before_days"],
            "lifetime_due": _iso(s["not_after"] - timedelta(days=s["renew_before_days"])),
            "ari_due": _iso(s["ari_due"]), "due": _iso(s["due"]),
            "horizon_days": horizon, "plan_from": _iso(s["due"] - timedelta(days=horizon)),
            "window": w or None, "window_tz": (w.get("tz") or "UTC") if w else None,
            "window_start": _iso(s["window_start"]),
            "window_start_local": _iso(s["window_start"].astimezone(tz)) if s["window_start"] and tz else None,
            "deadline": _iso(s["latest"]), "class": s["class"], "daily_cap": s["daily_cap"],
            "leveled": bool(s["window_start"] and s["start"] and s["start"].date() > s["window_start"].date()
                            and not retry),
            "backoff": {"failures": retry[1], "until": _iso(retry[0]), "active": retry[0] > now} if retry else None,
            "start": _iso(s["start"]), "reason": s["reason"],
        }
        if retry and retry[0] > now:
            blockers.append(f"backing off after {retry[1]} failed renewal(s) until {retry[0]:%Y-%m-%d %H:%M} UTC")

    nxt = out["next"]
    if not ep["enabled"]:
        nxt["summary"] = "endpoint is disabled: nothing is planned"
    elif discovered(ep):
        nxt["summary"] = "discovered endpoint, monitor only: approve it (farrier endpoints approve) to renew it"
    elif open_r and open_r["state"] == "planned":
        nxt["at"] = open_r["scheduled_for"]
        nxt["summary"] = f"renewal #{open_r['id']} is planned ({open_r['reason']})"
        if out["open_renewal"]["reason_code"]:
            nxt["summary"] += f"; {out['open_renewal']['reason_code']}"
    elif open_r:
        nxt["summary"] = f"renewal #{open_r['id']} is in progress ({open_r['state']})"
    elif not out["schedule"]:
        nxt["summary"] = "no certificate seen yet: run a scan (farrier tick)" if not obs else \
            "waiting for a successful scan before planning"
    else:
        sch = out["schedule"]
        nxt["at"] = sch["start"]
        nxt["summary"] = (f"will be planned for {sch['start'][:16]} UTC ({sch['reason']})" +
                          (f" on the tick after {sch['plan_from'][:10]} (due within {sch['horizon_days']} days)"
                           if parse_dt(sch["plan_from"]) > now else " on the next tick"))
    if open_r and out["approval"]["state"] == "pending":
        blockers.append(f"waiting for approval ({rec['mode']})" + (" and overdue" if rec.get("overdue") else ""))
    return out


def lines(d: dict):
    """Human text for `farrier explain`."""
    e = d["endpoint"]
    yield f"{e['name']} (id {e['id']}, {e['host']}:{e['port']}, {e['connector']}, issuer {e['issuer']}" + \
          (f", runner group {e['runner_group']}" if e["runner_group"] else "") + ")"
    yield f"Next: {d['next']['summary']}" + (f" -> {d['next']['at']}" if d["next"]["at"] else "")
    c = d["certificate"]
    if c:
        yield f"Certificate: {c['subject_cn']}, valid {c['not_before'][:10]} -> {c['not_after'][:10]} " \
              f"({c['days_left']} days left)"
    s = d["schedule"]
    if s:
        cap = "" if s["lifetime_days"] == s["observed_lifetime_days"] else \
            f", capped to today's public maximum of {s['max_lifetime_days']}"
        yield f"Lifetime: {s['observed_lifetime_days']} days{cap}; renew {s['renew_before_days']} days before expiry " \
              f"(a third of the lifetime, at least lead_days={s['lead_days']}, at most three quarters) -> " \
              f"{s['lifetime_due'][:16]}"
        if s["ari_due"]:
            yield f"ARI: the CA suggests renewing around {s['ari_due'][:16]}" + \
                  (" (earlier, so it wins)" if s["ari_due"] == s["due"] else " (later than the lifetime rule, ignored)")
        yield f"Due: {s['due'][:16]} UTC; planned once due is within horizon_days={s['horizon_days']} " \
              f"(from {s['plan_from'][:10]}); deadline {s['deadline'][:16]} UTC (expiry minus safety_days)"
        if s["window"]:
            w = s["window"]
            local = f" = {s['window_start_local'][:16]} {s['window_tz']}" if s["window_start_local"] else ""
            opening = f"{s['window_start'][:16]} UTC{local}" if s["window_start"] else "none before the deadline"
            yield f"Window: {','.join(w.get('days') or ['every day'])} {w.get('start', '00:00')} for " \
                  f"{w.get('hours', 24)} h ({s['window_tz']}); first opening from the due date: {opening}"
        else:
            yield "Window: none (any time)"
        yield f"Daily cap: {s['daily_cap']} {s['class']} renewals per day" + \
              (" -> moved to a later day with spare capacity" if s["leveled"] else "")
        if s["backoff"]:
            b = s["backoff"]
            yield f"Backoff: {b['failures']} failed renewal(s) in a row; retries not before {b['until'][:16]} UTC" + \
                  ("" if b["active"] else " (lifted)")
        yield f"Planner {'would choose, were nothing open' if d['open_renewal'] else 'chooses'}: "               f"{s['start'][:16]} UTC ({s['reason']})"
    a = d["approval"]
    if a["mode"]:
        yield f"Approval: {a['mode']}, {a['state'] or 'asked once the renewal is due'}" +               (" (overdue)" if a["overdue"] else "")
    else:
        yield "Approval: not required"
    p = d["policy"]
    yield "Issuance policy: " + ("allowed" if p["allowed"] else "DENIED: " + "; ".join(p["violations"]))
    if d["runner"]:
        r = d["runner"]
        yield f"Runner group {r['group']}: {'online' if r['online'] else 'OFFLINE'}, last seen " \
              f"{r.get('last_seen') or 'never'}, {r.get('pending_jobs', 0)} pending job(s)"
    if (o := d["open_renewal"]) and o["reason_code"]:
        yield f"Open renewal #{o['id']}: {o['reason_code']}: {o['error'] or o['state']}"
        yield f"  what to do: {o['hint']}"
    if f := d["last_failure"]:
        yield f"Last failure: renewal #{f['id']} {f['state']} {f['updated_at'][:16]}: {f['reason_code']}: {f['error']}"
        yield f"  what to do: {f['hint']}"
    for b in d["blockers"]:
        yield f"Blocker: {b}"
