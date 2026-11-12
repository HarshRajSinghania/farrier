"""Custom alert rules, configured in the dashboard and stored as config_items (kind "alert_rule").

    {"enabled": true, "channels": ["ops-slack"], "cooldown_hours": 24,
     "when": {"type": "expiring", "days": 7},
     "filter": {"tags": ["prod"], "connectors": ["f5"], "name": "web-*"}}

when.type:
  event        renewal state changes (fired from the engine's notification path, on any replica)
  expiring     the served certificate expires within N days
  health       the last stored health grade is below A/B/C/D (never probes from the rule loop)
  zombie       zombie certificate findings (optionally only some kinds)
  unreachable  no TLS answer for N days (zombie's dead_endpoint)
Threshold rules are evaluated at the end of each tick, by the leader only. Every (rule, subject) fires at
most once per cooldown; the time it fired is kept in ``alert_state`` so restarts and failover don't re-send.
"""
from __future__ import annotations

import fnmatch
from datetime import timedelta

from farrier.core import policy
from farrier.db.store import parse_dt

RULE_TYPES = {"event": "Renewal events", "expiring": "Certificate expiring", "health": "Health grade below",
              "zombie": "Zombie certificates", "unreachable": "Endpoint unreachable"}
GRADES = "ABCDF"
RULE_KEYS = {"enabled", "when", "filter", "channels", "cooldown_hours"}
DIGEST_OVER = 10   # more hits than this for one rule in one evaluation -> one summary message


def _str_list(v, what: str) -> list[str]:
    if not isinstance(v, list) or not all(isinstance(x, str) and x.strip() for x in v):
        raise ValueError(f"{what} must be a list of strings")
    return [x.strip() for x in v]


def validate_rule(body, channels_known) -> dict:
    from farrier.monitoring.notify import EVENTS
    from farrier.monitoring.zombie import SEVERITY
    if not isinstance(body, dict):
        raise ValueError("send {enabled, when, filter?, channels, cooldown_hours?}")
    unknown = sorted(set(body) - RULE_KEYS)
    if unknown:
        raise ValueError(f"unknown keys {unknown} (allowed: {sorted(RULE_KEYS)})")
    if not isinstance(body.get("enabled"), bool):
        raise ValueError("enabled must be true or false")
    w = body.get("when")
    if not isinstance(w, dict) or w.get("type") not in RULE_TYPES:
        raise ValueError(f"when.type must be one of {', '.join(RULE_TYPES)}")
    kind = w["type"]

    def days(lo, hi):
        d = w.get("days")
        if isinstance(d, bool) or not isinstance(d, int) or not lo <= d <= hi:
            raise ValueError(f"when.days must be a whole number from {lo} to {hi}")
        return d

    if kind == "event":
        ev = _str_list(w.get("events"), "when.events")
        bad = sorted(set(ev) - (EVENTS - {"test"}))
        if not ev or bad:
            raise ValueError(f"when.events must be drawn from {sorted(EVENTS - {'test'})}")
        when = {"type": kind, "events": ev}
    elif kind == "expiring":
        when = {"type": kind, "days": days(1, 365)}
    elif kind == "unreachable":
        when = {"type": kind, "days": days(1, 90)}
    elif kind == "health":
        if w.get("below") not in ("A", "B", "C", "D"):
            raise ValueError("when.below must be A, B, C or D")
        when = {"type": kind, "below": w["below"]}
    else:
        kinds = _str_list(w["kinds"], "when.kinds") if w.get("kinds") else []
        bad = sorted(set(kinds) - set(SEVERITY))
        if bad:
            raise ValueError(f"unknown zombie kinds {bad} (known: {sorted(SEVERITY)})")
        when = {"type": kind, "kinds": kinds} if kinds else {"type": kind}
    extra = set(w) - set(when) - ({"kinds"} if kind == "zombie" else set())
    if extra:
        raise ValueError(f"unknown when keys {sorted(extra)} for {kind}")

    f = body.get("filter") or {}
    if not isinstance(f, dict) or set(f) - {"tags", "connectors", "name"}:
        raise ValueError("filter may hold tags, connectors and name")
    flt = {}
    if f.get("tags"):
        flt["tags"] = _str_list(f["tags"], "filter.tags")
    if f.get("connectors"):
        flt["connectors"] = _str_list(f["connectors"], "filter.connectors")
    if f.get("name"):
        if not isinstance(f["name"], str):
            raise ValueError("filter.name must be a glob such as web-*")
        flt["name"] = f["name"].strip()

    ch = _str_list(body.get("channels"), "channels")
    if not ch:
        raise ValueError("channels must name at least one alert channel")
    missing = [c for c in ch if c not in channels_known]
    if missing:
        raise ValueError(f"no alert channel named {', '.join(missing)}")
    cd = body.get("cooldown_hours", 24)
    if isinstance(cd, bool) or not isinstance(cd, int) or not 1 <= cd <= 720:
        raise ValueError("cooldown_hours must be a whole number from 1 to 720")
    return {"enabled": body["enabled"], "when": when, "filter": flt, "channels": list(dict.fromkeys(ch)),
            "cooldown_hours": cd}


def matches(flt: dict, ep: dict | None) -> bool:
    if not flt:
        return True
    if ep is None:
        return False
    if flt.get("tags") and not set(flt["tags"]) & set(ep.get("tags") or []):
        return False
    if flt.get("connectors") and ep.get("connector") not in flt["connectors"]:
        return False
    return not (flt.get("name") and not fnmatch.fnmatchcase(ep.get("name") or "", flt["name"]))


def describe(when: dict) -> str:
    k = when["type"]
    if k == "event":
        return "renewal " + " / ".join(when["events"])
    if k == "expiring":
        return f"certificate expires within {when['days']} days"
    if k == "health":
        return f"health grade below {when['below']}"
    if k == "zombie":
        return "zombie certificate" + (f" ({', '.join(when['kinds'])})" if when.get("kinds") else "")
    return f"no TLS answer for {when['days']}+ days"


class Alerts:
    def __init__(self, engine):
        self.engine = engine
        self.store = engine.store

    def rules(self) -> dict[str, dict]:
        return self.engine.items.all("alert_rule")

    def last_fired(self) -> dict[str, str]:
        return {r["rule"]: r["at"] for r in self.store.q("SELECT rule, MAX(fired_at) AS at FROM alert_state GROUP BY rule")}

    def forget(self, rule: str) -> None:
        self.store.x("DELETE FROM alert_state WHERE rule=?", (rule,))

    # ---- dedup -------------------------------------------------------------------------------------
    def claim(self, rule: str, subject: str, cooldown_hours: int, now) -> bool:
        """True if this (rule, subject) may fire now; records the firing. Safe across replicas: the
        conditional UPDATE and the primary key let exactly one claimant win."""
        S, subject = self.store, subject[:200]
        t = now.isoformat(timespec="seconds")
        cutoff = (now - timedelta(hours=cooldown_hours)).isoformat(timespec="seconds")
        if S._run("UPDATE alert_state SET fired_at=? WHERE rule=? AND subject=? AND fired_at<=?",
                  (t, rule, subject, cutoff))[1]:
            return True
        if S.q1("SELECT fired_at FROM alert_state WHERE rule=? AND subject=?", (rule, subject)):
            return False
        try:
            S.x("INSERT INTO alert_state(rule, subject, fired_at) VALUES (?,?,?)", (rule, subject, t))
            return True
        except Exception as e:  # each driver has its own IntegrityError class
            if type(e).__name__ != "IntegrityError":
                raise
            if not S._tx_depth:
                S.conn.rollback()
            return False

    # ---- sending -----------------------------------------------------------------------------------
    def _payload(self, name: str, event: str, condition: str, endpoint: dict | None = None,
                 renewal: dict | None = None) -> dict:
        from farrier.monitoring.notify import payload
        return payload(event, renewal, endpoint, self.engine.notifier.dashboard_url) | {"rule": name,
                                                                                       "condition": condition}

    def _send(self, rule: dict, p: dict, wait: bool = False) -> dict:
        return self.engine.notifier.send_to(rule["channels"], p, wait=wait)

    def on_event(self, event: str, renewal: dict | None, endpoint: dict | None, now=None) -> int:
        """Event rules: called on every renewal state change."""
        from farrier.monitoring.notify import TITLES
        now = now or policy.utcnow()
        sent = 0
        for name, rule in self.rules().items():
            w = rule.get("when") or {}
            if not rule.get("enabled") or w.get("type") != "event" or event not in w.get("events", []):
                continue
            if not matches(rule.get("filter") or {}, endpoint):
                continue
            subject = f"event:{event}:ep:{(endpoint or {}).get('id')}"
            if self.claim(name, subject, rule.get("cooldown_hours", 24), now):
                self._send(rule, self._payload(name, event, TITLES.get(event, event), endpoint, renewal))
                sent += 1
        return sent

    def _hits(self, rule: dict, ctx: dict, now) -> list[tuple[str, dict | None, str]]:
        """[(subject, endpoint or None, condition text)] for one threshold rule."""
        w, flt = rule["when"], rule.get("filter") or {}
        eps = [e for e in ctx["endpoints"] if e["enabled"] and matches(flt, e)]
        out = []
        if w["type"] == "expiring":
            for e in eps:
                na = parse_dt(e["not_after"])
                if not na:   # the last scan failed: judge by the last certificate seen
                    last = self.store.latest_cert_observation(e["id"])
                    na = parse_dt(last["not_after"]) if last else None
                if not na:
                    continue
                left = (na - now) / timedelta(days=1)
                if left <= w["days"]:
                    cond = (f"certificate expired {-left:.1f} days ago" if left < 0 else
                            f"certificate expires in {left:.1f} days ({na:%Y-%m-%d})")
                    out.append((f"ep:{e['id']}", e, cond))
        elif w["type"] == "health":
            grades = ctx.setdefault("grades", {r["endpoint_id"]: r for r in
                                               self.store.q("SELECT endpoint_id, grade, checked_at FROM health_results")})
            for e in eps:
                g = grades.get(e["id"])
                if g and GRADES.index(g["grade"]) > GRADES.index(w["below"]):
                    cond = (f"health grade {g['grade']} (below {w['below']}), "
                            f"checked {g['checked_at'][:16].replace('T', ' ')} UTC")
                    out.append((f"ep:{e['id']}", e, cond))
        else:
            from farrier.monitoring import zombie
            dead = w["days"] if w["type"] == "unreachable" else 7
            key = f"zombies:{dead}"
            if key not in ctx:
                ctx[key] = zombie.from_store(self.store, now, dead_days=dead)
            by_id = {e["id"]: e for e in ctx["endpoints"]}
            for f in ctx[key]:
                if w["type"] == "unreachable" and f["kind"] != "dead_endpoint":
                    continue
                if w["type"] == "zombie" and w.get("kinds") and f["kind"] not in w["kinds"]:
                    continue
                ep = by_id.get(f["endpoint_id"]) if f["endpoint_id"] else None
                if not matches(flt, ep):
                    continue
                if w["type"] == "unreachable":
                    cond = f"no TLS answer for {f['evidence'].get('days')} days (last error: {f['evidence'].get('last_error')})"
                else:
                    cond = f"zombie certificate: {f['kind'].replace('_', ' ')} at {f['target']} ({f['severity']})"
                out.append((f"{f['kind']}:{f['endpoint_id'] or f['target']}", ep, cond))
        return out

    def evaluate(self, now=None) -> int:
        """Threshold rules; called by the leader at the end of each tick. Returns messages sent."""
        now = now or policy.utcnow()
        rules = {n: r for n, r in self.rules().items()
                 if r.get("enabled") and (r.get("when") or {}).get("type") in RULE_TYPES.keys() - {"event"}}
        if not rules:
            return 0
        ctx = {"endpoints": self.store.endpoints()}
        sent = 0
        for name, rule in rules.items():
            try:
                fired = [h for h in self._hits(rule, ctx, now)
                         if self.claim(name, h[0], rule.get("cooldown_hours", 24), now)]
            except Exception as e:  # noqa: BLE001 - one broken rule must not stop the others
                self.store.log(f"alert rule {name} failed: {type(e).__name__}: {e}", level="error")
                continue
            if len(fired) > DIGEST_OVER:
                names = ", ".join((ep or {}).get("name") or subj for subj, ep, _ in fired[:DIGEST_OVER])
                cond = f"{describe(rule['when'])}: {len(fired)} endpoints, including {names}"
                self._send(rule, self._payload(name, "alert", cond))
                sent += 1
            else:
                for _, ep, cond in fired:
                    self._send(rule, self._payload(name, "alert", cond, ep))
                    sent += 1
            if fired:
                self.store.log(f"alert rule {name} fired for {len(fired)} subject(s)")
        return sent

    def test(self, name: str) -> dict:
        rule = self.rules().get(name)
        if rule is None:
            raise KeyError(name)
        p = self._payload(name, "test", f"test of alert rule {name} ({describe(rule['when'])})")
        results = self._send(rule, p, wait=True)
        return {"ok": bool(results) and all(results.values()), "sent": [n for n, ok in results.items() if ok]}
