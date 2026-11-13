"""Approval gates: a renewal waits in `planned` until it is approved, before any key or CA request.

settings.json:
  "approvals": {"default": "manual", "payments": "servicenow:snow-prod", "lab": "none"}
An endpoint follows its project's mode, else "default"; the endpoint tag "require-approval" asks for
"manual" whatever the project says. Without "approvals", nothing waits (as before).

  manual               an admin approves or rejects in the dashboard (Renewals) or POST /api/renewals/{id}/approve
  servicenow:<channel> Farrier opens a change request through that ServiceNow channel and proceeds once its
                       approval field reads "approved"; "rejected" cancels the renewal. An admin can still
                       approve in Farrier (for an outage of ServiceNow itself); that is logged.
A gate still closed when the renewal's deadline passes is logged once as overdue, which alert rules see.
State lives in config_items (kind "approval", name = renewal id): {mode, state, by, at, ticket}.
"""
from __future__ import annotations

import json
from contextlib import closing

from farrier.db.store import now_iso, parse_dt

KIND = "approval"
TAG = "require-approval"


def mode_for(settings: dict, ep: dict) -> str | None:
    if TAG in (ep.get("tags") or []):
        return "manual"
    cfg = settings.get("approvals") or {}
    m = cfg.get(ep.get("project") or "default", cfg.get("default"))
    return None if m in (None, "", "none") else str(m)


def validate(cfg) -> None:
    if cfg is None:
        return
    if not isinstance(cfg, dict):
        raise ValueError('settings.json "approvals" maps project names to "manual", "servicenow:<channel>" or "none"')
    for project, m in cfg.items():
        if not (m in ("manual", "none") or (isinstance(m, str) and m.startswith("servicenow:") and len(m) > 11)):
            raise ValueError(f'approvals {project!r}: {m!r} is not "manual", "servicenow:<channel>" or "none"')


class Approvals:
    def __init__(self, engine):
        self.engine, self.store = engine, engine.store

    def get(self, rid: int) -> dict | None:
        row = self.store.q1("SELECT body FROM config_items WHERE kind=? AND name=?", (KIND, str(rid)))
        return json.loads(row["body"]) if row else None

    def records(self) -> dict[int, dict]:
        """Renewal id -> approval record, every state."""
        return {int(row["name"]): json.loads(row["body"])
                for row in self.store.q("SELECT name, body FROM config_items WHERE kind=?", (KIND,))}

    def pending(self) -> dict[int, dict]:
        """Renewal id -> approval record, for every gate that is still closed."""
        return {rid: b for rid, b in self.records().items() if b["state"] == "pending"}

    def _put(self, rid: int, body: dict) -> None:
        with self.store.transaction():
            self.store.x("DELETE FROM config_items WHERE kind=? AND name=?", (KIND, str(rid)))
            self.store.x("INSERT INTO config_items(kind, name, body, updated_at) VALUES (?,?,?,?)",
                         (KIND, str(rid), json.dumps(body), now_iso()))

    # ---- the gate, called from Engine._step_planned ----------------------------------------------------
    def gate(self, r: dict, ep: dict, now) -> bool:
        """True when the renewal may proceed."""
        mode = mode_for(self.engine.settings, ep)
        rec = self.get(r["id"])
        if not mode or (rec and rec["state"] == "approved"):
            return True
        if rec is None:
            rec = {"mode": mode, "state": "pending", "requested_at": now_iso(), "by": None, "at": None, "ticket": None}
            self._put(r["id"], rec)
            self.store.log(f"renewal waits for approval ({mode})", ep["id"], r["id"])
        if mode.startswith("servicenow:") and rec["state"] == "pending":
            rec = self._servicenow(r, ep, mode.split(":", 1)[1], rec)
            if rec["state"] == "approved":
                return True
        if rec["state"] == "pending" and r["deadline"] and now > parse_dt(r["deadline"]) and not rec.get("overdue"):
            self._put(r["id"], rec | {"overdue": True})
            self.store.log("approval is overdue: the current certificate expires soon", ep["id"], r["id"], level="error")
        return False

    def _servicenow(self, r: dict, ep: dict, channel: str, rec: dict) -> dict:
        from farrier.itsm import adapter_for
        from farrier.itsm.tickets import build_spec
        cfg = next((c for c in self.engine.itsm.channels() if c.get("name") == channel), None)
        if not cfg or cfg.get("type") != "servicenow":
            if not rec.get("misconfigured"):
                self._put(r["id"], rec := rec | {"misconfigured": True})
                self.store.log(f"approval channel {channel!r} is not a ServiceNow channel; approve in Farrier",
                               ep["id"], r["id"], level="error")
            return rec
        try:
            # approvals live on change requests, whatever table the channel uses for its other tickets
            with closing(adapter_for(cfg | {"table": "change_request"}, transport=self.engine.itsm.transport)) as a:
                if not rec.get("ticket"):
                    spec = build_spec(f"{self.engine.instance_id}-approval-{r['id']}", "change", r, ep, None)
                    spec.summary = f"Approve TLS certificate renewal for {ep['name']} ({ep['host']}:{ep['port']})"
                    spec.description = (f"Farrier will renew the certificate of {ep['name']} once this change is "
                                        "approved, inside its change window.\n\n" + spec.description)
                    t = a.find(spec.key, "change") or a.open(spec)
                    rec = rec | {"ticket": {"ref": t.ref, "ext_id": t.ext_id, "table": t.table, "url": t.url}}
                    self._put(r["id"], rec)
                    self.store.log(f"change {t.ref} opened for approval", ep["id"], r["id"])
                verdict = a.approval(rec["ticket"]["table"], rec["ticket"]["ext_id"])
        except Exception as e:  # noqa: BLE001 - ServiceNow being down keeps the gate closed, never opens it
            self.store.log(f"approval check in ServiceNow failed: {type(e).__name__}: {e}"[:400], ep["id"], r["id"],
                           level="warning")
            return rec
        if verdict == "approved":
            rec = rec | {"state": "approved", "by": f"servicenow {rec['ticket']['ref']}", "at": now_iso()}
            self._put(r["id"], rec)
            self.store.log(f"approved in ServiceNow ({rec['ticket']['ref']})", ep["id"], r["id"])
        elif verdict == "rejected":
            self._put(r["id"], rec | {"state": "rejected", "by": f"servicenow {rec['ticket']['ref']}", "at": now_iso()})
            self.engine.cancel(r["id"], f"rejected in ServiceNow ({rec['ticket']['ref']})")
            rec = self.get(r["id"])
        return rec

    # ---- people ----------------------------------------------------------------------------------------
    def decide(self, rid: int, approve: bool, actor: str) -> dict:
        r = self.store.renewal(rid)
        rec = self.get(rid)
        if not r or r["state"] != "planned" or not rec or rec["state"] != "pending":
            raise ValueError("this renewal is not waiting for approval")
        rec = rec | {"state": "approved" if approve else "rejected", "by": actor, "at": now_iso()}
        self._put(rid, rec)
        if approve:
            self.store.log(f"renewal approved by {actor}", r["endpoint_id"], rid)
        else:
            self.engine.cancel(rid, f"renewal rejected by {actor}")
        return rec
