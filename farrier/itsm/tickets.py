"""The ticket lifecycle for ServiceNow and Jira channels with "tickets": true.

  renewal enters awaiting_manual   open one change ticket (if the channel's events include
  (change pack ready)              awaiting_manual): endpoint, certificate (subject, SANs, issuer, expiry,
                                   SHA-256), deadline, the dashboard link to the change pack and the
                                   runbook steps. Never key material: the pack is only linked.
  failed / rolled_back, no ticket  open an incident, if the channel's events include that state
                                   (an automated renewal that failed or never went live)
  done (verified live)             note it and resolve/close the change ticket
  failed / rolled_back / cancelled / superseded, ticket open
                                   add a note and leave the ticket open for a person

One ticket per (channel, renewal): a row in itsm_tickets is claimed (unique index) before the call,
and the product-side idempotency key (ServiceNow correlation_id, Jira label) is searched before
creating, so neither a second replica nor a retry after a crash opens a second ticket. The ticket's
number/key goes into the renewal's ticket_ref when that is still empty.

Work runs on one background worker per engine (in order, off the renewal path). The leader's tick
reconciles: renewals awaiting a person that have no ticket yet, and tickets whose last update failed,
are retried with backoff (1, 2, 4 ... 60 minutes; at most MAX_ATTEMPTS tries).
"""
from __future__ import annotations

import queue
import threading
from contextlib import closing
from datetime import timedelta

from farrier.db.store import now_iso, parse_dt
from farrier.itsm import ITSM_TYPES, adapter_for, is_ticketing
from farrier.itsm.base import Ticket, TicketSpec, no_key_material

MAX_ATTEMPTS = 10
STALE_OPENING = timedelta(minutes=10)
FOLLOW_UPS = ("done", "failed", "rolled_back", "cancelled", "superseded")
NOTES = {
    "done": "The renewed certificate was seen live and verified by Farrier. Closing.",
    "failed": "The renewal failed. The ticket stays open for a person to decide what to do.",
    "rolled_back": "The new certificate never went live and the deployment was rolled back. The ticket stays open.",
    "cancelled": "The renewal was cancelled in Farrier. The change pack was deleted; the ticket stays open for "
                 "its owner to close.",
    "superseded": "A different certificate was installed on the endpoint, so this change pack is no longer needed. "
                  "The ticket stays open for its owner to close.",
}


def dashboard_link(base: str | None, rid: int) -> str | None:
    if not base:
        return None
    base = base.rstrip("/")
    if not base.endswith("/dashboard"):
        base += "/dashboard"
    return f"{base}/renewals?renewal={rid}"


def _cert_lines(r: dict) -> list[str]:
    if not r.get("cert_pem"):
        return []
    from farrier.core.x509util import parse_pem
    info = parse_pem(r["cert_pem"])
    return ["Certificate",
            f"  Subject: {info.subject_cn}",
            f"  SANs: {', '.join(info.sans) or '(none)'}",
            f"  Issuer: {info.issuer}",
            f"  Expires: {info.not_after:%Y-%m-%d %H:%M} UTC" if info.not_after else "  Expires: unknown",
            f"  SHA-256: {r.get('new_fingerprint') or info.fingerprint}"]


def build_spec(key: str, kind: str, r: dict, ep: dict, dashboard_url: str | None) -> TicketSpec:
    """The ticket for a renewal: what a person needs to act, and nothing secret."""
    addr = f"{ep['host']}:{ep['port']}"
    link = dashboard_link(dashboard_url, r["id"])
    who = [f"Endpoint: {ep['name']} ({addr}), connector {ep.get('connector')}"
           + (f", owner {ep['owner']}" if ep.get("owner") else "")]
    deadline = (r.get("deadline") or "")[:16].replace("T", " ")
    if kind == "change":
        summary = f"Install renewed TLS certificate on {ep['name']} ({addr})"
        from farrier.connectors.base import Bundle
        from farrier.connectors.manual import runbook_steps
        obj = Bundle(name=ep["name"], renewal_id=r["id"], key_pem="", cert_pem="", chain_pem="",
                     not_after=r.get("not_after") or "").object_name
        lines = [f"Farrier renewed the certificate for {ep['name']} and prepared a change pack (renewal #{r['id']}).",
                 "", *who, *_cert_lines(r),
                 f"Install before (deadline): {deadline + ' UTC' if deadline else 'as soon as possible'}",
                 f"Change pack: {link}" if link else "Change pack: in the Farrier dashboard, Renewals",
                 "  (download it there: it holds the new private key and is never attached to this ticket)",
                 "", "Runbook", runbook_steps(ep.get("connector_config") or {}, obj, addr, r.get("new_fingerprint") or ""),
                 "", f"Farrier watches {addr} and resolves this ticket when the new certificate is seen live."]
    else:
        summary = f"Certificate renewal {r['state'].replace('_', ' ')} on {ep['name']} ({addr})"
        lines = [f"Farrier's renewal #{r['id']} for {ep['name']} ended {r['state'].replace('_', ' ')}.", "",
                 f"Error: {(r.get('error') or 'none recorded')[:1000]}", "", *who, *_cert_lines(r)]
        if deadline:
            lines.append(f"Current certificate must be replaced before: {deadline} UTC")
        if link:
            lines.append(f"Renewal: {link}")
    return TicketSpec(key=key, kind=kind, summary=summary, description=no_key_material("\n".join(lines)),
                      ci={"name": ep["name"], "host": ep["host"]})


def follow_up_text(state: str, r: dict, ep: dict) -> str:
    text = f"Farrier: renewal #{r['id']} for {ep['name']} is now {state.replace('_', ' ')}. {NOTES.get(state, '')}"
    if state == "done":
        text += f"\nVerified live on {ep['host']}:{ep['port']}, SHA-256 {r.get('new_fingerprint')}."
    elif r.get("error"):
        text += f"\nDetail: {r['error'][:1000]}"
    return no_key_material(text)


class Itsm:
    """The engine's ITSM hub: ticket lifecycle (any replica, on state changes) and the leader's tick."""

    def __init__(self, engine):
        self.engine = engine
        self.store = engine.store
        self.synchronous = False            # tests: run ticket work inline
        self.transport = None               # tests: an httpx.MockTransport for every adapter
        self._q: queue.Queue = queue.Queue()
        self._worker: threading.Thread | None = None
        self._lock = threading.Lock()

    # ---- channels ---------------------------------------------------------------------------------
    def channels(self) -> list[dict]:
        return [c for c in self.engine.notifier.configs if c.get("type") in ITSM_TYPES]

    def ticket_channels(self) -> list[dict]:
        return [c for c in self.channels() if is_ticketing(c) and c.get("name")]

    def _log(self, msg: str, r: dict | None = None, level: str = "info") -> None:
        self.store.log(msg[:500], (r or {}).get("endpoint_id"), (r or {}).get("id"), level=level)

    # ---- entry points (never raise) ---------------------------------------------------------------
    def on_event(self, event: str, renewal: dict | None, endpoint: dict | None) -> None:
        """A renewal changed state (engine._notify)."""
        if not renewal or not endpoint:
            return
        try:
            for cfg in self.ticket_channels():
                if self.engine.notifier.hears(cfg, endpoint.get("project")):
                    self._submit(self._sync, cfg["name"], renewal["id"], event)
        except Exception as e:  # noqa: BLE001
            self._log(f"queueing ticket work failed: {type(e).__name__}", renewal, level="warning")

    def tick(self, now=None) -> None:
        """Leader only, end of each tick: reconcile tickets, then metrics and inventory."""
        from farrier.core import policy
        now = now or policy.utcnow()
        try:
            self.reconcile(now)
        except Exception as e:  # noqa: BLE001
            self._log(f"ticket reconciliation failed: {type(e).__name__}", level="warning")
        try:
            from farrier.itsm import telemetry
            telemetry.run(self.engine, [c for c in self.channels() if not is_ticketing(c)], now,
                          transport=self.transport)
        except Exception as e:  # noqa: BLE001
            self._log(f"ITSM telemetry failed: {type(e).__name__}", level="warning")

    def drain(self, timeout: float = 30.0) -> None:
        """Wait until queued ticket work is done (tests, graceful shutdown)."""
        done = threading.Event()
        self._submit(done.set)
        done.wait(timeout)

    def _submit(self, fn, *args) -> None:
        if self.synchronous:
            self._run(fn, args)
            return
        self._q.put((fn, args))
        with self._lock:
            if self._worker is None or not self._worker.is_alive():
                self._worker = threading.Thread(target=self._loop, daemon=True, name="farrier-itsm")
                self._worker.start()

    def _loop(self) -> None:
        while True:
            fn, args = self._q.get()
            try:
                self._run(fn, args)
            finally:
                self._q.task_done()

    def _run(self, fn, args) -> None:
        try:
            fn(*args)
        except Exception as e:  # noqa: BLE001 - ticketing must never break a renewal
            self._log(f"ITSM work failed: {type(e).__name__}", level="warning")

    # ---- reconcile (leader) -----------------------------------------------------------------------
    def reconcile(self, now) -> None:
        for cfg in self.ticket_channels():
            name = cfg["name"]
            if self.engine.notifier.wants(cfg, "awaiting_manual"):
                for row in self.store.q("""SELECT r.id FROM renewals r WHERE r.state='awaiting_manual' AND NOT EXISTS
                                           (SELECT 1 FROM itsm_tickets t WHERE t.renewal_id=r.id AND t.channel=?)""",
                                        (name,)):
                    self._submit(self._sync, name, row["id"], None)
            for row in self.store.q("""SELECT t.renewal_id, t.state, t.last_event, t.attempts, t.updated_at,
                                              r.state AS rstate
                                       FROM itsm_tickets t JOIN renewals r ON r.id = t.renewal_id
                                       WHERE t.channel=? AND t.state IN ('opening','open','error') AND t.attempts < ?""",
                                    (name, MAX_ATTEMPTS)):
                behind = row["state"] == "open" and row["rstate"] != row["last_event"] and row["rstate"] in FOLLOW_UPS
                if (row["state"] != "open" or behind) and self._due(row, parse_dt(now_iso())):
                    self._submit(self._sync, name, row["renewal_id"], None)

    @staticmethod
    def _due(row: dict, now) -> bool:
        at = parse_dt(row["updated_at"])
        if row["state"] == "opening":
            return at is None or now - at >= STALE_OPENING
        if not row["attempts"]:
            return True
        return at is None or now - at >= timedelta(minutes=min(60, 2 ** (row["attempts"] - 1)))

    # ---- the state machine ------------------------------------------------------------------------
    def _cfg(self, name: str) -> dict | None:
        return next((c for c in self.ticket_channels() if c["name"] == name), None)

    def _row(self, name: str, rid: int) -> dict | None:
        return self.store.q1("SELECT * FROM itsm_tickets WHERE channel=? AND renewal_id=?", (name, rid))

    def _key(self, rid: int) -> str:
        return f"{self.engine.instance_id}-renewal-{rid}"

    def _sync(self, name: str, rid: int, event: str | None) -> None:
        """Bring channel ``name``'s ticket for renewal ``rid`` up to date with the renewal's state."""
        cfg = self._cfg(name)
        r = self.store.renewal(rid)
        if not cfg or not r:
            return
        ep = self.store.endpoint(r["endpoint_id"])
        if not ep:
            return
        state = r["state"]
        row = self._row(name, rid)
        if row is None:
            if (event or state) != state:
                return                      # a stale event: the renewal has moved on, the tick reconciles
            kind = "change" if state == "awaiting_manual" else "incident" if state in ("failed", "rolled_back") else None
            if kind is None or not self.engine.notifier.wants(cfg, state):
                return
            row_id = self._claim_new(name, rid, kind, cfg["type"])
            if row_id is not None:
                self._open(cfg, row_id, r, ep, kind)
            return
        if row["attempts"] >= MAX_ATTEMPTS:
            return
        if row["state"] in ("error", "opening"):
            if row["state"] == "opening" and not self._due(row, parse_dt(now_iso())):
                return                      # another worker is opening it right now
            if row["kind"] == "change" and state != "awaiting_manual":
                self.store.x("UPDATE itsm_tickets SET state='closed', error=?, updated_at=? WHERE id=?",
                             (f"renewal ended {state} before a ticket could be opened", now_iso(), row["id"]))
                return
            if self.store._run("UPDATE itsm_tickets SET state='opening', updated_at=? WHERE id=? AND state=? "
                               "AND updated_at=?", (now_iso(), row["id"], row["state"], row["updated_at"]))[1]:
                self._open(cfg, row["id"], r, ep, row["kind"], attempts=row["attempts"])
            return
        if row["state"] == "open" and row["kind"] == "change" and state in FOLLOW_UPS and row["last_event"] != state:
            self._follow(cfg, row, r, ep, state)

    def _claim_new(self, name: str, rid: int, kind: str, product: str) -> int | None:
        t = now_iso()
        try:
            return self.store.x("""INSERT INTO itsm_tickets(channel, renewal_id, kind, product, state, attempts,
                                   created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)""",
                                (name, rid, kind, product, "opening", 0, t, t))
        except Exception as e:  # each driver has its own IntegrityError class
            if type(e).__name__ != "IntegrityError":
                raise
            if not self.store._tx_depth:
                self.store.conn.rollback()
            return None

    def _fail(self, row_id: int, attempts: int, e: Exception, r: dict, what: str, name: str, new_state=None):
        from farrier.monitoring.notify import failure_detail
        detail = failure_detail(e)
        attempts += 1
        sets, args = "attempts=?, error=?, updated_at=?", [attempts, detail[:500], now_iso()]
        if new_state:
            sets += ", state=?"
            args.append(new_state)
        self.store.x(f"UPDATE itsm_tickets SET {sets} WHERE id=?", (*args, row_id))
        give_up = " (giving up)" if attempts >= MAX_ATTEMPTS else ""
        self._log(f"{what} on alert channel {name} failed{give_up}: {detail}", r,
                  level="error" if give_up else "warning")

    def _open(self, cfg: dict, row_id: int, r: dict, ep: dict, kind: str, attempts: int = 0) -> None:
        name = cfg["name"]
        try:
            spec = build_spec(self._key(r["id"]), kind, r, ep, self.engine.notifier.dashboard_url)
            with closing(adapter_for(cfg, transport=self.transport)) as a:
                t = a.find(spec.key, kind) or a.open(spec)
        except Exception as e:  # noqa: BLE001
            self._fail(row_id, attempts, e, r, f"opening a {cfg['type']} ticket", name, new_state="error")
            return
        self.store.x("""UPDATE itsm_tickets SET state='open', ref=?, ext_id=?, tbl=?, url=?, last_event=?, attempts=0,
                        error=NULL, updated_at=? WHERE id=?""", (t.ref, t.ext_id, t.table, t.url, r["state"], now_iso(),
                                                                row_id))
        self.store.x("UPDATE renewals SET ticket_ref=? WHERE id=? AND ticket_ref IS NULL", (t.ref, r["id"]))
        self._log(f"{cfg['type']} ticket {t.ref} opened on alert channel {name}", r)

    def _follow(self, cfg: dict, row: dict, r: dict, ep: dict, state: str) -> None:
        name = cfg["name"]
        t = Ticket(row["ref"], row["ext_id"], row["tbl"] or "")
        try:
            text = follow_up_text(state, r, ep)
            with closing(adapter_for(cfg, transport=self.transport)) as a:
                if state == "done":
                    a.resolve(t, text)
                else:
                    a.comment(t, text)
        except Exception as e:  # noqa: BLE001
            self._fail(row["id"], row["attempts"], e, r, f"updating ticket {t.ref}", name)
            return
        closed = state == "done"
        self.store.x("UPDATE itsm_tickets SET last_event=?, state=?, attempts=0, error=NULL, updated_at=? WHERE id=?",
                     (state, "closed" if closed else "open", now_iso(), row["id"]))
        self._log(f"ticket {t.ref} {'resolved' if closed else 'updated'} ({state}) on alert channel {name}", r)
