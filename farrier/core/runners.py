"""Remote runners: Farrier's hands inside segmented networks (DMZ, OT, branch sites, another cloud).

An endpoint whose connector_config has "runner": "<group>" is never contacted by the engine. Every
action that touches its network becomes a job for that group: observe (scan), deploy, verify, rollback.
`farrier runner` inside the segment claims jobs over HTTPS (outbound only, like Keyfactor orchestrators
or GitHub runners), runs them with the same connector code, and posts results back.

Tokens: one per group, "frn.<group>.<secret>"; only the SHA-256 of the secret is stored. A token can
claim and complete its own group's jobs, nothing else in the API.
Credentials: connector_config travels as written, so env:/file:/cloud references are resolved on the
runner, against its own environment and secret store; the engine never needs the device password.
Leases: observe and verify jobs are re-offered when a runner disappears; deploy and rollback jobs never
are (a half-applied change is verified, not repeated), matching the engine's own crash recovery.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from datetime import timedelta

from farrier.core import policy
from farrier.db.store import now_iso

GROUP = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
KIND = "runner"                       # config_items kind: group -> {sha256, created_at, last_seen, version}
LEASE = timedelta(minutes=10)
REOFFER = ("observe", "verify")       # idempotent: safe to hand to another runner after a lease expires
ONLINE = timedelta(minutes=5)         # a runner polls every few seconds: five quiet minutes means it is down


def runner_of(ep: dict | None) -> str | None:
    return ((ep or {}).get("connector_config") or {}).get("runner") or None


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


class Runners:
    def __init__(self, store):
        self.store = store

    # ---- tokens ------------------------------------------------------------------------------------
    def issue_token(self, group: str) -> str:
        """Create or replace the group's token (the old one stops working at once)."""
        if not GROUP.match(group or ""):
            raise ValueError("runner group: lowercase letters, digits and dashes, e.g. dmz-frankfurt")
        secret = secrets.token_urlsafe(32)
        body = {"sha256": _hash(secret), "created_at": now_iso(), "last_seen": None, "version": None}
        with self.store.transaction():
            self.store.x("DELETE FROM config_items WHERE kind=? AND name=?", (KIND, group))
            self.store.x("INSERT INTO config_items(kind, name, body, updated_at) VALUES (?,?,?,?)",
                         (KIND, group, json.dumps(body), now_iso()))
        return f"frn.{group}.{secret}"

    def authenticate(self, token: str | None) -> str | None:
        """The group a bearer token belongs to, or None."""
        parts = (token or "").split(".", 2)
        if len(parts) != 3 or parts[0] != "frn" or not GROUP.match(parts[1]):
            return None
        row = self.store.q1("SELECT body FROM config_items WHERE kind=? AND name=?", (KIND, parts[1]))
        if not row or not hmac.compare_digest(json.loads(row["body"])["sha256"], _hash(parts[2])):
            return None
        return parts[1]

    def revoke(self, group: str) -> bool:
        return self.store._run("DELETE FROM config_items WHERE kind=? AND name=?", (KIND, group))[1] > 0

    def groups(self) -> list[dict]:
        """Every group: from tokens, and from endpoints that name one (a group with no runner yet shows)."""
        out = {}
        for row in self.store.q("SELECT name, body FROM config_items WHERE kind=?", (KIND,)):
            b = json.loads(row["body"])
            out[row["name"]] = {"group": row["name"], "token": True, "created_at": b["created_at"],
                                "last_seen": b.get("last_seen"), "version": b.get("version")}
        for ep in self.store.endpoints():
            if (g := runner_of(ep)) and g not in out:
                out[g] = {"group": g, "token": False, "created_at": None, "last_seen": None, "version": None}
        for row in self.store.q("SELECT runner_group, COUNT(*) AS n FROM runner_jobs WHERE status IN "
                                "('queued', 'leased') GROUP BY runner_group"):
            if row["runner_group"] in out:
                out[row["runner_group"]]["pending_jobs"] = row["n"]
        recent = (policy.utcnow() - ONLINE).isoformat(timespec="seconds")
        for g in out.values():
            g.setdefault("pending_jobs", 0)
            g["online"] = bool(g["last_seen"] and g["last_seen"] >= recent)
            g["endpoints"] = sum(1 for ep in self.store.endpoints() if runner_of(ep) == g["group"])
        return sorted(out.values(), key=lambda g: g["group"])

    def seen(self, group: str, version: str | None) -> None:
        row = self.store.q1("SELECT body FROM config_items WHERE kind=? AND name=?", (KIND, group))
        if row:
            b = json.loads(row["body"]) | {"last_seen": now_iso(), "version": version}
            self.store.x("UPDATE config_items SET body=? WHERE kind=? AND name=?", (json.dumps(b), KIND, group))

    # ---- jobs --------------------------------------------------------------------------------------
    def enqueue(self, group: str, kind: str, payload: dict, renewal_id: int | None = None) -> int:
        t = now_iso()
        return self.store.x("INSERT INTO runner_jobs(runner_group, kind, renewal_id, payload, status, created_at, "
                            "updated_at) VALUES (?,?,?,?,?,?,?)",
                            (group, kind, renewal_id, self.store.vault.seal(json.dumps(payload)), "queued", t, t))

    def job(self, jid: int) -> dict | None:
        row = self.store.q1("SELECT * FROM runner_jobs WHERE id=?", (jid,))
        if row:
            row["result"] = json.loads(row["result"]) if row["result"] else None
        return row

    def latest(self, renewal_id: int, kind: str) -> dict | None:
        row = self.store.q1("SELECT id FROM runner_jobs WHERE renewal_id=? AND kind=? ORDER BY id DESC LIMIT 1",
                            (renewal_id, kind))
        return self.job(row["id"]) if row else None

    def pending(self, group: str, kind: str) -> bool:
        return self.store.q1("SELECT id FROM runner_jobs WHERE runner_group=? AND kind=? AND status IN "
                             "('queued', 'leased') LIMIT 1", (group, kind)) is not None

    def claim(self, group: str, limit: int = 5) -> list[dict]:
        """Lease up to ``limit`` jobs to a runner of ``group``: queued ones, and re-offerable abandoned ones."""
        now = policy.utcnow()
        marks = ",".join("?" * len(REOFFER))
        rows = self.store.q(f"SELECT id, kind, payload, status, lease_until FROM runner_jobs WHERE runner_group=? AND "
                            f"(status='queued' OR (status='leased' AND kind IN ({marks}) AND lease_until < ?)) "
                            "ORDER BY id LIMIT ?", (group, *REOFFER, now.isoformat(timespec="seconds"), limit))
        out = []
        until = (now + LEASE).isoformat(timespec="seconds")
        for row in rows:   # compare-and-set: two runners of one group never get the same job
            if self.store._run("UPDATE runner_jobs SET status='leased', lease_until=?, updated_at=? WHERE id=? AND "
                               "status=? AND IFNULL(lease_until, '')=IFNULL(?, '')",
                               (until, now_iso(), row["id"], row["status"], row["lease_until"]))[1]:
                out.append({"id": row["id"], "kind": row["kind"], "payload": json.loads(self.store.vault.open(row["payload"]))})
        return out

    def complete(self, group: str, jid: int, ok: bool, result: dict) -> bool:
        """Record a runner's result; only a leased job of the caller's own group can be completed."""
        return self.store._run("UPDATE runner_jobs SET status=?, result=?, updated_at=? WHERE id=? AND runner_group=? "
                               "AND status='leased'", ("done" if ok else "failed", json.dumps(result)[:200000],
                                                       now_iso(), jid, group))[1] > 0

    def consume(self, jid: int) -> None:
        """The engine has acted on the result: drop the payload (a deploy job's holds the private key)."""
        self.store.x("UPDATE runner_jobs SET status='consumed', payload=?, updated_at=? WHERE id=?",
                     (self.store.vault.seal("{}"), now_iso(), jid))

    def abandoned(self, job: dict) -> bool:
        return job["status"] == "leased" and (job["lease_until"] or "") < policy.utcnow().isoformat(timespec="seconds")

    def sweep(self, keep_days: int = 7) -> None:
        """Finished jobs go after a week (payloads are sealed, and wiped once consumed)."""
        cutoff = (policy.utcnow() - timedelta(days=keep_days)).isoformat(timespec="seconds")
        self.store.x("DELETE FROM runner_jobs WHERE status IN ('done', 'failed', 'consumed') AND updated_at < ?",
                     (cutoff,))
