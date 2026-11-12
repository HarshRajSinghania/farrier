"""The renewal state machine.

  planned ──issue──▶ issued ──deploy──▶ verifying ──handshake ok──▶ done
                         │                    └─ never seen ──▶ rolled_back (failed if the rollback itself fails)
                         └─manual──▶ awaiting_manual ──seen live──▶ done
                                            └─ someone else replaced it ──▶ superseded

Whenever a renewal leaves the open states, any change pack it produced (which holds a
plaintext private key) is deleted.

On done, with FARRIER_STORAGE_URL set, fullchain.pem (certificate + chain, never the key) is written to
chains/<renewal id>/fullchain.pem in that store; for endpoints tagged export-key, with a cloud secret backend
(aws, gcp, azure), the private key is stored as secret keys/<renewal id> there. Event-bus channels receive
both references (chain_ref, private_key_ref) in the CloudEvent.
"""
from __future__ import annotations

import json
import os
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path

from farrier.config.integrations import ConfigItems
from farrier.connectors import Bundle, is_automated, make_connector
from farrier.core import policy
from farrier.core.discovery import fetch_cert
from farrier.core.scheduler import level, next_window_start
from farrier.core.x509util import build_csr, generate_key, key_to_pem, parse_pem
from farrier.db.store import OPEN_STATES, Store, now_iso, parse_dt
from farrier.issuers import build_issuer, load_issuers
from farrier.itsm.tickets import Itsm
from farrier.monitoring.alerts import Alerts
from farrier.monitoring.notify import Notifier
from farrier.security.secrets_store import SecretStore
from farrier.security.vault import PROTECTED_DIRS, set_vault_lookup

ROLLING_BACK = "; rolling back"   # error suffix of a claimed rollback not yet finished (see recover_rollbacks)
DEFAULT_SETTINGS = {
    "horizon_days": 14,          # create renewals this far ahead of their due date
    "manual_daily_cap": 25,      # change tickets a team can absorb per day
    "auto_daily_cap": 1000,
    "verify_max_attempts": 6,    # ticks before an automated deploy is rolled back
    "verify_retry_seconds": 2.0,
    "issue_max_attempts": 5,
    "safety_days": 2,            # never plan a change later than expiry minus this
    "scan_timeout": 5.0,
    # after the fingerprint matches: also require a complete, trusted chain and every name covered
    "verify_chain_and_names": True,
    # probe every A/AAAA record of the host too (catches one stale node behind round-robin DNS;
    # leave off where the engine can't reach every address, e.g. IPv6 it has no route to)
    "verify_all_addresses": False,
    # re-probe each reachable inventory endpoint's TLS crypto / PQC readiness this often (0 = never)
    "crypto_scan_hours": 24,
    # agentless SSH inventory: unauthenticated probe / authorized_keys collection cadence (0 = never)
    "ssh_scan_hours": 24,
    "ssh_collect_hours": 24,
    # private keys exported for tag export-key are deleted from the secret backend after this long (0 = keep)
    "export_key_retention_hours": 24,
}
EXPORTED_KEY = "exported_key"    # config_items kind: renewal id -> {backend, ref} of a key exported for consumers


class NotApproved(ValueError):
    """A renewal was asked for an endpoint discovery added that no admin has approved yet."""


def discovered(ep: dict | None) -> bool:
    """Added by discovery and not yet approved: names come from whatever the host served, so monitor only."""
    return bool(ep) and "discovered" in (ep.get("tags") or [])


class Engine:
    def __init__(self, data_dir: str | Path, issuers: dict | None = None, settings: dict | None = None):
        self.data_dir = Path(data_dir)
        self.store = Store(self.data_dir)
        # no connector may read master.key or the database as a "secret"
        PROTECTED_DIRS.add(self.data_dir.resolve())
        sp = self.data_dir / "settings.json"
        file_settings = json.loads(sp.read_text()) if sp.exists() else {}
        self.settings = {**DEFAULT_SETTINGS, **file_settings, **(settings or {})}
        # issuers passed in (tests, embedding) are kept; dashboard-configured ones are added around them
        self._explicit_issuers = issuers
        self._issuers = None
        self._dns_accounts = None
        # dashboard configuration (database): secrets resolve as vault:NAME, other replicas' changes are
        # noticed through the config version (check_config, every tick)
        self.items = ConfigItems(self.store)
        self.secrets = SecretStore(self.store)
        set_vault_lookup(self.secrets.get)
        self._config_version = self.items.version()
        self.notifier = self._build_notifier()
        self.alerts = Alerts(self)
        self.itsm = Itsm(self)                  # ServiceNow / Jira ticket lifecycle, Datadog / Splunk telemetry
        self._lease = None                    # leader lease, opened on the first tick
        self._tick_lock = threading.Lock()      # held for the duration of a tick
        self._stopping = threading.Event()

    # ---- leadership (several replicas may share one database) --------------
    @property
    def lease(self):
        if self._lease is None:
            self._lease = self.store.leader_lease()
        return self._lease

    def try_lead(self) -> bool:
        """Acquire or confirm the leader lease. Only the leader runs scan/plan/advance cycles;
        followers serve the API. A follower that finds the lease free takes over here."""
        if self._stopping.is_set():
            return False
        was = self.lease.is_leader
        now_leading = self.lease.try_acquire()
        if now_leading and not was:
            self.store.log(f"replica {self._replica()} is now the renewal leader ({self.lease.kind})")
        return now_leading

    def _replica(self) -> str:
        from farrier.db.leader import replica_id
        return replica_id()

    def status(self) -> dict:
        """Leadership and database facts for a health endpoint."""
        return {"replica": self._replica(), "leader": bool(self._lease and self._lease.is_leader),
                "lease": self.lease.kind, "ticking": self._tick_lock.locked(),
                "stopping": self._stopping.is_set(), **self.store.status()}

    def shutdown(self, timeout: float = 30.0) -> bool:
        """Graceful stop: start no new tick, let the running one finish, release the lease.
        Returns False if the running tick did not finish within ``timeout``."""
        self._stopping.set()
        finished = self._tick_lock.acquire(timeout=max(0.0, timeout))
        try:
            if self._lease is not None:
                self._lease.release()
        finally:
            if finished:
                self._tick_lock.release()
        return finished

    @property
    def issuers(self) -> dict:
        if self._issuers is None:
            ui = self.items.all("issuer")
            if self._explicit_issuers is not None:
                built = {}
                for name, c in ui.items():
                    if name in self._explicit_issuers:
                        continue
                    try:
                        built[name] = build_issuer(name, c, self.data_dir, lambda: self.dns_accounts)
                    except Exception as e:  # noqa: BLE001
                        self.store.log(f"issuer {name} (dashboard) not loaded: {e}", level="error")
                self._issuers = {**built, **self._explicit_issuers}
            else:
                self._issuers = load_issuers(self.data_dir, ui, lambda: self.dns_accounts, self.store.log)
        return self._issuers

    @property
    def dns_accounts(self):
        """dns.json plus the dashboard's DNS accounts (shared by every ACME issuer)."""
        if self._dns_accounts is None:
            from farrier.config.integrations import load_dns_accounts
            self._dns_accounts = load_dns_accounts(self)
        return self._dns_accounts

    def _build_notifier(self) -> Notifier:
        from farrier.config.integrations import notifier_list
        return Notifier(notifier_list(self),
                        self.settings.get("dashboard_url") or os.environ.get("FARRIER_DASHBOARD_URL"),
                        self.store.log, instance_id=self.instance_id)

    @property
    def instance_id(self) -> str:
        """This installation's id in CloudEvents (farrier://<id>); shared by replicas with one master key."""
        if getattr(self, "_instance_id", None) is None:
            from farrier.events.cloudevents import instance_id
            self._instance_id = instance_id(self.data_dir)
        return self._instance_id

    def reload_config(self) -> None:
        """Pick up configuration changes without a restart: issuers, DNS accounts and alert channels
        are rebuilt on next use. Alert rules are read from the database each time anyway."""
        self._config_version = self.items.version()
        self._issuers = None
        self._dns_accounts = None
        self.notifier = self._build_notifier()

    def check_config(self) -> bool:
        """Reload if another replica (or the API) changed the configuration. Returns True on reload."""
        try:
            v = self.items.version()
        except Exception:  # noqa: BLE001 - a database blip must not stop the tick
            return False
        if v == self._config_version:
            return False
        self.reload_config()
        return True

    def connector(self, ep: dict):
        return make_connector(ep["connector"], ep["connector_config"], self.data_dir)

    # ---- observe -----------------------------------------------------------
    def _fetch(self, ep: dict):
        """Handshake only, no DB writes, so it is safe to run in worker threads."""
        try:
            return fetch_cert(ep["host"], ep["port"], ep["sni"], self.settings["scan_timeout"]), None
        except Exception as e:  # noqa: BLE001
            return None, f"{type(e).__name__}: {e}"

    def observe(self, ep: dict):
        cert, error = self._fetch(ep)
        self.store.add_observation(ep["id"], cert, error)
        return cert

    def observe_all(self) -> int:
        """Scan every enabled endpoint concurrently; a few dead hosts no longer stall the cycle."""
        eps = [e for e in self.store.endpoints() if e["enabled"]]
        if not eps:
            return 0
        with ThreadPoolExecutor(max_workers=min(32, len(eps))) as pool:
            results = list(pool.map(self._fetch, eps))
        for ep, (cert, error) in zip(eps, results):
            self.store.add_observation(ep["id"], cert, error)
        return len(eps)

    def register_scan(self, results, project_id: int | None = None, visible=None) -> dict:
        """Persist discovery results; unknown host:port pairs become manual endpoints tagged `discovered`
        (in ``project_id``, default the default project). Their names come from whatever certificate the
        host served, so they are monitor-only (never planned or renewed) until an admin approves them.
        ``visible(endpoint) -> bool``: known endpoints the caller may not see are left alone and not counted."""
        new = seen = 0
        for r in results:
            ep = self.store.endpoint_by_addr(r.host, r.port, r.sni)
            if ep is not None and visible is not None and not visible(ep):
                continue
            if ep is None:
                if r.cert is None:
                    continue
                # never reuse an existing name: upsert would rewrite that endpoint with scanned data
                base = name = f"{r.sni or r.host}:{r.port}"
                taken = {e["name"] for e in self.store.endpoints()}
                n = 1
                while name in taken:
                    n += 1
                    name = f"{base} ({n})"
                eid = self.store.upsert_endpoint({
                    "name": name, "host": r.host, "port": r.port, "sni": r.sni,
                    "common_name": r.cert.subject_cn, "sans": r.cert.sans, "connector": "manual",
                    "connector_config": {}, "tags": ["discovered"], "project_id": project_id})
                self.store.log(f"discovered {name} ({r.cert.subject_cn}, issuer {r.cert.issuer})", eid)
                new += 1
            else:
                eid = ep["id"]
            seen += 1
            self.store.add_observation(eid, r.cert, r.error)
        return {"new": new, "seen": seen}

    # ---- plan --------------------------------------------------------------
    def plan(self, now: datetime | None = None) -> list[int]:
        now = now or policy.utcnow()
        created = []
        load = {"auto": Counter(), "manual": Counter()}
        for r in self.store.renewals(OPEN_STATES, limit=100000):
            load["auto" if is_automated(r["connector"]) else "manual"][r["scheduled_for"][:10]] += 1

        for ep in self.store.endpoints():
            if not ep["enabled"] or not ep["fingerprint"] or discovered(ep) or self.store.open_renewal(ep["id"]):
                continue
            nb, na = parse_dt(ep["not_before"]), parse_dt(ep["not_after"])
            lifetime = min(max(1, (na - nb).days), policy.max_lifetime_days(now))
            due = na - timedelta(days=policy.renew_before_days(lifetime, ep["lead_days"]))
            ari = self._ari_due(ep)
            if ari and ari < due:
                due = ari                     # the CA asked for an earlier renewal (RFC 9773)
            if due > now + timedelta(days=self.settings["horizon_days"]):
                continue
            latest = na - timedelta(days=self.settings["safety_days"])
            klass = "auto" if is_automated(ep["connector"]) else "manual"
            cap = self.settings[f"{klass}_daily_cap"]
            if na <= now:
                start, reason = now, "expired"
            elif latest <= now or next_window_start(ep["window"], max(now, due)) > latest:
                start, reason = now, "urgent: no window before expiry"
            else:
                start = level(ep["window"], max(now, due), latest, load[klass], cap)
                reason = "due (CA renewal window)" if ari and ari <= due else "due"
            load[klass][start.date().isoformat()] += 1
            rid = self.store.create_renewal(ep["id"], start.isoformat(timespec="seconds"),
                                            latest.isoformat(timespec="seconds"), ep["fingerprint"], reason)
            self.store.log(f"renewal planned for {start:%Y-%m-%d %H:%M} UTC ({reason}); "
                           f"current cert expires {na:%Y-%m-%d}", ep["id"], rid)
            created.append(rid)
        return created

    def _served_by_farrier(self, ep) -> dict | None:
        """The finished renewal whose certificate the endpoint serves right now, if any."""
        last = self.store.q1("SELECT cert_pem, new_fingerprint FROM renewals WHERE endpoint_id=? AND state='done' "
                             "ORDER BY id DESC LIMIT 1", (ep["id"],))
        return last if last and last["cert_pem"] and last["new_fingerprint"] == ep["fingerprint"] else None

    def _ari_due(self, ep) -> datetime | None:
        """A point inside the CA's suggested renewal window (RFC 9773), for certificates Farrier issued
        through an ACME CA that offers ARI. The point is fixed per certificate so plans don't flap."""
        issuer = self.issuers.get(ep["issuer"]) or self.issuers.get("default")
        last = self._served_by_farrier(ep)
        if not last or not getattr(issuer, "supports_ari", False):
            return None
        try:
            window = issuer.renewal_window(last["cert_pem"])
        except Exception:  # noqa: BLE001 - ARI is advice; the lifetime policy still plans the renewal
            return None
        if not window:
            return None
        start, end = parse_dt(window[0]), parse_dt(window[1])
        frac = int(ep["fingerprint"][:8], 16) / 0xFFFFFFFF
        return start + (end - start) * frac

    def force_renewal(self, eid: int, reason: str = "requested") -> int:
        if discovered(self.store.endpoint(eid)):
            raise NotApproved("approve this discovered endpoint first")
        if (r := self.store.open_renewal(eid)):
            if r["state"] == "planned":   # pull a window-scheduled renewal forward to now
                if self.store.update_renewal(r["id"], expect_state="planned", scheduled_for=now_iso(),
                                             reason=reason):
                    self.store.log(f"renewal pulled forward ({reason})", eid, r["id"])
            return r["id"]
        obs = self.store.latest_cert_observation(eid)
        rid = self.store.create_renewal(eid, now_iso(), None, obs["fingerprint"] if obs else None, reason)
        self.store.log(f"renewal requested ({reason})", eid, rid)
        return rid

    def approve(self, eid: int, actor: str = "api") -> None:
        """Let a discovered endpoint be renewed: drop its `discovered` tag (an admin decision)."""
        ep = self.store.endpoint(eid)
        tags = [t for t in (ep.get("tags") or []) if t != "discovered"]
        self.store.x("UPDATE endpoints SET tags=? WHERE id=?", (json.dumps(tags), eid))
        self.store.log(f"discovered endpoint {ep['name']} approved for renewal by {actor}", eid)

    # ---- advance -----------------------------------------------------------
    def advance(self, rid: int, now: datetime | None = None) -> str:
        """Push one renewal as far as it can go right now. Returns the resulting state."""
        before = (self.store.renewal(rid) or {}).get("state")
        after = self._advance(rid, now)
        if after != before:
            self._notify(after, rid)
        return after

    def _notify(self, event: str, rid: int):
        r = self.store.renewal(rid)
        ep = self.store.endpoint(r["endpoint_id"]) if r else None
        refs = self._export_artifacts(r, ep) if event == "done" and r and ep and r.get("cert_pem") else None
        self.notifier.send(event, r, ep, refs=refs)
        try:
            self.alerts.on_event(event, r, ep)
        except Exception as e:  # noqa: BLE001 - alerting must never break a renewal
            self.store.log(f"alert rules for {event} failed: {type(e).__name__}: {e}", level="warning")
        self.itsm.on_event(event, r, ep)        # queues ticket work; never raises

    def _advance(self, rid: int, now: datetime | None = None) -> str:
        now = now or policy.utcnow()
        for _ in range(5):
            r = self.store.renewal(rid)
            before = r["state"]
            if before not in OPEN_STATES:
                return before
            ep = self.store.endpoint(r["endpoint_id"])
            step = getattr(self, f"_step_{before}")
            step(r, ep, now)
            after = self.store.renewal(rid)["state"]
            if after == before:
                return after
        return self.store.renewal(rid)["state"]

    def _export_artifacts(self, r: dict, ep: dict) -> dict:
        """Publish a finished renewal's chain (and, if asked, its key) for other systems. Never raises:
        a failed export is logged and the event goes out with a null reference."""
        from farrier.security.secret_backends import CLOUD
        from farrier.storage import configured, explicit, is_remote
        refs = {"chain_ref": None, "private_key_ref": None}
        if explicit():
            try:
                st = configured(self.data_dir)
                url = st.put(f"chains/{r['id']}/fullchain.pem", (r["cert_pem"] + (r["chain_pem"] or "")).encode(),
                             "application/x-pem-file")
                refs["chain_ref"] = url if is_remote(st) else None
            except Exception as e:  # noqa: BLE001 - exporting must never undo a renewal
                self.store.log(f"certificate chain export failed: {type(e).__name__}: {e}"[:500], ep["id"], r["id"],
                               level="warning")
        if "export-key" in (ep.get("tags") or []):
            backend = self.secrets.backend
            if backend.name not in CLOUD:
                self.store.log(f"tag export-key ignored: the {backend.name} secret backend cannot share keys; set "
                               "FARRIER_SECRET_BACKEND to aws, gcp or azure", ep["id"], r["id"], level="warning")
            else:
                try:
                    ref = backend.put(f"keys/{r['id']}", self.store.vault.open(r["key_sealed"]))
                    with self.store.transaction():   # remembered so sweep_exported_keys can delete it later
                        self.store.x("DELETE FROM config_items WHERE kind=? AND name=?", (EXPORTED_KEY, str(r["id"])))
                        self.store.x("INSERT INTO config_items(kind, name, body, updated_at) VALUES (?,?,?,?)",
                                     (EXPORTED_KEY, str(r["id"]), json.dumps({"backend": backend.name, "ref": ref}),
                                      now_iso()))
                    refs["private_key_ref"] = backend.external(ref)
                    self.store.log(f"private key exported to {backend.describe()['location']}", ep["id"], r["id"])
                except Exception as e:  # noqa: BLE001
                    self.store.log(f"private key export failed: {type(e).__name__}: {e}"[:500], ep["id"], r["id"],
                                   level="warning")
        return refs

    def _fail(self, r, ep, msg: str, state: str = "failed"):
        if not self.store.update_renewal(r["id"], expect_state=r["state"], state=state, error=msg):
            return  # someone else moved this renewal meanwhile; their outcome stands
        self.store.log(msg, ep["id"], r["id"], level="error")
        self._discard_pack(r["id"], ep)

    def _discard_pack(self, rid: int, ep: dict | None):
        """Delete a renewal's change pack (it contains a plaintext key)."""
        try:
            conn = self.connector(ep) if ep else make_connector("manual", {}, self.data_dir)
        except Exception:  # noqa: BLE001 - a broken config must not keep a key on disk
            conn = make_connector("manual", {}, self.data_dir)
        if hasattr(conn, "cleanup"):
            conn.cleanup(rid)

    def cancel(self, rid: int, reason: str = "cancelled") -> None:
        r = self.store.renewal(rid)
        if not r or r["state"] not in OPEN_STATES:
            raise ValueError("renewal is not open")
        if not self.store.update_renewal(rid, expect_state=r["state"], state="cancelled"):
            raise ValueError("renewal changed state concurrently; retry")
        self.store.log(reason, r["endpoint_id"], rid)
        self._discard_pack(rid, self.store.endpoint(r["endpoint_id"]))
        self._notify("cancelled", rid)

    def sweep_packs(self) -> int:
        """Remove change packs left behind by renewals that are no longer awaiting a human."""
        from farrier.storage.packs import pack_store
        removed = 0
        for rid in pack_store(self.data_dir).ids():
            r = self.store.renewal(rid)
            # issued: the pack is written just before issued -> awaiting_manual; don't race that
            if r is None or r["state"] not in ("issued", "awaiting_manual"):
                self._discard_pack(rid, None)
                removed += 1
        return removed

    def sweep_exported_keys(self, now: datetime | None = None) -> int:
        """Delete keys exported for event consumers once export_key_retention_hours have passed."""
        hours = self.settings.get("export_key_retention_hours", 24)
        if not hours:
            return 0
        cutoff = ((now or policy.utcnow()) - timedelta(hours=hours)).isoformat(timespec="seconds")
        removed = 0
        for row in self.store.q("SELECT name, body FROM config_items WHERE kind=? AND updated_at < ?",
                                (EXPORTED_KEY, cutoff)):
            b = json.loads(row["body"])
            try:
                self.secrets._backend(b["backend"]).delete(b["ref"])
            except Exception as e:  # noqa: BLE001 - kept, retried next tick
                self.store.log(f"deleting exported key keys/{row['name']} failed: {type(e).__name__}: {e}"[:500],
                               level="warning")
                continue
            self.store.x("DELETE FROM config_items WHERE kind=? AND name=?", (EXPORTED_KEY, row["name"]))
            self.store.log(f"exported private key keys/{row['name']} deleted after {hours} h")
            removed += 1
        return removed

    def _step_planned(self, r, ep, now):
        if parse_dt(r["scheduled_for"]) > now or discovered(ep):
            return  # not yet, or a discovered endpoint planned before approval existed: wait for an admin
        try:
            issuer = self.issuers.get(ep["issuer"]) or self.issuers["default"]
            obs = self.store.latest_cert_observation(ep["id"])
            cn = ep["common_name"] or (obs and obs["subject_cn"]) or ep["host"]
            sans = ep["sans"] or (obs["sans"] if obs and obs["sans"] else [])
            names = list(dict.fromkeys([cn, *sans]))
            key = generate_key(ep["key_type"])
            csr = build_csr(key, cn, names)
            # per-endpoint DNS account (dns.json) overrides the issuer's zone matching
            acct = (ep.get("connector_config") or {}).get("dns_account")
            kw = {"dns_account": acct} if acct and getattr(issuer, "supports_dns_account", False) else {}
            if getattr(issuer, "supports_ari", False) and (prev := self._served_by_farrier(ep)):
                kw["replaces_pem"] = prev["cert_pem"]
            cert_pem, chain_pem = issuer.issue(csr, names, **kw)
            info = parse_pem(cert_pem)
        except Exception as e:  # noqa: BLE001
            attempts = r["attempts"] + 1
            if attempts >= self.settings["issue_max_attempts"]:
                return self._fail(r, ep, f"issuance failed {attempts}x: {e}")
            if self.store.update_renewal(r["id"], expect_state="planned", attempts=attempts,
                                         error=f"issuance: {e}"):
                self.store.log(f"issuance attempt {attempts} failed: {e}", ep["id"], r["id"], level="warning")
            return
        if not self.store.update_renewal(r["id"], expect_state="planned", state="issued",
                                         key_sealed=self.store.vault.seal(key_to_pem(key)),
                                         csr_pem=csr, cert_pem=cert_pem, chain_pem=chain_pem,
                                         new_fingerprint=info.fingerprint, not_after=info.not_after.isoformat(),
                                         attempts=0, error=None):
            return  # another replica advanced it first; this certificate is simply not used
        self.store.log(f"issued {info.subject_cn} by {info.issuer}, expires {info.not_after:%Y-%m-%d} "
                       f"({info.lifetime_days}d)", ep["id"], r["id"])

    def _bundle(self, r, ep) -> Bundle:
        return Bundle(name=ep["name"], renewal_id=r["id"], key_pem=self.store.vault.open(r["key_sealed"]),
                      cert_pem=r["cert_pem"], chain_pem=r["chain_pem"] or "", not_after=r["not_after"])

    def _step_issued(self, r, ep, now):
        try:
            conn = self.connector(ep)
            b = self._bundle(r, ep)
            if conn.automated:
                # claim the renewal before touching the device: only one replica ever deploys it
                if not self.store.update_renewal(r["id"], expect_state="issued", state="deploying"):
                    return
                token = conn.deploy(b)
                self.store.update_renewal(r["id"], expect_state="deploying", state="verifying", rollback=token,
                                          attempts=0)
                self.store.log(f"deployed via {conn.kind}", ep["id"], r["id"])
            else:
                due = r["deadline"] or (parse_dt(r["not_after"]) - timedelta(days=1)).isoformat()
                out = conn.deploy(b, addr=f"{ep['host']}:{ep['port']}", fingerprint=r["new_fingerprint"],
                                  due=due[:10])
                if not self.store.update_renewal(r["id"], expect_state="issued", state="awaiting_manual",
                                                 ticket_ref=out.get("ticket_ref")):
                    return
                self.store.log("change pack ready" + (f", ticket {out['ticket_ref']}" if out.get("ticket_ref")
                                                      else ""), ep["id"], r["id"])
        except Exception as e:  # noqa: BLE001
            self._fail(r, ep, f"deploy failed: {e}")

    def _step_deploying(self, r, ep, now):
        # A crash mid-deploy leaves us here. The device state is unknown: check, don't redeploy blindly.
        self.store.update_renewal(r["id"], expect_state="deploying", state="verifying")

    def _step_verifying(self, r, ep, now):
        cert = None
        for i in range(3):
            cert = self.observe(ep)
            if cert and cert.fingerprint == r["new_fingerprint"]:
                break
            if i < 2:
                time.sleep(self.settings["verify_retry_seconds"])
        problem = None
        if cert and cert.fingerprint == r["new_fingerprint"]:
            problem = self._deep_verify(r, ep)
            if problem is None:
                if self.store.update_renewal(r["id"], expect_state="verifying", state="done", error=None):
                    self.store.log(f"verified live on {ep['host']}:{ep['port']}", ep["id"], r["id"])
                return
        attempts = r["attempts"] + 1
        seen = problem or (cert.fingerprint[:16] if cert else "no TLS")
        if attempts < self.settings["verify_max_attempts"]:
            self.store.update_renewal(r["id"], expect_state="verifying", attempts=attempts,
                                      error=f"verify: {problem}" if problem else f"verify: endpoint serving {seen}")
            return
        # Claim the renewal before touching the device (verifying -> failed, then -> rolled_back once it
        # worked): a concurrent cancel or another replica must not see its renewal rolled back under it.
        if not self.store.update_renewal(r["id"], expect_state="verifying", state="failed",
                                         error=f"new cert never went live (serving {seen}){ROLLING_BACK}"):
            return
        self._roll_back(r, ep, seen)

    def _roll_back(self, r, ep, seen: str) -> None:
        """Run a claimed (state failed, error ending ROLLING_BACK) rollback and record how it ended."""
        try:
            if r["rollback"]:
                self.connector(ep).rollback(r["rollback"])
            msg = f"new cert never went live (serving {seen}); rolled back"
            self.store.update_renewal(r["id"], expect_state="failed", state="rolled_back", error=msg)
        except Exception as e:  # noqa: BLE001
            msg = f"new cert never went live and rollback failed: {e}"
            self.store.update_renewal(r["id"], expect_state="failed", error=msg)
        self.store.log(msg, ep["id"], r["id"], level="error")
        self._discard_pack(r["id"], ep)

    def recover_rollbacks(self, grace: timedelta = timedelta(minutes=10)) -> int:
        """Finish rollbacks a crash interrupted: renewals still ``failed`` with the "rolling back" marker and
        a rollback token, untouched for ``grace`` (longer than any rollback runs). Each is retried at most
        once: the marker is swapped with a compare-and-set before the device is touched."""
        cutoff = (policy.utcnow() - grace).isoformat(timespec="seconds")
        done = 0
        for row in self.store.q("SELECT id, error FROM renewals WHERE state='failed' AND rollback IS NOT NULL "
                                "AND error LIKE ? AND updated_at < ?", (f"%{ROLLING_BACK}", cutoff)):
            seen = row["error"][:-len(ROLLING_BACK)].removeprefix("new cert never went live (serving ").rstrip(")")
            claimed = self.store._run("UPDATE renewals SET error=?, updated_at=? WHERE id=? AND state='failed' "
                                      "AND error=?", (f"{row['error'][:-len(ROLLING_BACK)]}; rollback resumed "
                                                      "after a restart", now_iso(), row["id"], row["error"]))[1]
            if not claimed:
                continue
            r = self.store.renewal(row["id"])
            ep = self.store.endpoint(r["endpoint_id"])
            self._roll_back(r, ep, seen)
            self._notify(self.store.renewal(r["id"])["state"], r["id"])
            done += 1
        return done

    def _deep_verify(self, r, ep) -> str | None:
        """Chain, hostname and every-VIP checks once the new fingerprint is seen. None means good."""
        if not self.settings["verify_chain_and_names"]:
            return None
        from farrier.monitoring.health import verify_deployment
        names = [n for n in dict.fromkeys([ep.get("common_name"), *(ep.get("sans") or [])]) if n]
        v = verify_deployment(ep["host"], ep["port"], ep["sni"], r["new_fingerprint"], names,
                              addresses=(ep.get("connector_config") or {}).get("vips"),
                              resolve_all=self.settings["verify_all_addresses"],
                              trust_pems=r.get("chain_pem"), timeout=self.settings["scan_timeout"])
        return None if v["ok"] else "; ".join(v["problems"])[:500]

    def _step_awaiting_manual(self, r, ep, now):
        cert = self.observe(ep)
        if cert and cert.fingerprint == r["new_fingerprint"]:
            if not self.store.update_renewal(r["id"], expect_state="awaiting_manual", state="done", error=None):
                return
            self.store.log("installed by operator; verified live" +
                           (f"; ticket {r['ticket_ref']} can be closed" if r["ticket_ref"] else ""), ep["id"], r["id"])
            conn = self.connector(ep)
            if hasattr(conn, "cleanup"):
                conn.cleanup(r["id"])
            return
        if cert and cert.fingerprint not in (r["prev_fingerprint"], r["new_fingerprint"]) \
                and cert.not_after > policy.utcnow() + timedelta(days=30):
            if not self.store.update_renewal(r["id"], expect_state="awaiting_manual", state="superseded",
                                             error=f"a different cert ({cert.fingerprint[:16]}) was installed"):
                return
            self.store.log("someone installed a different certificate; renewal superseded", ep["id"], r["id"],
                           level="warning")
            self._discard_pack(r["id"], ep)
            return
        if r["deadline"] and now > parse_dt(r["deadline"]) and not (r["error"] or "").startswith("OVERDUE"):
            if self.store.update_renewal(r["id"], expect_state="awaiting_manual",
                                         error="OVERDUE: change not installed before deadline"):
                self.store.log("manual change is overdue; current cert expires imminently", ep["id"], r["id"],
                           level="error")

    # ---- tick --------------------------------------------------------------
    def tick(self, now: datetime | None = None, scan: bool = True) -> dict:
        """One scan/plan/advance cycle, run only by the leader replica. A follower (or a replica
        shutting down) returns at once with ``skipped`` set; it re-tries for the lease every call,
        so it takes over within one cycle of the leader going away."""
        self.check_config()  # every replica, leader or not, follows configuration changes
        if not self.try_lead():
            return {"planned": 0, "states": {}, "leader": False,
                    "skipped": "shutting down" if self._stopping.is_set() else "follower"}
        if not self._tick_lock.acquire(blocking=False):
            return {"planned": 0, "states": {}, "leader": True, "skipped": "tick already running"}
        try:
            return {**self._tick(now, scan), "leader": True}
        finally:
            self._tick_lock.release()

    def _tick(self, now: datetime | None = None, scan: bool = True) -> dict:
        now = now or policy.utcnow()
        if scan:
            self.observe_all()
        planned = self.plan(now)
        states = Counter()
        for r in self.store.renewals(OPEN_STATES, limit=100000):
            states[self.advance(r["id"], now)] += 1
        try:
            self.recover_rollbacks()
        except Exception as e:  # noqa: BLE001
            self.store.log(f"rollback recovery failed: {type(e).__name__}: {e}", level="error")
        self.sweep_packs()
        try:
            self.sweep_exported_keys(now)
        except Exception as e:  # noqa: BLE001
            self.store.log(f"exported key sweep failed: {type(e).__name__}: {e}", level="error")
        out = {"planned": len(planned), "states": dict(states)}
        if scan:
            try:   # after renewals, so a slow probe never delays a change; wall-clock cadence (stored times are real)
                from farrier.crypto.service import rescan_due
                if crypto := rescan_due(self):
                    out["crypto_scanned"] = crypto
            except Exception as e:  # noqa: BLE001
                self.store.log(f"crypto re-scan failed: {type(e).__name__}: {e}", level="error")
            try:   # SSH re-scan/collection: started in the background when due (farrier.ssh.schedule)
                from farrier.ssh.schedule import run_due as ssh_run_due
                if ssh := ssh_run_due(self, parse_dt(now_iso())):
                    out["ssh"] = ssh
            except Exception as e:  # noqa: BLE001
                self.store.log(f"ssh periodic run failed: {type(e).__name__}: {e}", level="error")
        try:
            alerts = self.alerts.evaluate(now)
        except Exception as e:  # noqa: BLE001
            self.store.log(f"alert rule evaluation failed: {type(e).__name__}: {e}", level="error")
            alerts = 0
        if alerts:
            out["alerts"] = alerts
        self.itsm.tick(now)                     # ticket retries, Datadog metrics, Splunk inventory; never raises
        return out
