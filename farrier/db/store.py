"""The Store: a thin SQL layer over SQLite (default), PostgreSQL or MySQL/MariaDB.

Private keys are sealed with the Vault before they touch the database. The backend is chosen by
FARRIER_DATABASE_URL (see farrier.db_dialects); callers write SQLite-flavoured SQL with ``?``
placeholders and the dialect translates it. The schema is versioned (farrier.db_migrations).
"""
from __future__ import annotations

import json
import os
import threading
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from farrier.db import migrations as db_migrations
from farrier.db.dialects import make_dialect, redact_url
from farrier.security.vault import Vault

TABLES = ("projects",                                       # migration 8; "default" exists in every database
          "endpoints", "observations", "renewals", "events",   # in foreign-key order
          "certificates", "crypto_assets", "crypto_scans",  # migration 5
          "ssh_hosts", "ssh_keys",                          # migration 6
          "itsm_tickets",                                   # migration 7
          "runner_jobs")                                    # migration 9
# Dashboard configuration (migration 4): keyed tables without an id, copied as is (secrets stay sealed)
CONFIG_TABLES = ("secrets", "secret_values", "config_items", "alert_state", "health_results",
                 "ssh_host_pins", "ssh_runs")  # keyed, no id: trusted host keys must survive a move

OPEN_STATES = ("planned", "issued", "deploying", "verifying", "awaiting_manual")
JSON_COLS = {"sans", "connector_config", "window", "tags", "rollback", "members"}
DEFAULT_PROJECT = "default"


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    d = datetime.fromisoformat(s)
    return d if d.tzinfo else d.replace(tzinfo=UTC)


def _row(r: dict | None) -> dict | None:
    if r is None:
        return None
    d = r
    for k in JSON_COLS & d.keys():
        if d[k] is not None:
            d[k] = json.loads(d[k])
    return d


class Store:
    def __init__(self, data_dir: str | Path, url: str | None = None):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.vault = Vault(self.data_dir)
        self._lock = threading.RLock()
        self._tx_depth = 0
        self.url = os.environ.get("FARRIER_DATABASE_URL", "") if url is None else url
        self.dialect = make_dialect(self.url, self.data_dir)
        self.conn = self.dialect.connect()
        self.migrated = db_migrations.apply(self)

    @property
    def backend(self) -> str:
        return self.dialect.name

    # ---- execution core ---------------------------------------------------
    def _reconnect(self) -> None:
        try:
            self.conn.close()
        except Exception:  # noqa: BLE001
            pass
        self.conn = self.dialect.connect()

    def _run(self, sql: str, args=(), fetch: bool | str = False):
        """Execute one statement. fetch=True -> list of dicts, "one" -> first dict or None,
        False -> (lastrowid, rowcount)."""
        d = self.dialect
        returning = not fetch and d.insert_returning(sql)
        stmt = d.translate(sql + (" RETURNING id" if returning else ""))
        params = d.adapt(args)
        with self._lock:
            for attempt in (0, 1):
                try:
                    cur = self.conn.cursor()
                    cur.execute(stmt, params)
                    break
                except d.disconnect_errors:
                    # A dropped server connection: reconnect once, but never mid-transaction
                    # (the server has already rolled it back) and never twice.
                    if attempt or self._tx_depth:
                        raise
                    self._reconnect()
            if fetch:
                cols = [c[0] for c in cur.description] if cur.description else []
                if fetch is True:
                    rows = cur.fetchall()
                else:
                    one = cur.fetchone()
                    rows = [] if one is None else [one]
                out = [dict(zip(cols, tuple(r))) for r in rows]
                return out if fetch is True else (out[0] if out else None)
            lastrowid = cur.lastrowid
            if returning:
                row = cur.fetchone()
                lastrowid = row[0] if row else None
            rowcount = cur.rowcount
            if not self._tx_depth:
                d.autocommit_after(self.conn)
            return lastrowid, rowcount

    @contextmanager
    def transaction(self):
        """Group statements atomically (nested calls join the outer transaction)."""
        with self._lock:
            if self._tx_depth:
                self._tx_depth += 1
                try:
                    yield self
                finally:
                    self._tx_depth -= 1
                return
            self.dialect.begin(self.conn)
            self._tx_depth = 1
            try:
                yield self
            except BaseException:
                self._tx_depth = 0
                try:
                    self.dialect.rollback(self.conn)
                except Exception:  # noqa: BLE001
                    pass
                raise
            self._tx_depth = 0
            self.dialect.commit(self.conn)

    @contextmanager
    def snapshot(self):
        """Read-only transaction with one consistent view of every table (farrier backup)."""
        with self._lock:
            if self._tx_depth:
                raise RuntimeError("snapshot() cannot run inside a transaction")
            self.dialect.begin_snapshot(self.conn)
            self._tx_depth = 1
            try:
                yield self
            finally:
                self._tx_depth = 0
                try:
                    self.dialect.rollback(self.conn)
                except Exception:  # noqa: BLE001
                    pass

    # ---- generic ----------------------------------------------------------
    def q(self, sql: str, args=()) -> list[dict]:
        return [_row(r) for r in self._run(sql, args, fetch=True)]

    def q1(self, sql: str, args=()) -> dict | None:
        return _row(self._run(sql, args, fetch="one"))

    def x(self, sql: str, args=()) -> int:
        return self._run(sql, args)[0]

    def close(self) -> None:
        with self._lock:
            try:
                self.conn.close()
            except Exception:  # noqa: BLE001
                pass

    # ---- status / HA ------------------------------------------------------
    def schema_version(self) -> int:
        return db_migrations.current_version(self)

    def status(self) -> dict:
        """Backend facts for health pages. The URL is shown without its password."""
        return {"backend": self.dialect.name, "database": redact_url(self.url),
                "schema_version": self.schema_version(), "schema_latest": db_migrations.latest_version()}

    def leader_lease(self):
        """A new leader lease suited to this backend (see farrier.leader)."""
        from farrier.db.leader import make_lease
        return make_lease(self.dialect, self.data_dir)

    # ---- copy (farrier db migrate --to) ------------------------------------
    def copy_to(self, dest: Store, batch: int = 500, progress=None) -> dict:
        """Copy every table into ``dest`` verbatim, ids included. Sealed keys are copied as
        ciphertext; nothing is decrypted. ``dest`` must be empty."""
        for t in TABLES + CONFIG_TABLES:
            if dest.row_count(t):
                raise ValueError(f"destination table {t} is not empty; refusing to merge")
        counts = {}
        with dest.transaction():
            dest.x("DELETE FROM projects")           # the source's projects (its "default" included) replace it
            for t in CONFIG_TABLES:
                rows = self._run(f"SELECT * FROM {t}", (), fetch=True)
                for r in rows:
                    cols = list(r)
                    dest._run(f"INSERT INTO {t}({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
                              tuple(r[c] for c in cols))
                if rows:  # reported only when there is something to report
                    counts[t] = len(rows)
            for t in TABLES:
                rows = self._run(f"SELECT * FROM {t} ORDER BY id", (), fetch=True)
                counts[t] = len(rows)
                for i in range(0, len(rows), batch):
                    chunk = rows[i:i + batch]
                    cols = list(chunk[0])
                    sql = f"INSERT INTO {t}({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})"
                    for r in chunk:
                        dest._run(sql, tuple(r[c] for c in cols))
                    if progress:
                        progress(t, min(i + batch, len(rows)), len(rows))
            for t in TABLES:
                dest.dialect.fix_sequence(dest, t)
            dest.ensure_default_project()
        return counts

    def row_count(self, table: str) -> int:
        """Rows in a table, not counting the built-in "default" project every migrated database has."""
        where = f" WHERE name <> '{DEFAULT_PROJECT}'" if table == "projects" else ""
        return self._run(f"SELECT COUNT(*) AS n FROM {table}{where}", (), fetch="one")["n"]

    # ---- projects ---------------------------------------------------------
    def ensure_default_project(self) -> None:
        """After a copy or restore from an older schema: the built-in project must exist."""
        if not self.q1("SELECT id FROM projects WHERE name=?", (DEFAULT_PROJECT,)):
            self.x("INSERT INTO projects(name, title, members, created_at) VALUES (?,?,?,?)",
                   (DEFAULT_PROJECT, "Default", "{}", now_iso()))
        self._default_pid = None

    def default_project_id(self) -> int:
        pid = getattr(self, "_default_pid", None)
        if pid is None:
            row = self.q1("SELECT id FROM projects WHERE name=?", (DEFAULT_PROJECT,))
            pid = self._default_pid = (row or {}).get("id") or 1
        return pid

    def projects(self) -> list[dict]:
        return self.q("SELECT * FROM projects ORDER BY name <> 'default', name")

    def project(self, name: str) -> dict | None:
        return self.q1("SELECT * FROM projects WHERE name=?", (name,))

    def project_id_of(self, row: dict | None) -> int:
        """The project a row belongs to (NULL is the default project)."""
        pid = (row or {}).get("project_id")
        return pid if pid is not None else self.default_project_id()

    def log(self, message: str, endpoint_id=None, renewal_id=None, level="info"):
        self.x("INSERT INTO events(at, endpoint_id, renewal_id, level, message) VALUES (?,?,?,?,?)",
               (now_iso(), endpoint_id, renewal_id, level, message))

    # ---- endpoints --------------------------------------------------------
    def upsert_endpoint(self, ep: dict) -> int:
        cols = ["name", "host", "port", "sni", "common_name", "sans", "key_type", "connector",
                "connector_config", "issuer", "window", "lead_days", "owner", "tags", "enabled", "project_id"]
        data = {k: ep[k] for k in cols if k in ep and not (k == "project_id" and ep[k] is None)}
        for k in JSON_COLS & data.keys():
            data[k] = json.dumps(data[k])
        existing = self.q1("SELECT id FROM endpoints WHERE name=?", (ep["name"],))
        if existing:
            if data:
                sets = ", ".join(f"{k}=?" for k in data)
                self.x(f"UPDATE endpoints SET {sets} WHERE id=?", (*data.values(), existing["id"]))
            return existing["id"]
        data["created_at"] = now_iso()
        if data.get("project_id") is None:
            data["project_id"] = self.default_project_id()
        keys = ", ".join(data)
        marks = ", ".join("?" * len(data))
        return self.x(f"INSERT INTO endpoints({keys}) VALUES ({marks})", tuple(data.values()))

    _EP = (f"SELECT e.*, COALESCE(p.name, '{DEFAULT_PROJECT}') AS project FROM endpoints e "
           "LEFT JOIN projects p ON p.id = e.project_id")

    def endpoint(self, eid: int) -> dict | None:
        return self.q1(f"{self._EP} WHERE e.id=?", (eid,))

    def endpoint_by_addr(self, host: str, port: int, sni: str | None) -> dict | None:
        return self.q1(f"{self._EP} WHERE e.host=? AND e.port=? AND IFNULL(e.sni,'')=IFNULL(?, '')",
                       (host, port, sni))

    def endpoints(self) -> list[dict]:
        return self.q(f"""
          SELECT e.*, COALESCE(p.name, '{DEFAULT_PROJECT}') AS project, o.fingerprint, o.not_after, o.not_before,
                 o.issuer AS cert_issuer, o.subject_cn, o.observed_at, o.error AS scan_error
          FROM endpoints e
          LEFT JOIN projects p ON p.id = e.project_id
          LEFT JOIN observations o ON o.id = (
             SELECT id FROM observations WHERE endpoint_id = e.id ORDER BY observed_at DESC, id DESC LIMIT 1)
          ORDER BY o.not_after IS NULL, o.not_after""")

    def latest_cert_observation(self, eid: int) -> dict | None:
        return self.q1("""SELECT * FROM observations WHERE endpoint_id=? AND fingerprint IS NOT NULL
                          ORDER BY observed_at DESC, id DESC LIMIT 1""", (eid,))

    def add_observation(self, eid: int, cert=None, error: str | None = None):
        if cert is None:
            self.x("INSERT INTO observations(endpoint_id, observed_at, error) VALUES (?,?,?)",
                   (eid, now_iso(), error))
            return
        self.x("""INSERT INTO observations(endpoint_id, observed_at, fingerprint, subject_cn, sans, issuer,
                   not_before, not_after, key_type) VALUES (?,?,?,?,?,?,?,?,?)""",
               (eid, now_iso(), cert.fingerprint, cert.subject_cn, json.dumps(cert.sans), cert.issuer,
                cert.not_before.isoformat(), cert.not_after.isoformat(), cert.key_type))
        if getattr(cert, "der", None):
            self.save_certificate(cert.fingerprint, cert.der, getattr(cert, "chain_der", None) or [])

    def save_certificate(self, fingerprint: str, der: bytes, chain_der: list[bytes]) -> None:
        """Keep the served PEM (and the chain sent with it) once per fingerprint. Best effort: an
        observation is never lost because its certificate could not be stored."""
        from farrier.core.x509util import der_to_pem
        try:
            cert_pem = der_to_pem(der)
            chain_pem = "".join(der_to_pem(c) for c in chain_der) or None
            row = self.q1("SELECT id, chain_pem FROM certificates WHERE fingerprint=?", (fingerprint,))
            if row is None:
                self.x("INSERT INTO certificates(fingerprint, cert_pem, chain_pem, first_seen) VALUES (?,?,?,?)",
                       (fingerprint, cert_pem, chain_pem, now_iso()))
            elif chain_pem and row["chain_pem"] != chain_pem:
                self.x("UPDATE certificates SET chain_pem=? WHERE id=?", (chain_pem, row["id"]))
        except Exception as e:  # noqa: BLE001 - e.g. a replica inserted the same fingerprint first
            if type(e).__name__ == "IntegrityError" and not self._tx_depth:
                self.conn.rollback()
            elif type(e).__name__ != "IntegrityError":
                self.log(f"could not store certificate {fingerprint[:16]}: {type(e).__name__}: {e}", level="warning")

    def certificate_pems(self, fingerprint: str) -> dict | None:
        """{cert_pem, chain_pem, first_seen} for a served fingerprint, or None (observed before migration 5)."""
        return self.q1("SELECT cert_pem, chain_pem, first_seen FROM certificates WHERE fingerprint=?", (fingerprint,))

    # ---- renewals ---------------------------------------------------------
    def open_renewal(self, eid: int) -> dict | None:
        marks = ",".join("?" * len(OPEN_STATES))
        return self.q1(f"SELECT * FROM renewals WHERE endpoint_id=? AND state IN ({marks}) ORDER BY id DESC LIMIT 1",
                       (eid, *OPEN_STATES))

    def create_renewal(self, eid: int, scheduled_for: str, deadline: str | None, prev_fp: str | None,
                       reason: str) -> int:
        """Open a renewal, or return the one already open for this endpoint (the unique open_slot
        index makes this safe when several replicas race)."""
        t = now_iso()
        try:
            return self.x("""INSERT INTO renewals(endpoint_id, state, reason, scheduled_for, deadline, prev_fingerprint,
                             created_at, updated_at, open_slot) VALUES (?,?,?,?,?,?,?,?,?)""",
                          (eid, "planned", reason, scheduled_for, deadline, prev_fp, t, t, eid))
        except Exception as e:  # each driver has its own IntegrityError class
            if type(e).__name__ != "IntegrityError":
                raise
            if not self._tx_depth:
                self.conn.rollback()            # drop the failed statement's implicit transaction
            if not (r := self.open_renewal(eid)):
                raise
            return r["id"]

    def renewal(self, rid: int) -> dict | None:
        return self.q1("SELECT * FROM renewals WHERE id=?", (rid,))

    def update_renewal(self, rid: int, expect_state: str | None = None, **fields) -> bool:
        """Update a renewal. With ``expect_state`` this is a compare-and-set: the row changes only
        if it is still in that state, and the return value says whether it did. Two replicas (or a
        replica and an API call) can therefore never both move the same renewal out of a state."""
        if "rollback" in fields and fields["rollback"] is not None:
            fields["rollback"] = json.dumps(fields["rollback"])
        if "state" in fields and fields["state"] not in OPEN_STATES:
            fields["open_slot"] = None          # finished: free the endpoint's slot
        fields["updated_at"] = now_iso()
        sets = ", ".join(f"{k}=?" for k in fields)
        sql, args = f"UPDATE renewals SET {sets} WHERE id=?", (*fields.values(), rid)
        if expect_state is not None:
            sql, args = sql + " AND state=?", (*args, expect_state)
        return self._run(sql, args)[1] > 0

    def renewals(self, states: tuple[str, ...] | None = None, limit: int = 500, scope=None) -> list[dict]:
        """``scope`` (farrier.api.scope.Scope) keeps only renewals of endpoints in those projects."""
        sql = """SELECT r.id, r.endpoint_id, r.state, r.reason, r.scheduled_for, r.deadline, r.prev_fingerprint,
                        r.new_fingerprint, r.not_after, r.ticket_ref, r.attempts, r.error, r.created_at, r.updated_at,
                        e.name, e.connector, e.host, e.port, e.project_id
                 FROM renewals r JOIN endpoints e ON e.id = r.endpoint_id"""
        args: tuple = ()
        sql += " WHERE 1=1"
        if states:
            sql += f" AND r.state IN ({','.join('?' * len(states))})"
            args = states
        if scope is not None:
            clause, extra = scope.sql("e.project_id")
            sql, args = sql + clause, (*args, *extra)
        sql += " ORDER BY r.scheduled_for LIMIT ?"
        return self.q(sql, (*args, limit))
