"""Database backends, migrations, leader election and compare-and-set."""
from __future__ import annotations

import os
import sqlite3
import threading

import pytest

from farrier.core.engine import Engine
from farrier.db import migrations as db_migrations
from farrier.db.dialects import (
    MySQLDialect,
    PostgresDialect,
    make_dialect,
    parse_url,
    redact_url,
)
from farrier.db.leader import FileLease, PostgresLease
from farrier.db.store import Store, now_iso


@pytest.fixture(autouse=True)
def _no_db_env(monkeypatch):
    for k in ("FARRIER_DATABASE_URL", "FARRIER_DATABASE_PASSWORD", "FARRIER_LEADER_ELECTION"):
        monkeypatch.delenv(k, raising=False)


def _endpoint(store, name="a.test"):
    return store.upsert_endpoint({"name": name, "host": "127.0.0.1", "port": 1, "sni": name,
                                  "window": {"days": ["mon"]}, "tags": ["x"], "enabled": True})


# ---- fake DB-API driver ------------------------------------------------------------------------
class FakeCursor:
    def __init__(self, conn):
        self.conn, self.description, self._rows, self.lastrowid, self.rowcount = conn, None, [], None, 1

    def execute(self, sql, params=None):
        self.conn.log.append((sql, params))
        if self.conn.fail_next:
            self.conn.fail_next = False
            raise ConnectionError("server closed the connection")
        if "MAX(version)" in sql:
            self.description, self._rows = [("v",)], [(self.conn.version,)]
        elif "RETURNING id" in sql:
            self.description, self._rows = [("id",)], [(42,)]
        elif "FROM endpoints" in sql:
            self.description, self._rows = [("id",)], []
        elif sql.lstrip().upper().startswith("SELECT"):
            self.description, self._rows = [("ok",)], [(self.conn.select_value,)]
        elif sql.lstrip().upper().startswith("INSERT"):
            self.lastrowid = 7
        elif "AND state=" in sql:
            self.rowcount = 0  # the compare-and-set misses

    def fetchone(self):
        return self._rows.pop(0) if self._rows else None

    def fetchall(self):
        rows, self._rows = self._rows, []
        return rows


class FakeConn:
    def __init__(self, version=0):
        self.log, self.version, self.select_value, self.fail_next, self.closed = [], version, 1, False, False

    def cursor(self):
        return FakeCursor(self)

    def execute(self, sql, params=None):
        return self.cursor().execute(sql, params)

    def close(self):
        self.closed = True

    def sql(self):
        return "\n".join(s for s, _ in self.log)


@pytest.fixture
def fake(monkeypatch):
    conns = []

    def connect(self):
        conns.append(FakeConn())
        return conns[-1]
    monkeypatch.setattr(PostgresDialect, "connect", connect)
    monkeypatch.setattr(MySQLDialect, "connect", connect)
    for d in (PostgresDialect, MySQLDialect):
        monkeypatch.setattr(d, "disconnect_errors", (ConnectionError,))
    return conns


# ---- dialect translation ---------------------------------------------------------------------
def test_postgres_translation(tmp_path):
    d = make_dialect("postgresql://farrier@db/farrier", tmp_path)
    sql = "SELECT * FROM endpoints WHERE host=? AND IFNULL(sni,'')=IFNULL(?, '') AND name LIKE 'a%?' AND window=?"
    assert d.translate(sql) == ("SELECT * FROM endpoints WHERE host=%s AND COALESCE(sni,'')=COALESCE(%s, '') "
                                "AND name LIKE 'a%%?' AND \"window\"=%s")
    assert d.insert_returning("INSERT INTO renewals(state) VALUES (?)")
    assert not d.insert_returning("INSERT INTO schema_version(version) VALUES (?)")
    assert not d.insert_returning("UPDATE renewals SET state=?")
    assert d.adapt((True, False, 3, "x")) == (1, 0, 3, "x")


def test_mysql_translation(tmp_path):
    d = make_dialect("mysql://farrier@db/farrier", tmp_path)
    assert d.translate('UPDATE endpoints SET window=?, "tags"=? WHERE id=?') == \
        "UPDATE endpoints SET `window`=%s, `tags`=%s WHERE id=%s"
    assert d.translate("SELECT IFNULL(a, 1)") == "SELECT IFNULL(a, 1)"   # MySQL has IFNULL
    assert not d.insert_returning("INSERT INTO renewals(state) VALUES (?)")  # uses cursor.lastrowid


def test_sqlite_is_untranslated(tmp_path):
    d = make_dialect(None, tmp_path)
    assert d.name == "sqlite" and d.translate("SELECT ? , window") == "SELECT ? , window"
    assert make_dialect("sqlite:///" + str(tmp_path / "x.db").replace("\\", "/"), tmp_path).url.path.endswith("x.db")


def test_postgres_store_against_mock_driver(tmp_path, fake):
    s = Store(tmp_path, url="postgresql://farrier@db/farrier?sslmode=verify-full")
    ddl = fake[0].sql()
    assert "BIGSERIAL PRIMARY KEY" in ddl and "INTEGER PRIMARY KEY" not in ddl.replace("NOT NULL PRIMARY KEY", "")
    assert "pg_advisory_xact_lock(%s)" in ddl and '"window" TEXT NOT NULL' in ddl
    assert s.migrated == [1, 2, 3, 4]
    fake[0].log.clear()
    assert s.x("INSERT INTO events(at, level, message) VALUES (?,?,?)", (now_iso(), "info", "hi")) == 42
    sql, params = fake[0].log[-1]
    assert sql.endswith("VALUES (%s,%s,%s) RETURNING id") and isinstance(params, tuple)
    _endpoint(s)
    sql, params = fake[0].log[-1]
    assert '"window"' in sql and 1 in params and True not in [p for p in params if p is True]
    assert s.update_renewal(5, expect_state="planned", state="issued") is False
    assert fake[0].log[-1][0].endswith("WHERE id=%s AND state=%s")


def test_mysql_store_against_mock_driver(tmp_path, fake):
    s = Store(tmp_path, url="mysql://farrier@db/farrier")
    ddl = fake[0].sql()
    assert "AUTO_INCREMENT PRIMARY KEY" in ddl and "name VARCHAR(255) NOT NULL UNIQUE" in ddl
    assert "DEFAULT ('[]')" in ddl and "ENGINE=InnoDB" in ddl and "INDEX IF NOT EXISTS" not in ddl
    assert "GET_LOCK('farrier-migrate'" in ddl and "RELEASE_LOCK" in ddl and "`window` MEDIUMTEXT" in ddl
    assert s.x("INSERT INTO events(at, level, message) VALUES (?,?,?)", (now_iso(), "info", "hi")) == 7


def test_reconnects_once_after_dropped_connection(tmp_path, fake):
    s = Store(tmp_path, url="postgresql://farrier@db/farrier")
    fake[0].fail_next = True
    assert s.q1("SELECT 1 AS ok") == {"ok": 1}
    assert fake[0].closed and len(fake) == 2


def test_url_parsing_tls_and_passwords(tmp_path, monkeypatch):
    monkeypatch.setenv("DBPW", "s3cret")
    u = parse_url("postgresql://farrier:env:DBPW@db.internal:5433/farrier?sslmode=verify-full"
                  "&sslrootcert=/etc/ca.pem", tmp_path)
    assert (u.user, u.host, u.port, u.database, u.password) == ("farrier", "db.internal", 5433, "farrier", "s3cret")
    kw = PostgresDialect(u).connect_kwargs()
    assert kw["sslmode"] == "verify-full" and kw["sslrootcert"] == "/etc/ca.pem" and kw["password"] == "s3cret"
    assert "s3cret" not in repr(u) and "DBPW" not in redact_url("postgresql://farrier:env:DBPW@db/f")

    with pytest.raises(ValueError, match="literal password"):
        parse_url("postgresql://farrier:hunter2@db/farrier", tmp_path)
    assert "hunter2" not in redact_url("postgresql://farrier:hunter2@db/farrier?password=hunter2")

    pwfile = tmp_path / "pw"
    pwfile.write_text("fromfile\n")
    monkeypatch.setenv("FARRIER_DATABASE_PASSWORD", f"file:{pwfile}")
    m = MySQLDialect(parse_url("mysql://farrier@db/farrier?sslmode=verify-full&sslrootcert=/ca.pem", tmp_path))
    kw = m.connect_kwargs()
    assert kw["password"] == "fromfile" and kw["ssl"] == {"ca": "/ca.pem"}
    assert kw["ssl_verify_cert"] and kw["ssl_verify_identity"] and kw["client_flag"] & 2


# ---- SQLite: migrations ------------------------------------------------------------------------
LEGACY_SCHEMA = """
CREATE TABLE endpoints (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, host TEXT NOT NULL,
  port INTEGER NOT NULL DEFAULT 443, sni TEXT, common_name TEXT, sans TEXT NOT NULL DEFAULT '[]',
  key_type TEXT NOT NULL DEFAULT 'ec256', connector TEXT NOT NULL DEFAULT 'manual',
  connector_config TEXT NOT NULL DEFAULT '{}', issuer TEXT NOT NULL DEFAULT 'default',
  window TEXT NOT NULL DEFAULT '{}', lead_days INTEGER NOT NULL DEFAULT 0, owner TEXT,
  tags TEXT NOT NULL DEFAULT '[]', enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
CREATE TABLE observations (id INTEGER PRIMARY KEY, endpoint_id INTEGER NOT NULL REFERENCES endpoints(id)
  ON DELETE CASCADE, observed_at TEXT NOT NULL, fingerprint TEXT, subject_cn TEXT, sans TEXT, issuer TEXT,
  not_before TEXT, not_after TEXT, key_type TEXT, error TEXT);
CREATE INDEX obs_ep ON observations(endpoint_id, observed_at);
CREATE TABLE renewals (id INTEGER PRIMARY KEY, endpoint_id INTEGER NOT NULL REFERENCES endpoints(id)
  ON DELETE CASCADE, state TEXT NOT NULL, reason TEXT, scheduled_for TEXT NOT NULL, deadline TEXT,
  prev_fingerprint TEXT, new_fingerprint TEXT, key_sealed TEXT, csr_pem TEXT, cert_pem TEXT, chain_pem TEXT,
  not_after TEXT, rollback TEXT, ticket_ref TEXT, attempts INTEGER NOT NULL DEFAULT 0, error TEXT,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE INDEX ren_state ON renewals(state, scheduled_for);
CREATE TABLE events (id INTEGER PRIMARY KEY, at TEXT NOT NULL, endpoint_id INTEGER, renewal_id INTEGER,
  level TEXT NOT NULL DEFAULT 'info', message TEXT NOT NULL);
"""


def test_migrations_apply_once_and_are_idempotent(tmp_path):
    s = Store(tmp_path)
    assert s.migrated == [1, 2, 3, 4] and s.schema_version() == db_migrations.latest_version()
    s.close()
    s2 = Store(tmp_path)
    assert s2.migrated == [] and len(s2.q("SELECT * FROM schema_version")) == len(db_migrations.MIGRATIONS)
    assert s2.status()["backend"] == "sqlite"


def test_legacy_sqlite_file_is_migrated_in_place(tmp_path):
    c = sqlite3.connect(tmp_path / "farrier.db.store")
    c.executescript(LEGACY_SCHEMA)
    c.execute("INSERT INTO endpoints(name, host, created_at, window) VALUES ('old', 'h', 'now', '{\"a\": 1}')")
    c.commit()
    c.close()
    s = Store(tmp_path)
    assert s.migrated == [1, 2, 3, 4]
    assert s.q1("SELECT name, window FROM endpoints") == {"name": "old", "window": {"a": 1}}
    idx = {r["name"] for r in s.q("SELECT name FROM sqlite_master WHERE type='index'")}
    assert {"obs_ep", "ren_state", "ren_ep", "ev_ep"} <= idx


def test_copy_to_new_database_keeps_ciphertext(tmp_path):
    src = Store(tmp_path / "a")
    eid = _endpoint(src)
    rid = src.create_renewal(eid, now_iso(), None, None, "due")
    sealed = src.vault.seal("-----BEGIN PRIVATE KEY-----")
    src.update_renewal(rid, key_sealed=sealed, rollback={"t": 1})
    src.log("hello", eid, rid)
    dest_url = "sqlite:///" + str(tmp_path / "b" / "copy.db").replace("\\", "/")
    dst = Store(tmp_path / "a", url=dest_url)
    counts = src.copy_to(dst)
    assert counts == {"endpoints": 1, "observations": 0, "renewals": 1, "events": 1}
    r = dst.renewal(rid)
    assert r["key_sealed"] == sealed and r["rollback"] == {"t": 1}
    assert dst.endpoint(eid)["window"] == {"days": ["mon"]}
    assert dst.open_renewal(eid)["id"] == rid                      # the open slot came across too
    dst.update_renewal(rid, state="done")
    assert dst.create_renewal(eid, now_iso(), None, None, "next") == rid + 1  # id sequence continues
    with pytest.raises(ValueError, match="not empty"):
        src.copy_to(dst)


def test_cli_db_migrate(tmp_path, capsys):
    from farrier.cli import main
    src = Store(tmp_path / "d")
    _endpoint(src)
    src.close()
    dest = "sqlite:///" + str(tmp_path / "new.db").replace("\\", "/")
    main(["--data", str(tmp_path / "d"), "db", "migrate", "--to", dest])
    assert "endpoints     1 rows" in capsys.readouterr().out
    assert Store(tmp_path / "d", url=dest).q1("SELECT name FROM endpoints")["name"] == "a.test"


# ---- compare-and-set ------------------------------------------------------------------------
def test_compare_and_set_allows_one_winner(tmp_path):
    s = Store(tmp_path)
    rid = s.create_renewal(_endpoint(s), now_iso(), None, None, "due")
    assert s.update_renewal(rid, expect_state="planned", state="issued") is True
    assert s.update_renewal(rid, expect_state="planned", state="issued") is False
    assert s.renewal(rid)["state"] == "issued"

    rid2 = s.create_renewal(_endpoint(s, "b.test"), now_iso(), None, None, "due")
    wins, barrier = [], threading.Barrier(8)

    def racer():
        barrier.wait()
        wins.append(s.update_renewal(rid2, expect_state="planned", state="issued"))
    ts = [threading.Thread(target=racer) for _ in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert wins.count(True) == 1


def test_stale_replica_never_deploys_twice(tmp_path):
    eng = Engine(tmp_path, issuers={"default": {"kind": "local"}})
    s = eng.store
    eid = _endpoint(s)
    rid = s.create_renewal(eid, now_iso(), None, None, "due")
    s.update_renewal(rid, state="issued", key_sealed=s.vault.seal("k"), cert_pem="c", not_after="2030-01-01")
    deploys = []

    class Conn:
        automated, kind = True, "fake"

        def deploy(self, b):
            deploys.append(b.renewal_id)
            return {"token": 1}
    eng.connector = lambda ep: Conn()
    stale = s.renewal(rid)                 # both replicas read the row while it is 'issued'
    ep = s.endpoint(eid)
    eng._step_issued(stale, ep, None)      # replica A claims and deploys
    eng._step_issued(stale, ep, None)      # replica B acts on its stale read: claim fails
    assert deploys == [rid] and s.renewal(rid)["state"] == "verifying"
    eng._fail(stale, ep, "late failure from stale replica")   # cannot overwrite A's outcome
    assert s.renewal(rid)["state"] == "verifying"


# ---- leader election ------------------------------------------------------------------------
def test_leader_election_on_sqlite(tmp_path):
    a = Engine(tmp_path, issuers={"default": {"kind": "local"}})
    b = Engine(tmp_path, issuers={"default": {"kind": "local"}})
    ra = a.tick(scan=False)
    rb = b.tick(scan=False)
    assert ra["leader"] is True and "skipped" not in ra
    assert rb == {"planned": 0, "states": {}, "leader": False, "skipped": "follower"}
    assert a.status()["leader"] and not b.status()["leader"] and a.status()["lease"] == "file"

    assert a.shutdown(timeout=5) is True             # graceful stop releases the lease
    assert a.tick(scan=False)["skipped"] == "shutting down"
    assert b.tick(scan=False)["leader"] is True      # follower takes over on its next cycle
    assert b.status()["leader"]


def test_shutdown_waits_for_running_tick(tmp_path):
    eng = Engine(tmp_path, issuers={"default": {"kind": "local"}})
    started, release = threading.Event(), threading.Event()
    real = eng._tick

    def slow(*a, **k):
        started.set()
        release.wait(5)
        return real(*a, **k)
    eng._tick = slow
    t = threading.Thread(target=eng.tick, kwargs={"scan": False})
    t.start()
    started.wait(5)
    assert eng.shutdown(timeout=0.1) is False         # tick still running
    release.set()
    t.join(5)
    assert eng.shutdown(timeout=5) is True and not eng.lease.is_leader


def test_file_lease_is_exclusive(tmp_path):
    a, b = FileLease(tmp_path / "l"), FileLease(tmp_path / "l")
    assert a.try_acquire() and a.try_acquire() and not b.try_acquire()
    a.release()
    assert b.try_acquire() and not a.try_acquire()
    b.release()


def test_postgres_lease_detects_lost_connection(tmp_path, fake):
    lease = PostgresLease(make_dialect("postgresql://farrier@db/farrier", tmp_path))
    assert lease.try_acquire() and lease.is_leader
    assert "pg_try_advisory_lock(%s)" in fake[0].sql()
    fake[0].fail_next = True                           # the leader's session drops
    assert lease.try_acquire() is True                 # reconnected and won again (nobody else held it)
    assert fake[0].closed and len(fake) == 2
    busy = FakeConn()
    busy.select_value = 0                              # another replica holds it by now
    lease.dialect.connect = lambda: busy
    fake[1].fail_next = True
    assert lease.try_acquire() is False and not lease.is_leader
    lease.release()


# ---- real Postgres (opt-in) -------------------------------------------------------------------
PG = os.environ.get("FARRIER_TEST_POSTGRES_URL")


@pytest.mark.skipif(not PG, reason="set FARRIER_TEST_POSTGRES_URL to run against a real PostgreSQL")
def test_real_postgres(tmp_path):
    s = Store(tmp_path, url=PG)
    for t in ("events", "renewals", "observations", "endpoints"):
        s.x(f"DELETE FROM {t}")
    assert Store(tmp_path, url=PG).migrated == []
    eid = _endpoint(s)
    assert s.endpoint(eid)["window"] == {"days": ["mon"]}
    assert s.endpoint_by_addr("127.0.0.1", 1, "a.test")["id"] == eid
    rid = s.create_renewal(eid, now_iso(), None, None, "due")
    assert s.open_renewal(eid)["id"] == rid and s.endpoints()[0]["name"] == "a.test"
    assert s.update_renewal(rid, expect_state="planned", state="issued")
    assert not s.update_renewal(rid, expect_state="planned", state="issued")
    a, b = s.leader_lease(), Store(tmp_path, url=PG).leader_lease()
    assert a.try_acquire() and not b.try_acquire()
    a.release()
    assert b.try_acquire()
    b.release()


def test_only_one_open_renewal_per_endpoint_even_when_racing(tmp_path):
    a, b = Store(tmp_path), Store(tmp_path)          # two replicas, one database
    eid = _endpoint(a, "race")
    first = a.create_renewal(eid, now_iso(), None, None, "replica a")
    second = b.create_renewal(eid, now_iso(), None, None, "replica b")
    assert first == second
    assert len(a.q("SELECT id FROM renewals WHERE endpoint_id=?", (eid,))) == 1
    # once finished, the slot frees and a new renewal can open
    assert a.update_renewal(first, expect_state="planned", state="cancelled")
    third = b.create_renewal(eid, now_iso(), None, None, "next")
    assert third != first and a.renewal(third)["state"] == "planned"
