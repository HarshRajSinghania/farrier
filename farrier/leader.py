"""Leader election: only one replica runs the renewal loop at a time.

A lease is held for as long as its holder lives (it is not renewed on a timer):

  * PostgreSQL: ``pg_try_advisory_lock(key)`` on a dedicated connection. The lock belongs to the
    session, so if the leader dies or its connection drops the server frees it and the next replica
    to try (at its next tick) wins. TCP keepalives on that connection make a silent drop visible in
    well under a minute. Do not route this connection through a transaction-pooling PgBouncer.
  * MySQL / MariaDB: ``GET_LOCK(name, 0)`` on a dedicated connection; same session semantics.
  * SQLite: an exclusive, non-blocking lock on ``<data_dir>/leader.lock``.

Every ``try_acquire()`` on a holder re-checks that it still holds the lock (the session is alive and
the lock is still its own) and reports ``False`` if it was lost, so a replica that lost its database
connection stops leading before its next cycle. ``FARRIER_LEADER_KEY`` namespaces the lock when
several independent Farrier deployments share one database server.
"""
from __future__ import annotations

import logging
import os
import socket
import threading
from pathlib import Path

from .db_dialects import lock_key

log = logging.getLogger("farrier.leader")


def replica_id() -> str:
    return os.environ.get("FARRIER_REPLICA_ID") or f"{socket.gethostname()}:{os.getpid()}"


def lock_name() -> str:
    return "farrier-leader:" + os.environ.get("FARRIER_LEADER_KEY", "default")


class Lease:
    """Base lease; also the 'always leader' lease used when election is turned off."""
    kind = "none"

    def __init__(self):
        self._held = False
        self._mu = threading.RLock()

    @property
    def is_leader(self) -> bool:
        return self._held

    def try_acquire(self) -> bool:
        self._held = True
        return True

    def release(self) -> None:
        self._held = False

    def __enter__(self):
        return self.try_acquire()

    def __exit__(self, *exc):
        self.release()


class FileLease(Lease):
    kind = "file"

    def __init__(self, path: Path):
        super().__init__()
        self.path = Path(path)
        self._fh = None

    def try_acquire(self) -> bool:
        with self._mu:
            if self._fh is not None:
                return True
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fh = open(self.path, "a+b")
            try:
                fh.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                fh.close()
                return False
            self._fh, self._held = fh, True
            return True

    def release(self) -> None:
        with self._mu:
            fh, self._fh, self._held = self._fh, None, False
            if fh is None:
                return
            try:
                fh.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            finally:
                fh.close()

    def __del__(self):
        try:
            self.release()
        except Exception:  # noqa: BLE001
            pass


class SessionLease(Lease):
    """A lock tied to a dedicated database session (Postgres advisory lock / MySQL GET_LOCK)."""

    def __init__(self, dialect):
        super().__init__()
        self.dialect = dialect
        self.conn = None

    # subclasses: SQL returning a single truthy/falsy value
    acquire_sql = check_sql = release_sql = ""
    args: tuple = ()

    def _one(self, sql: str):
        cur = self.conn.cursor()
        cur.execute(sql, self.args if "%s" in sql else None)
        row = cur.fetchone()
        return row[0] if row else None

    def _drop(self):
        conn, self.conn, self._held = self.conn, None, False
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass

    def try_acquire(self) -> bool:
        with self._mu:
            if self._held:
                try:
                    if self._one(self.check_sql):
                        return True
                    log.warning("leader lock no longer held by this session")
                except Exception as e:  # noqa: BLE001 - connection dropped: the server has freed the lock
                    log.warning("leader connection lost: %s", type(e).__name__)
                self._drop()
            try:
                if self.conn is None:
                    self.conn = self.dialect.connect()
                self._held = bool(self._one(self.acquire_sql))
            except Exception as e:  # noqa: BLE001
                log.warning("leader election failed: %s", type(e).__name__)
                self._drop()
            return self._held

    def release(self) -> None:
        with self._mu:
            if self._held and self.conn is not None:
                try:
                    self._one(self.release_sql)
                except Exception:  # noqa: BLE001
                    pass
            self._drop()


class PostgresLease(SessionLease):
    kind = "postgres-advisory-lock"
    acquire_sql = "SELECT pg_try_advisory_lock(%s)"
    # the dedicated session takes no other advisory locks, so any granted one is the leader lock
    check_sql = ("SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND granted "
                 "AND pid = pg_backend_pid())")
    release_sql = "SELECT pg_advisory_unlock(%s)"

    def __init__(self, dialect):
        super().__init__(dialect)
        self.args = (lock_key(lock_name()),)


class MySQLLease(SessionLease):
    kind = "mysql-get-lock"
    acquire_sql = "SELECT GET_LOCK(%s, 0)"
    check_sql = "SELECT IS_USED_LOCK(%s) = CONNECTION_ID()"
    release_sql = "SELECT RELEASE_LOCK(%s)"

    def __init__(self, dialect):
        super().__init__(dialect)
        self.args = (lock_name()[:64],)


def make_lease(dialect, data_dir: Path) -> Lease:
    if os.environ.get("FARRIER_LEADER_ELECTION", "on").lower() in ("off", "0", "false", "no"):
        return Lease()
    if dialect.name == "postgresql":
        return PostgresLease(dialect)
    if dialect.name == "mysql":
        return MySQLLease(dialect)
    return FileLease(Path(data_dir) / "leader.lock")
