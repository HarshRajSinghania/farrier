"""Database backends for the Store: SQLite (default), PostgreSQL and MySQL/MariaDB.

The rest of Farrier writes SQLite-flavoured SQL (``?`` placeholders, ``IFNULL``, plain ``INSERT``
followed by "lastrowid"). Each backend translates that to its own dialect, so ``Store``'s public
API stays the same whichever database sits underneath.

Selecting a backend: ``FARRIER_DATABASE_URL``

    (unset)                                   SQLite file <data_dir>/farrier.db
    sqlite:///path/to/farrier.db              SQLite file elsewhere
    postgresql://farrier@db.internal:5432/farrier?sslmode=verify-full&sslrootcert=/etc/ssl/db-ca.pem
    mysql://farrier@db.internal:3306/farrier?sslmode=verify-full&sslrootcert=/etc/ssl/db-ca.pem

Passwords never sit in the URL in clear text. Either:
  * ``FARRIER_DATABASE_PASSWORD`` (a literal, or an ``env:NAME`` / ``file:/path`` reference), or
  * a reference in the URL's password slot or ``password=`` query parameter:
    ``postgresql://farrier:env:PGPASSWORD@db/farrier`` or ``...?password=file:/run/secrets/db``.
References are resolved with ``farrier.vault.resolve_secret``. A literal password in the URL is refused.

TLS options (both servers): ``sslmode`` = disable | prefer | require | verify-ca | verify-full,
``sslrootcert`` (CA bundle), ``sslcert`` / ``sslkey`` (client certificate). Use ``verify-full`` in
production: the server certificate must chain to ``sslrootcert`` and match the host name.
"""
from __future__ import annotations

import hashlib
import os
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit

# Tables whose INSERTs have no ``id`` column to hand back (Postgres needs RETURNING id otherwise).
NO_ID_TABLES = {"schema_version", "secrets", "secret_values", "config_items", "config_version", "alert_state",
                "health_results"}
# Column names that are reserved words in Postgres and/or MySQL 8 and must be quoted there.
RESERVED_IDENTIFIERS = {"window"}

_TOKEN = re.compile(r"""('(?:[^']|'')*')|("(?:[^"]|"")*")|(`[^`]*`)|(\?)|(%)|([A-Za-z_][A-Za-z0-9_]*)""")


def redact_url(url: str) -> str:
    """The URL with any password (literal or reference) removed, safe for logs and status pages."""
    if not url or "://" not in url:
        return url or "sqlite (data dir)"
    parts = urlsplit(url)
    netloc = parts.netloc
    if "@" in netloc:
        userinfo, host = netloc.rsplit("@", 1)
        user = userinfo.split(":", 1)[0]
        netloc = f"{user}:***@{host}" if ":" in userinfo else f"{user}@{host}"
    query = "&".join(f"{k}=***" if k.lower() == "password" else f"{k}={v}"
                     for k, v in parse_qsl(parts.query, keep_blank_values=True))
    return f"{parts.scheme}://{netloc}{parts.path}" + (f"?{query}" if query else "")


@dataclass
class DatabaseURL:
    scheme: str                     # sqlite | postgresql | mysql
    host: str = ""
    port: int | None = None
    user: str | None = None
    database: str = ""
    path: str = ""                  # sqlite file
    password_ref: str | None = None
    options: dict = field(default_factory=dict)

    @property
    def password(self) -> str | None:
        """Resolved lazily, at connect time, so it is never stored on the Store or printed."""
        from .vault import resolve_secret
        ref = self.password_ref or os.environ.get("FARRIER_DATABASE_PASSWORD")
        return None if ref is None else resolve_secret(ref)


def parse_url(url: str | None, data_dir: Path) -> DatabaseURL:
    if not url:
        return DatabaseURL("sqlite", path=str(Path(data_dir) / "farrier.db"))
    parts = urlsplit(url)
    scheme = parts.scheme.split("+", 1)[0].lower()
    if scheme == "sqlite":
        # sqlite:///relative.db and sqlite:////abs/path.db ; on Windows sqlite:///C:/x/farrier.db
        p = unquote(url.split("://", 1)[1].split("?", 1)[0])
        p = p.removeprefix("/")
        return DatabaseURL("sqlite", path=p or str(Path(data_dir) / "farrier.db"))
    if scheme in ("postgres", "postgresql", "pgsql"):
        scheme = "postgresql"
    elif scheme in ("mysql", "mariadb"):
        scheme = "mysql"
    else:
        raise ValueError(f"unsupported FARRIER_DATABASE_URL scheme {parts.scheme!r} "
                         "(use postgresql://, mysql:// or sqlite:///)")
    opts = dict(parse_qsl(parts.query, keep_blank_values=True))
    pw = opts.pop("password", None)
    netloc = parts.netloc
    user = None
    if "@" in netloc:
        userinfo, _ = netloc.rsplit("@", 1)
        if ":" in userinfo:
            user, url_pw = userinfo.split(":", 1)
            pw = pw or unquote(url_pw)
        else:
            user = userinfo
        user = unquote(user)
    if pw is not None and not pw.startswith(("env:", "file:")):
        raise ValueError("refusing a literal password in FARRIER_DATABASE_URL; set FARRIER_DATABASE_PASSWORD "
                         "or use an env:NAME / file:/path reference")
    return DatabaseURL(scheme, host=parts.hostname or "localhost", port=parts.port, user=user,
                       database=parts.path.lstrip("/"), password_ref=pw, options=opts)


def lock_key(name: str) -> int:
    """A stable signed 64-bit key for pg advisory locks."""
    return int.from_bytes(hashlib.sha256(name.encode()).digest()[:8], "big", signed=True)


class Dialect:
    """SQLite: the reference dialect, nothing to translate."""
    name = "sqlite"
    param = "?"
    quote = '"'
    disconnect_errors: tuple = ()

    def __init__(self, url: DatabaseURL):
        self.url = url

    # ---- DDL vocabulary ------------------------------------------------------
    pk = "INTEGER PRIMARY KEY"
    ref = "INTEGER"                 # a foreign key column referencing a pk
    int_ = "INTEGER"
    text = "TEXT"                   # free text (PEMs, messages)
    key = "TEXT"                    # text that is indexed or unique
    table_suffix = ""
    index_if_not_exists = True

    def text_default(self, value: str) -> str:
        return f"TEXT NOT NULL DEFAULT '{value}'"

    def key_default(self, value: str) -> str:
        return f"{self.key} NOT NULL DEFAULT '{value}'"

    def create_index(self, name: str, table: str, cols: str, unique: bool = False) -> str:
        u = "UNIQUE " if unique else ""
        ine = "IF NOT EXISTS " if self.index_if_not_exists else ""
        return f"CREATE {u}INDEX {ine}{name} ON {table}({cols})"

    # ---- statements ------------------------------------------------------------
    def translate(self, sql: str) -> str:
        if self.name == "sqlite":
            return sql

        def sub(m: re.Match) -> str:
            lit, dq, bq, qmark, pct, word = m.groups()
            if lit is not None:
                return lit.replace("%", "%%")
            if dq is not None:
                return self.quote + dq[1:-1] + self.quote
            if bq is not None:
                return bq
            if qmark is not None:
                return self.param
            if pct is not None:
                return "%%"
            return self.word(word, m)

        return _TOKEN.sub(sub, sql)

    def word(self, word: str, m: re.Match) -> str:
        if word.lower() in RESERVED_IDENTIFIERS:
            return f"{self.quote}{word}{self.quote}"
        return word

    def adapt(self, args) -> tuple:
        """Booleans are stored as 0/1 integers everywhere (SQLite has no boolean type)."""
        return tuple(int(a) if isinstance(a, bool) else a for a in (args or ()))

    def insert_returning(self, sql: str) -> bool:
        return False

    # ---- connections -------------------------------------------------------------
    def connect(self):
        Path(self.url.path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.url.path, check_same_thread=False, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def begin(self, conn) -> None:
        conn.execute("BEGIN IMMEDIATE")

    def commit(self, conn) -> None:
        conn.commit()

    def rollback(self, conn) -> None:
        conn.rollback()

    def autocommit_after(self, conn) -> None:
        """Commit a single statement (SQLite opens implicit transactions; servers run in autocommit)."""
        conn.commit()

    def fix_sequence(self, store, table: str) -> None:
        pass


class PostgresDialect(Dialect):
    name = "postgresql"
    param = "%s"
    quote = '"'
    pk = "BIGSERIAL PRIMARY KEY"
    ref = "BIGINT"
    int_ = "INTEGER"
    text = "TEXT"
    key = "TEXT"

    @property
    def disconnect_errors(self):
        try:
            import psycopg
            return (psycopg.OperationalError, psycopg.InterfaceError)
        except ImportError:
            return ()

    def word(self, word, m):
        if word.upper() == "IFNULL":
            return "COALESCE"
        return super().word(word, m)

    def insert_returning(self, sql: str) -> bool:
        m = re.match(r"\s*INSERT\s+INTO\s+([A-Za-z_]\w*)", sql, re.IGNORECASE)
        return bool(m) and m.group(1).lower() not in NO_ID_TABLES and not re.search(r"\bRETURNING\b", sql, re.IGNORECASE)

    def connect_kwargs(self) -> dict:
        u = self.url
        kw = {"host": u.host, "dbname": u.database, "autocommit": True, "connect_timeout": 10,
              # notice a dead peer fast, so a dropped leader's advisory lock is freed within a cycle
              "keepalives": 1, "keepalives_idle": 10, "keepalives_interval": 5, "keepalives_count": 3,
              "application_name": "farrier"}
        if u.port:
            kw["port"] = u.port
        if u.user:
            kw["user"] = u.user
        pw = u.password
        if pw is not None:
            kw["password"] = pw
        for k in ("sslmode", "sslrootcert", "sslcert", "sslkey", "sslcrl", "target_session_attrs",
                  "connect_timeout", "options"):
            if k in u.options:
                kw[k] = u.options[k]
        return kw

    def connect(self):
        try:
            import psycopg
        except ImportError as e:  # pragma: no cover - depends on extras
            raise RuntimeError("PostgreSQL support needs the driver: pip install 'farrier-tls[postgres]'") from e
        return psycopg.connect(**self.connect_kwargs())

    def begin(self, conn):
        conn.execute("BEGIN")

    def commit(self, conn):
        conn.execute("COMMIT")

    def rollback(self, conn):
        conn.execute("ROLLBACK")

    def autocommit_after(self, conn):
        pass

    def fix_sequence(self, store, table):
        store._run(f"SELECT setval(pg_get_serial_sequence('{table}', 'id'), "
                   f"COALESCE((SELECT MAX(id) FROM {table}), 0) + 1, false)", (), fetch=True)


class MySQLDialect(Dialect):
    name = "mysql"
    param = "%s"
    quote = "`"
    pk = "BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY"
    ref = "BIGINT"
    int_ = "INTEGER"
    text = "MEDIUMTEXT"             # TEXT tops out at 64 KiB; a long chain or event can exceed it
    key = "VARCHAR(255)"            # InnoDB cannot index TEXT without a prefix length
    table_suffix = " ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
    index_if_not_exists = False     # MySQL 8 has no CREATE INDEX IF NOT EXISTS; versioning guards it

    @property
    def disconnect_errors(self):
        try:
            import pymysql
            return (pymysql.err.OperationalError, pymysql.err.InterfaceError)
        except ImportError:
            return ()

    def text_default(self, value):
        # TEXT/BLOB defaults must be expressions (MySQL 8.0.13+, MariaDB 10.2+)
        return f"MEDIUMTEXT NOT NULL DEFAULT ('{value}')"

    def connect_kwargs(self) -> dict:
        u = self.url
        kw = {"host": u.host, "port": u.port or 3306, "database": u.database, "autocommit": True,
              "charset": "utf8mb4", "connect_timeout": 10,
              # rowcount = rows matched, not rows changed, so compare-and-set sees its hit
              "client_flag": 2}  # pymysql.constants.CLIENT.FOUND_ROWS
        if u.user:
            kw["user"] = u.user
        pw = u.password
        if pw is not None:
            kw["password"] = pw
        mode = u.options.get("sslmode") or u.options.get("ssl-mode") or u.options.get("ssl_mode")
        mode = (mode or "").lower().replace("_", "-")
        if mode and mode != "disable":
            ssl = {}
            if u.options.get("sslrootcert"):
                ssl["ca"] = u.options["sslrootcert"]
            if u.options.get("sslcert"):
                ssl["cert"] = u.options["sslcert"]
            if u.options.get("sslkey"):
                ssl["key"] = u.options["sslkey"]
            kw["ssl"] = ssl or {"ca": None}
            kw["ssl_verify_cert"] = mode in ("verify-ca", "verify-full", "verify-identity")
            kw["ssl_verify_identity"] = mode in ("verify-full", "verify-identity")
        return kw

    def connect(self):
        try:
            import pymysql
        except ImportError as e:  # pragma: no cover - depends on extras
            raise RuntimeError("MySQL support needs the driver: pip install 'farrier-tls[mysql]'") from e
        return pymysql.connect(**self.connect_kwargs())

    def begin(self, conn):
        conn.cursor().execute("START TRANSACTION")

    def commit(self, conn):
        conn.cursor().execute("COMMIT")

    def rollback(self, conn):
        conn.cursor().execute("ROLLBACK")

    def autocommit_after(self, conn):
        pass


def make_dialect(url: str | None, data_dir: Path) -> Dialect:
    u = parse_url(url, data_dir)
    return {"sqlite": Dialect, "postgresql": PostgresDialect, "mysql": MySQLDialect}[u.scheme](u)
