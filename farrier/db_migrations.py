"""Versioned schema migrations.

``schema_version`` records each applied migration. ``apply(store)`` runs the missing ones in
order, under a cross-replica lock (SQLite: an immediate transaction; Postgres: a transaction-scoped
advisory lock; MySQL: GET_LOCK), so several replicas starting at once apply each migration exactly
once. Migration 1 uses CREATE TABLE IF NOT EXISTS, so a SQLite file from before versioning is
adopted in place.

To change the schema, append a migration; never edit one that has shipped.
"""
from __future__ import annotations

from collections.abc import Callable

from .db_dialects import Dialect, lock_key


def _m1_initial(d: Dialect) -> list[str]:
    s = d.table_suffix
    return [
        f"""CREATE TABLE IF NOT EXISTS endpoints (
  id {d.pk},
  name {d.key} NOT NULL UNIQUE,
  host {d.key} NOT NULL,
  port {d.int_} NOT NULL DEFAULT 443,
  sni {d.key},
  common_name {d.text},
  sans {d.text_default('[]')},
  key_type {d.key_default('ec256')},
  connector {d.key_default('manual')},
  connector_config {d.text_default('{}')},
  issuer {d.key_default('default')},
  window {d.text_default('{}')},
  lead_days {d.int_} NOT NULL DEFAULT 0,
  owner {d.key},
  tags {d.text_default('[]')},
  enabled {d.int_} NOT NULL DEFAULT 1,
  created_at {d.key} NOT NULL
){s}""",
        f"""CREATE TABLE IF NOT EXISTS observations (
  id {d.pk},
  endpoint_id {d.ref} NOT NULL,
  observed_at {d.key} NOT NULL,
  fingerprint {d.key},
  subject_cn {d.text},
  sans {d.text},
  issuer {d.text},
  not_before {d.key},
  not_after {d.key},
  key_type {d.key},
  error {d.text},
  FOREIGN KEY (endpoint_id) REFERENCES endpoints(id) ON DELETE CASCADE
){s}""",
        d.create_index("obs_ep", "observations", "endpoint_id, observed_at"),
        f"""CREATE TABLE IF NOT EXISTS renewals (
  id {d.pk},
  endpoint_id {d.ref} NOT NULL,
  state {d.key} NOT NULL,
  reason {d.text},
  scheduled_for {d.key} NOT NULL,
  deadline {d.key},
  prev_fingerprint {d.key},
  new_fingerprint {d.key},
  key_sealed {d.text},
  csr_pem {d.text},
  cert_pem {d.text},
  chain_pem {d.text},
  not_after {d.key},
  rollback {d.text},
  ticket_ref {d.key},
  attempts {d.int_} NOT NULL DEFAULT 0,
  error {d.text},
  created_at {d.key} NOT NULL,
  updated_at {d.key} NOT NULL,
  FOREIGN KEY (endpoint_id) REFERENCES endpoints(id) ON DELETE CASCADE
){s}""",
        d.create_index("ren_state", "renewals", "state, scheduled_for"),
        f"""CREATE TABLE IF NOT EXISTS events (
  id {d.pk},
  at {d.key} NOT NULL,
  endpoint_id {d.ref},
  renewal_id {d.ref},
  level {d.key} NOT NULL DEFAULT 'info',
  message {d.text} NOT NULL
){s}""",
    ]


def _m2_lookup_indexes(d: Dialect) -> list[str]:
    """Per-endpoint lookups (open_renewal, the events feed) without a table scan."""
    return [d.create_index("ren_ep", "renewals", "endpoint_id, state"),
            d.create_index("ev_ep", "events", "endpoint_id, id")]


def _m3_one_open_renewal(d: Dialect) -> list[str]:
    """At most one open renewal per endpoint, enforced by the database so two replicas can't both
    open one. ``open_slot`` holds the endpoint id while the renewal is open and NULL once it is
    finished; a unique index allows any number of NULLs on SQLite, Postgres and MySQL alike."""
    open_states = "'planned','issued','deploying','verifying','awaiting_manual'"
    return [f"ALTER TABLE renewals ADD COLUMN open_slot {d.int_} NULL",
            # adopt the newest open renewal per endpoint (older duplicates, if any, stay unslotted)
            f"""UPDATE renewals SET open_slot = endpoint_id WHERE id IN (
                  SELECT m FROM (SELECT MAX(id) AS m FROM renewals WHERE state IN ({open_states})
                                 GROUP BY endpoint_id) AS latest)""",
            d.create_index("ren_open_slot", "renewals", "open_slot", unique=True)]


MIGRATIONS: list[tuple[int, str, Callable[[Dialect], list[str]]]] = [
    (1, "initial schema", _m1_initial),
    (2, "lookup indexes", _m2_lookup_indexes),
    (3, "one open renewal per endpoint", _m3_one_open_renewal),
]


def _ensure_version_table(store) -> None:
    d = store.dialect
    store._run(f"CREATE TABLE IF NOT EXISTS schema_version (version {d.int_} NOT NULL PRIMARY KEY, "
               f"name {d.key} NOT NULL, applied_at {d.key} NOT NULL){d.table_suffix}", ())


def current_version(store) -> int:
    row = store._run("SELECT MAX(version) AS v FROM schema_version", (), fetch=True)
    return (row[0]["v"] if row else None) or 0


def apply(store) -> list[int]:
    """Bring the schema up to date. Returns the versions applied (empty when already current)."""
    from .db import now_iso
    d = store.dialect
    applied: list[int] = []
    with store._lock:
        if d.name == "mysql":  # DDL is not transactional in MySQL: serialise with a named lock
            store._run("SELECT GET_LOCK('farrier-migrate', 120) AS ok", (), fetch=True)
        try:
            with store.transaction():
                if d.name == "postgresql":
                    store._run("SELECT pg_advisory_xact_lock(?)", (lock_key("farrier-migrate"),), fetch=True)
                _ensure_version_table(store)
                have = current_version(store)
                for version, name, build in MIGRATIONS:
                    if version <= have:
                        continue
                    for stmt in build(d):
                        store._run(stmt, ())
                    store._run("INSERT INTO schema_version(version, name, applied_at) VALUES (?,?,?)",
                               (version, name, now_iso()))
                    applied.append(version)
        finally:
            if d.name == "mysql":
                store._run("SELECT RELEASE_LOCK('farrier-migrate') AS ok", (), fetch=True)
    return applied


def latest_version() -> int:
    return MIGRATIONS[-1][0]
