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

from farrier.db.dialects import Dialect, lock_key


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


def _m4_ui_config(d: Dialect) -> list[str]:
    """Configuration edited in the dashboard, shared by every replica.

    secrets        index of vault:NAME -> (backend, external reference); see farrier.secret_backends
    secret_values  the local backend's values, sealed under the master key
    config_items   issuers, DNS accounts, notifiers and alert rules (JSON body, no secret values)
    config_version one row; bumped on every change so other replicas reload on their next tick
    alert_state    when each (rule, subject) last fired, for the cooldown (survives restarts and failover)
    health_results the last health grade per endpoint, for health alert rules
    """
    s = d.table_suffix
    return [
        # the index: which backend holds each vault:NAME and under what reference (never a value)
        f"""CREATE TABLE secrets (
  name {d.key} NOT NULL PRIMARY KEY,
  backend {d.key} NOT NULL,
  ref {d.text} NOT NULL,
  created_at {d.key} NOT NULL,
  updated_at {d.key} NOT NULL
){s}""",
        # the "local" backend's storage: values sealed under the master key
        f"""CREATE TABLE secret_values (
  ref {d.key} NOT NULL PRIMARY KEY,
  value_sealed {d.text} NOT NULL
){s}""",
        f"""CREATE TABLE config_items (
  kind {d.key} NOT NULL,
  name {d.key} NOT NULL,
  body {d.text} NOT NULL,
  updated_at {d.key} NOT NULL,
  updated_by {d.key},
  PRIMARY KEY (kind, name)
){s}""",
        f"CREATE TABLE config_version (id {d.int_} NOT NULL PRIMARY KEY, version {d.int_} NOT NULL){s}",
        "INSERT INTO config_version(id, version) VALUES (1, 0)",
        f"""CREATE TABLE alert_state (
  rule {d.key} NOT NULL,
  subject {d.key} NOT NULL,
  fired_at {d.key} NOT NULL,
  PRIMARY KEY (rule, subject)
){s}""",
        f"""CREATE TABLE health_results (
  endpoint_id {d.ref} NOT NULL PRIMARY KEY,
  grade {d.key} NOT NULL,
  checked_at {d.key} NOT NULL
){s}""",
    ]


def _m5_certificates_and_crypto(d: Dialect) -> list[str]:
    """Served certificates (PEM, once per fingerprint) and agentless cryptographic discovery.

    certificates   leaf PEM and the chain the server sent, keyed by the observation fingerprint
                   (observations reference it by fingerprint; older observations simply have no row)
    crypto_assets  one row per probed TLS target with its latest probe result (JSON) and PQC status
    crypto_scans   every probe result, for history
    """
    s = d.table_suffix
    return [
        f"""CREATE TABLE certificates (
  id {d.pk},
  fingerprint {d.key} NOT NULL,
  cert_pem {d.text} NOT NULL,
  chain_pem {d.text},
  first_seen {d.key} NOT NULL
){s}""",
        d.create_index("cert_fp", "certificates", "fingerprint", unique=True),
        f"""CREATE TABLE crypto_assets (
  id {d.pk},
  kind {d.key} NOT NULL,
  target {d.key} NOT NULL,
  host {d.key} NOT NULL,
  port {d.int_} NOT NULL,
  sni {d.key},
  status {d.key} NOT NULL,
  result {d.text} NOT NULL,
  observed_at {d.key} NOT NULL,
  created_at {d.key} NOT NULL
){s}""",
        d.create_index("ca_target", "crypto_assets", "kind, target", unique=True),
        f"""CREATE TABLE crypto_scans (
  id {d.pk},
  asset_id {d.ref} NOT NULL,
  observed_at {d.key} NOT NULL,
  status {d.key} NOT NULL,
  result {d.text} NOT NULL,
  FOREIGN KEY (asset_id) REFERENCES crypto_assets(id) ON DELETE CASCADE
){s}""",
        d.create_index("cs_asset", "crypto_scans", "asset_id, id"),
    ]


def _m6_ssh(d: Dialect) -> list[str]:
    """Agentless SSH inventory (farrier.ssh).

    ssh_hosts        latest unauthenticated probe per host:port (banner, algorithms, host keys, findings)
    ssh_host_pins    host keys Farrier trusts per host:port (TOFU or explicitly trusted); a different key
                     on a later contact is an error, never silently accepted
    ssh_keys         authorized_keys entries found by collection; uid identifies host/user/file/line
    ssh_runs         when the periodic scan and collection last ran (survives leader failover)
    """
    s = d.table_suffix
    return [
        f"""CREATE TABLE ssh_hosts (
  id {d.pk},
  host {d.key} NOT NULL,
  port {d.int_} NOT NULL,
  banner {d.text},
  data {d.text} NOT NULL,
  pqc_kex {d.int_} NOT NULL DEFAULT 0,
  error {d.text},
  observed_at {d.key} NOT NULL
){s}""",
        d.create_index("ssh_host_addr", "ssh_hosts", "host, port", unique=True),
        f"""CREATE TABLE ssh_host_pins (
  host {d.key} NOT NULL,
  port {d.int_} NOT NULL,
  key_type {d.key} NOT NULL,
  key_b64 {d.text} NOT NULL,
  fingerprint {d.key} NOT NULL,
  source {d.key} NOT NULL,
  pinned_at {d.key} NOT NULL,
  PRIMARY KEY (host, port, key_type)
){s}""",
        f"""CREATE TABLE ssh_keys (
  id {d.pk},
  uid {d.key} NOT NULL,
  host {d.key} NOT NULL,
  port {d.int_} NOT NULL,
  access {d.key} NOT NULL,
  username {d.key} NOT NULL,
  path {d.text} NOT NULL,
  line_sha256 {d.key} NOT NULL,
  data {d.text} NOT NULL,
  fingerprint {d.key} NOT NULL,
  first_seen {d.key} NOT NULL,
  last_seen {d.key} NOT NULL
){s}""",
        d.create_index("ssh_key_uid", "ssh_keys", "uid", unique=True),
        d.create_index("ssh_key_host", "ssh_keys", "host, port"),
        d.create_index("ssh_key_fp", "ssh_keys", "fingerprint"),
        f"CREATE TABLE ssh_runs (kind {d.key} NOT NULL PRIMARY KEY, last_run_at {d.key} NOT NULL){s}",
    ]


def _m7_itsm_tickets(d: Dialect) -> list[str]:
    """Tickets Farrier opened in ServiceNow / Jira (farrier.itsm.tickets): one per (channel, renewal),
    enforced by a unique index so two replicas never open two. ``state`` is opening | open | closed |
    error; ``last_event`` is the renewal state the ticket was last brought up to date with."""
    s = d.table_suffix
    return [
        f"""CREATE TABLE itsm_tickets (
  id {d.pk},
  channel {d.key} NOT NULL,
  renewal_id {d.ref} NOT NULL,
  kind {d.key} NOT NULL,
  product {d.key} NOT NULL,
  ref {d.key},
  ext_id {d.key},
  tbl {d.key},
  url {d.text},
  state {d.key} NOT NULL,
  last_event {d.key},
  attempts {d.int_} NOT NULL DEFAULT 0,
  error {d.text},
  created_at {d.key} NOT NULL,
  updated_at {d.key} NOT NULL,
  FOREIGN KEY (renewal_id) REFERENCES renewals(id) ON DELETE CASCADE
){s}""",
        d.create_index("itsm_ticket_one", "itsm_tickets", "channel, renewal_id", unique=True),
        d.create_index("itsm_ticket_state", "itsm_tickets", "state"),
    ]


MIGRATIONS: list[tuple[int, str, Callable[[Dialect], list[str]]]] = [
    (1, "initial schema", _m1_initial),
    (2, "lookup indexes", _m2_lookup_indexes),
    (3, "one open renewal per endpoint", _m3_one_open_renewal),
    (4, "dashboard configuration, secrets and alert state", _m4_ui_config),
    (5, "served certificates and cryptographic discovery", _m5_certificates_and_crypto),
    (6, "agentless SSH inventory", _m6_ssh),
    (7, "ITSM tickets", _m7_itsm_tickets),
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
    from farrier.db.store import now_iso
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
