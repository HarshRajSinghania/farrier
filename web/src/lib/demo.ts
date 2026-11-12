/**
 * Demo mode: an in-memory stand-in for the Farrier API, used when FARRIER_API_URL
 * is not set (e.g. a Vercel preview of the marketing site). It mirrors the
 * shapes and state machine of farrier/engine.py closely enough to exercise every
 * dashboard screen. Nothing here touches a real CA or device.
 */
import "server-only";
import { forecastTimeline, maxLifetimeDays, dcvReuseDays, renewBeforeDays, SCHEDULE } from "./policy";
import type {
  AlertRule,
  AlertWhen,
  CatalogField,
  DnsAccount,
  IntegrationCatalog,
  Issuer,
  NotifierChannel,
  SecretInfo,
  TestResult,
  EngineSettings,
  FarrierConfig,
  HealthReport,
  ZombieReport,
  ConnectorInfo,
  Endpoint,
  EndpointInput,
  FarrierEvent,
  Renewal,
  RenewalState,
  Summary,
} from "./types";
import { OPEN_STATES } from "./types";

const DAY = 86_400_000;
const AUTOMATED = new Set(["files", "keystore", "f5", "fortigate", "panos"]);

export const CONNECTORS: ConnectorInfo[] = [
  { kind: "files", automated: true, required: ["cert_path", "key_path"], doc: "nginx, HAProxy, Apache, Postfix — atomic write + backup, test_command, reload_command; local or over SSH." },
  { kind: "keystore", automated: true, required: ["path", "password"], doc: "Tomcat, Jetty, Kafka, Elasticsearch, vendor Java apps — PKCS#12 keystore plus restart." },
  { kind: "f5", automated: true, required: ["url", "username", "password", "profile"], doc: "BIG-IP LTM client-ssl profiles via iControl REST: upload, install new objects, repoint certKeyChain, save." },
  { kind: "fortigate", automated: true, required: ["url", "api_token"], doc: "FortiGate SSL-VPN, admin GUI or any cmdb certificate reference via FortiOS REST import + bind." },
  { kind: "panos", automated: true, required: ["url", "api_key"], doc: "Palo Alto firewalls and GlobalProtect via XML API keypair import, profile update and commit." },
  { kind: "manual", automated: false, required: [], doc: "ASA, Citrix ADC, IIS, vCenter, anything else — change pack (PEM + PFX + runbook) and optional ServiceNow/Jira ticket; closes itself on detection." },
];

// [name, host, port, connector, owner, lifetime, days left]
const SEED: [string, string, number, string, string, number, number][] = [
  ["www-lb", "www.acme.internal", 443, "f5", "platform", 200, 61],
  ["api-lb", "api.acme.internal", 443, "f5", "platform", 200, 44],
  ["checkout-lb", "checkout.acme.internal", 443, "f5", "payments", 200, 118],
  ["partner-lb", "partners.acme.internal", 443, "f5", "platform", 200, 12],
  ["vpn-fgt", "vpn.acme.com", 443, "fortigate", "network", 200, 23],
  ["vpn-fgt-dr", "vpn-dr.acme.com", 443, "fortigate", "network", 200, 150],
  ["fgt-admin", "fw01-mgmt.acme.internal", 8443, "fortigate", "network", 200, 87],
  ["gp-portal", "gp.acme.com", 443, "panos", "network", 200, 33],
  ["gp-gateway-eu", "gp-eu.acme.com", 443, "panos", "network", 200, 96],
  ["pa-mgmt", "pa01-mgmt.acme.internal", 443, "panos", "network", 200, 5],
  ["jira", "jira.acme.internal", 8443, "keystore", "apps", 200, 71],
  ["confluence", "wiki.acme.internal", 8443, "keystore", "apps", 200, 54],
  ["kafka-broker-1", "kafka1.acme.internal", 9093, "keystore", "data", 200, 128],
  ["kafka-broker-2", "kafka2.acme.internal", 9093, "keystore", "data", 200, 128],
  ["elastic", "search.acme.internal", 9200, "keystore", "data", 200, 19],
  ["nexus", "nexus.acme.internal", 8443, "keystore", "devex", 200, 160],
  ["nginx-edge-1", "edge1.acme.com", 443, "files", "platform", 200, 39],
  ["nginx-edge-2", "edge2.acme.com", 443, "files", "platform", 200, 39],
  ["haproxy-int", "lb-int.acme.internal", 443, "files", "platform", 200, 81],
  ["grafana", "grafana.acme.internal", 443, "files", "sre", 200, 102],
  ["postfix-mx", "mx1.acme.com", 465, "files", "it", 200, 9],
  ["gitlab", "git.acme.internal", 443, "files", "devex", 200, 140],
  ["vault", "vault.acme.internal", 8200, "files", "security", 200, 66],
  ["harbor", "registry.acme.internal", 443, "files", "devex", 200, 27],
  ["asa-dc1", "remote.acme.com", 443, "manual", "network", 200, 15],
  ["asa-dc2", "remote2.acme.com", 443, "manual", "network", 200, 74],
  ["citrix-adc", "apps.acme.com", 443, "manual", "euc", 200, 31],
  ["citrix-storefront", "store.acme.com", 443, "manual", "euc", 200, 58],
  ["iis-intranet", "intranet.acme.internal", 443, "manual", "it", 200, 3],
  ["iis-adfs", "sts.acme.com", 443, "manual", "identity", 200, 47],
  ["vcenter-01", "vc01.acme.internal", 443, "manual", "infra", 200, 99],
  ["vcenter-02", "vc02.acme.internal", 443, "manual", "infra", 200, 135],
  ["idrac-r740-07", "idrac07.acme.internal", 443, "manual", "infra", 398, -4],
  ["printer-hq", "print.acme.internal", 443, "manual", "it", 398, 210],
  ["nas-backup", "nas01.acme.internal", 5001, "manual", "infra", 200, 68],
  ["ups-mgmt", "ups01.acme.internal", 443, "manual", "facilities", 398, 26],
  ["sap-gw", "sap.acme.internal", 44300, "manual", "erp", 200, 52],
  ["moveit", "transfer.acme.com", 443, "manual", "security", 200, 110],
  ["wlc-01", "wlc01.acme.internal", 443, "manual", "network", 200, 20],
  ["ilo-db-02", "ilo-db02.acme.internal", 443, "manual", "infra", 398, 175],
  ["badge-system", "access.acme.internal", 8443, "manual", "facilities", 398, null as unknown as number],
];

interface DemoStore {
  endpoints: Endpoint[];
  renewals: Renewal[];
  events: FarrierEvent[];
  nextId: { endpoint: number; renewal: number; event: number };
}

const g = globalThis as unknown as { __farrierDemo?: DemoStore };

function rng(seed: number) {
  return () => {
    seed = (seed * 1664525 + 1013904223) % 4294967296;
    return seed / 4294967296;
  };
}

function fingerprint(r: () => number) {
  return Array.from({ length: 32 }, () => Math.floor(r() * 256).toString(16).padStart(2, "0")).join(":").toUpperCase();
}

const isoAt = (ms: number) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "+00:00");

function build(): DemoStore {
  const now = Date.now();
  const r = rng(7);
  const store: DemoStore = { endpoints: [], renewals: [], events: [], nextId: { endpoint: 1, renewal: 1, event: 1 } };

  for (const [name, host, port, connector, owner, lifetime, left] of SEED) {
    const id = store.nextId.endpoint++;
    const hasCert = left !== null;
    const notAfter = hasCert ? now + left * DAY - Math.floor(r() * 8) * 3_600_000 : null;
    const window =
      connector === "manual" || connector === "fortigate" || connector === "panos"
        ? { days: [["sat"], ["sun"], ["tue", "thu"]][id % 3], start: ["02:00", "01:00", "22:00"][id % 3], hours: 3 }
        : {};
    store.endpoints.push({
      id,
      name,
      host,
      port,
      sni: host,
      common_name: host,
      sans: [],
      key_type: id % 4 === 0 ? "rsa2048" : "ec256",
      connector,
      issuer: connector === "manual" && id % 2 ? "private-ca" : "le",
      window,
      lead_days: connector === "manual" ? 10 : 0,
      owner,
      tags: [],
      enabled: 1,
      created_at: isoAt(now - 120 * DAY),
      fingerprint: hasCert ? fingerprint(r) : null,
      not_after: notAfter ? isoAt(notAfter) : null,
      not_before: notAfter ? isoAt(notAfter - lifetime * DAY) : null,
      cert_issuer: hasCert ? (connector === "manual" && id % 2 ? "CN=Acme Internal CA" : "CN=R11,O=Let's Encrypt,C=US") : null,
      subject_cn: hasCert ? host : null,
      observed_at: isoAt(now - Math.floor(r() * 290) * 1000),
      scan_error: hasCert ? null : "connection timed out after 5s",
      automated: AUTOMATED.has(connector),
      days_left: null,
    });
  }

  // A realistic mix of renewal history and in-flight work.
  const mk = (name: string, state: RenewalState, offsetDays: number, extra: Partial<Renewal> = {}) => {
    const ep = store.endpoints.find((e) => e.name === name)!;
    const id = store.nextId.renewal++;
    const sched = now + offsetDays * DAY;
    store.renewals.push({
      id,
      endpoint_id: ep.id,
      state,
      reason: "due: one-third of lifetime remaining",
      scheduled_for: isoAt(sched),
      deadline: ep.not_after,
      prev_fingerprint: ep.fingerprint,
      new_fingerprint: state === "done" || state === "verifying" ? fingerprint(r) : null,
      not_after: state === "done" ? isoAt(now + 199 * DAY) : null,
      ticket_ref: ep.connector === "manual" && state === "awaiting_manual" ? `CHG00${41200 + id}` : null,
      attempts: state === "verifying" ? 1 : 0,
      error: null,
      created_at: isoAt(sched - DAY),
      updated_at: isoAt(Math.min(now, sched + 3_600_000)),
      name: ep.name,
      connector: ep.connector,
      host: ep.host,
      port: ep.port,
      ...extra,
    });
    return id;
  };

  mk("pa-mgmt", "verifying", 0);
  mk("partner-lb", "issued", 0);
  mk("postfix-mx", "planned", 1);
  mk("iis-intranet", "awaiting_manual", -2);
  mk("asa-dc1", "awaiting_manual", -1);
  mk("wlc-01", "planned", 2);
  mk("elastic", "planned", 3);
  mk("vpn-fgt", "planned", 6);
  mk("idrac-r740-07", "failed", -6, { error: "change ticket expired without the new certificate going live" });
  mk("harbor", "rolled_back", -3, { error: "new cert never went live (serving 3f2a…); rolled back" });
  mk("grafana", "done", -12);
  mk("nginx-edge-1", "done", -20);
  mk("nginx-edge-2", "done", -20);
  mk("checkout-lb", "done", -30);
  mk("kafka-broker-1", "done", -31);
  mk("kafka-broker-2", "done", -31);
  mk("vpn-fgt-dr", "done", -48);
  mk("vcenter-02", "done", -64);
  mk("nexus", "done", -70);
  mk("gitlab", "superseded", -58);

  const log = (msg: string, name: string | null, level = "info", ago = 0) => {
    const ep = name ? store.endpoints.find((e) => e.name === name) : undefined;
    store.events.push({
      id: store.nextId.event++,
      at: isoAt(now - ago * 60_000),
      endpoint_id: ep?.id ?? null,
      renewal_id: null,
      level,
      message: msg,
      name: ep?.name ?? null,
    });
  };
  log("issued via ACME DNS-01 (le), deployed to /Common/clientssl_www", "checkout-lb", "info", 43_200);
  log("verified: handshake shows new fingerprint", "grafana", "info", 17_280);
  log("change pack ready, ticket CHG0041206 opened", "asa-dc1", "info", 1_440);
  log("change pack ready, ticket CHG0041205 opened", "iis-intranet", "info", 2_880);
  log("new cert never went live; rolled back to previous certkey", "harbor", "error", 4_320);
  log("ticket expired without the new certificate going live", "idrac-r740-07", "error", 8_640);
  log("scan: connection timed out after 5s", "badge-system", "warning", 6);
  log("issued via ACME DNS-01 (le)", "partner-lb", "info", 18);
  log("deployed: keypair imported, profile gp-portal-tls updated, commit job 4471", "pa-mgmt", "info", 9);
  log("verifying: attempt 1 of 3, still serving previous certificate", "pa-mgmt", "info", 4);
  log("tick: 41 endpoints observed, 1 planned", null, "info", 2);
  return store;
}

function db(): DemoStore {
  g.__farrierDemo ??= build();
  return g.__farrierDemo;
}

function withDaysLeft(e: Endpoint, now: number): Endpoint {
  return { ...e, days_left: e.not_after ? Math.round(((Date.parse(e.not_after) - now) / DAY) * 10) / 10 : null };
}

function log(message: string, ep?: Endpoint, renewalId: number | null = null, level = "info") {
  const s = db();
  s.events.push({
    id: s.nextId.event++,
    at: isoAt(Date.now()),
    endpoint_id: ep?.id ?? null,
    renewal_id: renewalId,
    level,
    message,
    name: ep?.name ?? null,
  });
}

/* ---------------------------------------------------------------- queries */

export function summary(): Summary {
  const s = db();
  const now = Date.now();
  const today = new Date(now).toISOString().slice(0, 10);
  const eps = s.endpoints;
  const expiry: Record<string, number> = {};
  for (const e of eps) {
    if (!e.not_after) {
      expiry.unknown = (expiry.unknown ?? 0) + 1;
      continue;
    }
    const d = Math.floor((Date.parse(e.not_after) - now) / DAY);
    const b = d < 0 ? "expired" : d < 7 ? "7d" : d < 30 ? "30d" : d < 90 ? "90d" : "later";
    expiry[b] = (expiry[b] ?? 0) + 1;
  }
  const auto = eps.filter((e) => e.automated).length;
  const states: Record<string, number> = {};
  for (const r of s.renewals) states[r.state] = (states[r.state] ?? 0) + 1;
  const byConnector: Record<string, number> = {};
  for (const e of eps) byConnector[e.connector] = (byConnector[e.connector] ?? 0) + 1;

  const cal = new Map<string, Summary["calendar"][number]>();
  for (let i = 0; i < 90; i++) {
    const date = new Date(now + i * DAY).toISOString().slice(0, 10);
    cal.set(date, { date, auto: 0, manual: 0, projected_auto: 0, projected_manual: 0 });
  }
  const openEps = new Set<number>();
  for (const r of s.renewals) {
    if (!OPEN_STATES.includes(r.state)) continue;
    openEps.add(r.endpoint_id);
    const day = r.scheduled_for.slice(0, 10) < today ? today : r.scheduled_for.slice(0, 10);
    const c = cal.get(day);
    if (c) c[AUTOMATED.has(r.connector) ? "auto" : "manual"]++;
  }
  for (const e of eps) {
    if (openEps.has(e.id) || !e.not_after || !e.not_before || !e.enabled) continue;
    const na = Date.parse(e.not_after);
    const life = Math.min(Math.max(1, Math.round((na - Date.parse(e.not_before)) / DAY)), maxLifetimeDays(today));
    const due = new Date(na - renewBeforeDays(life, e.lead_days) * DAY).toISOString().slice(0, 10);
    const c = cal.get(due < today ? today : due);
    if (c) c[e.automated ? "projected_auto" : "projected_manual"]++;
  }

  return {
    now: isoAt(now),
    policy: {
      max_lifetime_days: maxLifetimeDays(today),
      dcv_reuse_days: dcvReuseDays(today),
      schedule: SCHEDULE.map(([from, days, dcv]) => ({ from, days, dcv })),
    },
    endpoints: eps.length,
    automated: auto,
    manual: eps.length - auto,
    by_connector: byConnector,
    expiry,
    renewal_states: states,
    awaiting_manual: states.awaiting_manual ?? 0,
    attention: (states.failed ?? 0) + (states.rolled_back ?? 0),
    forecast: forecastTimeline(Math.max(eps.length, 1), eps.length ? (eps.length - auto) / eps.length : 0),
    calendar: [...cal.values()],
  };
}

export function endpoints(): Endpoint[] {
  const now = Date.now();
  return [...db().endpoints]
    .sort((a, b) => (a.not_after ?? "9999").localeCompare(b.not_after ?? "9999"))
    .map((e) => withDaysLeft(e, now));
}

export function renewals(states?: string[]): Renewal[] {
  return db()
    .renewals.filter((r) => !states || states.includes(r.state))
    .sort((a, b) => a.scheduled_for.localeCompare(b.scheduled_for));
}

export function events(limit = 100, endpointId?: number): FarrierEvent[] {
  return db()
    .events.filter((e) => !endpointId || e.endpoint_id === endpointId)
    .sort((a, b) => b.id - a.id)
    .slice(0, limit);
}

/* -------------------------------------------------------------- configuration */

const demoSettings: EngineSettings = {
  horizon_days: 14, safety_days: 2, manual_daily_cap: 25, auto_daily_cap: 1000, verify_max_attempts: 6,
  scan_timeout: 5, verify_chain_and_names: true, verify_all_addresses: false,
};
const LIMITS: FarrierConfig["limits"] = {
  horizon_days: { min: 1, max: 60, type: "int" }, safety_days: { min: 0, max: 30, type: "int" },
  manual_daily_cap: { min: 0, max: 10000, type: "int" }, auto_daily_cap: { min: 1, max: 100000, type: "int" },
  verify_max_attempts: { min: 1, max: 50, type: "int" }, scan_timeout: { min: 1, max: 60, type: "float" },
  verify_chain_and_names: { min: 0, max: 1, type: "bool" }, verify_all_addresses: { min: 0, max: 1, type: "bool" },
};

export function config(): FarrierConfig {
  return {
    settings: { ...demoSettings },
    limits: LIMITS,
    ...integrationConfig(),
    issuers_error: null,
    dns_error: null,
    engine: { backend: "sqlite", leader: true, replica: "demo", schema_version: 3, data_dir: "(demo)", mcp_writes: false },
  };
}

/** The same rules as farrier/config.py, so the demo rejects what the engine would. */
export function saveSettings(changes: Record<string, unknown>) {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(changes)) {
    const lim = LIMITS[k as keyof EngineSettings];
    if (!lim) throw new DemoError(400, `${k} can't be changed here`);
    if (lim.type === "bool" ? typeof v !== "boolean" : typeof v !== "number" || v < lim.min || v > lim.max || (lim.type === "int" && !Number.isInteger(v)))
      throw new DemoError(400, lim.type === "bool" ? `${k} must be true or false` : `${k} must be between ${lim.min} and ${lim.max}`);
    out[k] = v;
  }
  Object.assign(demoSettings, out);
  return { changed: out };
}

/** Zombie findings from the demo estate (farrier/zombie.py, stored-observation kinds only). */
export function zombies(): ZombieReport {
  const now = Date.now();
  const findings: ZombieReport["findings"] = [];
  for (const e of endpoints())
    if (e.days_left !== null && e.days_left < 0)
      findings.push({ kind: "expired_served", severity: "critical", endpoint_id: e.id, endpoint: e.name, target: `${e.host}:${e.port}`,
        action: "Renew now, or disable the endpoint if it is retired." });
  for (const r of db().renewals)
    if (r.state === "awaiting_manual" && r.deadline && Date.parse(r.deadline) < now + 3 * DAY) {
      const e = db().endpoints.find((x) => x.id === r.endpoint_id);
      findings.push({ kind: "pack_never_installed", severity: "warning", endpoint_id: r.endpoint_id, endpoint: e?.name ?? null,
        target: e ? `${e.host}:${e.port}` : "", action: "Install the change pack, or chase its ticket." });
    }
  return { generated_at: isoAt(now), count: findings.length, findings };
}

/** A health report card for one demo endpoint (farrier/health.py check ids). */
export function health(id: number): HealthReport {
  const e = endpoints().find((x) => x.id === id);
  if (!e) throw new DemoError(404, "not found");
  const expired = e.days_left !== null && e.days_left < 0;
  const soon = e.days_left !== null && e.days_left < 14;
  const checks: HealthReport["checks"] = [
    { id: "connect", status: "pass", detail: "TLSv1.3" },
    { id: "chain", status: "pass", detail: `complete and trusted: ${e.name} -> ${e.issuer ?? "issuer"}` },
    { id: "hostname", status: "pass", detail: `${e.name} covered by SANs` },
    { id: "expiry", status: expired ? "fail" : soon ? "warn" : "pass",
      detail: e.days_left === null ? "no certificate seen" : expired ? `expired ${Math.abs(e.days_left)} days ago` : `${e.days_left} days left` },
    { id: "key", status: "pass", detail: "ECDSA P-256" },
    { id: "signature", status: "pass", detail: "ecdsa-with-SHA256" },
    { id: "tls_versions", status: "pass", detail: "TLS 1.2 and 1.3 only" },
    { id: "ocsp_stapling", status: "warn", detail: "no stapled OCSP response" },
  ];
  const summary = { pass: 0, warn: 0, fail: 0 };
  for (const c of checks) summary[c.status]++;
  return { endpoint: e.name, grade: summary.fail ? "F" : summary.warn > 1 ? "B" : "A", checked_at: isoAt(Date.now()), summary, checks };
}

/* -------------------------------------------------------------- mutations */

/** One step of the renewal state machine (farrier/engine.py `advance`). */
export function advance(id: number): RenewalState {
  const s = db();
  const r = s.renewals.find((x) => x.id === id);
  if (!r) throw new DemoError(404, "not found");
  const ep = s.endpoints.find((e) => e.id === r.endpoint_id)!;
  const now = Date.now();
  const set = (state: RenewalState, msg: string, level = "info") => {
    r.state = state;
    r.updated_at = isoAt(now);
    log(msg, ep, r.id, level);
  };
  switch (r.state) {
    case "planned":
      if (Date.parse(r.scheduled_for) > now) break;
      r.new_fingerprint = fingerprint(rng(now % 9973));
      set("issued", `issued via ACME DNS-01 (${ep.issuer})`);
      break;
    case "issued":
      if (ep.automated) {
        r.attempts = 0;
        set("verifying", `deployed via ${ep.connector}; switched over, rollback recorded`);
      } else {
        r.ticket_ref = `CHG00${41300 + r.id}`;
        set("awaiting_manual", `change pack ready, ticket ${r.ticket_ref} opened`);
      }
      break;
    case "verifying":
    case "awaiting_manual":
      if (ep.automated || r.attempts >= 1) {
        ep.fingerprint = r.new_fingerprint;
        const life = maxLifetimeDays(new Date(now));
        ep.not_before = isoAt(now);
        ep.not_after = isoAt(now + life * DAY);
        ep.observed_at = isoAt(now);
        r.not_after = ep.not_after;
        set("done", "verified: handshake shows new fingerprint");
      } else {
        r.attempts++;
        r.updated_at = isoAt(now);
      }
      break;
  }
  return r.state;
}

export function forceRenewal(endpointId: number) {
  const s = db();
  const ep = s.endpoints.find((e) => e.id === endpointId);
  if (!ep) throw new DemoError(404, "not found");
  const open = s.renewals.find((r) => r.endpoint_id === ep.id && OPEN_STATES.includes(r.state));
  if (open) return { renewal_id: open.id, state: advance(open.id) };
  const now = Date.now();
  const id = s.nextId.renewal++;
  s.renewals.push({
    id,
    endpoint_id: ep.id,
    state: "planned",
    reason: "requested from dashboard",
    scheduled_for: isoAt(now),
    deadline: ep.not_after,
    prev_fingerprint: ep.fingerprint,
    new_fingerprint: null,
    not_after: null,
    ticket_ref: null,
    attempts: 0,
    error: null,
    created_at: isoAt(now),
    updated_at: isoAt(now),
    name: ep.name,
    connector: ep.connector,
    host: ep.host,
    port: ep.port,
  });
  log("renewal requested from dashboard", ep, id);
  return { renewal_id: id, state: advance(id) };
}

export function cancel(id: number) {
  const r = db().renewals.find((x) => x.id === id);
  if (!r || !OPEN_STATES.includes(r.state)) throw new DemoError(400, "renewal is not open");
  r.state = "cancelled";
  r.updated_at = isoAt(Date.now());
  log("cancelled from dashboard", db().endpoints.find((e) => e.id === r.endpoint_id), id);
  return { state: "cancelled" };
}

export function tick() {
  const open = db().renewals.filter((r) => OPEN_STATES.includes(r.state));
  const states: Record<string, number> = {};
  for (const r of open) {
    const st = advance(r.id);
    states[st] = (states[st] ?? 0) + 1;
  }
  log(`tick: ${db().endpoints.length} endpoints observed`);
  return { planned: 0, states };
}

export function addEndpoint(input: EndpointInput) {
  const s = db();
  if (!input.name || !input.host) throw new DemoError(400, "name and host are required");
  if (s.endpoints.some((e) => e.name === input.name)) throw new DemoError(400, `endpoint ${input.name} already exists`);
  const id = s.nextId.endpoint++;
  const connector = input.connector ?? "manual";
  s.endpoints.push({
    id,
    name: input.name,
    host: input.host,
    port: input.port ?? 443,
    sni: input.sni ?? null,
    common_name: input.common_name ?? input.host,
    sans: input.sans ?? [],
    key_type: input.key_type ?? "ec256",
    connector,
    issuer: input.issuer ?? "default",
    window: input.window ?? {},
    lead_days: input.lead_days ?? 0,
    owner: input.owner ?? null,
    tags: input.tags ?? [],
    enabled: 1,
    created_at: isoAt(Date.now()),
    fingerprint: null,
    not_after: null,
    not_before: null,
    cert_issuer: null,
    subject_cn: null,
    observed_at: isoAt(Date.now()),
    scan_error: "demo mode: endpoint is not scanned",
    automated: AUTOMATED.has(connector),
    days_left: null,
  });
  log("endpoint registered", s.endpoints.at(-1));
  return { id };
}

export function deleteEndpoint(id: number) {
  const s = db();
  s.endpoints = s.endpoints.filter((e) => e.id !== id);
  s.renewals = s.renewals.filter((r) => r.endpoint_id !== id);
  return { ok: true };
}

export function discover(targets: string) {
  const parts = targets.split(/[\s,]+/).filter(Boolean);
  if (!parts.length) throw new DemoError(400, "no targets");
  const scanned = parts.reduce((n, p) => {
    const m = p.match(/\/(\d+)/);
    return n + (m ? 2 ** (32 - Math.min(32, Math.max(20, Number(m[1])))) : 1);
  }, 0);
  log(`discovery: scanned ${scanned} targets (demo mode, nothing contacted)`);
  return { new: 0, seen: Math.min(scanned, db().endpoints.length), scanned, with_tls: Math.min(scanned, db().endpoints.length) };
}

export function runbook(id: number) {
  const r = db().renewals.find((x) => x.id === id);
  if (!r) throw new DemoError(404, "not found");
  return {
    markdown: `# Renewal ${r.id}: ${r.name}\n\n1. Download the change pack (fullchain.pem, key.pem, bundle.pfx).\n2. Import the certificate on **${r.host}** under a new name.\n3. Bind it to the TLS service on port ${r.port}.\n4. Leave the old certificate in place until Farrier reports the renewal as done.\n\nFarrier closes this renewal and the ticket by itself once a handshake shows the new fingerprint.`,
  };
}

export class DemoError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

/* ------------------------------------------------------------ integrations */
// The same shapes and refusals as the engine's integration routes, in memory.

const fld = (key: string, label: string, opts: Partial<CatalogField> = {}): CatalogField => ({
  key, label, secret: false, required: true, help: null, ...opts,
});
const secretFld = (key: string, label: string, opts: Partial<CatalogField> = {}) => fld(key, label, { secret: true, ...opts });
const optionalFld = (key: string, label: string, help?: string) => fld(key, label, { required: false, help: help ?? null });

export const CATALOG: IntegrationCatalog = {
  dns_providers: [
    { id: "cloudflare", label: "Cloudflare", fields: [secretFld("api_token", "API token", { help: "A token with Zone:Read and DNS:Edit on the zones below." })] },
    { id: "route53", label: "Amazon Route 53", fields: [
      secretFld("access_key_id", "Access key ID", { required: false, help: "Leave both keys empty to use the instance or pod role." }),
      secretFld("secret_access_key", "Secret access key", { required: false }),
      optionalFld("region", "Region", "Defaults to us-east-1."),
      optionalFld("hosted_zone_id", "Hosted zone ID", "Skips the zone lookup when set."),
    ] },
    { id: "azure", label: "Azure DNS", fields: [
      fld("tenant_id", "Tenant ID"), fld("client_id", "Client ID"), secretFld("client_secret", "Client secret"),
      fld("subscription_id", "Subscription ID"), fld("resource_group", "Resource group"),
    ] },
    { id: "gcloud", label: "Google Cloud DNS", fields: [
      fld("project", "Project ID"),
      secretFld("service_account_json", "Service account key (JSON)", { required: false, help: "Leave empty to use workload identity." }),
    ] },
    { id: "digitalocean", label: "DigitalOcean", fields: [secretFld("auth_token", "API token")] },
    { id: "godaddy", label: "GoDaddy", fields: [secretFld("api_key", "API key"), secretFld("api_secret", "API secret")] },
    { id: "hetzner", label: "Hetzner DNS", fields: [secretFld("api_token", "API token")] },
    { id: "namecheap", label: "Namecheap", fields: [
      fld("api_user", "API user"), secretFld("api_key", "API key"),
      fld("client_ip", "Allowed client IP", { help: "The engine's public IP, allow-listed in Namecheap." }),
    ] },
    { id: "ovh", label: "OVHcloud", fields: [
      fld("endpoint", "Endpoint", { help: "ovh-eu, ovh-ca or ovh-us." }), fld("application_key", "Application key"),
      secretFld("application_secret", "Application secret"), secretFld("consumer_key", "Consumer key"),
    ] },
    { id: "porkbun", label: "Porkbun", fields: [secretFld("api_key", "API key"), secretFld("secret_api_key", "Secret API key")] },
    { id: "scaleway", label: "Scaleway", fields: [secretFld("secret_key", "Secret key"), optionalFld("project_id", "Project ID")] },
    { id: "vultr", label: "Vultr", fields: [secretFld("api_key", "API key")] },
    { id: "edgedns", label: "Akamai Edge DNS", fields: [
      fld("host", "API host"), secretFld("client_token", "Client token"), secretFld("client_secret", "Client secret"),
      secretFld("access_token", "Access token"),
    ] },
    { id: "infomaniak", label: "Infomaniak", fields: [secretFld("access_token", "Access token")] },
    { id: "linode", label: "Akamai Cloud (Linode)", fields: [secretFld("token", "Personal access token")] },
    { id: "gandi", label: "Gandi", fields: [secretFld("personal_access_token", "Personal access token")] },
    { id: "powerdns", label: "PowerDNS", fields: [
      fld("api_url", "API URL"), secretFld("api_key", "API key"), optionalFld("server_id", "Server ID", "Defaults to localhost."),
    ] },
    { id: "rfc2136", label: "RFC 2136 (BIND, Windows DNS)", fields: [
      fld("nameserver", "Nameserver", { help: "host:port of the primary." }), fld("tsig_key", "TSIG key name"),
      secretFld("tsig_secret", "TSIG secret"), optionalFld("tsig_algorithm", "TSIG algorithm", "Defaults to hmac-sha256."),
    ] },
  ],
  ca_presets: [
    { id: "letsencrypt", label: "Let's Encrypt", eab: false, needs_directory_url: false, staging: false },
    { id: "letsencrypt-staging", label: "Let's Encrypt (staging)", eab: false, needs_directory_url: false, staging: true },
    { id: "zerossl", label: "ZeroSSL", eab: true, needs_directory_url: false, staging: false },
    { id: "google", label: "Google Trust Services", eab: true, needs_directory_url: false, staging: false },
    { id: "google-staging", label: "Google Trust Services (staging)", eab: true, needs_directory_url: false, staging: true },
    { id: "buypass", label: "Buypass", eab: false, needs_directory_url: false, staging: false },
    { id: "sslcom", label: "SSL.com", eab: true, needs_directory_url: false, staging: false },
    { id: "digicert", label: "DigiCert", eab: true, needs_directory_url: false, staging: false },
    { id: "sectigo", label: "Sectigo", eab: true, needs_directory_url: true, staging: false },
    { id: "local_ca", label: "Built-in private CA", eab: false, needs_directory_url: false, staging: false },
  ],
  notifier_types: [
    { id: "slack", label: "Slack", fields: [
      secretFld("webhook_url", "Incoming webhook URL"),
      optionalFld("channel", "Channel", "Shown in the list; the webhook decides where it posts."),
    ] },
    { id: "teams", label: "Microsoft Teams", fields: [secretFld("webhook_url", "Workflow webhook URL")] },
    { id: "webhook", label: "Webhook", fields: [
      fld("url", "URL", { help: "Receives a JSON POST per alert." }),
      secretFld("hmac_secret", "Signing secret", { required: false, help: "Signs each body with HMAC-SHA256 in X-Farrier-Signature." }),
    ] },
    { id: "email", label: "Email (SMTP)", fields: [
      fld("host", "SMTP host"), optionalFld("port", "Port", "587 with STARTTLS by default."), optionalFld("username", "Username"),
      secretFld("password", "Password", { required: false }), fld("from", "From address"), fld("to", "To", { help: "Comma-separated addresses." }),
    ] },
    { id: "ses", label: "Amazon SES", fields: [
      fld("region", "Region"), fld("from", "From address"), fld("to", "To", { help: "Comma-separated addresses." }),
      secretFld("access_key_id", "Access key ID", { required: false, help: "Leave both keys empty to use the instance or pod role." }),
      secretFld("secret_access_key", "Secret access key", { required: false }),
    ] },
  ],
  alert_rule_types: [
    { id: "expiring", label: "Certificate expiring" },
    { id: "event", label: "Renewal event" },
    { id: "health", label: "Health grade drops" },
    { id: "zombie", label: "Zombie certificate found" },
    { id: "unreachable", label: "Endpoint unreachable" },
  ],
};

const DIRECTORY: Record<string, string> = {
  letsencrypt: "https://acme-v02.api.letsencrypt.org/directory",
  "letsencrypt-staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
  zerossl: "https://acme.zerossl.com/v2/DV90",
  google: "https://dv.acme-v02.api.pki.goog/directory",
  "google-staging": "https://dv.acme-v02.test-api.pki.goog/directory",
  buypass: "https://api.buypass.com/acme/directory",
  sslcom: "https://acme.ssl.com/sslcom-dv-ecc",
  digicert: "https://acme.digicert.com/v2/acme/directory/",
};
const ALERT_EVENTS = ["failed", "rolled_back", "awaiting_manual", "done", "issued"];
const PROFILES = ["classic", "tlsserver", "shortlived"];
const GRADES = ["A", "B", "C", "D"];

interface StoredSecret extends Omit<SecretInfo, "used_by"> {
  value: string;
}
type StoredNotifier = { name: string; source: "file" | "ui"; type: string; events: string[]; fields: Record<string, string> };
interface IntegrationStore {
  secrets: StoredSecret[];
  issuers: Issuer[];
  dns: DnsAccount[];
  notifiers: StoredNotifier[];
  rules: AlertRule[];
}

const gi = globalThis as unknown as { __farrierIntegrations?: IntegrationStore };

function seedIntegrations(): IntegrationStore {
  const now = Date.now();
  return {
    secrets: [
      { name: "dns-cf-prod-api_token", value: "demo", created_at: isoAt(now - 40 * DAY), updated_at: isoAt(now - 40 * DAY) },
      { name: "notifier-ops-slack-webhook_url", value: "demo", created_at: isoAt(now - 30 * DAY), updated_at: isoAt(now - 30 * DAY) },
    ],
    issuers: [
      { name: "default", source: "file", type: "local_ca", preset: "local_ca", directory_url: null, email: null, dns: null,
        profile: null, preferred_chain: null, eab_kid: null, eab_hmac_key: null },
      { name: "letsencrypt", source: "ui", type: "acme", preset: "letsencrypt", directory_url: DIRECTORY.letsencrypt,
        email: "pki@example.com", dns: "auto", profile: "tlsserver", preferred_chain: null, eab_kid: null, eab_hmac_key: null },
    ],
    dns: [
      { name: "cf-prod", source: "ui", provider: "cloudflare", zones: ["example.com"],
        credentials: { api_token: "vault:dns-cf-prod-api_token" }, options: {} },
    ],
    notifiers: [
      { name: "ops-slack", source: "ui", type: "slack", events: ["failed", "rolled_back", "awaiting_manual"],
        fields: { webhook_url: "vault:notifier-ops-slack-webhook_url", channel: "#pki-ops" } },
    ],
    rules: [
      { name: "expiring-21d", enabled: true, when: { type: "expiring", days: 21 }, filter: null, channels: ["ops-slack"],
        cooldown_hours: 24, last_fired_at: isoAt(now - 2 * DAY) },
      { name: "renewal-failed", enabled: true, when: { type: "event", events: ["failed", "rolled_back"] }, filter: null,
        channels: ["ops-slack"], cooldown_hours: 0, last_fired_at: isoAt(now - 3 * DAY) },
    ],
  };
}

function ix(): IntegrationStore {
  gi.__farrierIntegrations ??= seedIntegrations();
  return gi.__farrierIntegrations;
}

const NAME = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const REF = /^(vault:[A-Za-z0-9][A-Za-z0-9_-]{0,127}|env:[A-Za-z_][A-Za-z0-9_]*|file:\/.+)$/;
const INLINE = "Use a stored secret or an env:/file: reference";

function checkName(name: string, what: string) {
  if (!NAME.test(name)) throw new DemoError(400, `${what} names use letters, digits, - and _ (up to 64)`);
}
const str = (v: unknown) => (typeof v === "string" ? v.trim() : typeof v === "number" ? String(v) : "");
const strList = (v: unknown) => (Array.isArray(v) ? v.map(str).filter(Boolean) : []);
const hostOf = (url: string | null) => {
  try {
    return url ? new URL(url).host : null;
  } catch {
    return url;
  }
};

/** A secret field's value must be a reference, and a vault reference must exist. */
function checkRef(v: unknown, field: string): string {
  const ref = str(v);
  if (!REF.test(ref)) throw new DemoError(400, `${field}: ${INLINE}`);
  if (ref.startsWith("vault:") && !ix().secrets.some((s) => s.name === ref.slice(6)))
    throw new DemoError(400, `${field}: no stored secret named ${ref.slice(6)}`);
  return ref;
}

function refuseFile(entry: { source: string; name: string } | undefined, file: string) {
  if (entry?.source === "file") throw new DemoError(409, `${entry.name} is managed in ${file}; edit the file to change it`);
}

/* secrets */

function refsByOwner(): [string, string[]][] {
  const s = ix();
  return [
    ...s.issuers.map((i): [string, string[]] => [`issuer:${i.name}`, [i.eab_hmac_key ?? ""]]),
    ...s.dns.map((d): [string, string[]] => [`dns:${d.name}`, Object.values(d.credentials).map((v) => v ?? "")]),
    ...s.notifiers.map((n): [string, string[]] => [`notifier:${n.name}`, Object.values(n.fields)]),
  ];
}

export function listSecrets(): SecretInfo[] {
  const owners = refsByOwner();
  return ix().secrets.map((s) => ({
    name: s.name,
    created_at: s.created_at,
    updated_at: s.updated_at,
    used_by: owners.filter(([, refs]) => refs.includes(`vault:${s.name}`)).map(([o]) => o),
  }));
}

export function putSecret(name: string, body: Record<string, unknown>) {
  checkName(name, "Secret");
  const value = typeof body.value === "string" ? body.value : "";
  if (!value.trim()) throw new DemoError(400, "value is required");
  if (value.length > 16_384) throw new DemoError(400, "value is too long");
  const now = isoAt(Date.now());
  const s = ix().secrets.find((x) => x.name === name);
  if (s) Object.assign(s, { value, updated_at: now });
  else ix().secrets.push({ name, value, created_at: now, updated_at: now });
  return { ok: true };
}

export function deleteSecret(name: string) {
  const s = listSecrets().find((x) => x.name === name);
  if (!s) throw new DemoError(404, `no secret named ${name}`);
  if (s.used_by.length) throw new DemoError(409, `${name} is in use by ${s.used_by.join(", ")}`);
  ix().secrets = ix().secrets.filter((x) => x.name !== name);
  return { ok: true };
}

/* issuers */

export const listIssuers = (): Issuer[] => ix().issuers.map((i) => ({ ...i }));

export function putIssuer(name: string, b: Record<string, unknown>) {
  checkName(name, "Issuer");
  const s = ix();
  const existing = s.issuers.find((i) => i.name === name);
  refuseFile(existing, "issuers.json");
  const presetId = str(b.preset);
  const preset = presetId ? CATALOG.ca_presets.find((p) => p.id === presetId) : undefined;
  if (presetId && !preset) throw new DemoError(400, `unknown preset ${presetId}`);
  const type = preset ? (preset.id === "local_ca" ? "local_ca" : "acme") : str(b.type);
  if (!["acme", "local_ca"].includes(type)) throw new DemoError(400, "choose a preset, or type acme with a directory_url");
  const out: Issuer = {
    name, source: "ui", type, preset: preset?.id ?? null, directory_url: null, email: null, dns: null,
    profile: null, preferred_chain: null, eab_kid: null, eab_hmac_key: null,
  };
  if (type === "acme") {
    const email = str(b.email);
    if (email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) throw new DemoError(400, "email is not a valid address");
    const dir = str(b.directory_url) || (preset ? DIRECTORY[preset.id] ?? "" : "");
    if (!/^https:\/\/\S+$/.test(dir)) throw new DemoError(400, "directory_url must be an https:// URL");
    const dns = str(b.dns) || "auto";
    if (dns !== "auto" && !s.dns.some((d) => d.name === dns)) throw new DemoError(400, `no DNS account named ${dns}`);
    const profile = str(b.profile);
    if (profile && !PROFILES.includes(profile)) throw new DemoError(400, `profile must be one of ${PROFILES.join(", ")}`);
    if (str(b.eab_hmac_key)) out.eab_hmac_key = checkRef(b.eab_hmac_key, "eab_hmac_key");
    out.eab_kid = str(b.eab_kid) || null;
    if (preset?.eab && (!out.eab_kid || !out.eab_hmac_key))
      throw new DemoError(400, `${preset.label} needs an EAB key ID and HMAC key from your CA account`);
    Object.assign(out, {
      email: email || null, directory_url: dir, dns, profile: profile || null, preferred_chain: str(b.preferred_chain) || null,
    });
  }
  if (existing) Object.assign(existing, out);
  else s.issuers.push(out);
  return out;
}

export function deleteIssuer(name: string) {
  const s = ix();
  const i = s.issuers.find((x) => x.name === name);
  if (!i) throw new DemoError(404, `no issuer named ${name}`);
  refuseFile(i, "issuers.json");
  const users = db().endpoints.filter((e) => e.issuer === name).map((e) => e.name);
  if (users.length) throw new DemoError(409, `${users.length} endpoint(s) use ${name}, including ${users.slice(0, 3).join(", ")}`);
  s.issuers = s.issuers.filter((x) => x.name !== name);
  return { ok: true };
}

export function testIssuer(name: string): TestResult {
  const i = ix().issuers.find((x) => x.name === name);
  if (!i) throw new DemoError(404, `no issuer named ${name}`);
  if (i.type === "local_ca") return { ok: true, detail: "Private CA key loaded; it signs certificates locally." };
  return {
    ok: true,
    detail: `Reached ${hostOf(i.directory_url) ?? "the directory"} and found the ACME account${i.email ? ` for ${i.email}` : ""} (demo: nothing contacted).`,
  };
}

/* DNS accounts */

export const listDns = (): DnsAccount[] => ix().dns.map((d) => ({ ...d, zones: [...d.zones] }));

export function putDns(name: string, b: Record<string, unknown>) {
  checkName(name, "DNS account");
  const s = ix();
  const existing = s.dns.find((d) => d.name === name);
  refuseFile(existing, "dns.json");
  const provider = CATALOG.dns_providers.find((p) => p.id === str(b.provider));
  if (!provider) throw new DemoError(400, `unknown provider ${str(b.provider) || "(none)"}`);
  const creds = (b.credentials ?? {}) as Record<string, unknown>;
  const opts = (b.options ?? {}) as Record<string, unknown>;
  const credentials: Record<string, string> = {};
  const options: Record<string, string> = {};
  for (const field of provider.fields) {
    const v = field.secret ? creds[field.key] : opts[field.key];
    if (!str(v)) {
      if (field.required) throw new DemoError(400, `${field.label} is required for ${provider.label}`);
      continue;
    }
    if (field.secret) credentials[field.key] = checkRef(v, field.key);
    else options[field.key] = str(v);
  }
  const zones = strList(b.zones).map((z) => z.toLowerCase());
  for (const z of zones) if (!/^([a-z0-9-]+\.)+[a-z]{2,}$/.test(z)) throw new DemoError(400, `${z} is not a DNS zone`);
  const out: DnsAccount = { name, source: "ui", provider: provider.id, zones, credentials, options };
  if (existing) Object.assign(existing, out);
  else s.dns.push(out);
  return out;
}

export function deleteDns(name: string) {
  const s = ix();
  const d = s.dns.find((x) => x.name === name);
  if (!d) throw new DemoError(404, `no DNS account named ${name}`);
  refuseFile(d, "dns.json");
  const users = s.issuers.filter((i) => i.dns === name).map((i) => i.name);
  if (users.length) throw new DemoError(409, `Issuer ${users.join(", ")} uses ${name}. Point it at another account first.`);
  s.dns = s.dns.filter((x) => x.name !== name);
  return { ok: true };
}

export function testDns(name: string): TestResult {
  const d = ix().dns.find((x) => x.name === name);
  if (!d) throw new DemoError(404, `no DNS account named ${name}`);
  const label = CATALOG.dns_providers.find((p) => p.id === d.provider)?.label ?? d.provider;
  const zones = [...new Set([...d.zones, "example.org", "internal.example.com"])];
  return { ok: true, detail: `Signed in to ${label}; ${zones.length} zones visible (demo data).`, zones };
}

/* notifiers */

function shownTarget(n: StoredNotifier) {
  const v = n.fields;
  if (n.type === "slack") return v.channel || "Slack webhook";
  if (n.type === "teams") return "Teams workflow";
  if (n.type === "webhook") return hostOf(v.url ?? null);
  return v.to || null;
}

export function listNotifiers(): NotifierChannel[] {
  return ix().notifiers.map((n) => ({
    ...n.fields, name: n.name, source: n.source, type: n.type, events: [...n.events], target: shownTarget(n),
  }));
}

export function putNotifier(name: string, b: Record<string, unknown>) {
  checkName(name, "Channel");
  const s = ix();
  const existing = s.notifiers.find((n) => n.name === name);
  refuseFile(existing, "notifiers.json");
  const type = CATALOG.notifier_types.find((t) => t.id === str(b.type));
  if (!type) throw new DemoError(400, `unknown channel type ${str(b.type) || "(none)"}`);
  const fields: Record<string, string> = {};
  for (const field of type.fields) {
    // an omitted secret keeps the stored reference, so an edit never needs the value again
    const v = field.key in b ? b[field.key] : field.secret && existing?.type === type.id ? existing.fields[field.key] : undefined;
    if (!str(v)) {
      if (field.required) throw new DemoError(400, `${field.label} is required for ${type.label}`);
      continue;
    }
    fields[field.key] = field.secret ? checkRef(v, field.key) : str(v);
  }
  if (type.id === "webhook" && !/^https?:\/\/\S+$/.test(fields.url)) throw new DemoError(400, "url must start with https://");
  const events = Array.isArray(b.events) ? strList(b.events) : existing?.events ?? [];
  const bad = events.find((e) => !ALERT_EVENTS.includes(e));
  if (bad) throw new DemoError(400, `unknown event ${bad}`);
  const out: StoredNotifier = { name, source: "ui", type: type.id, events, fields };
  if (existing) Object.assign(existing, out);
  else s.notifiers.push(out);
  return listNotifiers().find((n) => n.name === name);
}

export function deleteNotifier(name: string) {
  const s = ix();
  const n = s.notifiers.find((x) => x.name === name);
  if (!n) throw new DemoError(404, `no channel named ${name}`);
  refuseFile(n, "notifiers.json");
  const users = s.rules.filter((r) => r.channels.includes(name)).map((r) => r.name);
  if (users.length) throw new DemoError(409, `Rule ${users.join(", ")} sends to ${name}. Remove it from the rule first.`);
  s.notifiers = s.notifiers.filter((x) => x.name !== name);
  return { ok: true };
}

export function testNotifier(name: string): TestResult {
  const n = listNotifiers().find((x) => x.name === name);
  if (!n) throw new DemoError(404, `no channel named ${name}`);
  return { ok: true, detail: `Demo mode: nothing was sent. A live server posts a test message to ${n.target ?? n.type}.` };
}

/* alert rules */

export const listRules = (): AlertRule[] => ix().rules.map((r) => ({ ...r }));

function checkWhen(w: unknown): AlertWhen {
  const v = (w ?? {}) as Record<string, unknown>;
  const days = (min: number, max: number) => {
    const d = Number(v.days);
    if (!Number.isInteger(d) || d < min || d > max) throw new DemoError(400, `days must be a whole number from ${min} to ${max}`);
    return d;
  };
  switch (v.type) {
    case "event": {
      const events = strList(v.events);
      if (!events.length) throw new DemoError(400, "choose at least one event");
      const bad = events.find((e) => !ALERT_EVENTS.includes(e));
      if (bad) throw new DemoError(400, `unknown event ${bad}`);
      return { type: "event", events };
    }
    case "expiring":
      return { type: "expiring", days: days(1, 365) };
    case "unreachable":
      return { type: "unreachable", days: days(1, 90) };
    case "health":
      if (!GRADES.includes(String(v.below))) throw new DemoError(400, "below must be A, B, C or D");
      return { type: "health", below: v.below as "A" | "B" | "C" | "D" };
    case "zombie": {
      const kinds = strList(v.kinds);
      return kinds.length ? { type: "zombie", kinds } : { type: "zombie" };
    }
    default:
      throw new DemoError(400, "when.type must be event, expiring, health, zombie or unreachable");
  }
}

export function putRule(name: string, b: Record<string, unknown>) {
  checkName(name, "Rule");
  const s = ix();
  const channels = strList(b.channels);
  if (!channels.length) throw new DemoError(400, "a rule needs at least one channel");
  const missing = channels.find((c) => !s.notifiers.some((n) => n.name === c));
  if (missing) throw new DemoError(400, `no channel named ${missing}`);
  const cooldown = b.cooldown_hours === undefined || b.cooldown_hours === null ? 24 : Number(b.cooldown_hours);
  if (!Number.isInteger(cooldown) || cooldown < 0 || cooldown > 720) throw new DemoError(400, "cooldown_hours must be 0 to 720");
  const fl = (b.filter ?? {}) as Record<string, unknown>;
  const tags = strList(fl.tags);
  const connectors = strList(fl.connectors);
  const pattern = str(fl.name);
  const filter: AlertRule["filter"] =
    tags.length || connectors.length || pattern
      ? { ...(tags.length ? { tags } : {}), ...(connectors.length ? { connectors } : {}), ...(pattern ? { name: pattern } : {}) }
      : null;
  const existing = s.rules.find((r) => r.name === name);
  const out: AlertRule = {
    name, enabled: b.enabled !== false, when: checkWhen(b.when), filter, channels, cooldown_hours: cooldown,
    last_fired_at: existing?.last_fired_at ?? null,
  };
  if (existing) Object.assign(existing, out);
  else s.rules.push(out);
  return out;
}

export function deleteRule(name: string) {
  const s = ix();
  if (!s.rules.some((r) => r.name === name)) throw new DemoError(404, `no rule named ${name}`);
  s.rules = s.rules.filter((r) => r.name !== name);
  return { ok: true };
}

export function testRule(name: string) {
  const r = ix().rules.find((x) => x.name === name);
  if (!r) throw new DemoError(404, `no rule named ${name}`);
  return { ok: true, sent: r.channels.length };
}

/** The read-only /config view of the same integrations. */
function integrationConfig(): Pick<FarrierConfig, "issuers" | "dns_accounts" | "notifiers"> {
  const s = ix();
  return {
    issuers: s.issuers.map((i) => ({
      name: i.name, type: i.type, preset: i.preset, directory: hostOf(i.directory_url), email: i.email, dns: i.dns, eab: i.eab_kid,
    })),
    dns_accounts: s.dns.map((d) => ({ name: d.name, provider: d.provider, zones: d.zones, credentials: d.credentials })),
    notifiers: s.notifiers.map((n) => ({ type: n.type, events: n.events })),
  };
}
