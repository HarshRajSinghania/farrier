/**
 * Demo mode: an in-memory stand-in for the Farrier API, used when FARRIER_API_URL
 * is not set (e.g. a Vercel preview of the marketing site). It mirrors the
 * shapes and state machine of farrier/engine.py closely enough to exercise every
 * dashboard screen. Nothing here touches a real CA or device.
 */
import "server-only";
import { forecastTimeline, maxLifetimeDays, dcvReuseDays, renewBeforeDays, SCHEDULE } from "./policy";
import type {
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
