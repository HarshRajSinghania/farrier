/**
 * Types mirroring the Farrier HTTP API (farrier/api.py). Keep in sync when the
 * Python side changes — these are the only contract the dashboard relies on.
 */

export type RenewalState =
  | "planned"
  | "issued"
  | "deploying"
  | "verifying"
  | "awaiting_manual"
  | "done"
  | "failed"
  | "rolled_back"
  | "superseded"
  | "cancelled";

export const OPEN_STATES: RenewalState[] = ["planned", "issued", "deploying", "verifying", "awaiting_manual"];

export type ExpiryBucket = "expired" | "7d" | "30d" | "90d" | "later" | "unknown";

export interface ForecastRow {
  on: string;
  lifetime_days: number;
  interval_days: number;
  renewals_per_year: number;
  per_calendar_day: number;
  per_working_day: number;
  manual_renewals_per_year: number;
  manual_hours_per_year: number;
  manual_fte: number;
}

export interface CalendarDay {
  date: string;
  auto: number;
  manual: number;
  projected_auto: number;
  projected_manual: number;
}

export interface Summary {
  now: string;
  policy: {
    max_lifetime_days: number;
    dcv_reuse_days: number;
    schedule: { from: string; days: number; dcv: number }[];
  };
  endpoints: number;
  automated: number;
  manual: number;
  by_connector: Record<string, number>;
  expiry: Partial<Record<ExpiryBucket, number>>;
  renewal_states: Partial<Record<RenewalState, number>>;
  awaiting_manual: number;
  attention: number;
  forecast: ForecastRow[];
  calendar: CalendarDay[];
}

export interface MaintenanceWindow {
  days?: string[];
  start?: string;
  hours?: number;
}

export interface Endpoint {
  id: number;
  name: string;
  host: string;
  port: number;
  sni: string | null;
  common_name: string | null;
  sans: string[];
  key_type: string;
  connector: string;
  issuer: string;
  window: MaintenanceWindow;
  lead_days: number;
  owner: string | null;
  tags: string[];
  enabled: number | boolean;
  created_at: string;
  fingerprint: string | null;
  not_after: string | null;
  not_before: string | null;
  cert_issuer: string | null;
  subject_cn: string | null;
  observed_at: string | null;
  scan_error: string | null;
  automated: boolean;
  days_left: number | null;
}

export interface EndpointInput {
  name: string;
  host: string;
  port?: number;
  sni?: string | null;
  common_name?: string | null;
  sans?: string[];
  key_type?: string;
  connector?: string;
  connector_config?: Record<string, unknown>;
  issuer?: string;
  window?: MaintenanceWindow;
  lead_days?: number;
  owner?: string | null;
  tags?: string[];
  enabled?: boolean;
}

export interface Renewal {
  id: number;
  endpoint_id: number;
  state: RenewalState;
  reason: string | null;
  scheduled_for: string;
  deadline: string | null;
  prev_fingerprint: string | null;
  new_fingerprint: string | null;
  not_after: string | null;
  ticket_ref: string | null;
  attempts: number;
  error: string | null;
  created_at: string;
  updated_at: string;
  name: string;
  connector: string;
  host: string;
  port: number;
}

export interface FarrierEvent {
  id: number;
  at: string;
  endpoint_id: number | null;
  renewal_id: number | null;
  level: "info" | "warning" | "error" | string;
  message: string;
  name: string | null;
}

export interface ConnectorInfo {
  kind: string;
  automated: boolean;
  required: string[];
  doc: string;
}

export interface DiscoverResult {
  new: number;
  seen: number;
  scanned: number;
  with_tls: number;
}

export interface BackendStatus {
  mode: "live" | "demo";
  upstream: string | null;
  reachable: boolean;
  error?: string;
  /** the signed-in dashboard user ("demo" in demo mode) */
  user?: string;
  /** whether the dashboard is behind FARRIER_DASHBOARD_PASSWORD */
  auth?: boolean;
}

export type HealthStatus = "pass" | "warn" | "fail";
export interface HealthCheck {
  id: string;
  status: HealthStatus;
  detail: string;
}
export interface HealthReport {
  endpoint: string;
  grade: "A" | "B" | "C" | "D" | "F";
  checked_at: string;
  summary: Record<HealthStatus, number>;
  checks: HealthCheck[];
}
export interface ZombieFinding {
  kind: string;
  severity: "critical" | "warning" | "info";
  endpoint_id: number | null;
  endpoint: string | null;
  target: string;
  action: string;
}
export interface ZombieReport {
  generated_at: string;
  count: number;
  findings: ZombieFinding[];
}

export type EngineSettings = {
  horizon_days: number;
  safety_days: number;
  manual_daily_cap: number;
  auto_daily_cap: number;
  verify_max_attempts: number;
  scan_timeout: number;
  verify_chain_and_names: boolean;
  verify_all_addresses: boolean;
};
export interface FarrierConfig {
  settings: EngineSettings;
  limits: Record<keyof EngineSettings, { min: number; max: number; type: "int" | "float" | "bool" }>;
  issuers: { name: string; type: string; preset: string | null; directory: string | null; email: string | null; dns: string | null; eab: string | null }[];
  issuers_error: string | null;
  dns_accounts: { name: string; provider: string; zones: string[]; credentials: Record<string, string | null> }[];
  dns_error: string | null;
  notifiers: { type: string; events: string[] }[];
  engine: { backend: string; leader: boolean; replica: string; schema_version: number; data_dir: string; mcp_writes: boolean };
}

/* ------------------------------------------------------------ integrations */

/** `vault:NAME`, `env:NAME` or `file:/path`; never a secret value. */
export type SecretRef = string;
export type ConfigSource = "file" | "ui";

export interface SecretInfo {
  name: string;
  created_at: string;
  updated_at: string;
  used_by: string[];
}

export interface CatalogField {
  key: string;
  label: string;
  secret: boolean;
  required: boolean;
  help?: string | null;
}
export interface DnsProviderInfo {
  id: string;
  label: string;
  fields: CatalogField[];
}
export interface CaPreset {
  id: string;
  label: string;
  eab: boolean;
  needs_directory_url: boolean;
  /** true for a staging/test directory */
  staging: boolean | string | null;
}
export interface NotifierTypeInfo {
  id: string;
  label: string;
  fields: CatalogField[];
}
export interface IntegrationCatalog {
  dns_providers: DnsProviderInfo[];
  ca_presets: CaPreset[];
  notifier_types: NotifierTypeInfo[];
  alert_rule_types: { id: AlertWhen["type"]; label: string }[];
}

export interface Issuer {
  name: string;
  source: ConfigSource;
  type: string;
  preset: string | null;
  directory_url: string | null;
  email: string | null;
  dns: string | null;
  profile: string | null;
  preferred_chain: string | null;
  eab_kid: string | null;
  eab_hmac_key: SecretRef | null;
}
export interface IssuerInput {
  preset?: string;
  type?: string;
  email?: string;
  dns?: string;
  profile?: string;
  preferred_chain?: string;
  directory_url?: string;
  eab_kid?: string;
  eab_hmac_key?: SecretRef;
}

export interface DnsAccount {
  name: string;
  source: ConfigSource;
  provider: string;
  zones: string[];
  credentials: Record<string, SecretRef | null>;
  options: Record<string, string>;
}
export interface DnsAccountInput {
  provider: string;
  credentials: Record<string, SecretRef>;
  options: Record<string, string>;
  zones: string[];
}

export interface NotifierChannel {
  name: string;
  source: ConfigSource;
  type: string;
  events: string[];
  /** a display string: the channel, host or address it sends to */
  target: string | null;
  /** some servers also return the non-secret fields and secret references */
  [field: string]: unknown;
}
export type NotifierInput = { type: string; events?: string[] } & Record<string, unknown>;

export type HealthGrade = "A" | "B" | "C" | "D";
export type AlertWhen =
  | { type: "event"; events: string[] }
  | { type: "expiring"; days: number }
  | { type: "health"; below: HealthGrade }
  | { type: "zombie"; kinds?: string[] }
  | { type: "unreachable"; days: number };
export interface AlertFilter {
  tags?: string[];
  connectors?: string[];
  name?: string;
}
export interface AlertRule {
  name: string;
  enabled: boolean;
  when: AlertWhen;
  filter: AlertFilter | null;
  channels: string[];
  cooldown_hours: number | null;
  last_fired_at: string | null;
}
export interface AlertRuleInput {
  enabled: boolean;
  when: AlertWhen;
  filter?: AlertFilter;
  channels: string[];
  cooldown_hours?: number;
}

export interface TestResult {
  ok: boolean;
  detail: string;
  zones?: string[];
}
