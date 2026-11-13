"use client";

import { useSyncExternalStore } from "react";
import useSWR, { mutate as globalMutate, type SWRConfiguration } from "swr";
import { withProject } from "./projects";
import type {
  AlertRule,
  AlertRuleInput,
  BackendStatus,
  CertificateDetail,
  CryptoAsset,
  CryptoSummary,
  CtName,
  RunnerGroup,
  CloudInventory,
  ConnectorInfo,
  DiscoverResult,
  DnsAccount,
  DnsAccountInput,
  Endpoint,
  EndpointInput,
  EngineSettings,
  FarrierConfig,
  FarrierEvent,
  HealthReport,
  IntegrationCatalog,
  Issuer,
  IssuerInput,
  NotifierChannel,
  NotifierInput,
  Project,
  Renewal,
  SecretInfo,
  SshAccess,
  SshAccessInput,
  SshHost,
  SshKey,
  SshRemoveResult,
  SshSummary,
  Summary,
  TestResult,
  ZombieReport,
} from "./types";

const BASE = "/api/farrier";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: { "content-type": "application/json", ...init?.headers },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => null);
    const detail = body?.detail;
    throw new ApiError(res.status, typeof detail === "string" ? detail : `Request failed (${res.status})`);
  }
  return res.json() as Promise<T>;
}

const fetcher = <T,>(path: string) => request<T>(path);

/* ---- the project picked in the topbar: ?project= in the URL, else localStorage; null = all of mine ---- */
const PROJECT_KEY = "farrier.project";
let picked: string | null | undefined; // undefined until read on the client
const listeners = new Set<() => void>();

function readPicked(): string | null {
  if (picked === undefined) {
    picked = null;
    if (typeof window !== "undefined") {
      try {
        picked = new URLSearchParams(window.location.search).get("project") || window.localStorage.getItem(PROJECT_KEY) || null;
      } catch {
        /* storage blocked: start with every project */
      }
    }
  }
  return picked;
}

export function setProject(name: string | null) {
  if (name === readPicked()) return;
  picked = name;
  try {
    if (name) window.localStorage.setItem(PROJECT_KEY, name);
    else window.localStorage.removeItem(PROJECT_KEY);
    const url = new URL(window.location.href);
    if (name) url.searchParams.set("project", name);
    else url.searchParams.delete("project");
    window.history.replaceState(window.history.state, "", url);
  } catch {
    /* storage blocked: the pick lasts for this page */
  }
  listeners.forEach((l) => l());
}

const subscribe = (l: () => void) => {
  listeners.add(l);
  return () => listeners.delete(l);
};

/** The picked project name, or null for "all of my projects". */
export const useProject = () => useSyncExternalStore(subscribe, readPicked, () => null);
/** The current pick outside React (request bodies of scans). */
export const currentProject = () => readPicked();

/** A data path narrowed to the picked project; the key changes with it, so SWR refetches. */
const useScoped = (path: string | null) => {
  const project = useProject();
  return path === null ? null : withProject(path, project);
};

// The server renews on a 5-minute loop; 15s polling keeps screens fresh without load.
const live: SWRConfiguration = { refreshInterval: 15_000, revalidateOnFocus: true, keepPreviousData: true };

export const useSummary = () => useSWR<Summary>(useScoped("/summary"), fetcher, live);
export const useEndpoints = () => useSWR<Endpoint[]>(useScoped("/endpoints"), fetcher, live);
export const useRenewals = (state?: string) =>
  useSWR<Renewal[]>(useScoped(state ? `/renewals?state=${state}` : "/renewals"), fetcher, live);
export const useEvents = (limit = 100, endpointId?: number) =>
  useSWR<FarrierEvent[]>(useScoped(`/events?limit=${limit}${endpointId ? `&endpoint_id=${endpointId}` : ""}`), fetcher, live);
export const useConnectors = () => useSWR<ConnectorInfo[]>("/connectors", fetcher);
export const useZombies = () => useSWR<ZombieReport>(useScoped("/zombies"), fetcher, live);
export const useProjects = () => useSWR<Project[]>("/projects", fetcher);
export const useConfig = () => useSWR<FarrierConfig>("/config", fetcher);
// integrations change only when someone edits them; `act` refreshes them after a save
export const useCatalog = () => useSWR<IntegrationCatalog>("/integrations/catalog", fetcher, { revalidateOnFocus: false });
export const useSecrets = () => useSWR<SecretInfo[]>("/secrets", fetcher);
export const useIssuers = () => useSWR<Issuer[]>("/issuers", fetcher);
export const useCloudCertificates = () => useSWR<CloudInventory>("/cloud/certificates", fetcher, { revalidateOnFocus: false });
export const useRunners = () => useSWR<RunnerGroup[]>("/runners", fetcher, live);
export const useDnsAccounts = () => useSWR<DnsAccount[]>("/dns-accounts", fetcher);
export const useNotifiers = () => useSWR<NotifierChannel[]>("/notifiers", fetcher);
export const useAlertRules = () => useSWR<AlertRule[]>("/alert-rules", fetcher);
export const useCertificate = (id: number | null) =>
  useSWR<CertificateDetail>(id ? `/endpoints/${id}/certificate` : null, fetcher, live);
export const useSshSummary = () => useSWR<SshSummary>(useScoped("/ssh/summary"), fetcher, live);
export const useSshKeys = () => useSWR<SshKey[]>(useScoped("/ssh/keys"), fetcher, live);
export const useSshHosts = () => useSWR<SshHost[]>(useScoped("/ssh/hosts"), fetcher, live);
export const useSshAccess = () => useSWR<SshAccess[]>("/ssh/access", fetcher);
export const useCryptoSummary = () => useSWR<CryptoSummary>(useScoped("/crypto/summary"), fetcher, live);
export const useCryptoAssets = () => useSWR<CryptoAsset[]>(useScoped("/crypto/assets"), fetcher, live);
export const useStatus = () => useSWR<BackendStatus>("/_status", fetcher, { refreshInterval: 60_000 });

/** Revalidate every cached query after a mutation. */
const refreshAll = () => globalMutate(() => true);

async function act<T>(path: string, init: RequestInit): Promise<T> {
  const out = await request<T>(path, init);
  await refreshAll();
  return out;
}

export const api = {
  saveSettings: (changes: Partial<EngineSettings>) =>
    act<{ changed: Partial<EngineSettings> }>("/config/settings", { method: "PUT", body: JSON.stringify(changes) }),
  testNotifiers: () => request<{ sent: number }>("/notifiers/test", { method: "POST" }),
  // a live TLS probe: read-only, so no cache refresh afterwards
  health: (id: number) => request<HealthReport>(`/endpoints/${id}/health?caa=false`),
  renew: (id: number) => act<{ renewal_id: number; state: string }>(`/endpoints/${id}/renew`, { method: "POST" }),
  approve: (id: number) => act<{ ok: true }>(`/endpoints/${id}/approve`, { method: "POST" }),
  addEndpoint: (ep: EndpointInput) => act<{ id: number }>("/endpoints", { method: "POST", body: JSON.stringify(ep) }),
  deleteEndpoint: (id: number) => act<{ ok: true }>(`/endpoints/${id}`, { method: "DELETE" }),
  advance: (id: number) => act<{ state: string }>(`/renewals/${id}/advance`, { method: "POST" }),
  cancel: (id: number) => act<{ state: string }>(`/renewals/${id}/cancel`, { method: "POST" }),
  approveRenewal: (id: number) => act<{ state: string }>(`/renewals/${id}/approve`, { method: "POST" }),
  rejectRenewal: (id: number) => act<{ state: string }>(`/renewals/${id}/reject`, { method: "POST" }),
  tick: () => act<{ planned: number; states: Record<string, number> }>("/tick", { method: "POST" }),
  // new endpoints, hosts and assets land in the picked project (the engine picks your only one otherwise)
  discover: (targets: string) =>
    act<DiscoverResult>("/discover", { method: "POST", body: JSON.stringify({ targets, project: currentProject() ?? undefined }) }),
  runnerToken: (group: string) => act<{ group: string; token: string }>(`/runners/${encodeURIComponent(group)}/token`, { method: "POST" }),
  revokeRunner: (group: string) => act<{ ok: true }>(`/runners/${encodeURIComponent(group)}/token`, { method: "DELETE" }),
  refreshCloud: () => request<CloudInventory>("/cloud/certificates?refresh=true"),
  ctNames: (domain: string) => request<CtName[]>(`/discover/ct?domain=${encodeURIComponent(domain)}`),
  runbook: (id: number) => request<{ markdown: string }>(`/renewals/${id}/runbook`),
  packUrl: (id: number) => `${BASE}/renewals/${id}/pack`,

  // integrations: names are path segments, so they stay [A-Za-z0-9_-]
  putSecret: (name: string, value: string) =>
    request<{ ok: true }>(`/secrets/${enc(name)}`, { method: "PUT", body: JSON.stringify({ value }) }),
  deleteSecret: (name: string) => act<{ ok: true }>(`/secrets/${enc(name)}`, { method: "DELETE" }),
  saveIssuer: (name: string, body: IssuerInput) =>
    act<Issuer>(`/issuers/${enc(name)}`, { method: "PUT", body: JSON.stringify(body) }),
  deleteIssuer: (name: string) => act<{ ok: true }>(`/issuers/${enc(name)}`, { method: "DELETE" }),
  testIssuer: (name: string) => request<TestResult>(`/issuers/${enc(name)}/test`, { method: "POST" }),
  saveDnsAccount: (name: string, body: DnsAccountInput) =>
    act<DnsAccount>(`/dns-accounts/${enc(name)}`, { method: "PUT", body: JSON.stringify(body) }),
  deleteDnsAccount: (name: string) => act<{ ok: true }>(`/dns-accounts/${enc(name)}`, { method: "DELETE" }),
  testDnsAccount: (name: string) => request<TestResult>(`/dns-accounts/${enc(name)}/test`, { method: "POST" }),
  saveNotifier: (name: string, body: NotifierInput) =>
    act<NotifierChannel>(`/notifiers/${enc(name)}`, { method: "PUT", body: JSON.stringify(body) }),
  deleteNotifier: (name: string) => act<{ ok: true }>(`/notifiers/${enc(name)}`, { method: "DELETE" }),
  testNotifier: (name: string) => request<TestResult>(`/notifiers/${enc(name)}/test`, { method: "POST" }),
  saveAlertRule: (name: string, body: AlertRuleInput) =>
    act<AlertRule>(`/alert-rules/${enc(name)}`, { method: "PUT", body: JSON.stringify(body) }),
  deleteAlertRule: (name: string) => act<{ ok: true }>(`/alert-rules/${enc(name)}`, { method: "DELETE" }),

  // SSH keys
  sshScan: (targets: string) =>
    act<Record<string, unknown>>("/ssh/scan", { method: "POST", body: JSON.stringify({ targets, project: currentProject() ?? undefined }) }),
  sshCollect: (access?: string) =>
    act<Record<string, unknown>>("/ssh/collect", { method: "POST", body: JSON.stringify(access ? { access } : {}) }),
  /** dry_run first: the server says what it would change and changes nothing */
  sshRemoveKey: (id: number | string, dryRun: boolean) => {
    const call = dryRun ? request : act;
    return call<SshRemoveResult>(`/ssh/keys/${enc(String(id))}/remove`, { method: "POST", body: JSON.stringify({ dry_run: dryRun }) });
  },
  saveSshAccess: (name: string, body: SshAccessInput) =>
    act<SshAccess>(`/ssh/access/${enc(name)}`, { method: "PUT", body: JSON.stringify(body) }),
  deleteSshAccess: (name: string) => act<{ ok: true }>(`/ssh/access/${enc(name)}`, { method: "DELETE" }),
  testSshAccess: (name: string) => request<TestResult>(`/ssh/access/${enc(name)}/test`, { method: "POST" }),

  // crypto discovery
  cryptoScan: (targets: string) =>
    act<Record<string, unknown>>("/crypto/scan", { method: "POST", body: JSON.stringify({ targets, project: currentProject() ?? undefined }) }),
  cbomUrl: () => BASE + withProject("/crypto/cbom", currentProject()),
  inventoryCsvUrl: (project: string | null) => BASE + withProject("/inventory?format=csv", project),

  // teams and projects (global admins)
  saveProject: (name: string, body: Pick<Project, "title" | "members">) =>
    act<Project>(`/projects/${enc(name)}`, { method: "PUT", body: JSON.stringify(body) }),
  deleteProject: (name: string) => act<{ ok: true }>(`/projects/${enc(name)}`, { method: "DELETE" }),
  moveEndpoint: (id: number, project: string) =>
    act<{ ok: true }>(`/endpoints/${id}/move`, { method: "POST", body: JSON.stringify({ project }) }),

  testAlertRule: (name: string) => request<{ ok: boolean; sent: number }>(`/alert-rules/${enc(name)}/test`, { method: "POST" }),
};

function enc(name: string) {
  return encodeURIComponent(name);
}
