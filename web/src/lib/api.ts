"use client";

import useSWR, { mutate as globalMutate, type SWRConfiguration } from "swr";
import type {
  AlertRule,
  AlertRuleInput,
  BackendStatus,
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
  Renewal,
  SecretInfo,
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

// The server renews on a 5-minute loop; 15s polling keeps screens fresh without load.
const live: SWRConfiguration = { refreshInterval: 15_000, revalidateOnFocus: true, keepPreviousData: true };

export const useSummary = () => useSWR<Summary>("/summary", fetcher, live);
export const useEndpoints = () => useSWR<Endpoint[]>("/endpoints", fetcher, live);
export const useRenewals = (state?: string) =>
  useSWR<Renewal[]>(state ? `/renewals?state=${state}` : "/renewals", fetcher, live);
export const useEvents = (limit = 100, endpointId?: number) =>
  useSWR<FarrierEvent[]>(`/events?limit=${limit}${endpointId ? `&endpoint_id=${endpointId}` : ""}`, fetcher, live);
export const useConnectors = () => useSWR<ConnectorInfo[]>("/connectors", fetcher);
export const useZombies = () => useSWR<ZombieReport>("/zombies", fetcher, live);
export const useConfig = () => useSWR<FarrierConfig>("/config", fetcher);
// integrations change only when someone edits them; `act` refreshes them after a save
export const useCatalog = () => useSWR<IntegrationCatalog>("/integrations/catalog", fetcher, { revalidateOnFocus: false });
export const useSecrets = () => useSWR<SecretInfo[]>("/secrets", fetcher);
export const useIssuers = () => useSWR<Issuer[]>("/issuers", fetcher);
export const useDnsAccounts = () => useSWR<DnsAccount[]>("/dns-accounts", fetcher);
export const useNotifiers = () => useSWR<NotifierChannel[]>("/notifiers", fetcher);
export const useAlertRules = () => useSWR<AlertRule[]>("/alert-rules", fetcher);
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
  addEndpoint: (ep: EndpointInput) => act<{ id: number }>("/endpoints", { method: "POST", body: JSON.stringify(ep) }),
  deleteEndpoint: (id: number) => act<{ ok: true }>(`/endpoints/${id}`, { method: "DELETE" }),
  advance: (id: number) => act<{ state: string }>(`/renewals/${id}/advance`, { method: "POST" }),
  cancel: (id: number) => act<{ state: string }>(`/renewals/${id}/cancel`, { method: "POST" }),
  tick: () => act<{ planned: number; states: Record<string, number> }>("/tick", { method: "POST" }),
  discover: (targets: string) =>
    act<DiscoverResult>("/discover", { method: "POST", body: JSON.stringify({ targets }) }),
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
  testAlertRule: (name: string) => request<{ ok: boolean; sent: number }>(`/alert-rules/${enc(name)}/test`, { method: "POST" }),
};

function enc(name: string) {
  return encodeURIComponent(name);
}
