"use client";

import useSWR, { mutate as globalMutate, type SWRConfiguration } from "swr";
import type {
  BackendStatus,
  ConnectorInfo,
  DiscoverResult,
  Endpoint,
  EndpointInput,
  FarrierEvent,
  HealthReport,
  Renewal,
  Summary,
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
export const useStatus = () => useSWR<BackendStatus>("/_status", fetcher, { refreshInterval: 60_000 });

/** Revalidate every cached query after a mutation. */
const refreshAll = () => globalMutate(() => true);

async function act<T>(path: string, init: RequestInit): Promise<T> {
  const out = await request<T>(path, init);
  await refreshAll();
  return out;
}

export const api = {
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
};
