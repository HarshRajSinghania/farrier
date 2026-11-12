"use client";

import { useState } from "react";
import { AlertTriangle, CheckCircle2, Skull, Stethoscope, XCircle } from "lucide-react";
import { ErrorNotice, PageHeader } from "@/components/dashboard/shell";
import { TableSkeleton } from "@/components/dashboard/widgets";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/misc";
import { api, useEndpoints, useZombies } from "@/lib/api";
import type { HealthReport, HealthStatus } from "@/lib/types";
import { cn } from "@/lib/utils";

const KIND: Record<string, string> = {
  expired_served: "Expired, still served",
  stale_duplicate: "Old certificate still served",
  unexpected_issuer: "Issued by another CA",
  unexpected_issuance: "Not issued by Farrier",
  dead_endpoint: "Endpoint not answering",
  pack_never_installed: "Change pack never installed",
  discovered_unowned: "Discovered, no owner",
  not_in_inventory: "Not in the inventory",
};
// the engine's action text names API routes; operators get the plain version
const ACTION: Record<string, string> = {
  expired_served: "Renew it now, or disable the endpoint if it is retired.",
  stale_duplicate: "Redeploy the current certificate to the node still serving the old one.",
  unexpected_issuer: "Find who issued it, then bring the name under Farrier or remove it.",
  unexpected_issuance: "Check the CT log entry and the team that requested it.",
  dead_endpoint: "Confirm the host is gone, then disable the endpoint.",
  pack_never_installed: "Install the change pack, or chase its ticket.",
  discovered_unowned: "Give it an owner or disable it.",
  not_in_inventory: "Add it to the inventory so Farrier renews it.",
};
const STATUS: Record<HealthStatus, { icon: typeof CheckCircle2; cls: string; label: string }> = {
  pass: { icon: CheckCircle2, cls: "text-good-fg", label: "Pass" },
  warn: { icon: AlertTriangle, cls: "text-warning-fg", label: "Warning" },
  fail: { icon: XCircle, cls: "text-critical-fg", label: "Fail" },
};

function HealthCheck() {
  const { data: eps } = useEndpoints();
  const [id, setId] = useState<number | "">("");
  const [report, setReport] = useState<HealthReport | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const run = async () => {
    if (!id) return;
    setBusy(true);
    setError(null);
    try {
      setReport(await api.health(id));
    } catch (e) {
      setError(e as Error);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card className="p-6">
      <h2 className="text-lg font-semibold">Check an endpoint</h2>
      <p className="mt-1 text-sm text-muted-foreground">Chain, names, expiry, key, signature, TLS versions and OCSP, graded A to F.</p>
      <div className="mt-4 flex flex-wrap gap-2">
        <select
          aria-label="Endpoint"
          value={id}
          onChange={(e) => setId(e.target.value ? Number(e.target.value) : "")}
          className="h-9 min-w-64 rounded-md border bg-background px-2 text-sm"
        >
          <option value="">Choose an endpoint</option>
          {(eps ?? []).map((e) => (
            <option key={e.id} value={e.id}>
              {e.name}
            </option>
          ))}
        </select>
        <Button onClick={run} disabled={!id || busy}>
          <Stethoscope /> {busy ? "Checking…" : "Run check"}
        </Button>
      </div>
      <ErrorNotice error={error ?? undefined} />
      {report && (
        <div className="mt-6 flex flex-col gap-6 sm:flex-row">
          <div className="flex size-24 shrink-0 flex-col items-center justify-center rounded-2xl bg-muted">
            <span className="text-4xl font-semibold">{report.grade}</span>
            <span className="text-xs text-muted-foreground">grade</span>
          </div>
          <ul className="flex-1 divide-y text-sm">
            {report.checks.map((c) => {
              const s = STATUS[c.status];
              return (
                <li key={c.id} className="flex items-start gap-2 py-2">
                  <s.icon className={cn("mt-0.5 size-4 shrink-0", s.cls)} aria-label={s.label} />
                  <span className="w-28 shrink-0 font-medium">{c.id.replace("_", " ")}</span>
                  <span className="min-w-0 break-words text-muted-foreground">{c.detail}</span>
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </Card>
  );
}

export function HealthView() {
  const { data, error, isLoading } = useZombies();
  return (
    <>
      <PageHeader title="Health" description="Certificates that are alive but shouldn't be, and a TLS report card for any endpoint." />
      <ErrorNotice error={error} />
      <div className="grid gap-6">
        <Card className="overflow-hidden">
          <div className="flex items-center gap-2 border-b px-6 py-4">
            <h2 className="text-lg font-semibold">Zombie certificates</h2>
            {data && <Badge tone={data.count ? "critical" : "good"}>{data.count}</Badge>}
          </div>
          {isLoading ? (
            <TableSkeleton rows={4} />
          ) : !data?.findings.length ? (
            <EmptyState icon={<CheckCircle2 />} title="No zombies">Every served certificate is one Farrier expects.</EmptyState>
          ) : (
            <ul className="divide-y">
              {data.findings.map((f, k) => (
                <li key={k} className="flex flex-wrap items-start gap-4 px-6 py-4 text-sm">
                  <Skull className={cn("mt-0.5 size-4 shrink-0", f.severity === "critical" ? "text-critical-fg" : "text-warning-fg")} aria-hidden />
                  <div className="min-w-0 flex-1">
                    <p className="font-medium">
                      {KIND[f.kind] ?? f.kind} <span className="font-normal text-muted-foreground">· {f.endpoint ?? f.target}</span>
                    </p>
                    <p className="mt-1 text-muted-foreground">{ACTION[f.kind] ?? f.action}</p>
                  </div>
                  <Badge tone={f.severity === "critical" ? "critical" : "warning"}>{f.severity === "critical" ? "Critical" : "Warning"}</Badge>
                </li>
              ))}
            </ul>
          )}
        </Card>
        <HealthCheck />
      </div>
    </>
  );
}
