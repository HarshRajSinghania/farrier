"use client";

import { useMemo, useState } from "react";
import { AlertTriangle, Info, ScrollText, XCircle } from "lucide-react";
import { ErrorNotice, PageHeader } from "@/components/dashboard/shell";
import { TableSkeleton } from "@/components/dashboard/widgets";
import { Card } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/misc";
import { Segmented } from "@/components/ui/segmented";
import { Download, ShieldAlert, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { api, useAuditStatus, useEvents } from "@/lib/api";
import { cn, fmtDateTime, relativeTime } from "@/lib/utils";

const LEVEL = {
  info: { icon: Info, className: "text-muted-foreground", label: "Info" },
  warning: { icon: AlertTriangle, className: "text-warning-fg", label: "Warning" },
  // older engine versions logged "warn"
  warn: { icon: AlertTriangle, className: "text-warning-fg", label: "Warning" },
  error: { icon: XCircle, className: "text-critical-fg", label: "Error" },
} as const;

type Filter = "all" | "warning" | "error";

export default function ActivityPage() {
  const { data, error, isLoading } = useEvents(500);
  const [filter, setFilter] = useState<Filter>("all");

  const rows = useMemo(
    () => (data ?? []).filter((e) => filter === "all" || (filter === "error" ? e.level === "error" : e.level !== "info")),
    [data, filter],
  );

  return (
    <>
      <PageHeader
        title="Activity"
        description="Audit trail of every scan, issuance, deploy, verification and operator action, sealed in a hash chain."
        actions={<AuditActions />}
      />
      <ErrorNotice error={error} />
      <div className="mb-4">
        <Segmented
          label="Filter by level"
          value={filter}
          onChange={setFilter}
          options={[
            { value: "all", label: "All" },
            { value: "warning", label: "Warnings & errors" },
            { value: "error", label: "Errors" },
          ]}
        />
      </div>
      <Card className="overflow-hidden">
        {isLoading ? (
          <TableSkeleton rows={10} />
        ) : rows.length === 0 ? (
          <EmptyState icon={<ScrollText />} title={filter === "all" ? "No activity yet" : "No warnings or errors"}>
            {filter === "all" ? "Scans, renewals and changes appear here as they happen." : "Everything recent went through cleanly."}
          </EmptyState>
        ) : (
          <ol className="divide-y">
            {rows.map((e) => {
              const m = LEVEL[e.level as keyof typeof LEVEL] ?? LEVEL.info;
              const Icon = m.icon;
              return (
                <li key={e.id} className="flex items-start gap-4 px-6 py-4 text-sm">
                  <Icon className={cn("mt-1 size-4 shrink-0", m.className)} aria-label={m.label} />
                  <div className="min-w-0 flex-1">
                    <p className="break-words">
                      {e.name && <span className="font-medium">{e.name} </span>}
                      <span className={e.level === "info" ? "text-muted-foreground" : m.className}>{e.message}</span>
                    </p>
                    {e.renewal_id && <p className="mt-1 text-xs text-muted-foreground">Renewal #{e.renewal_id}</p>}
                  </div>
                  <time className="shrink-0 text-right text-xs text-muted-foreground" dateTime={e.at} title={fmtDateTime(e.at)}>
                    {relativeTime(e.at)}
                  </time>
                </li>
              );
            })}
          </ol>
        )}
      </Card>
    </>
  );
}

/** Integrity of the hash-chained log, and the exports auditors ask for. */
function AuditActions() {
  const { data, error } = useAuditStatus();
  return (
    <>
      {data && (
        <Badge tone={data.ok ? "good" : "critical"} title={data.head ? `Chain head ${data.head}` : undefined}>
          {data.ok ? <ShieldCheck /> : <ShieldAlert />}
          {data.ok ? `Log intact · ${data.sealed} sealed` : `Log altered at event ${data.first_bad_id}`}
        </Badge>
      )}
      {!error && (
        <>
          <Button asChild size="sm" variant="secondary">
            <a href={api.auditExportUrl()} download>
              <Download /> Audit log
            </a>
          </Button>
          <Button asChild size="sm" variant="secondary">
            <a href={api.complianceCsvUrl()} download>
              <Download /> Compliance report
            </a>
          </Button>
        </>
      )}
    </>
  );
}
