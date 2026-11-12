"use client";

import { useMemo } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { CalendarClock } from "lucide-react";
import { ErrorNotice, PageHeader } from "@/components/dashboard/shell";
import { RenewalActions } from "@/components/dashboard/renewal-actions";
import { TableSkeleton } from "@/components/dashboard/widgets";
import { CONNECTOR_LABEL, STATE_META, StateBadge } from "@/components/status";
import { Card } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/misc";
import { Segmented } from "@/components/ui/segmented";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { useRenewals } from "@/lib/api";
import type { RenewalState } from "@/lib/types";
import { cn, fmtDate, relativeTime } from "@/lib/utils";

const VIEWS = {
  open: { label: "In flight", states: ["planned", "issued", "deploying", "verifying"] },
  awaiting_manual: { label: "Awaiting human", states: ["awaiting_manual"] },
  attention: { label: "Needs attention", states: ["failed", "rolled_back"] },
  done: { label: "Done", states: ["done", "superseded", "cancelled"] },
  all: { label: "All", states: null },
} as const satisfies Record<string, { label: string; states: readonly RenewalState[] | null }>;
type View = keyof typeof VIEWS;

const PIPELINE: RenewalState[] = ["planned", "issued", "deploying", "verifying", "awaiting_manual", "done"];

function viewFromParam(p: string | null): View {
  if (!p) return "open";
  if (p in VIEWS) return p as View;
  if (p.includes("failed") || p.includes("rolled_back")) return "attention";
  return "open";
}

export function RenewalsView() {
  const params = useSearchParams();
  const router = useRouter();
  const view = viewFromParam(params.get("state"));
  const { data, error, isLoading } = useRenewals();

  const counts = useMemo(() => {
    const c: Partial<Record<RenewalState, number>> = {};
    for (const r of data ?? []) c[r.state] = (c[r.state] ?? 0) + 1;
    return c;
  }, [data]);

  const rows = useMemo(() => {
    const states = VIEWS[view].states as readonly RenewalState[] | null;
    return (data ?? []).filter((r) => !states || states.includes(r.state));
  }, [data, view]);

  const viewCount = (v: View) => {
    const states = VIEWS[v].states as readonly RenewalState[] | null;
    return states ? states.reduce((n, s) => n + (counts[s] ?? 0), 0) : (data?.length ?? 0);
  };

  return (
    <>
      <PageHeader
        title="Renewals"
        description="Each renewal walks plan → issue → deploy → verify. Manual ones wait for a human and close themselves when the new certificate is seen live."
      />
      <ErrorNotice error={error} />

      <ol className="mb-4 grid grid-cols-3 gap-px overflow-hidden rounded-lg border bg-border sm:grid-cols-6" aria-label="Renewal pipeline">
        {PIPELINE.map((s) => {
          const m = STATE_META[s];
          const Icon = m.icon;
          return (
            <li key={s} className="bg-card px-4 py-4">
              <p className="flex items-center gap-2 text-xs text-muted-foreground">
                <Icon className="size-3.5" aria-hidden /> {m.label}
              </p>
              <p className="tabular mt-1 text-xl font-semibold">{counts[s] ?? 0}</p>
            </li>
          );
        })}
      </ol>

      <div className="mb-4">
        <Segmented
          label="Filter renewals"
          value={view}
          onChange={(v) => router.replace(`?state=${v}`, { scroll: false })}
          options={(Object.keys(VIEWS) as View[]).map((v) => ({ value: v, label: VIEWS[v].label, count: viewCount(v) }))}
        />
      </div>

      <Card className="overflow-hidden">
        {isLoading ? (
          <TableSkeleton />
        ) : rows.length === 0 ? (
          <EmptyState icon={<CalendarClock />} title="No renewals here">
            Farrier plans renewals at the one-third point of a certificate&apos;s life, leveled into change windows.
          </EmptyState>
        ) : (
          <Table>
            <THead>
              <TR>
                <TH>Endpoint</TH>
                <TH>State</TH>
                <TH>Scheduled</TH>
                <TH className="hidden md:table-cell">Deadline</TH>
                <TH className="hidden lg:table-cell">Detail</TH>
                <TH className="text-right">
                  <span className="sr-only">Actions</span>
                </TH>
              </TR>
            </THead>
            <TBody>
              {rows.map((r) => (
                <TR key={r.id}>
                  <TD>
                    <p className="font-medium">{r.name}</p>
                    <p className="text-xs text-muted-foreground">
                      #{r.id} · {CONNECTOR_LABEL[r.connector] ?? r.connector}
                    </p>
                  </TD>
                  <TD>
                    <StateBadge state={r.state} />
                  </TD>
                  <TD className="text-[13px]">
                    {fmtDate(r.scheduled_for)}
                    <p className="text-xs text-muted-foreground">{relativeTime(r.scheduled_for)}</p>
                  </TD>
                  <TD className="hidden text-[13px] text-muted-foreground md:table-cell">{fmtDate(r.deadline)}</TD>
                  <TD className={cn("hidden max-w-72 truncate text-[13px] lg:table-cell", r.error ? "text-critical-fg" : "text-muted-foreground")} title={r.error ?? r.reason ?? ""}>
                    {r.error ?? (r.ticket_ref ? `Ticket ${r.ticket_ref}` : r.reason) ?? "—"}
                    {r.attempts > 0 && !r.error && <span className="ml-1">· attempt {r.attempts}</span>}
                  </TD>
                  <TD className="text-right">
                    <div className="flex justify-end">
                      <RenewalActions renewal={r} />
                    </div>
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </Card>
    </>
  );
}
