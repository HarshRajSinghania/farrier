"use client";

import Link from "next/link";
import { useMemo } from "react";
import { AlertOctagon, ArrowRight, CalendarClock, Hand, Server, ShieldAlert } from "lucide-react";
import { Legend, StackedBars } from "@/components/charts/stacked-bars";
import { ErrorNotice, PageHeader } from "@/components/dashboard/shell";
import { RenewalActions } from "@/components/dashboard/renewal-actions";
import { CertificateHealth } from "@/components/dashboard/certificate-health";
import { SetupChecklist } from "@/components/dashboard/setup-checklist";
import { RunCycle } from "@/components/dashboard/topbar";
import { StatTile } from "@/components/dashboard/widgets";
import { CONNECTOR_LABEL, StateBadge } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState, Skeleton } from "@/components/ui/misc";
import { useEvents, useRenewals, useSummary } from "@/lib/api";
import { cn, relativeTime } from "@/lib/utils";

const CAL_SERIES = [
  { key: "auto" as const, label: "Automated", color: "var(--series-auto)" },
  { key: "manual" as const, label: "Manual", color: "var(--series-manual)" },
  { key: "projected_auto" as const, label: "Projected automated", color: "var(--series-auto)", faint: true },
  { key: "projected_manual" as const, label: "Projected manual", color: "var(--series-manual)", faint: true },
];

export default function OverviewPage() {
  const { data: s, error, isLoading } = useSummary();
  const { data: queue } = useRenewals("awaiting_manual,failed,rolled_back");
  const { data: events } = useEvents(8);

  const calendar = useMemo(
    () =>
      (s?.calendar ?? []).map((d) => {
        const dt = new Date(d.date + "T00:00:00Z");
        return {
          ...d,
          label: dt.toLocaleDateString("en-US", { weekday: "short", month: "short", day: "numeric", timeZone: "UTC" }),
          sub: dt.toLocaleDateString("en-US", { month: "short", day: "numeric", timeZone: "UTC" }),
        };
      }),
    [s?.calendar],
  );

  const nextStep = s?.policy.schedule.find((p) => p.from > s.now.slice(0, 10));
  const soon = (s?.expiry.expired ?? 0) + (s?.expiry["7d"] ?? 0) + (s?.expiry["30d"] ?? 0);
  const open = Object.entries(s?.renewal_states ?? {})
    .filter(([k]) => ["planned", "issued", "deploying", "verifying"].includes(k))
    .reduce((n, [, v]) => n + (v ?? 0), 0);

  return (
    <>
      <PageHeader
        title="Overview"
        description={
          s ? (
            <>
              Public TLS certificates max out at <strong className="text-foreground">{s.policy.max_lifetime_days} days</strong> today
              {nextStep && (
                <>
                  , and {nextStep.days} days from{" "}
                  {new Date(nextStep.from).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric", timeZone: "UTC" })}
                </>
              )}
              .
            </>
          ) : (
            "Your certificate estate at a glance."
          )
        }
        actions={<RunCycle />}
      />
      <ErrorNotice error={error} />
      <SetupChecklist />

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatTile
          label="Endpoints"
          icon={Server}
          value={s?.endpoints ?? "—"}
          loading={isLoading}
          href="/dashboard/endpoints"
          footer={s && <span>{Math.round((s.automated / Math.max(1, s.endpoints)) * 100)}% automated</span>}
        />
        <StatTile
          label="Expiring ≤ 30 days"
          icon={ShieldAlert}
          tone={(s?.expiry.expired ?? 0) > 0 ? "critical" : soon > 0 ? "warning" : "good"}
          value={soon}
          loading={isLoading}
          href="/dashboard/endpoints?expiring=1"
          footer={s && <span>{s.expiry.expired ?? 0} already expired</span>}
        />
        <StatTile
          label="Awaiting a human"
          icon={Hand}
          tone={(s?.awaiting_manual ?? 0) > 0 ? "warning" : "default"}
          value={s?.awaiting_manual ?? "—"}
          loading={isLoading}
          href="/dashboard/renewals?state=awaiting_manual"
          footer={<span>Change packs ready to install</span>}
        />
        <StatTile
          label="Needs attention"
          icon={AlertOctagon}
          tone={(s?.attention ?? 0) > 0 ? "critical" : "good"}
          value={s?.attention ?? "—"}
          loading={isLoading}
          href="/dashboard/renewals?state=failed,rolled_back"
          footer={<span>Failed or rolled back · {open} in flight</span>}
        />
      </div>

      <CertificateHealth />


      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <div>
              <CardTitle>Needs you</CardTitle>
              <CardDescription>Manual installs waiting on a change window, and renewals that failed or rolled back.</CardDescription>
            </div>
            <Button asChild variant="ghost" size="sm">
              <Link href="/dashboard/renewals">
                All renewals <ArrowRight />
              </Link>
            </Button>
          </CardHeader>
          <div className="mt-4">
            {!queue ? (
              <div className="space-y-2 p-6">
                <Skeleton className="h-10" />
                <Skeleton className="h-10" />
              </div>
            ) : queue.length === 0 ? (
              <EmptyState icon={<CalendarClock />} title="Nothing waiting on you">
                Automated renewals run on their own. Manual ones will show up here with a change pack.
              </EmptyState>
            ) : (
              <ul className="divide-y border-t">
                {queue.slice(0, 6).map((r) => (
                  <li key={r.id} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-6 py-4">
                    <div className="min-w-0 flex-1 max-sm:basis-full">
                      <p className="truncate text-sm font-medium">{r.name}</p>
                      <p className="truncate text-xs text-muted-foreground">
                        {r.error ?? (r.ticket_ref ? `Ticket ${r.ticket_ref}` : r.host)} · {CONNECTOR_LABEL[r.connector] ?? r.connector}
                      </p>
                    </div>
                    <StateBadge state={r.state} />
                    <RenewalActions renewal={r} compact />
                  </li>
                ))}
              </ul>
            )}
          </div>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Recent activity</CardTitle>
            <Button asChild variant="ghost" size="sm">
              <Link href="/dashboard/activity">
                View all <ArrowRight />
              </Link>
            </Button>
          </CardHeader>
          <ul className="mt-4 divide-y border-t">
            {(events ?? []).map((e) => (
              <li key={e.id} className="flex items-start gap-4 px-6 py-2 text-sm">
                <span
                  aria-hidden
                  className={cn(
                    "mt-2 size-1.5 shrink-0 rounded-full",
                    e.level === "error" ? "bg-critical" : e.level === "warning" || e.level === "warn" ? "bg-warning" : "bg-neutral-status",
                  )}
                />
                <div className="min-w-0 flex-1">
                  <p className="truncate">
                    {e.name && <span className="font-medium">{e.name} </span>}
                    <span className="text-muted-foreground">{e.message}</span>
                  </p>
                </div>
                <time className="shrink-0 text-xs text-muted-foreground" dateTime={e.at}>
                  {relativeTime(e.at)}
                </time>
              </li>
            ))}
          </ul>
        </Card>
      </div>

      <div className="mt-4">
        <Card>
          <CardHeader>
            <div>
              <CardTitle>Renewal calendar</CardTitle>
              <CardDescription>Next 90 days: scheduled renewals and projected due dates, leveled into change windows.</CardDescription>
            </div>
          </CardHeader>
          <CardContent className="pt-4">
            {isLoading ? <Skeleton className="h-[220px] w-full" /> : <StackedBars data={calendar} series={CAL_SERIES} ariaLabel="Renewals per day over the next 90 days" />}
            <div className="mt-4">
              <Legend items={CAL_SERIES} />
            </div>
          </CardContent>
        </Card>

      </div>
    </>
  );
}
