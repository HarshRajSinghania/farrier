"use client";

import Link from "next/link";
import { useMemo } from "react";
import { AlertTriangle, ArrowRight, CheckCircle2, OctagonAlert } from "lucide-react";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/misc";
import { useEndpoints, useRenewals, useZombies } from "@/lib/api";
import { classify, type Severity } from "@/lib/health";
import { cn } from "@/lib/utils";


// one colour code across the dashboard: red critical, amber warning, green healthy (always with an icon and a word)
const META: Record<Severity, { label: string; icon: typeof OctagonAlert; text: string; bar: string; href: string; cta: string }> = {
  critical: { label: "Critical", icon: OctagonAlert, text: "text-critical-fg", bar: "bg-critical", href: "/dashboard/renewals?state=failed,rolled_back", cta: "Fix now" },
  warning: { label: "Warning", icon: AlertTriangle, text: "text-warning-fg", bar: "bg-warning", href: "/dashboard/endpoints?expiring=1", cta: "Review" },
  healthy: { label: "Healthy", icon: CheckCircle2, text: "text-good-fg", bar: "bg-good", href: "/dashboard/endpoints", cta: "All endpoints" },
};

export function CertificateHealth() {
  const { data: endpoints } = useEndpoints();
  const { data: renewals } = useRenewals("failed,rolled_back,awaiting_manual");
  const { data: zombies } = useZombies();
  const groups = useMemo(
    () => (endpoints && renewals ? classify(endpoints, renewals, zombies?.findings ?? []) : null),
    [endpoints, renewals, zombies],
  );
  const total = endpoints?.length ?? 0;

  return (
    <Card className="mt-4">
      <CardHeader>
        <div>
          <CardTitle>Certificate health</CardTitle>
          <CardDescription>Every endpoint, by its most urgent problem.</CardDescription>
        </div>
      </CardHeader>
      {!groups ? (
        <div className="space-y-4 p-6">
          <Skeleton className="h-2 w-full" />
          <Skeleton className="h-24 w-full" />
        </div>
      ) : (
        <div className="p-6 pt-4">
          <div className="flex h-2 gap-0.5 overflow-hidden rounded-full bg-muted" role="img"
            aria-label={`${groups.critical.length} critical, ${groups.warning.length} warning, ${groups.healthy.length} healthy`}>
            {(["critical", "warning", "healthy"] as const).map((s) =>
              groups[s].length ? <div key={s} className={META[s].bar} style={{ width: `${(groups[s].length / Math.max(1, total)) * 100}%` }} /> : null,
            )}
          </div>
          <div className="mt-6 grid gap-6 md:grid-cols-3">
            {(["critical", "warning", "healthy"] as const).map((s) => {
              const m = META[s];
              const items = groups[s];
              return (
                <section key={s} aria-labelledby={`health-${s}`} className="min-w-0">
                  <div className="flex items-baseline justify-between gap-2">
                    <h3 id={`health-${s}`} className={cn("flex items-center gap-2 text-sm font-semibold", m.text)}>
                      <m.icon className="size-4" aria-hidden /> {m.label}
                    </h3>
                    <span className="tabular text-2xl font-semibold">{items.length}</span>
                  </div>
                  {s !== "healthy" ? (
                    <ul className="mt-3 space-y-2 text-sm">
                      {items.slice(0, 3).map((i) => (
                        <li key={i.id} className="flex items-baseline justify-between gap-2">
                          <Link href={`/dashboard/endpoints/${i.id}`} className="truncate font-medium hover:underline">
                            {i.name}
                          </Link>
                          <span className="shrink-0 text-xs text-muted-foreground first-letter:uppercase">{i.reason}</span>
                        </li>
                      ))}
                      {items.length === 0 && <li className="text-muted-foreground">None</li>}
                    </ul>
                  ) : (
                    <p className="mt-3 text-sm text-muted-foreground">
                      {total ? `${Math.round((items.length / total) * 100)}% of endpoints need nothing from you.` : "No endpoints yet."}
                    </p>
                  )}
                  {items.length > 0 && (
                    <Link href={m.href} className="mt-3 inline-flex items-center gap-1 text-sm font-medium hover:underline">
                      {s === "healthy" ? m.cta : `${m.cta}${items.length > 3 ? ` · ${items.length - 3} more` : ""}`} <ArrowRight className="size-3.5" />
                    </Link>
                  )}
                </section>
              );
            })}
          </div>
        </div>
      )}
    </Card>
  );
}
