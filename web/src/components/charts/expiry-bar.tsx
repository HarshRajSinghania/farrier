import { AlertOctagon, AlertTriangle, CircleDashed, Clock, ShieldCheck } from "lucide-react";
import type { ExpiryBucket } from "@/lib/types";

const BUCKETS: { key: ExpiryBucket; label: string; color: string; icon: React.ElementType }[] = [
  { key: "expired", label: "Expired", color: "var(--status-critical)", icon: AlertOctagon },
  { key: "7d", label: "< 7 days", color: "var(--status-serious)", icon: AlertTriangle },
  { key: "30d", label: "< 30 days", color: "var(--status-warning)", icon: Clock },
  { key: "90d", label: "< 90 days", color: "var(--status-good)", icon: ShieldCheck },
  { key: "later", label: "90+ days", color: "color-mix(in oklab, var(--status-good) 45%, var(--card))", icon: ShieldCheck },
  { key: "unknown", label: "No cert seen", color: "var(--status-neutral)", icon: CircleDashed },
];

/** Segmented status bar: one row, 2px gaps, every colour labelled with icon + text. */
export function ExpiryBar({ expiry }: { expiry: Partial<Record<ExpiryBucket, number>> }) {
  const total = BUCKETS.reduce((s, b) => s + (expiry[b.key] ?? 0), 0) || 1;
  const shown = BUCKETS.filter((b) => (expiry[b.key] ?? 0) > 0);
  return (
    <div>
      <div className="flex h-2.5 w-full gap-1 overflow-hidden rounded-full" role="img" aria-label="Certificates by time to expiry">
        {shown.map((b) => (
          <div
            key={b.key}
            title={`${b.label}: ${expiry[b.key]}`}
            style={{ width: `${((expiry[b.key] ?? 0) / total) * 100}%`, background: b.color }}
          />
        ))}
      </div>
      <dl className="mt-4 grid grid-cols-2 gap-x-4 gap-y-4 sm:grid-cols-3">
        {BUCKETS.map((b) => {
          const Icon = b.icon;
          return (
            <div key={b.key} className="flex items-center gap-2">
              <span className="flex size-6 items-center justify-center rounded-md" style={{ background: `color-mix(in oklab, ${b.color} 16%, transparent)` }}>
                <Icon className="size-3.5" style={{ color: b.color }} aria-hidden />
              </span>
              <div className="leading-tight">
                <dd className="tabular text-sm font-semibold">{expiry[b.key] ?? 0}</dd>
                <dt className="text-xs text-muted-foreground">{b.label}</dt>
              </div>
            </div>
          );
        })}
      </dl>
    </div>
  );
}
