import Link from "next/link";
import { Card } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/misc";
import { cn } from "@/lib/utils";

type Tone = "default" | "good" | "warning" | "serious" | "critical";

// one colour code across the dashboard: blue = brand/primary, green = good, amber = warning, red = critical
const TONE_BADGE: Record<Tone, string> = {
  default: "bg-brand-soft text-brand-ink",
  good: "bg-good/12 text-good-fg",
  warning: "bg-warning/15 text-warning-fg",
  serious: "bg-serious/15 text-serious-fg",
  critical: "bg-critical/12 text-critical-fg",
};

const TONE_TEXT: Record<Tone, string> = {
  default: "text-muted-foreground",
  good: "text-good-fg",
  warning: "text-warning-fg",
  serious: "text-serious-fg",
  critical: "text-critical-fg",
};

/**
 * KPI tile: label, hero number, one line of context. Colour appears only as a status
 * (icon + text) when something needs attention — a calm dashboard is a healthy one.
 */
export function StatTile({
  label,
  value,
  icon: Icon,
  tone = "default",
  footer,
  href,
  loading,
}: {
  label: string;
  value: React.ReactNode;
  icon?: React.ElementType;
  tone?: Tone;
  footer?: React.ReactNode;
  href?: string;
  loading?: boolean;
}) {
  const alert = tone !== "default" && tone !== "good";
  const body = (
    <Card className={cn("h-full p-4 transition-[transform,box-shadow]", href && "hover:-translate-y-0.5 hover:shadow-md motion-reduce:hover:translate-y-0")}>
      <div className="flex items-start justify-between gap-2">
        <p className="text-sm text-muted-foreground">{label}</p>
        {Icon && (
          <span className={cn("flex size-8 shrink-0 items-center justify-center rounded-lg", TONE_BADGE[tone])} aria-hidden>
            <Icon className="size-4" />
          </span>
        )}
      </div>
      {loading ? (
        <Skeleton className="mt-2 h-9 w-16" />
      ) : (
        <p className="tabular text-3xl font-semibold tracking-tight">{value}</p>
      )}
      {footer && (
        <p className={cn("mt-1 flex items-center gap-2 text-xs", alert ? TONE_TEXT[tone] : "text-muted-foreground")}>
          {alert && Icon && <Icon className="size-3.5 shrink-0" aria-hidden />}
          {footer}
        </p>
      )}
    </Card>
  );
  return href ? (
    <Link href={href} className="block rounded-lg">
      {body}
    </Link>
  ) : (
    body
  );
}

/** Two-segment proportion bar (automated vs manual). */

export function TableSkeleton({ rows = 6 }: { rows?: number }) {
  return (
    <div role="status" aria-label="Loading" className="divide-y">
      <div className="flex gap-6 px-6 py-4">
        {[28, 16, 16, 20].map((w, i) => (
          <Skeleton key={i} className="h-3" style={{ width: `${w}%` }} />
        ))}
      </div>
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="flex items-center gap-6 px-6 py-4">
          <div className="w-[28%] space-y-2">
            <Skeleton className="h-4 w-4/5" />
            <Skeleton className="h-3 w-1/2" />
          </div>
          <Skeleton className="h-6 w-[16%] rounded-full" />
          <Skeleton className="h-4 w-[16%]" />
          <Skeleton className="ml-auto h-8 w-20" />
        </div>
      ))}
    </div>
  );
}
