import type { ForecastRow } from "@/lib/types";
import { fmtInt } from "@/lib/utils";

/**
 * Renewals per working day at each CA/B Forum step. Single series, so no legend:
 * the title names it. Horizontal bars with direct labels; the step in force is marked.
 */
export function ForecastChart({ rows, current }: { rows: ForecastRow[]; current?: string }) {
  const max = Math.max(1, ...rows.map((r) => r.per_working_day));
  return (
    <ul className="space-y-4">
      {rows.map((r) => {
        const active = r.on === current;
        return (
          <li key={r.on} className="grid grid-cols-[5.5rem_1fr] items-center gap-4 sm:grid-cols-[7rem_1fr]">
            <div className="leading-tight">
              <p className="tabular text-[13px] font-medium">{r.lifetime_days}-day certs</p>
              <p className="tabular text-xs text-muted-foreground">
                from {new Date(r.on).toLocaleDateString("en-US", { month: "short", year: "numeric", timeZone: "UTC" })}
              </p>
            </div>
            <div className="flex items-center gap-2">
              <div
                className="h-5 rounded-r-[4px]"
                style={{
                  width: `${Math.max(2, (r.per_working_day / max) * 82)}%`,
                  background: "var(--series-auto)",
                  opacity: !current || active ? 1 : 0.55,
                }}
              />
              <span className="tabular whitespace-nowrap text-[13px] font-medium">
                {r.per_working_day}
                <span className="font-normal text-muted-foreground">/day</span>
              </span>
              {active && (
                <span className="rounded-full bg-brand-soft px-2 py-px text-[10px] font-medium text-brand-ink">now</span>
              )}
            </div>
          </li>
        );
      })}
    </ul>
  );
}

export function ForecastTable({ rows }: { rows: ForecastRow[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="tabular w-full text-[13px]">
        <thead>
          <tr className="border-b text-left text-xs text-muted-foreground">
            <th className="py-2 pr-4 font-medium">From</th>
            <th className="py-2 pr-4 text-right font-medium">Max life</th>
            <th className="py-2 pr-4 text-right font-medium">Renew every</th>
            <th className="py-2 pr-4 text-right font-medium">Per year</th>
            <th className="py-2 pr-4 text-right font-medium">Per work day</th>
            <th className="py-2 pr-4 text-right font-medium">Manual h/yr</th>
            <th className="py-2 text-right font-medium">FTE</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.on} className="border-b last:border-0">
              <td className="py-2 pr-4">{r.on}</td>
              <td className="py-2 pr-4 text-right">{r.lifetime_days}d</td>
              <td className="py-2 pr-4 text-right">{r.interval_days}d</td>
              <td className="py-2 pr-4 text-right">{fmtInt(r.renewals_per_year)}</td>
              <td className="py-2 pr-4 text-right">{r.per_working_day}</td>
              <td className="py-2 pr-4 text-right">{fmtInt(r.manual_hours_per_year)}</td>
              <td className="py-2 text-right font-medium">{r.manual_fte}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
