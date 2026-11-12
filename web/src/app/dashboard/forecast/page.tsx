"use client";

import { PageHeader } from "@/components/dashboard/shell";
import { ForecastCalculator } from "@/components/forecast-calculator";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/misc";
import { useSummary } from "@/lib/api";

export default function ForecastPage() {
  const { data: s } = useSummary();
  return (
    <>
      <PageHeader
        title="Forecast"
        description="Renewal workload as certificate lifetimes shrink (CA/B Forum ballot SC-081). Starts from your estate; drag to plan for growth."
      />
      <Card>
        <CardContent className="p-6">
          {s ? (
            <ForecastCalculator
              key={s.endpoints}
              initialCerts={Math.max(50, s.endpoints)}
              initialManual={s.endpoints ? s.manual / s.endpoints : 0.4}
              today={s.now.slice(0, 10)}
            />
          ) : (
            <Skeleton className="h-72" />
          )}
        </CardContent>
      </Card>
      {s && (
        <Card className="mt-4">
          <CardContent className="p-0">
            <div className="grid divide-y sm:grid-cols-4 sm:divide-x sm:divide-y-0">
              {s.policy.schedule.map((p) => (
                <div key={p.from} className="p-6">
                  <p className="text-xs text-muted-foreground">
                    From{" "}
                    {new Date(p.from).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric", timeZone: "UTC" })}
                  </p>
                  <p className="mt-1 text-lg font-semibold">{p.days}-day certificates</p>
                  <p className="text-xs text-muted-foreground">Domain validation reused for {p.dcv} days</p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </>
  );
}
