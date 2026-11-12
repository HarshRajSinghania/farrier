"use client";

import { useMemo, useState } from "react";
import { ForecastChart, ForecastTable } from "@/components/charts/forecast-chart";
import { Segmented } from "@/components/ui/segmented";
import { forecast, forecastTimeline, SCHEDULE } from "@/lib/policy";
import { fmtInt } from "@/lib/utils";

function Slider({
  id,
  label,
  value,
  onChange,
  min,
  max,
  step = 1,
  format = String,
}: {
  id: string;
  label: string;
  value: number;
  onChange: (v: number) => void;
  min: number;
  max: number;
  step?: number;
  format?: (v: number) => string;
}) {
  return (
    <div>
      <div className="mb-2 flex items-baseline justify-between">
        <label htmlFor={id} className="text-[13px] font-medium">
          {label}
        </label>
        <output htmlFor={id} className="tabular text-sm font-semibold">
          {format(value)}
        </output>
      </div>
      <input
        id={id}
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        className="h-2 w-full cursor-pointer accent-[var(--brand)]"
      />
    </div>
  );
}

/** Interactive `farrier forecast`. Same maths as farrier/policy.py. */
export function ForecastCalculator({
  initialCerts = 1000,
  initialManual = 0.4,
  showTable = true,
  today,
}: {
  initialCerts?: number;
  initialManual?: number;
  showTable?: boolean;
  /** ISO date used to mark the policy step in force. */
  today?: string;
}) {
  const [certs, setCerts] = useState(initialCerts);
  const [manual, setManual] = useState(Math.round(initialManual * 100));
  const [minutes, setMinutes] = useState(45);
  const [lead, setLead] = useState(0);
  const [view, setView] = useState<"chart" | "table">("chart");

  const rows = useMemo(() => forecastTimeline(certs, manual / 100, minutes, lead), [certs, manual, minutes, lead]);
  const last = rows.at(-1)!;
  const naive = useMemo(() => forecast(certs, SCHEDULE.at(-1)![0], 0, 45, 0, false), [certs]);
  const current = today ? SCHEDULE.filter(([d]) => d <= today).at(-1)?.[0] : undefined;

  return (
    <div className="grid gap-8 lg:grid-cols-[18rem_1fr]">
      <div className="space-y-6">
        <Slider id="fc-certs" label="Certificates" value={certs} onChange={setCerts} min={50} max={20000} step={50} format={fmtInt} />
        <Slider id="fc-manual" label="Installed by hand" value={manual} onChange={setManual} min={0} max={100} format={(v) => `${v}%`} />
        <Slider id="fc-min" label="Minutes per manual change" value={minutes} onChange={setMinutes} min={5} max={240} step={5} format={(v) => `${v} min`} />
        <Slider id="fc-lead" label="Change lead time" value={lead} onChange={setLead} min={0} max={30} format={(v) => `${v} days`} />
        <div className="rounded-lg border bg-muted/50 p-4">
          <p className="text-xs text-muted-foreground">By March 2029, by hand</p>
          <p className="mt-1 text-3xl font-semibold tracking-tight">{last.manual_fte} FTE</p>
          <p className="mt-1 text-xs text-muted-foreground">
            {fmtInt(last.manual_hours_per_year)} hours a year on {fmtInt(last.manual_renewals_per_year)} manual renewals
          </p>
        </div>
      </div>

      <div className="min-w-0">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-4">
          <p className="text-sm font-medium">Renewals per working day</p>
          <Segmented
            label="Display"
            value={view}
            onChange={setView}
            options={[
              { value: "chart", label: "Chart" },
              { value: "table", label: "Table" },
            ]}
          />
        </div>
        {view === "chart" || !showTable ? <ForecastChart rows={rows} current={current} /> : <ForecastTable rows={rows} />}
        <p className="mt-6 text-xs leading-relaxed text-muted-foreground">
          The often-quoted figure assumes each certificate is replaced on its expiry day: {fmtInt(naive.renewals_per_year)} a year,{" "}
          {naive.per_calendar_day} per calendar day. Renewing safely at the one-third point makes it{" "}
          <strong className="font-medium text-foreground">{last.per_working_day} per working day</strong>.
        </p>
      </div>
    </div>
  );
}
