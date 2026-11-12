"use client";

import { useId, useLayoutEffect, useMemo, useRef, useState } from "react";
import { cn } from "@/lib/utils";

export interface Series<K extends string> {
  key: K;
  label: string;
  color: string;
  /** Projected/forecast segments render as a lighter tint of the same hue. */
  faint?: boolean;
}

interface Props<K extends string, D extends { [P in K]: number }> {
  data: (D & { label: string; sub?: string })[];
  series: Series<K>[];
  height?: number;
  /** Show an x tick every N bars. */
  tickEvery?: number;
  ariaLabel: string;
  className?: string;
}

function useWidth<T extends HTMLElement>() {
  const ref = useRef<T>(null);
  const [w, setW] = useState(0);
  useLayoutEffect(() => {
    if (!ref.current) return;
    const ro = new ResizeObserver(([e]) => setW(Math.floor(e.contentRect.width)));
    ro.observe(ref.current);
    return () => ro.disconnect();
  }, []);
  return [ref, w] as const;
}

const niceMax = (v: number) => {
  if (v <= 4) return 4;
  const p = 10 ** Math.floor(Math.log10(v));
  return Math.ceil(v / (p / 2)) * (p / 2);
};

/**
 * Stacked vertical bars with a per-bar hover tooltip.
 * Marks: 2px surface gap between segments, 4px rounded top on the stack,
 * square baseline, recessive gridlines, one axis.
 */
export function StackedBars<K extends string, D extends { [P in K]: number }>({
  data,
  series,
  height = 220,
  tickEvery = 7,
  ariaLabel,
  className,
}: Props<K, D>) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const [hover, setHover] = useState<number | null>(null);
  const clipBase = useId().replace(/:/g, "");

  const pad = { top: 8, right: 4, bottom: 22, left: 28 };
  const innerW = Math.max(0, width - pad.left - pad.right);
  const innerH = height - pad.top - pad.bottom;
  const totals = useMemo(() => data.map((d) => series.reduce((s, x) => s + (d[x.key] as number), 0)), [data, series]);
  const max = niceMax(Math.max(1, ...totals));
  const slot = data.length ? innerW / data.length : 0;
  const barW = Math.max(2, Math.min(18, slot - 2));
  const y = (v: number) => (v / max) * innerH;
  const ticks = [0, max / 2, max];

  return (
    <div ref={ref} className={cn("relative w-full", className)} style={{ height }}>
      {width > 0 && (
        <svg width={width} height={height} role="img" aria-label={ariaLabel} onMouseLeave={() => setHover(null)}>
          <g transform={`translate(${pad.left},${pad.top})`}>
            {ticks.map((t) => (
              <g key={t} transform={`translate(0,${innerH - y(t)})`}>
                <line x2={innerW} stroke={t === 0 ? "var(--chart-axis)" : "var(--chart-grid)"} />
                <text x={-8} dy="0.32em" textAnchor="end" className="tabular fill-muted-foreground text-[10px]">
                  {Number.isInteger(t) ? t : t.toFixed(1)}
                </text>
              </g>
            ))}
            {data.map((d, i) => {
              const x = i * slot + (slot - barW) / 2;
              let acc = 0;
              const total = totals[i];
              const clip = `${clipBase}-${i}`;
              return (
                <g key={d.label} opacity={hover === null || hover === i ? 1 : 0.45}>
                  {total > 0 && (
                    <clipPath id={clip}>
                      {/* rounded top, square baseline */}
                      <path
                        d={`M${x},${innerH} V${innerH - y(total) + 3} q0,-3 3,-3 h${barW - 6} q3,0 3,3 V${innerH} Z`}
                      />
                    </clipPath>
                  )}
                  <g clipPath={total > 0 ? `url(#${clip})` : undefined}>
                    {series.map((s) => {
                      const v = d[s.key] as number;
                      if (!v) return null;
                      const h = y(v);
                      const top = innerH - y(acc) - h;
                      acc += v;
                      // 2px surface gap above every segment except the top one
                      const gap = acc < total ? 2 : 0;
                      return (
                        <rect
                          key={s.key}
                          x={x}
                          y={top + gap}
                          width={barW}
                          height={Math.max(0, h - gap)}
                          fill={s.color}
                          fillOpacity={s.faint ? 0.35 : 1}
                        />
                      );
                    })}
                  </g>
                  {i % tickEvery === 0 && (
                    <text
                      x={x + barW / 2}
                      y={innerH + 15}
                      textAnchor="middle"
                      className="fill-muted-foreground text-[10px]"
                    >
                      {d.sub ?? d.label}
                    </text>
                  )}
                  {/* hit target wider than the mark */}
                  <rect
                    x={i * slot}
                    y={0}
                    width={slot}
                    height={innerH}
                    fill="transparent"
                    onMouseEnter={() => setHover(i)}
                  />
                </g>
              );
            })}
          </g>
        </svg>
      )}
      {hover !== null && width > 0 && (
        <div
          role="tooltip"
          className="pointer-events-none absolute top-0 z-10 min-w-40 rounded-md border bg-popover px-4 py-2 text-xs shadow-lg"
          style={{
            left: Math.min(Math.max(0, pad.left + hover * slot + slot / 2 - 80), width - 168),
          }}
        >
          <p className="mb-2 font-medium">{data[hover].label}</p>
          {series.map((s) => (
            <div key={s.key} className="flex items-center justify-between gap-4 py-1">
              <span className="flex items-center gap-2 text-muted-foreground">
                <span
                  className="size-2 rounded-[2px]"
                  style={{ background: s.color, opacity: s.faint ? 0.35 : 1 }}
                />
                {s.label}
              </span>
              <span className="tabular font-medium">{data[hover][s.key] as number}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function Legend({ items }: { items: { label: string; color: string; faint?: boolean }[] }) {
  return (
    <ul className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
      {items.map((i) => (
        <li key={i.label} className="flex items-center gap-2">
          <span className="size-2.5 rounded-[3px]" style={{ background: i.color, opacity: i.faint ? 0.35 : 1 }} />
          {i.label}
        </li>
      ))}
    </ul>
  );
}
