"use client";

import { cn } from "@/lib/utils";

/** Compact tab-like filter. Sits in one row above the content it filters. */
export function Segmented<T extends string>({
  value,
  onChange,
  options,
  className,
  label,
}: {
  value: T;
  onChange: (v: T) => void;
  options: { value: T; label: React.ReactNode; count?: number }[];
  className?: string;
  label: string;
}) {
  return (
    <div
      role="radiogroup"
      aria-label={label}
      className={cn("inline-flex max-w-full overflow-x-auto rounded-lg border bg-muted p-1", className)}
    >
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          role="radio"
          aria-checked={value === o.value}
          onClick={() => onChange(o.value)}
          className={cn(
            "inline-flex h-7 shrink-0 items-center gap-2 rounded-md px-2 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground",
            value === o.value && "bg-card text-foreground shadow-xs",
          )}
        >
          {o.label}
          {o.count !== undefined && <span className="tabular text-xs text-muted-foreground">{o.count}</span>}
        </button>
      ))}
    </div>
  );
}
