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
      className={cn("flex max-w-full gap-6 overflow-x-auto overflow-y-hidden border-b", className)}
    >
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          role="radio"
          aria-checked={value === o.value}
          onClick={() => onChange(o.value)}
          className={cn(
            "-mb-px inline-flex h-10 shrink-0 items-center gap-2 border-b-2 border-transparent text-sm font-medium text-muted-foreground transition-colors hover:text-foreground",
            value === o.value && "border-foreground text-foreground",
          )}
        >
          {o.label}
          {o.count !== undefined && (
            <span className="tabular rounded-full bg-muted px-2 text-xs leading-5 text-foreground">{o.count}</span>
          )}
        </button>
      ))}
    </div>
  );
}
