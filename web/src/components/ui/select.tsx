"use client";

import { Check, ChevronDown, ChevronUp } from "lucide-react";
import { Select as S } from "radix-ui";
import { cn } from "@/lib/utils";

export type SelectOption = {
  value: string;
  label: React.ReactNode;
  /** a second line under the label, e.g. a host or a hint; not shown in the closed trigger */
  description?: React.ReactNode;
  disabled?: boolean;
};

/**
 * The app's select: keyboard, type-ahead and screen-reader behaviour from Radix, styled like the
 * other fields. The menu matches the trigger's width, never runs off screen (it caps to the space
 * available and scrolls), and gives touch screens taller rows.
 */
export function Select({
  id,
  value,
  onValueChange,
  options,
  placeholder = "Select…",
  disabled,
  className,
  "aria-label": ariaLabel,
  "aria-invalid": ariaInvalid,
}: {
  id?: string;
  /** "" shows the placeholder (Radix reserves the empty string) */
  value: string;
  onValueChange: (value: string) => void;
  options: SelectOption[];
  placeholder?: string;
  disabled?: boolean;
  className?: string;
  "aria-label"?: string;
  "aria-invalid"?: boolean;
}) {
  return (
    <S.Root value={value === "" ? undefined : value} onValueChange={onValueChange} disabled={disabled}>
      <S.Trigger
        id={id}
        aria-label={ariaLabel}
        aria-invalid={ariaInvalid || undefined}
        className={cn(
          "flex h-9 w-full min-w-0 items-center justify-between gap-2 rounded-md border border-input bg-background px-4 text-left text-sm shadow-xs transition-colors",
          "focus-visible:border-ring focus-visible:outline-none focus-visible:ring-3 focus-visible:ring-ring/20 disabled:opacity-50",
          "aria-[invalid=true]:border-critical data-[placeholder]:text-muted-foreground [&>span]:truncate",
          className,
        )}
      >
        <S.Value placeholder={placeholder} />
        <S.Icon asChild>
          <ChevronDown className="size-4 shrink-0 opacity-60" />
        </S.Icon>
      </S.Trigger>
      <S.Portal>
        <S.Content
          position="popper"
          sideOffset={4}
          collisionPadding={8}
          className="z-50 max-h-[min(20rem,var(--radix-select-content-available-height))] w-[var(--radix-select-trigger-width)] min-w-40 overflow-hidden rounded-lg border bg-popover text-popover-foreground shadow-lg animate-fade-in"
        >
          <S.ScrollUpButton className="flex h-6 items-center justify-center text-muted-foreground">
            <ChevronUp className="size-4" />
          </S.ScrollUpButton>
          <S.Viewport className="p-1">
            {options.map((o) => (
              <S.Item
                key={o.value}
                value={o.value}
                disabled={o.disabled}
                className="relative flex min-h-11 cursor-default select-none items-center rounded-md py-2 pl-8 pr-2 text-sm outline-none data-[disabled]:pointer-events-none data-[highlighted]:bg-muted data-[disabled]:opacity-50 sm:min-h-9"
              >
                <S.ItemIndicator className="absolute left-2 inline-flex">
                  <Check className="size-4" />
                </S.ItemIndicator>
                <span className="min-w-0">
                  <S.ItemText>{o.label}</S.ItemText>
                  {o.description && <span className="block truncate text-xs text-muted-foreground">{o.description}</span>}
                </span>
              </S.Item>
            ))}
          </S.Viewport>
          <S.ScrollDownButton className="flex h-6 items-center justify-center text-muted-foreground">
            <ChevronDown className="size-4" />
          </S.ScrollDownButton>
        </S.Content>
      </S.Portal>
    </S.Root>
  );
}
