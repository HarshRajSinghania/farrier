"use client";

import { DropdownMenu as M } from "radix-ui";
import { cn } from "@/lib/utils";

export const Dropdown = M.Root;
export const DropdownTrigger = M.Trigger;

export function DropdownContent({ className, ...props }: React.ComponentProps<typeof M.Content>) {
  return (
    <M.Portal>
      <M.Content
        sideOffset={6}
        align="end"
        className={cn(
          "z-50 min-w-44 rounded-lg border bg-popover p-1 shadow-lg data-[state=open]:animate-fade-in",
          className,
        )}
        {...props}
      />
    </M.Portal>
  );
}

export function DropdownItem({
  className,
  danger,
  ...props
}: React.ComponentProps<typeof M.Item> & { danger?: boolean }) {
  return (
    <M.Item
      className={cn(
        "flex cursor-default select-none items-center gap-2 rounded-md px-2 py-2 text-sm outline-none data-[disabled]:pointer-events-none data-[highlighted]:bg-muted data-[disabled]:opacity-50 [&_svg]:size-4 [&_svg]:text-muted-foreground",
        danger && "text-critical-fg [&_svg]:text-critical-fg",
        className,
      )}
      {...props}
    />
  );
}

export const DropdownSeparator = () => <M.Separator className="my-1 h-px bg-border" />;
