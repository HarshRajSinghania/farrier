import { cn } from "@/lib/utils";

const field =
  "h-9 w-full rounded-md border border-input bg-background px-4 text-sm shadow-xs transition-colors placeholder:text-muted-foreground/70 focus-visible:border-ring focus-visible:outline-none focus-visible:ring-3 focus-visible:ring-ring/20 disabled:opacity-50";

export function Input({ className, ...props }: React.ComponentProps<"input">) {
  return <input className={cn(field, className)} {...props} />;
}

export function Textarea({ className, ...props }: React.ComponentProps<"textarea">) {
  return <textarea className={cn(field, "h-auto min-h-20 py-2 font-mono text-sm", className)} {...props} />;
}

export function Label({ className, ...props }: React.ComponentProps<"label">) {
  return <label className={cn("text-sm font-medium", className)} {...props} />;
}

export function FieldHint({ className, ...props }: React.ComponentProps<"p">) {
  return <p className={cn("text-xs text-muted-foreground", className)} {...props} />;
}
