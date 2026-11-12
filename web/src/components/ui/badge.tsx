import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

export const badgeVariants = cva(
  "inline-flex items-center gap-2 whitespace-nowrap rounded-full border px-2 py-1 text-xs font-medium [&_svg]:size-3",
  {
    variants: {
      tone: {
        neutral: "border-border bg-muted text-muted-foreground",
        brand: "border-transparent bg-brand-soft text-brand-ink",
        good: "border-transparent bg-good/12 text-good-fg",
        warning: "border-transparent bg-warning/15 text-warning-fg",
        serious: "border-transparent bg-serious/15 text-serious-fg",
        critical: "border-transparent bg-critical/12 text-critical-fg",
        info: "border-transparent bg-info-fg/10 text-info-fg",
        outline: "bg-transparent text-muted-foreground",
      },
    },
    defaultVariants: { tone: "neutral" },
  },
);

export type BadgeTone = NonNullable<VariantProps<typeof badgeVariants>["tone"]>;

export function Badge({
  className,
  tone,
  ...props
}: React.ComponentProps<"span"> & VariantProps<typeof badgeVariants>) {
  return <span className={cn(badgeVariants({ tone }), className)} {...props} />;
}
