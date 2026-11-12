import { cva, type VariantProps } from "class-variance-authority";
import { Slot } from "radix-ui";
import { cn } from "@/lib/utils";

export const buttonVariants = cva(
  "inline-flex shrink-0 items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium transition-colors disabled:pointer-events-none disabled:opacity-50 [&_svg]:size-4 [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        primary: "bg-brand text-brand-foreground shadow-sm hover:bg-brand-hover",
        secondary: "border bg-card text-foreground shadow-xs hover:bg-muted",
        ghost: "text-muted-foreground hover:bg-muted hover:text-foreground",
        inverted: "bg-foreground text-background hover:bg-foreground/90",
        danger: "bg-critical text-white hover:bg-critical/90",
        link: "h-auto px-0 text-brand-ink underline-offset-4 hover:underline",
      },
      size: {
        sm: "h-8 px-4 text-sm",
        md: "h-9 px-4",
        lg: "h-11 px-6 text-base",
        icon: "size-9",
        "icon-sm": "size-8",
      },
    },
    defaultVariants: { variant: "primary", size: "md" },
  },
);

type ButtonProps = React.ComponentProps<"button"> &
  VariantProps<typeof buttonVariants> & { asChild?: boolean };

export function Button({ className, variant, size, asChild, ...props }: ButtonProps) {
  const Comp = asChild ? Slot.Root : "button";
  return <Comp className={cn(buttonVariants({ variant, size }), className)} {...props} />;
}
