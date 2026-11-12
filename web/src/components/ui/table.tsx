import { cn } from "@/lib/utils";

export function Table({ className, ...props }: React.ComponentProps<"table">) {
  return (
    <div className="relative w-full overflow-x-auto">
      <table className={cn("w-full caption-bottom text-sm", className)} {...props} />
    </div>
  );
}

export const THead = ({ className, ...p }: React.ComponentProps<"thead">) => (
  <thead className={cn("[&_tr]:border-b [&_tr]:hover:bg-transparent", className)} {...p} />
);

export const TBody = ({ className, ...p }: React.ComponentProps<"tbody">) => (
  <tbody className={cn("[&_tr:last-child]:border-0", className)} {...p} />
);

export const TR = ({ className, ...p }: React.ComponentProps<"tr">) => (
  <tr className={cn("border-b transition-colors hover:bg-muted/50", className)} {...p} />
);

export const TH = ({ className, ...p }: React.ComponentProps<"th">) => (
  <th
    className={cn(
      "h-9 whitespace-nowrap px-4 text-left align-middle text-xs font-medium text-muted-foreground first:pl-6 last:pr-6",
      className,
    )}
    {...p}
  />
);

export const TD = ({ className, ...p }: React.ComponentProps<"td">) => (
  <td className={cn("whitespace-nowrap px-4 py-2 align-middle first:pl-6 last:pr-6", className)} {...p} />
);
