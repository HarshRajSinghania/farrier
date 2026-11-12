import type { MDXComponents } from "mdx/types";
import Link from "next/link";
import { AlertTriangle, Info, OctagonAlert } from "lucide-react";
import { Pre } from "@/components/docs/code-block";
import { cn } from "@/lib/utils";

const CALLOUT = {
  info: { icon: Info, className: "border-series-auto/30 bg-series-auto/5 [&_svg]:text-info-fg" },
  warning: { icon: AlertTriangle, className: "border-warning/40 bg-warning/8 [&_svg]:text-warning-fg" },
  danger: { icon: OctagonAlert, className: "border-critical/30 bg-critical/5 [&_svg]:text-critical-fg" },
};

function Callout({ type = "info", title, children }: { type?: keyof typeof CALLOUT; title?: string; children: React.ReactNode }) {
  const { icon: Icon, className } = CALLOUT[type] ?? CALLOUT.info;
  return (
    <div role="note" className={cn("not-prose my-6 flex gap-4 rounded-lg border px-4 py-4 text-[14px] leading-relaxed", className)}>
      <Icon className="mt-1 size-4 shrink-0" aria-hidden />
      <div className="min-w-0 [&_a]:font-medium [&_a]:text-brand-ink [&_code]:rounded [&_code]:bg-muted [&_code]:px-1 [&_code]:font-mono [&_code]:text-[0.85em] [&_p]:my-0 [&_p+p]:mt-2">
        {title && <p className="font-semibold">{title}</p>}
        {children}
      </div>
    </div>
  );
}

const components: MDXComponents = {
  Callout,
  pre: Pre,
  a: ({ href = "", ...props }) =>
    href.startsWith("/") || href.startsWith("#") ? <Link href={href} {...props} /> : <a href={href} target="_blank" rel="noreferrer" {...props} />,
  table: (props) => (
    <div className="overflow-x-auto">
      <table {...props} />
    </div>
  ),
};

export function useMDXComponents(): MDXComponents {
  return components;
}
