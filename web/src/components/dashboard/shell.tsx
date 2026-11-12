"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import {
  Activity,
  BookOpen,
  CalendarClock,
  Gauge,

  LayoutDashboard,
  Plug,
  Radar,
  Server,
  Settings,
  ShieldCheck,
  X,
} from "lucide-react";
import { GithubIcon, Logo, ThemeToggle } from "@/components/brand";
import { Button } from "@/components/ui/button";
import { Topbar } from "@/components/dashboard/topbar";
import { useStatus, useSummary } from "@/lib/api";
import { site } from "@/lib/site";
import { cn } from "@/lib/utils";

// Chunked into small labelled groups (Miller / Hick): operators scan 2–4 items, not 8.
const NAV = [
  {
    group: "Operate",
    items: [
      { href: "/dashboard", label: "Overview", icon: LayoutDashboard },
      { href: "/dashboard/renewals", label: "Renewals", icon: CalendarClock, badge: true },
      { href: "/dashboard/endpoints", label: "Endpoints", icon: Server },
      { href: "/dashboard/discovery", label: "Discovery", icon: Radar },
    ],
  },
  {
    group: "Insights",
    items: [
      { href: "/dashboard/forecast", label: "Forecast", icon: Gauge },
      { href: "/dashboard/health", label: "Health", icon: ShieldCheck },
      { href: "/dashboard/activity", label: "Activity", icon: Activity },
    ],
  },
  {
    group: "Configure",
    items: [
      { href: "/dashboard/connectors", label: "Connectors", icon: Plug },
      { href: "/dashboard/settings", label: "Settings", icon: Settings },
    ],
  },
];

function Nav({ onNavigate }: { onNavigate?: () => void }) {
  const path = usePathname();
  const { data } = useSummary();
  const pending = (data?.awaiting_manual ?? 0) + (data?.attention ?? 0);
  return (
    <nav className="flex flex-col gap-4" aria-label="Dashboard">
      {NAV.map(({ group, items }) => (
        <div key={group}>
          <p className="mb-1 px-2 text-[11px] font-medium uppercase tracking-wider text-muted-foreground/80">{group}</p>
          <div className="flex flex-col gap-1">
            {items.map(({ href, label, icon: Icon, badge }) => {
              const active = href === "/dashboard" ? path === href : path.startsWith(href);
              return (
                <Link
                  key={href}
                  href={href}
                  onClick={onNavigate}
                  aria-current={active ? "page" : undefined}
                  className={cn(
                    "flex h-9 items-center gap-2 rounded-md px-2 text-[13px] font-medium text-muted-foreground transition-colors hover:bg-muted hover:text-foreground lg:h-8",
                    active && "bg-muted text-foreground",
                  )}
                >
                  <Icon className="size-4" />
                  {label}
                  {badge && pending > 0 && (
                    <span
                      className="tabular ml-auto rounded-full bg-warning/20 px-2 text-[11px] text-warning-fg"
                      aria-label={`${pending} need attention`}
                    >
                      {pending}
                    </span>
                  )}
                </Link>
              );
            })}
          </div>
        </div>
      ))}
    </nav>
  );
}

function SidebarFooter() {
  return (
    <div className="mt-auto space-y-1 border-t pt-4">
      <Link
        href="/docs"
        className="flex h-8 items-center gap-2 rounded-md px-2 text-[13px] text-muted-foreground hover:bg-muted hover:text-foreground"
      >
        <BookOpen className="size-4" /> Documentation
      </Link>
      <a
        href={site.github}
        target="_blank"
        rel="noreferrer"
        className="flex h-8 items-center gap-2 rounded-md px-2 text-[13px] text-muted-foreground hover:bg-muted hover:text-foreground"
      >
        <GithubIcon className="size-4" /> GitHub
      </a>
      <div className="flex items-center justify-between px-2 pt-2">
        <span className="font-mono text-[11px] text-muted-foreground">v{site.version}</span>
        <ThemeToggle />
      </div>
    </div>
  );
}

export function DashboardShell({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  const { data: status } = useStatus();
  return (
    <div className="flex min-h-dvh bg-plane">
      <aside className="sticky top-0 hidden h-dvh w-56 shrink-0 flex-col gap-6 border-r bg-background px-4 py-4 lg:flex">
        <Logo href="/" className="px-2" />
        <Nav />
        <SidebarFooter />
      </aside>

      {open && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="absolute inset-0 bg-black/40" onClick={() => setOpen(false)} />
          <aside className="absolute inset-y-0 left-0 flex w-64 flex-col gap-6 border-r bg-background px-4 py-4 animate-fade-in">
            <div className="flex items-center justify-between px-2">
              <Logo href="/" />
              <Button variant="ghost" size="icon-sm" aria-label="Close menu" onClick={() => setOpen(false)}>
                <X />
              </Button>
            </div>
            <Nav onNavigate={() => setOpen(false)} />
            <SidebarFooter />
          </aside>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        {status?.mode === "demo" && (
          <div className="border-b bg-warning/10 px-4 py-2 text-center text-xs text-warning-fg">
            Demo mode: a simulated estate of appliances, reset on server restart.{" "}
            <Link href="/docs/self-hosting" className="font-medium underline underline-offset-2">
              Connect your Farrier
            </Link>
          </div>
        )}
        <Topbar onMenu={() => setOpen(true)} />
        <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6 sm:px-6 lg:py-8">{children}</main>
      </div>
    </div>
  );
}

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: React.ReactNode;
  actions?: React.ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {description && <p className="mt-1 text-sm text-muted-foreground">{description}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}

export function ErrorNotice({ error }: { error: unknown }) {
  if (!error) return null;
  return (
    <div role="alert" className="mb-4 rounded-lg border border-critical/30 bg-critical/5 px-4 py-4 text-[13px] text-critical-fg">
      {(error as Error).message || "Something went wrong talking to the Farrier API."}
    </div>
  );
}
