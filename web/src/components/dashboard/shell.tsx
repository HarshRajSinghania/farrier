"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import {
  Activity,
  BookOpen,
  CalendarClock,
  Gauge,

  LayoutDashboard,
  PanelLeftClose,
  PanelLeftOpen,
  Plug,
  Radar,
  Server,
  Settings,
  ShieldCheck,
  X,
} from "lucide-react";
import { GithubIcon, Logo, LogoMark, ThemeToggle } from "@/components/brand";
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

function Nav({ onNavigate, collapsed = false }: { onNavigate?: () => void; collapsed?: boolean }) {
  const path = usePathname();
  const { data } = useSummary();
  const pending = (data?.awaiting_manual ?? 0) + (data?.attention ?? 0);
  return (
    <nav className="flex flex-col gap-4" aria-label="Dashboard">
      {NAV.map(({ group, items }) => (
        <div key={group}>
          {collapsed ? (
            <div className="mx-2 mb-2 border-t" aria-hidden />
          ) : (
            <p className="mb-1 px-2 text-xs font-medium uppercase tracking-wider text-muted-foreground/80">{group}</p>
          )}
          <div className="flex flex-col gap-1">
            {items.map(({ href, label, icon: Icon, badge }) => {
              const active = href === "/dashboard" ? path === href : path.startsWith(href);
              return (
                <Link
                  key={href}
                  href={href}
                  onClick={onNavigate}
                  aria-current={active ? "page" : undefined}
                  title={collapsed ? label : undefined}
                  aria-label={collapsed ? label : undefined}
                  className={cn(
                    "relative flex h-9 items-center gap-2 rounded-lg px-2 text-sm font-medium text-muted-foreground transition-colors hover:bg-background/70 hover:text-foreground lg:h-8",
                    active &&
                      "bg-background text-foreground shadow-xs ring-1 ring-border before:absolute before:-left-2 before:top-2 before:bottom-2 before:w-1 before:rounded-full before:bg-[#c5f04a]",
                    collapsed && "relative justify-center px-0",
                  )}
                >
                  <Icon className="size-4 shrink-0" />
                  {!collapsed && label}
                  {badge && pending > 0 && collapsed && (
                    <span className="absolute right-2 top-1 size-2 rounded-full bg-warning" aria-hidden />
                  )}
                  {badge && pending > 0 && !collapsed && (
                    <span
                      className="tabular ml-auto rounded-full bg-warning/20 px-2 text-xs text-warning-fg"
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

function SidebarFooter({ collapsed = false }: { collapsed?: boolean }) {
  if (collapsed)
    return (
      <div className="mt-auto flex flex-col items-center gap-1 border-t pt-4">
        <Link href="/docs" title="Documentation" aria-label="Documentation" className="flex size-8 items-center justify-center rounded-md text-muted-foreground hover:bg-muted hover:text-foreground">
          <BookOpen className="size-4" />
        </Link>
        <a href={site.github} target="_blank" rel="noreferrer" title="GitHub" aria-label="GitHub" className="flex size-8 items-center justify-center rounded-md text-muted-foreground hover:bg-muted hover:text-foreground">
          <GithubIcon className="size-4" />
        </a>
      </div>
    );
  return (
    <div className="mt-auto space-y-1 border-t pt-4">
      <Link
        href="/docs"
        className="flex h-8 items-center gap-2 rounded-md px-2 text-sm text-muted-foreground hover:bg-muted hover:text-foreground"
      >
        <BookOpen className="size-4" /> Documentation
      </Link>
      <a
        href={site.github}
        target="_blank"
        rel="noreferrer"
        className="flex h-8 items-center gap-2 rounded-md px-2 text-sm text-muted-foreground hover:bg-muted hover:text-foreground"
      >
        <GithubIcon className="size-4" /> GitHub
      </a>
      <div className="flex items-center justify-between px-2 pt-2">
        <span className="font-mono text-xs text-muted-foreground">v{site.version}</span>
        <ThemeToggle />
      </div>
    </div>
  );
}

const COLLAPSE_KEY = "farrier.sidebar.collapsed";

export function DashboardShell({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(false);
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- a per-browser preference, only readable after mount
    setCollapsed(localStorage.getItem(COLLAPSE_KEY) === "1");
  }, []);
  const toggle = () => {
    const next = !collapsed;
    setCollapsed(next);
    try {
      localStorage.setItem(COLLAPSE_KEY, next ? "1" : "0");
    } catch {}
  };
  const { data: status } = useStatus();
  return (
    <div data-dashboard className="flex min-h-dvh bg-[var(--canvas)] lg:h-dvh lg:overflow-hidden">
      <aside
        className={cn(
          "sticky top-0 hidden h-dvh shrink-0 flex-col gap-6 overflow-y-auto py-4 transition-[width] duration-200 lg:flex",
          collapsed ? "w-16 px-2" : "w-60 px-4",
        )}
      >
        <div className={cn("flex items-center", collapsed ? "flex-col gap-2" : "justify-between px-2")}>
          {collapsed ? (
            <Link href="/" aria-label="Farrier home" className="flex size-8 items-center justify-center">
              <LogoMark />
            </Link>
          ) : (
            <div className="min-w-0">
              <Logo href="/" />
              <p className="mt-1 truncate pl-8 text-xs text-muted-foreground">
                {status?.mode === "demo" ? "Demo estate" : (status?.upstream?.replace(/^https?:\/\//, "") ?? "Connecting…")}
              </p>
            </div>
          )}
          <Button variant="ghost" size="icon-sm" onClick={toggle} aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"} title={collapsed ? "Expand sidebar" : "Collapse sidebar"}>
            {collapsed ? <PanelLeftOpen /> : <PanelLeftClose />}
          </Button>
        </div>
        <Nav collapsed={collapsed} />
        <SidebarFooter collapsed={collapsed} />
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

      <div className="flex min-w-0 flex-1 flex-col bg-background lg:my-2 lg:mr-2 lg:overflow-y-auto lg:rounded-2xl lg:border lg:shadow-sm">
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
    <div className="mb-8 flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        <h1 className="text-4xl font-semibold tracking-tight">{title}</h1>
        {description && <p className="mt-2 max-w-[65ch] text-base text-muted-foreground">{description}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}

export function ErrorNotice({ error }: { error: unknown }) {
  if (!error) return null;
  return (
    <div role="alert" className="mb-4 rounded-lg border border-critical/30 bg-critical/5 px-4 py-4 text-sm text-critical-fg">
      {(error as Error).message || "Something went wrong talking to the Farrier API."}
    </div>
  );
}
