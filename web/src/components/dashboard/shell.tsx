"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Suspense, useEffect, useState } from "react";
import {
  BookOpen,
  FileBadge,
  LayoutDashboard,
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

// Four sections in the sidebar; each section's pages are tabs at the top of the page, so the menu stays
// short (Hick) while every page keeps its own URL.
type Page = { href: string; label: string; badge?: boolean };
const NAV: { label: string; icon: typeof LayoutDashboard; pages: Page[] }[] = [
  {
    label: "Overview",
    icon: LayoutDashboard,
    pages: [
      { href: "/dashboard", label: "Overview" },
      { href: "/dashboard/activity", label: "Activity" },
    ],
  },
  {
    label: "Certificates",
    icon: FileBadge,
    pages: [
      { href: "/dashboard/endpoints", label: "Inventory" },
      { href: "/dashboard/renewals", label: "Renewals", badge: true },
      { href: "/dashboard/discovery", label: "Discovery" },
      { href: "/dashboard/cloud", label: "Cloud" },
    ],
  },
  {
    label: "Security",
    icon: ShieldCheck,
    pages: [
      { href: "/dashboard/health", label: "Health" },
      { href: "/dashboard/crypto", label: "Crypto & PQC" },
      { href: "/dashboard/ssh", label: "SSH keys" },
    ],
  },
  {
    label: "Setup",
    icon: Settings,
    pages: [
      { href: "/dashboard/integrations/authorities", label: "Authorities" },
      { href: "/dashboard/integrations/dns", label: "DNS" },
      { href: "/dashboard/integrations/alerts", label: "Alerts" },
      { href: "/dashboard/connectors", label: "Connectors" },
      { href: "/dashboard/settings", label: "Settings" },
    ],
  },
];

const isActive = (href: string, path: string) => (href === "/dashboard" ? path === href : path.startsWith(href));
const sectionOf = (path: string) => NAV.find((s) => s.pages.some((p) => isActive(p.href, path)));

function usePending() {
  const { data } = useSummary();
  return (data?.awaiting_manual ?? 0) + (data?.attention ?? 0);
}

type NavProps = { onNavigate?: () => void; collapsed?: boolean };

/**
 * The pathname is only known at request time on dynamic routes (/dashboard/endpoints/[id]),
 * so the active highlight streams in behind Suspense there; static routes prerender it.
 */
function Nav(props: NavProps) {
  return (
    <Suspense fallback={<NavLinks {...props} path="" />}>
      <ActiveNav {...props} />
    </Suspense>
  );
}

function ActiveNav(props: NavProps) {
  return <NavLinks {...props} path={usePathname()} />;
}

function NavLinks({ onNavigate, collapsed = false, path }: NavProps & { path: string }) {
  const pending = usePending();
  const current = sectionOf(path);
  return (
    <nav className="flex flex-col gap-1" aria-label="Dashboard">
      {NAV.map(({ label, icon: Icon, pages }) => {
        const active = current?.label === label;
        const badge = pages.some((p) => p.badge) && pending > 0;
        return (
          <Link
            key={label}
            href={pages[0].href}
            onClick={onNavigate}
            aria-current={active ? "true" : undefined}
            title={collapsed ? label : undefined}
            aria-label={collapsed ? label : undefined}
            className={cn(
              "relative flex h-9 items-center gap-2 rounded-lg px-2 text-sm font-medium text-muted-foreground transition-colors hover:bg-background/70 hover:text-foreground",
              active && "bg-brand-soft text-foreground",
              collapsed && "justify-center px-0",
            )}
          >
            <Icon className="size-4 shrink-0" />
            {!collapsed && label}
            {badge && collapsed && <span className="absolute right-2 top-1 size-2 rounded-full bg-warning" aria-hidden />}
            {badge && !collapsed && (
              <span className="tabular ml-auto rounded-full bg-warning/20 px-2 text-xs text-warning-fg" aria-label={`${pending} need attention`}>
                {pending}
              </span>
            )}
          </Link>
        );
      })}
    </nav>
  );
}

/** The current section's pages as tabs; hidden for a single-page section or a detail page outside the nav. */
function SectionTabs() {
  return (
    <Suspense fallback={null}>
      <SectionTabsInner />
    </Suspense>
  );
}

function SectionTabsInner() {
  const path = usePathname();
  const pending = usePending();
  const section = sectionOf(path);
  if (!section || section.pages.length < 2) return null;
  return (
    <nav aria-label={section.label} className="-mx-1 mb-6 flex gap-1 overflow-x-auto border-b px-1">
      {section.pages.map((p) => {
        const active = isActive(p.href, path);
        return (
          <Link
            key={p.href}
            href={p.href}
            aria-current={active ? "page" : undefined}
            className={cn(
              "-mb-px flex h-10 shrink-0 items-center gap-2 border-b-2 border-transparent px-3 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground",
              active && "border-foreground text-foreground",
            )}
          >
            {p.label}
            {p.badge && pending > 0 && (
              <span className="tabular rounded-full bg-warning/20 px-2 text-xs text-warning-fg" aria-label={`${pending} need attention`}>
                {pending}
              </span>
            )}
          </Link>
        );
      })}
    </nav>
  );
}

function SidebarFooter({ collapsed = false }: { collapsed?: boolean }) {
  if (collapsed)
    return (
      <div className="mt-auto flex flex-col items-center gap-1 border-t pt-4">
        <a href="/docs" target="_blank" title="Documentation" aria-label="Documentation" className="flex size-8 items-center justify-center rounded-md text-muted-foreground hover:bg-muted hover:text-foreground">
          <BookOpen className="size-4" />
        </a>
        <a href={site.github} target="_blank" rel="noreferrer" title="GitHub" aria-label="GitHub" className="flex size-8 items-center justify-center rounded-md text-muted-foreground hover:bg-muted hover:text-foreground">
          <GithubIcon className="size-4" />
        </a>
      </div>
    );
  return (
    <div className="mt-auto space-y-1 border-t pt-4">
      {/* /docs redirects to FARRIER_DOCS_URL (app/docs/[[...path]]/route.ts) */}
      <a
        href="/docs"
        target="_blank"
        className="flex h-8 items-center gap-2 rounded-md px-2 text-sm text-muted-foreground hover:bg-muted hover:text-foreground"
      >
        <BookOpen className="size-4" /> Documentation
      </a>
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
        <div className={cn("flex h-8 items-center", collapsed ? "justify-center" : "px-2")}>
          {collapsed ? (
            <Link href="/" aria-label="Farrier home" className="flex size-8 items-center justify-center">
              <LogoMark />
            </Link>
          ) : (
            <Logo href="/" />
          )}
        </div>
        <Nav collapsed={collapsed} />
        <SidebarFooter collapsed={collapsed} />
      </aside>

      {open && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="absolute inset-0 bg-black/40" onClick={() => setOpen(false)} />
          <aside className="absolute inset-y-0 left-0 flex w-64 max-w-[85vw] flex-col gap-6 overflow-y-auto overscroll-contain border-r bg-background px-4 py-4 animate-fade-in">
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
            <a href="/docs/self-hosting" target="_blank" className="font-medium underline underline-offset-2">
              Connect your Farrier
            </a>
          </div>
        )}
        <Topbar onMenu={() => setOpen(true)} onToggle={toggle} collapsed={collapsed} />
        <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6 sm:px-6 lg:py-8">
          <SectionTabs />
          {children}
        </main>
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
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
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
