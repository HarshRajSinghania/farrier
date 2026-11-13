"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { Suspense, useEffect, useRef, useState } from "react";
import { Bell, BookOpen, LogOut, Menu, PanelLeftClose, PanelLeftOpen, RefreshCw, Search, Settings, ShieldAlert, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import { GithubIcon } from "@/components/brand";
import { ProjectSwitcher } from "@/components/dashboard/project-switcher";
import { STATE_META } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Dropdown, DropdownContent, DropdownItem, DropdownSeparator, DropdownTrigger } from "@/components/ui/dropdown";
import { Kbd, Tip } from "@/components/ui/misc";
import { Badge } from "@/components/ui/badge";
import { api, ApiError, useRenewals, useStatus } from "@/lib/api";
import { useAccess } from "@/lib/auth/client";
import type { Role } from "@/lib/auth/roles";
import { site } from "@/lib/site";
import { cn, relativeTime } from "@/lib/utils";

const TITLES: Record<string, string> = {
  "/dashboard": "Overview",
  "/dashboard/renewals": "Renewals",
  "/dashboard/endpoints": "Certificates",
  "/dashboard/ssh": "SSH keys",
  "/dashboard/crypto": "Crypto & PQC",
  "/dashboard/discovery": "Discovery",
  "/dashboard/health": "Health",
  "/dashboard/activity": "Activity",
  "/dashboard/integrations/authorities": "Certificate authorities",
  "/dashboard/integrations/dns": "DNS accounts",
  "/dashboard/integrations/alerts": "Alerts",
  "/dashboard/connectors": "Connectors",
  "/dashboard/settings": "Settings",
  "/dashboard/settings/projects": "Projects",
};

// behind Suspense: dynamic routes only know their pathname at request time
function PageTitle() {
  return (
    <Suspense fallback={<Title path="" />}>
      <CurrentTitle />
    </Suspense>
  );
}

function CurrentTitle() {
  return <Title path={usePathname()} />;
}

function Title({ path }: { path: string }) {
  return (
    <div className="flex min-w-0 items-center gap-2 text-sm">
      <span className="hidden text-muted-foreground sm:inline">Farrier</span>
      <span className="hidden text-muted-foreground/60 sm:inline" aria-hidden>
        /
      </span>
      <span className="truncate font-medium">{TITLES[path] ?? (path.startsWith("/dashboard/endpoints/") ? "Certificate" : "Dashboard")}</span>
    </div>
  );
}

/** "/" focuses it from anywhere; Enter opens the endpoints list filtered by the query. */
function SearchBox() {
  const router = useRouter();
  const ref = useRef<HTMLInputElement>(null);
  const [q, setQ] = useState("");
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement | null;
      if (e.key === "/" && !(t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.isContentEditable))) {
        e.preventDefault();
        ref.current?.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  return (
    <form
      role="search"
      className="relative hidden w-full max-w-72 md:block"
      onSubmit={(e) => {
        e.preventDefault();
        router.push(`/dashboard/endpoints${q.trim() ? `?q=${encodeURIComponent(q.trim())}` : ""}`);
      }}
    >
      <Search className="pointer-events-none absolute left-2 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
      <input
        ref={ref}
        value={q}
        onChange={(e) => setQ(e.target.value)}
        placeholder="Search endpoints"
        aria-label="Search endpoints"
        className="h-9 w-full rounded-lg border border-input bg-muted/60 pl-8 pr-10 text-sm placeholder:text-muted-foreground focus-visible:border-ring focus-visible:bg-background focus-visible:outline-none"
      />
      <Kbd className="absolute right-2 top-1/2 -translate-y-1/2">/</Kbd>
    </form>
  );
}

function BackendPill() {
  const { data, error } = useStatus();
  const state = error ? "down" : !data ? "loading" : data.mode === "demo" ? "demo" : data.reachable ? "live" : "down";
  if (state !== "down") return null; // healthy or demo (which has its banner): nothing to show
  const meta = {
    loading: { dot: "bg-neutral-status", text: "Connecting", tip: "Checking the Farrier API" },
    demo: { dot: "bg-warning", text: "Demo data", tip: "FARRIER_API_URL is not set, so this dashboard shows a simulated estate." },
    live: { dot: "bg-good", text: data?.upstream ?? "Live", tip: "Connected to the Farrier API" },
    down: { dot: "bg-critical", text: "API unreachable", tip: data?.error ?? "The Farrier API did not respond" },
  }[state];
  return (
    <Tip content={meta.tip} side="bottom">
      <Link
        href="/dashboard/settings"
        className="hidden h-9 items-center gap-2 rounded-lg border px-4 text-xs text-muted-foreground hover:text-foreground sm:inline-flex"
      >
        <span className={cn("size-1.5 rounded-full", meta.dot)} aria-hidden />
        <span className="max-w-36 truncate">{meta.text}</span>
      </Link>
    </Tip>
  );
}

export function RunCycle() {
  const [busy, setBusy] = useState(false);
  const { can, status } = useAccess();
  // one cycle covers every project: global admins (and single-team installs) only
  if (!can("POST", "tick") || (status && status.allProjects === false)) return null;
  return (
    <Tip content="Scan every endpoint, plan due renewals and advance open ones. The server does this every 5 minutes.">
      <Button
        size="sm"
        variant="primary"
        className="h-9"
        disabled={busy}
        onClick={async () => {
          setBusy(true);
          try {
            const r = await api.tick();
            const moved = Object.entries(r.states)
              .map(([k, v]) => `${v} ${k.replace("_", " ")}`)
              .join(", ");
            toast.success("Cycle complete", { description: `${r.planned} planned${moved ? ` · ${moved}` : ""}` });
          } catch (e) {
            toast.error("Cycle failed", { description: (e as Error).message });
          } finally {
            setBusy(false);
          }
        }}
      >
        <RefreshCw className={cn(busy && "animate-spin")} />
        <span className="hidden sm:inline">Run cycle</span>
      </Button>
    </Tip>
  );
}

/** What needs a person, newest first: manual installs, failures and rollbacks. */
function Notifications() {
  const { data } = useRenewals("awaiting_manual,failed,rolled_back");
  const items = [...(data ?? [])].sort((a, b) => b.updated_at.localeCompare(a.updated_at)).slice(0, 6);
  const count = data?.length ?? 0;
  return (
    <Dropdown>
      <DropdownTrigger asChild>
        <Button variant="ghost" size="icon" className="relative shrink-0" aria-label={count ? `${count} renewals need attention` : "Notifications"}>
          <Bell />
          {count > 0 && (
            <span className="tabular absolute right-1 top-1 flex min-w-4 items-center justify-center rounded-full bg-foreground px-1 text-xs font-semibold leading-4 text-background">
              {count}
            </span>
          )}
        </Button>
      </DropdownTrigger>
      <DropdownContent className="w-80 p-0">
        <div className="flex items-center justify-between border-b px-4 py-2">
          <p className="text-sm font-semibold">Needs attention</p>
          <span className="tabular text-xs text-muted-foreground">{count}</span>
        </div>
        {items.length === 0 ? (
          <p className="px-4 py-6 text-center text-sm text-muted-foreground">Nothing is waiting on you.</p>
        ) : (
          <div className="max-h-80 overflow-y-auto p-1">
            {items.map((r) => {
              const m = STATE_META[r.state];
              const Icon = m.icon;
              return (
                <DropdownItem key={r.id} asChild>
                  <Link href={`/dashboard/renewals?state=${r.state === "awaiting_manual" ? "awaiting_manual" : "attention"}`} className="items-start py-2">
                    <Icon className="mt-1" />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate font-medium text-foreground">{r.name}</span>
                      <span className="block truncate text-xs text-muted-foreground">{r.error ?? m.hint}</span>
                    </span>
                    <span className="shrink-0 text-xs text-muted-foreground">{relativeTime(r.updated_at)}</span>
                  </Link>
                </DropdownItem>
              );
            })}
          </div>
        )}
        <div className="border-t p-1">
          <DropdownItem asChild>
            <Link href="/dashboard/renewals?state=attention">View all renewals</Link>
          </DropdownItem>
        </div>
      </DropdownContent>
    </Dropdown>
  );
}

function initials(name: string) {
  const parts = name.split(/[\s._@-]+/).filter(Boolean);
  return ((parts[0]?.[0] ?? "?") + (parts[1]?.[0] ?? "")).toUpperCase();
}

const ROLE_LABEL: Record<Role, string> = { viewer: "Viewer", operator: "Operator", admin: "Admin" };

function UserMenu() {
  const { status: data, error, role } = useAccess();
  const router = useRouter();
  const signOut = useRef<HTMLFormElement>(null);
  const user = data?.user ?? "operator";
  const auth = data?.auth ?? "none";
  const protectedDash = auth !== "none";
  const sso = auth === "oidc" || auth === "saml";

  // An SSO session that ends while the page is open: back to sign-in, then return here.
  useEffect(() => {
    if (sso && error instanceof ApiError && error.status === 401) {
      const here = window.location.pathname + window.location.search;
      router.replace(`/auth/signin?error=expired&returnTo=${encodeURIComponent(here)}`);
    }
  }, [sso, error, router]);

  return (
    <Dropdown>
      {/* a real POST: the server clears the session, then ends the identity provider's session */}
      <form ref={signOut} action="/auth/logout" method="post" className="hidden" />
      <DropdownTrigger asChild>
        <button
          type="button"
          aria-label={`Account menu for ${user}`}
          className="flex size-9 shrink-0 items-center justify-center rounded-full bg-foreground text-xs font-semibold text-background ring-offset-2 ring-offset-background transition hover:ring-2 hover:ring-border"
        >
          {initials(user)}
        </button>
      </DropdownTrigger>
      <DropdownContent className="w-64">
        <div className="flex items-center gap-4 px-2 py-2">
          <span className="flex size-9 items-center justify-center rounded-full bg-foreground text-xs font-semibold text-background">
            {initials(user)}
          </span>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <p className="truncate text-sm font-semibold">{user}</p>
              {data && protectedDash && (
                <Badge tone={role === "admin" ? "brand" : "neutral"} className="shrink-0 px-2 text-xs">
                  {ROLE_LABEL[role]}
                </Badge>
              )}
            </div>
            <p className="flex items-center gap-1 text-xs text-muted-foreground">
              {protectedDash ? (
                <>
                  <ShieldCheck className="size-3.5 text-good-fg" />
                  {sso ? "Signed in with SSO" : "Signed in"}
                </>
              ) : data?.mode === "demo" ? (
                "Demo session"
              ) : (
                <>
                  <ShieldAlert className="size-3.5 text-warning-fg" /> No sign-in configured
                </>
              )}
            </p>
          </div>
        </div>
        <DropdownSeparator />
        <DropdownItem asChild>
          <Link href="/dashboard/settings">
            <Settings /> Settings
          </Link>
        </DropdownItem>
        <DropdownItem asChild>
          <a href="/docs" target="_blank">
            <BookOpen /> Documentation
          </a>
        </DropdownItem>
        <DropdownItem asChild>
          <a href={site.github} target="_blank" rel="noreferrer">
            <GithubIcon className="size-4 text-muted-foreground" /> GitHub
          </a>
        </DropdownItem>
        {!protectedDash && data?.mode === "live" && (
          <DropdownItem asChild>
            <a href="/docs/security#hosting-checklist" target="_blank">
              <ShieldAlert /> Protect this dashboard
            </a>
          </DropdownItem>
        )}
        {sso && (
          <>
            <DropdownSeparator />
            <DropdownItem onSelect={() => signOut.current?.requestSubmit()}>
              <LogOut /> Sign out
            </DropdownItem>
          </>
        )}
        {auth === "basic" && (
          <>
            <DropdownSeparator />
            <DropdownItem asChild>
              {/* Basic auth has no server session: leaving clears the page; the browser forgets on close */}
              <Link href="/">
                <LogOut /> Leave dashboard
              </Link>
            </DropdownItem>
          </>
        )}
      </DropdownContent>
    </Dropdown>
  );
}

export function Topbar({ onMenu, onToggle, collapsed }: { onMenu: () => void; onToggle: () => void; collapsed: boolean }) {
  return (
    <header className="sticky top-0 z-30 flex h-14 shrink-0 items-center gap-4 border-b bg-background/80 px-4 backdrop-blur-xl backdrop-saturate-150 sm:px-6">
      <Button variant="ghost" size="icon-sm" className="lg:hidden" aria-label="Open menu" onClick={onMenu}>
        <Menu />
      </Button>
      <Button
        variant="ghost"
        size="icon-sm"
        className="hidden lg:inline-flex"
        aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        onClick={onToggle}
      >
        {collapsed ? <PanelLeftOpen /> : <PanelLeftClose />}
      </Button>
      <span className="hidden h-4 w-px bg-border lg:block" aria-hidden />
      <PageTitle />
      <ProjectSwitcher />
      <div className="ml-auto flex items-center gap-2">
        <SearchBox />
        <BackendPill />
        <Notifications />
        <UserMenu />
      </div>
    </header>
  );
}
