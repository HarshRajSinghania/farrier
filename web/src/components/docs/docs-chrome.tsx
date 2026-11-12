"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useMemo, useState } from "react";
import { ArrowLeft, ArrowRight, ChevronDown, ChevronRight, FileText, Hash, Menu, Search, X } from "lucide-react";
import { Dialog as D } from "radix-ui";
import { ThemeToggle } from "@/components/brand";
import { Button } from "@/components/ui/button";
import { Kbd } from "@/components/ui/misc";
import type { SearchEntry } from "@/lib/docs-index";
import { DOCS_FLAT, DOCS_NAV } from "@/lib/docs-nav";
import { site } from "@/lib/site";
import { cn } from "@/lib/utils";

/* ------------------------------------------------------------------ search (⌘K) */

function score(e: SearchEntry, q: string) {
  const title = `${e.heading ?? ""} ${e.page} ${e.group}`.toLowerCase();
  const body = e.text.toLowerCase();
  const words = q.toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.every((w) => title.includes(w) || body.includes(w))) return -1;
  const inTitle = words.filter((w) => title.includes(w)).length;
  return inTitle * 3 + ((e.heading ?? e.page).toLowerCase().startsWith(words[0]) ? 4 : 0) + (body.includes(q.toLowerCase()) ? 2 : 0);
}

/** A short stretch of the section's text around the first match. */
function snippet(e: SearchEntry, q: string) {
  const w = q.toLowerCase().split(/\s+/).filter(Boolean)[0];
  const at = w ? e.text.toLowerCase().indexOf(w) : -1;
  if (at < 0) return null;
  const start = Math.max(0, at - 40);
  return (start > 0 ? "…" : "") + e.text.slice(start, start + 120).trim() + "…";
}

function DocsSearch({ index, open, onOpenChange }: { index: SearchEntry[]; open: boolean; onOpenChange: (o: boolean) => void }) {
  const router = useRouter();
  const [q, setQ] = useState("");
  const [active, setActive] = useState(0);
  const results = useMemo(() => {
    if (!q.trim()) return index.filter((e) => !e.heading).slice(0, 8);
    return index
      .map((e) => [e, score(e, q)] as const)
      .filter(([, s]) => s >= 0)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 12)
      .map(([e]) => e);
  }, [index, q]);

  const go = (e: SearchEntry | undefined) => {
    if (!e) return;
    onOpenChange(false);
    setQ("");
    router.push(e.href);
  };

  return (
    <D.Root open={open} onOpenChange={onOpenChange}>
      <D.Portal>
        <D.Overlay className="fixed inset-0 z-50 bg-black/40 backdrop-blur-[2px]" />
        <D.Content className="fixed left-1/2 top-[12vh] z-50 w-[calc(100vw-2rem)] max-w-xl -translate-x-1/2 overflow-hidden rounded-xl border bg-popover shadow-2xl">
          <D.Title className="sr-only">Search the docs</D.Title>
          <D.Description className="sr-only">Type to search page titles and headings.</D.Description>
          <div className="flex items-center gap-2 border-b px-4">
            <Search className="size-4 text-muted-foreground" />
            <input
              autoFocus
              value={q}
              onChange={(e) => {
                setQ(e.target.value);
                setActive(0);
              }}
              onKeyDown={(e) => {
                if (e.key === "ArrowDown") {
                  e.preventDefault();
                  setActive((a) => Math.min(a + 1, results.length - 1));
                } else if (e.key === "ArrowUp") {
                  e.preventDefault();
                  setActive((a) => Math.max(a - 1, 0));
                } else if (e.key === "Enter") {
                  go(results[active]);
                }
              }}
              placeholder="Search the docs"
              aria-label="Search the docs"
              className="h-12 flex-1 bg-transparent text-sm outline-none placeholder:text-muted-foreground"
            />
            <Kbd>Esc</Kbd>
          </div>
          <ul className="max-h-[50vh] overflow-y-auto p-2" role="listbox" aria-label="Results">
            {results.length === 0 && <li className="px-4 py-8 text-center text-sm text-muted-foreground">No matches for “{q}”.</li>}
            {results.map((e, i) => (
              <li key={e.href} role="option" aria-selected={i === active}>
                <button
                  type="button"
                  onMouseEnter={() => setActive(i)}
                  onClick={() => go(e)}
                  className={cn("flex w-full items-center gap-4 rounded-md px-4 py-2 text-left", i === active && "bg-muted")}
                >
                  {e.heading ? <Hash className="size-4 shrink-0 text-muted-foreground" /> : <FileText className="size-4 shrink-0 text-muted-foreground" />}
                  <span className="min-w-0">
                    <span className="block truncate text-sm font-medium">{e.heading ?? e.page}</span>
                    <span className="block truncate text-xs text-muted-foreground">
                      {e.group} {e.heading ? `› ${e.page}` : ""}
                    </span>
                    {q.trim() && snippet(e, q) && (
                      <span className="mt-1 block truncate text-xs text-muted-foreground/80">{snippet(e, q)}</span>
                    )}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </D.Content>
      </D.Portal>
    </D.Root>
  );
}

function SearchTrigger({ onOpen }: { onOpen: () => void }) {
  return (
    <button
      type="button"
      onClick={onOpen}
      className="flex h-10 w-full items-center gap-2 rounded-xl bg-background px-4 text-sm text-muted-foreground ring-1 ring-border transition-shadow hover:text-foreground hover:ring-foreground/30"
    >
      <Search className="size-4 shrink-0" />
      <span className="flex-1 truncate text-left">Search docs</span>
      <span className="flex shrink-0 gap-1">
        <Kbd>Ctrl</Kbd>
        <Kbd>K</Kbd>
      </span>
    </button>
  );
}

/* ------------------------------------------------------------------ sidebar */

function NavList({ onNavigate }: { onNavigate?: () => void }) {
  const path = usePathname();
  const current = DOCS_NAV.find((g) => g.items.some((i) => i.href === path))?.title;
  const [closed, setClosed] = useState<Record<string, boolean>>({});
  return (
    <nav aria-label="Documentation" className="space-y-1">
      {DOCS_NAV.map((g) => {
        const isOpen = g.title === current || !closed[g.title];
        return (
          <div key={g.title}>
            <button
              type="button"
              aria-expanded={isOpen}
              onClick={() => setClosed((c) => ({ ...c, [g.title]: isOpen }))}
              className="flex w-full items-center justify-between rounded-md px-2 py-2 text-sm font-semibold hover:bg-muted"
            >
              {g.title}
              {isOpen ? <ChevronDown className="size-3.5 text-muted-foreground" /> : <ChevronRight className="size-3.5 text-muted-foreground" />}
            </button>
            {isOpen && (
              <ul className="mb-4 ml-2 mt-1 space-y-1 border-l">
                {g.items.map((i) => {
                  const active = path === i.href;
                  return (
                    <li key={i.href}>
                      <Link
                        href={i.href}
                        onClick={onNavigate}
                        aria-current={active ? "page" : undefined}
                        className={cn(
                          "-ml-px block border-l-2 border-transparent py-2 pl-4 text-sm text-muted-foreground transition-colors hover:text-foreground",
                          active && "border-foreground font-medium text-foreground",
                        )}
                      >
                        {i.label}
                      </Link>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        );
      })}
    </nav>
  );
}

export function DocsSidebar({ index }: { index: SearchEntry[] }) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState(false);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setSearch(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  return (
    <>
      <aside className="sticky top-16 hidden h-[calc(100dvh-4rem)] w-60 shrink-0 flex-col gap-6 overflow-y-auto py-8 pr-4 [scrollbar-width:thin] [scrollbar-color:transparent_transparent] hover:[scrollbar-color:var(--border)_transparent] lg:flex">
        <SearchTrigger onOpen={() => setSearch(true)} />
        <NavList />
        <div className="mt-auto flex items-center justify-between border-t pt-4">
          <span className="rounded-full border px-2 py-1 font-mono text-xs text-muted-foreground">v{site.version}</span>
          <ThemeToggle />
        </div>
      </aside>
      <div className="sticky top-16 z-30 -mx-4 flex items-center gap-2 border-b bg-background/90 px-4 py-2 backdrop-blur lg:hidden">
        <Button variant="ghost" size="sm" onClick={() => setOpen(true)} aria-label="Open docs navigation">
          <Menu /> Menu
        </Button>
        <Button variant="ghost" size="sm" className="ml-auto" onClick={() => setSearch(true)} aria-label="Search the docs">
          <Search /> Search
        </Button>
      </div>
      {open && (
        <div className="fixed inset-0 z-50 lg:hidden">
          <div className="absolute inset-0 bg-black/40" onClick={() => setOpen(false)} />
          <div className="absolute inset-y-0 left-0 w-72 overflow-y-auto border-r bg-background p-6 animate-fade-in">
            <div className="mb-6 flex justify-end">
              <Button variant="ghost" size="icon-sm" aria-label="Close" onClick={() => setOpen(false)}>
                <X />
              </Button>
            </div>
            <NavList onNavigate={() => setOpen(false)} />
          </div>
        </div>
      )}
      <DocsSearch index={index} open={search} onOpenChange={setSearch} />
    </>
  );
}

/* ------------------------------------------------------------------ breadcrumbs, toc, pager */

export function DocsBreadcrumbs() {
  const path = usePathname();
  const page = DOCS_FLAT.find((d) => d.href === path);
  if (!page) return null;
  return (
    <nav aria-label="Breadcrumb" className="mb-6 flex items-center gap-2 text-sm text-muted-foreground">
      <Link href="/docs" className="hover:text-foreground">
        Docs
      </Link>
      <ChevronRight className="size-3.5" />
      <span>{page.group}</span>
      {page.href !== "/docs" && (
        <>
          <ChevronRight className="size-3.5" />
          <span className="text-foreground">{page.label}</span>
        </>
      )}
    </nav>
  );
}

export function DocsToc() {
  const path = usePathname();
  const [items, setItems] = useState<{ id: string; text: string; depth: number }[]>([]);
  const [active, setActive] = useState<string | null>(null);

  useEffect(() => {
    const hs = [...document.querySelectorAll<HTMLHeadingElement>("article h2[id], article h3[id]")];
    // eslint-disable-next-line react-hooks/set-state-in-effect -- headings only exist after render
    setItems(hs.map((h) => ({ id: h.id, text: h.textContent ?? "", depth: h.tagName === "H3" ? 3 : 2 })));
    const io = new IntersectionObserver(
      (entries) => {
        const visible = entries.filter((e) => e.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
        if (visible[0]) setActive(visible[0].target.id);
      },
      { rootMargin: "-80px 0px -70% 0px" },
    );
    hs.forEach((h) => io.observe(h));
    return () => io.disconnect();
  }, [path]);

  if (items.length < 2) return null;
  return (
    <aside className="sticky top-16 hidden h-[calc(100dvh-4rem)] w-52 shrink-0 overflow-y-auto py-8 xl:block">
      <p className="mb-4 text-xs font-semibold">On this page</p>
      <ul className="space-y-2 border-l text-sm">
        {items.map((i) => (
          <li key={i.id}>
            <a
              href={`#${i.id}`}
              className={cn(
                "-ml-px block border-l-2 border-transparent text-muted-foreground transition-colors hover:text-foreground",
                i.depth === 3 ? "pl-6" : "pl-4",
                active === i.id && "border-foreground text-foreground",
              )}
            >
              {i.text}
            </a>
          </li>
        ))}
      </ul>
      <div className="mt-6 space-y-2 border-t pt-4 text-xs">
        <a
          href={`${site.github}/edit/main/web/src/app${path}/page.mdx`}
          className="block text-muted-foreground hover:text-foreground"
          target="_blank"
          rel="noreferrer"
        >
          Edit this page on GitHub
        </a>
        <a href={`${site.github}/issues/new`} className="block text-muted-foreground hover:text-foreground" target="_blank" rel="noreferrer">
          Report a problem with the docs
        </a>
      </div>
    </aside>
  );
}

export function DocsPager() {
  const path = usePathname();
  const i = DOCS_FLAT.findIndex((d) => d.href === path);
  const prev = i > 0 ? DOCS_FLAT[i - 1] : null;
  const next = i >= 0 && i < DOCS_FLAT.length - 1 ? DOCS_FLAT[i + 1] : null;
  return (
    <div className="mt-16 grid gap-4 border-t pt-6 sm:grid-cols-2">
      {prev ? (
        <Link href={prev.href} className="rounded-lg border p-4 transition-colors hover:border-foreground/30">
          <p className="flex items-center gap-1 text-xs text-muted-foreground">
            <ArrowLeft className="size-3" /> {prev.group}
          </p>
          <p className="mt-1 font-medium">{prev.label}</p>
        </Link>
      ) : (
        <span />
      )}
      {next && (
        <Link href={next.href} className="rounded-lg border p-4 text-right transition-colors hover:border-foreground/30">
          <p className="flex items-center justify-end gap-1 text-xs text-muted-foreground">
            {next.group} <ArrowRight className="size-3" />
          </p>
          <p className="mt-1 font-medium">{next.label}</p>
        </Link>
      )}
    </div>
  );
}
