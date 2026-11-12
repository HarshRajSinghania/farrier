"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { ArrowRight, ChevronDown, Menu, X } from "lucide-react";
import { GithubIcon, Logo } from "@/components/brand";
import { site } from "@/lib/site";
import { cn } from "@/lib/utils";
import { MENUS } from "./nav-data";

/**
 * The top bar on every page. With `overlay` (the landing page) it sits inside the dark hero:
 * transparent at the top, frosted dark while the hero is under it, and the normal light bar after.
 * Any open menu turns it light so the bar and its panel read as one surface.
 */
export function SiteHeader({ overlay = false }: { overlay?: boolean }) {
  const [open, setOpen] = useState<string | null>(null); // desktop menu
  const [mobile, setMobile] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const [overHero, setOverHero] = useState(overlay);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    const onScroll = () => {
      setScrolled(window.scrollY > 8);
      if (overlay) {
        const hero = document.getElementById("hero");
        setOverHero(!!hero && hero.getBoundingClientRect().bottom > 64);
      }
    };
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && (setOpen(null), setMobile(false));
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("keydown", onKey);
    };
  }, [overlay]);

  const dark = overHero && !open && !mobile;
  const enter = (label: string) => {
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => setOpen(label), 80);
  };
  const leave = () => {
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => setOpen(null), 120);
  };

  return (
    <header
      className={cn(
        "top-0 z-50 w-full transition-[background-color,border-color,color] duration-300",
        overlay ? "fixed" : "sticky",
        dark
          ? scrolled
            ? "border-b border-white/10 bg-[#0b0b0b]/70 text-[#f5f5f3] backdrop-blur-xl backdrop-saturate-150"
            : "border-b border-transparent bg-transparent text-[#f5f5f3]"
          : "border-b bg-background/90 text-foreground backdrop-blur-xl",
      )}
      onMouseLeave={leave}
    >
      <div className="mx-auto flex h-16 max-w-7xl items-center gap-8 px-4 sm:px-6">
        <Logo className={dark ? "text-[#f5f5f3]" : undefined} />

        <nav className="hidden items-center gap-1 lg:flex" aria-label="Main">
          {MENUS.map((m) => (
            <div key={m.label} onMouseEnter={() => enter(m.label)}>
              <button
                type="button"
                aria-expanded={open === m.label}
                aria-controls={`menu-${m.label}`}
                onClick={() => setOpen(open === m.label ? null : m.label)}
                onFocus={() => enter(m.label)}
                className={cn(
                  "flex h-9 items-center gap-1 rounded-full px-4 text-base font-medium transition-colors",
                  dark ? "text-white/80 hover:bg-white/10 hover:text-white" : "text-foreground/75 hover:bg-muted hover:text-foreground",
                  open === m.label && "bg-muted text-foreground",
                )}
              >
                {m.label}
                <ChevronDown className={cn("size-3.5 opacity-60 transition-transform", open === m.label && "rotate-180")} />
              </button>
            </div>
          ))}
          <Link
            href="/#deploy"
            onMouseEnter={leave}
            className={cn(
              "flex h-9 items-center rounded-full px-4 text-base font-medium transition-colors",
              dark ? "text-white/80 hover:bg-white/10 hover:text-white" : "text-foreground/75 hover:bg-muted hover:text-foreground",
            )}
          >
            Deploy
          </Link>
        </nav>

        <div className="ml-auto hidden items-center gap-2 lg:flex">
          <a
            href={site.github}
            target="_blank"
            rel="noreferrer"
            className={cn(
              "flex h-9 items-center gap-2 rounded-full px-4 text-base font-medium transition-colors",
              dark ? "text-white/80 hover:bg-white/10 hover:text-white" : "text-foreground/75 hover:bg-muted hover:text-foreground",
            )}
          >
            <GithubIcon className="size-4" /> GitHub
          </a>
          <Link
            href="/docs/quickstart"
            className="flex h-10 items-center gap-2 rounded-full bg-[#2563eb] px-6 text-base font-semibold text-white transition-colors hover:bg-[#1d4ed8]"
          >
            Install Farrier <ArrowRight className="size-4" />
          </Link>
        </div>

        <button
          type="button"
          className={cn("ml-auto flex size-10 items-center justify-center rounded-full lg:hidden", dark ? "hover:bg-white/10" : "hover:bg-muted")}
          aria-label={mobile ? "Close menu" : "Open menu"}
          aria-expanded={mobile}
          onClick={() => setMobile(!mobile)}
        >
          {mobile ? <X className="size-5" /> : <Menu className="size-5" />}
        </button>
      </div>

      {/* desktop panels */}
      {MENUS.map((m) => (
        <div
          key={m.label}
          id={`menu-${m.label}`}
          hidden={open !== m.label}
          onMouseEnter={() => enter(m.label)}
          className="absolute inset-x-0 top-full hidden border-b bg-background text-foreground shadow-xl lg:block"
        >
          <div className="mx-auto grid max-w-7xl grid-cols-12 gap-8 px-4 py-8 sm:px-6">
            {m.groups.map((g) => (
              <div key={g.title} className="col-span-4">
                <p className="mb-4 text-xs font-medium uppercase tracking-wider text-muted-foreground">{g.title}</p>
                <ul className="space-y-1">
                  {g.links.map((l) => (
                    <li key={l.label}>
                      <Link href={l.href} onClick={() => setOpen(null)} className="group -mx-4 block rounded-xl px-4 py-2 hover:bg-muted">
                        <span className="block text-base font-medium">{l.label}</span>
                        {l.desc && <span className="block text-sm text-muted-foreground">{l.desc}</span>}
                      </Link>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
            <Link
              href="/dashboard"
              onClick={() => setOpen(null)}
              className="col-span-4 flex flex-col justify-between rounded-2xl bg-[#141414] p-6 text-[#f5f5f3] transition-transform hover:-translate-y-0.5"
            >
              <span className="font-mono text-xs uppercase tracking-widest text-[#60a5fa]">Live demo</span>
              <span>
                <span className="block text-xl font-semibold tracking-tight">Watch 41 endpoints renew</span>
                <span className="mt-1 block text-sm text-white/65">The real dashboard on demo data. Nothing to install.</span>
              </span>
              <span className="mt-6 inline-flex items-center gap-2 text-sm font-semibold text-[#60a5fa]">
                Open the demo <ArrowRight className="size-4" />
              </span>
            </Link>
          </div>
        </div>
      ))}

      {/* mobile sheet */}
      {mobile && (
        <div className="max-h-[calc(100dvh-4rem)] overflow-y-auto border-t bg-background px-4 pb-6 text-foreground lg:hidden">
          {MENUS.map((m) => (
            <details key={m.label} className="group border-b">
              <summary className="flex h-14 cursor-pointer list-none items-center justify-between text-lg font-medium">
                {m.label}
                <ChevronDown className="size-4 transition-transform group-open:rotate-180" />
              </summary>
              <ul className="pb-4">
                {m.groups.flatMap((g) => g.links).map((l) => (
                  <li key={l.label}>
                    <Link href={l.href} onClick={() => setMobile(false)} className="block py-2 text-base text-muted-foreground hover:text-foreground">
                      {l.label}
                    </Link>
                  </li>
                ))}
              </ul>
            </details>
          ))}
          <Link href="/#deploy" onClick={() => setMobile(false)} className="flex h-14 items-center border-b text-lg font-medium">
            Deploy
          </Link>
          <div className="mt-6 grid gap-4">
            <Link href="/docs/quickstart" className="flex h-12 items-center justify-center rounded-full bg-[#2563eb] font-semibold text-white">
              Install Farrier
            </Link>
            <a href={site.github} className="flex h-12 items-center justify-center gap-2 rounded-full border font-medium">
              <GithubIcon className="size-4" /> GitHub
            </a>
          </div>
        </div>
      )}
    </header>
  );
}
