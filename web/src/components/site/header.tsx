"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { ChevronDown, Menu, X } from "lucide-react";
import { GithubIcon, Logo } from "@/components/brand";
import { site } from "@/lib/site";
import { cn } from "@/lib/utils";
import { MENUS } from "./nav-data";

const link = "flex h-9 items-center rounded-full px-3 text-[15px] font-medium text-foreground/80 transition-colors hover:text-foreground";

/**
 * The top bar on every page: white, sticky, a hairline once the page scrolls. Three menus on the
 * left; GitHub, the demo and the one blue button on the right. `landing` makes it 56px tall
 * (docs and legal pages keep 64px, which their sticky sidebars are aligned to).
 */
export function SiteHeader({ landing = false }: { landing?: boolean }) {
  const [open, setOpen] = useState<string | null>(null); // desktop menu
  const [mobile, setMobile] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 4);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && (setOpen(null), setMobile(false));
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("keydown", onKey);
    };
  }, []);

  const enter = (label: string) => {
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => setOpen(label), 60);
  };
  const leave = () => {
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => setOpen(null), 140);
  };

  return (
    <header
      className={cn(
        "sticky top-0 z-50 w-full border-b bg-background transition-colors duration-200",
        scrolled || mobile || !landing ? "border-[var(--l-line)]" : "border-transparent",
      )}
    >
      <div className={cn("mx-auto flex max-w-7xl items-center gap-6 px-4 sm:px-6", landing ? "h-14" : "h-16")}>
        <Logo className="text-[15px]" />

        <nav className="hidden items-center lg:flex" aria-label="Main" onMouseLeave={leave}>
          {MENUS.map((m) => (
            <div key={m.label} className="relative" onMouseEnter={() => enter(m.label)}>
              <button
                type="button"
                aria-expanded={open === m.label}
                aria-controls={`menu-${m.label}`}
                onClick={() => setOpen(open === m.label ? null : m.label)}
                className={cn(link, "gap-1", open === m.label && "text-foreground")}
              >
                {m.label}
                <ChevronDown className={cn("size-3.5 opacity-50 transition-transform", open === m.label && "rotate-180")} />
              </button>
              <div id={`menu-${m.label}`} hidden={open !== m.label} className="absolute left-0 top-full pt-2">
                <div className="grid w-[520px] grid-cols-2 gap-2 rounded-2xl border border-[var(--l-line)] bg-popover p-2 shadow-[0_12px_32px_rgb(0_0_0/0.08)]">
                  {m.groups.map((g) => (
                    <div key={g.title}>
                      <p className="px-3 pb-1 pt-2 text-xs font-medium text-[var(--l-sub)]">{g.title}</p>
                      <ul>
                        {g.links.map((l) => (
                          <li key={l.label}>
                            <Link href={l.href} onClick={() => setOpen(null)} className="block rounded-xl px-3 py-2 hover:bg-[var(--l-panel)]">
                              <span className="block text-sm font-medium">{l.label}</span>
                              {l.desc && <span className="block text-[13px] text-[var(--l-sub)]">{l.desc}</span>}
                            </Link>
                          </li>
                        ))}
                      </ul>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </nav>

        <div className="ml-auto hidden items-center gap-1 lg:flex">
          <a href={site.github} target="_blank" rel="noreferrer" aria-label="Farrier on GitHub" className={cn(link, "w-9 justify-center px-0")}>
            <GithubIcon className="size-[18px]" />
          </a>
          <Link href="/dashboard" className={link}>
            Live demo
          </Link>
          <Link
            href="/docs/quickstart"
            className="ml-2 flex h-9 items-center rounded-full bg-[#2563eb] px-4 text-[15px] font-medium text-white transition-colors hover:bg-[#1d4ed8]"
          >
            Install
          </Link>
        </div>

        <button
          type="button"
          className="ml-auto flex size-10 items-center justify-center rounded-full hover:bg-[var(--l-panel)] lg:hidden"
          aria-label={mobile ? "Close menu" : "Open menu"}
          aria-expanded={mobile}
          onClick={() => setMobile(!mobile)}
        >
          {mobile ? <X className="size-5" /> : <Menu className="size-5" />}
        </button>
      </div>

      {/* mobile sheet */}
      {mobile && (
        <div className="max-h-[calc(100dvh-3.5rem)] overflow-y-auto bg-background px-4 pb-6 lg:hidden">
          {MENUS.map((m) => (
            <details key={m.label} className="group border-b border-[var(--l-line)]">
              <summary className="flex h-14 cursor-pointer list-none items-center justify-between text-base font-medium">
                {m.label}
                <ChevronDown className="size-4 opacity-60 transition-transform group-open:rotate-180" />
              </summary>
              <ul className="pb-4">
                {m.groups.flatMap((g) => g.links).map((l) => (
                  <li key={l.label}>
                    <Link href={l.href} onClick={() => setMobile(false)} className="block py-2 text-[15px] text-[var(--l-sub)] hover:text-foreground">
                      {l.label}
                    </Link>
                  </li>
                ))}
              </ul>
            </details>
          ))}
          <div className="mt-6 grid gap-2">
            <Link href="/docs/quickstart" className="flex h-11 items-center justify-center rounded-full bg-[#2563eb] text-[15px] font-medium text-white hover:bg-[#1d4ed8]">
              Install Farrier
            </Link>
            <Link href="/dashboard" className="flex h-11 items-center justify-center rounded-full bg-[var(--l-pill)] text-[15px] font-medium hover:bg-[var(--l-pill-hover)]">
              Live demo
            </Link>
            <a href={site.github} className="flex h-11 items-center justify-center gap-2 text-[15px] font-medium">
              <GithubIcon className="size-4" /> GitHub
            </a>
          </div>
        </div>
      )}
    </header>
  );
}
