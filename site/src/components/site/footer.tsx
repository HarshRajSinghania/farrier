import Link from "next/link";
import { ArrowRight } from "lucide-react";
import { GithubIcon, LogoMark } from "@/components/brand";
import { site } from "@/lib/site";
import { FOOTER_COLUMNS } from "./nav-data";

const muted = "text-white/60 transition-colors hover:text-white";

/** The closing call to action (landing only) and the footer, on every marketing and docs page. */
export function SiteFooter({ cta = true }: { cta?: boolean }) {
  return (
    <>
      {cta && (
        <section className="mx-auto w-full max-w-7xl px-4 pb-24 sm:px-6">
          <div data-reveal className="grid items-center gap-10 overflow-hidden rounded-[32px] bg-[#2563eb] px-6 py-12 text-white sm:px-12 sm:py-16 lg:grid-cols-2">
            <div className="min-w-0">
              <h2 className="max-w-[16ch] text-[34px] font-semibold leading-[1.08] tracking-[-0.03em] text-balance sm:text-[48px]">
                Renew your first certificate tonight
              </h2>
              <p className="mt-4 max-w-md text-[17px] text-white/80">
                Open source and self-hosted. Running in five minutes, with no account.
              </p>
              <div className="mt-8 flex flex-wrap gap-2">
                <Link
                  href="/docs/quickstart"
                  className="inline-flex h-11 items-center rounded-full bg-white px-5 text-[15px] font-semibold text-[#2563eb] transition-colors hover:bg-white/90"
                >
                  Install Farrier
                </Link>
                <Link
                  href={site.demo}
                  className="inline-flex h-11 items-center gap-1 rounded-full px-5 text-[15px] font-semibold ring-1 ring-white/40 ring-inset transition-colors hover:bg-white/10"
                >
                  Try it <ArrowRight className="size-4" />
                </Link>
              </div>
            </div>
            <pre className="min-w-0 overflow-x-auto rounded-2xl bg-[#0b1220] p-6 font-mono text-[13px] leading-7 text-white/70 shadow-[0_24px_48px_-12px_rgba(11,18,32,0.5)]">
              <span className="text-white/40">$</span> <span className="text-white">git clone {site.github}</span>
              {"\n"}
              <span className="text-white/40">$</span> <span className="text-white">pip install -e ./farrier</span>
              {"\n"}
              <span className="text-white/40">$</span> <span className="text-white">farrier demo</span>
              {"\n"}  demo estate: 41 endpoints, 18 automated{"\n"}
              <span className="text-[#4ade80]">  ✔</span> nginx-01    verified live{"\n"}
              <span className="text-[#4ade80]">  ✔</span> tomcat-03   verified live{"\n"}
              <span className="text-[#fbbf24]">  ●</span> asa-dc1     change pack ready{"\n"}
              <span className="text-white/40">$</span> <span className="text-white">cd farrier/web && npm i && npm run dev</span>
            </pre>
          </div>
        </section>
      )}

      <footer className="bg-[#0b0b0c] text-sm text-white [&_:focus-visible]:outline-[#60a5fa]">
        <div className="mx-auto grid max-w-7xl gap-10 px-4 py-14 sm:px-6 lg:grid-cols-12">
          <div className="lg:col-span-4">
            <Link
              href="/"
              className="inline-flex items-center gap-2 text-[15px] font-semibold tracking-tight"
            >
              <LogoMark className="size-5" /> Farrier
            </Link>
            <p className="mt-3 max-w-xs text-white/60">
              Agentless machine identity automation. Open source, MIT licensed.
            </p>
            <a
              href={site.github}
              target="_blank"
              rel="noreferrer"
              className="mt-6 inline-flex h-10 items-center gap-2 rounded-full bg-white/10 px-4 font-medium text-white ring-1 ring-white/15 ring-inset transition-colors hover:bg-white/15"
            >
              <GithubIcon className="size-4" /> Star on GitHub
            </a>
          </div>
          <nav
            aria-label="Footer"
            className="grid grid-cols-2 gap-8 sm:grid-cols-4 lg:col-span-8"
          >
            {FOOTER_COLUMNS.map((c) => (
              <div key={c.title}>
                <h3 className="mb-3 font-medium">{c.title}</h3>
                <ul className="space-y-1">
                  {c.links.map((l) => (
                    <li key={l.label}>
                      <Link
                        href={l.href}
                        {...(l.href.startsWith("http")
                          ? { target: "_blank", rel: "noreferrer" }
                          : {})}
                        className={`inline-flex min-h-7 items-center ${muted}`}
                      >
                        {l.label}
                      </Link>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </nav>
        </div>
        <div className="mx-auto max-w-7xl px-4 sm:px-6">
          <div className="flex flex-wrap items-center justify-between gap-4 border-t border-white/10 py-6 text-white/50">
            <span>© 2026 Farrier contributors</span>
            <nav aria-label="Legal" className="flex gap-6">
              <Link
                href="/privacy"
                className={`inline-flex min-h-6 items-center ${muted}`}
              >
                Privacy
              </Link>
              <Link
                href="/terms"
                className={`inline-flex min-h-6 items-center ${muted}`}
              >
                Terms
              </Link>
              <a
                href={`${site.github}/blob/main/LICENSE`}
                className={`inline-flex min-h-6 items-center ${muted}`}
              >
                MIT licence
              </a>
            </nav>
          </div>
        </div>
      </footer>
    </>
  );
}
