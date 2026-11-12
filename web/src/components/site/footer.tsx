import Link from "next/link";
import { ArrowRight } from "lucide-react";
import { GithubIcon, LogoMark } from "@/components/brand";
import { site } from "@/lib/site";
import { FOOTER_COLUMNS } from "./nav-data";

function FLink({ href, children }: { href: string; children: React.ReactNode }) {
  const cls = "inline-flex min-h-8 items-center text-base text-white/75 transition-colors hover:text-[#60a5fa]";
  return href.startsWith("http") ? (
    <a href={href} target="_blank" rel="noreferrer" className={cls}>
      {children}
    </a>
  ) : (
    <a href={href} className={cls}>
      {children}
    </a>
  );
}

/** The closing call to action and the footer, on every marketing and docs page. */
export function SiteFooter({ cta = true }: { cta?: boolean }) {
  return (
    <footer className="relative overflow-hidden bg-[#0b0b0b] text-[#f5f5f3] [&_:focus-visible]:outline-[#60a5fa]">
      <div className="mx-auto max-w-7xl px-4 sm:px-6">
        {cta && (
          // the one blue surface on the page: the pitch on the left, the three commands that prove it on the right
          <div className="mt-20 grid overflow-hidden rounded-[32px] bg-[#2563eb] text-white lg:grid-cols-2">
            <div className="min-w-0 p-8 sm:p-12 lg:py-16">
              <h2 className="max-w-[14ch] text-3xl font-semibold tracking-[-0.02em]">
                Renew your first appliance tonight
              </h2>
              <p className="mt-6 max-w-md text-lg text-white/80">
                Open source and self-hosted. Running in five minutes.
              </p>
              <div className="mt-8 flex flex-wrap gap-4">
                <Link
                  href="/docs/quickstart"
                  className="inline-flex h-12 items-center gap-2 rounded-full bg-white px-6 font-semibold text-[#2563eb] hover:bg-white/90"
                >
                  Install Farrier <ArrowRight className="size-4" />
                </Link>
                <Link
                  href="/dashboard"
                  className="inline-flex h-12 items-center rounded-full px-6 font-semibold ring-1 ring-white/40 ring-inset hover:ring-white"
                >
                  Open the live demo
                </Link>
              </div>
            </div>
            <div className="flex min-w-0 items-end pl-8 pt-2 sm:pl-12 lg:pt-16">
              <pre className="w-full overflow-x-auto rounded-tl-2xl bg-[#0b0b0b] p-6 font-mono text-sm leading-7 text-white/70">
                <span className="text-white/40">$</span> <span className="text-white">pip install farrier-tls</span>
                {"\n"}
                <span className="text-white/40">$</span> <span className="text-white">farrier demo</span>
                {"\n"}  41 endpoints on 127.0.0.1, 18 automated{"\n"}  <span className="text-[#60a5fa]">✔</span> nginx-01   renewed   verified live{"\n"}  <span className="text-[#60a5fa]">✔</span> tomcat-03  renewed   verified live{"\n"}  <span className="text-[#60a5fa]">●</span> asa-dc1    change pack, ticket opened{"\n"}
                <span className="text-white/40">$</span> <span className="text-white">open http://localhost:3000/dashboard</span>
              </pre>
            </div>
          </div>
        )}

        <div className="grid gap-12 py-16 lg:grid-cols-12">
          <div className="lg:col-span-4">
            <Link href="/" className="inline-flex items-center gap-2 text-xl font-semibold tracking-tight">
              <LogoMark className="size-6" /> Farrier
            </Link>
            <p className="mt-4 max-w-xs text-white/60">Agentless machine identity automation: TLS certificates, SSH keys and PQC readiness.</p>
            <a
              href={site.github}
              target="_blank"
              rel="noreferrer"
              className="mt-6 inline-flex h-10 items-center gap-2 rounded-full px-4 text-sm font-medium ring-1 ring-white/20 ring-inset hover:ring-white"
            >
              <GithubIcon className="size-4" /> Star on GitHub
            </a>
          </div>
          <nav aria-label="Footer" className="grid grid-cols-2 gap-8 sm:grid-cols-4 lg:col-span-8">
            {FOOTER_COLUMNS.map((c) => (
              <div key={c.title}>
                <h3 className="mb-4 text-sm font-medium text-white/45">{c.title}</h3>
                <ul>
                  {c.links.map((l) => (
                    <li key={l.label}>
                      <FLink href={l.href}>{l.label}</FLink>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </nav>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-4 border-t border-white/10 py-6 text-sm text-white/45">
          <span>© 2026 Farrier contributors</span>
          <nav aria-label="Legal" className="flex gap-6">
            <Link href="/privacy" className="inline-flex min-h-6 items-center hover:text-white">
              Privacy
            </Link>
            <Link href="/terms" className="inline-flex min-h-6 items-center hover:text-white">
              Terms
            </Link>
            <a href={`${site.github}/blob/main/LICENSE`} className="inline-flex min-h-6 items-center hover:text-white">
              MIT licence
            </a>
          </nav>
        </div>
      </div>
      <p
        aria-hidden
        className="pointer-events-none -mb-[0.22em] select-none text-center text-[22vw] font-semibold leading-[0.8] tracking-[-0.06em] text-transparent [-webkit-text-stroke:1px_rgba(245,245,243,0.12)]"
      >
        Farrier
      </p>
    </footer>
  );
}
