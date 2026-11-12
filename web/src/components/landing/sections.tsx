/* eslint-disable @next/next/no-img-element -- small brand SVGs and icons: next/image adds nothing for these */
import Link from "next/link";
import {
  ArrowRight,
  Bot,
  Check,
  DatabaseZap,
  FileArchive,
  Fingerprint,
  KeyRound,
  Lock,
  RotateCcw,
  ScrollText,
  ShieldCheck,
  Skull,
  Timer,
  UserCheck,
  Users,
} from "lucide-react";
import { cn } from "@/lib/utils";
import Image from "next/image";

const icon = (f: string) => `/assets/icons/${f}`;
const wrap = "mx-auto w-full max-w-7xl px-4 sm:px-6";

function H2({ children, className }: { children: React.ReactNode; className?: string }) {
  return <h2 className={cn("text-3xl font-semibold tracking-[-0.02em] text-balance", className)}>{children}</h2>;
}

/* ------------------------------------------------------------------ hero */

export function Hero() {
  return (
    <section id="hero" className="relative isolate overflow-hidden bg-[#0b0b0b] pt-36 text-[#f5f5f3] sm:pt-44">
      {/* ground: a lime glow and film grain, edge to edge behind the bar, the words and the product */}
      <div aria-hidden className="absolute inset-0 -z-10">
        <div className="absolute left-1/2 top-[-20%] h-[720px] w-[1100px] -translate-x-1/2 rounded-full bg-[radial-gradient(closest-side,rgba(197,240,74,0.28),rgba(197,240,74,0))]" />
        <div className="absolute bottom-0 right-[-10%] h-[520px] w-[720px] rounded-full bg-[radial-gradient(closest-side,rgba(42,120,214,0.18),rgba(42,120,214,0))]" />
        <div className="absolute inset-0 opacity-[0.12] mix-blend-overlay [background-image:url('data:image/svg+xml;utf8,<svg xmlns=%22http://www.w3.org/2000/svg%22 width=%22160%22 height=%22160%22><filter id=%22n%22><feTurbulence type=%22fractalNoise%22 baseFrequency=%220.9%22 numOctaves=%222%22 stitchTiles=%22stitch%22/></filter><rect width=%22100%25%22 height=%22100%25%22 filter=%22url(%23n)%22/></svg>')]" />
      </div>

      <div className={cn(wrap, "text-center")}>
        <a
          href="#lifetimes"
          className="enter inline-flex items-center gap-2 rounded-full bg-white/[0.06] py-1 pl-1 pr-4 text-sm text-white/80 ring-1 ring-white/12 ring-inset transition-colors hover:bg-white/10"
        >
          <span className="rounded-full bg-[#c5f04a] px-2 py-1 text-xs font-semibold text-[#141414]">2029</span>
          47-day certificates are coming <ArrowRight className="size-3.5" />
        </a>
        <h1 className="enter [--d:80ms] mx-auto mt-8 max-w-4xl text-4xl font-semibold tracking-[-0.03em] text-balance">
          Certificate renewal for the boxes ACME can&rsquo;t reach
        </h1>
        <p className="enter [--d:160ms] mx-auto mt-6 max-w-[65ch] text-lg text-white/65">
          Renews TLS on F5, FortiGate, Palo Alto and Java keystores, and proves it went live.
        </p>
        <div className="enter [--d:240ms] mt-10 flex flex-wrap justify-center gap-4">
          <Link
            href="/docs/quickstart"
            className="inline-flex h-12 items-center gap-2 rounded-full bg-[#c5f04a] px-6 font-semibold text-[#141414] transition-colors hover:bg-[#d4f76e]"
          >
            Install Farrier <ArrowRight className="size-4" />
          </Link>
          <Link
            href="/dashboard"
            className="inline-flex h-12 items-center gap-2 rounded-full bg-white/[0.06] px-6 font-medium text-white ring-1 ring-white/20 ring-inset transition-colors hover:bg-white/10"
          >
            <span className="relative flex size-2">
              <span className="absolute inline-flex size-full animate-ping rounded-full bg-[#c5f04a] opacity-60 motion-reduce:hidden" />
              <span className="relative inline-flex size-2 rounded-full bg-[#c5f04a]" />
            </span>
            Live demo
          </Link>
        </div>
      </div>

      <div className="enter-up [--d:360ms] mx-auto mt-16 max-w-6xl px-4 sm:mt-20 sm:px-6">
        <div className="overflow-hidden rounded-t-2xl border border-b-0 border-white/15 bg-white shadow-2xl">
          {/* a real capture of /dashboard on the demo engine: regenerate when the dashboard changes */}
          <Image src="/product/dashboard.png" width={2880} height={1800} alt="The Farrier dashboard: 41 endpoints, expiring certificates, a renewal calendar and change packs awaiting a person" priority sizes="(min-width: 1152px) 1104px, 100vw" className="h-auto w-full" />
        </div>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ logos */

const DEVICES = [
  ["f5.svg", "F5 BIG-IP"],
  ["fortinet.svg", "FortiGate"],
  ["paloaltonetworks.svg", "Palo Alto"],
  ["cisco.svg", "Cisco ASA"],
  ["citrix.svg", "Citrix ADC"],
  ["tomcat.svg", "Tomcat"],
  ["kafka-icon.svg", "Kafka"],
  ["nginx.svg", "nginx"],
];

export function DeviceStrip() {
  return (
    <section className="border-b bg-background py-12">
      <div className={wrap}>
        <p className="text-center text-sm text-muted-foreground">Works with</p>
        <ul className="mt-8 grid grid-cols-2 gap-x-6 gap-y-6 sm:grid-cols-4 lg:grid-cols-8">
          {DEVICES.map(([f, n]) => (
            <li key={n} className="flex items-center justify-center gap-2 text-base font-medium">
              <img src={icon(f)} alt="" className="size-7 object-contain" />
              {n}
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ how */

const STEPS = [
  { n: "01", t: "Scan", d: "Reads what every endpoint serves.", code: "443  www-lb   expires 18 Jan" },
  { n: "02", t: "Issue", d: "Orders over DNS-01. No inbound port.", code: "TXT seen on 4/4 nameservers" },
  { n: "03", t: "Deploy", d: "Installs in the change window. The old one stays.", code: "repoint clientssl_www → new" },
  { n: "04", t: "Verify", d: "Done only when the handshake proves it.", code: "serving 3f2a…c91 · chain ok" },
];

export function How() {
  return (
    <section id="how" className="scroll-mt-16 bg-background py-24 sm:py-32">
      <div className={wrap}>
        <div className="max-w-2xl">
          <H2>One renewal, checked against the wire</H2>
        </div>
        <ol className="relative mt-16 grid gap-4 md:grid-cols-4">
          <div aria-hidden className="absolute left-0 right-0 top-6 hidden h-px bg-[repeating-linear-gradient(90deg,var(--border)_0_6px,transparent_6px_12px)] md:block" />
          {STEPS.map((s, k) => (
            <li key={s.n} className="reveal relative">
              <span
                className={cn(
                  "relative z-10 flex size-12 items-center justify-center rounded-full font-mono text-sm font-medium ring-1 ring-border",
                  k === 3 ? "bg-[#c5f04a] text-[#141414] ring-[#c5f04a]" : "bg-background",
                )}
              >
                {s.n}
              </span>
              <h3 className="mt-6 text-xl font-semibold tracking-tight">{s.t}</h3>
              <p className="mt-2 text-base text-muted-foreground">{s.d}</p>
              <p className="mt-4 rounded-lg bg-muted px-4 py-2 font-mono text-xs text-foreground/80">{s.code}</p>
            </li>
          ))}
        </ol>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ bento */

function Cell({ className, title, desc, children, dark }: { className?: string; title: string; desc: string; children: React.ReactNode; dark?: boolean }) {
  return (
    <article
      className={cn(
        "reveal flex flex-col overflow-hidden rounded-3xl p-6 ring-1 sm:p-8",
        dark ? "bg-[#0b0b0b] text-[#f5f5f3] ring-white/10" : "bg-card ring-border",
        className,
      )}
    >
      <h3 className="text-lg font-semibold tracking-tight">{title}</h3>
      <p className={cn("mt-2 text-base", dark ? "text-white/60" : "text-muted-foreground")}>{desc}</p>
      <div className="mt-6 flex flex-1 flex-col justify-end">{children}</div>
    </article>
  );
}

export function Features() {
  return (
    <section id="features" className="scroll-mt-16 bg-[var(--plane)] py-24 sm:py-32">
      <div className={wrap}>
        <div className="max-w-2xl">
          <H2>Everything a renewal needs</H2>
        </div>
        <div className="mt-14 grid gap-4 md:grid-cols-6">
          {/* agents */}
          <Cell dark className="md:col-span-4 md:row-span-2" title="Ask your agent what expires next" desc="Claude, Gemini and Codex query Farrier over MCP. Read-only by default.">
            <div className="space-y-4 rounded-2xl bg-white/[0.04] p-4 ring-1 ring-white/10 sm:p-6">
              <div className="ml-auto w-fit max-w-[85%] rounded-2xl rounded-br-md bg-white/10 px-4 py-2 text-sm">What expires before the 20 December change freeze?</div>
              <div className="flex gap-4">
                <span className="mt-1 flex size-7 shrink-0 items-center justify-center rounded-full bg-[#c5f04a] text-[#141414]">
                  <Bot className="size-4" />
                </span>
                <div className="text-sm leading-relaxed text-white/85">
                  Three certificates. <b className="text-white">www-lb</b> on F5 renews tonight at 02:00. <b className="text-white">vpn-fgt</b> is planned for 3
                  December. <b className="text-white">jira&#8209;app</b> needs a change pack, due 9 December.
                  <div className="mt-4 flex flex-wrap gap-2">
                    {["expiring_certificates", "renewal_status"].map((t) => (
                      <span key={t} className="rounded-full bg-white/[0.06] px-2 py-1 font-mono text-xs text-white/70 ring-1 ring-white/10">
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
              <div className="ml-auto w-fit rounded-2xl rounded-br-md bg-white/10 px-4 py-2 text-sm">Check jira-app&rsquo;s chain too.</div>
              <div className="flex gap-4">
                <span className="mt-1 flex size-7 shrink-0 items-center justify-center rounded-full bg-[#c5f04a] text-[#141414]">
                  <Bot className="size-4" />
                </span>
                <p className="text-sm leading-relaxed text-white/85">
                  Grade <b className="text-[#c5f04a]">C</b>. The server doesn&rsquo;t send the R11 intermediate, so older Java clients will fail.
                </p>
              </div>
            </div>
          </Cell>

          {/* health */}
          <Cell className="md:col-span-2" title="Domain health" desc="An A–F grade for every endpoint.">
            <div className="flex items-center gap-4">
              <span className="flex size-16 items-center justify-center rounded-2xl bg-[#c5f04a] text-3xl font-semibold text-[#141414]">A</span>
              <ul className="space-y-1 text-sm">
                {["Chain complete", "Names covered", "TLS 1.2+ only", "OCSP stapled"].map((c) => (
                  <li key={c} className="flex items-center gap-2">
                    <Check className="size-3.5 text-[var(--status-good-fg)]" /> {c}
                  </li>
                ))}
              </ul>
            </div>
          </Cell>

          {/* zombies */}
          <Cell className="md:col-span-2" title="Zombie scanner" desc="Certificates alive that shouldn't be.">
            <ul className="space-y-2 text-sm">
              {[
                ["Expired, still served", "asa-dc2:443"],
                ["Not issued by Farrier", "mail.corp"],
                ["Change pack never installed", "iis-07"],
              ].map(([k, v]) => (
                <li key={k} className="flex items-center gap-2 rounded-lg bg-muted px-4 py-2">
                  <Skull className="size-3.5 shrink-0 text-[var(--status-critical-fg)]" />
                  <span className="font-medium">{k}</span>
                  <span className="ml-auto font-mono text-xs text-muted-foreground">{v}</span>
                </li>
              ))}
            </ul>
          </Cell>

          {/* HA */}
          <Cell className="md:col-span-3" title="Zero downtime, on your database" desc="SQLite to start, your Postgres or MySQL when it matters.">
            <div className="flex items-end justify-center gap-4">
              {["replica-a", "replica-b", "replica-c"].map((r, k) => (
                <div key={r} className="flex flex-col items-center gap-2">
                  <span
                    className={cn(
                      "rounded-full px-2 py-1 text-xs font-medium",
                      k === 0 ? "bg-[#c5f04a] text-[#141414]" : "bg-muted text-muted-foreground",
                    )}
                  >
                    {k === 0 ? "leader" : "follower"}
                  </span>
                  <span className="flex h-14 w-24 items-center justify-center rounded-xl font-mono text-xs ring-1 ring-border">{r}</span>
                  <span className="h-6 w-px bg-border" />
                </div>
              ))}
            </div>
            <div className="mx-auto flex w-fit items-center gap-2 rounded-xl bg-muted px-4 py-2 text-sm font-medium">
              <DatabaseZap className="size-4" /> PostgreSQL · advisory lock
            </div>
          </Cell>

          {/* SSO */}
          <Cell className="md:col-span-3" title="Single sign-on and roles" desc="OIDC with three roles.">
            <div className="flex flex-wrap items-center gap-2">
              {[
                ["idp-okta.svg", "Okta"],
                ["microsoft-azure.svg", "Entra ID"],
                ["dns-google.svg", "Google"],
                ["idp-keycloak.svg", "Keycloak"],
                ["idp-auth0.svg", "Auth0"],
              ].map(([f, n]) => (
                <span key={n} className="inline-flex items-center gap-2 rounded-full px-4 py-2 text-sm font-medium ring-1 ring-border">
                  <img src={icon(f)} alt="" className="size-4" /> {n}
                </span>
              ))}
            </div>
            <div className="mt-4 grid grid-cols-3 gap-2 text-xs">
              {[
                [Users, "Viewer", "Read"],
                [UserCheck, "Operator", "Renew"],
                [KeyRound, "Admin", "Everything"],
              ].map(([I, r, d]) => {
                const Ico = I as typeof Users;
                return (
                  <div key={r as string} className="rounded-xl bg-muted p-4">
                    <Ico className="size-4" />
                    <p className="mt-2 font-semibold">{r as string}</p>
                    <p className="text-muted-foreground">{d as string}</p>
                  </div>
                );
              })}
            </div>
          </Cell>

          {/* small trio */}
          {[
            [RotateCcw, "Rolls back by itself", "Three failed handshakes and it switches back."],
            [Timer, "Change windows", "Each device renews in its own window."],
            [FileArchive, "Change packs", "Files, a runbook and a ticket for the rest."],
          ].map(([I, t, d]) => {
            const Ico = I as typeof Users;
            return (
              <article key={t as string} className="reveal rounded-3xl bg-card p-6 ring-1 ring-border md:col-span-2">
                <Ico className="size-5" />
                <h3 className="mt-4 font-semibold tracking-tight">{t as string}</h3>
                <p className="mt-2 text-base text-muted-foreground">{d as string}</p>
              </article>
            );
          })}
        </div>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ integrations */

type Tile = [string | null, string];
const GROUPS: { title: string; note: string; tiles: Tile[] }[] = [
  {
    title: "DNS providers",
    note: "29 providers, several accounts each, CNAME delegation",
    tiles: [
      ["dns-cloudflare.svg", "Cloudflare"],
      ["dns-amazonroute53.svg", "Route 53"],
      ["microsoft-azure.svg", "Azure DNS"],
      ["google-cloud.svg", "Cloud DNS"],
      ["dns-digitalocean.svg", "DigitalOcean"],
      ["dns-akamai.svg", "Akamai"],
      ["dns-hetzner.svg", "Hetzner"],
      ["dns-ovh.svg", "OVHcloud"],
      ["dns-godaddy.svg", "GoDaddy"],
      ["dns-namecheap.svg", "Namecheap"],
      ["dns-porkbun.svg", "Porkbun"],
      ["dns-scaleway.svg", "Scaleway"],
      ["dns-vultr.svg", "Vultr"],
      ["dns-infomaniak.svg", "Infomaniak"],
    ],
  },
  {
    title: "Certificate authorities",
    note: "Any ACME CA, with External Account Binding, plus a private CA",
    tiles: [
      ["letsencrypt.svg", "Let's Encrypt"],
      ["dns-google.svg", "Google Trust Services"],
      ["ca-zerossl.png", "ZeroSSL"],
      ["ca-digicert.png", "DigiCert"],
      ["ca-sectigo.png", "Sectigo"],
      ["ca-ssl.png", "SSL.com"],
      ["ca-buypass.png", "Buypass"],
      [null, "Built-in private CA"],
    ],
  },
];

export function Integrations() {
  return (
    <section id="integrations" className="scroll-mt-16 bg-background py-24 sm:py-32">
      <div className={wrap}>
        <div className="grid gap-6 lg:grid-cols-12 lg:items-end">
          <div className="lg:col-span-7">
            <H2>Your DNS, your CA, your accounts</H2>
          </div>
        </div>
        {GROUPS.map((g) => (
          <div key={g.title} className="mt-14">
            <div className="mb-4 flex flex-wrap items-baseline justify-between gap-2">
              <h3 className="font-semibold">{g.title}</h3>
            </div>
            <ul className="grid grid-cols-3 gap-2 sm:grid-cols-4 lg:grid-cols-8">
              {g.tiles.map(([f, n]) => (
                <li
                  key={n}
                  className="reveal group flex min-h-28 flex-col items-center justify-center gap-4 rounded-2xl bg-card p-4 text-center ring-1 ring-border transition-all hover:-translate-y-0.5 hover:ring-foreground/40"
                >
                  {f ? (
                    <img src={icon(f)} alt="" className="size-8 object-contain" />
                  ) : (
                    <span className="flex size-8 items-center justify-center rounded-lg bg-[#141414] text-[#c5f04a]">
                      <Lock className="size-4" />
                    </span>
                  )}
                  <span className="text-sm font-medium leading-tight">{n}</span>
                </li>
              ))}
              {g.title === "DNS providers" && (
                <li className="col-span-1 lg:col-span-2">
                  <Link
                    href="/docs/dns"
                    className="flex h-full min-h-28 flex-col justify-center rounded-2xl bg-[#141414] p-6 text-[#f5f5f3] transition-transform hover:-translate-y-0.5"
                  >
                    <span className="text-lg font-semibold">+15 more</span>
                    <span className="mt-1 text-sm text-white/60">PowerDNS, NS1, deSEC, Gandi, RFC 2136&hellip;</span>
                  </Link>
                </li>
              )}
            </ul>
          </div>
        ))}
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ lifetimes */

const LIFETIMES = [
  { when: "Today", days: 398, per: "1.4" },
  { when: "15 Mar 2026", days: 200, per: "2.7" },
  { when: "15 Mar 2027", days: 100, per: "5.5" },
  { when: "15 Mar 2029", days: 47, per: "11.7" },
];

export function Lifetimes() {
  return (
    <section id="lifetimes" className="scroll-mt-16 bg-[#0b0b0b] py-24 text-[#f5f5f3] sm:py-32">
      <div className={cn(wrap, "grid gap-14 lg:grid-cols-12")}>
        <div className="lg:col-span-5">
          <H2>Every certificate renews twelve times a year by 2029</H2>
          <p className="mt-6 text-lg text-white/60">For 1,000 certificates that is 47 renewals every working day.</p>
        </div>
        <figure className="lg:col-span-7" aria-label="Maximum certificate lifetime in days, by date">
          <ul className="space-y-6">
            {LIFETIMES.map((l, k) => (
              <li key={l.when} className="grid grid-cols-[7.5rem_1fr] items-center gap-4">
                <span className="text-sm text-white/60">{l.when}</span>
                <div className="flex items-center gap-4">
                  <div
                    className={cn("grow-x h-10 origin-left rounded-r-md rounded-l-sm", k === 3 ? "bg-[#c5f04a]" : "bg-white/85")}
                    style={{ width: `${(l.days / 398) * 100}%`, minWidth: "3.5rem" }}
                  />
                  <span className="whitespace-nowrap text-sm tabular-nums">
                    <b className="text-base">{l.days} days</b> <span className="text-white/50">· {l.per}× a year</span>
                  </span>
                </div>
              </li>
            ))}
          </ul>
          <figcaption className="mt-6 text-sm text-white/45">Maximum lifetime of a publicly trusted TLS certificate (CA/B Forum ballot SC-081), and renewals a year when each one renews at two-thirds of its life.</figcaption>
        </figure>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ deploy */

const PLATFORMS = [
  { logo: "aws.svg", t: "AWS", d: "EKS or EC2 with Secrets Manager.", code: ["secretStoreRef: aws-sm", "dns: route53"] },
  { logo: "google-cloud.svg", t: "Google Cloud", d: "GKE with Cloud SQL.", code: ["replicas: 3", "dns: google"] },
  { logo: "microsoft-azure.svg", t: "Azure", d: "AKS or a VM with Key Vault.", code: ["keyvaultName: ops-pki", "dns: azure"] },
  { logo: "kubernetes.svg", t: "On-prem", d: "Compose, Kubernetes or air-gapped.", code: ["docker compose up -d", "dns: rfc2136"] },
];

export function Deploy() {
  return (
    <section id="deploy" className="scroll-mt-16 bg-background py-24 sm:py-32">
      <div className={wrap}>
        <div className="grid gap-6 lg:grid-cols-12 lg:items-end">
          <div className="lg:col-span-7">
            <H2>Runs where your devices are</H2>
          </div>
        </div>
        <div className="mt-14 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {PLATFORMS.map((p) => (
            <article key={p.t} className="reveal flex flex-col rounded-3xl bg-card p-6 ring-1 ring-border">
              <img src={icon(p.logo)} alt="" className="size-9 object-contain" />
              <h3 className="mt-6 text-lg font-semibold tracking-tight">{p.t}</h3>
              <p className="mt-2 flex-1 text-base text-muted-foreground">{p.d}</p>
              <pre className="mt-6 rounded-xl bg-muted px-4 py-4 font-mono text-xs leading-relaxed">{p.code.join("\n")}</pre>
            </article>
          ))}
        </div>
        <div className="mt-6 overflow-hidden rounded-3xl bg-[#0b0b0b] text-[#f5f5f3] ring-1 ring-black/5">
          <div className="flex items-center gap-2 border-b border-white/10 px-6 py-4 font-mono text-xs text-white/50">
            <ScrollText className="size-3.5" /> terminal
          </div>
          <pre className="overflow-x-auto px-6 py-6 font-mono text-sm leading-7">
            <span className="text-white/40">$</span> docker compose up -d{"\n"}
            <span className="text-white/50"> ✔ farrier-engine   started   :8740</span>
            {"\n"}
            <span className="text-white/50"> ✔ farrier-web      started   :3000</span>
            {"\n"}
            <span className="text-white/40">$</span> farrier discover 10.20.0.0/24 --ports 443,8443{"\n"}
            <span className="text-[#c5f04a]"> 41 endpoints found, 18 automated, 23 change packs</span>
          </pre>
        </div>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ security */

const GUARDS = [
  [Lock, "Keys sealed at rest", "Private, account and CA keys are encrypted under your master key."],
  [Fingerprint, "No secrets in configs", "Credentials are env: or file: references. Inline values are refused."],
  [ShieldCheck, "Scoped tokens", "Read tokens can't change anything. MCP writes are off by default."],
  [ScrollText, "Every change attributed", "Each action is logged with the signed-in person or agent."],
];

export function Security() {
  return (
    <section className="bg-[var(--plane)] py-24 sm:py-32">
      <div className={cn(wrap, "grid gap-14 lg:grid-cols-12")}>
        <div className="lg:col-span-5">
          <H2>Security</H2>
          <Link href="/docs/security" className="mt-6 inline-flex items-center gap-2 font-semibold underline decoration-foreground/30 underline-offset-4 hover:decoration-foreground">
            Read the security model <ArrowRight className="size-4" />
          </Link>
        </div>
        <ul className="grid gap-4 sm:grid-cols-2 lg:col-span-7">
          {GUARDS.map(([I, t, d]) => {
            const Ico = I as typeof Lock;
            return (
              <li key={t as string} className="reveal rounded-3xl bg-card p-6 ring-1 ring-border">
                <span className="flex size-10 items-center justify-center rounded-xl bg-[#141414] text-[#c5f04a]">
                  <Ico className="size-5" />
                </span>
                <h3 className="mt-6 font-semibold tracking-tight">{t as string}</h3>
                <p className="mt-2 text-base text-muted-foreground">{d as string}</p>
              </li>
            );
          })}
        </ul>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ faq */

const FAQ = [
  ["Does an F5 or FortiGate need internet access?", "No. Farrier answers DNS-01 through your DNS and deploys over the management interface."],
  ["Which certificate authorities work?", "Let's Encrypt, ZeroSSL, Google Trust Services, Buypass, SSL.com, DigiCert and Sectigo over ACME, plus a built-in private CA."],
  ["What if a deploy breaks a profile?", "The old certificate stays installed, and Farrier switches back if the new one never goes live."],
  ["Which database does it need?", "None to start: SQLite is built in. For several replicas, point it at your own PostgreSQL or MySQL."],
  ["What does it cost?", "Nothing. It is MIT licensed and runs on your own machines, with no hosted service and no account."],
  ["Has it run on real F5 hardware?", "Not yet. The appliance connectors pass tests against mock APIs. Start on a lab device."],
];

export function Faq() {
  return (
    <section className="bg-background py-24 sm:py-32">
      <div className={cn(wrap, "grid gap-12 lg:grid-cols-12")}>
        <div className="lg:col-span-4">
          <H2>Questions</H2>
          <a
            href="https://github.com/gagankarthik/farrier/issues"
            className="mt-6 inline-flex items-center gap-2 font-semibold underline decoration-foreground/30 underline-offset-4 hover:decoration-foreground"
          >
            Ask on GitHub <ArrowRight className="size-4" />
          </a>
        </div>
        <div className="divide-y border-y lg:col-span-8">
          {FAQ.map(([q, a]) => (
            <details key={q} className="group py-1">
              <summary className="flex cursor-pointer list-none items-center justify-between gap-6 py-4 text-lg font-medium">
                {q}
                <span className="flex size-8 shrink-0 items-center justify-center rounded-full ring-1 ring-border transition-transform group-open:rotate-45">+</span>
              </summary>
              <p className="pb-6 pr-14 text-muted-foreground">{a}</p>
            </details>
          ))}
        </div>
      </div>
    </section>
  );
}
