/* eslint-disable @next/next/no-img-element -- small brand SVGs and icons: next/image adds nothing for these */
import Link from "next/link";
import {
  ArrowRight,
  Bot,
  CalendarClock,
  DatabaseZap,
  FileArchive,
  Lock,
  RotateCcw,
  ShieldCheck,
  Skull,
  Sparkles,
  Users,
  type LucideIcon,
} from "lucide-react";
import { asset, site } from "@/lib/site";
import { cn } from "@/lib/utils";

const icon = (f: string) => asset(`/assets/icons/${f}`);
const wrap = "mx-auto w-full max-w-7xl px-4 sm:px-6";
const panel = "rounded-[24px] bg-[var(--l-panel)] sm:rounded-[32px]";
const frame = "rounded-2xl bg-[var(--l-frame)] ring-1 ring-black/[0.04] shadow-[0_1px_3px_rgb(0_0_0/0.06)] dark:ring-white/[0.06]";
const h2 = "text-[30px] font-semibold leading-[1.1] tracking-[-0.03em] text-balance sm:text-[40px]";
const pill = "inline-flex h-10 items-center gap-1 rounded-full px-4 text-[15px] font-medium transition-colors";
const primary = cn(pill, "bg-[#2563eb] text-white hover:bg-[#1d4ed8]");
const secondary = cn(pill, "bg-[var(--l-pill)] hover:bg-[var(--l-pill-hover)]");
const logo = "transition-transform duration-200 hover:scale-110";  // brand colours, as the vendors ship them
// marks drawn in black or a very dark brand colour vanish on the dark ground: show them in white there
const DARK_INK = new Set(["splunk.svg", "kafka-icon.svg", "aws.svg", "citrix.svg", "dns-ovh.svg"]);
const onDark = (f: string) => (DARK_INK.has(f) ? "dark:brightness-0 dark:invert" : undefined);

/* ------------------------------------------------------------------ hero */

/** A small app-icon tile that sits inline in the headline, one em tall. */
/** One headline word, animated on its own. */
function W({ i, children }: { i: number; children: string }) {
  return (
    <span data-hw className="inline-block" style={{ "--i": i } as React.CSSProperties}>
      {children}
    </span>
  );
}

function Tile({ i, src }: { i: number; src: string }) {
  return (
    <span
      aria-hidden
      data-hw
      data-hw-tile
      style={{ "--i": i } as React.CSSProperties}
      className="mx-[0.06em] inline-flex size-[0.86em] -translate-y-[0.06em] items-center justify-center rounded-[0.22em] bg-white align-middle shadow-[0_2px_8px_rgb(0_0_0/0.12)] ring-1 ring-black/5"
    >
      <img src={icon(src)} alt="" width={48} height={48} decoding="async" className="size-[58%] object-contain" />
    </span>
  );
}

const WORKS_WITH: [string, string][] = [
  ["letsencrypt.svg", "Let's Encrypt"],
  ["dns-google.svg", "Google Trust Services"],
  ["ca-zerossl.png", "ZeroSSL"],
  ["ca-digicert.png", "DigiCert"],
  ["ca-sectigo.png", "Sectigo"],
  ["ca-ssl.png", "SSL.com"],
  ["ca-buypass.png", "Buypass"],
  ["dns-cloudflare.svg", "Cloudflare"],
  ["dns-amazonroute53.svg", "Amazon Route 53"],
  ["microsoft-azure.svg", "Azure DNS"],
  ["google-cloud.svg", "Google Cloud DNS"],
  ["dns-digitalocean.svg", "DigitalOcean"],
  ["dns-akamai.svg", "Akamai"],
  ["dns-hetzner.svg", "Hetzner"],
  ["dns-ovh.svg", "OVHcloud"],
  ["dns-godaddy.svg", "GoDaddy"],
  ["dns-namecheap.svg", "Namecheap"],
  ["dns-porkbun.svg", "Porkbun"],
];

export function Hero() {
  return (
    <section id="hero" className="pt-14 sm:pt-24">
      <div className={cn(wrap, "text-center")}>
        <h1 className="mx-auto max-w-5xl text-[44px] font-semibold leading-[1.05] tracking-[-0.03em] text-balance sm:text-[64px] lg:text-[84px]">
          <W i={0}>Every</W> <Tile i={1} src="letsencrypt.svg" /> <W i={2}>machine</W> <W i={3}>identity,</W>
          <br className="hidden sm:inline" /> <Tile i={4} src="key.svg" /> <W i={5}>managed</W> <Tile i={6} src="f5.svg" />
          <br className="hidden sm:inline" /> <W i={7}>without</W> <W i={8}>agents.</W>
        </h1>
        <p data-hero-item style={{ "--i": 0 } as React.CSSProperties} className="mx-auto mt-6 max-w-[34rem] text-[17px] leading-[1.5] text-[var(--l-sub)]">
          Farrier finds and renews TLS certificates, inventories SSH keys, maps your cryptography and tracks post-quantum readiness.
        </p>
        <p data-hero-item style={{ "--i": 1 } as React.CSSProperties} className="mt-2 text-[15px] font-medium">No agents. No manual renewals. No missed expirations.</p>
        <div data-hero-item style={{ "--i": 2 } as React.CSSProperties} className="mt-8 flex flex-wrap justify-center gap-2">
          <Link href="/docs/quickstart" className={primary}>
            Install Farrier
          </Link>
          <Link href={site.demo} className={secondary}>
            Try it <ArrowRight className="size-4" />
          </Link>
        </div>
      </div>

      <div id="integrations" className={cn(wrap, "scroll-mt-20 pt-20 sm:pt-28")}>
        <div data-reveal className="border-b border-[var(--l-line)] pb-16 sm:pb-20">
          <p className="text-center text-[13px] text-[var(--l-sub)]">Works with your certificate authorities and DNS providers</p>
          <div className="l-row mt-8 [mask-image:linear-gradient(90deg,transparent,#000_8%,#000_92%,transparent)]">
            <ul className="l-track py-1 [animation-duration:45s]">
              {[false, true].map((dup) =>
                WORKS_WITH.map(([f, n]) => (
                  <li
                    key={`${n}${dup ? "-dup" : ""}`}
                    aria-hidden={dup || undefined}
                    className={cn("shrink-0 items-center gap-2 rounded-full border border-[var(--l-line)] bg-background px-4 py-2", dup ? "l-dup" : "flex")}
                  >
                    <img src={icon(f)} alt="" width={24} height={24} decoding="async" className={cn("size-6 object-contain", onDark(f))} />
                    <span className="text-sm font-medium">{n}</span>
                  </li>
                )),
              )}
            </ul>
          </div>
          <p className="mt-8 text-center text-[13px]">
            <Link href="/docs/dns" className="text-[var(--l-sub)] underline decoration-[var(--l-line)] underline-offset-4 hover:text-foreground">
              Any ACME CA, a built-in private CA and 29 DNS providers
            </Link>
          </p>
        </div>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ how: one statement, one visual */

const LIFETIMES = [
  { when: "Until 2026", days: 398 },
  { when: "Mar 2026", days: 200 },
  { when: "Mar 2027", days: 100 },
  { when: "Mar 2029", days: 47 },
];

export function How() {
  return (
    <section id="how" className="scroll-mt-20 py-24 sm:py-32">
      <div className={wrap}>
        <div data-reveal className="max-w-4xl text-[28px] font-semibold leading-[1.15] tracking-[-0.025em] sm:text-[40px]">
          <h2 className="text-balance">Renewals that check their own work.</h2>
          <p className="mt-1 text-[var(--l-quiet)]">
            Farrier scans, orders over DNS-01, installs in your change window and calls it done only when the handshake proves it. Ready for 47-day certificates.
          </p>
        </div>

        <figure data-reveal className={cn(panel, "mt-14 p-2 sm:p-10")}>
          <div className={cn(frame, "p-5 sm:p-8")}>
            <ul className="space-y-4" aria-label="Maximum certificate lifetime in days, by date">
              {LIFETIMES.map((l, k) => (
                <li key={l.when} className="grid grid-cols-[4.5rem_1fr] items-center gap-3 sm:grid-cols-[6rem_1fr] sm:gap-4">
                  <span className="text-[13px] text-[var(--l-sub)] sm:text-sm">{l.when}</span>
                  <div className="flex min-w-0 items-center gap-3">
                    <div
                      data-bar
                      className={cn("h-7 shrink-0 rounded-md sm:h-8", k === 3 ? "bg-[#2563eb]" : "bg-foreground/85")}
                      style={{ width: `${(l.days / 398) * 72}%`, minWidth: "1.5rem" }}
                    />
                    <span className="whitespace-nowrap text-sm font-medium tabular-nums">{l.days} days</span>
                  </div>
                </li>
              ))}
            </ul>
          </div>
          <figcaption className="px-3 pb-2 pt-4 text-[13px] text-[var(--l-sub)] sm:px-0 sm:pb-0 sm:pt-6">
            Maximum lifetime of a public TLS certificate, CA/B Forum ballot SC-081.
          </figcaption>
        </figure>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ features: a drifting row of cards */

type Tone = { bg: string; fg: string };
const TONES: Record<string, Tone> = {
  blue: { bg: "bg-[#e8efff] dark:bg-[#14254a]", fg: "text-[#2563eb] dark:text-[#93b4fd]" },
  green: { bg: "bg-[#e3f6e8] dark:bg-[#12301c]", fg: "text-[#16a34a] dark:text-[#6ee7a0]" },
  red: { bg: "bg-[#fde8e8] dark:bg-[#3a1515]", fg: "text-[#dc2626] dark:text-[#fca5a5]" },
  amber: { bg: "bg-[#fdf1dc] dark:bg-[#3a2a0f]", fg: "text-[#d97706] dark:text-[#fcd34d]" },
  violet: { bg: "bg-[#efe9ff] dark:bg-[#2a1f4a]", fg: "text-[#7c3aed] dark:text-[#c4b5fd]" },
  teal: { bg: "bg-[#e0f5f3] dark:bg-[#0f302d]", fg: "text-[#0d9488] dark:text-[#5eead4]" },
};

const FEATURES: { t: string; d: string; Icon: LucideIcon; tone: keyof typeof TONES }[] = [
  { t: "Ask your agent", d: "Claude, Gemini and Codex over MCP. Read-only by default.", Icon: Bot, tone: "violet" },
  { t: "Domain health", d: "An A to F grade for every endpoint.", Icon: ShieldCheck, tone: "green" },
  { t: "Zombie scanner", d: "Certificates still alive that should not be.", Icon: Skull, tone: "red" },
  { t: "Rolls back by itself", d: "If the new certificate never shows up live, the old one goes back.", Icon: RotateCcw, tone: "amber" },
  { t: "Change windows", d: "Each device renews in its own window, with daily caps.", Icon: CalendarClock, tone: "blue" },
  { t: "Change packs", d: "Files, a runbook and a ticket for devices without an API.", Icon: FileArchive, tone: "teal" },
  { t: "Single sign-on", d: "OIDC with viewer, operator and admin roles.", Icon: Users, tone: "violet" },
  { t: "Zero-downtime HA", d: "SQLite to start, your Postgres or MySQL when it matters.", Icon: DatabaseZap, tone: "blue" },
  { t: "Keys sealed, changes signed", d: "Keys encrypted under your master key; every action attributed.", Icon: Lock, tone: "green" },
];

function FeatureCard({ f, dup }: { f: (typeof FEATURES)[number]; dup?: boolean }) {
  const tone = TONES[f.tone];
  return (
    <article
      aria-hidden={dup || undefined}
      className={cn("w-[260px] shrink-0 flex-col rounded-3xl bg-[var(--l-panel)] p-6 sm:w-[300px]", dup ? "l-dup" : "flex")}
    >
      <span className={cn("flex size-12 items-center justify-center rounded-2xl", tone.bg)}>
        <f.Icon className={cn("size-6", tone.fg)} strokeWidth={1.75} />
      </span>
      <h3 className="mt-8 text-[17px] font-semibold">{f.t}</h3>
      <p className="mt-1 text-sm text-[var(--l-sub)]">{f.d}</p>
    </article>
  );
}

export function Features() {
  return (
    <section id="features" className="scroll-mt-20 pb-24 sm:pb-32">
      <div className={wrap}>
        <h2 className="flex items-center gap-3 text-[22px] font-semibold tracking-[-0.02em]">
          <span className="flex size-8 items-center justify-center rounded-lg bg-[var(--l-panel)]">
            <Sparkles className="size-4" />
          </span>
          The parts that usually break
        </h2>
        <p className="mt-2 text-[15px] text-[var(--l-sub)]">Handled, so a renewal at 02:00 needs nobody awake.</p>
      </div>
      {/* full bleed, like a shelf: scrolls inside itself, never the page */}
      <div data-reveal className="l-row mt-8 px-4 sm:px-6" tabIndex={0} role="region" aria-label="Features">
        <div className="l-track">
          {FEATURES.map((f) => (
            <FeatureCard key={f.t} f={f} />
          ))}
          {FEATURES.map((f) => (
            <FeatureCard key={`${f.t}-dup`} f={f} dup />
          ))}
        </div>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ platform: three equal cards, one illustration each */

/** Flat illustrations on a 240x160 canvas; the pale grounds swap for deep tints in dark mode. */
function CertArt() {
  return (
    <svg viewBox="0 0 240 160" className="h-auto w-full max-w-[260px]" aria-hidden>
      <circle cx="120" cy="80" r="64" fill="#e8efff" className="dark:fill-[#14254a]" />
      <rect x="72" y="34" width="96" height="92" rx="10" fill="#fff" stroke="#c7d6fb" strokeWidth="2" className="dark:fill-[#0f1830] dark:stroke-[#2c4a8a]" />
      <rect x="86" y="50" width="52" height="7" rx="3.5" fill="#2563eb" />
      <rect x="86" y="64" width="68" height="5" rx="2.5" fill="#dbe5fd" className="dark:fill-[#2c4a8a]" />
      <rect x="86" y="75" width="60" height="5" rx="2.5" fill="#dbe5fd" className="dark:fill-[#2c4a8a]" />
      <rect x="86" y="86" width="40" height="5" rx="2.5" fill="#dbe5fd" className="dark:fill-[#2c4a8a]" />
      <path d="M142 128l-6 18 10-5 6 9 4-18z" fill="#1d4ed8" />
      <circle cx="150" cy="112" r="20" fill="#2563eb" />
      <path d="M140 112l7 7 13-14" stroke="#fff" strokeWidth="4" fill="none" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M44 92a40 40 0 0 1 14-38" stroke="#93b4fd" strokeWidth="4" fill="none" strokeLinecap="round" />
      <path d="M52 50l8 4-2 9" stroke="#93b4fd" strokeWidth="4" fill="none" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M196 68a40 40 0 0 1-14 38" stroke="#93b4fd" strokeWidth="4" fill="none" strokeLinecap="round" />
      <path d="M188 110l-8-4 2-9" stroke="#93b4fd" strokeWidth="4" fill="none" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function KeyArt() {
  return (
    <svg viewBox="0 0 240 160" className="h-auto w-full max-w-[260px]" aria-hidden>
      <circle cx="120" cy="80" r="64" fill="#efe9ff" className="dark:fill-[#2a1f4a]" />
      <rect x="58" y="40" width="112" height="76" rx="10" fill="#1e1b2e" className="dark:fill-[#120f1f]" />
      <circle cx="70" cy="52" r="3" fill="#f87171" />
      <circle cx="80" cy="52" r="3" fill="#fbbf24" />
      <circle cx="90" cy="52" r="3" fill="#4ade80" />
      <path d="M70 72l8 6-8 6" stroke="#c4b5fd" strokeWidth="3" fill="none" strokeLinecap="round" strokeLinejoin="round" />
      <rect x="84" y="82" width="30" height="4" rx="2" fill="#c4b5fd" />
      <rect x="70" y="96" width="56" height="4" rx="2" fill="#4c4470" />
      <path d="M174 118l22 22" stroke="#7c3aed" strokeWidth="10" strokeLinecap="round" />
      <path d="M186 130l-7 7M194 138l-6 6" stroke="#7c3aed" strokeWidth="7" strokeLinecap="round" />
      <circle cx="158" cy="104" r="22" fill="#7c3aed" />
      <circle cx="158" cy="104" r="8" fill="#efe9ff" className="dark:fill-[#2a1f4a]" />
    </svg>
  );
}

function QuantumArt() {
  return (
    <svg viewBox="0 0 240 160" className="h-auto w-full max-w-[260px]" aria-hidden>
      <circle cx="120" cy="80" r="64" fill="#e0f5f3" className="dark:fill-[#0f302d]" />
      <ellipse cx="120" cy="80" rx="74" ry="24" fill="none" stroke="#5eead4" strokeWidth="3" />
      <ellipse cx="120" cy="80" rx="74" ry="24" fill="none" stroke="#2dd4bf" strokeWidth="3" transform="rotate(60 120 80)" />
      <ellipse cx="120" cy="80" rx="74" ry="24" fill="none" stroke="#99f6e4" strokeWidth="3" transform="rotate(-60 120 80)" />
      <circle cx="194" cy="80" r="6" fill="#0d9488" />
      <circle cx="83" cy="16" r="6" fill="#2dd4bf" />
      <circle cx="83" cy="144" r="6" fill="#14b8a6" />
      <path d="M120 50l26 10v20c0 18-12 28-26 34-14-6-26-16-26-34V60z" fill="#0d9488" />
      <path d="M109 82l8 8 15-17" stroke="#fff" strokeWidth="4.5" fill="none" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

const PILLARS: { t: string; d: string; Art: () => React.ReactNode }[] = [
  { t: "TLS certificates", d: "Found, renewed and verified on the wire.", Art: CertArt },
  { t: "SSH keys", d: "Host keys and authorized_keys, read over SSH.", Art: KeyArt },
  { t: "Crypto and PQC", d: "Ciphers and key exchange, with post-quantum readiness.", Art: QuantumArt },
];

const TOOLS: [string | null, string][] = [
  [null, "ServiceNow"],
  ["jira.svg", "Jira"],
  ["datadog.svg", "Datadog"],
  ["splunk.svg", "Splunk"],
];

export function Platform() {
  return (
    <section id="platform" className="scroll-mt-20 pb-24 sm:pb-32">
      <div className={wrap}>
        <h2 data-reveal className={cn(h2, "text-center")}>One platform for every machine identity</h2>
        <div data-stagger className="mt-12 grid gap-4 md:grid-cols-3">
          {PILLARS.map((p) => (
            <article key={p.t} className="flex flex-col rounded-3xl bg-[var(--l-panel)] p-3">
              <div className="px-4 pb-6 pt-6 text-center">
                <h3 className="text-[19px] font-semibold tracking-[-0.01em]">{p.t}</h3>
                <p className="mt-1 text-sm text-[var(--l-sub)]">{p.d}</p>
              </div>
              <div className={cn(frame, "flex min-h-[200px] flex-1 items-center justify-center p-6")}>
                <p.Art />
              </div>
            </article>
          ))}
        </div>
        <div data-reveal className="mt-12 text-center">
          <p className="text-[13px] text-[var(--l-sub)]">Tickets and events go to</p>
          <ul className="mt-6 flex flex-wrap items-center justify-center gap-x-12 gap-y-6">
            {TOOLS.map(([f, n]) => (
              <li key={n} title={n}>
                {f ? (
                  <img src={icon(f)} alt={n} width={40} height={40} loading="lazy" decoding="async" className={cn("object-contain", n === "Splunk" ? "h-auto w-32 -my-6" : "h-10 w-auto", logo, onDark(f))} />
                ) : (
                  // no official mark ships in the icon set; the name in ServiceNow green stands in
                  <span className={cn("block text-[26px] font-bold tracking-[-0.03em] text-[#62d84e]", logo)}>servicenow</span>
                )}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ devices: split */

const DEVICES: [string, string][] = [
  ["f5.svg", "F5 BIG-IP"],
  ["fortinet.svg", "FortiGate"],
  ["paloaltonetworks.svg", "Palo Alto"],
  ["cisco.svg", "Cisco ASA"],
  ["citrix.svg", "Citrix ADC"],
  ["tomcat.svg", "Tomcat"],
  ["kafka-icon.svg", "Kafka"],
  ["nginx.svg", "nginx"],
];

export function Devices() {
  return (
    <section className="pb-24 sm:pb-32">
      <div className={cn(wrap, "grid items-center gap-10 lg:grid-cols-12 lg:gap-12")}>
        <div data-reveal className="min-w-0 lg:col-span-5">
          <h2 className={h2}>Renews the appliances other tools skip</h2>
          <p className="mt-4 max-w-md text-[17px] text-[var(--l-sub)]">
            F5, FortiGate and Palo Alto through their own APIs. Everything else gets a change pack and a ticket.
          </p>
          <Link href="/docs/connectors" className={cn(secondary, "mt-8")}>
            See connectors <ArrowRight className="size-4" />
          </Link>
          <ul data-stagger className="mt-10 flex flex-wrap gap-5">
            {DEVICES.map(([f, n]) => (
              <li key={n}>
                <img src={icon(f)} alt={n} title={n} width={28} height={28} loading="lazy" decoding="async" className={cn("size-7 object-contain", logo, onDark(f))} />
              </li>
            ))}
          </ul>
        </div>
        <div data-reveal className={cn(panel, "min-w-0 p-2 sm:p-10 lg:col-span-7")}>
          <div className={cn(frame, "overflow-hidden")}>
            <div className="flex items-center gap-1.5 border-b border-[var(--l-line)] px-4 py-3">
              <span className="size-2.5 rounded-full bg-[var(--l-line)]" />
              <span className="size-2.5 rounded-full bg-[var(--l-line)]" />
              <span className="size-2.5 rounded-full bg-[var(--l-line)]" />
              <span className="ml-2 font-mono text-xs text-[var(--l-sub)]">farrier</span>
            </div>
            <pre data-type className="overflow-x-auto p-4 font-mono text-[12px] leading-6 sm:p-6 sm:text-[13px] sm:leading-7">
              <span className="text-[var(--l-sub)]">$</span> farrier scan 10.20.0.0/24{"\n"}
              <span className="text-[var(--l-sub)]">  41 endpoints, 18 automated, 23 change packs</span>
              {"\n"}
              <span className="text-[var(--l-sub)]">$</span> farrier tick{"\n"}
              {"  "}<span className="text-[var(--status-good-fg)]">✔</span> www-lb    F5 BIG-IP   verified live{"\n"}
              {"  "}<span className="text-[var(--status-good-fg)]">✔</span> vpn-fgt   FortiGate   verified live{"\n"}
              {"  "}<span className="text-[var(--status-good-fg)]">✔</span> edge-pa   Palo Alto   verified live{"\n"}
              {"  "}<span className="text-[var(--status-warning-fg)]">●</span> asa-dc1   Cisco ASA   change pack, ticket opened{"\n"}
              <span className="text-[var(--l-sub)]">$</span> <span className="inline-block h-4 w-2 translate-y-0.5 bg-foreground motion-safe:animate-pulse" />
            </pre>
          </div>
        </div>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ deploy */

const PLATFORMS = [
  { logo: "aws.svg", t: "AWS", d: "ECS Fargate with Secrets Manager and RDS." },
  { logo: "google-cloud.svg", t: "Google Cloud", d: "Cloud Run with Cloud SQL and Secret Manager." },
  { logo: "microsoft-azure.svg", t: "Azure", d: "Container Apps with Key Vault and Front Door." },
  { logo: "docker.svg", t: "On-prem", d: "Docker Compose, Helm on Kubernetes, or air-gapped." },
];

export function Deploy() {
  return (
    <section id="deploy" className="scroll-mt-20 pb-24 sm:pb-32">
      <div className={wrap}>
        <h2 data-reveal className={cn(h2, "text-center")}>Runs where your devices are</h2>
        <p className="mx-auto mt-4 max-w-xl text-center text-[17px] text-[var(--l-sub)]">Self-hosted on your own machines. No account, no hosted service.</p>
        <div data-stagger className="mt-12 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {PLATFORMS.map((p) => (
            <article key={p.t} className="flex flex-col rounded-3xl bg-[var(--l-panel)] p-3">
              <div className="flex-1 px-3 pb-5 pt-4">
                <img src={icon(p.logo)} alt="" width={32} height={32} loading="lazy" decoding="async" className={cn("size-8 object-contain", onDark(p.logo))} />
                <h3 className="mt-4 text-[17px] font-semibold">{p.t}</h3>
                <p className="mt-1 text-sm text-[var(--l-sub)]">{p.d}</p>
              </div>
              <Link href="/docs/install" className={cn(frame, "flex items-center justify-between px-4 py-3 text-sm font-medium transition-colors hover:text-[#2563eb]")}>
                Install guide <ArrowRight className="size-4" />
              </Link>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ faq */

export const FAQ = [
  ["Do I install an agent on each machine?", "No. Farrier reads TLS and SSH over the network and makes changes through each device's management API or SSH."],
  ["Does an F5 or FortiGate need internet access?", "No. Farrier answers DNS-01 through your DNS and deploys over the management interface."],
  ["Which certificate authorities work?", "Let's Encrypt, ZeroSSL, Google Trust Services, Buypass, SSL.com, DigiCert, Sectigo and AWS Certificate Manager over ACME; AWS Private CA and Google CAS; and a built-in private CA."],
  ["Are renewals automatic?", "Yes. Farrier plans each renewal from the certificate's lifetime and the CA's renewal window, renews inside your change windows, deploys, verifies and rolls back on its own. Devices without an API get a ready change pack and a ticket."],
  ["What if a deploy breaks a profile?", "The old certificate stays installed, and Farrier switches back if the new one never goes live."],
  ["What does it cost?", "Nothing. It is MIT licensed and runs on your own machines, with no hosted service and no account."],
  ["How is it tested?", "Every commit runs the renewal engine, each vendor API contract and Let's Encrypt's Pebble test CA; Let's Encrypt staging and AWS ACM run nightly. Start production with the pilot checklist on one endpoint per device type."],
];

export function Faq() {
  return (
    <section className="pb-24 sm:pb-32">
      <div className="mx-auto w-full max-w-3xl px-4 sm:px-6">
        <h2 data-reveal className={cn(h2, "text-center")}>Questions</h2>
        <div data-reveal className="mt-10 divide-y divide-[var(--l-line)] border-y border-[var(--l-line)]">
          {FAQ.map(([q, a]) => (
            <details key={q} className="group">
              <summary className="flex cursor-pointer list-none items-center justify-between gap-6 py-5 text-[17px] font-medium">
                {q}
                <span
                  aria-hidden
                  className="flex size-7 shrink-0 items-center justify-center rounded-full bg-[var(--l-pill)] text-lg leading-none transition-transform group-open:rotate-45"
                >
                  +
                </span>
              </summary>
              <p className="-mt-1 pb-5 pr-12 text-[15px] text-[var(--l-sub)]">{a}</p>
            </details>
          ))}
        </div>
        <p className="mt-6 text-center text-sm text-[var(--l-sub)]">
          Something else?{" "}
          <a href="https://github.com/gagankarthik/farrier/issues" className="font-medium text-foreground underline decoration-[var(--l-line)] underline-offset-4 hover:decoration-foreground">
            Ask on GitHub
          </a>
        </p>
      </div>
    </section>
  );
}

