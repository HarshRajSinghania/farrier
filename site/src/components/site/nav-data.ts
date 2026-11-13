/** One source for the top bar's menus and the footer's columns, on every page. */
import { site } from "@/lib/site";
export type NavLink = { href: string; label: string; desc?: string };
export type NavMenu = { label: string; href: string; groups: { title: string; links: NavLink[] }[] };

export const MENUS: NavMenu[] = [
  {
    label: "Product",
    href: "/#platform",
    groups: [
      {
        title: "Platform",
        links: [
          { href: "/#platform", label: "TLS certificates", desc: "Found, renewed and verified live" },
          { href: "/#platform", label: "SSH keys", desc: "Host keys and authorized_keys" },
          { href: "/#platform", label: "Crypto and PQC", desc: "Readiness and a CBOM export" },
        ],
      },
      {
        title: "Operate",
        links: [
          { href: "/#how", label: "How a renewal runs", desc: "And what 47-day certificates mean" },
          { href: "/#features", label: "AI agents", desc: "Claude, Gemini and Codex over MCP" },
          { href: site.demo, label: "Try it", desc: "The dashboard on a demo estate, on your laptop" },
        ],
      },
    ],
  },
  {
    label: "Integrations",
    href: "/#integrations",
    groups: [
      {
        title: "Devices",
        links: [
          { href: "/docs/connectors", label: "F5, FortiGate, Palo Alto, Citrix", desc: "Renewed through each vendor's API" },
          { href: "/docs/connectors", label: "Keystores and files", desc: "Tomcat, Kafka, nginx over SSH" },
          { href: "/docs/connectors", label: "IIS, Kubernetes, change packs", desc: "Windows over SSH, TLS Secrets, Cisco ASA and the rest" },
        ],
      },
      {
        title: "DNS and CAs",
        links: [
          { href: "/docs/dns", label: "29 DNS providers", desc: "Several accounts each" },
          { href: "/docs/dns#certificate-authorities", label: "Certificate authorities", desc: "Let's Encrypt, ZeroSSL, Google" },
          { href: "/docs/sso", label: "Single sign-on", desc: "Okta, Entra ID, Google, Keycloak" },
        ],
      },
    ],
  },
  {
    label: "Docs",
    href: "/docs",
    groups: [
      {
        title: "Get started",
        links: [
          { href: "/docs/quickstart", label: "Quickstart", desc: "Running in five minutes" },
          { href: "/docs/concepts", label: "Core concepts", desc: "Endpoints, renewals, windows" },
          { href: "/docs/self-hosting", label: "Self-hosting", desc: "One machine to a cluster" },
        ],
      },
      {
        title: "Reference",
        links: [
          { href: "/docs/install", label: "Install", desc: "Laptop, one server, Kubernetes, EKS, GKE, AKS, clouds" },
          { href: "/docs/api", label: "REST API and metrics", desc: "Prometheus, inventory, events" },
          { href: "/docs/security", label: "Security", desc: "Guardrails and hosting" },
        ],
      },
    ],
  },
];

export const FOOTER_COLUMNS: { title: string; links: NavLink[] }[] = [
  {
    title: "Product",
    links: [
      { href: "/#how", label: "How it works" },
      { href: "/#platform", label: "Platform" },
      { href: "/#deploy", label: "Deploy" },
      { href: "/solutions", label: "Solutions" },
      { href: site.demo, label: "Try it" },
    ],
  },
  {
    title: "Integrations",
    links: [
      { href: "/docs/connectors", label: "Devices" },
      { href: "/docs/dns", label: "DNS providers" },
      { href: "/docs/dns#certificate-authorities", label: "Certificate authorities" },
      { href: "/docs/sso", label: "Single sign-on" },
    ],
  },
  {
    title: "Resources",
    links: [
      { href: "/docs/quickstart", label: "Quickstart" },
      { href: "/docs/install", label: "Install" },
      { href: "/docs/mcp", label: "MCP server" },
      { href: "/docs/api", label: "REST API" },
    ],
  },
  {
    title: "Project",
    links: [
      { href: "https://github.com/gagankarthik/farrier", label: "GitHub" },
      { href: "/docs/contributing", label: "Contributing" },
      { href: "/docs/security", label: "Security" },
      { href: "https://github.com/gagankarthik/farrier/issues", label: "Report an issue" },
    ],
  },
];
