/** Docs information architecture, grouped by what the reader is trying to do (cert-manager style). */
export type DocsGroup = { title: string; items: { href: string; label: string }[] };

export const DOCS_NAV: DocsGroup[] = [
  {
    title: "Getting started",
    items: [
      { href: "/docs", label: "Introduction" },
      { href: "/docs/quickstart", label: "Quickstart" },
      { href: "/docs/concepts", label: "Core concepts" },
    ],
  },
  {
    title: "Installation",
    items: [
      { href: "/docs/self-hosting", label: "Self-hosting" },
      { href: "/docs/deploy", label: "Deploy anywhere" },
      { href: "/docs/databases", label: "Databases and HA" },
    ],
  },
  {
    title: "Configuration",
    items: [
      { href: "/docs/configuration", label: "Issuers and settings" },
      { href: "/docs/dns", label: "DNS providers and CAs" },
      { href: "/docs/connectors", label: "Connectors" },
      { href: "/docs/sso", label: "Single sign-on and roles" },
    ],
  },
  {
    title: "Usage",
    items: [
      { href: "/docs/health", label: "Health and zombie certs" },
      { href: "/docs/mcp", label: "AI agents (MCP)" },
      { href: "/docs/events", label: "Events and triggers" },
    ],
  },
  {
    title: "Reference",
    items: [{ href: "/docs/api", label: "REST API and metrics" }],
  },
  {
    title: "Operations",
    items: [{ href: "/docs/security", label: "Security and hosting" }],
  },
  {
    title: "Project",
    items: [
      { href: "/docs/contributing", label: "Contributing" },
      { href: "/docs/design-system", label: "Design system" },
    ],
  },
];

export const DOCS_FLAT = DOCS_NAV.flatMap((g) => g.items.map((i) => ({ ...i, group: g.title })));
