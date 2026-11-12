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
      { href: "/docs/install", label: "Install" },
      { href: "/docs/self-hosting", label: "Running and upgrading" },
      { href: "/docs/databases", label: "Databases and HA" },
      { href: "/docs/enterprise", label: "Enterprise and cloud" },
      { href: "/docs/deploy", label: "Deployment reference" },
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
      { href: "/docs/ssh", label: "SSH keys" },
      { href: "/docs/pqc", label: "Crypto and PQC readiness" },
      { href: "/docs/integrations", label: "ServiceNow, Jira, Datadog, Splunk" },
      { href: "/docs/mcp", label: "AI agents (MCP)" },
      { href: "/docs/events", label: "Events and triggers" },
    ],
  },
  {
    title: "Reference",
    items: [
      { href: "/docs/api", label: "REST API and metrics" },
      { href: "/docs/cli", label: "Command line" },
    ],
  },
  {
    title: "Operations",
    items: [
      { href: "/docs/security", label: "Security and hosting" },
      { href: "/docs/pilot", label: "Pilot checklist" },
    ],
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
