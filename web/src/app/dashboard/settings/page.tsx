"use client";

import Link from "next/link";
import { useState } from "react";
import { BellRing, CheckCircle2, ChevronRight, CircleDashed, Globe, Landmark, Save, XCircle } from "lucide-react";
import { ErrorNotice, PageHeader } from "@/components/dashboard/shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/misc";
import { api, useAlertRules, useConfig, useDnsAccounts, useIssuers, useNotifiers, useStatus, useSummary } from "@/lib/api";
import { useAccess } from "@/lib/auth/client";
import type { EngineSettings } from "@/lib/types";

const NUMBERS: { key: keyof EngineSettings; label: string; help: string; unit?: string }[] = [
  { key: "horizon_days", label: "Planning horizon", help: "Open a renewal this far ahead of its due date.", unit: "days" },
  { key: "safety_days", label: "Safety margin", help: "Never plan a change later than expiry minus this.", unit: "days" },
  { key: "manual_daily_cap", label: "Manual changes per day", help: "Change packs a team can absorb; the rest move to the next window." },
  { key: "auto_daily_cap", label: "Automated renewals per day", help: "An upper bound on automated deploys." },
  { key: "verify_max_attempts", label: "Verification attempts", help: "Cycles before a deploy that never goes live is rolled back." },
  { key: "scan_timeout", label: "Scan timeout", help: "How long to wait for a TLS handshake.", unit: "seconds" },
  { key: "crypto_scan_hours", label: "Crypto rescan", help: "Re-check TLS versions, ciphers and PQC readiness this often. 0 turns it off.", unit: "hours" },
  { key: "ssh_scan_hours", label: "SSH host rescan", help: "Re-read SSH host keys and algorithms this often. 0 turns it off.", unit: "hours" },
  { key: "ssh_collect_hours", label: "SSH key collection", help: "Re-read authorized_keys over SSH this often. 0 turns it off.", unit: "hours" },
  { key: "export_key_retention_hours", label: "Exported key retention", help: "Delete keys exported for cloud events after this long. 0 keeps them.", unit: "hours" },
];
const TOGGLES: { key: keyof EngineSettings; label: string; help: string }[] = [
  { key: "verify_chain_and_names", label: "Check chain and names after deploy", help: "Done only when the chain is complete and every name is covered." },
  { key: "verify_all_addresses", label: "Probe every DNS address", help: "Catches a stale node behind round-robin DNS. Leave off if the engine can't reach every address." },
];

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4 py-2 text-sm">
      <dt className="text-muted-foreground">{k}</dt>
      <dd className="min-w-0 truncate text-right font-medium">{v}</dd>
    </div>
  );
}

function Policy() {
  const { data, error } = useConfig();
  const { can } = useAccess();
  const [edits, setForm] = useState<EngineSettings | null>(null);
  const form = edits ?? data?.settings ?? null; // server values until the first edit
  const [state, setState] = useState<{ busy?: boolean; error?: Error; saved?: boolean }>({});

  const editable = can("PUT", "config/settings");
  const dirty = !!data && !!form && (Object.keys(form) as (keyof EngineSettings)[]).some((k) => form[k] !== data.settings[k]);

  const save = async () => {
    if (!data || !form) return;
    const changes = Object.fromEntries(Object.entries(form).filter(([k, v]) => v !== data.settings[k as keyof EngineSettings]));
    setState({ busy: true });
    try {
      await api.saveSettings(changes);
      setState({ saved: true });
    } catch (e) {
      setState({ error: e as Error });
    }
  };

  return (
    <Card className="lg:col-span-2">
      <CardHeader>
        <div>
          <CardTitle>Renewal policy</CardTitle>
          <CardDescription>Applied immediately and saved to settings.json.{!editable && " Only admins can change these."}</CardDescription>
        </div>
      </CardHeader>
      <CardContent>
        <ErrorNotice error={error ?? state.error} />
        {!form || !data ? (
          <Skeleton className="h-48" />
        ) : (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              save();
            }}
          >
            <fieldset disabled={!editable || state.busy} className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
              {/* only what this engine knows: an older engine behind a newer dashboard has fewer settings */}
              {NUMBERS.filter(({ key }) => data.limits[key]).map(({ key, label, help, unit }) => {
                const lim = data.limits[key];
                return (
                  <label key={key} className="grid content-start gap-2 text-sm">
                    <span className="font-medium">{label}</span>
                    <span className="flex items-center gap-2">
                      <Input
                        type="number"
                        min={lim.min}
                        max={lim.max}
                        step={lim.type === "int" ? 1 : 0.5}
                        required
                        value={String(form[key])}
                        onChange={(e) => {
                          setState({});
                          setForm({ ...form, [key]: e.target.value === "" ? "" : Number(e.target.value) });
                        }}
                        className="w-28"
                      />
                      {unit && <span className="text-muted-foreground">{unit}</span>}
                    </span>
                    <span className="text-xs text-muted-foreground">{help}</span>
                  </label>
                );
              })}
            </fieldset>
            <fieldset disabled={!editable || state.busy} className="mt-6 grid gap-4 border-t pt-6 sm:grid-cols-2">
              {TOGGLES.filter(({ key }) => data.limits[key]).map(({ key, label, help }) => (
                <label key={key} className="flex items-start gap-4 text-sm">
                  <input
                    type="checkbox"
                    checked={Boolean(form[key])}
                    onChange={(e) => {
                      setState({});
                      setForm({ ...form, [key]: e.target.checked });
                    }}
                    className="mt-1 size-4 accent-[#141414]"
                  />
                  <span>
                    <span className="block font-medium">{label}</span>
                    <span className="block text-xs text-muted-foreground">{help}</span>
                  </span>
                </label>
              ))}
            </fieldset>
            {editable && (
              <div className="mt-6 flex items-center gap-4 border-t pt-6">
                <Button type="submit" disabled={!dirty || state.busy}>
                  <Save /> {state.busy ? "Saving…" : "Save changes"}
                </Button>
                {dirty && (
                  <Button type="button" variant="ghost" onClick={() => setForm(null)}>
                    Discard
                  </Button>
                )}
                {state.saved && !dirty && (
                  <span className="flex items-center gap-2 text-sm text-good-fg">
                    <CheckCircle2 className="size-4" /> Saved
                  </span>
                )}
              </div>
            )}
          </form>
        )}
      </CardContent>
    </Card>
  );
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/** Links to the pages that configure CAs, DNS and alerts, with what each holds today. */
function IntegrationsCard() {
  const issuers = useIssuers();
  const dns = useDnsAccounts();
  const channels = useNotifiers();
  const rules = useAlertRules();
  const count = (q: { data?: unknown[]; error?: unknown }, text: (n: number) => string) =>
    q.data ? text(q.data.length) : q.error ? "Unavailable" : null;
  const links = [
    { href: "/dashboard/integrations/authorities", icon: Landmark, label: "Certificate authorities", detail: count(issuers, (n) => plural(n, "authority", "authorities")) },
    { href: "/dashboard/integrations/dns", icon: Globe, label: "DNS accounts", detail: count(dns, (n) => plural(n, "account")) },
    {
      href: "/dashboard/integrations/alerts",
      icon: BellRing,
      label: "Alerts",
      detail: rules.data && channels.data
        ? `${plural(rules.data.length, "rule")} · ${plural(channels.data.length, "channel")}`
        : rules.error || channels.error ? "Unavailable" : null,
    },
  ];
  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle>Integrations</CardTitle>
          <CardDescription>Where certificates come from, how names are validated, and who hears about it.</CardDescription>
        </div>
      </CardHeader>
      <CardContent className="pt-4">
        <ul className="divide-y">
          {links.map(({ href, icon: Icon, label, detail }) => (
            <li key={href}>
              <Link href={href} className="group -mx-2 flex items-center gap-4 rounded-md px-2 py-2 text-sm hover:bg-muted">
                <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-muted text-muted-foreground" aria-hidden>
                  <Icon className="size-4" />
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block font-medium">{label}</span>
                  {detail === null ? <Skeleton className="mt-1 h-3 w-24" /> : <span className="block text-xs text-muted-foreground">{detail}</span>}
                </span>
                <ChevronRight className="size-4 text-muted-foreground transition-transform group-hover:translate-x-0.5" aria-hidden />
              </Link>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}

export default function SettingsPage() {
  const { data: cfg } = useConfig();
  const { data: st } = useStatus();
  const { data: s } = useSummary();

  return (
    <>
      <PageHeader title="Settings" description="How Farrier plans and verifies renewals, and what it is connected to." />
      <div className="grid gap-6 lg:grid-cols-2">
        <Policy />

        <IntegrationsCard />

        <Card>
          <CardHeader>
            <div>
              <CardTitle>Engine</CardTitle>
              <CardDescription>The server this dashboard talks to.</CardDescription>
            </div>
          </CardHeader>
          <CardContent>
            {!st || !cfg ? (
              <Skeleton className="h-40" />
            ) : (
              <dl className="divide-y">
                <Row
                  k="Status"
                  v={
                    st.mode === "demo" ? (
                      <Badge tone="warning">
                        <CircleDashed /> Demo
                      </Badge>
                    ) : st.reachable ? (
                      <Badge tone="good">
                        <CheckCircle2 /> Reachable
                      </Badge>
                    ) : (
                      <Badge tone="critical">
                        <XCircle /> {st.error ?? "Unreachable"}
                      </Badge>
                    )
                  }
                />
                <Row k="Database" v={`${cfg.engine.backend} · schema ${cfg.engine.schema_version}`} />
                <Row k="This replica" v={`${cfg.engine.replica}${cfg.engine.leader ? " · leader" : ""}`} />
                <Row k="AI agent writes" v={cfg.engine.mcp_writes ? "Allowed" : "Off"} />
                {s && <Row k="Max certificate lifetime" v={`${s.policy.max_lifetime_days} days`} />}
              </dl>
            )}
          </CardContent>
        </Card>
      </div>
    </>
  );
}
