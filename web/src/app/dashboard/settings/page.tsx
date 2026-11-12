"use client";

import Link from "next/link";
import { useState } from "react";
import { BellRing, CheckCircle2, CircleDashed, Save, XCircle } from "lucide-react";
import { ErrorNotice, PageHeader } from "@/components/dashboard/shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { EmptyState, Skeleton } from "@/components/ui/misc";
import { api, useConfig, useStatus, useSummary } from "@/lib/api";
import { useAccess } from "@/lib/auth/client";
import type { EngineSettings } from "@/lib/types";

const NUMBERS: { key: keyof EngineSettings; label: string; help: string; unit?: string }[] = [
  { key: "horizon_days", label: "Planning horizon", help: "Open a renewal this far ahead of its due date.", unit: "days" },
  { key: "safety_days", label: "Safety margin", help: "Never plan a change later than expiry minus this.", unit: "days" },
  { key: "manual_daily_cap", label: "Manual changes per day", help: "Change packs a team can absorb; the rest move to the next window." },
  { key: "auto_daily_cap", label: "Automated renewals per day", help: "An upper bound on automated deploys." },
  { key: "verify_max_attempts", label: "Verification attempts", help: "Cycles before a deploy that never goes live is rolled back." },
  { key: "scan_timeout", label: "Scan timeout", help: "How long to wait for a TLS handshake.", unit: "seconds" },
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

function FileHint({ file }: { file: string }) {
  return (
    <p className="mt-4 text-xs text-muted-foreground">
      Edit <code className="font-mono">&lt;data&gt;/{file}</code> to change these. Credentials stay <code className="font-mono">env:</code> or{" "}
      <code className="font-mono">file:</code> references.
    </p>
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
              {NUMBERS.map(({ key, label, help, unit }) => {
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
              {TOGGLES.map(({ key, label, help }) => (
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

export default function SettingsPage() {
  const { data: cfg } = useConfig();
  const { data: st } = useStatus();
  const { data: s } = useSummary();
  const { can } = useAccess();
  const [test, setTest] = useState<{ ok?: string; error?: Error }>({});

  return (
    <>
      <PageHeader title="Settings" description="How Farrier plans and verifies renewals, and what it is connected to." />
      <div className="grid gap-6 lg:grid-cols-2">
        <Policy />

        <Card>
          <CardHeader>
            <div>
              <CardTitle>Certificate authorities</CardTitle>
              <CardDescription>Endpoints choose one with their issuer field.</CardDescription>
            </div>
          </CardHeader>
          <CardContent>
            {cfg?.issuers_error && <ErrorNotice error={new Error(cfg.issuers_error)} />}
            {!cfg ? (
              <Skeleton className="h-24" />
            ) : (
              <ul className="divide-y text-sm">
                {cfg.issuers.map((i) => (
                  <li key={i.name} className="flex items-center justify-between gap-4 py-2">
                    <span className="min-w-0">
                      <span className="block font-medium">{i.name}</span>
                      <span className="block truncate text-xs text-muted-foreground">
                        {i.type === "local_ca" ? "Built-in private CA" : i.directory}
                        {i.dns && ` · DNS ${i.dns}`}
                        {i.eab && ` · EAB ${i.eab}`}
                      </span>
                    </span>
                    <Badge tone={i.type === "local_ca" ? "neutral" : "brand"}>{i.preset ?? (i.type === "local_ca" ? "private" : "ACME")}</Badge>
                  </li>
                ))}
              </ul>
            )}
            <FileHint file="issuers.json" />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <div>
              <CardTitle>DNS accounts</CardTitle>
              <CardDescription>Used for DNS-01; the most specific zone wins.</CardDescription>
            </div>
          </CardHeader>
          <CardContent>
            {cfg?.dns_error && <ErrorNotice error={new Error(cfg.dns_error)} />}
            {!cfg ? (
              <Skeleton className="h-24" />
            ) : cfg.dns_accounts.length === 0 ? (
              <EmptyState
                className="py-8"
                title="No DNS accounts"
                action={
                  <Button asChild variant="secondary" size="sm">
                    <Link href="/docs/dns">Add a DNS account</Link>
                  </Button>
                }
              >
                Issuers use their DNS hook, and the private CA needs none.
              </EmptyState>
            ) : (
              <ul className="divide-y text-sm">
                {cfg.dns_accounts.map((a) => (
                  <li key={a.name} className="py-2">
                    <span className="flex items-center justify-between gap-4">
                      <span className="font-medium">{a.name}</span>
                      <Badge tone="neutral">{a.provider}</Badge>
                    </span>
                    <span className="block truncate text-xs text-muted-foreground">
                      {a.zones.join(", ") || "no zones"} · {Object.values(a.credentials).filter(Boolean).join(", ")}
                    </span>
                  </li>
                ))}
              </ul>
            )}
            <FileHint file="dns.json" />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <div>
              <CardTitle>Notifications</CardTitle>
              <CardDescription>Where Farrier says a renewal failed, rolled back or needs a person.</CardDescription>
            </div>
          </CardHeader>
          <CardContent>
            {!cfg ? (
              <Skeleton className="h-16" />
            ) : cfg.notifiers.length === 0 ? (
              <EmptyState
                className="py-8"
                title="No notifications"
                action={
                  <Button asChild variant="secondary" size="sm">
                    <Link href="/docs/configuration#notifications">Set up alerts</Link>
                  </Button>
                }
              >
                Send failures and change packs to Slack, Teams, a webhook or email.
              </EmptyState>
            ) : (
              <ul className="divide-y text-sm">
                {cfg.notifiers.map((n, k) => (
                  <li key={k} className="flex items-center justify-between gap-4 py-2">
                    <span className="font-medium capitalize">{n.type}</span>
                    <span className="truncate text-xs text-muted-foreground">{n.events.join(", ").replaceAll("_", " ")}</span>
                  </li>
                ))}
              </ul>
            )}
            {cfg && cfg.notifiers.length > 0 && can("POST", "notifiers/test") && (
              <div className="mt-4 flex items-center gap-4">
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={async () => {
                    setTest({});
                    try {
                      const r = await api.testNotifiers();
                      setTest({ ok: `Sent to ${r.sent}` });
                    } catch (e) {
                      setTest({ error: e as Error });
                    }
                  }}
                >
                  <BellRing /> Send a test
                </Button>
                {test.ok && <span className="text-sm text-good-fg">{test.ok}</span>}
                {test.error && <span className="text-sm text-critical-fg">{test.error.message}</span>}
              </div>
            )}
          </CardContent>
        </Card>

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
