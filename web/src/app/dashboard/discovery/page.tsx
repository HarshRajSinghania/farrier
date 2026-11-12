"use client";

import Link from "next/link";
import { useState } from "react";
import { ArrowRight, Radar } from "lucide-react";
import { PageHeader } from "@/components/dashboard/shell";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { FieldHint, Label, Textarea } from "@/components/ui/input";
import { api } from "@/lib/api";
import type { DiscoverResult } from "@/lib/types";

const EXAMPLES = ["10.20.0.0/24:443", "10.20.1.0/24:443|8443|4443", "vpn.example.com:443, 192.168.1.1:8443"];

export default function DiscoveryPage() {
  const [targets, setTargets] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<DiscoverResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function scan(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await api.discover(targets));
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHeader
        title="Discovery"
        description="Handshake with a network range and register every TLS listener it finds. Read-only: nothing on the devices changes."
      />
      <div className="grid gap-4 lg:grid-cols-[1fr_20rem]">
        <Card>
          <CardHeader>
            <div>
              <CardTitle>Scan targets</CardTitle>
              <CardDescription>Hosts, IPs or CIDR ranges with ports. Up to 4,096 targets per scan.</CardDescription>
            </div>
          </CardHeader>
          <CardContent>
            <form onSubmit={scan} className="space-y-4">
              <Label htmlFor="targets" className="sr-only">
                Targets
              </Label>
              <Textarea
                id="targets"
                rows={4}
                value={targets}
                onChange={(e) => setTargets(e.target.value)}
                placeholder="10.20.0.0/22:443|8443|4443"
                required
              />
              <div className="flex flex-wrap items-center gap-2">
                <FieldHint className="mr-1">Examples:</FieldHint>
                {EXAMPLES.map((x) => (
                  <button
                    key={x}
                    type="button"
                    onClick={() => setTargets(x)}
                    className="rounded-md border bg-muted px-2 py-1 font-mono text-xs text-muted-foreground hover:text-foreground"
                  >
                    {x}
                  </button>
                ))}
              </div>
              <div className="flex items-center justify-end gap-4 pt-1">
                {busy && <span className="text-xs text-muted-foreground">Scanning — large ranges take a minute…</span>}
                <Button type="submit" disabled={busy || !targets.trim()}>
                  <Radar className={busy ? "animate-pulse" : undefined} />
                  {busy ? "Scanning" : "Scan and register"}
                </Button>
              </div>
            </form>

            {error && (
              <p role="alert" className="mt-4 rounded-md bg-critical/8 px-4 py-2 text-sm text-critical-fg">
                {error}
              </p>
            )}

            {result && (
              <div className="mt-6 animate-fade-in rounded-lg border">
                <dl className="grid grid-cols-2 divide-x divide-y sm:grid-cols-4 sm:divide-y-0">
                  {[
                    ["Scanned", result.scanned],
                    ["Serving TLS", result.with_tls],
                    ["New endpoints", result.new],
                    ["Already known", result.seen - result.new],
                  ].map(([k, v]) => (
                    <div key={k} className="p-4">
                      <dt className="text-xs text-muted-foreground">{k}</dt>
                      <dd className="tabular mt-1 text-xl font-semibold">{v}</dd>
                    </div>
                  ))}
                </dl>
                <div className="flex justify-end border-t p-4">
                  <Button asChild variant="ghost" size="sm">
                    <Link href="/dashboard/endpoints">
                      Review endpoints <ArrowRight />
                    </Link>
                  </Button>
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>What happens next</CardTitle>
          </CardHeader>
          <CardContent>
            <ol className="space-y-4 text-sm">
              {[
                ["Registered as manual", "New listeners start on the manual connector, so nothing is pushed to a device you haven't configured."],
                ["Assign a connector", "Switch F5, FortiGate, PAN-OS, keystore or SSH hosts to their connector to automate them."],
                ["Planned at one third of life", "Renewals land in each device's change window, capped per day so your team isn't flooded."],
              ].map(([t, d], i) => (
                <li key={t} className="flex gap-4">
                  <span className="tabular flex size-5 shrink-0 items-center justify-center rounded-full bg-brand-soft text-xs font-semibold text-brand-ink">
                    {i + 1}
                  </span>
                  <div>
                    <p className="font-medium">{t}</p>
                    <p className="mt-1 text-muted-foreground">{d}</p>
                  </div>
                </li>
              ))}
            </ol>
          </CardContent>
        </Card>
      </div>
    </>
  );
}
