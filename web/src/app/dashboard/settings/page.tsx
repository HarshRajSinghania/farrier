"use client";

import Link from "next/link";
import { CheckCircle2, CircleDashed, XCircle } from "lucide-react";
import { PageHeader } from "@/components/dashboard/shell";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/misc";
import { useStatus, useSummary } from "@/lib/api";

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4 py-2 text-[13px]">
      <dt className="text-muted-foreground">{k}</dt>
      <dd className="text-right font-medium">{v}</dd>
    </div>
  );
}

export default function SettingsPage() {
  const { data: st } = useStatus();
  const { data: s } = useSummary();

  return (
    <>
      <PageHeader title="Settings" description="Connection and policy. Farrier is configured with files and environment variables, so it stays reproducible." />
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <div>
              <CardTitle>API connection</CardTitle>
              <CardDescription>The dashboard reaches Farrier through a server-side proxy; the token never reaches the browser.</CardDescription>
            </div>
          </CardHeader>
          <CardContent>
            {!st ? (
              <Skeleton className="h-24" />
            ) : (
              <dl className="divide-y">
                <Row
                  k="Mode"
                  v={
                    st.mode === "demo" ? (
                      <Badge tone="warning">
                        <CircleDashed /> Demo
                      </Badge>
                    ) : (
                      <Badge tone="info">Live</Badge>
                    )
                  }
                />
                <Row k="Upstream" v={<span className="font-mono">{st.upstream ?? "—"}</span>} />
                <Row
                  k="Status"
                  v={
                    st.reachable ? (
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
              </dl>
            )}
            <pre className="mt-4 overflow-x-auto rounded-md border bg-muted p-4 font-mono text-[12px] leading-relaxed">
{`# web/.env.local
FARRIER_API_URL=http://127.0.0.1:8740
FARRIER_API_TOKEN=…            # same value as on the Farrier server
FARRIER_DASHBOARD_PASSWORD=…   # required in production`}
            </pre>
            <p className="mt-4 text-xs text-muted-foreground">
              See{" "}
              <Link href="/docs/self-hosting" className="text-brand-ink hover:underline">
                Self-hosting
              </Link>{" "}
              for Docker and reverse-proxy setups.
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <div>
              <CardTitle>Lifetime policy in force</CardTitle>
              <CardDescription>CA/Browser Forum ballot SC-081, as computed by the server.</CardDescription>
            </div>
          </CardHeader>
          <CardContent>
            {!s ? (
              <Skeleton className="h-24" />
            ) : (
              <dl className="divide-y">
                <Row k="Max certificate lifetime" v={`${s.policy.max_lifetime_days} days`} />
                <Row k="Domain-validation reuse" v={`${s.policy.dcv_reuse_days} days`} />
                <Row k="Server clock (UTC)" v={<span className="font-mono">{s.now.replace("T", " ").slice(0, 19)}</span>} />
              </dl>
            )}
            <p className="mt-4 text-xs text-muted-foreground">
              Tune <code className="font-mono">horizon_days</code>, <code className="font-mono">manual_daily_cap</code>,{" "}
              <code className="font-mono">verify_max_attempts</code> and <code className="font-mono">safety_days</code> in{" "}
              <code className="font-mono">&lt;data&gt;/settings.json</code>.{" "}
              <Link href="/docs/configuration" className="text-brand-ink hover:underline">
                Configuration reference
              </Link>
            </p>
          </CardContent>
        </Card>
      </div>
    </>
  );
}
