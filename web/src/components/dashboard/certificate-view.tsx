"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { useParams } from "next/navigation";
import { AlertTriangle, ArrowLeft, Check, CheckCircle2, Copy, Download, FileBadge, OctagonAlert, RefreshCw, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import { ErrorNotice, PageHeader } from "@/components/dashboard/shell";
import { TableSkeleton } from "@/components/dashboard/widgets";
import { ConnectorTag, ExpiryBadge, expiryLevel, StateBadge } from "@/components/status";
import { Badge, type BadgeTone } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState, Skeleton } from "@/components/ui/misc";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { api, ApiError, useCertificate, useEndpoints, useRenewals, useZombies } from "@/lib/api";
import { useAccess } from "@/lib/auth/client";
import { classify, type Severity } from "@/lib/health";
import type { CertKey, CertificateDetail, HealthReport } from "@/lib/types";
import { cn, fmtDate, fmtDateTime, relativeTime, shortFp } from "@/lib/utils";

const SEVERITY: Record<Severity, { label: string; tone: BadgeTone; icon: React.ElementType }> = {
  critical: { label: "Critical", tone: "critical", icon: OctagonAlert },
  warning: { label: "Warning", tone: "warning", icon: AlertTriangle },
  healthy: { label: "Healthy", tone: "good", icon: CheckCircle2 },
};

const GRADE_TONE: Record<HealthReport["grade"], BadgeTone> = { A: "good", B: "good", C: "warning", D: "serious", F: "critical" };

/** "CN=R11,O=Let's Encrypt,C=US" -> "R11" */
const cnOf = (dn: string | null | undefined) => dn?.match(/CN=([^,]+)/)?.[1] ?? dn ?? "—";

export function keyLabel(key: CertKey | string | null | undefined) {
  if (!key) return "—";
  if (typeof key === "string") return key;
  if (key.curve) return `${key.algorithm} ${key.curve}`;
  return key.size ? `${key.algorithm} ${key.size}` : key.algorithm;
}

export function CopyButton({ value, label }: { value: string; label: string }) {
  const [done, setDone] = useState(false);
  return (
    <Button
      type="button"
      size="icon-sm"
      variant="ghost"
      aria-label={`Copy ${label}`}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setDone(true);
          toast.success(`${label} copied`);
          setTimeout(() => setDone(false), 1500);
        } catch {
          toast.error("Could not copy", { description: "The browser blocked clipboard access." });
        }
      }}
    >
      {done ? <Check /> : <Copy />}
    </Button>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid gap-1 py-4 sm:grid-cols-[10rem_1fr] sm:gap-4">
      <dt className="text-sm text-muted-foreground">{label}</dt>
      <dd className="min-w-0 text-sm">{children}</dd>
    </div>
  );
}

function ValidityBar({ from, to, daysLeft }: { from: string | null; to: string | null; daysLeft: number | null }) {
  if (!from || !to) return <span className="text-muted-foreground">—</span>;
  const start = Date.parse(from);
  const end = Date.parse(to);
  const life = Math.max(1, Math.round((end - start) / 86_400_000));
  // days_left comes from the server's clock, so the bar matches the badge
  const used = daysLeft === null ? 0 : Math.min(100, Math.max(0, ((life - daysLeft) / life) * 100));
  const level = expiryLevel(daysLeft);
  const bar = level === "expired" || level === "critical" ? "bg-critical" : level === "warning" ? "bg-warning" : "bg-good";
  return (
    <div className="max-w-md">
      <div
        className="h-2 overflow-hidden rounded-full bg-muted"
        role="img"
        aria-label={`${Math.round(used)}% of a ${life}-day lifetime used`}
      >
        <div className={cn("h-full rounded-full", bar)} style={{ width: `${used}%` }} />
      </div>
      <div className="mt-2 flex justify-between gap-4 text-xs text-muted-foreground">
        <span>{fmtDate(from)}</span>
        <span className="tabular">{life}-day lifetime</span>
        <span>{fmtDate(to)}</span>
      </div>
    </div>
  );
}

function Fingerprint({ label, value }: { label: string; value: string | null }) {
  if (!value) return <span className="text-muted-foreground">—</span>;
  return (
    <div className="flex items-start gap-2">
      <code className="min-w-0 break-all font-mono text-xs leading-5">{value}</code>
      <CopyButton value={value} label={`${label} fingerprint`} />
    </div>
  );
}

function CertificateCard({ cert }: { cert: CertificateDetail }) {
  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle>Certificate</CardTitle>
          <CardDescription>What the endpoint served at the last scan, {relativeTime(cert.observed_at)}.</CardDescription>
        </div>
        {cert.self_signed && <Badge tone="warning">Self-signed</Badge>}
      </CardHeader>
      <dl className="divide-y px-6 pb-2">
        <Row label="Subject">
          <span className="break-all font-mono text-xs">{cert.subject ?? "—"}</span>
        </Row>
        <Row label="Names">
          {cert.sans.length ? (
            <ul className="flex flex-wrap gap-1">
              {cert.sans.map((n) => (
                <li key={n} className="inline-flex h-6 items-center rounded-full bg-muted px-2 font-mono text-xs">
                  {n}
                </li>
              ))}
            </ul>
          ) : (
            <span className="text-muted-foreground">No subject alternative names</span>
          )}
        </Row>
        <Row label="Issuer">
          <span title={cert.issuer ?? undefined}>{cnOf(cert.issuer)}</span>
        </Row>
        <Row label="Serial">
          <code className="break-all font-mono text-xs">{cert.serial ?? "—"}</code>
        </Row>
        <Row label="Validity">
          <ValidityBar from={cert.not_before} to={cert.not_after} daysLeft={cert.days_left} />
        </Row>
        <Row label="Key">{keyLabel(cert.key)}</Row>
        <Row label="Signature">
          <span className="font-mono text-xs">{cert.signature_algorithm ?? "—"}</span>
        </Row>
        <Row label="SHA-256">
          <Fingerprint label="SHA-256" value={cert.fingerprints.sha256} />
        </Row>
        <Row label="SHA-1">
          <Fingerprint label="SHA-1" value={cert.fingerprints.sha1} />
        </Row>
      </dl>
    </Card>
  );
}

function ChainCard({ cert }: { cert: CertificateDetail }) {
  const links = [
    { subject: cert.subject ?? "", issuer: cert.issuer ?? "", not_after: cert.not_after, key: cert.key, signature_algorithm: cert.signature_algorithm },
    ...cert.chain,
  ];
  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle>Chain</CardTitle>
          <CardDescription>In the order the server sends it, leaf first.</CardDescription>
        </div>
      </CardHeader>
      <ol className="space-y-2 p-6 pt-4">
        {links.map((c, i) => (
          <li key={`${c.subject}-${i}`} className="flex gap-4">
            <span className="tabular flex size-6 shrink-0 items-center justify-center rounded-full bg-muted text-xs font-semibold">{i + 1}</span>
            <div className="min-w-0 flex-1 pb-2">
              <p className="truncate font-medium" title={c.subject}>
                {cnOf(c.subject)}
                {i === 0 && <span className="ml-2 text-xs font-normal text-muted-foreground">Leaf</span>}
              </p>
              <p className="truncate text-xs text-muted-foreground" title={c.issuer}>
                Issued by {cnOf(c.issuer)} · {keyLabel(c.key)} · expires {fmtDate(c.not_after)}
              </p>
            </div>
          </li>
        ))}
        {cert.self_signed ? (
          <li className="text-sm text-warning-fg">Self-signed: clients only trust it if it is pinned or installed by hand.</li>
        ) : (
          cert.chain.length === 0 && <li className="text-sm text-warning-fg">The server sends no intermediates. Some clients will fail to build a chain.</li>
        )}
      </ol>
    </Card>
  );
}

function HistoryCard({ cert }: { cert: CertificateDetail }) {
  return (
    <Card className="overflow-hidden">
      <CardHeader className="pb-4">
        <div>
          <CardTitle>History</CardTitle>
          <CardDescription>Each certificate this endpoint has served.</CardDescription>
        </div>
      </CardHeader>
      {cert.history.length === 0 ? (
        <p className="px-6 pb-6 text-sm text-muted-foreground">Nothing recorded yet.</p>
      ) : (
        <Table>
          <THead>
            <TR>
              <TH>Seen</TH>
              <TH>Fingerprint</TH>
              <TH>Expires</TH>
              <TH className="hidden md:table-cell">Issuer</TH>
            </TR>
          </THead>
          <TBody>
            {cert.history.map((h, i) => (
              <TR key={`${h.fingerprint_sha256}-${h.observed_at}-${i}`}>
                <TD className="text-sm">{fmtDateTime(h.observed_at)}</TD>
                <TD>
                  <span className="font-mono text-xs" title={h.fingerprint_sha256}>
                    {shortFp(h.fingerprint_sha256)}
                  </span>
                  {h.fingerprint_sha256 === cert.fingerprints.sha256 && (
                    <Badge tone="good" className="ml-2">
                      Serving
                    </Badge>
                  )}
                </TD>
                <TD className="text-sm text-muted-foreground">{fmtDate(h.not_after)}</TD>
                <TD className="hidden text-sm text-muted-foreground md:table-cell">{cnOf(h.issuer)}</TD>
              </TR>
            ))}
          </TBody>
        </Table>
      )}
    </Card>
  );
}

function RenewalsCard({ cert }: { cert: CertificateDetail }) {
  return (
    <Card className="overflow-hidden">
      <CardHeader className="pb-4">
        <div>
          <CardTitle>Renewals</CardTitle>
          <CardDescription>Planned, in flight and finished.</CardDescription>
        </div>
        <Button asChild size="sm" variant="ghost">
          <Link href="/dashboard/renewals">All renewals</Link>
        </Button>
      </CardHeader>
      {cert.renewals.length === 0 ? (
        <p className="px-6 pb-6 text-sm text-muted-foreground">No renewals yet. Farrier plans one at a third of the certificate&rsquo;s life.</p>
      ) : (
        <Table>
          <THead>
            <TR>
              <TH>State</TH>
              <TH>Scheduled</TH>
              <TH className="hidden md:table-cell">Reason</TH>
              <TH className="hidden sm:table-cell">Updated</TH>
            </TR>
          </THead>
          <TBody>
            {cert.renewals.map((r) => (
              <TR key={r.id}>
                <TD>
                  <StateBadge state={r.state} />
                </TD>
                <TD className="text-sm">{fmtDate(r.scheduled_for)}</TD>
                <TD className="hidden max-w-64 truncate text-sm text-muted-foreground md:table-cell">{r.reason ?? "—"}</TD>
                <TD className="hidden text-xs text-muted-foreground sm:table-cell">{relativeTime(r.updated_at)}</TD>
              </TR>
            ))}
          </TBody>
        </Table>
      )}
    </Card>
  );
}

export function CertificateView() {
  const params = useParams<{ id: string }>();
  const id = Number(params.id);
  const valid = Number.isInteger(id) && id > 0;
  const { data: cert, error, isLoading } = useCertificate(valid ? id : null);
  const { data: endpoints, isLoading: loadingEndpoints } = useEndpoints();
  const { data: renewals } = useRenewals();
  const { data: zombies } = useZombies();
  const { can } = useAccess();
  const [busy, setBusy] = useState<"renew" | "health" | null>(null);
  const [report, setReport] = useState<HealthReport | null>(null);

  const ep = endpoints?.find((e) => e.id === id);
  const severity = useMemo(() => {
    if (!ep || !renewals) return null;
    const groups = classify([ep], renewals, zombies?.findings ?? []);
    const s = (["critical", "warning", "healthy"] as const).find((k) => groups[k].length);
    return s ? { severity: s, reason: groups[s][0].reason } : null;
  }, [ep, renewals, zombies]);
  const awaiting = renewals?.find((r) => r.endpoint_id === id && r.state === "awaiting_manual");
  const missing = error instanceof ApiError && error.status === 404;

  if (!valid || (!loadingEndpoints && endpoints && !ep && (missing || !cert))) {
    return (
      <>
        <BackLink />
        <Card>
          <EmptyState
            icon={<FileBadge />}
            title="Endpoint not found"
            action={
              <Button asChild>
                <Link href="/dashboard/endpoints">All certificates</Link>
              </Button>
            }
          >
            It may have been removed. The certificates list shows everything Farrier watches.
          </EmptyState>
        </Card>
      </>
    );
  }

  const renew = async () => {
    if (!ep) return;
    setBusy("renew");
    try {
      const r = await api.renew(ep.id);
      toast.success(`Renewal started for ${ep.name}`, { description: `State: ${r.state.replace("_", " ")}` });
    } catch (e) {
      toast.error("Could not start renewal", { description: (e as Error).message });
    } finally {
      setBusy(null);
    }
  };
  const check = async () => {
    setBusy("health");
    try {
      const r = await api.health(id);
      setReport(r);
      const failing = r.checks.filter((c) => c.status !== "pass").map((c) => c.id.replaceAll("_", " "));
      toast.success(`Grade ${r.grade}`, { description: failing.length ? `Check: ${failing.join(", ")}` : "Every check passed." });
    } catch (e) {
      toast.error("Health check failed", { description: (e as Error).message });
    } finally {
      setBusy(null);
    }
  };
  const grade = report ? { grade: report.grade, checked_at: report.checked_at } : cert?.health ?? null;
  const sev = severity && SEVERITY[severity.severity];

  return (
    <>
      <BackLink />
      <PageHeader
        title={ep?.name ?? (cert ? cnOf(cert.subject) : "Certificate")}
        description={
          ep ? (
            <span className="flex flex-wrap items-center gap-x-4 gap-y-2">
              <span className="font-mono text-sm">
                {ep.host}:{ep.port}
              </span>
              <ConnectorTag kind={ep.connector} automated={ep.automated} />
              {ep.owner && <span className="text-sm">Owner: {ep.owner}</span>}
            </span>
          ) : undefined
        }
        actions={
          <>
            {awaiting && can("GET", `renewals/${awaiting.id}/pack`) && (
              <Button asChild variant="secondary">
                <a href={api.packUrl(awaiting.id)} download>
                  <Download /> Change pack
                </a>
              </Button>
            )}
            <Button variant="secondary" onClick={check} disabled={busy !== null}>
              <ShieldCheck className={busy === "health" ? "animate-pulse" : undefined} /> Check health
            </Button>
            {ep && can("POST", `endpoints/${ep.id}/renew`) && (
              <Button onClick={renew} disabled={busy !== null}>
                <RefreshCw className={busy === "renew" ? "animate-spin" : undefined} /> Renew now
              </Button>
            )}
          </>
        }
      />

      <div className="mb-6 flex flex-wrap items-center gap-2">
        {sev && severity ? (
          <Badge tone={sev.tone}>
            <sev.icon aria-hidden /> {sev.label}
            {severity.reason && <span className="font-normal first-letter:uppercase">· {severity.reason}</span>}
          </Badge>
        ) : (
          <Skeleton className="h-6 w-24 rounded-full" />
        )}
        {ep && <ExpiryBadge daysLeft={ep.days_left} />}
        {grade && (
          <Link href="/dashboard/health" title={`Checked ${fmtDateTime(grade.checked_at)}`}>
            <Badge tone={GRADE_TONE[grade.grade] ?? "neutral"}>Health grade {grade.grade}</Badge>
          </Link>
        )}
      </div>

      {!missing && <ErrorNotice error={error} />}

      {isLoading || (!cert && !error) ? (
        <Card className="overflow-hidden">
          <TableSkeleton rows={4} />
        </Card>
      ) : !cert ? (
        <Card>
          <EmptyState
            icon={<FileBadge />}
            title="No certificate seen yet"
            action={
              <Button variant="secondary" onClick={check} disabled={busy !== null}>
                <ShieldCheck /> Check health
              </Button>
            }
          >
            {ep?.scan_error ? `The last scan failed: ${ep.scan_error}.` : "Farrier hasn't completed a handshake with this endpoint."} The details appear after the next successful scan.
          </EmptyState>
        </Card>
      ) : (
        <div className="grid gap-4 xl:grid-cols-[3fr_2fr]">
          <div className="min-w-0 space-y-4">
            <CertificateCard cert={cert} />
            <HistoryCard cert={cert} />
          </div>
          <div className="min-w-0 space-y-4">
            <ChainCard cert={cert} />
            <RenewalsCard cert={cert} />
          </div>
        </div>
      )}
    </>
  );
}

function BackLink() {
  return (
    <Link href="/dashboard/endpoints" className="mb-4 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
      <ArrowLeft className="size-4" /> Certificates
    </Link>
  );
}
