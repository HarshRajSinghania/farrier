"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { AlertTriangle, Atom, CircleDashed, Download, OctagonAlert, Radar, Search, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import { ErrorNotice, PageHeader } from "@/components/dashboard/shell";
import { StatTile, TableSkeleton } from "@/components/dashboard/widgets";
import { Badge, type BadgeTone } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogClose, DialogContent } from "@/components/ui/dialog";
import { FieldHint, Input, Label, Textarea } from "@/components/ui/input";
import { EmptyState, Skeleton } from "@/components/ui/misc";
import { Select } from "@/components/ui/select";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { api, ApiError, useCryptoAssets, useCryptoSummary } from "@/lib/api";
import { useAccess } from "@/lib/auth/client";
import type { CryptoAsset, PqcStatus } from "@/lib/types";
import { cn, fmtInt, relativeTime } from "@/lib/utils";

/* ------------------------------------------------------------- vocabulary */

const STATUS: Record<PqcStatus, { label: string; tone: BadgeTone; bar: string; icon: React.ElementType; means: string }> = {
  ready: { label: "Ready", tone: "good", bar: "bg-good", icon: ShieldCheck, means: "Post-quantum key exchange and certificate." },
  hybrid: {
    label: "Hybrid",
    tone: "info",
    bar: "bg-series-auto",
    icon: Atom,
    means: "Post-quantum key exchange, classical certificate. Recorded traffic stays private.",
  },
  vulnerable: {
    label: "Vulnerable",
    tone: "warning",
    bar: "bg-warning",
    icon: AlertTriangle,
    means: "Classical key exchange only. Traffic recorded today could be decrypted later.",
  },
  unknown: { label: "Unknown", tone: "neutral", bar: "bg-muted-foreground/40", icon: CircleDashed, means: "No handshake yet, or not enough data to tell." },
};
const ORDER: PqcStatus[] = ["ready", "hybrid", "vulnerable", "unknown"];

const WEAK_LABEL: Record<string, string> = {
  tls10: "TLS 1.0",
  tls11: "TLS 1.1",
  rsa_lt_2048: "RSA < 2048",
  sha1: "SHA-1",
  cbc: "CBC",
  "3des": "3DES",
  rc4: "RC4",
  expired: "Expired",
};

/** the engine sends a list of flags; tolerate a map of booleans too */
function weakFlags(w: CryptoAsset["weak"]): string[] {
  if (Array.isArray(w)) return w;
  if (w && typeof w === "object") return Object.entries(w).filter(([, v]) => v).map(([k]) => k);
  return w ? ["weak"] : [];
}
const asList = (v: string[] | string | boolean | null | undefined) => (Array.isArray(v) ? v : typeof v === "string" && v ? [v] : []);
const pqcKex = (a: CryptoAsset) => (typeof a.pqc_key_exchange === "boolean" ? a.pqc_key_exchange : asList(a.pqc_key_exchange).length > 0);
const OLD_TLS = new Set(["TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"]);

/* ------------------------------------------------------------- readiness */

function Readiness() {
  const { data, error, isLoading } = useCryptoSummary();
  const total = data?.total ?? 0;
  const algos = Object.entries(data?.by_key_algorithm ?? {}).sort((a, b) => b[1] - a[1]);
  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle>Post-quantum readiness</CardTitle>
          <CardDescription>Every TLS and SSH service, by what a quantum computer could break.</CardDescription>
        </div>
      </CardHeader>
      <ErrorNotice error={error} />
      {isLoading || !data ? (
        <div className="space-y-4 p-6">
          <Skeleton className="h-3 w-full" />
          <Skeleton className="h-20 w-full" />
        </div>
      ) : (
        <div className="p-6 pt-4">
          <div
            className="flex h-3 gap-0.5 overflow-hidden rounded-full bg-muted"
            role="img"
            aria-label={ORDER.map((s) => `${data.by_status[s] ?? 0} ${STATUS[s].label.toLowerCase()}`).join(", ")}
          >
            {ORDER.map((s) =>
              data.by_status[s] ? (
                <div key={s} className={STATUS[s].bar} style={{ width: `${(data.by_status[s] / Math.max(1, total)) * 100}%` }} />
              ) : null,
            )}
          </div>
          <ul className="mt-6 grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
            {ORDER.map((s) => {
              const m = STATUS[s];
              const n = data.by_status[s] ?? 0;
              return (
                <li key={s} className="min-w-0">
                  <div className="flex items-baseline justify-between gap-2">
                    <span className="flex items-center gap-2 text-sm font-semibold">
                      <span aria-hidden className={cn("size-2 rounded-[2px]", m.bar)} />
                      {m.label}
                    </span>
                    <span className="tabular text-2xl font-semibold">{fmtInt(n)}</span>
                  </div>
                  <p className="mt-1 text-sm text-muted-foreground">{m.means}</p>
                </li>
              );
            })}
          </ul>
          {algos.length > 0 && (
            <p className="mt-6 border-t pt-4 text-sm text-muted-foreground">
              Keys in use:{" "}
              {algos.map(([k, n], i) => (
                <span key={k}>
                  {i > 0 && " · "}
                  <span className="font-medium text-foreground">{k}</span> <span className="tabular">{n}</span>
                </span>
              ))}
            </p>
          )}
        </div>
      )}
    </Card>
  );
}

function WeakTiles() {
  const { data, isLoading } = useCryptoSummary();
  const w = data?.weak;
  const tile = (label: string, n: number | undefined, footer: string, severe: boolean) => (
    <StatTile
      label={label}
      value={n ?? "—"}
      loading={isLoading}
      icon={n ? (severe ? OctagonAlert : AlertTriangle) : ShieldCheck}
      tone={!n ? "good" : severe ? "critical" : "warning"}
      footer={n ? footer : "None found"}
    />
  );
  return (
    <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
      {tile("Accept TLS 1.0", w?.tls10, "Retired protocol, still accepted", true)}
      {tile("Accept TLS 1.1", w?.tls11, "Retired protocol, still accepted", false)}
      {tile("RSA under 2048 bits", w?.rsa_lt_2048, "Breakable today", true)}
      {tile("SHA-1 signatures", w?.sha1, "Forgeable signatures in use", false)}
    </div>
  );
}

/* ------------------------------------------------------------------- scan */

function ScanDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const [targets, setTargets] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        title="Scan for cryptography"
        description="Handshakes with each target to record protocol versions, cipher suites, key exchange and keys. Read-only."
      >
        <form
          className="space-y-4"
          onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true);
            setError(null);
            try {
              const r = await api.cryptoScan(targets);
              toast.success("Scan finished", { description: typeof r.scanned === "number" ? `${r.scanned} targets probed.` : undefined });
              setTargets("");
              onOpenChange(false);
            } catch (err) {
              setError(err as Error);
            } finally {
              setBusy(false);
            }
          }}
        >
          <div className="space-y-2">
            <Label htmlFor="crypto-targets">Targets</Label>
            <Textarea
              id="crypto-targets"
              rows={3}
              value={targets}
              onChange={(e) => setTargets(e.target.value)}
              placeholder="10.20.0.0/24:443|8443, vpn.example.com:443, git.example.com:22"
              autoFocus
            />
            <FieldHint>Hosts, IPs or CIDR ranges with ports. Port 22 is probed as SSH.</FieldHint>
          </div>
          <ErrorNotice error={error} />
          <div className="flex justify-end gap-2 border-t pt-4">
            <DialogClose asChild>
              <Button type="button" variant="secondary">
                Cancel
              </Button>
            </DialogClose>
            <Button type="submit" disabled={busy || !targets.trim()}>
              <Radar className={busy ? "animate-pulse" : undefined} /> {busy ? "Scanning…" : "Scan"}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

async function exportCbom() {
  try {
    const res = await fetch(api.cbomUrl());
    if (!res.ok) {
      const body = await res.json().catch(() => null);
      throw new ApiError(res.status, typeof body?.detail === "string" ? body.detail : `Request failed (${res.status})`);
    }
    const blob = new Blob([await res.text()], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "farrier-cbom.json";
    a.click();
    URL.revokeObjectURL(url);
    toast.success("CBOM downloaded", { description: "CycloneDX JSON: farrier-cbom.json" });
  } catch (e) {
    toast.error("Could not export the CBOM", { description: (e as Error).message });
  }
}

/* ----------------------------------------------------------------- assets */

type KindFilter = "all" | "tls" | "ssh";
type StatusFilter = "all" | PqcStatus;

function Assets({ canScan, onScan }: { canScan: boolean; onScan: () => void }) {
  const { data, error, isLoading } = useCryptoAssets();
  const [kind, setKind] = useState<KindFilter>("all");
  const [status, setStatus] = useState<StatusFilter>("all");
  const [query, setQuery] = useState("");

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    const rank = (a: CryptoAsset) => ORDER.indexOf(a.pqc.status) * -1 + (weakFlags(a.weak).length ? -10 : 0);
    return (data ?? [])
      .filter(
        (a) =>
          (kind === "all" || a.kind === kind) &&
          (status === "all" || a.pqc.status === status) &&
          (!q || [a.target, a.signature_algorithm, ...asList(a.key_exchange)].some((v) => v?.toLowerCase().includes(q))),
      )
      .sort((a, b) => rank(a) - rank(b) || a.target.localeCompare(b.target));
  }, [data, kind, status, query]);

  return (
    <>
      <ErrorNotice error={error} />
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <Select
          value={kind}
          onValueChange={(v) => setKind(v as KindFilter)}
          aria-label="Filter by protocol"
          className="w-full sm:w-40"
          options={[
            { value: "all", label: "TLS and SSH" },
            { value: "tls", label: "TLS only" },
            { value: "ssh", label: "SSH only" },
          ]}
        />
        <Select
          value={status}
          onValueChange={(v) => setStatus(v as StatusFilter)}
          aria-label="Filter by readiness"
          className="w-full sm:w-44"
          options={[{ value: "all", label: "Any readiness" }, ...ORDER.map((s) => ({ value: s, label: STATUS[s].label }))]}
        />
        <div className="relative ml-auto w-full sm:w-64">
          <Search className="pointer-events-none absolute left-2 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search host, algorithm…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="pl-8"
            aria-label="Search crypto assets"
          />
        </div>
      </div>
      <Card className="overflow-hidden">
        {isLoading ? (
          <TableSkeleton />
        ) : rows.length === 0 ? (
          <EmptyState
            icon={<Atom />}
            title={data?.length ? "No assets match" : "No cryptography recorded yet"}
            action={
              !data?.length &&
              canScan && (
                <Button onClick={onScan}>
                  <Radar /> Scan targets
                </Button>
              )
            }
          >
            {data?.length ? "Try a different filter or search." : "Scan your endpoints to record what each one negotiates."}
          </EmptyState>
        ) : (
          <Table>
            <THead>
              <TR>
                <TH>Target</TH>
                <TH>Readiness</TH>
                <TH className="hidden md:table-cell">Protocols</TH>
                <TH className="hidden lg:table-cell">Key exchange</TH>
                <TH className="hidden lg:table-cell">Key and signature</TH>
                <TH>Weak</TH>
                <TH className="hidden xl:table-cell">Scanned</TH>
              </TR>
            </THead>
            <TBody>
              {rows.map((a) => {
                const m = STATUS[a.pqc.status] ?? STATUS.unknown;
                const flags = weakFlags(a.weak);
                const kex = asList(a.key_exchange);
                return (
                  <TR key={`${a.kind}-${a.id}`}>
                    <TD>
                      <div className="flex items-center gap-2">
                        <Badge tone="outline" className="font-mono uppercase">
                          {a.kind}
                        </Badge>
                        {a.endpoint_id ? (
                          <Link href={`/dashboard/endpoints/${a.endpoint_id}`} className="font-mono text-sm hover:underline">
                            {a.target}
                          </Link>
                        ) : (
                          <span className="font-mono text-sm">{a.target}</span>
                        )}
                      </div>
                    </TD>
                    <TD>
                      <Badge tone={m.tone} title={a.pqc.reasons.join("\n")}>
                        <m.icon aria-hidden /> {m.label}
                      </Badge>
                      {a.pqc.reasons[0] && <p className="mt-1 max-w-56 truncate text-xs text-muted-foreground" title={a.pqc.reasons.join("\n")}>{a.pqc.reasons[0]}</p>}
                    </TD>
                    <TD className="hidden md:table-cell">
                      <ul className="flex max-w-48 flex-wrap gap-1">
                        {a.protocol_versions.length ? (
                          a.protocol_versions.map((v) => (
                            <li
                              key={v}
                              className={cn(
                                "inline-flex h-6 items-center rounded-full px-2 font-mono text-xs",
                                OLD_TLS.has(v) ? "bg-critical/12 text-critical-fg" : "bg-muted",
                              )}
                            >
                              {v.replace(/^TLSv1$/, "TLSv1.0")}
                            </li>
                          ))
                        ) : (
                          <li className="text-sm text-muted-foreground">—</li>
                        )}
                      </ul>
                    </TD>
                    <TD className="hidden lg:table-cell">
                      <p className="max-w-48 truncate font-mono text-xs" title={kex.join(", ")}>
                        {kex[0] ?? "—"}
                      </p>
                      {pqcKex(a) && <p className="mt-1 text-xs text-info-fg">Post-quantum</p>}
                    </TD>
                    <TD className="hidden lg:table-cell">
                      <p className="text-sm">{a.cert_key ? `${a.cert_key.algorithm}${a.cert_key.size ? ` ${a.cert_key.size}` : ""}` : "—"}</p>
                      <p className="max-w-48 truncate font-mono text-xs text-muted-foreground">{a.signature_algorithm ?? ""}</p>
                    </TD>
                    <TD>
                      {flags.length ? (
                        <ul className="flex max-w-48 flex-wrap gap-1">
                          {flags.map((f) => (
                            <li key={f}>
                              <Badge tone={f === "tls10" || f === "rsa_lt_2048" || f === "rc4" || f === "expired" ? "critical" : "warning"}>
                                {WEAK_LABEL[f] ?? f}
                              </Badge>
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <span className="text-sm text-muted-foreground">None</span>
                      )}
                    </TD>
                    <TD className="hidden text-xs text-muted-foreground xl:table-cell">{relativeTime(a.observed_at)}</TD>
                  </TR>
                );
              })}
            </TBody>
          </Table>
        )}
      </Card>
      {data && (
        <p className="mt-4 text-xs text-muted-foreground">
          Showing {rows.length} of {data.length} assets
        </p>
      )}
    </>
  );
}

/* ------------------------------------------------------------------- page */

export function CryptoView() {
  const { can } = useAccess();
  const [scanning, setScanning] = useState(false);
  const canScan = can("POST", "crypto/scan");
  return (
    <>
      <PageHeader
        title="Crypto & PQC"
        description="What every TLS and SSH service negotiates, what is weak today, and what a quantum computer could break."
        actions={
          <>
            <Button variant="secondary" onClick={exportCbom}>
              <Download /> Export CBOM
            </Button>
            {canScan && (
              <Button onClick={() => setScanning(true)}>
                <Radar /> Scan
              </Button>
            )}
          </>
        }
      />
      <div className="space-y-4">
        <Readiness />
        <WeakTiles />
      </div>
      <h2 className="mb-4 mt-8 text-lg font-semibold tracking-tight">Assets</h2>
      <Assets canScan={canScan} onScan={() => setScanning(true)} />
      <ScanDialog open={scanning} onOpenChange={setScanning} />
    </>
  );
}
