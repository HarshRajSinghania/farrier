import {
  AlertOctagon,
  AlertTriangle,
  Ban,
  CheckCircle2,
  CircleDashed,
  Clock,
  Hand,
  KeyRound,
  Loader2,
  RotateCcw,
  ShieldCheck,
  Truck,
  XCircle,
} from "lucide-react";
import { Badge, type BadgeTone } from "@/components/ui/badge";
import type { RenewalState } from "@/lib/types";

/** One vocabulary for renewal states across tables, filters and charts. */
export const STATE_META: Record<RenewalState, { label: string; tone: BadgeTone; icon: React.ElementType; hint: string }> = {
  planned: { label: "Planned", tone: "neutral", icon: Clock, hint: "Scheduled into the next change window" },
  issued: { label: "Issued", tone: "info", icon: KeyRound, hint: "New certificate issued, not yet deployed" },
  deploying: { label: "Deploying", tone: "info", icon: Truck, hint: "Connector is installing the certificate" },
  verifying: { label: "Verifying", tone: "info", icon: Loader2, hint: "Waiting for a handshake to show the new fingerprint" },
  awaiting_manual: { label: "Awaiting human", tone: "warning", icon: Hand, hint: "Change pack ready; closes itself when the scanner sees it live" },
  done: { label: "Done", tone: "good", icon: CheckCircle2, hint: "Verified live" },
  failed: { label: "Failed", tone: "critical", icon: XCircle, hint: "Needs attention" },
  rolled_back: { label: "Rolled back", tone: "serious", icon: RotateCcw, hint: "New cert never went live; previous one restored" },
  superseded: { label: "Superseded", tone: "neutral", icon: CircleDashed, hint: "Replaced by a newer renewal" },
  cancelled: { label: "Cancelled", tone: "neutral", icon: Ban, hint: "Cancelled by an operator" },
};

export function StateBadge({ state }: { state: RenewalState }) {
  const m = STATE_META[state] ?? STATE_META.planned;
  const Icon = m.icon;
  return (
    <Badge tone={m.tone} title={m.hint}>
      <Icon aria-hidden className={state === "verifying" ? "animate-spin [animation-duration:2s]" : undefined} />
      {m.label}
    </Badge>
  );
}

export type ExpiryLevel = "expired" | "critical" | "warning" | "ok" | "unknown";

export function expiryLevel(daysLeft: number | null | undefined): ExpiryLevel {
  if (daysLeft === null || daysLeft === undefined) return "unknown";
  if (daysLeft < 0) return "expired";
  if (daysLeft < 7) return "critical";
  if (daysLeft < 30) return "warning";
  return "ok";
}

const EXPIRY_META: Record<ExpiryLevel, { tone: BadgeTone; icon: React.ElementType }> = {
  expired: { tone: "critical", icon: AlertOctagon },
  critical: { tone: "serious", icon: AlertTriangle },
  warning: { tone: "warning", icon: Clock },
  ok: { tone: "good", icon: ShieldCheck },
  unknown: { tone: "neutral", icon: CircleDashed },
};

export function ExpiryBadge({ daysLeft }: { daysLeft: number | null }) {
  const level = expiryLevel(daysLeft);
  const { tone, icon: Icon } = EXPIRY_META[level];
  const label =
    daysLeft === null
      ? "No cert seen"
      : daysLeft < 0
        ? `Expired ${Math.abs(Math.floor(daysLeft))}d ago`
        : `${Math.floor(daysLeft)}d left`;
  return (
    <Badge tone={tone} className="tabular">
      <Icon aria-hidden />
      {label}
    </Badge>
  );
}

export const CONNECTOR_LABEL: Record<string, string> = {
  files: "Files / SSH",
  keystore: "Java keystore",
  f5: "F5 BIG-IP",
  fortigate: "FortiGate",
  panos: "PAN-OS",
  manual: "Manual",
};

export function ConnectorTag({ kind, automated }: { kind: string; automated: boolean }) {
  return (
    <span className="inline-flex items-center gap-2 text-sm">
      <span
        aria-hidden
        className="size-2 rounded-[2px]"
        style={{ background: automated ? "var(--series-auto)" : "var(--series-manual)" }}
      />
      {CONNECTOR_LABEL[kind] ?? kind}
    </span>
  );
}
