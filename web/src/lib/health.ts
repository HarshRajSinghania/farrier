/** Certificate health: every endpoint in exactly one severity (pure, so it is unit-tested). */

export type Severity = "critical" | "warning" | "healthy";
export type HealthItem = { id: number; name: string; reason: string };

const WARN_DAYS = 14;

/**
 * Every endpoint in exactly one severity, worst reason first:
 *   critical  expired, renewal failed or rolled back, or a critical zombie finding
 *   warning   expires within 14 days, waiting on a person, or a warning zombie finding
 *   healthy   everything else
 */
export function classify(
  endpoints: { id: number; name: string; days_left: number | null }[],
  renewals: { endpoint_id: number; state: string }[],
  zombies: { endpoint_id: number | null; severity: string; kind: string }[],
): Record<Severity, HealthItem[]> {
  const out: Record<Severity, HealthItem[]> = { critical: [], warning: [], healthy: [] };
  const byState = new Map(renewals.map((r) => [r.endpoint_id, r.state]));
  const zombie = new Map<number, { severity: string; kind: string }>();
  for (const z of zombies) if (z.endpoint_id != null && (!zombie.has(z.endpoint_id) || z.severity === "critical")) zombie.set(z.endpoint_id, z);

  for (const e of endpoints) {
    const state = byState.get(e.id);
    const z = zombie.get(e.id);
    const d = e.days_left;
    const critical =
      d !== null && d < 0 ? `Expired ${Math.abs(Math.round(d))} days ago`
      : state === "failed" ? "Renewal failed"
      : state === "rolled_back" ? "Deploy rolled back"
      : z?.severity === "critical" ? z.kind.replaceAll("_", " ")
      : null;
    if (critical) {
      out.critical.push({ id: e.id, name: e.name, reason: critical });
      continue;
    }
    const warning =
      d !== null && d <= WARN_DAYS ? `Expires in ${Math.max(0, Math.round(d))} days`
      : state === "awaiting_manual" ? "Change pack waiting"
      : z ? z.kind.replaceAll("_", " ")
      : null;
    if (warning) out.warning.push({ id: e.id, name: e.name, reason: warning });
    else out.healthy.push({ id: e.id, name: e.name, reason: "" });
  }
  return out;
}
