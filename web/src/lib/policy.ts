/**
 * TypeScript port of farrier/policy.py — CA/Browser Forum SC-081 lifetime
 * schedule and the renewal-timing maths. Used by the landing-page calculator
 * and by demo mode; the live dashboard always shows the server's numbers.
 */
import type { ForecastRow } from "./types";

/** [effective date, max validity days, max DCV-reuse days] */
export const SCHEDULE: [string, number, number][] = [
  ["2020-09-01", 398, 398],
  ["2026-03-15", 200, 200],
  ["2027-03-15", 100, 100],
  ["2029-03-15", 47, 10],
];

export const WORKING_DAYS_PER_YEAR = 250;
const FTE_HOURS = 1600;

const iso = (d: Date | string) => (typeof d === "string" ? d.slice(0, 10) : d.toISOString().slice(0, 10));

export function maxLifetimeDays(on: Date | string): number {
  const day = iso(on);
  let days = SCHEDULE[0][1];
  for (const [eff, life] of SCHEDULE) if (day >= eff) days = life;
  return days;
}

export function dcvReuseDays(on: Date | string): number {
  const day = iso(on);
  let days = SCHEDULE[0][2];
  for (const [eff, , reuse] of SCHEDULE) if (day >= eff) days = reuse;
  return days;
}

/** Renew at the one-third point, never sooner than the change lead time, never in the first quarter of life. */
export function renewBeforeDays(lifetime: number, leadDays = 0): number {
  const third = Math.max(1, Math.round(lifetime / 3));
  return Math.min(Math.max(third, leadDays), Math.floor(lifetime * 0.75));
}

export function renewalIntervalDays(lifetime: number, leadDays = 0): number {
  return lifetime - renewBeforeDays(lifetime, leadDays);
}

// Python's round() uses banker's rounding; match it so numbers agree with the CLI.
function pyRound(x: number, digits = 0): number {
  const m = 10 ** digits;
  const v = x * m;
  const r = Math.round(v);
  const isHalf = Math.abs(v - Math.trunc(v)) === 0.5;
  return (isHalf ? (r % 2 === 0 ? r : r - 1) : r) / m;
}

export function forecast(
  certs: number,
  on: string,
  manualFraction = 0,
  minutesPerManual = 45,
  leadDays = 0,
  early = true,
): ForecastRow {
  const lifetime = maxLifetimeDays(on);
  const interval = early ? renewalIntervalDays(lifetime, leadDays) : lifetime;
  const perYear = pyRound((certs * 365) / interval);
  const manual = pyRound(perYear * manualFraction);
  const hours = (manual * minutesPerManual) / 60;
  return {
    on,
    lifetime_days: lifetime,
    interval_days: interval,
    renewals_per_year: perYear,
    per_calendar_day: pyRound(perYear / 365, 1),
    per_working_day: pyRound(perYear / WORKING_DAYS_PER_YEAR, 1),
    manual_renewals_per_year: manual,
    manual_hours_per_year: pyRound(hours, 1),
    manual_fte: pyRound(hours / FTE_HOURS, 2),
  };
}

export function forecastTimeline(certs: number, manualFraction: number, minutes = 45, leadDays = 0): ForecastRow[] {
  return SCHEDULE.map(([eff]) => forecast(certs, eff, manualFraction, minutes, leadDays));
}
