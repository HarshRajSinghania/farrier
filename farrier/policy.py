"""CA/Browser Forum lifetime schedule (Ballot SC-081) and renewal-timing maths."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta

# (effective date, max validity days, max DCV-reuse days)
SCHEDULE: list[tuple[date, int, int]] = [
    (date(2020, 9, 1), 398, 398),
    (date(2026, 3, 15), 200, 200),
    (date(2027, 3, 15), 100, 100),
    (date(2029, 3, 15), 47, 10),
]

WORKING_DAYS_PER_YEAR = 250


def _as_date(d: date | datetime) -> date:
    return d.date() if isinstance(d, datetime) else d


def max_lifetime_days(on: date | datetime) -> int:
    on = _as_date(on)
    days = SCHEDULE[0][1]
    for eff, lifetime, _ in SCHEDULE:
        if on >= eff:
            days = lifetime
    return days


def dcv_reuse_days(on: date | datetime) -> int:
    on = _as_date(on)
    days = SCHEDULE[0][2]
    for eff, _, reuse in SCHEDULE:
        if on >= eff:
            days = reuse
    return days


def renew_before_days(lifetime_days: int, lead_days: int = 0) -> int:
    """How many days before expiry to start a renewal.

    Default is one third of the lifetime (the ACME/ARI convention), but never less
    than the lead time a change needs (ticket SLA + waiting for a window + slack).
    Capped so a cert is never renewed in the first quarter of its life.
    """
    third = max(1, round(lifetime_days / 3))
    return min(max(third, lead_days), int(lifetime_days * 0.75))


def renewal_interval_days(lifetime_days: int, lead_days: int = 0) -> int:
    return lifetime_days - renew_before_days(lifetime_days, lead_days)


@dataclass
class Forecast:
    on: str
    lifetime_days: int
    interval_days: int
    renewals_per_year: int
    per_calendar_day: float
    per_working_day: float
    manual_renewals_per_year: int
    manual_hours_per_year: float
    manual_fte: float


def forecast(
    cert_count: int,
    on: date | datetime,
    manual_fraction: float = 0.0,
    minutes_per_manual: float = 45.0,
    lead_days: int = 0,
    early: bool = True,
) -> Forecast:
    """Renewal workload for an estate on a given date.

    early=False reproduces the naive "renew on the last day" number
    (count * 365 / lifetime); early=True uses the real renewal interval.
    """
    lifetime = max_lifetime_days(on)
    interval = renewal_interval_days(lifetime, lead_days) if early else lifetime
    per_year = round(cert_count * 365 / interval)
    manual = round(per_year * manual_fraction)
    hours = manual * minutes_per_manual / 60
    return Forecast(
        on=_as_date(on).isoformat(),
        lifetime_days=lifetime,
        interval_days=interval,
        renewals_per_year=per_year,
        per_calendar_day=round(per_year / 365, 1),
        per_working_day=round(per_year / WORKING_DAYS_PER_YEAR, 1),
        manual_renewals_per_year=manual,
        manual_hours_per_year=round(hours, 1),
        manual_fte=round(hours / 1600, 2),
    )


def forecast_timeline(cert_count: int, manual_fraction: float, minutes_per_manual: float = 45.0,
                      lead_days: int = 0) -> list[dict]:
    out = []
    for eff, _, _ in SCHEDULE:
        f = forecast(cert_count, eff, manual_fraction, minutes_per_manual, lead_days)
        out.append(f.__dict__)
    return out


def utcnow() -> datetime:
    return datetime.now(UTC)


def days_left(not_after: datetime, now: datetime | None = None) -> float:
    now = now or utcnow()
    return (not_after - now) / timedelta(days=1)
