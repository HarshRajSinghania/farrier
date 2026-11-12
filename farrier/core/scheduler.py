"""Maintenance windows and workload leveling.

A window is {"days": ["sat", "sun"], "start": "02:00", "hours": 4} in UTC.
An empty window ({}) means "any time" (typical for automated, hitless reloads).
"""
from __future__ import annotations

from datetime import datetime, time, timedelta

DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


def next_window_start(window: dict, after: datetime) -> datetime:
    if not window:
        return after
    days = [d.lower()[:3] for d in window.get("days", [])] or DAYS
    hh, mm = (int(x) for x in window.get("start", "00:00").split(":"))
    length = timedelta(hours=float(window.get("hours", 24)))
    for offset in range(-1, 15):
        day = (after + timedelta(days=offset)).date()
        if DAYS[day.weekday()] not in days:
            continue
        start = datetime.combine(day, time(hh, mm), tzinfo=after.tzinfo)
        if start <= after < start + length:
            return after                      # already inside a window
        if start > after:
            return start
    raise ValueError(f"window {window} never opens")


def window_end(window: dict, start: datetime) -> datetime:
    if not window:
        return start + timedelta(days=1)
    return start + timedelta(hours=float(window.get("hours", 24)))


def level(window: dict, earliest: datetime, latest: datetime, load: dict[str, int], cap: int) -> datetime:
    """First window start >= earliest whose day has spare capacity; falls back to `earliest`
    if nothing fits before `latest` (expiry beats tidy workload)."""
    t = earliest
    for _ in range(120):
        start = next_window_start(window, t)
        if start > latest:
            break
        if load.get(start.date().isoformat(), 0) < cap:
            return start
        t = datetime.combine(start.date() + timedelta(days=1), time(0, 0), tzinfo=start.tzinfo)
    return earliest
