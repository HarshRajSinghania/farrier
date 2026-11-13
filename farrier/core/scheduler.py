"""Maintenance windows and workload leveling.

A window is {"days": ["sat", "sun"], "start": "02:00", "hours": 4}, in UTC unless it names a time zone:
{"days": ["sun"], "start": "02:00", "hours": 4, "tz": "Europe/Berlin"} opens at 02:00 Berlin time all
year (01:00 UTC in winter, 00:00 UTC in summer).
An empty window ({}) means "any time" (typical for automated, hitless reloads).
"""
from __future__ import annotations

from datetime import datetime, time, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


def zone(window: dict):
    """The window's time zone (ValueError for an unknown name), or None for UTC."""
    if not window or not window.get("tz"):
        return None
    try:
        return ZoneInfo(str(window["tz"]))
    except (ZoneInfoNotFoundError, ValueError):
        raise ValueError(f"window time zone {window['tz']!r} is not an IANA name like Europe/Berlin") from None


def check(window: dict) -> None:
    """Raise ValueError for a window that can never be used, when an endpoint is saved."""
    if not window:
        return
    zone(window)
    unknown = [d for d in window.get("days", []) if str(d).lower()[:3] not in DAYS]
    if unknown:
        raise ValueError(f"window days {unknown}: use mon, tue, wed, thu, fri, sat, sun")
    hh, mm = (int(x) for x in str(window.get("start", "00:00")).split(":"))
    if not (0 <= hh < 24 and 0 <= mm < 60) or not 0 < float(window.get("hours", 24)) <= 168:
        raise ValueError("window start is HH:MM and hours between 0 and 168")


def next_window_start(window: dict, after: datetime) -> datetime:
    if not window:
        return after
    tz = zone(window)
    local = after.astimezone(tz) if tz else after
    days = [d.lower()[:3] for d in window.get("days", [])] or DAYS
    hh, mm = (int(x) for x in window.get("start", "00:00").split(":"))
    length = timedelta(hours=float(window.get("hours", 24)))
    for offset in range(-1, 15):
        day = (local + timedelta(days=offset)).date()
        if DAYS[day.weekday()] not in days:
            continue
        start = datetime.combine(day, time(hh, mm), tzinfo=tz or after.tzinfo)
        if start <= local < start + length:
            return after                      # already inside a window
        if start > local:
            return start.astimezone(after.tzinfo) if tz else start
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
