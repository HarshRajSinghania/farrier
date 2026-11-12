from datetime import date, datetime, timezone

from farrier.core import policy
from farrier.core.discovery import expand_targets
from farrier.core.scheduler import level, next_window_start


def test_schedule_steps():
    assert policy.max_lifetime_days(date(2026, 3, 14)) == 398
    assert policy.max_lifetime_days(date(2026, 3, 15)) == 200
    assert policy.max_lifetime_days(date(2027, 3, 15)) == 100
    assert policy.max_lifetime_days(date(2029, 3, 14)) == 100
    assert policy.max_lifetime_days(date(2029, 3, 15)) == 47
    assert policy.dcv_reuse_days(date(2029, 3, 15)) == 10


def test_naive_forecast_matches_brief():
    f = policy.forecast(1000, date(2029, 3, 15), early=False)
    assert f.renewals_per_year == 7766
    assert f.per_calendar_day == 21.3          # the brief's "21 a day" is per calendar day
    assert f.per_working_day == 31.1           # ...it is ~31 per working day


def test_real_forecast_renews_early():
    f = policy.forecast(1000, date(2029, 3, 15), manual_fraction=0.4, minutes_per_manual=45)
    assert f.interval_days == 31               # renew with 16 days left
    assert f.renewals_per_year == 11774
    assert f.manual_renewals_per_year == 4710
    assert f.manual_fte > 2


def test_lead_time_pulls_renewal_earlier():
    assert policy.renew_before_days(47, lead_days=0) == 16
    assert policy.renew_before_days(47, lead_days=21) == 21
    assert policy.renew_before_days(47, lead_days=60) == 35   # capped at 75% of life


def test_windows():
    wed = datetime(2026, 11, 11, 10, 0, tzinfo=timezone.utc)
    w = {"days": ["sat"], "start": "02:00", "hours": 4}
    assert next_window_start(w, wed) == datetime(2026, 11, 14, 2, 0, tzinfo=timezone.utc)
    inside = datetime(2026, 11, 14, 3, 0, tzinfo=timezone.utc)
    assert next_window_start(w, inside) == inside
    assert next_window_start({}, wed) == wed


def test_leveling_spills_to_next_window():
    w = {"days": ["sat", "sun"], "start": "02:00", "hours": 4}
    wed = datetime(2026, 11, 11, 10, 0, tzinfo=timezone.utc)
    latest = datetime(2026, 12, 31, tzinfo=timezone.utc)
    got = level(w, wed, latest, {"2026-11-14": 25}, cap=25)
    assert got == datetime(2026, 11, 15, 2, 0, tzinfo=timezone.utc)


def test_expand_targets():
    t = expand_targets("a.example:8443, 10.0.0.0/30:443|8443 vpn.example@10.1.1.1")
    assert ("a.example", 8443, None) in t
    assert ("10.0.0.1", 8443, None) in t and ("10.0.0.2", 443, None) in t
    assert ("10.1.1.1", 443, "vpn.example") in t


def test_expand_targets_rejects_garbage():
    import pytest

    for bad in ("not a target!!", "host:99999", "host:abc", "10.0.0.300/24", "bad_sni!@10.0.0.1", "-lead.example"):
        with pytest.raises(ValueError):
            expand_targets(bad)
    assert expand_targets("svc_1.corp.internal.") == [("svc_1.corp.internal.", 443, None)]
