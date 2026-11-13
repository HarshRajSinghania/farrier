"""Operability: reason codes, `farrier explain` (and its API route), and the /metrics lines built on them."""
from __future__ import annotations

import json
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from test_cli import run, run_json
from test_engine import _due_now, _endpoint

from farrier.api.app import create_app
from farrier.core import policy
from farrier.core.explain import explain, lines
from farrier.core.reasons import CODES, HINTS, code
from farrier.db.store import parse_dt


@pytest.mark.parametrize("state, error, approval, want", [
    ("planned", None, None, None),
    ("done", None, None, None),
    ("planned", None, {"state": "pending"}, "APPROVAL_PENDING"),
    ("planned", None, {"state": "pending", "overdue": True}, "APPROVAL_OVERDUE"),
    ("cancelled", None, {"state": "rejected"}, "APPROVAL_REJECTED"),
    ("planned", "issuance: ACME 429: {'type': 'urn:ietf:params:acme:error:rateLimited'} (retry after 60s)", None,
     "ISSUE_RATE_LIMITED"),
    ("failed", "issuance failed 5x: TXT records not visible after 120s (8.8.8.8: none)", None, "ISSUE_DNS"),
    ("planned", "issuance: ACME 403: www.example.com is not prevalidated on this ACME endpoint", None,
     "NOT_PREVALIDATED"),
    ("failed", "issuance failed 5x: ACME 500: internal error", None, "ISSUE_CA_ERROR"),
    ("failed", "policy: names not allowed: evil.test", None, "POLICY_DENIED"),
    ("failed", "deploy failed: connection refused", None, "DEPLOY_FAILED"),
    ("failed", "no runner of group dmz picked up the deploy before the deadline; is it running?", None,
     "DEPLOY_RUNNER_OFFLINE"),
    ("verifying", "verify: endpoint serving runner group dmz could not check (no answer)", None,
     "DEPLOY_RUNNER_OFFLINE"),
    ("verifying", "verify: endpoint serving 0123456789abcdef", None, "VERIFY_MISMATCH"),
    ("rolled_back", "new cert never went live (serving no TLS); rolled back", None, "VERIFY_MISMATCH"),
    ("verifying", "verify: chain: missing intermediate", None, "VERIFY_CHAIN"),
    ("verifying", "verify: hostname: www.example.com not covered", None, "VERIFY_CHAIN"),
    ("failed", "new cert never went live and rollback failed: timeout", None, "ROLLBACK_FAILED"),
    ("failed", "new cert never went live and the rollback did not finish: gone; check the device", None,
     "ROLLBACK_FAILED"),
    ("awaiting_manual", "OVERDUE: change not installed before deadline", None, "OVERDUE_MANUAL"),
    ("superseded", "a different cert (0123456789abcdef) was installed", None, "SUPERSEDED"),
    ("failed", "something nobody expected", None, "UNKNOWN"),
])
def test_reason_codes(state, error, approval, want):
    got = code(state, error, approval)
    assert got == want
    assert got is None or HINTS[got]


def test_every_code_has_a_one_line_hint():
    assert len(CODES) == len(set(CODES)) == 16 and all("\n" not in h and len(h) < 220 for h in HINTS.values())


# ---- explain ---------------------------------------------------------------------------------------------

def _files(engine, served, **kw):
    s, srv = served
    eid = _endpoint(engine, s.port, "files", {"cert_path": str(srv / "fullchain.pem"),
                                              "key_path": str(srv / "key.pem")}, **kw)
    engine.observe(engine.store.endpoint(eid))
    return eid, engine.store.endpoint(eid)


def test_explain_plain_due_date(engine, served):
    _, ep = _files(engine, served)
    now = policy.utcnow()
    d = explain(engine, ep, now)
    s, na = d["schedule"], parse_dt(d["certificate"]["not_after"])
    assert s["observed_lifetime_days"] == 9 and s["renew_before_days"] == 3     # a third of 9 days
    assert parse_dt(s["due"]) == na - timedelta(days=3) == parse_dt(s["start"]) and s["reason"] == "due"
    assert s["ari_due"] is None and s["window"] is None and s["backoff"] is None
    assert d["approval"]["mode"] is None and d["policy"]["allowed"] and not d["blockers"]
    assert d["next"]["at"] == s["start"] and "next tick" in d["next"]["summary"]
    text = "\n".join(lines(d))
    assert "renew 3 days before expiry" in text and "Approval: not required" in text


def test_explain_ari_window_wins(engine, served, monkeypatch):
    eid, ep = _files(engine, served)
    na = parse_dt(engine.store.latest_cert_observation(eid)["not_after"])
    monkeypatch.setattr(type(engine), "_ari_due", lambda self, ep: na - timedelta(days=5))
    d = explain(engine, ep)
    assert parse_dt(d["schedule"]["ari_due"]) == na - timedelta(days=5) == parse_dt(d["schedule"]["due"])
    assert d["schedule"]["reason"] == "due (CA renewal window)"
    assert "(earlier, so it wins)" in "\n".join(lines(d))


def test_explain_change_window_in_its_time_zone(engine, served):
    eid, _ = _files(engine, served, window={"start": "02:00", "hours": 1, "tz": "Europe/Berlin"})
    d = explain(engine, engine.store.endpoint(eid))
    s = d["schedule"]
    assert s["window_tz"] == "Europe/Berlin" and parse_dt(s["window_start_local"]).hour == 2
    assert s["start"] == s["window_start"] and parse_dt(s["start"]) >= parse_dt(s["due"])
    assert "Europe/Berlin" in "\n".join(lines(d))


def test_explain_backoff_and_last_failure(engine, served):
    eid, ep = _files(engine, served)
    now = policy.utcnow()
    rid = engine.store.create_renewal(eid, now.isoformat(), None, None, "test")
    engine.store.update_renewal(rid, state="failed", error="issuance failed 5x: ACME 429: rateLimited")
    d = explain(engine, ep, now)
    b = d["schedule"]["backoff"]
    assert b["failures"] == 1 and b["active"] and parse_dt(b["until"]) > now
    assert d["last_failure"]["reason_code"] == "ISSUE_RATE_LIMITED" and d["last_failure"]["hint"]
    assert any("backing off" in x for x in d["blockers"])
    assert d["schedule"]["reason"] == "due"            # the due date is days away: later than the backoff


def test_explain_approval_pending(engine, served):
    engine.settings["approvals"] = {"default": "manual"}
    eid, ep = _files(engine, served)
    engine.tick(now=_due_now(engine, eid), scan=False)
    d = explain(engine, ep)
    assert d["approval"] == {"mode": "manual", "state": "pending", "overdue": False, "ticket": None}
    assert d["open_renewal"]["reason_code"] == "APPROVAL_PENDING" and "APPROVAL_PENDING" in d["next"]["summary"]
    assert any("waiting for approval" in x for x in d["blockers"])


def test_explain_policy_denial(engine, served):
    engine.settings["policy"] = {"default": {"allowed_names": ["*.example.com"]}}
    _, ep = _files(engine, served)
    d = explain(engine, ep)
    assert not d["policy"]["allowed"] and "app.internal.test" in d["policy"]["violations"][0]
    assert any("POLICY_DENIED" in x for x in d["blockers"])


def test_explain_runner_endpoint_and_api(engine, served):
    s, srv = served
    eid = _endpoint(engine, s.port, "files", {"runner": "dmz", "cert_path": str(srv / "fullchain.pem"),
                                              "key_path": str(srv / "key.pem")})
    d = explain(engine, engine.store.endpoint(eid))
    assert d["endpoint"]["runner_group"] == "dmz" and d["runner"]["online"] is False
    assert d["schedule"] is None and "no certificate seen yet" in d["next"]["summary"]
    assert any("DEPLOY_RUNNER_OFFLINE" in x for x in d["blockers"])
    c = TestClient(create_app(engine))
    body = c.get(f"/api/endpoints/{eid}/explain").json()
    assert body["runner"]["group"] == "dmz" and c.get("/api/endpoints/999/explain").status_code == 404


def test_explain_cli(capsys, data_dir, engine, served):
    _files(engine, served)
    out = run(capsys, data_dir, "explain", "app1")
    assert out.startswith("app1 (id ") and "Next:" in out and "Daily cap:" in out
    assert run_json(capsys, data_dir, "explain", "app1")["schedule"]["renew_before_days"] == 3


# ---- API annotations and metrics --------------------------------------------------------------------------

def test_renewals_carry_reason_codes_and_metrics(engine, served):
    engine.settings["approvals"] = {"default": "manual"}
    eid, _ = _files(engine, served)
    now = policy.utcnow()
    failed = engine.store.create_renewal(eid, now.isoformat(), None, None, "test")
    engine.store.update_renewal(failed, state="failed", error="deploy failed: connection refused")
    engine.tick(now=_due_now(engine, eid), scan=False)       # plans a new renewal, held for approval
    engine.runners.issue_token("dmz")
    c = TestClient(create_app(engine))

    rows = {r["id"]: r for r in c.get("/api/renewals").json()}
    assert rows[failed]["reason_code"] == "DEPLOY_FAILED" and "connector" in rows[failed]["hint"]
    pending = next(r for r in rows.values() if r["state"] == "planned")
    assert pending["reason_code"] == "APPROVAL_PENDING" and pending["approval"]["mode"] == "manual"

    text = c.get("/metrics").text
    assert "# TYPE farrier_renewal_failures_total counter" in text
    assert 'farrier_renewal_failures_total{reason="DEPLOY_FAILED",issuer="default"} 1' in text
    line = next(x for x in text.splitlines() if x.startswith("farrier_renewal_planned_timestamp_seconds{"))
    assert 'endpoint="app1",state="planned"' in line and int(line.split()[-1]) > 0
    assert 'farrier_approvals_pending{overdue="false"} 1' in text
    assert 'farrier_approvals_pending{overdue="true"} 0' in text
    assert 'farrier_runner_group_online{group="dmz"} 0' in text
    assert 'farrier_runner_group_pending_jobs{group="dmz"} 0' in text
    assert "farrier_audit_log_intact 1" in text
    for line in text.splitlines():   # every sample line is "name{labels} number" or "name number"
        if line and not line.startswith("#"):
            float(line.rsplit(" ", 1)[1])
    json.dumps(c.get(f"/api/endpoints/{eid}/explain").json())   # serialisable
