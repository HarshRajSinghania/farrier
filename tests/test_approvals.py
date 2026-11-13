"""Approval gates: manual approval and rejection, ServiceNow change approval, late approvals and windows."""
import json
from datetime import timedelta

import httpx
import pytest

from farrier.core.approvals import mode_for, validate
from farrier.db.store import parse_dt
from test_engine import _due_now, _endpoint


def _setup(engine, served, **settings):
    s, srv = served
    engine.settings.update(settings)
    eid = _endpoint(engine, s.port, "files", {"cert_path": str(srv / "fullchain.pem"), "key_path": str(srv / "key.pem")})
    engine.observe(engine.store.endpoint(eid))
    return eid, _due_now(engine, eid)


def test_modes_and_validation():
    assert mode_for({"approvals": {"default": "manual", "lab": "none"}}, {"project": "lab"}) is None
    assert mode_for({"approvals": {"default": "manual"}}, {"project": "payments"}) == "manual"
    assert mode_for({}, {"tags": ["require-approval"]}) == "manual"
    assert mode_for({}, {}) is None
    with pytest.raises(ValueError):
        validate({"default": "yes please"})


def test_manual_gate_holds_issuance_until_approved(engine, served):
    eid, now = _setup(engine, served, approvals={"default": "manual"})
    engine.tick(now=now, scan=False)
    r = engine.store.renewals()[0]
    assert r["state"] == "planned" and not engine.store.renewal(r["id"])["cert_pem"]   # nothing issued
    assert engine.approvals.pending()[r["id"]]["mode"] == "manual"
    engine.approvals.decide(r["id"], True, "alice")
    engine.tick(now=now, scan=False)
    assert engine.store.renewal(r["id"])["state"] == "done"
    with pytest.raises(ValueError):
        engine.approvals.decide(r["id"], True, "bob")                                  # nothing left to approve


def test_rejection_cancels(engine, served):
    eid, now = _setup(engine, served, approvals={"default": "manual"})
    engine.tick(now=now, scan=False)
    rid = engine.store.renewals()[0]["id"]
    engine.approvals.decide(rid, False, "carol")
    assert engine.store.renewal(rid)["state"] == "cancelled"


def test_late_approval_waits_for_the_next_window(engine, served):
    eid, now = _setup(engine, served, approvals={"default": "manual"})
    engine.tick(now=now, scan=False)
    rid = engine.store.renewals()[0]["id"]
    engine.approvals.decide(rid, True, "alice")
    nxt = now + timedelta(hours=6)
    engine.store.x("UPDATE endpoints SET window=? WHERE id=?",
                   (json.dumps({"start": f"{nxt:%H}:00", "hours": 1}), eid))
    engine.store.x("UPDATE renewals SET deadline=? WHERE id=?", ((now + timedelta(days=2)).isoformat(), rid))
    engine.tick(now=now, scan=False)
    r = engine.store.renewal(rid)
    assert r["state"] == "planned" and parse_dt(r["scheduled_for"]) > now


def test_servicenow_change_approval(engine, served):
    from farrier.itsm import servicenow
    state = {"approval": "requested"}
    opened = []

    def h(req):
        if req.url.path == "/oauth_token.do":
            return httpx.Response(200, json={"access_token": "t", "expires_in": 3600})
        if req.method == "GET" and req.url.path == "/api/now/table/change_request":
            return httpx.Response(200, json={"result": []})
        if req.method == "POST" and req.url.path == "/api/now/table/change_request":
            opened.append(json.loads(req.content))
            return httpx.Response(201, json={"result": {"sys_id": "abc", "number": "CHG0040001"}})
        if req.url.path == "/api/now/table/change_request/abc":
            return httpx.Response(200, json={"result": {"approval": state["approval"]}})
        return httpx.Response(200, json={"result": []})

    eid, now = _setup(engine, served, approvals={"default": "servicenow:snow"})
    engine.itsm.transport = httpx.MockTransport(h)
    engine.itsm.channels = lambda: [{"name": "snow", "type": "servicenow", "instance": "acme.service-now.com",
                                     "username": "farrier", "password": "pw", "tickets": False}]
    engine.tick(now=now, scan=False)
    rid = engine.store.renewals()[0]["id"]
    assert opened and "Approve TLS certificate renewal" in opened[0]["short_description"]
    assert engine.store.renewal(rid)["state"] == "planned"
    state["approval"] = "approved"
    engine.tick(now=now, scan=False)
    assert engine.store.renewal(rid)["state"] == "done"
    assert engine.approvals.get(rid)["by"] == "servicenow CHG0040001" and len(opened) == 1
    del servicenow
