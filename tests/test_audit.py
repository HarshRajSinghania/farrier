"""Tamper-evident activity log and compliance report."""
import json

from farrier.monitoring import audit


def test_chain_detects_edits_and_deletions_and_exports_verify(engine):
    for i in range(5):
        engine.store.log(f"event {i}")
    assert audit.seal(engine.store) >= 5
    v = audit.verify(engine.store)
    assert v["ok"] and v["unsealed"] == 0 and v["head"]
    data = audit.export(engine.store)
    assert audit.check_export(engine.store, data)["ok"]

    rows = engine.store.q("SELECT id FROM events ORDER BY id")
    engine.store.x("UPDATE events SET message='nothing to see' WHERE id=?", (rows[2]["id"],))
    v = audit.verify(engine.store)
    assert not v["ok"] and v["first_bad_id"] == rows[2]["id"] and v["head"] is None
    engine.store.x("DELETE FROM events WHERE id=?", (rows[2]["id"],))
    assert audit.verify(engine.store)["first_bad_id"] == rows[3]["id"]        # a gap breaks the next link

    lines = data.decode().splitlines()
    forged = json.loads(lines[-1]) | {"signature": "00" * 32}
    assert not audit.check_export(engine.store, ("\n".join(lines[:-1] + [json.dumps(forged)]) + "\n").encode())["ok"]


def test_new_events_after_sealing_extend_the_chain(engine):
    engine.store.log("a")
    audit.seal(engine.store)
    head1 = audit.verify(engine.store)["head"]
    engine.store.log("b")
    assert audit.verify(engine.store)["unsealed"] == 1
    audit.seal(engine.store)
    v = audit.verify(engine.store)
    assert v["ok"] and v["head"] != head1


def test_compliance_report(engine, served):
    from test_engine import _endpoint
    s, srv = served
    eid = _endpoint(engine, s.port, "files", {"cert_path": str(srv / "fullchain.pem"), "key_path": str(srv / "key.pem")})
    engine.observe(engine.store.endpoint(eid))
    rep = audit.compliance(engine)
    p = rep["projects"]["default"]
    assert p["endpoints"] == 1 and p["automated_pct"] == 100.0 and p["expiring_30d"] == 1   # a 9-day cert
    assert "pqc_status" in rep["crypto"] and rep["audit"]["ok"]


def test_audit_and_report_routes(engine, monkeypatch):
    from fastapi.testclient import TestClient

    from farrier.api.app import create_app
    monkeypatch.setenv("FARRIER_API_TOKEN", "admin-tok")
    c = TestClient(create_app(engine))
    h = {"Authorization": "Bearer admin-tok"}
    engine.store.log("x")
    audit.seal(engine.store)
    assert c.get("/api/audit/verify", headers=h).json()["ok"] is True
    data = c.get("/api/audit/export", headers=h).content
    assert audit.check_export(engine.store, data)["ok"]
    csv = c.get("/api/reports/compliance?format=csv", headers=h).text
    assert csv.startswith("project,endpoints,automated") and csv.endswith("\n")
    assert c.get("/api/reports/compliance", headers=h).json()["audit"]["ok"] is True
