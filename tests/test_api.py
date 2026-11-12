"""API + demo estate smoke test: seeds the SNI demo, runs a cycle, exercises every route."""
import io
import zipfile

from fastapi.testclient import TestClient

from farrier.api import create_app
from farrier.demo import start


def test_demo_estate_through_api(tmp_path, monkeypatch):
    monkeypatch.delenv("FARRIER_API_TOKEN", raising=False)
    eng, srv = start(tmp_path / "demo")
    eng.settings["verify_retry_seconds"] = 0.05
    c = TestClient(create_app(eng))

    assert "Farrier" in c.get("/").text
    s = c.get("/api/summary").json()
    assert s["endpoints"] == 41 and s["automated"] == 18
    assert len(s["calendar"]) == 90 and len(s["forecast"]) == 4

    t = c.post("/api/tick").json()
    assert t["planned"] > 0
    states = t["states"]
    assert "failed" not in states and "rolled_back" not in states, states

    done = c.get("/api/renewals?state=done").json()
    assert done and all(r["connector"] == "files" for r in done)
    waiting = c.get("/api/renewals?state=awaiting_manual").json()
    if waiting:
        rid = waiting[0]["id"]
        z = zipfile.ZipFile(io.BytesIO(c.get(f"/api/renewals/{rid}/pack").content))
        assert {"bundle.pfx", "fullchain.pem", "key.pem", "RUNBOOK.md"} <= set(z.namelist())
        assert "Steps" in c.get(f"/api/renewals/{rid}/runbook").json()["markdown"]

    eps = c.get("/api/endpoints").json()
    assert all("connector_config" not in e for e in eps)       # no secrets/paths leak to the UI
    target = next(e for e in eps if e["connector"] == "files" and e["days_left"] > 60)
    r = c.post(f"/api/endpoints/{target['id']}/renew").json()
    assert r["state"] == "done"

    assert c.post("/api/endpoints", json={"name": "x", "host": "h", "connector": "f5"}).status_code == 400
    assert c.get("/api/forecast?certs=1000&manual=0.4").json()["naive_2029"]["renewals_per_year"] == 7766
    assert c.get("/api/events").json()
    assert c.get("/api/connectors").json()


def test_token_required_when_set(tmp_path, monkeypatch):
    monkeypatch.setenv("FARRIER_API_TOKEN", "s3cret")
    from farrier.engine import Engine
    c = TestClient(create_app(Engine(tmp_path)))
    assert c.get("/api/summary").status_code == 401
    assert c.get("/api/summary", headers={"Authorization": "Bearer s3cret"}).status_code == 200
