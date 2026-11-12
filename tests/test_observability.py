"""Prometheus metrics, inventory export and notifications."""
import csv
import io

from fastapi.testclient import TestClient

from farrier.api.app import create_app
from farrier.demo import start
from farrier.monitoring.notify import body_for, payload


def test_metrics_and_inventory(tmp_path, monkeypatch):
    monkeypatch.delenv("FARRIER_API_TOKEN", raising=False)
    monkeypatch.delenv("FARRIER_API_READ_TOKEN", raising=False)
    eng, _ = start(tmp_path / "demo")
    eng.settings["verify_retry_seconds"] = 0.05
    c = TestClient(create_app(eng))
    c.post("/api/tick")  # observe every endpoint once

    m = c.get("/metrics")
    assert m.status_code == 200 and m.headers["content-type"].startswith("text/plain")
    text = m.text
    for name in ("farrier_cert_not_after_timestamp_seconds", "farrier_cert_expires_in_seconds",
                 "farrier_cert_expired", "farrier_endpoint_up", "farrier_build_info"):
        assert f"# TYPE {name} gauge" in text
    assert text.count("farrier_cert_not_after_timestamp_seconds{") == 41
    assert 'automated="true"' in text and 'automated="false"' in text

    rows = c.get("/api/inventory").json()
    assert len(rows) == 41 and {"name", "not_after", "days_left"} <= rows[0].keys()
    r = c.get("/api/inventory?format=csv")
    assert r.headers["content-type"].startswith("text/csv")
    parsed = list(csv.DictReader(io.StringIO(r.text)))
    assert len(parsed) == 41 and parsed[0]["name"]


def test_notifier_shapes_and_delivery(tmp_path, monkeypatch):
    p = payload("rolled_back", {"id": 7, "error": "never went live"}, {"name": "www-lb", "host": "10.0.0.1", "port": 443})
    assert body_for("webhook", p)["event"] == "rolled_back"
    assert "www-lb" in body_for("slack", p)["text"] and "rolled back" in body_for("slack", p)["text"]
    assert "never went live" in body_for("teams", p)["text"]

    sent = []

    class Ok:
        def raise_for_status(self):
            pass

    monkeypatch.setattr("farrier.monitoring.notify.httpx.post", lambda url, json, headers, timeout: sent.append((url, json, headers)) or Ok())
    monkeypatch.setenv("FARRIER_SECRET_HOOK", "https://hooks.example.internal/x")
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "settings.json").write_text(
        '{"notifiers": [{"type": "slack", "url": "env:FARRIER_SECRET_HOOK"}, '
        '{"type": "webhook", "url": "https://h.example.internal", "events": ["done"]}]}')
    monkeypatch.delenv("FARRIER_API_TOKEN", raising=False)
    from farrier.core.engine import Engine

    eng = Engine(tmp_path / "data", issuers={"default": {"kind": "local"}})
    c = TestClient(create_app(eng))
    assert c.post("/api/notifiers/test").json() == {"sent": ["slack", "webhook"]}
    assert {u for u, _, _ in sent} == {"https://hooks.example.internal/x", "https://h.example.internal"}

    # a webhook URL can't be pointed at Farrier's own secrets either
    sent.clear()
    eng.notifier.configs = [{"type": "webhook", "url": "env:FARRIER_MASTER_KEY"}]
    eng.notifier.send("test", wait=True)
    assert sent == []
    assert any("notification for test failed" in e["message"] for e in c.get("/api/events").json())


def test_inventory_csv_neutralises_tab_and_cr_led_formulas(tmp_path, monkeypatch):
    from farrier.core.engine import Engine
    monkeypatch.delenv("FARRIER_API_TOKEN", raising=False)
    monkeypatch.delenv("FARRIER_API_READ_TOKEN", raising=False)
    eng = Engine(tmp_path / "d")
    for i, name in enumerate(("\t=1+1", "\r=cmd|' /C calc'!A0", "=x", "web")):
        eng.store.upsert_endpoint({"name": name, "host": f"10.0.0.{i}", "port": 443, "connector": "manual",
                                   "connector_config": {}})
    parsed = list(csv.DictReader(io.StringIO(TestClient(create_app(eng)).get("/api/inventory?format=csv").text)))
    assert sorted(r["name"] for r in parsed) == sorted(["'\t=1+1", "'\r=cmd|' /C calc'!A0", "'=x", "web"])


def test_slack_and_teams_escape_device_controlled_strings():
    p = payload("failed", {"id": 7, "error": "<!channel> <https://evil.example|click> & [x](https://evil) *b*"},
                {"name": "web<@U1>", "host": "h", "port": 443})
    p["dashboard_url"] = "https://farrier.example/renewals/7"
    slack = body_for("slack", p)["text"]
    assert "<" not in slack.replace("&lt;", "") and "&lt;!channel&gt;" in slack and "&amp;" in slack
    teams = body_for("teams", p)["text"]
    assert "<" not in teams and r"\[x\](https://evil)" in teams and r"\*b\*" in teams
    assert "https://farrier.example/renewals/7" in slack and "https://farrier.example/renewals/7" in teams
