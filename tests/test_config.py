"""Dashboard configuration: a read view that never shows a secret, and validated settings changes."""
import json

import pytest
from fastapi.testclient import TestClient

from farrier.api.app import create_app
from farrier.core.engine import Engine

ADMIN = {"authorization": "Bearer admin-token"}
READER = {"authorization": "Bearer read-token"}
HOOK = "https://hooks.slack.com/services/T000/B000/very-secret"


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv("FARRIER_API_TOKEN", "admin-token")
    monkeypatch.setenv("FARRIER_API_READ_TOKEN", "read-token")
    data = tmp_path / "data"
    data.mkdir()
    (data / "settings.json").write_text(json.dumps({"horizon_days": 10, "notifiers": [{"type": "slack", "url": HOOK}]}))
    (data / "issuers.json").write_text(json.dumps({
        "le": {"preset": "letsencrypt", "email": "pki@example.com", "dns": "auto"},
        "zs": {"preset": "zerossl", "eab_kid": "env:ZS_KID", "eab_hmac_key": "inline-hmac-secret"},
    }))
    (data / "dns.json").write_text(json.dumps({
        "cf": {"provider": "cloudflare", "credentials": {"api_token": "env:CF_TOKEN"}, "zones": ["example.com"]},
    }))
    eng = Engine(data, issuers={"default": {"kind": "local"}})
    return eng, TestClient(create_app(eng)), data


def test_view_shows_references_never_secrets(setup):
    _, c, _ = setup
    r = c.get("/api/config", headers=READER)
    assert r.status_code == 200
    body = r.text
    assert HOOK not in body and "very-secret" not in body and "inline-hmac-secret" not in body
    cfg = r.json()
    assert cfg["settings"]["horizon_days"] == 10
    le = next(i for i in cfg["issuers"] if i["name"] == "le")
    assert le["directory"] == "acme-v02.api.letsencrypt.org" and le["dns"] == "auto"
    assert cfg["dns_accounts"][0]["credentials"] == {"api_token": "env:CF_TOKEN"}
    assert cfg["notifiers"] == [{"type": "slack", "events": ["failed", "rolled_back", "awaiting_manual"]}]


def test_settings_change_is_validated_saved_and_live(setup):
    eng, c, data = setup
    assert c.put("/api/config/settings", json={"horizon_days": 21}, headers=READER).status_code == 403
    for bad in ({"horizon_days": 0}, {"horizon_days": 2.5}, {"horizon_days": True},
                {"verify_all_addresses": "yes"}, {"notifiers": []}, {}):
        assert c.put("/api/config/settings", json=bad, headers=ADMIN).status_code == 400, bad
    r = c.put("/api/config/settings", json={"horizon_days": 21, "verify_all_addresses": True}, headers=ADMIN)
    assert r.status_code == 200
    assert eng.settings["horizon_days"] == 21 and eng.settings["verify_all_addresses"] is True
    saved = json.loads((data / "settings.json").read_text())
    assert saved["horizon_days"] == 21 and saved["notifiers"][0]["url"] == HOOK   # other keys kept
