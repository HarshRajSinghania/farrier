"""Keys and credentials at rest: sealed issuer keys, no plaintext secrets via the API, email over TLS only."""
import os

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from farrier.api.app import create_app
from farrier.core.engine import Engine
from farrier.issuers.local_ca import LocalCA
from farrier.monitoring.notify import send_email
from farrier.security.vault import load_private_key, save_private_key


def test_ca_key_is_encrypted_at_rest(tmp_path):
    LocalCA(tmp_path)
    pem = (tmp_path / "local-ca" / "ca.key").read_bytes()
    assert b"ENCRYPTED PRIVATE KEY" in pem
    with pytest.raises(TypeError):  # useless without the master key
        serialization.load_pem_private_key(pem, None)
    if os.name == "posix":
        assert (tmp_path / "local-ca" / "ca.key").stat().st_mode & 0o077 == 0
    LocalCA(tmp_path)  # and loads back with it


def test_plaintext_key_from_older_version_is_sealed_on_load(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    path = tmp_path / "acme-account-old.key"
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    loaded = load_private_key(path, tmp_path)
    assert loaded.private_numbers() == key.private_numbers()
    assert b"ENCRYPTED PRIVATE KEY" in path.read_bytes()


def test_wrong_master_key_cannot_open_keys(tmp_path, monkeypatch):
    save_private_key(tmp_path / "k.key", ec.generate_private_key(ec.SECP256R1()), tmp_path)
    monkeypatch.setenv("FARRIER_MASTER_KEY", "A" * 43 + "=")
    with pytest.raises(ValueError):
        load_private_key(tmp_path / "k.key", tmp_path)


def test_api_refuses_plaintext_credentials(tmp_path, monkeypatch):
    monkeypatch.delenv("FARRIER_API_TOKEN", raising=False)
    monkeypatch.delenv("FARRIER_ALLOW_INLINE_SECRETS", raising=False)
    monkeypatch.setenv("FARRIER_SECRET_F5", "from-the-secret-store")
    c = TestClient(create_app(Engine(tmp_path / "d", issuers={"default": {"kind": "local"}})))
    ep = {"name": "lb", "host": "127.0.0.1", "connector": "f5",
          "connector_config": {"url": "https://bigip.example.internal", "username": "farrier",
                               "password": "hunter2", "profile": "/Common/p"}}
    r = c.post("/api/endpoints", json=ep)
    assert r.status_code == 400 and "password" in r.json()["detail"]
    ep["connector_config"]["password"] = "env:FARRIER_SECRET_F5"
    assert c.post("/api/endpoints", json=ep).status_code == 200
    # a ticket header carrying a token is a credential too
    manual = {"name": "asa", "host": "127.0.0.1", "connector": "manual",
              "connector_config": {"ticket": {"url": "https://x.example.internal", "headers": {"Authorization": "Basic abc"}}}}
    assert c.post("/api/endpoints", json=manual).status_code == 400


class FakeSMTP:
    sent, log = [], []

    def __init__(self, host, port, timeout=None, context=None):
        FakeSMTP.log.append(("connect", host, port))

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self, context=None):
        FakeSMTP.log.append(("starttls", context.verify_mode == 2))  # ssl.CERT_REQUIRED

    def login(self, user, password):
        FakeSMTP.log.append(("login", user, password))

    def send_message(self, msg):
        FakeSMTP.sent.append(msg)


def test_email_and_ses(monkeypatch):
    monkeypatch.setattr("smtplib.SMTP", FakeSMTP)
    monkeypatch.setenv("FARRIER_SECRET_SES_USER", "AKIAEXAMPLE")
    monkeypatch.setenv("FARRIER_SECRET_SES_PASS", "smtp-secret")
    p = {"event": "failed", "endpoint": "www-lb", "host": "10.0.0.1", "port": 443, "error": "x\r\nBcc: evil@example.com"}
    send_email({"type": "ses", "region": "eu-west-1", "username": "env:FARRIER_SECRET_SES_USER",
                "password": "env:FARRIER_SECRET_SES_PASS", "from": "farrier@example.com", "to": ["pki@example.com"]}, p)
    assert ("connect", "email-smtp.eu-west-1.amazonaws.com", 587) in FakeSMTP.log
    assert ("starttls", True) in FakeSMTP.log                       # TLS with certificate verification
    assert ("login", "AKIAEXAMPLE", "smtp-secret") in FakeSMTP.log
    msg = FakeSMTP.sent[-1]
    assert msg["To"] == "pki@example.com" and "\n" not in msg["Subject"] and msg["Bcc"] is None

    with pytest.raises(ValueError):  # never a password over plain SMTP
        send_email({"type": "email", "host": "relay.internal", "tls": "none", "username": "u",
                    "password": "env:FARRIER_SECRET_SES_PASS", "from": "a@example.com", "to": "b@example.com"}, p)
