"""Configure everything from the dashboard: secrets, CAs, DNS accounts, alert channels and alert rules."""
import json
from datetime import timedelta
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient

from farrier.api.app import create_app
from farrier.core import policy
from farrier.core.engine import Engine
from farrier.core.x509util import parse_pem
from farrier.db.store import Store, now_iso
from farrier.issuers import acme as acme_mod
from farrier.issuers.acme import b64u
from farrier.issuers.local_ca import LocalCA
from farrier.monitoring.health import store_grade
from farrier.monitoring.notify import Notifier
from farrier.security.vault import resolve_secret

ADMIN = {"Authorization": "Bearer admin-tok", "X-Farrier-Actor": "alice"}
READ = {"Authorization": "Bearer read-tok"}


@pytest.fixture
def env(data_dir, monkeypatch):
    monkeypatch.setenv("FARRIER_API_TOKEN", "admin-tok")
    monkeypatch.setenv("FARRIER_API_READ_TOKEN", "read-tok")
    monkeypatch.delenv("FARRIER_ALLOW_API_COMMANDS", raising=False)
    monkeypatch.delenv("FARRIER_ALLOW_INLINE_SECRETS", raising=False)
    eng = Engine(data_dir, settings={"verify_retry_seconds": 0.01, "scan_timeout": 0.5})
    return eng, TestClient(create_app(eng))


@pytest.fixture
def sent(monkeypatch):
    """Record alert-rule deliveries instead of sending them."""
    out = []

    def send_to(self, names, p, wait=False):
        out.append((sorted(names), p))
        return {n: True for n in names}
    monkeypatch.setattr(Notifier, "send_to", send_to)
    return out


def put(c, path, body, headers=ADMIN):
    return c.put(path, json=body, headers=headers)


def _cert(days_left: float, fp="ab" * 16):
    now = policy.utcnow()
    return SimpleNamespace(fingerprint=fp, subject_cn="x.test", sans=["x.test"], issuer="Test CA",
                           not_before=now - timedelta(days=30), not_after=now + timedelta(days=days_left),
                           key_type="ec256")


def _endpoint(eng, name, days_left, tags=(), connector="manual"):
    eid = eng.store.upsert_endpoint({"name": name, "host": "127.0.0.1", "port": 1, "connector": connector,
                                     "connector_config": {}, "tags": list(tags)})
    eng.store.add_observation(eid, _cert(days_left, fp=f"{eid:032x}"))
    return eid


# ---- secrets -----------------------------------------------------------------------------------------
def test_secret_is_write_only_and_sealed_at_rest(env):
    eng, c = env
    assert put(c, "/api/secrets/cf-token", {"value": "s3cr3t-cloudflare-token"}).json() == {"name": "cf-token"}
    listed = c.get("/api/secrets", headers=ADMIN)
    assert "s3cr3t-cloudflare-token" not in listed.text
    (row,) = listed.json()
    assert row["name"] == "cf-token" and row["used_by"] == [] and row["created_at"] and row["updated_at"]
    assert row["backend"] == "local" and "master key" in row["location"]
    index = eng.store.q1("SELECT * FROM secrets WHERE name='cf-token'")
    assert index["backend"] == "local" and "s3cr3t" not in json.dumps(index)
    raw = eng.store.q1("SELECT * FROM secret_values WHERE ref=?", (index["ref"],))
    assert "s3cr3t" not in json.dumps(raw) and eng.store.vault.open(raw["value_sealed"]) == "s3cr3t-cloudflare-token"
    assert c.get("/api/secrets/backend", headers=READ).json()["backend"] == "local"
    assert c.get("/api/secrets/backend", headers=READ).json()["writable"] is True
    assert resolve_secret("vault:cf-token") == "s3cr3t-cloudflare-token"
    with pytest.raises(KeyError, match="vault:nope"):
        resolve_secret("vault:nope")
    assert put(c, "/api/secrets/cf-token", {"value": ""}).status_code == 400
    assert put(c, "/api/secrets/cf-token", {"value": "x" * (16 * 1024 + 1)}).status_code == 400
    assert put(c, "/api/secrets/bad name", {"value": "x"}).status_code in (400, 404)
    assert put(c, "/api/secrets/-bad", {"value": "x"}).status_code == 400
    # the event log names the actor, never the value
    ev = c.get("/api/events", headers=ADMIN).text
    assert "secret cf-token added by alice" in ev and "s3cr3t" not in ev


def test_secret_in_use_cannot_be_deleted(env):
    _, c = env
    put(c, "/api/secrets/cf", {"value": "tok"})
    r = put(c, "/api/dns-accounts/cf-prod", {"provider": "cloudflare", "credentials": {"api_token": "vault:cf"},
                                             "zones": ["example.com"]})
    assert r.status_code == 200, r.text
    assert c.get("/api/secrets", headers=ADMIN).json()[0]["used_by"] == ["dns:cf-prod"]
    r = c.delete("/api/secrets/cf", headers=ADMIN)
    assert r.status_code == 409 and "dns:cf-prod" in r.json()["detail"]
    assert c.delete("/api/dns-accounts/cf-prod", headers=ADMIN).json() == {"ok": True}
    assert c.delete("/api/secrets/cf", headers=ADMIN).json() == {"ok": True}
    assert c.delete("/api/secrets/cf", headers=ADMIN).status_code == 404


# ---- guardrails --------------------------------------------------------------------------------------
def test_inline_secrets_refused_in_every_config_type(env):
    _, c = env
    r = put(c, "/api/issuers/zs", {"preset": "zerossl", "dns": "auto", "eab_kid": "kid", "eab_hmac_key": "raw"})
    assert r.status_code == 400 and "eab" in r.json()["detail"]
    r = put(c, "/api/dns-accounts/cf", {"provider": "cloudflare", "credentials": {"api_token": "raw-token"}})
    assert r.status_code == 400 and "must be a reference" in r.json()["detail"]
    r = put(c, "/api/notifiers/ops", {"type": "slack", "url": "https://hooks.slack.com/services/T/B/x"})
    assert r.status_code == 400 and "secret" in r.json()["detail"]
    r = put(c, "/api/notifiers/hook", {"type": "webhook", "url": "env:HOOK", "headers": {"Authorization": "Bearer x"}})
    assert r.status_code == 400
    r = put(c, "/api/notifiers/mail", {"type": "email", "host": "smtp.test", "from": "a@b.c", "to": ["d@e.f"],
                                       "password": "hunter2"})
    assert r.status_code == 400
    # a vault reference must exist; Farrier's own credentials are never a secret source
    r = put(c, "/api/dns-accounts/cf", {"provider": "cloudflare", "credentials": {"api_token": "vault:missing"}})
    assert r.status_code == 400 and "missing" in r.json()["detail"]
    r = put(c, "/api/dns-accounts/cf", {"provider": "cloudflare", "credentials": {"api_token": "env:FARRIER_MASTER_KEY"}})
    assert r.status_code == 400


def test_command_fields_refused_unless_allowed(env, data_dir, monkeypatch):
    _, c = env
    r = put(c, "/api/issuers/hooked", {"type": "acme", "directory_url": "https://acme.test/directory",
                                       "dns_hook": "/opt/hook.sh"})
    assert r.status_code == 400 and "dns_hook" in r.json()["detail"]
    r = put(c, "/api/dns-accounts/scripted", {"provider": "script", "options": {"dns_hook": "/opt/hook.sh"}})
    assert r.status_code == 400 and "dns_hook" in r.json()["detail"]
    assert "script" not in {p["id"] for p in c.get("/api/integrations/catalog", headers=ADMIN).json()["dns_providers"]}
    monkeypatch.setenv("FARRIER_ALLOW_API_COMMANDS", "1")
    c2 = TestClient(create_app(Engine(data_dir)))
    r = put(c2, "/api/issuers/hooked", {"type": "acme", "directory_url": "https://acme.test/directory",
                                        "dns_hook": "/opt/hook.sh"})
    assert r.status_code == 200, r.text


def test_read_token_can_read_but_not_write(env):
    _, c = env
    for path in ("/api/secrets", "/api/issuers", "/api/dns-accounts", "/api/notifiers", "/api/alert-rules",
                 "/api/integrations/catalog"):
        assert c.get(path, headers=READ).status_code == 200, path
    assert put(c, "/api/secrets/x", {"value": "v"}, headers=READ).status_code == 403
    assert put(c, "/api/issuers/x", {"type": "local_ca"}, headers=READ).status_code == 403
    assert c.delete("/api/issuers/default", headers=READ).status_code == 403
    assert c.post("/api/notifiers/x/test", headers=READ).status_code == 403
    assert c.get("/api/issuers").status_code == 401


# ---- file-sourced entries ----------------------------------------------------------------------------
def test_file_entries_are_listed_read_only(data_dir, monkeypatch):
    monkeypatch.delenv("FARRIER_API_TOKEN", raising=False)
    monkeypatch.delenv("FARRIER_API_READ_TOKEN", raising=False)
    (data_dir / "issuers.json").write_text(json.dumps({"default": {"type": "local_ca"}}))
    (data_dir / "dns.json").write_text(json.dumps({"cf": {"provider": "cloudflare",
                                                          "credentials": {"api_token": "env:CF_TOKEN"}}}))
    (data_dir / "settings.json").write_text(json.dumps({"notifiers": [
        {"type": "slack", "url": "env:SLACK_HOOK"}, {"type": "email", "host": "smtp.test", "from": "f@x.test",
                                                      "to": ["pki@x.test"]}]}))
    c = TestClient(create_app(Engine(data_dir)))
    assert [(i["name"], i["source"], i["type"]) for i in c.get("/api/issuers").json()] == [("default", "file", "local_ca")]
    (d,) = c.get("/api/dns-accounts").json()
    assert d == {"name": "cf", "source": "file", "provider": "cloudflare", "zones": [],
                 "credentials": {"api_token": "env:CF_TOKEN"}, "options": {}}
    ns = c.get("/api/notifiers").json()
    assert [(n["name"], n["source"], n["target"]) for n in ns] == [("settings-1", "file", "Slack"),
                                                                   ("settings-2", "file", "pki@x.test")]
    for method, path, body in [("put", "/api/issuers/default", {"type": "local_ca"}),
                               ("delete", "/api/issuers/default", None),
                               ("put", "/api/dns-accounts/cf", {"provider": "cloudflare"}),
                               ("delete", "/api/dns-accounts/cf", None),
                               ("put", "/api/notifiers/settings-1", {"type": "slack", "url": "env:X"}),
                               ("delete", "/api/notifiers/settings-2", None)]:
        r = c.request(method.upper(), path, json=body)
        assert r.status_code == 409 and r.json()["detail"].startswith("managed in "), (path, r.text)
    assert "issuers.json" in c.delete("/api/issuers/default").json()["detail"]
    # a dashboard issuer alongside the file; then the file issuer is the only other one
    assert put(c, "/api/issuers/lab", {"type": "local_ca"}, headers={}).status_code == 200
    assert {i["name"]: i["source"] for i in c.get("/api/issuers").json()} == {"default": "file", "lab": "ui"}


def test_last_issuer_and_issuer_in_use_are_kept(data_dir, monkeypatch):
    monkeypatch.delenv("FARRIER_API_TOKEN", raising=False)
    monkeypatch.delenv("FARRIER_API_READ_TOKEN", raising=False)
    (data_dir / "issuers.json").write_text("{}")
    eng = Engine(data_dir)
    c = TestClient(create_app(eng))
    assert put(c, "/api/issuers/only", {"type": "local_ca"}, headers={}).status_code == 200
    r = c.delete("/api/issuers/only")
    assert r.status_code == 409 and "last issuer" in r.json()["detail"]
    assert put(c, "/api/issuers/second", {"type": "local_ca"}, headers={}).status_code == 200
    eng.store.upsert_endpoint({"name": "web-1", "host": "h", "issuer": "second"})
    r = c.delete("/api/issuers/second")
    assert r.status_code == 409 and "web-1" in r.json()["detail"]
    assert c.delete("/api/issuers/only").json() == {"ok": True}


# ---- issuers -----------------------------------------------------------------------------------------
def test_issuer_validation_errors_are_clear(env):
    _, c = env

    def err(body):
        r = put(c, "/api/issuers/ca", body)
        assert r.status_code == 400, r.text
        return r.json()["detail"]

    assert "External Account Binding" in err({"preset": "zerossl", "dns": "auto"})
    assert "unknown preset" in err({"preset": "nope", "dns": "auto"})
    assert "directory_url" in err({"preset": "digicert", "dns": "auto", "eab_kid": "env:K", "eab_hmac_key": "env:H"})
    assert "unknown keys" in err({"preset": "letsencrypt", "dns": "auto", "emial": "x@y.z"})
    assert "no DNS account named 'cf'" in err({"preset": "letsencrypt", "dns": "cf"})
    assert "\"dns\"" in err({"preset": "letsencrypt"})
    assert "not set" in err({"preset": "zerossl", "dns": "auto", "eab_kid": "env:FARRIER_TEST_UNSET_KID",
                             "eab_hmac_key": "env:FARRIER_TEST_UNSET_HMAC"})


def test_issuer_round_trip_and_eab_refs(env):
    _, c = env
    put(c, "/api/secrets/zs-kid", {"value": "kid-123"})
    put(c, "/api/secrets/zs-hmac", {"value": b64u(b"hmac-key")})
    r = put(c, "/api/issuers/zerossl", {"preset": "zerossl", "email": "pki@example.com", "dns": "auto",
                                        "eab_kid": "vault:zs-kid", "eab_hmac_key": "vault:zs-hmac", "profile": None})
    assert r.status_code == 200, r.text
    view = r.json()
    assert view == {"name": "zerossl", "source": "ui", "type": "acme", "preset": "zerossl",
                    "directory_url": "https://acme.zerossl.com/v2/DV90", "email": "pki@example.com", "dns": "auto",
                    "profile": None, "preferred_chain": None, "eab_kid": "vault:zs-kid", "eab_hmac_key": "vault:zs-hmac"}
    listed = {i["name"]: i for i in c.get("/api/issuers", headers=ADMIN).json()}
    assert listed["default"]["source"] == "builtin" and listed["zerossl"] == view
    used = {s["name"]: s["used_by"] for s in c.get("/api/secrets", headers=ADMIN).json()}
    assert used == {"zs-hmac": ["issuer:zerossl"], "zs-kid": ["issuer:zerossl"]}
    assert "kid-123" not in c.get("/api/issuers", headers=ADMIN).text


def test_issuer_test_creates_account_with_eab(env, monkeypatch):
    from test_acme import FakeAcme
    eng, c = env
    srv = FakeAcme(LocalCA(eng.data_dir), eab=("kid-1", b"supersecret-hmac"))
    srv.bad_nonce_once = False
    mock = SimpleNamespace(Client=lambda **kw: httpx.Client(transport=httpx.MockTransport(srv.handler)))
    monkeypatch.setattr(acme_mod, "httpx", mock)
    put(c, "/api/secrets/kid", {"value": "kid-1"})
    put(c, "/api/secrets/hmac", {"value": b64u(b"supersecret-hmac")})
    put(c, "/api/dns-accounts/duck", {"provider": "duckdns", "credentials": {"token": "vault:kid"},
                                      "zones": ["x.duckdns.org"]})
    body = {"type": "acme", "directory_url": "https://acme.test/directory", "dns": "duck",
            "eab_kid": "vault:kid", "eab_hmac_key": "vault:hmac"}
    assert put(c, "/api/issuers/corp", body).status_code == 200
    r = c.post("/api/issuers/corp/test", headers=ADMIN).json()
    assert r == {"ok": True, "detail": "account ready at acme.test with External Account Binding"}
    assert srv.accounts
    put(c, "/api/secrets/hmac", {"value": b64u(b"wrong")})
    r = c.post("/api/issuers/corp/test", headers=ADMIN).json()   # the fake CA rejects the wrong EAB MAC
    assert r["ok"] is False and "account was refused" in r["detail"]
    assert c.post("/api/issuers/default/test", headers=ADMIN).json()["ok"] is True
    assert c.post("/api/issuers/nope/test", headers=ADMIN).status_code == 404


def test_issuer_put_is_used_by_the_next_issuance_without_restart(env, data_dir):
    eng, c = env
    other = Engine(data_dir)                          # a second replica on the same database
    assert "lab" not in eng.issuers and "lab" not in other.issuers
    r = put(c, "/api/issuers/lab", {"preset": "local_ca", "lifetime_days": 10})   # the UI's spelling
    assert r.status_code == 200 and r.json()["type"] == "local_ca", r.text
    eid = eng.store.upsert_endpoint({"name": "lab-ep", "host": "127.0.0.1", "port": 1, "connector": "manual",
                                     "common_name": "lab.internal.test", "issuer": "lab"})
    rid = eng.force_renewal(eid)
    assert eng.advance(rid) == "awaiting_manual"
    info = parse_pem(eng.store.renewal(rid)["cert_pem"])
    assert info.lifetime_days == 10                   # issued by the dashboard-configured issuer
    assert other.check_config() is True and "lab" in other.issuers
    assert other.check_config() is False              # nothing new since
    eng.cancel(rid)


# ---- DNS accounts ------------------------------------------------------------------------------------
def test_dns_accounts_validated_with_validate_account(env):
    eng, c = env

    def err(body):
        r = put(c, "/api/dns-accounts/acct", body)
        assert r.status_code == 400, r.text
        return r.json()["detail"]

    assert "unknown DNS provider" in err({"provider": "nope"})
    assert "needs credentials" in err({"provider": "route53", "credentials": {"access_key_id": "env:A"}})
    assert "unknown option" in err({"provider": "cloudflare", "credentials": {"api_token": "env:T"},
                                    "options": {"colour": "red"}})
    assert "unknown keys" in err({"provider": "cloudflare", "credentials": {"api_token": "env:T"}, "zone": "x"})
    r = put(c, "/api/dns-accounts/aws", {"provider": "aws", "credentials": {"access_key_id": "env:A",
                                         "secret_access_key": "env:B"}, "options": {"private_zones": "true",
                                         "ttl": "30"}, "zones": ["Corp.Example.NET."]})
    assert r.status_code == 200, r.text
    assert r.json() == {"name": "aws", "source": "ui", "provider": "route53", "zones": ["corp.example.net"],
                        "credentials": {"access_key_id": "env:A", "secret_access_key": "env:B"},
                        "options": {"private_zones": True, "ttl": 30}}
    assert eng.dns_accounts.get("aws").ttl == 30      # reloaded into the engine
    # an issuer that names it keeps it
    assert put(c, "/api/issuers/le", {"preset": "letsencrypt", "dns": "aws"}).status_code == 200
    r = c.delete("/api/dns-accounts/aws", headers=ADMIN)
    assert r.status_code == 409 and "issuer:le" in r.json()["detail"]


def test_dns_account_test_is_read_only(env, monkeypatch):
    _, c = env
    put(c, "/api/secrets/duck", {"value": "duck-token"})
    put(c, "/api/dns-accounts/duck", {"provider": "duckdns", "credentials": {"token": "vault:duck"},
                                      "zones": ["me.duckdns.org"]})
    r = c.post("/api/dns-accounts/duck/test", headers=ADMIN).json()
    assert r["ok"] is True and r["zones"] == ["me.duckdns.org"]
    put(c, "/api/dns-accounts/cf", {"provider": "cloudflare", "credentials": {"api_token": "env:FARRIER_TEST_NO_SUCH"}})
    r = c.post("/api/dns-accounts/cf/test", headers=ADMIN).json()
    assert r["ok"] is False and "FARRIER_TEST_NO_SUCH" in r["detail"]

    # Cloudflare: zones are listed (GET only) and compared
    from farrier.dns.providers import cloudflare
    calls = []

    def fake_request(self, method, url, **kw):
        calls.append(method)
        return httpx.Response(200, json={"success": True, "result": [{"name": "example.com", "id": "z1"}],
                                         "result_info": {"total_pages": 1}})
    monkeypatch.setattr(cloudflare.Cloudflare, "request", fake_request)
    put(c, "/api/secrets/cf", {"value": "tok"})
    put(c, "/api/dns-accounts/cf", {"provider": "cloudflare", "credentials": {"api_token": "vault:cf"},
                                    "zones": ["example.com", "other.org"]})
    r = c.post("/api/dns-accounts/cf/test", headers=ADMIN).json()
    assert r["ok"] is False and "other.org" in r["detail"] and r["zones"] == ["example.com"]
    assert set(calls) == {"GET"}


# ---- alert channels ----------------------------------------------------------------------------------
def test_notifiers_round_trip_without_urls(env, monkeypatch):
    eng, c = env
    put(c, "/api/secrets/slack-hook", {"value": "https://hooks.slack.com/services/T/B/secret"})
    r = put(c, "/api/notifiers/ops", {"type": "slack", "url": "vault:slack-hook", "channel": "#ops",
                                      "events": ["failed", "done"]})
    assert r.status_code == 200, r.text
    assert r.json() == {"name": "ops", "source": "ui", "type": "slack", "events": ["failed", "done"],
                        "target": "#ops on Slack", "fields": {"url": "vault:slack-hook", "channel": "#ops"}}
    # an edit that leaves out the secret keeps the stored reference
    r = put(c, "/api/notifiers/ops", {"type": "slack", "channel": "#pki", "events": ["failed", "done"]})
    assert r.status_code == 200, r.text
    assert r.json()["fields"] == {"url": "vault:slack-hook", "channel": "#pki"}
    put(c, "/api/notifiers/ops", {"type": "slack", "channel": "#ops", "events": ["failed", "done"]})
    r = put(c, "/api/notifiers/mail", {"type": "email", "host": "smtp.test", "port": "587", "from": "f@x.test",
                                       "to": "pki@x.test", "username": "apikey", "password": "vault:slack-hook"})
    assert r.status_code == 200 and r.json()["target"] == "pki@x.test"
    assert "hooks.slack.com" not in c.get("/api/notifiers", headers=ADMIN).text
    assert {n["name"] for n in eng.notifier.configs} == {"ops", "mail"}   # live without restart

    posted = []

    def fake_post(url, json=None, headers=None, timeout=None):
        posted.append(url)
        return httpx.Response(500 if "bad" in url else 200, request=httpx.Request("POST", url))
    monkeypatch.setattr("farrier.monitoring.notify.httpx.post", fake_post)
    assert c.post("/api/notifiers/ops/test", headers=ADMIN).json() == {"ok": True, "detail": "delivered to #ops on Slack"}
    assert posted == ["https://hooks.slack.com/services/T/B/secret"]
    put(c, "/api/secrets/slack-hook", {"value": "https://hooks.slack.com/bad"})
    r = c.post("/api/notifiers/ops/test", headers=ADMIN).json()
    assert r == {"ok": False, "detail": "the receiver answered HTTP 500"}
    assert c.post("/api/notifiers/test", headers=ADMIN).json()["sent"]    # the old route still works
    assert c.delete("/api/notifiers/mail", headers=ADMIN).json() == {"ok": True}


# ---- alert rules -------------------------------------------------------------------------------------
def _channel(c):
    put(c, "/api/secrets/hook", {"value": "https://hooks.example.test/x"})
    assert put(c, "/api/notifiers/ops", {"type": "webhook", "url": "vault:hook", "events": []}).status_code == 200


def test_alert_rule_validation(env):
    _, c = env
    _channel(c)

    def err(body):
        r = put(c, "/api/alert-rules/r", body)
        assert r.status_code == 400, r.text
        return r.json()["detail"]

    base = {"enabled": True, "channels": ["ops"]}
    assert "when.type" in err(base | {"when": {"type": "weather"}})
    assert "days" in err(base | {"when": {"type": "expiring", "days": 0}})
    assert "days" in err(base | {"when": {"type": "unreachable", "days": 91}})
    assert "below" in err(base | {"when": {"type": "health", "below": "F"}})
    assert "events" in err(base | {"when": {"type": "event", "events": ["exploded"]}})
    assert "zombie kinds" in err(base | {"when": {"type": "zombie", "kinds": ["ghost"]}})
    assert "no alert channel" in err(base | {"channels": ["nope"], "when": {"type": "expiring", "days": 7}})
    assert "cooldown" in err(base | {"when": {"type": "expiring", "days": 7}, "cooldown_hours": 0})
    r = put(c, "/api/alert-rules/r", base | {"when": {"type": "expiring", "days": 7}, "filter": {"name": "web-*"}})
    assert r.json() == {"name": "r", "enabled": True, "when": {"type": "expiring", "days": 7},
                        "filter": {"name": "web-*"}, "channels": ["ops"], "cooldown_hours": 24, "last_fired_at": None}
    r = c.delete("/api/notifiers/ops", headers=ADMIN)
    assert r.status_code == 409 and "r" in r.json()["detail"]


def test_expiring_rule_fires_once_per_cooldown_and_survives_restart(env, data_dir, sent):
    eng, c = env
    _channel(c)
    _endpoint(eng, "web-1", days_left=5, tags=["prod"])
    _endpoint(eng, "web-2", days_left=200, tags=["prod"])
    _endpoint(eng, "db-1", days_left=3, tags=["staging"])
    r = put(c, "/api/alert-rules/expiring-prod", {"enabled": True, "when": {"type": "expiring", "days": 14},
                                                  "filter": {"tags": ["prod"]}, "channels": ["ops"],
                                                  "cooldown_hours": 12})
    assert r.status_code == 200, r.text
    now = policy.utcnow()
    eng.tick(now=now, scan=False)
    assert len(sent) == 1
    channels, p = sent[0]
    assert channels == ["ops"] and p["endpoint"] == "web-1" and p["rule"] == "expiring-prod"
    assert "expires in 4.9 days" in p["condition"] or "expires in 5.0 days" in p["condition"]
    eng.tick(now=now + timedelta(hours=1), scan=False)
    assert len(sent) == 1                              # within the cooldown
    assert c.get("/api/alert-rules", headers=ADMIN).json()[0]["last_fired_at"]

    eng2 = Engine(data_dir)                            # restart / another replica
    assert eng2.alerts.evaluate(now + timedelta(hours=2)) == 0
    assert eng2.alerts.evaluate(now + timedelta(hours=13)) == 1
    assert len(sent) == 2
    # disabled rules never fire
    put(c, "/api/alert-rules/expiring-prod", {"enabled": False, "when": {"type": "expiring", "days": 14},
                                              "filter": {"tags": ["prod"]}, "channels": ["ops"]})
    assert eng.alerts.evaluate(now + timedelta(days=5)) == 0


def test_event_rule_fires_on_state_change_with_cooldown(env, sent):
    eng, c = env
    _channel(c)
    eid = _endpoint(eng, "web-1", days_left=60)
    put(c, "/api/alert-rules/cancels", {"enabled": True, "when": {"type": "event", "events": ["cancelled"]},
                                        "channels": ["ops"]})
    put(c, "/api/alert-rules/only-db", {"enabled": True, "when": {"type": "event", "events": ["cancelled"]},
                                        "filter": {"name": "db-*"}, "channels": ["ops"]})
    eng.cancel(eng.force_renewal(eid))
    assert len(sent) == 1
    assert sent[0][1]["event"] == "cancelled" and sent[0][1]["endpoint"] == "web-1" and sent[0][1]["rule"] == "cancels"
    eng.cancel(eng.force_renewal(eid))
    assert len(sent) == 1                              # same rule + endpoint within 24 h


def test_zombie_and_health_rules(env, sent):
    eng, c = env
    _channel(c)
    expired = _endpoint(eng, "old-1", days_left=-2)
    graded = _endpoint(eng, "web-1", days_left=60)
    store_grade(eng.store, graded, "D", now_iso())
    store_grade(eng.store, expired, "A", now_iso())
    put(c, "/api/alert-rules/zombies", {"enabled": True, "when": {"type": "zombie", "kinds": ["expired_served"]},
                                        "channels": ["ops"]})
    put(c, "/api/alert-rules/grades", {"enabled": True, "when": {"type": "health", "below": "B"}, "channels": ["ops"]})
    assert eng.alerts.evaluate() == 2
    by_rule = {p["rule"]: p for _, p in sent}
    assert by_rule["zombies"]["endpoint"] == "old-1" and "expired served" in by_rule["zombies"]["condition"]
    assert by_rule["grades"]["endpoint"] == "web-1" and "grade D" in by_rule["grades"]["condition"]
    assert eng.alerts.evaluate() == 0
    r = c.post("/api/alert-rules/grades/test", headers=ADMIN).json()
    assert r == {"ok": True, "sent": ["ops"]}
    assert "test of alert rule grades" in sent[-1][1]["condition"]


def test_migration_4_applied_once(tmp_path):
    s = Store(tmp_path)
    assert 4 in s.migrated and s.schema_version() >= 4
    assert s.q1("SELECT version FROM config_version WHERE id=1") == {"version": 0}
    s.close()
    s2 = Store(tmp_path)
    assert s2.migrated == [] and len(s2.q("SELECT * FROM config_version")) == 1


def test_catalog_shape(env):
    _, c = env
    cat = c.get("/api/integrations/catalog", headers=ADMIN).json()
    cf = next(p for p in cat["dns_providers"] if p["id"] == "cloudflare")
    assert {f["key"] for f in cf["fields"] if f["secret"]} == {"api_token", "api_key", "email"}
    r53 = next(p for p in cat["dns_providers"] if p["id"] == "route53")
    req = {f["key"] for f in r53["fields"] if f["required"]}
    assert req == {"access_key_id", "secret_access_key"}
    assert {"hosted_zone_id", "role_arn"} <= {f["key"] for f in r53["fields"] if not f["secret"]}
    zs = next(p for p in cat["ca_presets"] if p["id"] == "zerossl")
    assert zs == {"id": "zerossl", "label": "ZeroSSL", "eab": True, "needs_directory_url": False, "staging": False}
    assert next(p for p in cat["ca_presets"] if p["id"] == "digicert")["needs_directory_url"] is True
    slack = next(t for t in cat["notifier_types"] if t["id"] == "slack")
    assert next(f for f in slack["fields"] if f["key"] == "url")["secret"] is True
    assert [t["id"] for t in cat["alert_rule_types"]] == ["event", "expiring", "health", "zombie", "unreachable"]
