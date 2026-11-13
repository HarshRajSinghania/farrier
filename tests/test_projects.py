"""Teams and projects: the migration, the signed scope header, and scope filtering on every route."""
from __future__ import annotations

import io
import time
import zipfile

import pytest
from fastapi.testclient import TestClient

from farrier.api import scope as scope_mod
from farrier.api.app import create_app
from farrier.api.mcp import MCPServer, Session, project_scope
from farrier.crypto import repository
from farrier.db import migrations as db_migrations
from farrier.db.store import Store
from farrier.demo import start
from farrier.monitoring.alerts import matches, validate_rule
from farrier.monitoring.notify import Notifier
from farrier.ssh import db as ssh_db

ADMIN_TOKEN, READ_TOKEN = "admin-token", "read-token"


# ---- the signature (shared test vector with web/src/lib/auth/auth.test.mjs) -----------------------------
def test_signature_vector_matches_the_dashboard():
    assert scope_mod.sign("tok", "GET", "/api/endpoints", "1,2", 1700000000) == (
        "v1;1,2;1700000000;1df0998b35e23e80b2a464350261f2f7ab5ce1f2ddfe9ddbe44774ae358520b2")


def test_parse_rejects_forgery_expiry_and_other_routes():
    now = 1_800_000_000
    good = scope_mod.sign("tok", "GET", "/api/endpoints", "2", now)
    assert scope_mod.parse(good, "tok", "GET", "/api/endpoints", now=now).ids == frozenset({2})
    assert scope_mod.parse(scope_mod.sign("tok", "GET", "/x", "*", now), "tok", "GET", "/x", now=now).all
    assert scope_mod.parse(scope_mod.sign("tok", "GET", "/x", "", now), "tok", "GET", "/x", now=now).ids == frozenset()
    v, ids, ts, sig = good.split(";")
    bad = [
        f"{v};2,3;{ts};{sig}",                                         # another project added
        f"{v};*;{ts};{sig}",                                           # widened to everything
        f"{v};{ids};{int(ts) + 1};{sig}",                              # re-dated
        scope_mod.sign("other-token", "GET", "/api/endpoints", "2", now),  # not this install's key
        "v2;2;1;" + "0" * 64, "garbage", "", f"{v};2;{ts}",
    ]
    for b in bad:
        with pytest.raises(scope_mod.ScopeError):
            scope_mod.parse(b, "tok", "GET", "/api/endpoints", now=now)
    with pytest.raises(scope_mod.ScopeError, match="expired"):
        scope_mod.parse(good, "tok", "GET", "/api/endpoints", now=now + scope_mod.MAX_AGE + 1)
    with pytest.raises(scope_mod.ScopeError):                          # minted for a read, replayed on a change
        scope_mod.parse(good, "tok", "POST", "/api/endpoints", now=now)
    with pytest.raises(scope_mod.ScopeError):
        scope_mod.parse(good, "tok", "GET", "/api/renewals", now=now)
    with pytest.raises(scope_mod.ScopeError):                          # no token on the engine: cannot verify
        scope_mod.parse(good, None, "GET", "/api/endpoints", now=now)


# ---- migration ----------------------------------------------------------------------------------------
def test_migration_8_backfills_the_default_project(tmp_path, monkeypatch):
    monkeypatch.setattr(db_migrations, "MIGRATIONS", db_migrations.MIGRATIONS[:7])
    s = Store(tmp_path)
    assert s.schema_version() == 7
    s.x("INSERT INTO endpoints(name, host, created_at) VALUES ('old', 'h', '2026-01-01')")
    s.x("INSERT INTO ssh_hosts(host, port, data, observed_at) VALUES ('h', 22, '{}', '2026-01-01')")
    s.x("INSERT INTO ssh_keys(uid, host, port, access, username, path, line_sha256, data, fingerprint, first_seen, "
        "last_seen) VALUES ('u', 'h', 22, 'p', 'root', '/k', 'x', '{}', 'f', 'a', 'b')")
    s.x("INSERT INTO crypto_assets(kind, target, host, port, status, result, observed_at, created_at) "
        "VALUES ('tls', 'h:443', 'h', 443, 'unknown', '{}', 'a', 'b')")
    s.close()
    monkeypatch.undo()
    s = Store(tmp_path)
    assert s.migrated[0] == 8                      # then any later migrations
    d = s.project("default")
    assert d and d["id"] == s.default_project_id() == 1
    for t in ("endpoints", "ssh_hosts", "ssh_keys", "crypto_assets"):
        assert {r["project_id"] for r in s.q(f"SELECT project_id FROM {t}")} == {d["id"]}, t
    assert s.endpoints()[0]["project"] == "default"
    eid = s.upsert_endpoint({"name": "new", "host": "h2"})
    assert s.endpoint(eid)["project_id"] == d["id"]


def test_copy_keeps_projects(tmp_path):
    src = Store(tmp_path / "a")
    src.x("INSERT INTO projects(name, title, members, created_at) VALUES ('pay', 'Payments', '{}', 'x')")
    pid = src.project("pay")["id"]
    src.upsert_endpoint({"name": "e", "host": "h", "project_id": pid})
    dst = Store(tmp_path / "b")
    src.copy_to(dst)
    assert [p["name"] for p in dst.projects()] == ["default", "pay"]
    assert dst.endpoints()[0]["project"] == "pay"


# ---- the API ------------------------------------------------------------------------------------------
@pytest.fixture
def estate(tmp_path, monkeypatch):
    """The demo estate split into projects a and b, with SSH and crypto rows in each."""
    monkeypatch.setenv("FARRIER_API_TOKEN", ADMIN_TOKEN)
    monkeypatch.setenv("FARRIER_API_READ_TOKEN", READ_TOKEN)
    eng, srv = start(tmp_path / "demo")
    eng.settings["crypto_scan_hours"] = 0
    eng.settings["verify_retry_seconds"] = 0.05
    c = TestClient(create_app(eng))
    admin = {"authorization": f"Bearer {ADMIN_TOKEN}"}
    c.post("/api/tick", headers=admin)
    for name, title in (("a", "Team A"), ("b", "Team B")):
        assert c.put(f"/api/projects/{name}", json={"title": title, "members": {"groups": [f"team-{name}"]}},
                     headers=admin).status_code == 200
    S = eng.store
    pid = {p["name"]: p["id"] for p in S.projects()}
    eps = S.endpoints()
    waiting = {r["endpoint_id"] for r in S.renewals(("awaiting_manual",))}
    assert len(waiting) >= 2
    w = sorted(waiting)
    a_ids = {w[0]} | {e["id"] for e in eps[: len(eps) // 2]} - {w[1]}
    for e in eps:
        p = "a" if e["id"] in a_ids else "b"
        assert c.post(f"/api/endpoints/{e['id']}/move", json={"project": p}, headers=admin).status_code == 200
    for p in ("a", "b"):
        repository.save_result(S, {"target": f"{p}-only:443", "host": f"{p}-only", "port": 443, "sni": None,
                                   "error": "refused"}, pid[p])
        ssh_db.save_host(S, f"{p}-ssh", 22, "SSH-2.0-OpenSSH_9.6", {"host_keys": [], "findings": []}, False, None,
                         pid[p])
        ssh_db.sync_host_keys(S, f"{p}-ssh", 22, "prof", [{
            "username": "root", "path": "/root/.ssh/authorized_keys", "line_sha256": p * 8, "fingerprint": f"SHA256:{p}",
            "data": {"type": "ssh-ed25519", "bits": 256, "findings": []}}], project_id=pid[p])
    yield eng, c, pid, a_ids
    srv._stop.set()


def call(c, method, path, ids, token=ADMIN_TOKEN, ts=None, **kw):
    url = path
    path = path.split("?")[0]
    h = {"authorization": f"Bearer {token}",
         "x-farrier-scope": scope_mod.sign(ADMIN_TOKEN, method, path, ids, ts)}
    return c.request(method, url, headers=h, **kw)


def test_a_viewer_in_a_never_sees_b(estate):
    eng, c, pid, a_ids = estate
    S = eng.store
    a = str(pid["a"])
    b_ids = {e["id"] for e in S.endpoints()} - a_ids
    a_names = {e["name"] for e in S.endpoints() if e["id"] in a_ids}

    def get(path):
        r = call(c, "GET", path, a, token=READ_TOKEN)
        assert r.status_code == 200, (path, r.text)
        return r

    eps = get("/api/endpoints").json()
    assert {e["id"] for e in eps} == a_ids and {e["project"] for e in eps} == {"a"}
    assert get("/api/summary").json()["endpoints"] == len(a_ids)
    ren = get("/api/renewals").json()
    assert ren and {r["endpoint_id"] for r in ren} <= a_ids
    ev = get("/api/events?limit=1000").json()
    assert ev and all(e["endpoint_id"] in a_ids for e in ev)
    assert get(f"/api/events?endpoint_id={min(b_ids)}").json() == []
    csv = get("/api/inventory?format=csv").text
    assert all(n in csv for n in a_names) and not any(e["name"] in csv for e in S.endpoints() if e["id"] in b_ids)
    assert {f["endpoint_id"] for f in get("/api/zombies").json()["findings"]} <= a_ids
    assets = get("/api/crypto/assets").json()
    targets = {x["target"] for x in assets}
    assert "a-only:443" in targets and "b-only:443" not in targets
    assert {x["endpoint_id"] for x in assets if x["endpoint_id"]} <= a_ids
    assert get("/api/crypto/summary").json()["total"] == len(assets)
    assert "b-only" not in get("/api/crypto/cbom").text
    assert [h["host"] for h in get("/api/ssh/hosts").json()] == ["a-ssh"]
    assert [k["host"] for k in get("/api/ssh/keys").json()] == ["a-ssh"]
    assert get("/api/ssh/summary").json()["keys"] == 1
    for path in (f"/api/endpoints/{min(b_ids)}/certificate", f"/api/endpoints/{min(b_ids)}/health",
                 "/api/projects/b"):
        assert call(c, "GET", path, a, token=READ_TOKEN).status_code == 404, path
    assert get("/api/projects/a").json()["title"] == "Team A"
    # no header: the read token keeps reading everything, as before
    assert len(c.get("/api/endpoints", headers={"authorization": f"Bearer {READ_TOKEN}"}).json()) == len(S.endpoints())


def test_packs_and_runbooks_follow_the_endpoint(estate):
    eng, c, pid, a_ids = estate
    waiting = eng.store.renewals(("awaiting_manual",))
    ra = next(r for r in waiting if r["endpoint_id"] in a_ids)
    rb = next(r for r in waiting if r["endpoint_id"] not in a_ids)
    a = str(pid["a"])
    r = call(c, "GET", f"/api/renewals/{ra['id']}/pack", a)
    assert r.status_code == 200 and "key.pem" in zipfile.ZipFile(io.BytesIO(r.content)).namelist()
    assert call(c, "GET", f"/api/renewals/{rb['id']}/pack", a).status_code == 404
    assert call(c, "GET", f"/api/renewals/{rb['id']}/runbook", a).status_code == 404
    assert call(c, "GET", f"/api/renewals/{ra['id']}/runbook", a).status_code == 200


def test_writes_outside_scope_are_refused(estate):
    eng, c, pid, a_ids = estate
    S = eng.store
    a = str(pid["a"])
    b_ep = next(e for e in S.endpoints() if e["id"] not in a_ids)
    rb = next(r for r in S.renewals(("awaiting_manual",)) if r["endpoint_id"] not in a_ids)
    b_key = next(k for k in ssh_db.keys(S) if k["host"] == "b-ssh")
    b_host = next(h for h in ssh_db.hosts(S) if h["host"] == "b-ssh")
    for method, path, body in [
        ("POST", f"/api/endpoints/{b_ep['id']}/renew", None),
        ("POST", f"/api/endpoints/{b_ep['id']}/approve", None),
        ("DELETE", f"/api/endpoints/{b_ep['id']}", None),
        ("POST", f"/api/renewals/{rb['id']}/advance", None),
        ("POST", f"/api/renewals/{rb['id']}/cancel", None),
        ("POST", f"/api/ssh/keys/{b_key['id']}/remove", {"dry_run": True}),
        ("POST", f"/api/ssh/hosts/{b_host['id']}/trust", {}),
        ("POST", "/api/discover", {"targets": "127.0.0.1:1", "project": "b"}),
        ("POST", "/api/crypto/scan", {"targets": "127.0.0.1:1", "project": "b"}),
        ("POST", "/api/ssh/scan", {"targets": "127.0.0.1:1", "project": "b"}),
        # install-wide changes need a global admin, whatever the project role
        ("POST", "/api/tick", None),
        ("POST", "/api/endpoints", {"name": "x", "host": "h", "project": "a"}),
        ("PUT", "/api/issuers/x", {"type": "local_ca"}),
        ("PUT", "/api/config/settings", {}),
        ("PUT", "/api/alert-rules/x", {}),
        ("POST", "/api/notifiers/test", None),
        ("PUT", "/api/projects/a", {"title": "mine now"}),
        ("POST", f"/api/endpoints/{min(a_ids)}/move", {"project": "b"}),
        ("GET", "/api/projects", None),
    ]:
        r = call(c, method, path, a, json=body)
        assert r.status_code == 403, (method, path, r.status_code, r.text)
    assert S.endpoint(b_ep["id"]) and S.renewal(rb["id"])["state"] == "awaiting_manual"
    # inside the scope the same calls work
    a_ep = next(e for e in S.endpoints() if e["id"] in a_ids)
    assert call(c, "POST", f"/api/endpoints/{a_ep['id']}/approve", a).status_code == 200
    r = call(c, "POST", "/api/discover", a, json={"targets": "127.0.0.1:1"})   # the only project: lands in a
    assert r.status_code == 200, r.text
    two = f"{pid['a']},{pid['b']}"
    assert call(c, "POST", "/api/discover", two, json={"targets": "127.0.0.1:1"}).status_code == 400  # choose one


def test_forged_expired_and_replayed_headers_are_refused(estate):
    eng, c, pid, a_ids = estate
    a, b = str(pid["a"]), str(pid["b"])
    admin = {"authorization": f"Bearer {ADMIN_TOKEN}"}
    good = scope_mod.sign(ADMIN_TOKEN, "GET", "/api/endpoints", a)
    v, ids, ts, sig = good.split(";")
    for forged in (f"{v};{b};{ts};{sig}", f"{v};*;{ts};{sig}", f"{v};{a},{b};{ts};{sig}",
                   scope_mod.sign(READ_TOKEN, "GET", "/api/endpoints", b),          # signed with the wrong token
                   scope_mod.sign(ADMIN_TOKEN, "GET", "/api/endpoints", b, int(time.time()) - 600)):   # expired
        r = c.get("/api/endpoints", headers=admin | {"x-farrier-scope": forged})
        assert r.status_code == 401, forged
    # a header minted for project b's read can't be replayed on another route
    b_ep = next(e for e in eng.store.endpoints() if e["id"] not in a_ids)
    replay = scope_mod.sign(ADMIN_TOKEN, "GET", "/api/endpoints", b)
    assert c.post(f"/api/endpoints/{b_ep['id']}/renew", headers=admin | {"x-farrier-scope": replay}).status_code == 401
    assert c.get("/api/endpoints", headers=admin | {"x-farrier-scope": good}).status_code == 200
    # the admin token without a header is the CLI/automation: everything
    assert len(c.get("/api/endpoints", headers=admin).json()) == len(eng.store.endpoints())


def test_projects_api(estate):
    eng, c, pid, a_ids = estate
    admin = {"authorization": f"Bearer {ADMIN_TOKEN}"}
    rows = {p["name"]: p for p in c.get("/api/projects", headers=admin).json()}
    assert set(rows) == {"default", "a", "b"} and rows["a"]["endpoints"] == len(a_ids)
    assert rows["a"]["members"]["groups"] == ["team-a"]
    assert c.put("/api/projects/Bad_Name", json={}, headers=admin).status_code == 400
    assert c.put("/api/projects/c", json={"members": {"admin": "x"}}, headers=admin).status_code == 400
    assert c.put("/api/projects/c", json={"members": {"admin": ["pki-c"]}}, headers=admin).json()["title"] == "c"
    assert c.delete("/api/projects/a", headers=admin).status_code == 409          # still has endpoints
    assert c.delete("/api/projects/default", headers=admin).status_code == 409
    assert c.delete("/api/projects/c", headers=admin).status_code == 200
    assert c.post(f"/api/endpoints/{min(a_ids)}/move", json={"project": "nope"}, headers=admin).status_code == 404
    # star scope (a global admin in the dashboard) is full access
    assert call(c, "GET", "/api/projects", "*").status_code == 200


# ---- alerts, channels, MCP ----------------------------------------------------------------------------
def test_alert_rule_and_channel_project_filters(estate):
    eng, c, pid, a_ids = estate
    admin = {"authorization": f"Bearer {ADMIN_TOKEN}"}
    rule = validate_rule({"enabled": True, "when": {"type": "expiring", "days": 30}, "filter": {"project": "a"},
                          "channels": ["ops"]}, {"ops"})
    assert rule["filter"] == {"project": "a"}
    assert matches(rule["filter"], {"project": "a", "name": "x"})
    assert not matches(rule["filter"], {"project": "b", "name": "x"})
    assert not matches({"project": "a"}, None)
    assert matches({}, {"project": "b"})
    body = {"enabled": True, "when": {"type": "expiring", "days": 30}, "filter": {"project": "zzz"},
            "channels": ["ops"]}
    c.put("/api/secrets/hook", json={"value": "https://hooks.example/x"}, headers=admin)
    assert c.put("/api/notifiers/ops", json={"type": "webhook", "url": "vault:hook", "project": "zzz"},
                 headers=admin).status_code == 400
    assert c.put("/api/notifiers/ops", json={"type": "webhook", "url": "vault:hook", "project": "a"},
                 headers=admin).json()["project"] == "a"
    assert c.put("/api/alert-rules/r", json=body, headers=admin).status_code == 400
    assert c.put("/api/alert-rules/r", json=body | {"filter": {"project": "a"}}, headers=admin).status_code == 200

    sent = []
    n = Notifier([{"name": "team-a", "type": "webhook", "url": "https://x", "project": "a"},
                  {"name": "all", "type": "webhook", "url": "https://y"}], None, lambda *a, **k: None)
    n._dispatch = lambda targets, p, wait: sent.append(sorted(t["name"] for t in targets)) or {}
    n.send("failed", {"id": 1}, {"name": "e", "project": "b"})
    n.send("failed", {"id": 2}, {"name": "e", "project": "a"})
    n.send("test")
    n.send_to(["team-a", "all"], {"event": "alert", "project": "b"})
    assert sent == [["all"], ["all", "team-a"], ["all", "team-a"], ["all"]]


def test_mcp_project_limit(estate, monkeypatch):
    eng, c, pid, a_ids = estate
    monkeypatch.setenv("FARRIER_MCP_PROJECT", "a")
    monkeypatch.setenv("FARRIER_MCP_ALLOW_WRITES", "1")
    server = MCPServer(eng)
    s = Session("admin")
    s.scope = project_scope(eng.store)

    def tool(name, args):
        r = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                           "params": {"name": name, "arguments": args}}, s)["result"]
        return r["structuredContent"], r["isError"]

    out, _ = tool("list_endpoints", {"limit": 2000})
    assert {e["id"] for e in out["endpoints"]} == a_ids
    b_ep = next(e for e in eng.store.endpoints() if e["id"] not in a_ids)
    assert tool("get_endpoint", {"id": b_ep["id"]})[1] is True
    assert tool("renew_endpoint", {"id": b_ep["id"]})[1] is True
    assert {r["endpoint_id"] for r in tool("renewal_status", {"state": "awaiting_manual"})[0]["renewals"]} <= a_ids
    assert tool("domain_health", {"target": "example.com"})[1] is True
    monkeypatch.setenv("FARRIER_MCP_PROJECT", "nope")
    assert project_scope(eng.store).ids == frozenset()
    monkeypatch.delenv("FARRIER_MCP_PROJECT")
    assert project_scope(eng.store).all
