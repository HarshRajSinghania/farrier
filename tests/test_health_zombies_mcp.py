"""Domain health, zombie certificates, deployment verification and the MCP server."""
from __future__ import annotations

import io
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from conftest import TLSServer, issue_initial
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from farrier import health, zombie
from farrier.api import create_app
from farrier.mcp_server import MCPServer, Session, run_stdio, validate
from farrier.x509util import parse_pem

NOW = datetime.now(timezone.utc)


def _endpoint(engine, port, name="app", sni="app.internal.test", **kw):
    eid = engine.store.upsert_endpoint({"name": name, "host": "127.0.0.1", "port": port, "sni": sni,
                                        "common_name": sni, "sans": [sni] if sni else [], "connector": "manual",
                                        "connector_config": {}, **kw})
    return engine.store.endpoint(eid)


def _cert(subject, issuer_name, issuer_key, pub, *, ca=False, days=30, sans=(), algo=None, start=None):
    start = start or NOW - timedelta(hours=1)
    b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
         .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)]))
         .public_key(pub).serial_number(x509.random_serial_number())
         .not_valid_before(start).not_valid_after(start + timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
    return b.sign(issuer_key, algo or hashes.SHA256())


def _pem(*certs):
    return "".join(c.public_bytes(serialization.Encoding.PEM).decode() for c in certs)


@pytest.fixture
def three_level(tmp_path, engine):
    """Local CA root -> intermediate -> leaf; returns (root, inter, leaf, leaf_key_pem, dir)."""
    ca = engine.issuers["default"]
    ikey = ec.generate_private_key(ec.SECP256R1())
    inter = _cert("Farrier Test Intermediate", ca.cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
                  ca.key, ikey.public_key(), ca=True, days=365)
    lkey = ec.generate_private_key(ec.SECP256R1())
    leaf = _cert("shop.internal.test", "Farrier Test Intermediate", ikey, lkey.public_key(), days=60,
                 sans=["shop.internal.test", "*.shop.internal.test"])
    d = tmp_path / "three"
    d.mkdir()
    (d / "key.pem").write_text(lkey.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                  serialization.NoEncryption()).decode())
    return ca.cert, inter, leaf, d


# ---- health -------------------------------------------------------------------------------------
def test_health_report_for_endpoint(engine, served, monkeypatch):
    monkeypatch.delenv("FARRIER_API_TOKEN", raising=False)
    monkeypatch.delenv("FARRIER_API_READ_TOKEN", raising=False)
    srv, _ = served
    ep = _endpoint(engine, srv.port)
    engine.observe(ep)
    c = TestClient(create_app(engine))
    r = c.get(f"/api/endpoints/{ep['id']}/health")
    assert r.status_code == 200
    rep = r.json()
    checks = {x["id"]: x for x in rep["checks"]}
    assert set(checks) == {"connect", "chain", "hostname", "expiry", "lifetime", "key", "signature", "tls_versions",
                           "ocsp_stapling", "caa", "deployed_match"}
    for cid in ("connect", "chain", "hostname", "lifetime", "key", "signature", "tls_versions", "caa",
                "deployed_match"):
        assert checks[cid]["status"] == "pass", checks[cid]
    assert checks["tls_versions"]["offered"]["TLSv1.0"] is False and checks["tls_versions"]["offered"]["TLSv1.2"]
    assert checks["chain"]["path"] == ["app.internal.test", "Farrier Local CA"]
    assert "not a public DNS name" in checks["caa"]["detail"]
    assert rep["grade"] in ("A", "B") and rep["certificate"]["fingerprint"] == ep_fp(engine, ep)

    m = c.get("/metrics").text
    assert "# TYPE farrier_health_check_failed gauge" in m
    assert 'farrier_health_check_failed{endpoint="app",check="chain"} 0' in m

    # any target, in discovery syntax; an inventory match gets the deployed check
    r = c.post("/api/health", json={"targets": f"app.internal.test@127.0.0.1:{srv.port}"})
    assert r.status_code == 200 and r.json()["reports"][0]["endpoint_id"] == ep["id"]
    assert c.post("/api/health", json={"targets": "not a host!"}).status_code == 400
    assert c.post("/api/health", json={"targets": "10.0.0.0/24"}).status_code == 400  # too many for health
    assert c.get("/api/endpoints/9999/health").status_code == 404


def ep_fp(engine, ep):
    return engine.store.latest_cert_observation(ep["id"])["fingerprint"]


def test_health_flags_incomplete_chain_order_and_names(engine, three_level):
    root, inter, leaf, d = three_level
    (d / "leaf-only.pem").write_text(_pem(leaf))
    (d / "misordered.pem").write_text(_pem(leaf, root, inter))
    anchors = [root]
    s1 = TLSServer(d / "leaf-only.pem", d / "key.pem")
    s2 = TLSServer(d / "misordered.pem", d / "key.pem")
    try:
        rep = health.check("127.0.0.1", s1.port, "shop.internal.test", anchors=anchors, caa=False)
        chain = next(c for c in rep["checks"] if c["id"] == "chain")
        assert chain["status"] == "fail" and chain["missing"] == "Farrier Test Intermediate"
        assert rep["grade"] == "F"

        rep = health.check("127.0.0.1", s2.port, "api.shop.internal.test", ["shop.internal.test", "other.test"],
                           anchors=anchors, caa=False)
        checks = {c["id"]: c for c in rep["checks"]}
        assert checks["chain"]["status"] == "warn" and not checks["chain"]["ordered"] and checks["chain"]["trusted"]
        assert checks["hostname"]["status"] == "fail" and checks["hostname"]["missing"] == ["other.test"]

        # without the private root the chain is complete but untrusted
        rep = health.check("127.0.0.1", s2.port, "shop.internal.test", anchors=[], caa=False)
        chain = next(c for c in rep["checks"] if c["id"] == "chain")
        assert chain["status"] == "fail" and "not in the trust store" in chain["detail"]
    finally:
        s1.close()
        s2.close()


def test_health_unit_checks():
    k = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    weak = _cert("old.example.com", "old.example.com", k, k.public_key(), days=800, start=NOW - timedelta(days=900))
    assert health.key_check(weak)["status"] == "fail"
    ica = _cert("Some CA", "Root", k, k.public_key(), ca=True)
    leaf = _cert("x.example.com", "Some CA", k, k.public_key())
    assert health.signature_check([leaf, ica])["status"] == "pass"

    class Sha1Signed:  # cryptography no longer signs with SHA-1, so present a real cert as if it were
        subject, issuer, signature_algorithm_oid = leaf.subject, leaf.issuer, leaf.signature_algorithm_oid
        signature_hash_algorithm = hashes.SHA1()

    assert health.signature_check([Sha1Signed(), ica])["status"] == "fail"
    assert health.expiry_check(weak, NOW)["status"] == "fail"
    assert health.lifetime_check(weak, NOW)["status"] == "warn"  # 800 days > 398 in force at issuance
    assert health.hostname_check(weak, ["old.example.com"])["status"] == "fail"  # no SAN at all
    assert health.name_matches("*.example.com", "a.example.com")
    assert not health.name_matches("*.example.com", "a.b.example.com")
    assert not health.name_matches("*.example.com", "example.com")
    assert health.grade([{"status": "pass"}, {"status": "warn"}]) == "B"
    assert health.caa_check("intranet.corp", None)["status"] == "pass"


def test_verify_deployment_fingerprint_chain_names_and_every_vip(engine, served, tmp_path):
    srv, d = served
    fullchain = (d / "fullchain.pem").read_text()
    fp = parse_pem(fullchain).fingerprint
    ca_pem = engine.issuers["default"].ca_pem
    v = health.verify_deployment("127.0.0.1", srv.port, "app.internal.test", fp, ["app.internal.test"],
                                 trust_pems=ca_pem)
    assert v["ok"] and v["fingerprint_ok"] and v["chain_ok"] and v["hostname_ok"] and v["problems"] == []

    v = health.verify_deployment("127.0.0.1", srv.port, "app.internal.test", "00" * 32, ["app.internal.test"],
                                 trust_pems=ca_pem)
    assert not v["ok"] and not v["fingerprint_ok"] and v["problems"]

    # the right cert but a name it does not carry
    v = health.verify_deployment("127.0.0.1", srv.port, "app.internal.test", fp, ["app.internal.test", "www.other.test"],
                                 trust_pems=ca_pem)
    assert not v["ok"] and v["fingerprint_ok"] and not v["hostname_ok"]

    # private root not trusted -> chain not ok
    v = health.verify_deployment("127.0.0.1", srv.port, "app.internal.test", fp, ["app.internal.test"])
    assert not v["chain_ok"] and not v["ok"]

    # a second VIP still serving the old certificate
    other = tmp_path / "vip2"
    other.mkdir()
    key, chain = issue_initial(engine.issuers["default"], "app.internal.test", days=9)
    (other / "k.pem").write_text(key)
    (other / "c.pem").write_text(chain)
    s2 = TLSServer(other / "c.pem", other / "k.pem")
    try:
        v = health.verify_deployment("127.0.0.1", srv.port, "app.internal.test", fp, ["app.internal.test"],
                                     addresses=[f"127.0.0.1:{s2.port}"], trust_pems=ca_pem)
        assert not v["ok"] and not v["fingerprint_ok"]
        assert {p["address"] for p in v["probes"] if not p["ok"]} == {f"127.0.0.1:{s2.port}"}
    finally:
        s2.close()


# ---- zombies ------------------------------------------------------------------------------------
def _obs(S, eid, at, fp=None, issuer=None, not_after=None, error=None, cn="x"):
    S.x("""INSERT INTO observations(endpoint_id, observed_at, fingerprint, subject_cn, sans, issuer, not_before,
           not_after, key_type, error) VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (eid, at.isoformat(timespec="seconds"), fp, cn if fp else None, "[]" if fp else None, issuer,
         (at - timedelta(days=30)).isoformat() if fp else None, not_after.isoformat() if not_after else None,
         "EC-secp256r1" if fp else None, error))


def _renewal(S, eid, state, prev, new, updated, cert_pem=None, deadline=None):
    t = updated.isoformat(timespec="seconds")
    return S.x("""INSERT INTO renewals(endpoint_id, state, reason, scheduled_for, deadline, prev_fingerprint,
                  new_fingerprint, cert_pem, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)""",
               (eid, state, "test", t, deadline, prev, new, cert_pem, t, t))


def test_zombies_from_stored_observations(engine, monkeypatch):
    S = engine.store
    ca = engine.issuers["default"]
    _key, fullchain = issue_initial(ca, "pay.internal.test", days=30)
    farrier_pem = fullchain
    mk = lambda name, **kw: S.upsert_endpoint({"name": name, "host": f"{name}.internal.test", "port": 443,
                                               "common_name": f"{name}.internal.test", "connector": "manual",
                                               "connector_config": {}, **kw})
    expired, dead, node1, node2, swapped, waiting, found = (mk(n) for n in (
        "expired", "dead", "node1", "node2", "swapped", "waiting", "found"))
    S.upsert_endpoint({"name": "found", "tags": ["discovered"]})

    _obs(S, expired, NOW - timedelta(hours=1), "e" * 64, "Farrier Local CA", NOW - timedelta(days=3))
    _obs(S, dead, NOW - timedelta(days=20), "d" * 64, "Farrier Local CA", NOW + timedelta(days=50))
    for days in (12, 6, 0):
        _obs(S, dead, NOW - timedelta(days=days, minutes=1), error="ConnectionRefusedError: refused")
    # node1 was renewed and verified; node2 (same service, another node) still serves the old cert
    _renewal(S, node1, "done", "a" * 64, "b" * 64, NOW - timedelta(days=2), farrier_pem)
    _obs(S, node1, NOW - timedelta(minutes=5), "b" * 64, "Farrier Local CA", NOW + timedelta(days=30))
    _obs(S, node2, NOW - timedelta(minutes=5), "a" * 64, "Farrier Local CA", NOW + timedelta(days=5))
    # swapped: Farrier deployed, then someone installed a cert from another CA
    _renewal(S, swapped, "done", "c" * 64, "f" * 64, NOW - timedelta(days=3), farrier_pem)
    _obs(S, swapped, NOW - timedelta(minutes=1), "9" * 64, "Other Public CA", NOW + timedelta(days=90))
    # a change pack nobody installed
    rid = _renewal(S, waiting, "awaiting_manual", "1" * 64, "2" * 64, NOW - timedelta(days=5))
    _obs(S, found, NOW, "3" * 64, "Somebody CA", NOW + timedelta(days=200))

    out = zombie.summarize(zombie.from_store(S))
    kinds = {(f["kind"], f["endpoint"]) for f in out["findings"]}
    assert ("expired_served", "expired") in kinds
    assert ("dead_endpoint", "dead") in kinds
    assert ("stale_duplicate", "node2") in kinds
    assert ("unexpected_issuer", "swapped") in kinds
    assert ("pack_never_installed", "waiting") in kinds
    assert ("discovered_unowned", "found") in kinds
    assert not any(f["endpoint"] == "node1" for f in out["findings"])
    pack = next(f for f in out["findings"] if f["kind"] == "pack_never_installed")
    assert pack["evidence"]["renewal_id"] == rid and pack["action"]
    assert all({"kind", "severity", "endpoint", "target", "evidence", "action"} <= f.keys() for f in out["findings"])
    assert zombie.from_store(S, dead_days=30) and not any(
        f["kind"] == "dead_endpoint" for f in zombie.from_store(S, dead_days=30))

    # active scan: an unknown endpoint, and a cert for a managed name from another CA
    cert = SimpleNamespace(fingerprint="7" * 64, subject_cn="pay.internal.test", sans=["pay.internal.test"],
                           issuer="Rogue CA", not_after=NOW + timedelta(days=30))
    S.upsert_endpoint({"name": "node1", "sans": ["pay.internal.test"]})
    res = [SimpleNamespace(host="10.9.9.9", port=443, sni=None, cert=cert, error=None),
           SimpleNamespace(host="10.9.9.8", port=443, sni=None, cert=None, error="timeout")]
    scan_kinds = {f["kind"] for f in zombie.from_scan(S, res)}
    assert scan_kinds == {"not_in_inventory", "unexpected_issuer"}

    # API
    monkeypatch.setenv("FARRIER_API_TOKEN", "admin-token")
    monkeypatch.setenv("FARRIER_API_READ_TOKEN", "read-token")
    c = TestClient(create_app(engine))
    r = c.get("/api/zombies", headers={"Authorization": "Bearer read-token"})
    assert r.status_code == 200 and r.json()["by_kind"]["stale_duplicate"] == 1
    assert c.post("/api/zombies/scan", json={"targets": "127.0.0.1:1"},
                  headers={"Authorization": "Bearer read-token"}).status_code == 403
    r = c.post("/api/zombies/scan", json={"targets": "127.0.0.1:1"}, headers={"Authorization": "Bearer admin-token"})
    assert r.status_code == 200 and r.json()["scanned"] == 1


# ---- MCP over Streamable HTTP --------------------------------------------------------------------
ADMIN, READ = "admin-token-123", "read-token-456"


def _mcp(c, token, body, sid=None, **headers):
    h = {"Authorization": f"Bearer {token}", "Accept": "application/json, text/event-stream",
         "MCP-Protocol-Version": "2025-06-18", **headers}
    if sid:
        h["Mcp-Session-Id"] = sid
    return c.post("/mcp", json=body, headers=h)


def _init(c, token, version="2025-06-18", name="test-client"):
    r = c.post("/mcp", headers={"Authorization": f"Bearer {token}", "Accept": "application/json, text/event-stream"},
               json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
                     "params": {"protocolVersion": version, "capabilities": {},
                                "clientInfo": {"name": name, "version": "1.0"}}})
    assert r.status_code == 200, r.text
    sid = r.headers["mcp-session-id"]
    assert _mcp(c, token, {"jsonrpc": "2.0", "method": "notifications/initialized"}, sid).status_code == 202
    return sid, r.json()["result"]


def _tools(c, token, sid):
    return {t["name"]: t for t in _mcp(c, token, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, sid)
            .json()["result"]["tools"]}


def _call(c, token, sid, name, args, rid=3):
    return _mcp(c, token, {"jsonrpc": "2.0", "id": rid, "method": "tools/call",
                           "params": {"name": name, "arguments": args}}, sid).json()


@pytest.fixture
def mcp_client(engine, served, monkeypatch):
    monkeypatch.setenv("FARRIER_API_TOKEN", ADMIN)
    monkeypatch.setenv("FARRIER_API_READ_TOKEN", READ)
    monkeypatch.delenv("FARRIER_MCP_ALLOW_WRITES", raising=False)
    monkeypatch.setenv("SHOULD_NOT_LEAK", "s3cret-value-xyz")
    srv, _ = served
    ep = _endpoint(engine, srv.port, connector_config={"password": "env:SHOULD_NOT_LEAK"})
    engine.observe(ep)
    return TestClient(create_app(engine)), ep


def test_mcp_http_read_token(mcp_client, engine):
    c, ep = mcp_client
    assert c.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"}).status_code == 401
    assert c.post("/mcp", json={}, headers={"Authorization": "Bearer nope"}).status_code == 401
    r = c.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
               headers={"Authorization": f"Bearer {READ}", "Origin": "http://evil.example"})
    assert r.status_code == 403

    sid, init = _init(c, READ)
    assert init["protocolVersion"] == "2025-06-18" and init["capabilities"]["tools"] == {"listChanged": False}
    assert init["serverInfo"]["name"] == "farrier"

    tools = _tools(c, READ, sid)
    assert set(tools) == {"list_endpoints", "get_endpoint", "expiring_certificates", "renewal_status",
                          "domain_health", "find_zombies", "forecast"}
    assert tools["list_endpoints"]["annotations"]["readOnlyHint"] is True
    assert tools["domain_health"]["annotations"]["openWorldHint"] is True
    assert "x-oneRequired" not in tools["domain_health"]["inputSchema"]

    out = _call(c, READ, sid, "list_endpoints", {})
    assert out["result"]["isError"] is False
    data = out["result"]["structuredContent"]
    assert data["total"] == 1 and data["endpoints"][0]["name"] == "app"
    assert json.loads(out["result"]["content"][0]["text"]) == data
    blob = json.dumps(out) + json.dumps(_call(c, READ, sid, "get_endpoint", {"id": ep["id"]}))
    assert "connector_config" not in blob and "SHOULD_NOT_LEAK" not in blob and "s3cret-value-xyz" not in blob and "key_sealed" not in blob

    exp = _call(c, READ, sid, "expiring_certificates", {"days": 30})["result"]["structuredContent"]
    assert exp["count"] == 1 and exp["certificates"][0]["days_left"] < 10
    assert "counts" in _call(c, READ, sid, "renewal_status", {})["result"]["structuredContent"]
    assert "findings" in _call(c, READ, sid, "find_zombies", {})["result"]["structuredContent"]
    fc = _call(c, READ, sid, "forecast", {"certs": 500, "manual": 0.3})["result"]["structuredContent"]
    assert fc["timeline"][-1]["lifetime_days"] == 47
    h = _call(c, READ, sid, "domain_health", {"endpoint_id": ep["id"], "caa": False})["result"]["structuredContent"]
    assert h["endpoint_id"] == ep["id"] and h["grade"]

    # validation and unknown/forbidden tools are protocol errors
    bad = _call(c, READ, sid, "forecast", {"certs": "many", "manual": 3})
    assert bad["error"]["code"] == -32602 and "certs" in bad["error"]["message"]
    assert _call(c, READ, sid, "list_endpoints", {"bogus": 1})["error"]["code"] == -32602
    assert _call(c, READ, sid, "domain_health", {})["error"]["code"] == -32602
    refused = _call(c, READ, sid, "domain_health", {"target": "example.com"})
    assert "endpoint_id" in json.dumps(refused)  # read tokens cannot probe arbitrary hosts
    assert _call(c, READ, sid, "renew_endpoint", {"id": ep["id"]})["error"]["code"] == -32602
    assert _call(c, READ, sid, "nope", {})["error"]["code"] == -32602
    nf = _call(c, READ, sid, "get_endpoint", {"id": 999})
    assert nf["result"]["isError"] is True
    assert _mcp(c, READ, {"jsonrpc": "2.0", "id": 9, "method": "resources/list"}, sid).json()["error"]["code"] == -32601
    assert _mcp(c, READ, {"jsonrpc": "2.0", "id": 9, "method": "ping"}, sid).json()["result"] == {}

    # every call is in the event log, attributed to the client
    msgs = [e["message"] for e in engine.store.q("SELECT message FROM events")]
    assert any("mcp:test-client called MCP tool list_endpoints" in m for m in msgs)

    # session rules
    assert _mcp(c, READ, {"jsonrpc": "2.0", "id": 1, "method": "ping"}).status_code == 400
    assert _mcp(c, READ, {"jsonrpc": "2.0", "id": 1, "method": "ping"}, "unknown").status_code == 404
    assert _mcp(c, ADMIN, {"jsonrpc": "2.0", "id": 1, "method": "ping"}, sid).status_code == 403
    assert _mcp(c, READ, {"jsonrpc": "2.0", "id": 1, "method": "ping"}, sid,
                **{"MCP-Protocol-Version": "1999-01-01"}).status_code == 400
    assert c.get("/mcp", headers={"Authorization": f"Bearer {READ}"}).status_code == 405
    assert c.delete("/mcp", headers={"Authorization": f"Bearer {READ}", "Mcp-Session-Id": sid}).status_code == 204
    assert _mcp(c, READ, {"jsonrpc": "2.0", "id": 1, "method": "ping"}, sid).status_code == 404


def test_mcp_http_writes_need_admin_and_flag(mcp_client, engine, monkeypatch):
    c, ep = mcp_client
    sid, _ = _init(c, ADMIN, name="claude-code")
    assert "renew_endpoint" not in _tools(c, ADMIN, sid)  # admin alone is not enough

    monkeypatch.setenv("FARRIER_MCP_ALLOW_WRITES", "1")
    tools = _tools(c, ADMIN, sid)
    assert tools["renew_endpoint"]["annotations"]["destructiveHint"] is True
    assert tools["cancel_renewal"]["annotations"]["readOnlyHint"] is False
    rsid, _ = _init(c, READ)
    assert "renew_endpoint" not in _tools(c, READ, rsid)  # flag alone is not enough either

    out = _call(c, ADMIN, sid, "renew_endpoint", {"id": ep["id"]})["result"]
    assert out["isError"] is False and out["structuredContent"]["state"] == "awaiting_manual"
    rid = out["structuredContent"]["renewal_id"]
    assert "mcp:claude-code" in engine.store.renewal(rid)["reason"]
    out = _call(c, ADMIN, sid, "cancel_renewal", {"id": rid})["result"]
    assert out["structuredContent"]["state"] == "cancelled"
    again = _call(c, ADMIN, sid, "cancel_renewal", {"id": rid})["result"]
    assert again["isError"] is True
    msgs = [e["message"] for e in engine.store.q("SELECT message FROM events")]
    assert any("cancelled by mcp:claude-code" in m for m in msgs)


def test_mcp_version_negotiation(mcp_client):
    c, _ = mcp_client
    assert _init(c, READ, "2025-03-26")[1]["protocolVersion"] == "2025-03-26"
    assert _init(c, READ, "2024-11-05")[1]["protocolVersion"] == "2024-11-05"
    assert _init(c, READ, "2099-01-01")[1]["protocolVersion"] == "2025-06-18"


def test_mcp_without_configured_tokens_is_refused(engine, monkeypatch):
    monkeypatch.delenv("FARRIER_API_TOKEN", raising=False)
    monkeypatch.delenv("FARRIER_API_READ_TOKEN", raising=False)
    c = TestClient(create_app(engine))
    r = c.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert r.status_code == 401


# ---- stdio ----------------------------------------------------------------------------------------
def test_mcp_stdio_framing(engine, monkeypatch):
    monkeypatch.delenv("FARRIER_MCP_ALLOW_WRITES", raising=False)
    lines = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "gemini-cli"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": "x", "method": "tools/call",
         "params": {"name": "list_endpoints", "arguments": {"filter": "line\nbreak é"}}},
    ]
    raw = b"".join(json.dumps(m).encode() + b"\n" for m in lines) + b"\n" + b"{not json\n"
    out = io.BytesIO()
    run_stdio(engine, io.BytesIO(raw), out, role="admin")
    text = out.getvalue().decode()
    assert text.endswith("\n")
    replies = [json.loads(line) for line in text.splitlines()]
    assert [r.get("id") for r in replies] == [1, 2, "x", None]  # no reply to the notification
    assert replies[0]["result"]["protocolVersion"] == "2025-06-18"
    assert "renew_endpoint" not in {t["name"] for t in replies[1]["result"]["tools"]}
    assert replies[3]["error"]["code"] == -32700
    assert any("mcp:gemini-cli" in e["message"] for e in engine.store.q("SELECT message FROM events"))

    # text streams work too
    out = io.StringIO()
    run_stdio(engine, io.StringIO(json.dumps({"jsonrpc": "2.0", "id": 5, "method": "ping"}) + "\n"), out, role="read")
    assert json.loads(out.getvalue()) == {"jsonrpc": "2.0", "id": 5, "result": {}}


def test_schema_validator_and_session_rate_limit(engine):
    schema = {"type": "object", "properties": {"n": {"type": "integer", "minimum": 1}}, "required": ["n"],
              "additionalProperties": False}
    assert validate(schema, {"n": 2}) == []
    assert validate(schema, {"n": True})
    assert validate(schema, {}) and validate(schema, {"n": 0}) and validate(schema, {"n": 1, "m": 2})
    srv = MCPServer(engine, rate_per_minute=2)
    s = Session("read")
    call = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "forecast",
                                                                         "arguments": {"certs": 1, "manual": 0}}}
    assert srv.handle(call, s)["result"]["isError"] is False
    assert srv.handle(call, s)["result"]["isError"] is False
    assert srv.handle(call, s)["result"]["isError"] is True  # third call within a minute
