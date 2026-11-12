"""Certificate details, agentless cryptographic discovery and PQC readiness."""
from __future__ import annotations

import socket
import ssl
import struct
import threading
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from farrier.api.app import create_app
from farrier.crypto import repository
from farrier.crypto import tls_wire as W
from farrier.crypto.analysis import classify, summarize, weak_flags
from farrier.crypto.cbom import build_cbom
from farrier.crypto.probe import pqc_outcome, probe_tls
from farrier.crypto.service import rescan_due
from farrier.db import migrations as db_migrations
from farrier.db.store import Store


# ---- crafted server bytes -------------------------------------------------------------------------
def _record(rtype: int, payload: bytes) -> bytes:
    return struct.pack(">BHH", rtype, W.TLS12, len(payload)) + payload


def server_hello(*, suite: int = 0x1301, version: int | None = W.TLS13, group: int | None = None,
                 share_len: int = 32, hrr: bool = False, legacy: int = W.TLS12) -> bytes:
    exts = b""
    if version is not None and version >= W.TLS13:
        exts += struct.pack(">HHH", W.EXT_SUPPORTED_VERSIONS, 2, version)
    if group is not None:
        data = struct.pack(">H", group) if hrr else struct.pack(">HH", group, share_len) + b"\x00" * share_len
        exts += struct.pack(">HH", W.EXT_KEY_SHARE, len(data)) + data
    sid = b"\x11" * 32
    body = (struct.pack(">H", legacy) + (W.HRR_RANDOM if hrr else b"\x22" * 32) + bytes([len(sid)]) + sid
            + struct.pack(">H", suite) + b"\x00" + struct.pack(">H", len(exts)) + exts)
    return _record(W.REC_HANDSHAKE, b"\x02" + len(body).to_bytes(3, "big") + body)


def alert(desc: int) -> bytes:
    return _record(W.REC_ALERT, bytes([2, desc]))


# ---- ClientHello ---------------------------------------------------------------------------------
def _hello_exts(rec: bytes) -> dict[int, bytes]:
    assert rec[0] == W.REC_HANDSHAKE and rec[5] == 1                     # handshake record, ClientHello
    body = rec[9:]
    i = 2 + 32
    i += 1 + body[i]                                                      # session id
    i += 2 + struct.unpack(">H", body[i:i + 2])[0]                        # suites
    i += 1 + body[i]                                                      # compression
    end, i = i + 2 + struct.unpack(">H", body[i:i + 2])[0], i + 2
    exts = {}
    while i < end:
        t, n = struct.unpack(">HH", body[i:i + 4])
        exts[t] = body[i + 4:i + 4 + n]
        i += 4 + n
    return exts


def test_pqc_client_hello_offers_only_x25519mlkem768_with_a_valid_share():
    rec = W.client_hello(version=W.TLS13, sni="a.example", groups=[W.X25519MLKEM768], key_shares=[W.X25519MLKEM768])
    assert struct.unpack(">H", rec[3:5])[0] == len(rec) - 5
    exts = _hello_exts(rec)
    assert exts[W.EXT_GROUPS] == struct.pack(">HH", 2, 0x11EC)
    assert exts[W.EXT_SUPPORTED_VERSIONS] == b"\x02\x03\x04"
    ks = exts[W.EXT_KEY_SHARE]
    group, n = struct.unpack(">HH", ks[2:6])
    assert group == 0x11EC and n == 1184 + 32 and len(ks) == 2 + 4 + n
    ek = ks[6:6 + 1152]                                                   # ML-KEM-768 t-hat, 12-bit packed
    coeffs = [c for j in range(0, 1152, 3)
              for c in (ek[j] | (ek[j + 1] & 0x0F) << 8, ek[j + 1] >> 4 | ek[j + 2] << 4)]
    assert len(coeffs) == 768 and max(coeffs) < 3329                      # passes the FIPS 203 modulus check
    assert b"a.example" in exts[W.EXT_SNI]


def test_legacy_hello_has_no_supported_versions():
    exts = _hello_exts(W.client_hello(version=W.TLS10, sni=None))
    assert W.EXT_SUPPORTED_VERSIONS not in exts and W.EXT_KEY_SHARE not in exts and W.EXT_SNI not in exts
    with pytest.raises(ValueError):
        W.client_hello(version=W.TLS13, sni=None, groups=[W.X25519], key_shares=[W.X25519MLKEM768])


# ---- ServerHello / HRR / alert parsing -----------------------------------------------------------
def test_server_selects_x25519mlkem768():
    reply = W.parse_flight(server_hello(group=W.X25519MLKEM768, share_len=1120))
    assert (reply.kind, reply.version, reply.group, reply.key_share_length) == ("server_hello", W.TLS13, 0x11EC, 1120)
    assert pqc_outcome(reply) == {"outcome": "selected", "selected": True, "detail": "key share of 1120 bytes"}


def test_hello_retry_request_is_not_pqc():
    reply = W.parse_flight(server_hello(group=W.X25519, hrr=True))
    assert reply.kind == "hello_retry" and reply.group == W.X25519 and reply.version == W.TLS13
    out = pqc_outcome(reply)
    assert out["outcome"] == "hello_retry" and not out["selected"] and "x25519" in out["detail"]


def test_alert_is_not_pqc():
    reply = W.parse_flight(alert(40))
    assert reply.kind == "alert" and reply.alert == 40 and reply.detail == "handshake_failure"
    assert pqc_outcome(reply) == {"outcome": "alert", "selected": False, "detail": "handshake_failure"}


def test_tls12_server_hello_and_incremental_feed():
    data = _record(W.REC_CCS, b"\x01") + server_hello(suite=0xC02F, version=None, legacy=W.TLS12)
    reader = W.FlightReader()
    replies = [reader.feed(data[i:i + 7]) for i in range(0, len(data), 7)]
    reply = next(r for r in replies if r)
    assert reply.version == W.TLS12 and W.suite_name(reply.cipher_suite) == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    assert pqc_outcome(reply)["outcome"] == "not_selected"


def test_garbage_and_truncation():
    assert W.parse_flight(b"HTTP/1.1 400 Bad Request\r\n\r\n").kind == "unexpected"
    assert W.parse_flight(server_hello()[:20]) is None                   # needs more bytes
    bad = bytearray(server_hello(group=W.X25519))
    bad[5 + 4 + 2 + 32 + 1 + 32 + 3:5 + 4 + 2 + 32 + 1 + 32 + 5] = b"\xff\xff"   # extensions length past the end
    assert W.parse_flight(bytes(bad)).kind == "unexpected"


# ---- classification ---------------------------------------------------------------------------------
def _result(versions=("TLSv1.2", "TLSv1.3"), pqc=False, sig_oid="1.2.840.10045.4.3.2", key=None,
            suites=None, sha1=False, not_after=None, error=None, tls13_group="x25519"):
    suites = suites or {}
    return {"kind": "tls", "target": "h:443", "host": "h", "port": 443, "sni": None, "error": error,
            "versions": {v: {"accepted": v in versions, "cipher": suites.get(v)} for v in
                         ("TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3")},
            "tls13_group": tls13_group if "TLSv1.3" in versions else None, "weak_cipher": None,
            "pqc": {"group": "X25519MLKEM768", "selected": pqc},
            "certificate": {"key": key or {"algorithm": "EC", "size": 256, "curve": "secp256r1"},
                            "signature_algorithm": "x", "signature_oid": sig_oid, "sha1_signed": sha1,
                            "not_after": not_after or (datetime.now(UTC) + timedelta(days=30)).isoformat(),
                            "fingerprint": "ab" * 32}}


@pytest.mark.parametrize("result, status, reason", [
    (_result(pqc=True, sig_oid="2.16.840.1.101.3.4.3.18"), "ready", "post-quantum certificate signature (x)"),
    (_result(pqc=True, sig_oid="1.3.6.1.5.5.7.6.41"), "ready", "post-quantum certificate signature (x)"),
    (_result(pqc=True), "hybrid", "X25519MLKEM768 key exchange accepted"),
    (_result(), "vulnerable", "x25519 key exchange only"),
    (_result(versions=("TLSv1.0", "TLSv1.2"), suites={"TLSv1.2": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
             key={"algorithm": "RSA", "size": 2048, "curve": None}), "vulnerable", "RSA-2048 certificate"),
    (_result(versions=("TLSv1.0", "TLSv1.2")), "vulnerable", "TLS 1.0 accepted"),
    (_result(error="ConnectionRefusedError: refused"), "unknown", "probe failed: ConnectionRefusedError: refused"),
    (_result(versions=()), "unknown", "no TLS version could be negotiated"),
    (None, "unknown", "not scanned"),
])
def test_pqc_classification(result, status, reason):
    out = classify(result)
    assert out["status"] == status and reason in out["reasons"], out


def test_weak_flags():
    r = _result(versions=("TLSv1.0", "TLSv1.1", "TLSv1.2"), key={"algorithm": "RSA", "size": 1024, "curve": None},
                sha1=True, not_after="2020-01-01T00:00:00+00:00",
                suites={"TLSv1.0": "TLS_RSA_WITH_AES_128_CBC_SHA", "TLSv1.2": "TLS_RSA_WITH_3DES_EDE_CBC_SHA"})
    r["weak_cipher"] = "TLS_RSA_WITH_RC4_128_SHA"
    assert weak_flags(r) == ["tls10", "tls11", "rsa_lt_2048", "sha1", "cbc", "3des", "rc4", "expired"]
    s = summarize([{"pqc": classify(r), "cert_key": {"algorithm": "RSA"}, "weak": weak_flags(r)},
                   {"pqc": {"status": "hybrid"}, "cert_key": None, "weak": []}])
    assert s == {"total": 2, "by_status": {"ready": 0, "hybrid": 1, "vulnerable": 1, "unknown": 0},
                 "by_key_algorithm": {"RSA": 1, "unknown": 1},
                 "weak": {"tls10": 1, "tls11": 1, "rsa_lt_2048": 1, "sha1": 1}}


# ---- live probes against in-process servers -----------------------------------------------------
class _CtxServer:
    """Like conftest.TLSServer, with a configurable server context (e.g. TLS 1.2 only)."""

    def __init__(self, ctx: ssl.SSLContext):
        self.ctx, self.sock = ctx, socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self.t = threading.Thread(target=self._loop, daemon=True)
        self.t.start()

    def _loop(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            try:
                conn.settimeout(2)
                with self.ctx.wrap_socket(conn, server_side=True):
                    pass
            except Exception:  # noqa: BLE001
                conn.close()

    def close(self):
        self._stop.set()
        self.t.join(timeout=2)
        self.sock.close()


def test_probe_modern_server(served):
    s, _ = served
    r = probe_tls("127.0.0.1", s.port, "app.internal.test", timeout=3)
    assert r["error"] is None
    assert {v: i["accepted"] for v, i in r["versions"].items()} == {
        "TLSv1.0": False, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True}
    assert r["versions"]["TLSv1.3"]["cipher"].startswith("TLS_AES_") or "CHACHA20" in r["versions"]["TLSv1.3"]["cipher"]
    assert "ECDHE_ECDSA" in r["versions"]["TLSv1.2"]["cipher"]           # EC certificate -> ECDSA suite
    assert r["tls13_group"] == "x25519"
    assert r["pqc"]["outcome"] in ("alert", "hello_retry", "selected")   # OpenSSL < 3.5 has no ML-KEM
    assert r["certificate"]["key"] == {"algorithm": "EC", "size": 256, "curve": "secp256r1"}
    assert r["certificate"]["signature_algorithm"].startswith("ecdsa-with-")
    expected = "hybrid" if r["pqc"]["selected"] else "vulnerable"
    assert classify(r)["status"] == expected


def test_probe_tls12_only_server(served):
    _, srv = served
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(srv / "fullchain.pem", srv / "key.pem")
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    s = _CtxServer(ctx)
    try:
        r = probe_tls("127.0.0.1", s.port, None, timeout=3)
    finally:
        s.close()
    assert [v for v, i in r["versions"].items() if i["accepted"]] == ["TLSv1.2"]
    assert r["tls13_group"] is None and not r["pqc"]["selected"]
    out = classify(r)
    assert out["status"] == "vulnerable" and "TLS 1.3 not supported (no post-quantum key exchange possible)" in out["reasons"]


def test_probe_unreachable_target():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]                                         # bound, not listening
    r = probe_tls("127.0.0.1", port, None, timeout=1)
    assert r["error"] and classify(r)["status"] == "unknown"


# ---- API ------------------------------------------------------------------------------------------
@pytest.fixture
def client(engine, monkeypatch):
    monkeypatch.delenv("FARRIER_API_TOKEN", raising=False)
    monkeypatch.delenv("FARRIER_API_READ_TOKEN", raising=False)
    return TestClient(create_app(engine))


def test_crypto_scan_assets_summary_cbom(client, served):
    s, _ = served
    out = client.post("/api/crypto/scan", json={"targets": f"app.internal.test@127.0.0.1:{s.port}"}).json()
    assert out["scanned"] == 1 and out["stored"] == 1 and out["total"] == 1
    assert out["by_status"]["vulnerable"] + out["by_status"]["hybrid"] == 1

    assets = client.get("/api/crypto/assets").json()
    a = assets[0]
    assert set(a) >= {"id", "kind", "endpoint_id", "target", "protocol_versions", "cipher_suites", "key_exchange",
                      "pqc_key_exchange", "cert_key", "signature_algorithm", "pqc", "weak", "observed_at"}
    assert a["kind"] == "tls" and a["endpoint_id"] is None and a["target"] == f"app.internal.test@127.0.0.1:{s.port}"
    assert a["protocol_versions"] == ["TLSv1.2", "TLSv1.3"] and a["cert_key"] == {"algorithm": "EC", "size": 256}

    summary = client.get("/api/crypto/summary").json()
    assert summary["total"] == 1 and summary["by_key_algorithm"] == {"EC": 1}
    assert set(summary["weak"]) == {"tls10", "tls11", "rsa_lt_2048", "sha1"}

    # a re-scan keeps one asset and adds history
    client.post("/api/crypto/scan", json={"targets": f"app.internal.test@127.0.0.1:{s.port}"})
    assert len(client.get("/api/crypto/assets").json()) == 1

    bom = client.get("/api/crypto/cbom").json()
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.6" and bom["serialNumber"].startswith("urn:uuid:")
    kinds = {c["cryptoProperties"]["assetType"] for c in bom["components"]}
    assert {"protocol", "algorithm", "certificate", "related-crypto-material"} <= kinds
    assert all(c["type"] == "cryptographic-asset" and c["bom-ref"] for c in bom["components"])
    assert len({c["bom-ref"] for c in bom["components"]}) == len(bom["components"])
    tls13 = next(c for c in bom["components"] if c["cryptoProperties"]["assetType"] == "protocol"
                 and c["cryptoProperties"]["protocolProperties"]["version"] == "1.3")
    pp = tls13["cryptoProperties"]["protocolProperties"]
    assert pp["type"] == "tls" and pp["cipherSuites"][0]["identifiers"][0] == "0x13"
    refs = {c["bom-ref"] for c in bom["components"]}
    assert set(pp["cryptoRefArray"]) <= refs
    cert = next(c for c in bom["components"] if c["cryptoProperties"]["assetType"] == "certificate")
    assert cert["cryptoProperties"]["certificateProperties"]["signatureAlgorithmRef"] in refs


def test_crypto_scan_validation_and_auth(engine, monkeypatch):
    monkeypatch.setenv("FARRIER_API_TOKEN", "admin")
    monkeypatch.setenv("FARRIER_API_READ_TOKEN", "reader")
    c = TestClient(create_app(engine))
    ro, rw = {"Authorization": "Bearer reader"}, {"Authorization": "Bearer admin"}
    assert c.get("/api/crypto/summary", headers=ro).status_code == 200
    assert c.get("/api/crypto/cbom", headers=ro).status_code == 200
    assert c.get("/api/crypto/assets").status_code == 401
    assert c.post("/api/crypto/scan", json={"targets": "127.0.0.1:1"}, headers=ro).status_code == 403
    assert c.post("/api/crypto/scan", json={"targets": "not a host!"}, headers=rw).status_code == 400
    assert c.post("/api/crypto/scan", json={"targets": "10.0.0.0/8"}, headers=rw).status_code == 400
    assert c.post("/api/crypto/scan", json={"targets": "10.0.0.0/19:443|8443"}, headers=rw).status_code == 400
    assert c.post("/api/crypto/scan", json={"targets": ""}, headers=rw).status_code == 400


def test_ssh_assets_join_summary_and_cbom(client, monkeypatch):
    import farrier.ssh as ssh_pkg
    fake = {"id": 9, "endpoint_id": None, "target": "10.0.0.5:22", "protocol_versions": ["2.0"], "cipher_suites": {},
            "key_exchange": "mlkem768x25519-sha256", "pqc_key_exchange": True, "cert_key": {"algorithm": "Ed25519", "size": 256},
            "signature_algorithm": "ssh-ed25519", "pqc": {"status": "hybrid", "reasons": []}, "weak": [], "observed_at": "x"}
    monkeypatch.setattr(ssh_pkg, "ssh_crypto_assets", lambda store: [fake], raising=False)
    s = client.get("/api/crypto/summary").json()
    assert s["total"] == 1 and s["by_status"]["hybrid"] == 1 and s["by_key_algorithm"] == {"Ed25519": 1}
    bom = client.get("/api/crypto/cbom").json()
    assert any(c["cryptoProperties"].get("protocolProperties", {}).get("type") == "ssh" for c in bom["components"])
    monkeypatch.setattr(ssh_pkg, "ssh_crypto_assets", lambda store: 1 / 0, raising=False)
    assert client.get("/api/crypto/summary").json()["total"] == 0           # an SSH failure never breaks the report


def test_endpoint_certificate_details(client, engine, served):
    s, srv = served
    S = engine.store
    eid = S.upsert_endpoint({"name": "app", "host": "127.0.0.1", "port": s.port, "sni": "app.internal.test",
                             "common_name": "app.internal.test", "sans": ["app.internal.test"]})
    engine.observe(S.endpoint(eid))
    S.x("INSERT INTO health_results(endpoint_id, grade, checked_at) VALUES (?,?,?)", (eid, "B", "2026-01-01T00:00:00+00:00"))
    rid = engine.force_renewal(eid, "test")

    d = client.get(f"/api/endpoints/{eid}/certificate").json()
    assert d["endpoint_id"] == eid and d["common_name"] == "app.internal.test" and d["sans"] == ["app.internal.test"]
    assert d["subject"] == "CN=app.internal.test" and d["issuer"] == "CN=Farrier Local CA" and d["serial"]
    assert d["key"] == {"algorithm": "EC", "size": 256, "curve": "secp256r1"}
    assert d["signature_algorithm"].startswith("ecdsa-with-") and d["self_signed"] is False
    assert len(d["fingerprints"]["sha256"]) == 64 and len(d["fingerprints"]["sha1"]) == 40
    assert d["chain"] and d["chain"][0]["subject"] == "CN=Farrier Local CA" and d["chain"][0]["key"]["algorithm"]
    assert 8 <= d["days_left"] <= 9 and d["observed_at"]
    assert d["health"] == {"grade": "B", "checked_at": "2026-01-01T00:00:00+00:00"}
    assert [r["id"] for r in d["renewals"]] == [rid] and set(d["renewals"][0]) == {
        "id", "state", "reason", "scheduled_for", "updated_at"}

    # a new certificate is served: two distinct entries in history, newest first, repeats collapsed
    from conftest import issue_initial
    key, chain = issue_initial(engine.issuers["default"], "app.internal.test", days=30)
    (srv / "key.pem").write_text(key)
    (srv / "fullchain.pem").write_text(chain)
    S.x("UPDATE observations SET observed_at='2000-01-01T00:00:00+00:00' WHERE endpoint_id=?", (eid,))
    engine.observe(S.endpoint(eid))
    engine.observe(S.endpoint(eid))
    d2 = client.get(f"/api/endpoints/{eid}/certificate").json()
    assert len(d2["history"]) == 2 and d2["history"][0]["fingerprint_sha256"] == d2["fingerprints"]["sha256"]
    assert d2["history"][1]["fingerprint_sha256"] == d["fingerprints"]["sha256"]
    assert d2["days_left"] > 25

    assert client.get("/api/endpoints/999999/certificate").status_code == 404


def test_certificate_details_without_stored_pem(client, engine):
    """Observations from before migration 5 have no PEM: the route still answers, with nulls."""
    S = engine.store
    eid = S.upsert_endpoint({"name": "old", "host": "old.example", "port": 443})
    S.x("""INSERT INTO observations(endpoint_id, observed_at, fingerprint, subject_cn, sans, issuer, not_before,
           not_after, key_type) VALUES (?,?,?,?,?,?,?,?,?)""",
        (eid, "2026-01-01T00:00:00+00:00", "cd" * 32, "old.example", '["old.example"]', "Old CA",
         "2026-01-01T00:00:00+00:00", "2099-01-01T00:00:00+00:00", "RSA-2048"))
    d = client.get(f"/api/endpoints/{eid}/certificate").json()
    assert d["common_name"] == "old.example" and d["issuer"] == "Old CA" and d["serial"] is None
    assert d["key"] == {"algorithm": "RSA", "size": 2048, "curve": None} and d["chain"] == []
    assert d["fingerprints"] == {"sha256": "cd" * 32, "sha1": None} and d["health"] is None
    assert len(d["history"]) == 1 and d["renewals"] == []


# ---- tick re-scan, storage, migration -------------------------------------------------------------
def test_tick_rescans_inventory_crypto_once_per_period(engine, served):
    s, _ = served
    S = engine.store
    eid = S.upsert_endpoint({"name": "app", "host": "127.0.0.1", "port": s.port, "sni": "app.internal.test",
                             "common_name": "app.internal.test", "sans": ["app.internal.test"]})
    S.upsert_endpoint({"name": "dead", "host": "127.0.0.1", "port": 1})   # never answers: never probed
    engine.observe_all()
    assert rescan_due(engine) == 1
    assert rescan_due(engine) == 0                                         # within crypto_scan_hours
    assets = repository.tls_assets(S)
    assert len(assets) == 1 and assets[0]["endpoint_id"] == eid
    S.x("UPDATE crypto_assets SET observed_at='2000-01-01T00:00:00+00:00'")
    assert rescan_due(engine) == 1
    assert S.q1("SELECT COUNT(*) AS n FROM crypto_scans")["n"] == 2
    engine.settings["crypto_scan_hours"] = 0
    S.x("UPDATE crypto_assets SET observed_at='2000-01-01T00:00:00+00:00'")
    assert rescan_due(engine) == 0


def test_migration_5_applied_once(tmp_path):
    s = Store(tmp_path)
    assert 5 in s.migrated and s.schema_version() == db_migrations.latest_version()
    for t in ("certificates", "crypto_assets", "crypto_scans"):
        assert s.q(f"SELECT * FROM {t}") == []
    s.close()
    s2 = Store(tmp_path)
    assert s2.migrated == [] and len(s2.q("SELECT * FROM schema_version WHERE version=5")) == 1


def test_build_cbom_from_raw_results():
    r = _result(pqc=True)
    r["certificate"] |= {"subject": "CN=h", "issuer": "CN=ca", "not_before": "2026-01-01T00:00:00+00:00"}
    r["versions"]["TLSv1.3"]["cipher"] = "TLS_AES_128_GCM_SHA256"
    from farrier.crypto.analysis import asset_view
    bom = build_cbom([asset_view(1, r, 7)], {1: r})
    algs = {c["name"]: c["cryptoProperties"]["algorithmProperties"] for c in bom["components"]
            if c["cryptoProperties"]["assetType"] == "algorithm"}
    assert algs["X25519MLKEM768"]["primitive"] == "kem" and algs["X25519MLKEM768"]["nistQuantumSecurityLevel"] == 3
    proto = [c for c in bom["components"] if c["cryptoProperties"]["assetType"] == "protocol"]
    assert {c["cryptoProperties"]["protocolProperties"]["version"] for c in proto} == {"1.2", "1.3"}
    props = {p["name"]: p["value"] for p in proto[0]["properties"]}
    assert props["farrier:pqc_status"] == "hybrid" and props["farrier:endpoint_id"] == "7"
