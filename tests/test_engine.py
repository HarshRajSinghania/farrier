"""End-to-end: real TLS listener, real issuance from the local CA, real file deploys."""
from datetime import timedelta

from farrier.discovery import fetch_cert, scan
from farrier.x509util import parse_pem


def _endpoint(engine, port, connector, cfg, **kw):
    return engine.store.upsert_endpoint({
        "name": kw.pop("name", "app1"), "host": "127.0.0.1", "port": port, "sni": "app.internal.test",
        "connector": connector, "connector_config": cfg, **kw})


def _due_now(engine, eid):
    obs = engine.store.latest_cert_observation(eid)
    from farrier.db import parse_dt
    return parse_dt(obs["not_after"]) - timedelta(days=3)


def test_discovery_registers_unknown_endpoint(engine, served):
    s, _ = served
    res = scan([("127.0.0.1", s.port, "app.internal.test")])
    assert res[0].cert.subject_cn == "app.internal.test"
    out = engine.register_scan(res)
    assert out == {"new": 1, "seen": 1}
    ep = engine.store.endpoints()[0]
    assert ep["connector"] == "manual" and ep["subject_cn"] == "app.internal.test"


def test_automated_renewal_files_connector(engine, served):
    s, srv = served
    old_fp = fetch_cert("127.0.0.1", s.port, "app.internal.test").fingerprint
    eid = _endpoint(engine, s.port, "files",
                    {"cert_path": str(srv / "fullchain.pem"), "key_path": str(srv / "key.pem")})
    engine.observe(engine.store.endpoint(eid))
    now = _due_now(engine, eid)
    # make cert_path hold the full chain (the server reads one file)
    engine.store.upsert_endpoint({"name": "app1", "connector_config": {
        "fullchain_path": str(srv / "fullchain.pem"), "cert_path": str(srv / "leaf.pem"),
        "key_path": str(srv / "key.pem")}})

    result = engine.tick(now=now)
    assert result["planned"] == 1
    assert result["states"] == {"done": 1}

    live = fetch_cert("127.0.0.1", s.port, "app.internal.test")
    assert live.fingerprint != old_fp
    r = engine.store.renewals()[0]
    assert r["new_fingerprint"] == live.fingerprint
    assert live.lifetime_days in (200, 100, 47)                 # policy-capped lifetime
    assert (srv / "fullchain.pem.farrier-bak-1").exists()        # backup kept
    # private key is sealed at rest
    raw = engine.store.q1("SELECT key_sealed FROM renewals")["key_sealed"]
    assert "PRIVATE KEY" not in raw

    # next tick: nothing new to plan (fresh cert is far from due)
    assert engine.tick(now=now)["planned"] == 0


def test_rollback_when_cert_never_goes_live(engine, served, tmp_path):
    s, srv = served
    engine.settings["verify_max_attempts"] = 1
    wrong = tmp_path / "elsewhere"
    eid = _endpoint(engine, s.port, "files",
                    {"cert_path": str(wrong / "c.pem"), "key_path": str(wrong / "k.pem")})
    engine.observe(engine.store.endpoint(eid))
    engine.tick(now=_due_now(engine, eid))
    r = engine.store.renewals()[0]
    assert r["state"] == "rolled_back"
    assert "never went live" in r["error"]
    assert not (wrong / "c.pem").exists()   # nothing existed before, rollback left no stale file? (backup None)


def test_manual_renewal_closes_itself_when_seen_live(engine, served):
    s, srv = served
    eid = _endpoint(engine, s.port, "manual", {"runbook": "cisco-asa"}, name="vpn-asa-01")
    engine.observe(engine.store.endpoint(eid))
    now = _due_now(engine, eid)
    assert engine.tick(now=now)["states"] == {"awaiting_manual": 1}

    r = engine.store.renewals()[0]
    pack = engine.data_dir / "packs" / str(r["id"])
    assert (pack / "bundle.pfx").exists()
    runbook = (pack / "RUNBOOK.md").read_text()
    assert "ssl trust-point" in runbook and r["new_fingerprint"] in runbook

    # still waiting: nothing changed on the box
    assert engine.tick(now=now)["states"] == {"awaiting_manual": 1}

    # operator installs it
    (srv / "fullchain.pem").write_text((pack / "fullchain.pem").read_text())
    (srv / "key.pem").write_text((pack / "key.pem").read_text())
    assert engine.tick(now=now)["states"] == {"done": 1}
    assert not pack.exists()                 # key material cleaned up
    assert parse_pem((srv / "fullchain.pem").read_text()).fingerprint == r["new_fingerprint"]


def test_keystore_connector(engine, served, tmp_path):
    from cryptography.hazmat.primitives.serialization import pkcs12

    from farrier.connectors import Bundle, make_connector

    ca = engine.issuers["default"]
    from conftest import issue_initial
    key, full = issue_initial(ca, "kafka.internal.test", 30)
    from farrier.x509util import split_pem_chain
    certs = split_pem_chain(full)
    path = tmp_path / "ks" / "server.p12"
    conn = make_connector("keystore", {"path": str(path), "password": "changeit", "alias": "kafka"}, tmp_path)
    tok = conn.deploy(Bundle("kafka", 7, key, certs[0], "".join(certs[1:]), "2027-01-01"))
    loaded = pkcs12.load_pkcs12(path.read_bytes(), b"changeit")
    assert loaded.cert.friendly_name == b"kafka"
    assert len(loaded.additional_certs) == 1
    assert tok["backup"] is None

    legacy = make_connector("keystore", {"path": str(path), "password": "changeit", "format": "pkcs12-legacy"},
                            tmp_path)
    tok2 = legacy.deploy(Bundle("kafka", 8, key, certs[0], "".join(certs[1:]), "2027-01-01"))
    assert tok2["backup"] and pkcs12.load_pkcs12(path.read_bytes(), b"changeit").key is not None


def test_cancelled_manual_renewal_deletes_change_pack(engine, served):
    s, _ = served
    eid = _endpoint(engine, s.port, "manual", {"runbook": "cisco-asa"}, name="vpn-asa-02")
    engine.observe(engine.store.endpoint(eid))
    assert engine.tick(now=_due_now(engine, eid))["states"] == {"awaiting_manual": 1}
    r = engine.store.renewals()[0]
    pack = engine.data_dir / "packs" / str(r["id"])
    assert (pack / "key.pem").exists()

    engine.cancel(r["id"])
    assert engine.store.renewal(r["id"])["state"] == "cancelled"
    assert not pack.exists()                 # plaintext key gone with the renewal


def test_sweep_removes_orphaned_packs(engine):
    orphan = engine.data_dir / "packs" / "999"
    orphan.mkdir(parents=True)
    (orphan / "key.pem").write_text("secret")
    assert engine.sweep_packs() == 1
    assert not orphan.exists()


def test_tick_scans_endpoints_concurrently(engine):
    import time
    for i in range(6):   # unroutable TEST-NET addresses: each handshake waits for the timeout
        engine.store.upsert_endpoint({"name": f"dead{i}", "host": "192.0.2.1", "port": 443 + i, "connector": "manual"})
    engine.settings["scan_timeout"] = 1.0
    t = time.monotonic()
    engine.tick()
    assert time.monotonic() - t < 4          # serial would be >= 6s
    assert all(e["scan_error"] for e in engine.store.endpoints())
