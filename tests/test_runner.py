"""Remote runners end to end: an endpoint behind a runner is observed, deployed, verified and rolled back
only through jobs, with a real TLS listener, the real API and the real runner loop."""
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from farrier.api.app import create_app
from farrier.core.discovery import fetch_cert
from farrier.db.store import parse_dt
from farrier.runner import run


@pytest.fixture
def api(engine, monkeypatch):
    monkeypatch.setenv("FARRIER_API_TOKEN", "admin-tok")
    return TestClient(create_app(engine))


def _endpoint(engine, port, srv, **cfg):
    eid = engine.store.upsert_endpoint({
        "name": "dmz-app", "host": "127.0.0.1", "port": port, "sni": "app.internal.test", "connector": "files",
        "connector_config": {"runner": "dmz", "cert_path": str(srv / "leaf.pem"), "key_path": str(srv / "key.pem"),
                             "fullchain_path": str(srv / "fullchain.pem"), **cfg}})
    return eid


def _runner(api, token):
    return run("http://testserver", token, once=True, http=api, log=lambda *a, **k: None)


def test_tokens_are_scoped_to_runner_routes(api, engine):
    assert api.post("/api/runners/dmz/token").status_code == 401                 # admin only
    tok = api.post("/api/runners/dmz/token", headers={"Authorization": "Bearer admin-tok"}).json()["token"]
    assert tok.startswith("frn.dmz.")
    h = {"Authorization": f"Bearer {tok}"}
    assert api.post("/api/runner/poll", json={}, headers=h).json() == {"group": "dmz", "jobs": []}
    assert api.get("/api/summary", headers=h).status_code == 401                  # opens nothing else
    assert api.post("/api/runner/poll", json={}, headers={"Authorization": "Bearer frn.dmz.wrong"}).status_code == 401
    other = engine.runners.enqueue("ot", "observe", {"targets": [], "timeout": 1})
    assert api.post(f"/api/runner/jobs/{other}", json={"ok": True}, headers=h).status_code == 409   # not its group
    assert engine.runners.groups()[0]["group"] == "dmz"


def test_renewal_through_a_runner(api, engine, served):
    s, srv = served
    tok = engine.runners.issue_token("dmz")
    eid = _endpoint(engine, s.port, srv)
    old = fetch_cert("127.0.0.1", s.port, "app.internal.test").fingerprint

    engine.tick(scan=True)                                   # the engine queues an observe job, contacts nothing
    assert engine.store.latest_cert_observation(eid) is None
    assert _runner(api, tok) == 1
    engine.tick(scan=False)                                  # stores the runner's observation
    obs = engine.store.latest_cert_observation(eid)
    assert obs["fingerprint"] == old

    now = parse_dt(obs["not_after"]) - timedelta(days=3)
    engine.tick(now=now, scan=False)                         # plans, issues, hands the deploy to the runner
    r = engine.store.renewal(engine.store.renewals()[0]["id"])
    assert r["state"] == "deploying" and "runner_job" in r["rollback"]
    job = engine.runners.job(r["rollback"]["runner_job"])
    assert "PRIVATE KEY" not in job["payload"]               # sealed at rest
    _runner(api, tok)                                        # deploys the files
    engine.tick(now=now, scan=False)                         # deploying -> verifying, queues a verify job
    _runner(api, tok)
    engine.tick(now=now, scan=False)
    r = engine.store.renewal(r["id"])
    assert r["state"] == "done", r
    assert fetch_cert("127.0.0.1", s.port, "app.internal.test").fingerprint == r["new_fingerprint"] != old
    assert engine.runners.job(job["id"])["status"] == "consumed"   # the key left the job table


def test_runner_rollback_when_the_new_cert_never_goes_live(api, engine, served):
    s, srv = served
    tok = engine.runners.issue_token("dmz")
    # the runner writes the files, but the listener serves a path nobody reloads: never live
    eid = _endpoint(engine, s.port, srv, fullchain_path=str(srv / "elsewhere.pem"), cert_path=str(srv / "leaf2.pem"),
                    key_path=str(srv / "key2.pem"))
    engine.settings["verify_max_attempts"] = 2
    engine.tick(scan=True)
    _runner(api, tok)
    engine.tick(scan=False)
    now = parse_dt(engine.store.latest_cert_observation(eid)["not_after"]) - timedelta(days=3)
    engine.tick(now=now, scan=False)
    for _ in range(6):                                       # deploy, verify, verify, rollback
        _runner(api, tok)
        engine.tick(now=now, scan=False)
    r = engine.store.renewals()[0]
    assert r["state"] == "rolled_back" and "rolled back by runner group dmz" in r["error"], r


def test_a_runner_lost_mid_deploy_leads_to_verification_not_a_second_deploy(engine, served, monkeypatch):
    s, srv = served
    engine.runners.issue_token("dmz")
    eid = _endpoint(engine, s.port, srv)
    obs_job = engine.runners.enqueue("dmz", "observe", {"targets": [], "timeout": 1})
    engine.runners.claim("dmz")
    engine.runners.complete("dmz", obs_job, True, {"observations": []})
    from farrier.core.discovery import fetch_cert as real
    engine.store.add_observation(eid, real("127.0.0.1", s.port, "app.internal.test"))
    now = parse_dt(engine.store.latest_cert_observation(eid)["not_after"]) - timedelta(days=3)
    engine.tick(now=now, scan=False)
    r = engine.store.renewal(engine.store.renewals()[0]["id"])
    jid = r["rollback"]["runner_job"]
    assert [j["id"] for j in engine.runners.claim("dmz")] == [jid]
    engine.store.x("UPDATE runner_jobs SET lease_until='2000-01-01T00:00:00+00:00' WHERE id=?", (jid,))
    assert engine.runners.claim("dmz") == []                 # a deploy is never handed out twice
    engine.tick(now=now, scan=False)
    r = engine.store.renewal(r["id"])
    assert r["state"] == "verifying" and r["rollback"] is None


def test_a_bad_or_foreign_runner_report_cannot_stop_ticks_or_speak_for_other_endpoints(api, engine, served):
    s, srv = served
    tok = engine.runners.issue_token("dmz")
    eid = _endpoint(engine, s.port, srv)
    local = engine.store.upsert_endpoint({"name": "local", "host": "127.0.0.1", "port": s.port,
                                          "sni": "other.test", "connector": "manual", "connector_config": {}})
    jid = engine.runners.enqueue("dmz", "observe", {"targets": [{"endpoint_id": eid, "host": "x", "port": 1}]})
    h = {"Authorization": f"Bearer {tok}"}
    assert api.post("/api/runner/poll", json={}, headers=h).json()["jobs"][0]["id"] == jid
    assert api.post(f"/api/runner/jobs/{jid}", headers=h, json={"ok": True, "result": {"observations": [
        {"endpoint_id": "not-a-number"}, {"no": "id"},
        {"endpoint_id": local, "error": "pretend"}]}}).status_code == 200
    engine.tick(scan=False)                                   # survives, and ignores the foreign endpoint
    assert engine.store.q("SELECT * FROM observations WHERE endpoint_id=?", (local,)) == []
    assert engine.runners.job(jid)["status"] == "consumed"


def test_cancel_withdraws_a_queued_runner_deploy(engine, served):
    s, srv = served
    engine.runners.issue_token("dmz")
    eid = _endpoint(engine, s.port, srv)
    engine.store.add_observation(eid, fetch_cert("127.0.0.1", s.port, "app.internal.test"))
    now = parse_dt(engine.store.latest_cert_observation(eid)["not_after"]) - timedelta(days=3)
    engine.tick(now=now, scan=False)
    r = engine.store.renewal(engine.store.renewals()[0]["id"])
    engine.cancel(r["id"])
    assert engine.runners.claim("dmz") == []                  # the runner never gets the cancelled bundle
    assert "PRIVATE KEY" not in (engine.store.vault.open(engine.runners.job(r["rollback"]["runner_job"])["payload"]))


def test_runner_endpoint_saves_without_the_engine_holding_its_secret(api, monkeypatch):
    monkeypatch.delenv("ADC_PASSWORD", raising=False)
    r = api.post("/api/endpoints", headers={"Authorization": "Bearer admin-tok"}, json={
        "name": "dmz-adc", "host": "10.40.0.20", "port": 443, "connector": "citrix",
        "connector_config": {"runner": "dmz", "url": "https://10.40.0.5", "username": "farrier",
                             "password": "env:ADC_PASSWORD", "certkey": "app_cert"}})
    assert r.status_code == 200, r.text


def test_a_verify_no_runner_takes_counts_as_a_failed_attempt(engine, served):
    s, srv = served
    engine.runners.issue_token("dmz")
    eid = _endpoint(engine, s.port, srv)
    rid = engine.store.create_renewal(eid, "2000-01-01T00:00:00+00:00", None, None, "test")
    engine.store.x("UPDATE renewals SET state='verifying', new_fingerprint='ab' WHERE id=?", (rid,))
    engine.advance(rid)                                       # queues a verify job
    job = engine.runners.latest(rid, "verify")
    engine.store.x("UPDATE runner_jobs SET created_at='2000-01-01T00:00:00+00:00' WHERE id=?", (job["id"],))
    engine.advance(rid)
    r = engine.store.renewal(rid)
    assert r["attempts"] == 1 and "could not check" in r["error"]
