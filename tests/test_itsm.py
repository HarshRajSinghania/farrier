"""ServiceNow, Jira, Datadog and Splunk channels (farrier.itsm), against httpx.MockTransport fakes."""
import base64
import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi.testclient import TestClient

from farrier.api.app import create_app
from farrier.config.integrations import catalog
from farrier.core.x509util import parse_pem
from farrier.itsm import adapter_for, telemetry
from farrier.itsm import http as itsm_http
from farrier.itsm.base import TicketSpec
from farrier.itsm.http import Http, ItsmError

SNOW_PW = "snow-Pa55word-do-not-leak"
JIRA_TOKEN = "jira-api-token-do-not-leak"
DD_KEY = "dd0123456789abcdef-do-not-leak"
HEC_TOKEN = "11111111-2222-3333-4444-hec-do-not-leak"
SECRETS = (SNOW_PW, JIRA_TOKEN, DD_KEY, HEC_TOKEN)


@pytest.fixture(autouse=True)
def secrets_env(monkeypatch):
    monkeypatch.setenv("FARRIER_SECRET_SNOW_PW", SNOW_PW)
    monkeypatch.setenv("FARRIER_SECRET_JIRA", JIRA_TOKEN)
    monkeypatch.setenv("FARRIER_SECRET_DD", DD_KEY)
    monkeypatch.setenv("FARRIER_SECRET_HEC", HEC_TOKEN)
    sleeps = []
    monkeypatch.setattr(itsm_http, "SLEEP", sleeps.append)
    return sleeps


def mock(monkeypatch, handler):
    t = httpx.MockTransport(handler)
    monkeypatch.setattr(itsm_http, "transport_override", t)
    return t


# ---- fake products ---------------------------------------------------------------------------------
class FakeServiceNow:
    def __init__(self):
        self.requests: list[httpx.Request] = []
        self.records: dict[str, dict] = {}          # sys_id -> record
        self.patches: list[tuple[str, dict]] = []
        self.fail_next: list[httpx.Response] = []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        if self.fail_next:
            return self.fail_next.pop(0)
        parts = req.url.path.split("/")             # ['', 'api', 'now', 'table', <table>, <sys_id>?]
        if req.url.path == "/oauth_token.do":
            return httpx.Response(200, json={"access_token": "oauth-access-tok", "expires_in": 1800})
        table = parts[4]
        if req.method == "GET" and table == "cmdb_ci":
            name = req.url.params["sysparm_query"].removeprefix("name=")
            return httpx.Response(200, json={"result": [{"sys_id": "ci-1"}] if name == "vpn-1" else []})
        if req.method == "GET" and table == "sys_user":
            return httpx.Response(200, json={"result": [{"sys_id": "u1"}]})
        if req.method == "GET":
            corr = req.url.params.get("sysparm_query", "").removeprefix("correlation_id=")
            hits = [r for r in self.records.values() if r["_table"] == table and r.get("correlation_id") == corr]
            return httpx.Response(200, json={"result": [{"sys_id": h["sys_id"], "number": h["number"]} for h in hits]})
        if req.method == "POST":
            body = json.loads(req.content)
            sid = f"sys{len(self.records) + 1}"
            prefix = "CHG" if table == "change_request" else "INC"
            rec = {**body, "_table": table, "sys_id": sid, "number": f"{prefix}00{len(self.records) + 1:05d}"}
            self.records[sid] = rec
            return httpx.Response(201, json={"result": {"sys_id": sid, "number": rec["number"]}})
        if req.method == "PATCH":
            body = json.loads(req.content)
            self.patches.append((parts[5], body))
            self.records[parts[5]].update(body)
            return httpx.Response(200, json={"result": {"sys_id": parts[5]}})
        return httpx.Response(404)


class FakeJira:
    def __init__(self, transitions=("Start", "Done")):
        self.requests: list[httpx.Request] = []
        self.issues: dict[str, dict] = {}
        self.comments: dict[str, list] = {}
        self.transitioned: dict[str, str] = {}
        self.transitions = transitions

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        p = req.url.path
        if p.endswith("/myself"):
            return httpx.Response(200, json={"displayName": "PKI Bot"})
        if p.endswith(("/search/jql", "/search")):
            label = req.url.params["jql"].split('labels = "')[1].rstrip('"')
            hits = [k for k, i in self.issues.items() if label in i["fields"]["labels"]]
            return httpx.Response(200, json={"issues": [{"key": k} for k in hits]})
        if p.endswith("/issue") and req.method == "POST":
            key = f"OPS-{len(self.issues) + 1}"
            self.issues[key] = json.loads(req.content)
            return httpx.Response(201, json={"id": "100", "key": key})
        if p.endswith("/comment"):
            self.comments.setdefault(p.split("/")[-2], []).append(json.loads(req.content)["body"])
            return httpx.Response(201, json={"id": "c1"})
        if p.endswith("/transitions") and req.method == "GET":
            return httpx.Response(200, json={"transitions": [
                {"id": str(i + 11), "name": n, "to": {"name": n}} for i, n in enumerate(self.transitions)]})
        if p.endswith("/transitions") and req.method == "POST":
            self.transitioned[p.split("/")[-2]] = json.loads(req.content)["transition"]["id"]
            return httpx.Response(204)
        return httpx.Response(404)


SNOW = {"type": "servicenow", "instance": "acme.service-now.com", "auth": "basic", "username": "farrier",
        "password": "env:FARRIER_SECRET_SNOW_PW", "table": "change_request", "assignment_group": "PKI",
        "cmdb_ci_field": "name", "tickets": True}
JIRA = {"type": "jira", "base_url": "https://acme.atlassian.net", "email": "bot@acme.test",
        "api_token": "env:FARRIER_SECRET_JIRA", "project_key": "OPS", "labels": ["tls"], "tickets": True}


# ---- catalog and validation ------------------------------------------------------------------------
def test_catalog_lists_every_type_with_secret_fields():
    types = {t["id"]: t for t in catalog()["notifier_types"]}
    want = {"servicenow": {"instance", "auth", "username", "password", "client_id", "client_secret", "table",
                           "assignment_group", "category", "cmdb_ci_field", "tickets"},
            "jira": {"base_url", "email", "api_token", "pat", "project_key", "issue_type", "labels",
                     "done_transition", "tickets"},
            "datadog": {"site", "api_key"},
            "splunk": {"url", "token", "index", "source", "sourcetype", "verify_tls", "ca_file"}}
    secret = {"password", "client_secret", "api_token", "pat", "api_key", "token", "ca_file"}
    for kind, keys in want.items():
        fields = {f["key"]: f for f in types[kind]["fields"]}
        assert keys <= set(fields), kind
        for k, f in fields.items():
            assert f["secret"] == (k in secret), (kind, k)


@pytest.fixture
def api(data_dir, monkeypatch):
    from farrier.core.engine import Engine
    monkeypatch.setenv("FARRIER_API_TOKEN", "admin-tok")
    monkeypatch.delenv("FARRIER_ALLOW_INLINE_SECRETS", raising=False)
    eng = Engine(data_dir, settings={"verify_retry_seconds": 0.01, "scan_timeout": 0.5})
    return eng, TestClient(create_app(eng))


H = {"Authorization": "Bearer admin-tok"}


def test_dashboard_round_trip_refs_only_and_test_button(api, monkeypatch):
    eng, c = api
    assert c.put("/api/notifiers/snow", json={**SNOW, "password": "plaintext"}, headers=H).status_code == 400
    assert c.put("/api/notifiers/snow", json={**SNOW, "instance": "evil host/x"}, headers=H).status_code == 400
    assert c.put("/api/notifiers/dd", json={"type": "datadog", "site": "attacker.example",
                                            "api_key": "env:FARRIER_SECRET_DD"}, headers=H).status_code == 400
    assert c.put("/api/notifiers/hec", json={"type": "splunk", "url": "http://splunk:8088/services/collector/event",
                                             "token": "env:FARRIER_SECRET_HEC"}, headers=H).status_code == 400
    r = c.put("/api/notifiers/snow", json=SNOW, headers=H)
    assert r.status_code == 200, r.text
    assert r.json()["fields"]["password"] == "env:FARRIER_SECRET_SNOW_PW"
    assert r.json()["target"] == "change_request on acme.service-now.com"
    # an edit that leaves the secret out keeps the stored reference
    edit = {k: v for k, v in SNOW.items() if k != "password"} | {"category": "Security"}
    assert c.put("/api/notifiers/snow", json=edit, headers=H).status_code == 200
    assert eng.items.get("notifier", "snow")["password"] == "env:FARRIER_SECRET_SNOW_PW"
    r = c.put("/api/notifiers/dd", json={"type": "datadog", "site": "eu", "api_key": "env:FARRIER_SECRET_DD",
                                        "tickets": "x"}, headers=H)
    assert r.status_code == 400                       # unknown field
    r = c.put("/api/notifiers/dd", json={"type": "datadog", "site": "eu", "api_key": "env:FARRIER_SECRET_DD"},
              headers=H)
    assert r.status_code == 200 and eng.items.get("notifier", "dd")["site"] == "datadoghq.eu"

    snow = FakeServiceNow()
    seen = []

    def handler(req):
        seen.append(req)
        if req.url.host == "api.datadoghq.eu":
            return httpx.Response(200, json={"valid": True})
        return snow(req)
    mock(monkeypatch, handler)
    out = c.post("/api/notifiers/snow/test", headers=H).json()
    assert out["ok"] and "acme.service-now.com" in out["detail"]
    req = seen[-1]
    assert req.method == "GET" and req.url.path == "/api/now/table/sys_user" and req.url.params["sysparm_limit"] == "1"
    assert req.headers["Authorization"] == "Basic " + base64.b64encode(f"farrier:{SNOW_PW}".encode()).decode()
    out = c.post("/api/notifiers/dd/test", headers=H).json()
    assert out["ok"] and seen[-1].url.path == "/api/v1/validate" and seen[-1].headers["DD-API-KEY"] == DD_KEY

    # a refused credential: the detail names the call and status, never the secret
    mock(monkeypatch, lambda req: httpx.Response(401, json={"error": {"message": f"bad password {SNOW_PW}"}}))
    out = c.post("/api/notifiers/snow/test", headers=H).json()
    assert not out["ok"] and "HTTP 401" in out["detail"] and SNOW_PW not in out["detail"]


# ---- the HTTP client -------------------------------------------------------------------------------
def test_retry_after_is_honoured_and_bounded(secrets_env):
    calls = []

    def handler(req):
        calls.append(req)
        if len(calls) == 1:
            return httpx.Response(429, headers={"Retry-After": "7"})
        if len(calls) == 2:
            return httpx.Response(503, headers={"Retry-After": "Wed, 21 Oct 2015 07:28:00 GMT"})  # in the past
        return httpx.Response(200, json={"ok": True})
    h = Http("https://x.test", transport=httpx.MockTransport(handler))
    assert h.post("/a", json={}, idempotent=False).json() == {"ok": True}
    assert secrets_env == [7.0, 0.0]

    h = Http("https://x.test", transport=httpx.MockTransport(lambda r: httpx.Response(429, headers={"Retry-After": "3600"})))
    with pytest.raises(ItsmError, match="asked to wait 3600s"):
        h.get("/a")

    # a create is not repeated after a 502 (it may have been processed); a GET is
    calls.clear()
    h = Http("https://x.test", transport=httpx.MockTransport(lambda r: (calls.append(r), httpx.Response(502))[1]))
    with pytest.raises(ItsmError, match="HTTP 502"):
        h.post("/create", json={}, idempotent=False)
    assert len(calls) == 1
    with pytest.raises(ItsmError):
        h.get("/read")
    assert len(calls) == 1 + 4                         # bounded: 4 attempts


# ---- per-product request shapes --------------------------------------------------------------------
def test_servicenow_oauth_and_ticket_shapes(monkeypatch):
    sn = FakeServiceNow()
    mock(monkeypatch, sn)
    monkeypatch.setenv("FARRIER_SECRET_SNOW_CS", "client-secret-value")
    cfg = {**SNOW, "auth": "oauth", "client_id": "cid", "client_secret": "env:FARRIER_SECRET_SNOW_CS"}
    a = adapter_for(cfg)
    t = a.open(TicketSpec(key="farrier-x-renewal-1", kind="change", summary="Install", description="body",
                          ci={"name": "vpn-1", "host": "10.0.0.1"}))
    tok = sn.requests[0]
    assert tok.url.path == "/oauth_token.do" and b"grant_type=client_credentials" in tok.content
    create = sn.requests[-1]
    assert create.headers["Authorization"] == "Bearer oauth-access-tok"
    assert create.url.path == "/api/now/table/change_request"
    body = json.loads(create.content)
    assert body["correlation_id"] == "farrier-x-renewal-1" and body["assignment_group"] == "PKI"
    assert body["cmdb_ci"] == "ci-1" and body["short_description"] == "Install"
    assert t.ref.startswith("CHG") and a.find("farrier-x-renewal-1", "change").ext_id == t.ext_id
    a.resolve(t, "verified")
    assert [p[1].get("state") for p in sn.patches] == ["0"]                 # change_request -> Review
    inc = a.open(TicketSpec(key="k2", kind="incident", summary="s", description="d"))
    a.resolve(inc, "ok")
    assert sn.patches[-1][1]["state"] == "6" and sn.patches[-1][1]["close_code"] == "Solution provided"


def test_jira_cloud_and_data_center_shapes(monkeypatch):
    j = FakeJira()
    mock(monkeypatch, j)
    a = adapter_for(JIRA)
    assert a.check() == "signed in to Jira as PKI Bot"
    req = j.requests[-1]
    assert req.url.path == "/rest/api/3/myself"
    assert req.headers["Authorization"] == "Basic " + base64.b64encode(f"bot@acme.test:{JIRA_TOKEN}".encode()).decode()
    t = a.open(TicketSpec(key="lbl-1", kind="change", summary="Install", description="line 1\nline 2"))
    fields = json.loads(j.requests[-1].content)["fields"]
    assert fields["project"] == {"key": "OPS"} and fields["issuetype"] == {"name": "Task"}
    assert fields["labels"] == ["farrier", "tls", "lbl-1"]
    assert fields["description"]["type"] == "doc" and len(fields["description"]["content"]) == 2   # ADF
    a.resolve(t, "done")
    assert j.transitioned[t.ext_id] == "12"                                # the "Done" transition

    dc = adapter_for({**JIRA, "base_url": "https://jira.acme.internal", "email": None, "api_token": None,
                      "pat": "env:FARRIER_SECRET_JIRA"})
    dc.check()
    assert j.requests[-1].url.path == "/rest/api/2/myself"
    assert j.requests[-1].headers["Authorization"] == f"Bearer {JIRA_TOKEN}"


def test_datadog_events_v2_and_v1(monkeypatch):
    seen = []
    mock(monkeypatch, lambda req: (seen.append(req), httpx.Response(202, json={}))[1])
    from farrier.monitoring.notify import Notifier, payload
    p = payload("failed", {"id": 9, "error": "deploy failed"}, {"name": "web-1", "host": "h", "port": 443,
                                                                  "connector": "f5"})
    Notifier.deliver_one({"type": "datadog", "site": "us5.datadoghq.com", "api_key": "env:FARRIER_SECRET_DD"}, p)
    req = seen[-1]
    assert str(req.url) == "https://api.us5.datadoghq.com/api/v2/events" and req.headers["DD-API-KEY"] == DD_KEY
    attrs = json.loads(req.content)["data"]["attributes"]
    assert attrs["category"] == "alert" and attrs["attributes"]["status"] == "error"
    assert attrs["aggregation_key"] == "farrier-renewal-9" and "endpoint:web-1" in attrs["tags"]
    Notifier.deliver_one({"type": "datadog", "site": "datadoghq.com", "api_key": "env:FARRIER_SECRET_DD",
                          "events_api": "v1"}, p)
    body = json.loads(seen[-1].content)
    assert seen[-1].url.path == "/api/v1/events" and body["alert_type"] == "error" and body["title"]


def _add_endpoint(engine, name, host="127.0.0.1", port=443, connector="manual", cfg=None, tags=None, days=20):
    from conftest import issue_initial
    eid = engine.store.upsert_endpoint({"name": name, "host": host, "port": port, "connector": connector,
                                        "connector_config": cfg or {}, "tags": list(tags or [])})
    _, fullchain = issue_initial(engine.issuers["default"], f"{name}.internal.test", days=days)
    engine.store.add_observation(eid, parse_pem(fullchain))
    return eid


def test_datadog_metric_series_shape(engine, monkeypatch):
    seen = []
    mock(monkeypatch, lambda req: (seen.append(req), httpx.Response(202, json={"errors": []}))[1])
    _add_endpoint(engine, "web-1", tags=["env:prod"], connector="files")
    _add_endpoint(engine, "web-2", port=8443)
    cfg = {"type": "datadog", "name": "dd", "site": "datadoghq.com", "api_key": "env:FARRIER_SECRET_DD", "env": "lab"}
    now = datetime.now(UTC)
    assert telemetry.datadog_metrics(engine, cfg, now) == 3
    series = json.loads(seen[-1].content)["series"]
    assert seen[-1].url.path == "/api/v2/series"
    days = {s["tags"][0]: s for s in series if s["metric"] == "farrier.certificate.days_left"}
    s1 = days["endpoint:web-1"]
    assert s1["type"] == 3 and 19 < s1["points"][0]["value"] <= 20 and isinstance(s1["points"][0]["timestamp"], int)
    assert set(s1["tags"]) == {"endpoint:web-1", "connector:files", "issuer:default", "env:prod"}
    assert "env:lab" in days["endpoint:web-2"]["tags"]
    failed = [s for s in series if s["metric"] == "farrier.renewals.failed"]
    assert failed[0]["type"] == 1 and failed[0]["points"][0]["value"] == 0
    # one renewal fails after the watermark: the next tick counts it once
    rid = engine.store.create_renewal(engine.store.endpoints()[0]["id"], now.isoformat(), None, None, "due")
    engine.store.update_renewal(rid, state="failed", error="x")
    later = datetime.now(UTC) + timedelta(seconds=2)
    telemetry.datadog_metrics(engine, cfg, later)
    assert [s for s in json.loads(seen[-1].content)["series"] if s["metric"] == "farrier.renewals.failed"][0][
        "points"][0]["value"] == 1
    telemetry.datadog_metrics(engine, cfg, later + timedelta(seconds=5))
    assert [s for s in json.loads(seen[-1].content)["series"] if s["metric"] == "farrier.renewals.failed"][0][
        "points"][0]["value"] == 0


def test_splunk_hec_batch_shape_and_tls_default(engine, monkeypatch):
    seen = []

    def handler(req):
        seen.append(req)
        if req.url.path.endswith("/health"):
            return httpx.Response(200, json={"text": "HEC is healthy", "code": 17})
        return httpx.Response(200, json={"text": "Success", "code": 0})
    mock(monkeypatch, handler)
    cfg = {"type": "splunk", "name": "hec", "url": "https://splunk.acme.internal:8088/services/collector/event",
           "token": "env:FARRIER_SECRET_HEC", "index": "pki"}
    a = adapter_for(cfg)
    assert a.verify is True                                 # TLS verified unless switched off
    assert adapter_for({**cfg, "verify_tls": False}).verify is False
    assert "index pki" in a.check()
    assert seen[-2].url.path == "/services/collector/health"
    test_ev = json.loads(seen[-1].content)
    assert test_ev["index"] == "pki" and test_ev["sourcetype"] == "farrier:event" and test_ev["source"] == "farrier"

    _add_endpoint(engine, "web-1")
    _add_endpoint(engine, "web-2", port=8443)
    now = datetime.now(UTC)
    assert telemetry.splunk_inventory(engine, cfg, now) == 2
    req = seen[-1]
    assert req.url.path == "/services/collector/event" and req.headers["Authorization"] == f"Splunk {HEC_TOKEN}"
    lines = req.content.decode().split("\n")
    events = [json.loads(x) for x in lines]
    assert len(events) == 2 and all(e["index"] == "pki" and e["event"]["kind"] == "inventory" for e in events)
    cert = events[0]["event"]["certificate"]
    assert cert["fingerprint_sha256"] and cert["not_after"] and cert["days_left"] > 0
    assert "PRIVATE KEY" not in req.content.decode()
    assert telemetry.splunk_inventory(engine, cfg, now + timedelta(hours=1)) == 0   # once a day

    # renewal events and alerts go out as single HEC events
    from farrier.monitoring.notify import Notifier, payload
    Notifier.deliver_one(cfg, payload("done", {"id": 4}, {"name": "web-1", "host": "h", "port": 1}) | {"x": None})
    ev = json.loads(seen[-1].content)
    assert ev["event"]["kind"] == "renewal" and ev["event"]["id"] == "renewal-4-done"


# ---- the ticket lifecycle --------------------------------------------------------------------------
def _manual_renewal(engine, name="vpn-1"):
    eid = _add_endpoint(engine, name, cfg={"runbook": "cisco-asa"})
    ca = engine.issuers["default"]
    from farrier.core.x509util import build_csr, generate_key
    key = generate_key("ec256")
    cert, chain = ca.issue(build_csr(key, f"{name}.internal.test", [f"{name}.internal.test", f"alt.{name}.test"]),
                           [f"{name}.internal.test", f"alt.{name}.test"])
    info = parse_pem(cert)
    rid = engine.store.create_renewal(eid, datetime.now(UTC).isoformat(), "2030-01-02T00:00:00+00:00", None, "due")
    engine.store.update_renewal(rid, state="awaiting_manual", cert_pem=cert, chain_pem=chain,
                                new_fingerprint=info.fingerprint, not_after=info.not_after.isoformat(),
                                key_sealed=engine.store.vault.seal("-----BEGIN PRIVATE KEY-----\nxx\n"))
    return eid, rid


def _setup(engine, cfg, name):
    engine.items.put("notifier", name, cfg)
    engine.reload_config()
    engine.notifier.dashboard_url = "https://farrier.acme.test"
    engine.itsm.synchronous = True


def _fire(engine, rid, state=None, **fields):
    if state:
        engine.store.update_renewal(rid, state=state, **fields)
    engine._notify(engine.store.renewal(rid)["state"], rid)


def _logs(engine) -> str:
    return "\n".join(r["message"] for r in engine.store.q("SELECT message FROM events"))


def test_servicenow_ticket_lifecycle(engine, monkeypatch):
    sn = FakeServiceNow()
    mock(monkeypatch, sn)
    _setup(engine, SNOW, "snow")
    _, rid = _manual_renewal(engine)
    _fire(engine, rid)
    _fire(engine, rid)                                     # the same event twice ...
    engine.itsm.reconcile(datetime.now(UTC))               # ... and a reconcile pass
    assert len(sn.records) == 1                            # ... one ticket
    rec = next(iter(sn.records.values()))
    assert rec["_table"] == "change_request" and rec["correlation_id"].endswith(f"-renewal-{rid}")
    d = rec["description"]
    assert "alt.vpn-1.test" in d and "Issuer:" in d and "2030-01-02" in d and "ssl trust-point" in d
    assert f"https://farrier.acme.test/dashboard/renewals?renewal={rid}" in d
    assert "PRIVATE KEY" not in d and SNOW_PW not in json.dumps(rec)
    r = engine.store.renewal(rid)
    assert r["ticket_ref"] == rec["number"]

    _fire(engine, rid, "done")
    assert sn.patches[-1][1]["state"] == "0" and "seen live" in sn.patches[-1][1]["work_notes"]
    row = engine.store.q1("SELECT * FROM itsm_tickets WHERE renewal_id=?", (rid,))
    assert row["state"] == "closed" and row["last_event"] == "done"
    _fire(engine, rid)
    assert len(sn.patches) == 1                            # nothing more once closed
    assert SNOW_PW not in _logs(engine)


def test_failed_manual_renewal_comments_and_leaves_ticket_open(engine, monkeypatch):
    j = FakeJira()
    mock(monkeypatch, j)
    _setup(engine, JIRA, "jira")
    _, rid = _manual_renewal(engine)
    _fire(engine, rid)
    (key,) = j.issues
    assert f"renewal-{rid}" in " ".join(j.issues[key]["fields"]["labels"])
    _fire(engine, rid, "failed", error="operator reported the device refused the import")
    assert key not in j.transitioned
    assert "refused the import" in json.dumps(j.comments[key])
    row = engine.store.q1("SELECT * FROM itsm_tickets WHERE renewal_id=?", (rid,))
    assert row["state"] == "open" and row["last_event"] == "failed"
    _fire(engine, rid)
    assert len(j.comments[key]) == 1                       # one note per state change


def test_failed_automated_renewal_opens_incident_when_wanted(engine, monkeypatch):
    sn = FakeServiceNow()
    mock(monkeypatch, sn)
    _setup(engine, {**SNOW, "events": ["failed", "rolled_back"]}, "snow")
    eid = _add_endpoint(engine, "web-9", connector="files")
    rid = engine.store.create_renewal(eid, datetime.now(UTC).isoformat(), None, None, "due")
    _fire(engine, rid, "rolled_back", error="new cert never went live (serving abc); rolled back")
    (rec,) = sn.records.values()
    assert rec["_table"] == "incident" and "never went live" in rec["description"]
    # a channel that does not list the event opens nothing
    _setup(engine, {**SNOW, "events": ["awaiting_manual"]}, "snow")
    rid2 = engine.store.create_renewal(_add_endpoint(engine, "web-10", connector="files"),
                                       datetime.now(UTC).isoformat(), None, None, "due")
    _fire(engine, rid2, "failed", error="x")
    assert len(sn.records) == 1


def test_open_failure_is_retried_without_duplicates_and_never_logs_secrets(engine, monkeypatch):
    sn = FakeServiceNow()
    mock(monkeypatch, sn)
    _setup(engine, SNOW, "snow")
    _, rid = _manual_renewal(engine)
    sn.fail_next = [httpx.Response(200, json={"result": []}),          # lookup: none yet
                    httpx.Response(200, json={"result": []}),          # no CMDB CI
                    httpx.Response(500, json={"error": {"message": f"boom {SNOW_PW}"}})]
    _fire(engine, rid)
    row = engine.store.q1("SELECT * FROM itsm_tickets WHERE renewal_id=?", (rid,))
    assert row["state"] == "error" and row["attempts"] == 1
    assert SNOW_PW not in _logs(engine) and SNOW_PW not in (row["error"] or "")
    assert "HTTP 500" in row["error"]
    # the next tick retries once the backoff has passed
    engine.store.x("UPDATE itsm_tickets SET updated_at='2000-01-01T00:00:00+00:00' WHERE id=?", (row["id"],))
    engine.itsm.reconcile(datetime.now(UTC))
    assert len(sn.records) == 1
    assert engine.store.q1("SELECT state FROM itsm_tickets WHERE id=?", (row["id"],))["state"] == "open"


def test_end_to_end_manual_renewal_opens_and_closes_ticket(engine, served, monkeypatch):
    """Real engine ticks: change pack ready -> ticket; installed and seen live -> resolved."""
    s, srv = served
    sn = FakeServiceNow()
    mock(monkeypatch, sn)
    _setup(engine, SNOW, "snow")
    eid = engine.store.upsert_endpoint({"name": "vpn-live", "host": "127.0.0.1", "port": s.port,
                                        "sni": "app.internal.test", "connector": "manual",
                                        "connector_config": {"runbook": "generic"}})
    engine.observe(engine.store.endpoint(eid))
    obs = engine.store.latest_cert_observation(eid)
    now = datetime.fromisoformat(obs["not_after"]) - timedelta(days=3)
    assert engine.tick(now=now)["states"] == {"awaiting_manual": 1}
    (rec,) = sn.records.values()
    r = engine.store.renewals()[0]
    assert engine.store.renewal(r["id"])["ticket_ref"] == rec["number"]
    pack = engine.data_dir / "packs" / str(r["id"])
    assert "PRIVATE KEY" not in rec["description"]
    (srv / "fullchain.pem").write_text((pack / "fullchain.pem").read_text())
    (srv / "key.pem").write_text((pack / "key.pem").read_text())
    assert engine.tick(now=now)["states"] == {"done": 1}
    assert sn.patches and sn.patches[-1][1]["state"] == "0"
