"""Appliance connectors against mock management APIs: request shape, switch-over and rollback."""
import base64
import json
import xml.etree.ElementTree as ET

import httpx
import pytest

from conftest import issue_initial
from farrier.connectors import Bundle, DeployError, make_connector
from farrier.connectors.f5 import F5Connector
from farrier.connectors.fortigate import FortiGateConnector
from farrier.connectors.panos import PanOSConnector
from farrier.issuers.local_ca import LocalCA
from farrier.x509util import split_pem_chain


@pytest.fixture
def bundle(tmp_path):
    key, full = issue_initial(LocalCA(tmp_path), "lb.example.test", 47)
    c = split_pem_chain(full)
    return Bundle("lb-01", 42, key, c[0], "".join(c[1:]), "2027-01-01T00:00:00+00:00")


@pytest.fixture(autouse=True)
def reset_transports():
    yield
    for cls in (F5Connector, FortiGateConnector, PanOSConnector):
        cls.transport = None


def test_f5_deploy_and_rollback(tmp_path, bundle):
    calls, uploads = [], {}
    profile = {"certKeyChain": [{"name": "default", "cert": "/Common/old.crt", "key": "/Common/old.key"},
                                {"name": "rsa", "cert": "/Common/rsa.crt", "key": "/Common/rsa.key"}]}

    def h(req: httpx.Request):
        calls.append((req.method, req.url.path))
        assert req.headers["authorization"].startswith("Basic ")
        if "/file-transfer/uploads/" in req.url.path:
            n = len(req.content)
            assert req.headers["content-range"] == f"0-{n - 1}/{n}"
            uploads[req.url.path.rsplit("/", 1)[1]] = req.content
            return httpx.Response(200, json={})
        if req.url.path == "/mgmt/tm/ltm/profile/client-ssl/~Common~clientssl_app":
            if req.method == "PATCH":
                profile.update(json.loads(req.content))
            return httpx.Response(200, json=profile)
        return httpx.Response(200, json={})

    F5Connector.transport = httpx.MockTransport(h)
    c = make_connector("f5", {"url": "https://bigip", "username": "u", "password": "p",
                              "profile": "/Common/clientssl_app"}, tmp_path)
    tok = c.deploy(bundle)
    obj = bundle.object_name
    assert uploads[f"{obj}.key"].decode() == bundle.key_pem
    assert profile["certKeyChain"][0] == {"name": "default", "cert": f"/Common/{obj}.crt",
                                          "key": f"/Common/{obj}.key", "chain": f"/Common/{obj}_chain.crt"}
    assert profile["certKeyChain"][1]["name"] == "rsa"            # other pairs untouched
    assert ("POST", "/mgmt/tm/sys/config") in calls
    c.rollback(tok)
    assert profile["certKeyChain"][0]["cert"] == "/Common/old.crt"


def test_f5_error_surfaces(tmp_path, bundle):
    F5Connector.transport = httpx.MockTransport(
        lambda r: httpx.Response(401, text="auth failed") if r.method == "GET" else httpx.Response(200))
    c = make_connector("f5", {"url": "https://bigip", "username": "u", "password": "p", "profile": "/Common/x"},
                       tmp_path)
    with pytest.raises(DeployError, match="401"):
        c.deploy(bundle)


def test_fortigate_sslvpn(tmp_path, bundle, monkeypatch):
    monkeypatch.setenv("FGT_TOKEN", "t0k")
    state = {"servercert": "old-cert"}
    imported = {}

    def h(req):
        assert req.headers["authorization"] == "Bearer t0k"
        if req.url.path == "/api/v2/cmdb/vpn.ssl/settings":
            if req.method == "PUT":
                state.update(json.loads(req.content))
            return httpx.Response(200, json={"results": state})
        if req.url.path.endswith("/local/import"):
            imported.update(json.loads(req.content))
        return httpx.Response(200, json={"status": "success"})

    FortiGateConnector.transport = httpx.MockTransport(h)
    c = make_connector("fortigate", {"url": "https://fgt", "api_token": "env:FGT_TOKEN", "bind": "sslvpn"}, tmp_path)
    tok = c.deploy(bundle)
    assert base64.b64decode(imported["key_file_content"]).decode() == bundle.key_pem
    assert state["servercert"] == imported["certname"] and len(imported["certname"]) <= 35
    c.rollback(tok)
    assert state["servercert"] == "old-cert"


def test_panos_import_and_commit(tmp_path, bundle):
    cfg = {"cert": "gp-old"}
    seen = []

    def ok(inner=""):
        return httpx.Response(200, text=f'<response status="success"><result>{inner}</result></response>')

    def h(req):
        q = dict(req.url.params)
        seen.append(q.get("type"))
        assert q["key"] == "K"
        if q["type"] == "config" and q["action"] == "get":
            return ok(f"<certificate>{cfg['cert']}</certificate>")
        if q["type"] == "config" and q["action"] == "set":
            cfg["cert"] = ET.fromstring(q["element"]).text
            return ok()
        if q["type"] == "import":
            body = req.content.decode(errors="ignore")
            assert "ENCRYPTED PRIVATE KEY" in body and "BEGIN CERTIFICATE" in body
            cfg["imported"] = q["certificate-name"]
        return ok()

    PanOSConnector.transport = httpx.MockTransport(h)
    c = make_connector("panos", {"url": "https://fw", "api_key": "K", "profile": "gp-portal"}, tmp_path)
    tok = c.deploy(bundle)
    assert cfg["cert"] == cfg["imported"] and tok == {"previous": "gp-old"}
    assert seen.count("commit") == 1
    c.rollback(tok)
    assert cfg["cert"] == "gp-old" and seen.count("commit") == 2


def test_panos_error_status(tmp_path, bundle):
    PanOSConnector.transport = httpx.MockTransport(lambda r: httpx.Response(
        200, text='<response status="error"><msg><line>Invalid credentials</line></msg></response>'))
    c = make_connector("panos", {"url": "https://fw", "api_key": "K", "profile": "p"}, tmp_path)
    with pytest.raises(DeployError, match="Invalid credentials"):
        c.deploy(bundle)
