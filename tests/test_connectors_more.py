"""Citrix ADC (NITRO), Kubernetes Secret and IIS (OpenSSH + PowerShell) connectors: deploy and rollback."""
import base64
import json
import re

import httpx
import pytest
from conftest import issue_initial
from cryptography.hazmat.primitives.serialization import pkcs12

from farrier.connectors import Bundle, DeployError, make_connector
from farrier.connectors.citrix import CitrixConnector
from farrier.connectors.kubernetes import KubernetesConnector
from farrier.core.x509util import split_pem_chain
from farrier.issuers.local_ca import LocalCA


@pytest.fixture
def bundle(tmp_path):
    key, full = issue_initial(LocalCA(tmp_path), "app.example.test", 47)
    c = split_pem_chain(full)
    return Bundle("app-01", 7, key, c[0], "".join(c[1:]), "2027-01-01T00:00:00+00:00")


@pytest.fixture(autouse=True)
def reset_transports():
    yield
    CitrixConnector.transport = KubernetesConnector.transport = None


# ---- Citrix ADC ---------------------------------------------------------------------------------
def test_citrix_updates_certkey_in_place_and_rolls_back(tmp_path, bundle):
    files, certkeys, actions = {}, {"app_cert": {"certkey": "app_cert", "cert": "old.crt", "key": "old.key",
                                                  "linkcertkeyname": "old_ca"}}, []

    def h(req):
        assert req.headers["X-NITRO-USER"] == "nsroot" and req.headers["X-NITRO-PASS"] == "pw"
        path, action = req.url.path, req.url.params.get("action")
        body = json.loads(req.content) if req.content else {}
        if path == "/nitro/v1/config/systemfile":
            f = body["systemfile"]
            files[f["filename"]] = base64.b64decode(f["filecontent"]).decode()
            return httpx.Response(201, json={})
        if path == "/nitro/v1/config/sslcertkey/app_cert":
            return httpx.Response(200, json={"sslcertkey": [dict(certkeys["app_cert"])]})
        if path == "/nitro/v1/config/sslcertkey":
            ck = body["sslcertkey"]
            actions.append(action)
            if action == "update":
                certkeys[ck["certkey"]].update(cert=ck["cert"], key=ck["key"])
            elif action == "unlink":
                certkeys[ck["certkey"]].pop("linkcertkeyname", None)
            elif action == "link":
                certkeys[ck["certkey"]]["linkcertkeyname"] = ck["linkcertkeyname"]
            else:
                certkeys[ck["certkey"]] = ck
            return httpx.Response(200, json={})
        if path == "/nitro/v1/config/nsconfig":
            actions.append("save")
            return httpx.Response(200, json={})
        return httpx.Response(404, json={"message": path})

    CitrixConnector.transport = httpx.MockTransport(h)
    c = make_connector("citrix", {"url": "https://adc", "username": "nsroot", "password": "pw",
                                  "certkey": "app_cert"}, tmp_path)
    tok = c.deploy(bundle)
    obj = bundle.object_name
    assert files[f"{obj}.key"] == bundle.key_pem and files[f"{obj}.crt"] == bundle.cert_pem
    assert certkeys["app_cert"]["cert"] == f"{obj}.crt" and certkeys["app_cert"]["linkcertkeyname"] == f"{obj}_ca"
    assert actions[-1] == "save" and tok == {"cert": "old.crt", "key": "old.key", "link": "old_ca"}
    c.rollback(tok)
    assert certkeys["app_cert"] | {} == {"certkey": "app_cert", "cert": "old.crt", "key": "old.key",
                                         "linkcertkeyname": "old_ca"}


# ---- Kubernetes ---------------------------------------------------------------------------------
def _k8s(secrets, patches):
    def h(req):
        assert req.headers["Authorization"] == "Bearer k8s-token"
        m = re.fullmatch(r"/api/v1/namespaces/web/secrets(?:/([\w.-]+))?", req.url.path)
        if m:
            name = m.group(1)
            if req.method == "GET":
                return httpx.Response(200, json=secrets[name]) if name in secrets else httpx.Response(404)
            if req.method in ("PUT", "POST"):
                body = json.loads(req.content)
                if req.method == "POST" and body["metadata"]["name"] in secrets:
                    return httpx.Response(409)
                secrets[body["metadata"]["name"]] = body
                return httpx.Response(200, json=body)
            if req.method == "DELETE":
                return httpx.Response(200 if secrets.pop(name, None) else 404)
        if req.method == "PATCH" and req.url.path == "/apis/apps/v1/namespaces/web/deployments/web":
            patches.append(json.loads(req.content))
            return httpx.Response(200, json={})
        return httpx.Response(404)
    return h


def test_kubernetes_secret_with_backup_restart_and_rollback(tmp_path, bundle):
    old = {"tls.crt": "T0xEQ0VSVA==", "tls.key": "T0xES0VZ", "extra": "eA=="}
    helm = {"name": "app-tls", "labels": {"app.kubernetes.io/managed-by": "Helm"},
            "annotations": {"meta.helm.sh/release-name": "web"}}
    secrets = {"app-tls": {"metadata": helm, "type": "Opaque", "data": old}}
    patches = []
    KubernetesConnector.transport = httpx.MockTransport(_k8s(secrets, patches))
    c = make_connector("kubernetes", {"url": "https://k8s", "token": "k8s-token", "namespace": "web",
                                      "secret": "app-tls", "restart": ["deployment/web"]}, tmp_path)
    tok = c.deploy(bundle)
    data = secrets["app-tls"]["data"]
    assert base64.b64decode(data["tls.key"]).decode() == bundle.key_pem
    assert base64.b64decode(data["tls.crt"]).decode() == bundle.fullchain_pem
    assert secrets["app-tls-farrier-previous"]["data"] == old and tok == {"backup": "app-tls-farrier-previous"}
    assert secrets["app-tls"]["metadata"] == helm and secrets["app-tls"]["type"] == "Opaque"   # owner kept
    assert data["extra"] == "eA=="                                   # other keys untouched
    assert "restartedAt" in json.dumps(patches[0])
    assert "PRIVATE KEY" not in json.dumps(tok)          # the old key stays in the cluster, not in Farrier's DB
    c.rollback(tok)
    assert secrets["app-tls"]["data"] == old and secrets["app-tls"]["metadata"] == helm and len(patches) == 2


def test_kubernetes_creates_missing_secret_and_rollback_deletes_it(tmp_path, bundle):
    secrets = {}
    KubernetesConnector.transport = httpx.MockTransport(_k8s(secrets, []))
    c = make_connector("kubernetes", {"url": "https://k8s", "token": "k8s-token", "namespace": "web",
                                      "secret": "new-tls"}, tmp_path)
    tok = c.deploy(bundle)
    assert "new-tls" in secrets and tok == {"backup": None}
    c.rollback(tok)
    assert secrets == {}


def test_kubernetes_rejects_unknown_restart_kind(tmp_path):
    with pytest.raises(ValueError, match="restart"):
        make_connector("kubernetes", {"namespace": "web", "secret": "s", "restart": ["pod/x"]}, tmp_path)


# ---- IIS ----------------------------------------------------------------------------------------
class FakeSsh:
    def __init__(self, prev="A" * 40):
        self.scripts, self.prev = [], prev

    def __call__(self, argv, input=None, **kw):
        assert argv[:3] == ["ssh", "-o", "BatchMode=yes"] and argv[-1].startswith("powershell")
        assert "BEGIN" not in " ".join(argv)            # key material only on stdin
        self.scripts.append(input)
        out = f"FARRIER_PREVIOUS={self.prev}\n" if "Import-PfxCertificate" in input else ""
        return type("P", (), {"returncode": 0, "stdout": out, "stderr": ""})()


def test_iis_imports_pfx_switches_binding_and_rolls_back(tmp_path, bundle, monkeypatch):
    fake = FakeSsh()
    monkeypatch.setattr("farrier.connectors.iis.subprocess.run", fake)
    c = make_connector("iis", {"ssh": "Administrator@iis01", "site": "Bob's Site", "host_header": "app.example.test"},
                       tmp_path)
    tok = c.deploy(bundle)
    s = fake.scripts[0]
    assert "-Name 'Bob''s Site' -Protocol https -Port 443 -HostHeader 'app.example.test'" in s
    pfx = base64.b64decode(re.search(r"FromBase64String\('([^']+)'\)", s).group(1))
    password = re.search(r"ConvertTo-SecureString '([^']+)'", s).group(1)
    key, cert, chain = pkcs12.load_key_and_certificates(pfx, password.encode())
    assert key and cert and chain                       # key, leaf and intermediates in one PFX
    assert tok == {"previous": "A" * 40}
    c.rollback(tok)
    assert f"AddSslCertificate('{'A' * 40}', 'My')" in fake.scripts[1]


def test_iis_rollback_without_previous_binding_is_an_error(tmp_path, bundle, monkeypatch):
    monkeypatch.setattr("farrier.connectors.iis.subprocess.run", FakeSsh(prev=""))
    c = make_connector("iis", {"ssh": "a@b", "site": "s"}, tmp_path)
    tok = c.deploy(bundle)
    with pytest.raises(DeployError, match="no previous"):
        c.rollback(tok)


def test_citrix_reuses_an_intermediate_the_adc_already_has(tmp_path, bundle):
    from cryptography import x509
    inter = x509.load_pem_x509_certificate(bundle.chain_pem.encode())
    links = []

    def h(req):
        path, action = req.url.path, req.url.params.get("action")
        body = json.loads(req.content) if req.content else {}
        if path == "/nitro/v1/config/sslcertkey/app_cert":
            return httpx.Response(200, json={"sslcertkey": [{"certkey": "app_cert", "cert": "o.crt", "key": "o.key"}]})
        if path == "/nitro/v1/config/sslcertkey" and req.method == "GET":
            return httpx.Response(200, json={"sslcertkey": [{"certkey": "le_r11", "serial": format(inter.serial_number, "X")}]})
        if path == "/nitro/v1/config/sslcertkey" and action is None:
            return httpx.Response(599, json={"errorcode": 1540, "message": "Certificate already exists"})
        if action == "link":
            links.append(body["sslcertkey"]["linkcertkeyname"])
        return httpx.Response(200, json={})

    CitrixConnector.transport = httpx.MockTransport(h)
    make_connector("citrix", {"url": "https://adc", "username": "u", "password": "p", "certkey": "app_cert"},
                   tmp_path).deploy(bundle)
    assert links == ["le_r11"]


def test_iis_binds_the_leaf_by_thumbprint(tmp_path, bundle, monkeypatch):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    fake = FakeSsh()
    monkeypatch.setattr("farrier.connectors.iis.subprocess.run", fake)
    make_connector("iis", {"ssh": "a@b", "site": "s"}, tmp_path).deploy(bundle)
    thumb = x509.load_pem_x509_certificate(bundle.cert_pem.encode()).fingerprint(hashes.SHA1()).hex().upper()
    assert f"Cert:\LocalMachine\My\{thumb}" in fake.scripts[0] and f"AddSslCertificate('{thumb}', 'My')" in fake.scripts[0]
    assert "HasPrivateKey" in fake.scripts[0]
