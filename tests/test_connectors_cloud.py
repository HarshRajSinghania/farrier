"""Azure Key Vault and Google Cloud certificate connectors against fake Key Vault, Resource Manager,
Certificate Manager and Compute endpoints (httpx.MockTransport; nothing touches the network)."""
import base64
import json
import uuid

import httpx
import pytest
from conftest import issue_initial
from cryptography.hazmat.primitives.serialization import NoEncryption, pkcs12

from farrier.connectors import Bundle, DeployError, make_connector
from farrier.connectors.azure_keyvault import AzureKeyVaultConnector
from farrier.connectors.gcp_certificate_manager import GcpCertificateManagerConnector
from farrier.connectors.keystore import build_pkcs12
from farrier.core.x509util import build_csr, generate_key, key_to_pem, split_pem_chain
from farrier.issuers.local_ca import LocalCA
from farrier.security.cloud_auth import http as cloud_http

VAULT = "https://kv1.vault.azure.net"
GW = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Network/applicationGateways/agw"
PROFILE = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Cdn/profiles/afd"
DOMAIN = f"{PROFILE}/customDomains/www"
DOMAIN2 = f"{PROFILE}2/customDomains/api"      # a second profile, so it gets its own pinned secret
KV_SOURCE = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1/secrets/app"


class Tokens:
    def token(self, scope=None):
        return "tok"


def _bundle(ca, kind="ec256"):
    key = generate_key(kind)
    cert, chain = ca.issue(build_csr(key, "app.example.test", ["app.example.test"]), ["app.example.test"])
    c = split_pem_chain(cert + chain)
    return Bundle("app-01", 7, key_to_pem(key), c[0], "".join(c[1:]), "2027-01-01T00:00:00+00:00")


@pytest.fixture
def bundle(tmp_path):
    key, full = issue_initial(LocalCA(tmp_path), "app.example.test", 47)
    c = split_pem_chain(full)
    return Bundle("app-01", 7, key, c[0], "".join(c[1:]), "2027-01-01T00:00:00+00:00")


@pytest.fixture
def fake(monkeypatch):
    calls = []

    def route(handler):
        def h(req):
            assert req.headers["Authorization"] == "Bearer tok"
            calls.append(req)
            return handler(req, json.loads(req.content) if req.content else {})
        cloud_http.set_client(httpx.Client(transport=httpx.MockTransport(h)))
    monkeypatch.setattr(cloud_http, "sleep", lambda s: None)
    AzureKeyVaultConnector.tokens = GcpCertificateManagerConnector.tokens = Tokens()
    yield route, calls
    cloud_http.set_client(None)
    AzureKeyVaultConnector.tokens = GcpCertificateManagerConnector.tokens = None


# ---- Azure Key Vault ----------------------------------------------------------------------------
class KeyVault:
    """Certificate versions, an application gateway and a Front Door profile."""

    def __init__(self, versions=()):
        self.versions = [dict(v) for v in versions]   # {"v", "value", "contentType", "pwd", "enabled"}
        self.gw_tags = {"env": "prod"}
        self.afd_secrets = {f"{p}/secrets/old": {"properties": {"provisioningState": "Succeeded", "parameters": {
            "type": "CustomerCertificate", "secretSource": {"id": KV_SOURCE}, "useLatestVersion": False}}}
            for p in (PROFILE, PROFILE + "2")}
        self.domains = {d: {"certificateType": "CustomerCertificate", "minimumTlsVersion": "TLS12",
                            "secret": {"id": f"{d.split('/customDomains/')[0]}/secrets/old"}} for d in (DOMAIN, DOMAIN2)}
        self.failing = set()    # profiles whose new Front Door secrets end Failed

    def __call__(self, req, body):
        path, host = req.url.path, req.url.host
        if host == "kv1.vault.azure.net":
            assert req.url.params["api-version"] == "7.4"
            if path == "/certificates/app" and req.method == "GET":
                if not self.versions:
                    return httpx.Response(404, json={"error": {"code": "CertificateNotFound"}})
                return httpx.Response(200, json={"id": f"{VAULT}/certificates/app/{self.versions[-1]['v']}"})
            if path == "/certificates/app/import":
                v = uuid.uuid4().hex
                self.versions.append({"v": v, "value": body["value"], "pwd": body.get("pwd"), "enabled": True,
                                      "contentType": body["policy"]["secret_props"]["contentType"]})
                assert body["policy"]["key_props"]["exportable"] is True
                return httpx.Response(200, json={"id": f"{VAULT}/certificates/app/{v}"})
            if path.startswith("/secrets/app/"):
                v = next(x for x in self.versions if x["v"] == path.rsplit("/", 1)[1])
                return httpx.Response(200, json={"value": v["value"], "contentType": v["contentType"]})
            if path.startswith("/certificates/app/") and req.method == "PATCH":
                next(x for x in self.versions if x["v"] == path.rsplit("/", 1)[1])["enabled"] = body["attributes"]["enabled"]
                return httpx.Response(200, json={})
        if host == "management.azure.com":
            if path == GW:
                if req.method == "PATCH":
                    self.gw_tags = body["tags"]
                return httpx.Response(200, json={"tags": self.gw_tags})
            if path in self.domains:
                if req.method == "PATCH":
                    self.domains[path] = body["properties"]["tlsSettings"]
                return httpx.Response(200, json={"properties": {"tlsSettings": self.domains[path]}})
            if "/Microsoft.Cdn/profiles/" in path and "/secrets/" in path:
                if req.method == "PUT":
                    self.afd_secrets[path] = {"properties": {**body["properties"], "provisioningState": "Creating"}}
                    return httpx.Response(201, json=self.afd_secrets[path])
                s = self.afd_secrets[path]
                out = json.loads(json.dumps(s))
                done = "Failed" if path.split("/secrets/")[0] in self.failing else "Succeeded"
                s["properties"]["provisioningState"] = done   # the next poll sees it finished
                return httpx.Response(200, json=out)
        return httpx.Response(404, json={"error": {"code": "NotFound", "message": f"{req.method} {path}"}})


def _kv(tmp_path, **extra):
    return make_connector("azure_keyvault", {"vault": VAULT, "certificate": "app", **extra}, tmp_path)


def _pfx_with_key(b):
    """A Key Vault-style secret value: base64 PFX, no password, key included."""
    key, cert, cas = pkcs12.load_key_and_certificates(build_pkcs12(b, "x", "pw"), b"pw")
    return base64.b64encode(pkcs12.serialize_key_and_certificates(b"x", key, cert, cas, NoEncryption())).decode()


def test_keyvault_imports_new_version_refreshes_gateway_and_rolls_back_by_reimport(tmp_path, bundle, fake):
    route, _ = fake
    old = _pfx_with_key(bundle)
    kv = KeyVault([{"v": "a" * 32, "value": old, "contentType": "application/x-pkcs12", "enabled": True}])
    route(kv)
    c = _kv(tmp_path, refresh={"application_gateway": GW})
    token = c.deploy(bundle)
    new = kv.versions[-1]
    assert token == {"version": new["v"], "previous": "a" * 32, "front_door": {}}
    key, cert, cas = pkcs12.load_key_and_certificates(base64.b64decode(new["value"]), new["pwd"].encode())
    assert key is not None and cas and cert.subject.rfc4514_string() == "CN=app.example.test"
    assert kv.gw_tags["env"] == "prod" and "farrier-refresh" in kv.gw_tags
    kv.gw_tags.pop("farrier-refresh")

    c.rollback(token)
    assert kv.versions[-1]["value"] == old and len(kv.versions) == 3   # previous material is newest again
    assert "farrier-refresh" in kv.gw_tags                              # and the gateway re-read it


def test_keyvault_first_import_rollback_disables_it(tmp_path, bundle, fake):
    route, _ = fake
    kv = KeyVault()
    route(kv)
    c = _kv(tmp_path)
    token = c.deploy(bundle)
    assert token["previous"] is None
    c.rollback(token)
    assert kv.versions[0]["enabled"] is False and len(kv.versions) == 1


def test_keyvault_rollback_refuses_unsafe_cases(tmp_path, bundle, fake):
    route, _ = fake
    pem_without_key = bundle.cert_pem
    kv = KeyVault([{"v": "a" * 32, "value": pem_without_key, "contentType": "application/x-pem-file"}])
    route(kv)
    c = _kv(tmp_path)
    token = c.deploy(bundle)
    with pytest.raises(DeployError, match="non-exportable key"):
        c.rollback(token)
    c.deploy(bundle)                              # someone (here: Farrier again) imported a newer version
    with pytest.raises(DeployError, match="not rolling back over it"):
        c.rollback(token)


def test_keyvault_front_door_pins_new_version_and_switches_back(tmp_path, fake):
    route, _ = fake
    rsa_bundle = _bundle(LocalCA(tmp_path), "rsa2048")
    kv = KeyVault()
    route(kv)
    c = _kv(tmp_path, refresh={"front_door": [DOMAIN]})
    token = c.deploy(rsa_bundle)
    v = kv.versions[-1]["v"]
    pinned = f"{PROFILE}/secrets/farrier-app-{v[:12]}"
    p = kv.afd_secrets[pinned]["properties"]["parameters"]
    assert p == {"type": "CustomerCertificate", "secretSource": {"id": KV_SOURCE}, "secretVersion": v,
                 "useLatestVersion": False}
    assert kv.domains[DOMAIN] == {"certificateType": "CustomerCertificate", "minimumTlsVersion": "TLS12",
                             "secret": {"id": pinned}}
    assert token["front_door"] == {DOMAIN: f"{PROFILE}/secrets/old"}
    c.rollback(token)
    assert kv.domains[DOMAIN]["secret"]["id"] == f"{PROFILE}/secrets/old"


def test_keyvault_failed_deploy_undoes_switched_domains_and_restores_version(tmp_path, fake):
    route, _ = fake
    rsa_bundle = _bundle(LocalCA(tmp_path), "rsa2048")
    old = _pfx_with_key(rsa_bundle)
    kv = KeyVault([{"v": "a" * 32, "value": old, "contentType": "application/x-pkcs12", "enabled": True}])
    kv.failing.add(PROFILE + "2")
    route(kv)
    c = _kv(tmp_path, refresh={"front_door": [DOMAIN, DOMAIN2], "application_gateway": GW})
    with pytest.raises(DeployError) as e:
        c.deploy(rsa_bundle)
    msg = str(e.value)
    assert "is Failed, not Succeeded" in msg and "undone" in msg
    assert f"switched Front Door domain {DOMAIN} back" in msg and f"re-imported previous version {'a' * 32}" in msg
    assert kv.domains[DOMAIN]["secret"]["id"] == f"{PROFILE}/secrets/old"         # domain 1 switched back
    assert kv.domains[DOMAIN2]["secret"]["id"] == f"{PROFILE}2/secrets/old"       # domain 2 never moved
    assert kv.versions[-1]["value"] == old and len(kv.versions) == 3             # previous material is current


def test_keyvault_failed_deploy_says_when_previous_version_cannot_return(tmp_path, fake):
    route, _ = fake
    kv = KeyVault([{"v": "a" * 32, "value": "no key here", "contentType": "application/x-pem-file"}])
    kv.failing.add(PROFILE)
    route(kv)
    c = _kv(tmp_path, refresh={"front_door": DOMAIN})
    with pytest.raises(DeployError) as e:
        c.deploy(_bundle(LocalCA(tmp_path), "rsa2048"))
    new = kv.versions[-1]["v"]
    assert "is Failed, not Succeeded; undoing it failed" in str(e.value)
    assert "non-exportable key" in str(e.value) and f"version {new} stays current" in str(e.value)
    assert len(kv.versions) == 2


def test_keyvault_front_door_refuses_ec_and_foreign_certificates(tmp_path, bundle, fake):
    route, calls = fake
    kv = KeyVault()
    route(kv)
    with pytest.raises(DeployError, match="elliptic-curve"):
        _kv(tmp_path, refresh={"front_door": DOMAIN}).deploy(bundle)    # the fixture's key is P-256
    assert calls == []
    kv.afd_secrets[f"{PROFILE}/secrets/old"]["properties"]["parameters"]["secretSource"]["id"] = KV_SOURCE + "-other"
    with pytest.raises(DeployError, match="not app"):
        _kv(tmp_path, refresh={"front_door": DOMAIN}).deploy(_bundle(LocalCA(tmp_path), "rsa2048"))


def test_keyvault_errors_and_config(tmp_path, bundle, fake):
    route, _ = fake
    route(lambda req, body: httpx.Response(403, json={"error": {"code": "Forbidden", "message": "no access"}}))
    with pytest.raises(DeployError, match="403 Forbidden"):
        _kv(tmp_path).deploy(bundle)
    with pytest.raises(ValueError, match="vault"):
        make_connector("azure_keyvault", {"vault": "https://evil.example.com", "certificate": "app"}, tmp_path)
    with pytest.raises(ValueError, match="resource id"):
        _kv(tmp_path, refresh={"application_gateway": DOMAIN})
    with pytest.raises(ValueError, match="refresh 'app_service'"):
        _kv(tmp_path, refresh={"app_service": GW})


# ---- Google Cloud -------------------------------------------------------------------------------
CERT = "projects/p1/locations/global/certificates/app"
COMPUTE = "/compute/v1/projects/p1/global"


class Google:
    def __init__(self, existing=None):
        self.cert = existing                  # Certificate Manager certificate body, or None
        self.ssl = {}
        self.proxy = [f"https://compute.googleapis.com{COMPUTE}/sslCertificates/old"]
        self.op_error = None

    def __call__(self, req, body):
        path, m = req.url.path, req.method
        done = {"name": "operations/op1", "done": True, **({"error": self.op_error} if self.op_error else {})}
        if path == f"/v1/{CERT}":
            if m == "GET":
                return httpx.Response(200, json=self.cert) if self.cert else httpx.Response(404, json={})
            if m == "PATCH":
                assert req.url.params["updateMask"] == "selfManaged"
                self.cert.update(body)
            if m == "DELETE":
                self.cert = None
            return httpx.Response(200, json=done)
        if path == "/v1/projects/p1/locations/global/certificates" and m == "POST":
            assert req.url.params["certificateId"] == "app"
            self.cert = body
            return httpx.Response(200, json={"name": "operations/op1", "done": False})
        if path == "/v1/operations/op1":
            return httpx.Response(200, json=done)
        if path == f"{COMPUTE}/sslCertificates":
            self.ssl[body["name"]] = body
            return httpx.Response(200, json={"name": "op2", "status": "RUNNING"})
        if path == f"{COMPUTE}/operations/op2/wait":
            return httpx.Response(200, json={"name": "op2", "status": "DONE"})
        if path == f"{COMPUTE}/targetHttpsProxies/web":
            return httpx.Response(200, json={"sslCertificates": self.proxy})
        if path == f"{COMPUTE}/targetHttpsProxies/web/setSslCertificates":
            self.proxy = body["sslCertificates"]
            return httpx.Response(200, json={"name": "op2", "status": "DONE"})
        return httpx.Response(404, json={"error": {"message": f"{m} {path}"}})


def _gcp(tmp_path, **cfg):
    return make_connector("gcp_certificate_manager", {"project": "p1", **cfg}, tmp_path)


def test_gcp_patches_certificate_and_switches_proxy_rollback_is_honest(tmp_path, bundle, fake):
    route, _ = fake
    g = Google({"name": CERT, "selfManaged": {}})
    route(g)
    c = _gcp(tmp_path, certificate="app", target_https_proxies=["web"])
    token = c.deploy(bundle)
    assert g.cert["selfManaged"] == {"pemCertificate": bundle.fullchain_pem, "pemPrivateKey": bundle.key_pem}
    (name, ssl), = g.ssl.items()
    assert name == "farrier-app-01-20270101-7" and ssl["privateKey"] == bundle.key_pem
    assert g.proxy == [f"https://compute.googleapis.com{COMPUTE}/sslCertificates/{name}"]
    with pytest.raises(DeployError, match="never returns a private key"):
        c.rollback(token)
    assert g.proxy[0].endswith("/sslCertificates/old")     # the proxy was still restored


def test_gcp_creates_certificate_and_rollback_deletes_it(tmp_path, bundle, fake):
    route, _ = fake
    g = Google()
    route(g)
    c = _gcp(tmp_path, certificate="app")
    token = c.deploy(bundle)
    assert token == {"created": True} and g.cert["labels"] == {"managed-by": "farrier"}
    c.rollback(token)
    assert g.cert is None


def test_gcp_refuses_managed_certificates_and_reports_operation_errors(tmp_path, bundle, fake):
    route, _ = fake
    g = Google({"name": CERT, "managed": {"domains": ["app.example.test"]}})
    route(g)
    with pytest.raises(DeployError, match="Google-managed"):
        _gcp(tmp_path, certificate="app").deploy(bundle)
    g.cert, g.op_error = {"name": CERT, "selfManaged": {}}, {"code": 3, "message": "certificate and key do not match"}
    with pytest.raises(DeployError, match="do not match"):
        _gcp(tmp_path, certificate="app").deploy(bundle)
    with pytest.raises(ValueError, match="certificate, target_https_proxies"):
        _gcp(tmp_path)
    with pytest.raises(ValueError, match="not a valid"):
        _gcp(tmp_path, certificate="App/../x")
