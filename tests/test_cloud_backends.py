"""Cloud identity, secret backends, KMS master key, object storage, backups and event publishing.

Every provider call goes to an httpx.MockTransport fake; nothing touches the network."""
from __future__ import annotations

import base64
import io
import json
import os
import time
import zipfile
from pathlib import Path
from urllib.parse import parse_qs, unquote

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from farrier.security import cloud_auth, vault
from farrier.security.cloud_auth import http as cloud_http
from farrier.security.cloud_auth.hashicorp import VaultAuth
from farrier.security.secret_backends import external, make_backend
from farrier.security.vault import SecretRefused, resolve_secret

SCHEMA = Path(__file__).resolve().parents[1] / "events" / "schema" / "renewal-event.schema.json"
ENV_PREFIXES = ("AWS_", "GOOGLE_", "GCE_", "GCLOUD_", "AZURE_", "IDENTITY_", "VAULT_", "FARRIER_SECRET_",
                "FARRIER_MASTER_KEY", "FARRIER_STORAGE_", "FARRIER_INSTANCE_ID", "FARRIER_API_")
WEB = {"AccessKeyId": "ASIAWEB", "SecretAccessKey": "web-secret-key", "SessionToken": "web-session"}


# ---- fakes ---------------------------------------------------------------------------------------
class Cloud:
    """Routes requests by host (and path prefix) to handlers; records every request."""

    def __init__(self):
        self.calls: list[httpx.Request] = []
        self.routes: list[tuple[str, str, object]] = []

    def on(self, host: str, handler, prefix: str = ""):
        self.routes.insert(0, (host, prefix, handler))

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.calls.append(req)
        for host, prefix, h in self.routes:
            if req.url.host == host and req.url.path.startswith(prefix):
                return h(req)
        return httpx.Response(418, text=f"no fake for {req.method} {req.url.host}{req.url.path}")

    def to(self, host: str, path: str = "") -> list[httpx.Request]:
        return [r for r in self.calls if r.url.host == host and r.url.path.startswith(path)]


@pytest.fixture
def cloud(monkeypatch):
    for k in list(os.environ):
        if k.startswith(ENV_PREFIXES):
            monkeypatch.delenv(k, raising=False)
    c = Cloud()
    cloud_http.set_client(httpx.Client(transport=httpx.MockTransport(c)))
    monkeypatch.setattr(cloud_http, "sleep", lambda s: None)
    cloud_auth.reset()
    external.reset()
    vault._unwrapped.clear()
    yield c
    cloud_http.set_client(None)
    cloud_auth.reset()
    external.reset()
    vault._unwrapped.clear()


def aws_error(code: str, status=400):
    return httpx.Response(status, json={"__type": f"com.amazonaws.secretsmanager#{code}", "message": code})


def fake_sts(cloud: Cloud, host="sts.us-east-1.amazonaws.com"):
    def h(req):
        creds = "".join(f"<{k}>{v}</{k}>" for k, v in WEB.items())
        return httpx.Response(200, text=(
            '<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
            f"<AssumeRoleWithWebIdentityResult><Credentials>{creds}<Expiration>2099-01-01T00:00:00Z</Expiration>"
            "</Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>"))
    cloud.on(host, h)


def fake_secrets_manager(cloud: Cloud, region="eu-west-1"):
    state: dict[str, dict] = {}

    def arn(name):
        return f"arn:aws:secretsmanager:{region}:123456789012:secret:{name}-AbCdEf"

    def name_of(sid):
        return sid.split(":secret:", 1)[1].rsplit("-", 1)[0] if sid.startswith("arn:") else sid

    def h(req):
        target = req.headers["X-Amz-Target"].split(".", 1)[1]
        b = json.loads(req.content)
        if target == "CreateSecret":
            state[b["Name"]] = {"value": b["SecretString"], "kms": b.get("KmsKeyId")}
            return httpx.Response(200, json={"ARN": arn(b["Name"]), "Name": b["Name"]})
        name = name_of(b["SecretId"])
        if name not in state:
            return aws_error("ResourceNotFoundException")
        if target == "PutSecretValue":
            state[name]["value"] = b["SecretString"]
            return httpx.Response(200, json={"ARN": arn(name)})
        if target == "GetSecretValue":
            return httpx.Response(200, json={"ARN": arn(name), "SecretString": state[name]["value"]})
        if target == "DeleteSecret":
            state[name]["deleted"] = b["RecoveryWindowInDays"]
            return httpx.Response(200, json={"ARN": arn(name)})
        return aws_error("InvalidAction")
    cloud.on(f"secretsmanager.{region}.amazonaws.com", h)
    return state


def fake_gcp_metadata(cloud: Cloud):
    def h(req):
        assert req.headers["Metadata-Flavor"] == "Google"
        return httpx.Response(200, json={"access_token": "gcp-meta-token", "expires_in": 3600})
    cloud.on("metadata.google.internal", h)


def fake_azure_imds(cloud: Cloud):
    def h(req):
        assert req.headers["Metadata"] == "true"
        return httpx.Response(200, json={"access_token": "az-" + req.url.params["resource"],
                                         "expires_on": str(int(time.time()) + 3600)})
    cloud.on("169.254.169.254", h, "/metadata/identity")


def env_aws_irsa(monkeypatch, tmp_path):
    tok = tmp_path / "web-identity-token"
    tok.write_text("projected-sa-jwt\n")
    monkeypatch.setenv("AWS_WEB_IDENTITY_TOKEN_FILE", str(tok))
    monkeypatch.setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/farrier")
    monkeypatch.setenv("AWS_REGION", "us-east-1")


# ---- AWS -------------------------------------------------------------------------------------------
def test_aws_secrets_manager_through_irsa(cloud, data_dir, monkeypatch, tmp_path):
    env_aws_irsa(monkeypatch, tmp_path)
    fake_sts(cloud)
    state = fake_secrets_manager(cloud)
    monkeypatch.setenv("FARRIER_SECRET_BACKEND", "aws")
    monkeypatch.setenv("FARRIER_SECRET_AWS_REGION", "eu-west-1")
    monkeypatch.setenv("FARRIER_SECRET_AWS_KMS_KEY", "alias/farrier")
    monkeypatch.setenv("FARRIER_API_TOKEN", "admin-tok")
    from farrier.api.app import create_app
    from farrier.core.engine import Engine
    eng = Engine(data_dir)
    c = TestClient(create_app(eng))
    h = {"Authorization": "Bearer admin-tok"}

    assert c.get("/api/secrets/backend", headers=h).json() == {
        "backend": "aws", "location": "AWS Secrets Manager eu-west-1, prefix farrier/", "writable": True}
    assert c.put("/api/secrets/cf-token", json={"value": "s3cr3t-v1"}, headers=h).status_code == 200
    assert state["farrier/cf-token"] == {"value": "s3cr3t-v1", "kms": "alias/farrier"}   # CreateSecret
    c.put("/api/secrets/cf-token", json={"value": "s3cr3t-v2"}, headers=h)                 # PutSecretValue
    assert state["farrier/cf-token"]["value"] == "s3cr3t-v2"
    row = eng.store.q1("SELECT * FROM secrets WHERE name='cf-token'")
    assert row["backend"] == "aws" and row["ref"].startswith("arn:aws:secretsmanager:eu-west-1:")
    assert eng.store.q1("SELECT COUNT(*) AS n FROM secret_values")["n"] == 0             # nothing local

    assert resolve_secret("vault:cf-token") == "s3cr3t-v2"
    assert resolve_secret("vault:cf-token") == "s3cr3t-v2"                                  # cached
    targets = [r.headers["X-Amz-Target"] for r in cloud.to("secretsmanager.eu-west-1.amazonaws.com")]
    assert targets == ["secretsmanager.PutSecretValue", "secretsmanager.CreateSecret",
                       "secretsmanager.PutSecretValue", "secretsmanager.GetSecretValue"]

    # SigV4 with the web-identity session; STS called once (credentials cached)
    req = cloud.to("secretsmanager.eu-west-1.amazonaws.com")[-1]
    assert req.headers["Authorization"].startswith("AWS4-HMAC-SHA256 Credential=ASIAWEB/")
    assert "/eu-west-1/secretsmanager/aws4_request" in req.headers["Authorization"]
    assert req.headers["X-Amz-Security-Token"] == "web-session" and req.headers["X-Amz-Date"]
    (sts,) = cloud.to("sts.us-east-1.amazonaws.com")
    form = parse_qs(sts.content.decode())
    assert form["Action"] == ["AssumeRoleWithWebIdentity"] and form["WebIdentityToken"] == ["projected-sa-jwt"]
    assert form["RoleArn"] == ["arn:aws:iam::123456789012:role/farrier"]

    assert c.delete("/api/secrets/cf-token", headers=h).json() == {"ok": True}
    assert state["farrier/cf-token"]["deleted"] == 7
    # no value in the event log or the index
    assert "s3cr3t" not in c.get("/api/events", headers=h).text
    assert "s3cr3t" not in json.dumps(eng.store.q("SELECT * FROM secrets"))


def test_switching_backend_keeps_existing_secrets(cloud, data_dir, monkeypatch, tmp_path):
    from farrier.core.engine import Engine
    Engine(data_dir).secrets.put("old", "local-value")
    env_aws_irsa(monkeypatch, tmp_path)
    fake_sts(cloud)
    fake_secrets_manager(cloud)
    monkeypatch.setenv("FARRIER_SECRET_BACKEND", "aws")
    monkeypatch.setenv("FARRIER_SECRET_AWS_REGION", "eu-west-1")
    eng = Engine(data_dir)
    eng.secrets.put("new", "cloud-value")
    assert resolve_secret("vault:old") == "local-value" and resolve_secret("vault:new") == "cloud-value"
    assert {r["name"]: r["backend"] for r in eng.secrets.list()} == {"new": "aws", "old": "local"}
    # and back again: the aws secret still resolves from Secrets Manager
    monkeypatch.setenv("FARRIER_SECRET_BACKEND", "local")
    assert Engine(data_dir).secrets.get("new") == "cloud-value"


def test_backend_settings_are_named_in_errors(cloud, monkeypatch):
    for kind, setting in (("aws", "FARRIER_SECRET_AWS_REGION"), ("gcp", "FARRIER_SECRET_GCP_PROJECT"),
                          ("azure", "FARRIER_SECRET_AZURE_VAULT_URL"), ("hashicorp", "FARRIER_SECRET_VAULT_ADDR")):
        with pytest.raises(ValueError, match=setting):
            make_backend(kind, None)
    monkeypatch.setenv("FARRIER_SECRET_AZURE_VAULT_URL", "https://evil.example.com")
    with pytest.raises(ValueError, match="vault.azure.net"):
        make_backend("azure", None)


def test_external_references_and_allowlist(cloud, monkeypatch, tmp_path):
    env_aws_irsa(monkeypatch, tmp_path)
    fake_sts(cloud)
    state = fake_secrets_manager(cloud)
    state["farrier/db"] = {"value": "db-pass"}
    state["other/x"] = {"value": "not-yours"}
    ours = "aws-sm:arn:aws:secretsmanager:eu-west-1:123456789012:secret:farrier/db-AbCdEf"
    theirs = "aws-sm:arn:aws:secretsmanager:eu-west-1:123456789012:secret:other/x-AbCdEf"
    assert vault.is_ref(ours)

    with pytest.raises(SecretRefused, match="FARRIER_SECRET_BACKEND=local"):   # default: local allows none
        resolve_secret(ours)
    monkeypatch.setenv("FARRIER_SECRET_BACKEND", "aws")
    monkeypatch.setenv("FARRIER_SECRET_AWS_REGION", "eu-west-1")
    external.reset()
    assert resolve_secret(ours) == "db-pass"                                    # under the backend's prefix
    with pytest.raises(SecretRefused, match="prefix"):
        resolve_secret(theirs)
    monkeypatch.setenv("FARRIER_SECRET_EXTERNAL_PREFIXES",
                       "aws-sm:arn:aws:secretsmanager:eu-west-1:123456789012:secret:other/")
    assert resolve_secret(theirs) == "not-yours"
    with pytest.raises(SecretRefused, match="FARRIER_SECRET_EXTERNAL_PREFIXES"):
        resolve_secret(ours)
    # a token is never sent to a host that is not Key Vault, whatever the allowlist says
    monkeypatch.setenv("FARRIER_SECRET_EXTERNAL_PREFIXES", "azure-kv:")
    with pytest.raises(SecretRefused, match="Key Vault|vault.azure.net"):
        resolve_secret("azure-kv:https://evil.example.com/secrets/x")
    with pytest.raises(SecretRefused):
        resolve_secret("hcvault:secret/../../sys/x")


# ---- Google ----------------------------------------------------------------------------------------
def test_gcp_metadata_token_and_secret_manager(cloud, monkeypatch):
    fake_gcp_metadata(cloud)
    secrets: dict[str, list[str]] = {}

    def sm(req):
        p = req.url.path
        assert req.headers["Authorization"] == "Bearer gcp-meta-token"
        if p.endswith(":addVersion"):
            sid = p.split("/secrets/")[1].split(":")[0]
            if sid not in secrets:
                return httpx.Response(404, json={"error": {"code": 404, "status": "NOT_FOUND"}})
            secrets[sid].append(base64.b64decode(json.loads(req.content)["payload"]["data"]).decode())
            return httpx.Response(200, json={"name": f"projects/123/secrets/{sid}/versions/{len(secrets[sid])}"})
        if p == "/v1/projects/proj-123/secrets" and req.method == "POST":
            assert json.loads(req.content)["replication"] == {"automatic": {}}
            secrets[req.url.params["secretId"]] = []
            return httpx.Response(200, json={})
        if p.endswith("/versions/latest:access"):
            sid = p.split("/secrets/")[1].split("/")[0]
            if not secrets.get(sid):
                return httpx.Response(404, json={})
            return httpx.Response(200, json={"payload": {"data": base64.b64encode(secrets[sid][-1].encode()).decode()}})
        if req.method == "DELETE":
            secrets.pop(p.split("/secrets/")[1], None)
            return httpx.Response(200, json={})
        return httpx.Response(400)
    cloud.on("secretmanager.googleapis.com", sm)
    monkeypatch.setenv("FARRIER_SECRET_GCP_PROJECT", "proj-123")
    b = make_backend("gcp", None)
    ref = b.put("cf-token", "gcp-secret")
    assert ref == "projects/proj-123/secrets/farrier-cf-token" and secrets["farrier-cf-token"] == ["gcp-secret"]
    b.put("cf-token", "gcp-secret-2")                          # a new version, no create
    assert secrets["farrier-cf-token"] == ["gcp-secret", "gcp-secret-2"]
    assert b.get(ref) == "gcp-secret-2"
    assert b.put("a.b", "x") == "projects/proj-123/secrets/farrier-a_2eb"   # escaped, never colliding with a_b
    assert b.put("a_b", "y") == "projects/proj-123/secrets/farrier-a_5fb"
    assert b.external(ref) == "gcp-sm:projects/proj-123/secrets/farrier-cf-token/versions/latest"
    assert b.describe() == {"kind": "gcp", "location": "Google Secret Manager project proj-123, prefix farrier-"}
    b.delete(ref)
    assert b.get(ref) is None
    assert len(cloud.to("metadata.google.internal")) == 1     # token cached


def test_gcp_workload_identity_federation(cloud, monkeypatch, tmp_path):
    subject = tmp_path / "oidc-token"
    subject.write_text("k8s-oidc-jwt")
    cred = tmp_path / "wif.json"
    cred.write_text(json.dumps({"type": "external_account",
                                "audience": "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/k",
                                "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
                                "token_url": "https://sts.googleapis.com/v1/token",
                                "credential_source": {"file": str(subject)}}))
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(cred))
    cloud.on("sts.googleapis.com", lambda req: httpx.Response(200, json={"access_token": "federated", "expires_in": 3600}))
    from farrier.security.cloud_auth.google import GoogleTokenProvider
    assert GoogleTokenProvider().token() == "federated"
    form = parse_qs(cloud.to("sts.googleapis.com")[0].content.decode())
    assert form["grant_type"] == ["urn:ietf:params:oauth:grant-type:token-exchange"]
    assert form["subject_token"] == ["k8s-oidc-jwt"]


# ---- Azure -----------------------------------------------------------------------------------------
def test_azure_imds_token_and_key_vault(cloud, monkeypatch):
    fake_azure_imds(cloud)
    kv: dict[str, str] = {"deleted": {}}
    seen = {}

    def vault_api(req):
        assert req.headers["Authorization"] == "Bearer az-https://vault.azure.net"
        assert req.url.params["api-version"] == "7.4"
        p = req.url.path
        if p.startswith("/deletedsecrets/") and p.endswith("/recover"):
            name = p.split("/")[2]
            kv[name] = kv["deleted"].pop(name)
            return httpx.Response(200, json={})
        name = p.split("/")[2]
        if req.method == "PUT":
            if name in kv["deleted"]:
                return httpx.Response(409, json={"error": {"code": "ObjectIsDeletedButRecoverable"}})
            kv[name] = json.loads(req.content)["value"]
            seen["put"] = name
            return httpx.Response(200, json={"id": f"https://kv1.vault.azure.net/secrets/{name}/" + "a" * 32})
        if req.method == "GET":
            return httpx.Response(200, json={"value": kv[name]}) if name in kv else httpx.Response(404, json={})
        if req.method == "DELETE":
            kv["deleted"][name] = kv.pop(name)
            return httpx.Response(200, json={})
        return httpx.Response(400)
    cloud.on("kv1.vault.azure.net", vault_api)
    monkeypatch.setenv("FARRIER_SECRET_AZURE_VAULT_URL", "https://kv1.vault.azure.net/")
    b = make_backend("azure", None)
    ref = b.put("cf-token", "azure-secret")
    assert ref == "https://kv1.vault.azure.net/secrets/farrier-cf-2dtoken" and kv["farrier-cf-2dtoken"] == "azure-secret"
    assert b.get(ref) == "azure-secret"
    b.delete(ref)
    assert "farrier-cf-2dtoken" in kv["deleted"]                    # soft-deleted, not purged
    assert b.get(ref) is None
    b.put("cf-token", "again")                                      # recovered, then set
    assert kv["farrier-cf-2dtoken"] == "again"
    assert b.external(ref) == "azure-kv:" + ref
    assert len(cloud.to("169.254.169.254")) == 1                   # token cached per scope


def test_azure_workload_identity_assertion(cloud, monkeypatch, tmp_path):
    tok = tmp_path / "azure-token"
    tok.write_text("projected-azure-jwt")
    monkeypatch.setenv("AZURE_FEDERATED_TOKEN_FILE", str(tok))
    monkeypatch.setenv("AZURE_CLIENT_ID", "client-1")
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant-1")
    cloud.on("login.microsoftonline.com", lambda r: httpx.Response(200, json={"access_token": "wi", "expires_in": 3600}))
    from farrier.security.cloud_auth.azure import EVENTGRID_SCOPE, AzureTokenProvider
    assert AzureTokenProvider().token(EVENTGRID_SCOPE) == "wi"
    req = cloud.to("login.microsoftonline.com", "/tenant-1/oauth2/v2.0/token")[0]
    form = parse_qs(req.content.decode())
    assert form["client_assertion"] == ["projected-azure-jwt"] and form["scope"] == [EVENTGRID_SCOPE]
    assert form["client_assertion_type"] == ["urn:ietf:params:oauth:client-assertion-type:jwt-bearer"]
    assert not cloud.to("169.254.169.254")


# ---- HashiCorp Vault -------------------------------------------------------------------------------
def test_vault_kubernetes_auth_kv2_and_renewal(cloud, monkeypatch, tmp_path):
    sa = tmp_path / "sa-token"
    sa.write_text("k8s-sa-jwt")
    monkeypatch.setenv("FARRIER_SECRET_VAULT_ADDR", "https://vault.test:8200")
    monkeypatch.setenv("FARRIER_SECRET_VAULT_ROLE", "farrier")
    monkeypatch.setenv("FARRIER_SECRET_VAULT_K8S_TOKEN_FILE", str(sa))
    monkeypatch.setenv("FARRIER_SECRET_VAULT_NAMESPACE", "pki")
    kv: dict[str, str] = {}
    tokens = iter(["hvs.login-1", "hvs.renewed"])

    def api(req):
        p = req.url.path
        assert req.headers["X-Vault-Namespace"] == "pki"
        if p == "/v1/auth/kubernetes/login":
            assert json.loads(req.content) == {"role": "farrier", "jwt": "k8s-sa-jwt"}
            return httpx.Response(200, json={"auth": {"client_token": next(tokens), "lease_duration": 3600,
                                                      "renewable": True}})
        if p == "/v1/auth/token/renew-self":
            assert req.headers["X-Vault-Token"] == "hvs.login-1"
            return httpx.Response(200, json={"auth": {"client_token": "hvs.login-1", "lease_duration": 3600,
                                                      "renewable": True}})
        assert req.headers["X-Vault-Token"] == "hvs.login-1"
        path = p.split("/data/", 1)[-1] if "/data/" in p else p.split("/metadata/", 1)[1]
        if req.method == "POST":
            kv[path] = json.loads(req.content)["data"]["value"]
            return httpx.Response(200, json={"data": {"version": 1}})
        if req.method == "GET":
            return httpx.Response(200, json={"data": {"data": {"value": kv[path]}}}) if path in kv \
                else httpx.Response(404, json={"errors": []})
        kv.pop(path, None)
        return httpx.Response(204)
    cloud.on("vault.test", api)
    b = make_backend("hashicorp", None)
    ref = b.put("cf", "vault-secret")
    assert ref == "secret/farrier/cf" and kv["farrier/cf"] == "vault-secret"
    assert b.get(ref) == "vault-secret"
    assert b.describe()["location"] == "Vault https://vault.test:8200 (namespace pki), KV v2 mount secret, prefix farrier/"
    b.auth._expires = time.time() + 60                   # a third of the TTL left: renew, don't log in again
    b._cache.clear()
    assert b.get("secret/data/farrier/cf#value") == "vault-secret"
    assert len(cloud.to("vault.test", "/v1/auth/kubernetes/login")) == 1
    assert len(cloud.to("vault.test", "/v1/auth/token/renew-self")) == 1
    b.delete(ref)
    assert cloud.calls[-1].url.path == "/v1/secret/metadata/farrier/cf" and not kv


def test_vault_token_from_env_needs_no_login(cloud, monkeypatch):
    monkeypatch.setenv("VAULT_TOKEN", "hvs.static")
    auth = VaultAuth("https://vault.test:8200")
    assert auth.headers() == {"X-Vault-Token": "hvs.static"}
    assert not cloud.calls


# ---- KMS-wrapped master key ------------------------------------------------------------------------
def _reverse_b64(s: str) -> str:
    return base64.b64encode(b"WRAPPED" + base64.b64decode(s)[::-1]).decode()


def _unreverse_b64(s: str) -> str:
    return base64.b64encode(base64.b64decode(s)[len(b"WRAPPED"):][::-1]).decode()


def _kms_fakes(cloud: Cloud, monkeypatch, kind: str) -> str:
    if kind == "aws":
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws-secret")

        def kms(req):
            assert req.headers["Authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/")
            b = json.loads(req.content)
            assert b["EncryptionContext"] == {"purpose": "farrier-master-key"}
            if req.headers["X-Amz-Target"] == "TrentService.Encrypt":
                return httpx.Response(200, json={"CiphertextBlob": _reverse_b64(b["Plaintext"]), "KeyId": b["KeyId"]})
            return httpx.Response(200, json={"Plaintext": _unreverse_b64(b["CiphertextBlob"])})
        cloud.on("kms.eu-west-1.amazonaws.com", kms)
        return "aws-kms:arn:aws:kms:eu-west-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"
    if kind == "gcp":
        fake_gcp_metadata(cloud)

        def kms(req):
            b = json.loads(req.content)
            if req.url.path.endswith(":encrypt"):
                return httpx.Response(200, json={"ciphertext": _reverse_b64(b["plaintext"])})
            return httpx.Response(200, json={"plaintext": _unreverse_b64(b["ciphertext"])})
        cloud.on("cloudkms.googleapis.com", kms)
        return "gcp-kms:projects/p1/locations/global/keyRings/farrier/cryptoKeys/master"
    fake_azure_imds(cloud)
    kid = "https://kv1.vault.azure.net/keys/master/" + "b" * 32
    b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()  # noqa: E731
    unb64u = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))  # noqa: E731

    def kv(req):
        b = json.loads(req.content)
        assert b["alg"] == "RSA-OAEP-256"
        if req.url.path == "/keys/master/wrapkey":
            return httpx.Response(200, json={"kid": kid, "value": b64u(b"WRAPPED" + unb64u(b["value"])[::-1])})
        assert req.url.path == f"/keys/master/{'b' * 32}/unwrapkey"
        return httpx.Response(200, json={"kid": kid, "value": b64u(unb64u(b["value"])[len(b"WRAPPED"):][::-1])})
    cloud.on("kv1.vault.azure.net", kv)
    return "azure-kv:https://kv1.vault.azure.net/keys/master"


def _files_contain(root: Path, needle: bytes) -> list[str]:
    return [str(p) for p in root.rglob("*") if p.is_file() and needle in p.read_bytes()]


@pytest.mark.parametrize("kind", ["aws", "gcp", "azure"])
def test_master_key_wrapped_by_kms(cloud, data_dir, monkeypatch, kind):
    from farrier.core.engine import Engine
    spec = _kms_fakes(cloud, monkeypatch, kind)
    monkeypatch.setenv("FARRIER_MASTER_KEY_KMS", spec)
    eng = Engine(data_dir)
    eng.secrets.put("db", "sealed-value")
    key = vault.master_key(data_dir)
    Fernet(key)
    assert not (data_dir / "master.key").exists()
    blob = json.loads((data_dir / "master.key.wrapped").read_text())
    assert blob["kms"] == spec and "ciphertext" in blob
    assert _files_contain(data_dir, key) == [] and _files_contain(data_dir, base64.urlsafe_b64decode(key)) == []
    wraps = len(cloud.calls)

    vault._unwrapped.clear()                             # a new process: unwrap once, same key
    eng2 = Engine(data_dir)
    assert eng2.secrets.get("db") == "sealed-value"
    assert vault.master_key(data_dir) == key
    assert len(cloud.calls) - wraps <= 2                 # one unwrap (+ one token fetch), then memory

    monkeypatch.setenv("FARRIER_MASTER_KEY_KMS", "aws-kms:arn:aws:kms:eu-west-1:123456789012:key/other")
    vault._unwrapped.clear()
    with pytest.raises(ValueError, match="FARRIER_MASTER_KEY_KMS"):
        vault.master_key(data_dir)


def test_kms_adopts_an_existing_plaintext_master_key(cloud, data_dir, monkeypatch):
    old = Fernet.generate_key()
    (data_dir / "master.key").write_bytes(old)
    monkeypatch.setenv("FARRIER_MASTER_KEY_KMS", _kms_fakes(cloud, monkeypatch, "aws"))
    assert vault.master_key(data_dir) == old
    assert not (data_dir / "master.key").exists() and _files_contain(data_dir, old) == []
    with pytest.raises(ValueError, match="FARRIER_MASTER_KEY_KMS"):
        monkeypatch.setenv("FARRIER_MASTER_KEY_KMS", "kms:nope")
        vault.master_key(data_dir)


# ---- object storage --------------------------------------------------------------------------------
def fake_s3(cloud: Cloud, host: str, path_style: bool):
    objects: dict[tuple[str, str], tuple[bytes, dict]] = {}

    def h(req):
        assert req.headers["Authorization"].startswith("AWS4-HMAC-SHA256 ")
        assert "x-amz-content-sha256" in req.headers["Authorization"]
        path = req.url.path
        if path_style:
            bucket, _, key = path.lstrip("/").partition("/")
        else:
            bucket, key = req.url.host.split(".", 1)[0], path.lstrip("/")
        if req.url.params.get("list-type") == "2":
            prefix = req.url.params.get("prefix", "")
            keys = "".join(f"<Contents><Key>{k}</Key></Contents>" for (b, k) in sorted(objects)
                           if b == bucket and k.startswith(prefix))
            return httpx.Response(200, text='<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                                            f"{keys}<IsTruncated>false</IsTruncated></ListBucketResult>")
        if req.method == "PUT":
            objects[(bucket, key)] = (req.content, dict(req.headers))
            return httpx.Response(200)
        if req.method == "GET":
            return httpx.Response(200, content=objects[(bucket, key)][0]) if (bucket, key) in objects \
                else httpx.Response(404, text="<Error><Code>NoSuchKey</Code></Error>")
        objects.pop((bucket, key), None)
        return httpx.Response(204)
    cloud.on(host, h)
    return objects


def fake_gcs(cloud: Cloud):
    objects: dict[str, bytes] = {}

    def h(req):
        assert req.headers["Authorization"] == "Bearer gcp-meta-token"
        raw = req.url.raw_path.decode().split("?")[0]
        if raw == "/upload/storage/v1/b/bkt/o":
            objects[req.url.params["name"]] = req.content
            return httpx.Response(200, json={"name": req.url.params["name"]})
        if raw == "/storage/v1/b/bkt/o":
            pre = req.url.params.get("prefix", "")
            return httpx.Response(200, json={"items": [{"name": n} for n in sorted(objects) if n.startswith(pre)]})
        name = unquote(raw.split("/o/", 1)[1])
        if req.method == "GET":
            return httpx.Response(200, content=objects[name]) if name in objects else httpx.Response(404, json={})
        objects.pop(name, None)
        return httpx.Response(204)
    cloud.on("storage.googleapis.com", h)
    return objects


def fake_azblob(cloud: Cloud):
    blobs: dict[str, bytes] = {}

    def h(req):
        assert req.headers["Authorization"] == "Bearer az-https://storage.azure.com" and req.headers["x-ms-version"]
        if req.url.params.get("comp") == "list":
            pre = req.url.params.get("prefix", "")
            names = "".join(f"<Blob><Name>{n.split('/', 1)[1]}</Name></Blob>" for n in sorted(blobs)
                            if n.split("/", 1)[1].startswith(pre))
            return httpx.Response(200, text=f"<EnumerationResults><Blobs>{names}</Blobs><NextMarker/></EnumerationResults>")
        name = req.url.path.lstrip("/")
        if req.method == "PUT":
            assert req.headers["x-ms-blob-type"] == "BlockBlob"
            blobs[name] = req.content
            return httpx.Response(201)
        if req.method == "GET":
            return httpx.Response(200, content=blobs[name]) if name in blobs else httpx.Response(404)
        blobs.pop(name, None)
        return httpx.Response(202)
    cloud.on("acct1.blob.core.windows.net", h)
    return blobs


def _exercise(store, url_prefix: str):
    assert store.put("certs/1/fullchain.pem", b"PEM-1", "application/x-pem-file") == f"{url_prefix}/certs/1/fullchain.pem"
    store.put("certs/2/fullchain.pem", b"PEM-2")
    store.put("other/x", b"x")
    assert store.get("certs/1/fullchain.pem") == b"PEM-1" and store.get("certs/9/none") is None
    assert store.list("certs/") == ["certs/1/fullchain.pem", "certs/2/fullchain.pem"]
    store.delete("certs/1/fullchain.pem")
    store.delete("certs/1/fullchain.pem")                # missing is fine
    assert store.list("certs/") == ["certs/2/fullchain.pem"]
    with pytest.raises(ValueError):
        store.put("../escape", b"")


def test_s3_storage_aws_with_sse_kms(cloud, monkeypatch):
    from farrier.storage import from_url
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws-secret")
    monkeypatch.setenv("FARRIER_STORAGE_S3_REGION", "eu-west-1")
    monkeypatch.setenv("FARRIER_STORAGE_KMS_KEY", "arn:aws:kms:eu-west-1:123456789012:key/k1")
    objects = fake_s3(cloud, "certs-bucket.s3.eu-west-1.amazonaws.com", path_style=False)
    _exercise(from_url("s3://certs-bucket/prod"), "s3://certs-bucket/prod")
    headers = objects[("certs-bucket", "prod/certs/2/fullchain.pem")][1]
    assert headers["x-amz-server-side-encryption"] == "aws:kms"
    assert headers["x-amz-server-side-encryption-aws-kms-key-id"] == "arn:aws:kms:eu-west-1:123456789012:key/k1"
    assert "/eu-west-1/s3/aws4_request" in headers["authorization"]


def test_s3_storage_minio_path_style(cloud, monkeypatch):
    from farrier.storage import from_url
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "minio")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "minio-secret")
    monkeypatch.setenv("FARRIER_STORAGE_S3_ENDPOINT", "https://minio.internal:9000")
    objects = fake_s3(cloud, "minio.internal", path_style=True)
    _exercise(from_url("s3://farrier/backups"), "s3://farrier/backups")
    assert ("farrier", "backups/certs/2/fullchain.pem") in objects
    assert all(r.url.path.startswith("/farrier") for r in cloud.calls)
    assert "x-amz-server-side-encryption" not in objects[("farrier", "backups/other/x")][1]


def test_gcs_and_azure_blob_storage(cloud):
    from farrier.storage import from_url
    fake_gcp_metadata(cloud)
    objects = fake_gcs(cloud)
    _exercise(from_url("gs://bkt/prod"), "gs://bkt/prod")
    assert set(objects) == {"prod/certs/2/fullchain.pem", "prod/other/x"}
    fake_azure_imds(cloud)
    blobs = fake_azblob(cloud)
    _exercise(from_url("azblob://acct1/certs/prod"), "azblob://acct1/certs/prod")
    assert set(blobs) == {"certs/prod/certs/2/fullchain.pem", "certs/prod/other/x"}


def test_file_storage_and_bad_urls(tmp_path):
    from farrier.storage import from_url
    _exercise(from_url(tmp_path.as_uri()), tmp_path.resolve().as_uri())
    with pytest.raises(ValueError, match="FARRIER_STORAGE_URL"):
        from_url("ftp://x/y")


# ---- change packs ----------------------------------------------------------------------------------
def test_pack_with_private_key_is_sealed_before_upload(cloud, data_dir, monkeypatch):
    from conftest import issue_initial

    from farrier.api.app import create_app
    from farrier.connectors import Bundle, make_connector
    from farrier.core.engine import Engine
    from farrier.core.x509util import split_pem_chain
    from farrier.issuers.local_ca import LocalCA
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "minio")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "minio-secret")
    monkeypatch.setenv("FARRIER_STORAGE_S3_ENDPOINT", "https://minio.internal:9000")
    monkeypatch.setenv("FARRIER_STORAGE_URL", "s3://farrier/state")
    objects = fake_s3(cloud, "minio.internal", path_style=True)
    eng = Engine(data_dir, issuers={"default": LocalCA(data_dir)})
    eid = eng.store.upsert_endpoint({"name": "vpn", "host": "127.0.0.1", "port": 1, "connector": "manual",
                                     "connector_config": {}})
    rid = eng.store.create_renewal(eid, "2026-01-01T00:00:00+00:00", None, None, "due")
    eng.store.update_renewal(rid, state="awaiting_manual")
    key, full = issue_initial(eng.issuers["default"], "vpn.internal.test", 30)
    certs = split_pem_chain(full)
    conn = make_connector("manual", {"runbook": "cisco-asa"}, data_dir)
    out = conn.deploy(Bundle("vpn", rid, key, certs[0], "".join(certs[1:]), "2027-01-01"), addr="vpn:443",
                      fingerprint="ab" * 32, due="2026-12-01")
    assert out["pack_dir"] == f"s3://farrier/state/change-packs/{rid}/"
    assert all(k.startswith(f"state/change-packs/{rid}/") for (_, k) in objects)
    names = {k.rsplit("/", 1)[1] for (_, k) in objects}
    assert {"key.pem.sealed", "bundle.pfx.sealed", "passphrase.txt.sealed", "RUNBOOK.md", "fullchain.pem"} <= names
    assert not names & {"key.pem", "bundle.pfx", "passphrase.txt"}
    assert not [k for k, (body, _) in objects.items() if b"PRIVATE KEY" in body]
    assert not (data_dir / "packs").exists()                     # nothing on local disk either

    monkeypatch.delenv("FARRIER_API_TOKEN", raising=False)
    c = TestClient(create_app(eng))
    z = zipfile.ZipFile(io.BytesIO(c.get(f"/api/renewals/{rid}/pack").content))
    assert z.read("key.pem").decode() == key and "bundle.pfx" in z.namelist()
    assert "trust-point" in c.get(f"/api/renewals/{rid}/runbook").json()["markdown"]

    eng.store.update_renewal(rid, state="cancelled")
    assert eng.sweep_packs() == 1 and not objects


# ---- backup ----------------------------------------------------------------------------------------
def test_backup_round_trip_into_a_new_store(cloud, tmp_path, monkeypatch):
    from farrier.cli import main
    from farrier.core.engine import Engine
    from farrier.db.backup import backup, restore, split_object_url
    from farrier.db.store import Store
    monkeypatch.setenv("FARRIER_MASTER_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "minio")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "minio-secret")
    monkeypatch.setenv("FARRIER_STORAGE_S3_ENDPOINT", "https://minio.internal:9000")
    objects = fake_s3(cloud, "minio.internal", path_style=True)
    src = Engine(tmp_path / "a")
    src.secrets.put("hook", "https://hooks.example/secret-path")
    eid = src.store.upsert_endpoint({"name": "web", "host": "10.0.0.1", "port": 443, "connector": "manual",
                                     "connector_config": {"runbook": "generic"}, "tags": ["prod"]})
    rid = src.store.create_renewal(eid, "2026-01-01T00:00:00+00:00", None, None, "due")
    src.store.update_renewal(rid, key_sealed=src.store.vault.seal("-----BEGIN PRIVATE KEY-----x"))
    src.items.put("notifier", "ops", {"type": "webhook", "url": "vault:hook"})
    src.store.log("before backup", eid, rid)

    url = backup(src.store, __import__("farrier.storage", fromlist=["from_url"]).from_url("s3://farrier/backups"))
    assert url.startswith("s3://farrier/backups/backups/farrier-backup-") and url.endswith(".jsonl")
    (body,) = [b for (_, k), (b, _) in objects.items() if k.endswith(".jsonl")]
    assert b"secret-path" not in body and b"PRIVATE KEY" not in body       # sealed values stay sealed

    store, key = split_object_url(url)
    dst = Store(tmp_path / "b")
    counts = restore(dst, store.get(key))
    assert counts["endpoints"] == 1 and counts["renewals"] == 1 and counts["secrets"] == 1
    for t in ("endpoints", "renewals", "events", "secrets", "secret_values", "config_items"):
        assert src.store.q(f"SELECT * FROM {t}") == dst.q(f"SELECT * FROM {t}"), t
    assert dst.vault.open(dst.renewal(rid)["key_sealed"]).startswith("-----BEGIN PRIVATE KEY")
    assert Engine(tmp_path / "b").secrets.get("hook") == "https://hooks.example/secret-path"
    with pytest.raises(ValueError, match="not empty"):
        restore(dst, store.get(key))
    assert dst.upsert_endpoint({"name": "new", "host": "h", "port": 1, "connector": "manual",
                                "connector_config": {}}) == eid + 1      # sequences follow the restored ids

    # the CLI writes the same thing
    main(["--data", str(tmp_path / "a"), "backup", "--to", "s3://farrier/cli"])
    assert any(k.startswith("cli/backups/farrier-backup-") for (_, k) in objects)


# ---- events ----------------------------------------------------------------------------------------
def _renewal_and_endpoint(data_dir, state="done"):
    from conftest import issue_initial

    from farrier.core.x509util import parse_pem, split_pem_chain
    from farrier.issuers.local_ca import LocalCA
    _, full = issue_initial(LocalCA(data_dir), "www.example.test", 30)
    certs = split_pem_chain(full)
    info = parse_pem(certs[0])
    r = {"id": 2041, "state": state, "reason": "due", "cert_pem": certs[0], "chain_pem": "".join(certs[1:]),
         "new_fingerprint": info.fingerprint, "not_after": info.not_after.isoformat()}
    ep = {"id": 12, "name": "www-lb", "host": "10.20.1.10", "port": 443, "connector": "f5", "tags": ["prod"]}
    return r, ep


def _check_schema(event: dict):
    from schema_lite import validate
    if SCHEMA.exists():
        assert validate(json.loads(SCHEMA.read_text()), event) == []
    assert event["specversion"] == "1.0" and event["type"].startswith("dev.farrier.renewal.")


def test_event_publishing_shape_for_each_transport(cloud, data_dir, monkeypatch):
    from farrier.monitoring.notify import Notifier
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws-secret")
    monkeypatch.setenv("FARRIER_SECRET_EG_KEY", "eg-sas-key")
    fake_gcp_metadata(cloud)
    cloud.on("events.eu-west-1.amazonaws.com", lambda r: httpx.Response(200, json={"FailedEntryCount": 0, "Entries": [{"EventId": "1"}]}))
    cloud.on("pubsub.googleapis.com", lambda r: httpx.Response(200, json={"messageIds": ["9"]}))
    cloud.on("farrier-topic.westeurope-1.eventgrid.azure.net", lambda r: httpx.Response(200))
    log = []
    n = Notifier([
        {"name": "eb", "type": "eventbridge", "bus": "arn:aws:events:eu-west-1:123456789012:event-bus/farrier"},
        {"name": "ps", "type": "pubsub", "topic": "projects/proj-123/topics/farrier-renewals"},
        {"name": "eg", "type": "eventgrid", "endpoint": "https://farrier-topic.westeurope-1.eventgrid.azure.net/api/events",
         "key": "env:FARRIER_SECRET_EG_KEY"},
    ], None, lambda *a, **k: log.append(a), instance_id="prod-eu-1")
    r, ep = _renewal_and_endpoint(data_dir)
    sent = n.send("done", r, ep, wait=True, refs={"chain_ref": "s3://farrier-certs/prod/certs/2041/fullchain.pem",
                                                  "private_key_ref": None})
    assert sorted(sent) == ["eventbridge", "eventgrid", "pubsub"] and not log

    (eb,) = cloud.to("events.eu-west-1.amazonaws.com")
    assert eb.headers["X-Amz-Target"] == "AWSEvents.PutEvents"
    (entry,) = json.loads(eb.content)["Entries"]
    assert entry["Source"] == "farrier" and entry["DetailType"] == "dev.farrier.renewal.done"
    assert entry["EventBusName"].endswith("event-bus/farrier")
    event = json.loads(entry["Detail"])
    _check_schema(event)
    d = event["data"]
    assert event["source"] == "farrier://prod-eu-1" and event["subject"] == "www-lb"
    assert d["renewal"]["fingerprint_sha256"] == r["new_fingerprint"] and d["renewal"]["not_after"].endswith("Z")
    assert d["certificate"]["names"] == ["www.example.test"]
    assert d["certificate"]["chain_ref"] == "s3://farrier-certs/prod/certs/2041/fullchain.pem"
    assert d["private_key_ref"] is None                                  # no export-key tag

    (ps,) = cloud.to("pubsub.googleapis.com")
    assert ps.url.path == "/v1/projects/proj-123/topics/farrier-renewals:publish"
    (msg,) = json.loads(ps.content)["messages"]
    ps_event = json.loads(base64.b64decode(msg["data"]))
    _check_schema(ps_event)
    assert msg["attributes"] == {"ce-id": ps_event["id"], "ce-type": "dev.farrier.renewal.done",
                                 "ce-source": "farrier://prod-eu-1", "ce-specversion": "1.0"}

    (eg,) = cloud.to("farrier-topic.westeurope-1.eventgrid.azure.net")
    assert eg.headers["aeg-sas-key"] == "eg-sas-key"
    assert eg.headers["Content-Type"].startswith("application/cloudevents-batch+json")
    (eg_event,) = json.loads(eg.content)
    _check_schema(eg_event)

    # a failure before issuance: no certificate, and states outside the contract are not published
    cloud.calls.clear()
    failed = {"id": 7, "state": "failed", "reason": "due", "cert_pem": None}
    n.configs[0]["events"] = ["failed", "superseded"]
    n.send("failed", failed, ep, wait=True)
    (eb,) = cloud.to("events.eu-west-1.amazonaws.com")
    ev = json.loads(json.loads(eb.content)["Entries"][0]["Detail"])
    _check_schema(ev)
    assert ev["data"]["certificate"] is None and ev["data"]["renewal"]["fingerprint_sha256"] is None
    cloud.calls.clear()
    n.send("superseded", failed, ep, wait=True)
    assert not cloud.calls


def test_event_grid_uses_managed_identity_without_key(cloud, data_dir):
    from farrier.monitoring.notify import Notifier
    fake_azure_imds(cloud)
    cloud.on("t1.westeurope-1.eventgrid.azure.net", lambda r: httpx.Response(200))
    r, ep = _renewal_and_endpoint(data_dir)
    Notifier([{"type": "eventgrid", "endpoint": "https://t1.westeurope-1.eventgrid.azure.net/api/events",
               "events": ["done"]}], None, print).send("done", r, ep, wait=True)
    (eg,) = cloud.to("t1.westeurope-1.eventgrid.azure.net")
    assert eg.headers["Authorization"] == "Bearer az-https://eventgrid.azure.net"


def test_done_exports_chain_and_private_key_reference(cloud, engine, served, monkeypatch, tmp_path):
    """A real renewal to done: fullchain.pem lands in the bucket (no key), the key goes to Secrets Manager,
    and the EventBridge event carries both references."""
    from test_engine import _due_now, _endpoint

    from farrier.monitoring.notify import Notifier
    s, srv = served
    env_aws_irsa(monkeypatch, tmp_path)
    fake_sts(cloud)
    state = fake_secrets_manager(cloud)
    objects = fake_s3(cloud, "minio.internal", path_style=True)
    monkeypatch.setenv("FARRIER_SECRET_BACKEND", "aws")
    monkeypatch.setenv("FARRIER_SECRET_AWS_REGION", "eu-west-1")
    monkeypatch.setenv("FARRIER_STORAGE_URL", "s3://farrier-certs/prod")
    monkeypatch.setenv("FARRIER_STORAGE_S3_ENDPOINT", "https://minio.internal:9000")
    cloud.on("events.eu-west-1.amazonaws.com", lambda r: httpx.Response(200, json={"FailedEntryCount": 0}))
    from farrier.security.secrets_store import SecretStore
    engine.secrets = SecretStore(engine.store)                  # the fixture engine was built before the env
    engine.items.put("notifier", "bus", {"type": "eventbridge", "bus": "farrier", "region": "eu-west-1",
                                         "events": ["done"]})
    engine.reload_config()
    orig = Notifier._dispatch
    monkeypatch.setattr(Notifier, "_dispatch", lambda self, t, p, wait: orig(self, t, p, True))

    eid = _endpoint(engine, s.port, "files", {"fullchain_path": str(srv / "fullchain.pem"),
                                              "cert_path": str(srv / "leaf.pem"), "key_path": str(srv / "key.pem")},
                    tags=["prod", "export-key"])
    engine.observe(engine.store.endpoint(eid))
    assert engine.tick(now=_due_now(engine, eid))["states"] == {"done": 1}
    r = engine.store.renewal(engine.store.renewals()[0]["id"])

    chain = objects[("farrier-certs", f"prod/chains/{r['id']}/fullchain.pem")][0]
    assert chain.startswith(b"-----BEGIN CERTIFICATE") and b"PRIVATE KEY" not in chain
    assert state[f"farrier/keys/{r['id']}"]["value"] == engine.store.vault.open(r["key_sealed"])
    (eb,) = cloud.to("events.eu-west-1.amazonaws.com")
    ev = json.loads(json.loads(eb.content)["Entries"][0]["Detail"])
    _check_schema(ev)
    assert ev["data"]["certificate"]["chain_ref"] == f"s3://farrier-certs/prod/chains/{r['id']}/fullchain.pem"
    assert ev["data"]["private_key_ref"] == \
        f"aws-sm:arn:aws:secretsmanager:eu-west-1:123456789012:secret:farrier/keys/{r['id']}-AbCdEf"
    assert "PRIVATE KEY" not in json.dumps(ev)

    # without the tag nothing is exported
    ep = engine.store.endpoint(eid) | {"tags": ["prod"]}
    assert engine._export_artifacts(r, ep)["private_key_ref"] is None


def test_event_channels_in_the_dashboard(cloud, data_dir, monkeypatch):
    from farrier.api.app import create_app
    from farrier.core.engine import Engine
    monkeypatch.setenv("FARRIER_API_TOKEN", "admin-tok")
    eng = Engine(data_dir)
    c = TestClient(create_app(eng))
    h = {"Authorization": "Bearer admin-tok"}
    types = {t["id"]: t for t in c.get("/api/integrations/catalog", headers=h).json()["notifier_types"]}
    assert {"eventbridge", "pubsub", "eventgrid"} <= set(types)
    assert [f["key"] for f in types["eventgrid"]["fields"] if f["secret"]] == ["key"]
    assert not [f for f in types["eventbridge"]["fields"] + types["pubsub"]["fields"] if f["secret"]]

    r = c.put("/api/notifiers/bus", json={"type": "eventbridge", "bus": "farrier", "region": "eu-west-1"}, headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["target"] == "farrier on EventBridge" and "done" in r.json()["events"]
    assert c.put("/api/notifiers/ps", json={"type": "pubsub", "topic": "nope"}, headers=h).status_code == 400
    assert c.put("/api/notifiers/eg", json={"type": "eventgrid", "endpoint": "https://t.eventgrid.azure.net/api/events",
                                            "key": "raw-key"}, headers=h).status_code == 400
    c.put("/api/secrets/eg", json={"value": "k"}, headers=h)
    assert c.put("/api/notifiers/eg", json={"type": "eventgrid", "endpoint": "https://t.eventgrid.azure.net/api/events",
                                            "key": "vault:eg"}, headers=h).status_code == 200
    r = c.put("/api/notifiers/eg", json={"type": "eventgrid", "endpoint": "https://t2.eventgrid.azure.net/api/events"},
              headers=h)
    assert r.json()["fields"]["key"] == "vault:eg"                       # omitted secret kept
    assert {n["name"] for n in eng.notifier.configs} == {"bus", "eg"}


# ---- DNS accounts keep omitted credentials -----------------------------------------------------------
def test_dns_account_put_keeps_omitted_credentials(cloud, data_dir, monkeypatch):
    from farrier.api.app import create_app
    from farrier.core.engine import Engine
    monkeypatch.setenv("FARRIER_API_TOKEN", "admin-tok")
    c = TestClient(create_app(Engine(data_dir)))
    h = {"Authorization": "Bearer admin-tok"}
    c.put("/api/secrets/aws-id", json={"value": "AKIA"}, headers=h)
    c.put("/api/secrets/aws-key", json={"value": "secret"}, headers=h)
    r = c.put("/api/dns-accounts/aws", json={"provider": "route53", "credentials": {
        "access_key_id": "vault:aws-id", "secret_access_key": "vault:aws-key"}, "zones": ["example.com"]}, headers=h)
    assert r.status_code == 200, r.text
    # an edit of zones only: the stored references stay
    r = c.put("/api/dns-accounts/aws", json={"provider": "aws", "zones": ["example.com", "example.org"],
                                             "credentials": {"access_key_id": "", "secret_access_key": None}},
              headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["credentials"] == {"access_key_id": "vault:aws-id", "secret_access_key": "vault:aws-key"}
    r = c.put("/api/dns-accounts/aws", json={"provider": "route53", "zones": ["example.com"],
                                             "credentials": {"secret_access_key": "env:NEW_KEY"}}, headers=h)
    assert r.json()["credentials"] == {"access_key_id": "vault:aws-id", "secret_access_key": "env:NEW_KEY"}
    listed = c.get("/api/dns-accounts", headers=h).text
    assert "AKIA" not in listed and "vault:aws-id" in listed
    # another provider starts from scratch
    r = c.put("/api/dns-accounts/aws", json={"provider": "cloudflare", "zones": ["example.com"]}, headers=h)
    assert r.status_code == 400


def test_wrapped_master_key_in_env_is_unwrapped_and_never_stored(cloud, data_dir, monkeypatch):
    """Deploy modules put the base64 KMS ciphertext in FARRIER_MASTER_KEY next to FARRIER_MASTER_KEY_KMS."""
    spec = _kms_fakes(cloud, monkeypatch, "aws")
    key = Fernet.generate_key()
    monkeypatch.setenv("FARRIER_MASTER_KEY_KMS", spec)
    monkeypatch.setenv("FARRIER_MASTER_KEY", _reverse_b64(base64.b64encode(key).decode()))
    assert vault.master_key(data_dir) == key
    assert vault.master_key(data_dir) == key
    assert len(cloud.to("kms.eu-west-1.amazonaws.com")) == 1          # unwrapped once per process
    assert not list(data_dir.iterdir())                               # nothing generated or written
    monkeypatch.setenv("FARRIER_MASTER_KEY", "not base64 at all!")
    vault._unwrapped.clear()
    with pytest.raises(Exception):  # noqa: B017 - the fake KMS refuses; startup stops
        vault.master_key(data_dir)


def test_database_password_is_reread_on_every_reconnect(tmp_path, monkeypatch):
    """Managed-password rotation (RDS every 7 days): a reconnect uses the file's current content."""
    import sys
    import types

    from farrier.db.dialects import PostgresDialect, parse_url
    seen = []
    fake = types.SimpleNamespace(connect=lambda **kw: seen.append(kw.get("password")) or object())
    monkeypatch.setitem(sys.modules, "psycopg", fake)
    pw = tmp_path / "db-password"
    pw.write_text("first\n")
    monkeypatch.setenv("FARRIER_DATABASE_PASSWORD", f"file:{pw}")
    d = PostgresDialect(parse_url("postgresql://farrier@db.internal/farrier?sslmode=verify-full", tmp_path))
    d.connect()
    pw.write_text("rotated\n")                    # the secret store / sidecar rewrote it
    d.connect()                                   # what Store._reconnect does after a dropped connection
    assert seen == ["first", "rotated"]


def test_eventgrid_identity_token_only_goes_to_event_grid_hosts(cloud, data_dir, monkeypatch):
    from farrier.api.app import create_app
    from farrier.core.engine import Engine
    from farrier.events import publishers
    monkeypatch.setenv("FARRIER_API_TOKEN", "admin-tok")
    c = TestClient(create_app(Engine(data_dir)))
    h = {"Authorization": "Bearer admin-tok"}
    r = c.put("/api/notifiers/eg", json={"type": "eventgrid", "endpoint": "https://attacker.example/api/events"},
              headers=h)
    assert r.status_code == 400 and "Event Grid host" in r.text
    r = c.put("/api/notifiers/eg", json={"type": "eventgrid", "endpoint": "https://eventgrid.azure.net.attacker.example/"},
              headers=h)
    assert r.status_code == 400
    for host in ("t.westeurope-1.eventgrid.azure.net", "t.usgovvirginia-1.eventgrid.azure.us",
                 "t.chinaeast2-1.eventgrid.chinacloudapi.cn"):
        publishers.check({"type": "eventgrid", "endpoint": f"https://{host}/api/events"})
    publishers.check({"type": "eventgrid", "endpoint": "https://hook.example/api", "key": "vault:eg"})  # own key: ok
    with pytest.raises(Exception, match="Event Grid host"):          # a channel saved before the rule
        publishers.publish({"type": "eventgrid", "endpoint": "https://attacker.example/"}, {"id": "1"})
    assert not cloud.to("attacker.example")
