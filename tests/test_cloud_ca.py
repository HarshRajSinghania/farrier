"""AWS Private CA and Google CAS issuers against fake APIs that sign with a real local CA."""
import base64
import json

import httpx
import pytest
from cryptography import x509

from farrier.core.x509util import build_csr, generate_key, parse_pem
from farrier.issuers import build_issuer
from farrier.issuers.cloud_ca import AwsPrivateCA, GoogleCAS
from farrier.issuers.local_ca import LocalCA

CA_ARN = "arn:aws:acm-pca:eu-west-1:123456789012:certificate-authority/11111111-2222-3333-4444-555555555555"
POOL = "projects/p1/locations/europe-west1/caPools/internal"


def _sans(csr_pem: str) -> list[str]:
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    return csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)


@pytest.fixture
def aws(monkeypatch, tmp_path):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws-secret")
    ca, issued, seen = LocalCA(tmp_path), {}, []

    def handler(req):
        assert req.url.host == "acm-pca.eu-west-1.amazonaws.com"
        action = req.headers["X-Amz-Target"].removeprefix("ACMPrivateCA.")
        b = json.loads(req.content)
        seen.append((action, b))
        if action == "DescribeCertificateAuthority":
            return httpx.Response(200, json={"CertificateAuthority": {"Status": "ACTIVE", "CertificateAuthorityConfiguration": {
                "KeyAlgorithm": "EC_secp384r1", "SigningAlgorithm": "SHA384WITHECDSA"}}})
        if action == "IssueCertificate":
            csr = base64.b64decode(b["Csr"]).decode()
            issued["a"] = ca.issue(csr, _sans(csr))
            return httpx.Response(200, json={"CertificateArn": CA_ARN + "/certificate/abc"})
        if action == "GetCertificate":
            if len([s for s in seen if s[0] == "GetCertificate"]) == 1:   # first poll: still signing
                return httpx.Response(400, json={"__type": "RequestInProgressException", "message": "wait"})
            cert, chain = issued["a"]
            return httpx.Response(200, json={"Certificate": cert, "CertificateChain": chain})
        return httpx.Response(400, json={"__type": "ValidationException"})
    return AwsPrivateCA(ca_arn=CA_ARN, lifetime_days=30, poll_interval=0,
                        http=httpx.Client(transport=httpx.MockTransport(handler))), seen


def test_aws_private_ca_issues_and_polls(aws):
    pca, seen = aws
    names = ["app.corp.test", "api.corp.test"]
    cert, chain = pca.issue(build_csr(generate_key(), names[0], names), names)
    assert sorted(parse_pem(cert).sans) == sorted(names) and "BEGIN CERTIFICATE" in chain
    issue = next(b for a, b in seen if a == "IssueCertificate")
    assert issue["SigningAlgorithm"] == "SHA384WITHECDSA"          # from the CA's key algorithm
    assert issue["Validity"] == {"Type": "DAYS", "Value": 30}
    assert [a for a, _ in seen].count("GetCertificate") == 2        # waited out RequestInProgressException
    assert "ACTIVE" in pca.check()


def test_google_cas_issues(tmp_path):
    ca, calls = LocalCA(tmp_path), []

    class Tokens:
        def token(self, scope):
            return "ya29.test"

    def handler(req):
        calls.append(req)
        assert req.headers["Authorization"] == "Bearer ya29.test"
        if req.method == "GET":
            return httpx.Response(200, json={"name": POOL, "tier": "ENTERPRISE"})
        assert req.url.path == f"/v1/{POOL}/certificates" and req.url.params["requestId"]
        b = json.loads(req.content)
        assert b["lifetime"] == f"{14 * 86400}s" and b["certificateTemplate"].endswith("/tls-server")
        cert, chain = ca.issue(b["pemCsr"], _sans(b["pemCsr"]))
        return httpx.Response(200, json={"pemCertificate": cert, "pemCertificateChain": [chain]})

    cas = GoogleCAS(ca_pool=POOL, certificate_template="projects/p1/locations/europe-west1/certificateTemplates/tls-server",
                    lifetime_days=14, tokens=Tokens(), http=httpx.Client(transport=httpx.MockTransport(handler)))
    cert, chain = cas.issue(build_csr(generate_key(), "db.corp.test", ["db.corp.test"]), ["db.corp.test"])
    assert parse_pem(cert).sans == ["db.corp.test"] and x509.load_pem_x509_certificate(chain.encode())
    assert "ENTERPRISE" in cas.check()


def test_issuers_json_and_validation(tmp_path):
    assert isinstance(build_issuer("pca", {"type": "aws_pca", "ca_arn": CA_ARN}, tmp_path), AwsPrivateCA)
    assert isinstance(build_issuer("cas", {"type": "gcp_cas", "ca_pool": POOL}, tmp_path), GoogleCAS)
    with pytest.raises(ValueError, match="ca_arn"):
        build_issuer("pca", {"type": "aws_pca", "ca_arn": "arn:aws:acm:eu-west-1:123456789012:certificate/x"}, tmp_path)
    with pytest.raises(ValueError, match="ca_pool"):
        build_issuer("cas", {"type": "gcp_cas", "ca_pool": "internal"}, tmp_path)
