"""AWS ACM managed ACME: the control plane over a fake ACM JSON API, and issuance from a PRE_APPROVED endpoint."""
import base64
import json

import httpx
import pytest

from farrier.cli import _acm_domain_lines
from farrier.core.x509util import build_csr, generate_key, parse_pem
from farrier.issuers import build_issuer
from farrier.issuers.acme import AcmeError
from farrier.issuers.aws_acm import Acm, AcmAcmeIssuer, endpoint_of, region_of, wait_until
from farrier.issuers.local_ca import LocalCA
from test_acme import B, FakeAcme

EP = "arn:aws:acm:eu-west-1:123456789012:acme-endpoint/ep-1"
EAB = f"{EP}/acme-external-account-binding/b-1"
SECRET = b"acm-mac-key-bytes"


class FakeAcm:
    """ACM's ACME actions, as JSON 1.1 over SigV4."""

    def __init__(self):
        self.calls: list[tuple[str, dict]] = []
        self.domains: dict[str, dict] = {}

    def handler(self, req: httpx.Request) -> httpx.Response:
        assert req.url.host == "acm.eu-west-1.amazonaws.com"
        assert req.headers["Authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/")
        assert "/eu-west-1/acm/aws4_request" in req.headers["Authorization"]
        action = req.headers["X-Amz-Target"].removeprefix("CertificateManager.")
        body = json.loads(req.content)
        self.calls.append((action, body))
        if action == "CreateAcmeEndpoint":
            return httpx.Response(200, json={"AcmeEndpointArn": EP})
        if action == "DescribeAcmeEndpoint":
            return httpx.Response(200, json={"AcmeEndpoint": {"AcmeEndpointArn": EP, "Status": "ACTIVE",
                                                              "EndpointUrl": f"{B}/directory"}})
        if action == "ListAcmeEndpoints":   # two pages
            if "NextToken" not in body:
                return httpx.Response(200, json={"AcmeEndpoints": [{"AcmeEndpointArn": EP}], "NextToken": "t2"})
            return httpx.Response(200, json={"AcmeEndpoints": [{"AcmeEndpointArn": EP + "x"}]})
        if action == "CreateAcmeDomainValidation":
            arn = f"{EP}/acme-domain-validation/d-{len(self.domains)}"
            self.domains[arn] = {"AcmeDomainValidationArn": arn, "DomainName": body["DomainName"],
                                 "Status": "VALIDATING", "PrevalidationDetails": {"DnsPrevalidation": {
                                     **body["PrevalidationOptions"]["DnsPrevalidation"],
                                     "ResourceRecord": {"Name": "_x." + body["DomainName"], "Type": "CNAME",
                                                        "Value": "_y.acm-validations.aws"}}}}
            return httpx.Response(200, json={"AcmeDomainValidationArn": arn})
        if action == "DescribeAcmeDomainValidation":
            return httpx.Response(200, json={"AcmeDomainValidation": self.domains[body["AcmeDomainValidationArn"]]})
        if action == "GetAcmeExternalAccountBindingCredentials":
            assert body == {"AcmeExternalAccountBindingArn": EAB}
            return httpx.Response(200, json={"KeyId": "kid-acm", "MacKey": base64.b64encode(SECRET).decode()})
        if action == "CreateAcmeExternalAccountBinding":
            return httpx.Response(200, json={"ExternalAccountBinding": {"AcmeExternalAccountBindingArn": EAB}})
        if action == "DeleteAcmeEndpoint":
            return httpx.Response(200)
        return httpx.Response(400, json={"__type": "ValidationException", "message": action})


@pytest.fixture
def acm(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws-secret")
    fake = FakeAcm()
    return fake, Acm("eu-west-1", http=httpx.Client(transport=httpx.MockTransport(fake.handler)))


class PreApproved(FakeAcme):
    """An ACM endpoint's ACME side: EAB required and every authorization already valid."""

    def __init__(self, ca, allowed=("example.test",)):
        super().__init__(ca, eab=("kid-acm", SECRET))
        self.allowed = allowed

    def handler(self, req):
        r = super().handler(req)
        if req.url.path == "/order" and r.status_code == 201:
            for a in self.authz.values():
                if a["identifier"]["value"].removeprefix("*.").endswith(self.allowed):
                    a.update(status="valid", challenges=[])
        return r


def test_arns():
    assert region_of(EAB) == "eu-west-1" and endpoint_of(EAB) == EP
    with pytest.raises(ValueError):
        region_of("arn:aws:acm:eu-west-1:123456789012:certificate/abc")


def test_control_plane_calls(acm):
    fake, client = acm
    assert client.create_endpoint(["ec256", "rsa2048"], contact_required=True) == EP
    action, body = fake.calls[-1]
    assert body["AuthorizationBehavior"] == "PRE_APPROVED" and body["Contact"] == "REQUIRED"
    assert body["CertificateAuthority"] == {"PublicCertificateAuthority": {
        "AllowedKeyAlgorithms": ["EC_prime256v1", "RSA_2048"]}}
    assert [e["AcmeEndpointArn"] for e in client.list_endpoints()] == [EP, EP + "x"]   # follows NextToken
    arn = client.add_domain(EP, "Example.TEST.", hosted_zone_id="Z123", wildcards=True)
    _, body = fake.calls[-1]
    assert body["DomainName"] == "example.test"
    assert body["PrevalidationOptions"]["DnsPrevalidation"] == {
        "DomainScope": {"ExactDomain": "ENABLED", "Subdomains": "ENABLED", "Wildcards": "ENABLED"},
        "HostedZoneId": "Z123"}
    assert client.describe_domain(arn)["Status"] == "VALIDATING"
    assert client.create_eab(EP, "arn:aws:iam::123456789012:role/issue", 7)["AcmeExternalAccountBindingArn"] == EAB
    assert fake.calls[-1][1]["Expiration"] == {"Type": "DAYS", "Value": 7}
    client.delete_endpoint(EP)


def test_domain_output_shows_cname_or_route53(acm):
    _, client = acm
    manual = client.describe_domain(client.add_domain(EP, "a.test"))
    assert any("_x.a.test CNAME _y.acm-validations.aws" in line for line in _acm_domain_lines(manual))
    r53 = client.describe_domain(client.add_domain(EP, "b.test", hosted_zone_id="Z9"))
    assert any("hosted zone Z9" in line for line in _acm_domain_lines(r53))


def test_wait_until_reports_failure():
    with pytest.raises(RuntimeError, match="INVALID"):
        wait_until(lambda: {"Status": "INVALID", "FailureDetails": {"Reason": "TIMED_OUT"}}, interval=0)
    assert wait_until(lambda: {"Status": "VALID"}, interval=0)["Status"] == "VALID"


def _issuer(tmp_path, srv, client, **kw):
    return AcmAcmeIssuer(tmp_path, acm=client, http=httpx.Client(transport=httpx.MockTransport(srv.handler)),
                         poll_interval=0, **kw)


def test_issues_from_eab_arn_without_dns_or_stored_secrets(tmp_path, acm):
    fake, client = acm
    srv = PreApproved(LocalCA(tmp_path))
    iss = _issuer(tmp_path, srv, client, acm_eab_arn=EAB)
    names = ["example.test", "*.example.test"]
    cert, chain = iss.issue(build_csr(generate_key(), names[0], names), names)
    assert sorted(parse_pem(cert).sans) == sorted(names) and "BEGIN CERTIFICATE" in chain
    assert iss.directory_url == f"{B}/directory"          # resolved from DescribeAcmeEndpoint
    assert iss.eab_kid == "kid-acm"                        # read from ACM; the fake checked the HMAC
    assert srv.dns == {}                                   # no DNS-01 at all


def test_name_outside_prevalidated_domains_is_a_clear_error(tmp_path, acm):
    _, client = acm
    iss = _issuer(tmp_path, PreApproved(LocalCA(tmp_path)), client, acm_eab_arn=EAB)
    with pytest.raises(AcmeError, match="not prevalidated"):
        iss.issue(build_csr(generate_key(), "other.test", ["other.test"]), ["other.test"])


def test_portable_form_with_stored_eab(tmp_path, acm):
    _, client = acm
    srv = PreApproved(LocalCA(tmp_path))
    iss = _issuer(tmp_path, srv, client, directory_url=f"{B}/directory", eab_kid="kid-acm",
                  eab_hmac_key=base64.urlsafe_b64encode(SECRET).decode().rstrip("="))
    cert, _ = iss.issue(build_csr(generate_key(), "www.example.test", ["www.example.test"]), ["www.example.test"])
    assert parse_pem(cert).sans == ["www.example.test"]


def test_issuers_json_entries(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_REGION", "eu-west-1")
    iss = build_issuer("acm", {"preset": "aws-acm", "acm_eab_arn": EAB}, tmp_path)
    assert isinstance(iss, AcmAcmeIssuer) and iss.acm.region == "eu-west-1"
    with pytest.raises(ValueError, match="directory_url"):
        build_issuer("acm", {"preset": "aws-acm"}, tmp_path)
    with pytest.raises(ValueError, match="acm_eab_arn"):
        build_issuer("acm", {"preset": "aws-acm", "acm_eab_arn": EP}, tmp_path)
