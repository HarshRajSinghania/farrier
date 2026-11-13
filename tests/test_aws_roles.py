"""AWS across accounts: sts:AssumeRole (cache, ExternalId, Route 53), the aws_acm connector (re-import,
listener switch, SNI list, rollback) and the ACM inventory of other accounts, against fake STS, ACM and ELBv2."""
import base64
import json
from urllib.parse import parse_qs

import httpx
import pytest
from conftest import issue_initial

from farrier.connectors import Bundle, DeployError, make_connector
from farrier.core.x509util import split_pem_chain
from farrier.issuers.local_ca import LocalCA
from farrier.monitoring import cloud_inventory as ci
from farrier.security import cloud_auth
from farrier.security.cloud_auth import aws
from farrier.security.cloud_auth import http as cloud_http
from farrier.security.cloud_auth.http import CloudConfigError

ROLE = "arn:aws:iam::210987654321:role/farrier-deploy"
LISTENER = "arn:aws:elasticloadbalancing:eu-west-1:210987654321:listener/app/web/50dc6c495c0c9188/f2f7dc8efc522ab2"
OLD = "arn:aws:acm:eu-west-1:210987654321:certificate/old"
ELB_NS = "http://elasticloadbalancing.amazonaws.com/doc/2015-12-01/"


def form(req) -> dict:
    return {k: v[0] for k, v in parse_qs(req.content.decode()).items()}


class FakeAws:
    """STS AssumeRole (XML), ACM (JSON 1.1) and ELBv2 (Query/XML), with just enough state."""

    def __init__(self):
        self.calls: list[tuple[str, str, dict, str]] = []     # (service, action, params, access key)
        self.expiration = "2099-01-01T00:00:00Z"
        self.certs: dict[str, dict] = {OLD: {"tags": {"farrier:endpoint": "app-01"}}}
        self.listener = [(OLD, True)]
        self.fail: dict[str, list[str]] = {}                 # action -> error codes to answer, in order
        self.n = 0

    def actions(self, service=None):
        return [a for s, a, _, _ in self.calls if service in (None, s)]

    def __call__(self, req: httpx.Request) -> httpx.Response:
        key = req.headers["Authorization"].split("Credential=")[1].split("/")[0]
        host = req.url.host
        if host == "sts.amazonaws.com":
            f = form(req)
            self.calls.append(("sts", f["Action"], f, key))
            self.n += 1
            return httpx.Response(200, text=(
                '<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult>'
                f"<Credentials><AccessKeyId>ASIAROLE{self.n}</AccessKeyId><SecretAccessKey>rs{self.n}</SecretAccessKey>"
                f"<SessionToken>tok{self.n}</SessionToken><Expiration>{self.expiration}</Expiration></Credentials>"
                "</AssumeRoleResult></AssumeRoleResponse>"))
        if host == "acm.eu-west-1.amazonaws.com":
            action = req.headers["X-Amz-Target"].split(".")[1]
            body = json.loads(req.content)
            self.calls.append(("acm", action, body, key))
            if self.fail.get(action):
                return httpx.Response(400, json={"__type": self.fail[action].pop(0), "message": "no"})
            if action == "ImportCertificate":
                arn = body.get("CertificateArn") or f"arn:aws:acm:eu-west-1:210987654321:certificate/new{len(self.certs)}"
                self.certs.setdefault(arn, {"tags": {t["Key"]: t["Value"] for t in body.get("Tags", [])}})
                return httpx.Response(200, json={"CertificateArn": arn})
            if action == "ListTagsForCertificate":
                tags = self.certs[body["CertificateArn"]]["tags"]
                return httpx.Response(200, json={"Tags": [{"Key": k, "Value": v} for k, v in tags.items()]})
            if action == "DeleteCertificate":
                self.certs.pop(body["CertificateArn"])
                return httpx.Response(200)
            if action == "ListCertificates":
                return httpx.Response(200, json={"CertificateSummaryList": [{
                    "CertificateArn": OLD, "DomainName": "old.example.com", "NotAfter": 1893456000}]})
        if host == "elasticloadbalancing.eu-west-1.amazonaws.com":
            f = form(req)
            action = f["Action"]
            self.calls.append(("elb", action, f, key))
            assert f["Version"] == "2015-12-01" and f.get("ListenerArn") == LISTENER
            if self.fail.get(action):
                code = self.fail[action].pop(0)
                return httpx.Response(400, text=f'<ErrorResponse xmlns="{ELB_NS}"><Error><Type>Sender</Type>'
                                                f"<Code>{code}</Code><Message>nope</Message></Error></ErrorResponse>")
            arns = [v for k, v in sorted(f.items()) if k.startswith("Certificates.member.")]
            if action == "DescribeListenerCertificates":
                members = "".join(f"<member><CertificateArn>{a}</CertificateArn><IsDefault>{str(d).lower()}"
                                  "</IsDefault></member>" for a, d in self.listener)
                return httpx.Response(200, text=f'<DescribeListenerCertificatesResponse xmlns="{ELB_NS}">'
                                      f"<DescribeListenerCertificatesResult><Certificates>{members}</Certificates>"
                                      "</DescribeListenerCertificatesResult></DescribeListenerCertificatesResponse>")
            if action == "ModifyListener":
                self.listener = [(arns[0], True)] + [(a, d) for a, d in self.listener if not d]
            elif action == "AddListenerCertificates":
                self.listener += [(a, False) for a in arns]
            elif action == "RemoveListenerCertificates":
                self.listener = [(a, d) for a, d in self.listener if d or a not in arns]
            return httpx.Response(200, text=f'<{action}Response xmlns="{ELB_NS}"><{action}Result/></{action}Response>')
        return httpx.Response(418)


@pytest.fixture
def fake(monkeypatch):
    for k in ("AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
              "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_SESSION_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "s")
    monkeypatch.setenv("ROLE_EXTERNAL_ID", "ext-123")
    f = FakeAws()
    cloud_http.set_client(httpx.Client(transport=httpx.MockTransport(f)))
    monkeypatch.setattr(cloud_http, "sleep", lambda s: None)
    cloud_auth.reset()
    yield f
    cloud_http.set_client(None)
    cloud_auth.reset()


@pytest.fixture
def bundle(tmp_path):
    key, full = issue_initial(LocalCA(tmp_path), "app.example.test", 47)
    c = split_pem_chain(full)
    return Bundle("app-01", 7, key, c[0], "".join(c[1:]), "2027-01-01T00:00:00+00:00")


# ---- AssumeRole -----------------------------------------------------------------------------------------------
def test_assume_role_is_cached_until_shortly_before_expiry(fake):
    p = aws.assume_role(ROLE, "ext-123", "farrier-test")
    assert aws.assume_role(ROLE, "ext-123", "farrier-test") is p             # one shared session per role
    c = p.get()
    assert (c.access_key, c.token, c.source) == ("ASIAROLE1", "tok1", "assume-role")
    assert p.get() is c and fake.actions("sts") == ["AssumeRole"]
    _, _, params, signer = fake.calls[0]
    assert signer == "AKIDEXAMPLE"                                            # signed with the default chain
    assert (params["RoleArn"], params["ExternalId"], params["RoleSessionName"]) == (ROLE, "ext-123", "farrier-test")
    fake.expiration = "2000-01-01T00:00:00Z"                                  # within the 5-minute margin
    p.clear()
    p.get()
    assert p.get().access_key == "ASIAROLE3" and fake.actions("sts") == ["AssumeRole"] * 3   # refreshed each time
    with pytest.raises(CloudConfigError, match="not an IAM role ARN"):
        aws.AssumeRoleProvider("arn:aws:iam::1:user/x")


def test_route53_role_arn_uses_the_shared_assume_role(fake, monkeypatch):
    from farrier.dns import provider_class
    monkeypatch.setenv("R53_ID", "AKIDR53")
    monkeypatch.setenv("R53_KEY", "r53secret")
    seen = []

    def r53(req):
        if req.url.host == "sts.amazonaws.com":
            return fake(req)
        seen.append(req.headers["Authorization"].split("Credential=")[1].split("/")[0])
        return httpx.Response(200, text='<ListHostedZonesResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">'
                                        "<HostedZones/><IsTruncated>false</IsTruncated></ListHostedZonesResponse>")

    p = provider_class("route53")("acct", {"access_key_id": "env:R53_ID", "secret_access_key": "env:R53_KEY",
                                           "external_id": "env:ROLE_EXTERNAL_ID"}, {"role_arn": ROLE}, ["example.com"],
                                  http=httpx.Client(transport=httpx.MockTransport(r53)))
    p.list_zones()
    p.list_zones()
    assert seen == ["ASIAROLE1", "ASIAROLE1"] and fake.actions("sts") == ["AssumeRole"]
    _, _, params, signer = fake.calls[0]
    assert signer == "AKIDR53" and params["ExternalId"] == "ext-123" and params["RoleSessionName"] == "farrier-dns01"
    assert "rs1" in p._redact and "tok1" in p._redact


# ---- aws_acm connector ----------------------------------------------------------------------------------------
def acm(tmp_path, **cfg):
    return make_connector("aws_acm", {"region": "eu-west-1", **cfg}, tmp_path)


def test_reimport_in_place_and_rollback_refuses_honestly(fake, tmp_path, bundle):
    c = acm(tmp_path, certificate_arn=OLD)
    token = c.deploy(bundle)
    assert token == {"reimported": OLD}
    _, action, body, _ = fake.calls[-1]
    assert action == "ImportCertificate" and body["CertificateArn"] == OLD and "Tags" not in body
    assert base64.b64decode(body["Certificate"]).decode() == bundle.cert_pem
    assert base64.b64decode(body["CertificateChain"]).decode() == bundle.chain_pem
    with pytest.raises(DeployError, match="cannot be rolled back.*listener_arn"):
        c.rollback(token)


def test_listener_default_switch_retries_until_elb_sees_the_cert_and_rolls_back(fake, tmp_path, bundle):
    fake.fail = {"ModifyListener": ["CertificateNotFound"], "DeleteCertificate": ["ResourceInUseException"]}
    c = acm(tmp_path, listener_arn=LISTENER, tags={"team": "web"})
    token = c.deploy(bundle)
    new = token["certificate_arn"]
    assert token == {"certificate_arn": new, "listener_arn": LISTENER, "previous_default": OLD}
    assert fake.certs[new]["tags"] == {"farrier:endpoint": "app-01", "team": "web"}
    assert fake.listener == [(new, True)] and fake.actions("elb").count("ModifyListener") == 2
    c.rollback(token)
    assert fake.listener == [(OLD, True)] and new not in fake.certs and OLD in fake.certs
    assert fake.actions("acm")[-2:] == ["DeleteCertificate", "DeleteCertificate"]   # retried while ELB let go


def test_failed_switch_deletes_the_unused_import(fake, tmp_path, bundle):
    fake.fail = {"ModifyListener": ["AccessDenied"]}
    with pytest.raises(Exception, match="AccessDenied"):
        acm(tmp_path, listener_arn=LISTENER).deploy(bundle)
    assert list(fake.certs) == [OLD] and fake.listener == [(OLD, True)]


def test_additional_mode_replaces_this_endpoints_previous_renewal_only(fake, tmp_path, bundle):
    other = "arn:aws:acm:eu-west-1:210987654321:certificate/other"
    prev = "arn:aws:acm:eu-west-1:210987654321:certificate/prev"
    fake.certs.update({other: {"tags": {"farrier:endpoint": "shop"}}, prev: {"tags": {"farrier:endpoint": "app-01"}}})
    fake.listener = [(OLD, True), (OLD, False), (other, False), (prev, False),
                     ("arn:aws:iam::210987654321:server-certificate/legacy", False)]
    c = acm(tmp_path, listener_arn=LISTENER, listener_mode="additional")
    token = c.deploy(bundle)
    new = token["certificate_arn"]
    assert token["removed"] == [prev]                       # not the default, nor another endpoint's, nor IAM
    assert (new, False) in fake.listener and (prev, False) not in fake.listener and (other, False) in fake.listener
    c.rollback(token)
    assert (prev, False) in fake.listener and (new, False) not in fake.listener and new not in fake.certs


def test_import_only_in_another_account(fake, tmp_path, bundle):
    c = acm(tmp_path, role_arn=ROLE, external_id="env:ROLE_EXTERNAL_ID")
    token = c.deploy(bundle)
    assert fake.actions() == ["AssumeRole", "ImportCertificate"]
    assert fake.calls[0][2]["ExternalId"] == "ext-123" and fake.calls[1][3] == "ASIAROLE1"   # signed as the role
    c.rollback(token)
    assert token["certificate_arn"] not in fake.certs and fake.actions("sts") == ["AssumeRole"]   # session re-used


def test_config_validation(tmp_path):
    with pytest.raises(ValueError, match="missing config: region"):
        make_connector("aws_acm", {}, tmp_path)
    with pytest.raises(ValueError, match="not both"):
        acm(tmp_path, certificate_arn=OLD, listener_arn=LISTENER)
    with pytest.raises(ValueError, match="listener_arn must be an elasticloadbalancing ARN in region us-east-1"):
        make_connector("aws_acm", {"region": "us-east-1", "listener_arn": LISTENER}, tmp_path)
    with pytest.raises(ValueError, match="certificate_arn must be an acm ARN"):
        acm(tmp_path, certificate_arn=LISTENER)
    with pytest.raises(ValueError, match="listener_mode"):
        acm(tmp_path, listener_arn=LISTENER, listener_mode="sni")
    with pytest.raises(ValueError, match="role_arn"):
        acm(tmp_path, role_arn="arn:aws:iam::1:user/me")
    with pytest.raises(ValueError, match="region"):
        make_connector("aws_acm", {"region": "europe"}, tmp_path)
    make_connector("aws_acm", {"region": "env:REGION", "role_arn": "env:ROLE", "runner": "dmz"}, tmp_path)


# ---- inventory across accounts --------------------------------------------------------------------------------
def test_inventory_lists_other_accounts_with_account_in_location(fake):
    cfg = {"aws_accounts": [{"role_arn": ROLE, "external_id": "env:ROLE_EXTERNAL_ID", "regions": ["eu-west-1"]}]}
    ci.validate(cfg)
    out = ci.inventory(cfg)
    assert out["errors"] == []
    assert [(r["location"], r["name"]) for r in out["certificates"]] == [("210987654321/eu-west-1", "old.example.com")]
    assert fake.calls[0][2]["ExternalId"] == "ext-123" and fake.calls[1][3] == "ASIAROLE1"
    for bad in ([{"role_arn": ROLE}], [{"role_arn": "x", "regions": ["eu-west-1"]}],
                [{"role_arn": ROLE, "regions": ["eu-west-1"], "extra": 1}], {"role_arn": ROLE}):
        with pytest.raises(ValueError, match="aws_accounts"):
            ci.validate({"aws_accounts": bad})
