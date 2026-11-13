"""Cloud certificate inventory against fake ACM, Key Vault and Certificate Manager APIs."""
import json

import httpx
import pytest

from farrier.monitoring import cloud_inventory as ci


class Tok:
    def token(self, scope):
        return "tok"


def test_each_cloud_and_one_failing_source(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "s")
    monkeypatch.setattr(ci.azure, "default_provider", lambda: Tok())
    monkeypatch.setattr(ci.google, "default_provider", lambda: Tok())
    pages = []

    def h(req):
        host = req.url.host
        if host == "acm.eu-west-1.amazonaws.com":
            b = json.loads(req.content)
            assert "EC_prime256v1" in b["Includes"]["keyTypes"]          # not only RSA_2048, ACM's default
            pages.append(b.get("NextToken"))
            if not b.get("NextToken"):
                return httpx.Response(200, json={"NextToken": "p2", "CertificateSummaryList": [{
                    "CertificateArn": "arn:aws:acm:eu-west-1:1:certificate/a", "DomainName": "a.example.com",
                    "NotAfter": 1893456000, "InUse": True, "Type": "IMPORTED", "Status": "ISSUED"}]})
            return httpx.Response(200, json={"CertificateSummaryList": [{
                "CertificateArn": "arn:aws:acm:eu-west-1:1:certificate/b", "DomainName": "b.example.com",
                "NotAfter": 1800000000, "InUse": False, "Type": "AMAZON_ISSUED", "RenewalEligibility": "ELIGIBLE"}]})
        if host == "acm.us-east-1.amazonaws.com":
            return httpx.Response(400, json={"__type": "AccessDeniedException", "message": "no"})
        if host == "prod-kv.vault.azure.net":
            assert req.headers["Authorization"] == "Bearer tok"
            return httpx.Response(200, json={"value": [{"id": "https://prod-kv.vault.azure.net/certificates/web",
                                                        "attributes": {"enabled": True, "exp": 1850000000}}]})
        if host == "certificatemanager.googleapis.com":
            return httpx.Response(200, json={"certificates": [{
                "name": "projects/p1/locations/global/certificates/edge", "sanDnsnames": ["edge.example.com"],
                "expireTime": "2027-05-01T00:00:00Z", "managed": {"state": "ACTIVE"}}]})
        return httpx.Response(404)

    out = ci.inventory({"aws_regions": ["eu-west-1", "us-east-1"], "azure_vaults": ["prod-kv"], "gcp_projects": ["p1"]},
                       http=httpx.Client(transport=httpx.MockTransport(h)))
    names = [c["name"] for c in out["certificates"]]
    assert names == ["b.example.com", "edge", "web", "a.example.com"]           # soonest expiry first
    assert pages == [None, "p2"]                                              # followed NextToken
    b = next(c for c in out["certificates"] if c["name"] == "b.example.com")
    assert b["managed"] is True and b["not_after"].startswith("2027-01-15") and isinstance(b["days_left"], float)
    assert next(c for c in out["certificates"] if c["name"] == "edge")["managed"] is True
    assert out["errors"] == [{"source": "aws-acm", "location": "us-east-1",
                              "error": out["errors"][0]["error"]}] and "AccessDenied" in out["errors"][0]["error"]


def test_validate():
    ci.validate(None)
    ci.validate({"aws_regions": ["eu-west-1"]})
    with pytest.raises(ValueError):
        ci.validate({"aws_region": "eu-west-1"})
