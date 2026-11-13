"""Certificate Transparency discovery against a fake crt.sh."""
import httpx
import pytest

from farrier.core.ct import ct_names

ROWS = [
    {"name_value": "www.example.com\nexample.com", "not_after": "2027-01-01T00:00:00", "issuer_name": "C=US, O=Let's Encrypt, CN=R11"},
    {"name_value": "www.example.com", "not_after": "2026-12-01T00:00:00", "issuer_name": "old"},
    {"name_value": "*.example.com", "not_after": "2027-02-01T00:00:00", "issuer_name": "DigiCert"},
    {"name_value": "VPN.Example.com.\nevil-example.com", "not_after": "2027-03-01T00:00:00", "issuer_name": "Sectigo"},
]


def client(seen):
    def h(req):
        seen.append(dict(req.url.params))
        return httpx.Response(200, json=ROWS)
    return httpx.Client(transport=httpx.MockTransport(h))


def test_names_newest_cert_each_wildcards_last():
    seen = []
    rows = ct_names("*.Example.com.", http=client(seen))
    assert seen == [{"q": "%.example.com", "output": "json", "exclude": "expired"}]
    assert [r["name"] for r in rows] == ["example.com", "vpn.example.com", "www.example.com", "*.example.com"]
    www = next(r for r in rows if r["name"] == "www.example.com")
    assert www["issuer"].endswith("R11")                   # the newer of its two certificates
    assert rows[-1]["wildcard"] is True                     # a look-alike domain is never included


def test_rejects_non_domains_and_reports_outages():
    with pytest.raises(ValueError):
        ct_names("example.com/../x")
    down = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(503)))
    with pytest.raises(RuntimeError, match="503"):
        ct_names("example.com", http=down)
