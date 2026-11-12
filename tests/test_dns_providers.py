"""Built-in DNS-01 providers: exact HTTP requests (mocked), SigV4/TSIG known answers, multi-account routing,
secret handling, propagation checks and TXT cleanup on failure."""
import base64
import hashlib
import hmac
import json
import socket
import struct
import threading
import xml.etree.ElementTree as ET
from urllib.parse import parse_qs

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from farrier.core.x509util import build_csr, generate_key
from farrier.dns import (
    DnsAccounts,
    DnsConfigError,
    DnsError,
    DnsPropagationError,
    provider_class,
)
from farrier.dns.providers.rfc2136 import (
    RFC2136,
    build_update,
    sign,
    tsig_vars,
    verify_response,
)
from farrier.dns.providers.route53 import signing_key, sigv4_headers
from farrier.dns.resolver import Resolver, parse_message
from farrier.issuers import PRESETS, apply_preset, load_issuers
from farrier.issuers.acme import AcmeError, AcmeIssuer
from farrier.issuers.local_ca import LocalCA

CHAL = "_acme-challenge.www.example.com"


class Recorder:
    """httpx MockTransport handler: records requests, answers from a routing function."""

    def __init__(self, route):
        self.route, self.calls = route, []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.calls.append(req)
        return self.route(req)

    def client(self):
        return httpx.Client(transport=httpx.MockTransport(self))

    def summary(self):
        return [(r.method, r.url.path) for r in self.calls]


class FakeResolver:
    def __init__(self, cnames=None):
        self.cnames, self.waits = dict(cnames or {}), []

    def cname(self, name):
        return self.cnames.get(name)

    def wait_for(self, records, timeout=300, interval=5, sleep=None):
        self.waits.append({k: set(v) for k, v in records.items()})


def make(provider, creds, options=None, zones=("example.com",), route=None):
    rec = Recorder(route)
    p = provider_class(provider)("acct", creds, options or {}, list(zones), http=rec.client(), resolver=FakeResolver())
    p.sleep = lambda s: None
    return p, rec


# ---- Cloudflare ------------------------------------------------------------------------------------------------
class CloudflareFake:
    """Just enough of api.cloudflare.com: one zone, TXT records stored in `store` (name -> [values])."""

    def __init__(self, store=None, fail_create_for=None):
        self.store = {} if store is None else store
        self.ids: dict[str, tuple[str, str]] = {}
        self.fail_create_for = fail_create_for

    def __call__(self, req):
        p = req.url.path
        if p == "/client/v4/zones":
            return httpx.Response(200, json={"success": True, "result": [{"id": "zone1", "name": req.url.params["name"]}]})
        if p == "/client/v4/zones/zone1/dns_records" and req.method == "GET":
            name = req.url.params["name"]
            res = [{"id": i, "name": n, "type": "TXT", "content": f'"{v}"'} for i, (n, v) in self.ids.items() if n == name]
            return httpx.Response(200, json={"success": True, "result": res})
        if p == "/client/v4/zones/zone1/dns_records" and req.method == "POST":
            body = json.loads(req.content)
            if body["name"] == self.fail_create_for:
                return httpx.Response(400, json={"success": False, "errors": [{"code": 81057}]})
            rid = f"r{len(self.ids) + 1}"
            self.ids[rid] = (body["name"], body["content"])
            self.store.setdefault(body["name"], []).append(body["content"])
            return httpx.Response(200, json={"success": True, "result": {"id": rid}})
        if req.method == "DELETE":
            rid = p.rsplit("/", 1)[1]
            name, value = self.ids.pop(rid)
            self.store[name].remove(value)
            return httpx.Response(200, json={"success": True, "result": {"id": rid}})
        return httpx.Response(404, json={"success": False, "errors": []})


def test_cloudflare_exact_requests_and_multi_value(monkeypatch):
    monkeypatch.setenv("FARRIER_SECRET_CF", "cf-token-123")
    fake = CloudflareFake()
    p, rec = make("cloudflare", {"api_token": "env:FARRIER_SECRET_CF"}, route=fake)
    p.present(CHAL, "v1")
    p.present(CHAL, "v2")          # wildcard + apex: second value is ADDED
    p.present(CHAL, "v2")          # idempotent
    assert fake.store[CHAL] == ["v1", "v2"]
    first = rec.calls[0]
    assert (first.method, first.url.path, first.url.params["name"]) == ("GET", "/client/v4/zones", "example.com")
    assert first.headers["Authorization"] == "Bearer cf-token-123"
    post = next(r for r in rec.calls if r.method == "POST")
    assert json.loads(post.content) == {"type": "TXT", "name": CHAL, "content": "v1", "ttl": 120}
    lst = rec.calls[1]
    assert lst.url.params["type"] == "TXT" and lst.url.params["name"] == CHAL
    p.cleanup(CHAL, "v1")
    assert fake.store[CHAL] == ["v2"]
    assert rec.calls[-1].method == "DELETE" and rec.calls[-1].url.path == "/client/v4/zones/zone1/dns_records/r1"


def test_provider_errors_never_contain_secrets(monkeypatch):
    monkeypatch.setenv("FARRIER_SECRET_CF", "cf-token-SECRETVALUE")
    p, _ = make("cloudflare", {"api_token": "env:FARRIER_SECRET_CF"},
                route=lambda r: httpx.Response(403, text="bad token cf-token-SECRETVALUE"))
    with pytest.raises(DnsError) as e:
        p.present(CHAL, "v")
    assert "SECRETVALUE" not in str(e.value) and "***" in str(e.value)
    monkeypatch.setenv("FARRIER_SECRET_DUCK", "duck-SECRETVALUE")
    d, _ = make("duckdns", {"token": "env:FARRIER_SECRET_DUCK"}, zones=(), route=lambda r: httpx.Response(500))
    with pytest.raises(DnsError) as e:
        d.present("_acme-challenge.me.duckdns.org", "v")
    assert "SECRETVALUE" not in str(e.value) and "token" not in str(e.value)  # query string never echoed


# ---- Route 53 --------------------------------------------------------------------------------------------------
AWS_KEY, AWS_SECRET = "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"


def test_sigv4_known_answers_from_aws_docs():
    # AWS SigV4 test suite "get-vanilla"
    h = sigv4_headers("GET", "https://example.amazonaws.com/", {}, b"", AWS_KEY, AWS_SECRET, "us-east-1", "service",
                      amz_date="20150830T123600Z")
    assert h["Authorization"] == ("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, "
                                  "SignedHeaders=host;x-amz-date, "
                                  "Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31")
    # "Examples of how to derive a signing key" + the IAM ListUsers walkthrough
    assert signing_key(AWS_SECRET, "20150830", "us-east-1", "iam").hex() == \
        "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
    h = sigv4_headers("GET", "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08",
                      {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"}, b"", AWS_KEY, AWS_SECRET,
                      "us-east-1", "iam", amz_date="20150830T123600Z")
    assert h["Authorization"].endswith("Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7")


R53 = "https://route53.amazonaws.com/doc/2013-04-01/"


def test_route53_upsert_keeps_other_values_and_delete_matches_exactly(monkeypatch):
    monkeypatch.setenv("FARRIER_SECRET_AWS_ID", AWS_KEY)
    monkeypatch.setenv("FARRIER_SECRET_AWS_KEY", AWS_SECRET)
    state = {"values": ['"existing"'], "ttl": 120}
    bodies = []

    def route(req):
        p = req.url.path
        if p == "/2013-04-01/hostedzone":
            return httpx.Response(200, text=f'<ListHostedZonesResponse xmlns="{R53}"><HostedZones>'
                                  '<HostedZone><Id>/hostedzone/ZPRIV</Id><Name>example.com.</Name><Config><PrivateZone>true</PrivateZone></Config></HostedZone>'
                                  '<HostedZone><Id>/hostedzone/Z123</Id><Name>example.com.</Name><Config><PrivateZone>false</PrivateZone></Config></HostedZone>'
                                  '</HostedZones><IsTruncated>false</IsTruncated></ListHostedZonesResponse>')
        if p == "/2013-04-01/hostedzone/Z123/rrset" and req.method == "GET":
            recs = "".join(f"<ResourceRecord><Value>{v}</Value></ResourceRecord>" for v in state["values"])
            return httpx.Response(200, text=f'<ListResourceRecordSetsResponse xmlns="{R53}"><ResourceRecordSets>'
                                  f'<ResourceRecordSet><Name>{CHAL}.</Name><Type>TXT</Type><TTL>{state["ttl"]}</TTL>'
                                  f'<ResourceRecords>{recs}</ResourceRecords></ResourceRecordSet></ResourceRecordSets>'
                                  '</ListResourceRecordSetsResponse>')
        if p == "/2013-04-01/hostedzone/Z123/rrset/" and req.method == "POST":
            bodies.append(req.content)
            return httpx.Response(200, text=f'<ChangeResourceRecordSetsResponse xmlns="{R53}"><ChangeInfo>'
                                  '<Id>/change/C1</Id><Status>PENDING</Status></ChangeInfo></ChangeResourceRecordSetsResponse>')
        if p == "/2013-04-01/change/C1":
            return httpx.Response(200, text=f'<GetChangeResponse xmlns="{R53}"><ChangeInfo><Id>/change/C1</Id>'
                                  '<Status>INSYNC</Status></ChangeInfo></GetChangeResponse>')
        return httpx.Response(404)

    p, rec = make("route53", {"access_key_id": "env:FARRIER_SECRET_AWS_ID",
                              "secret_access_key": "env:FARRIER_SECRET_AWS_KEY"}, route=route)
    p.present(CHAL, "new")
    ns = {"r": R53}
    change = ET.fromstring(bodies[0]).find(".//r:Change", ns)
    assert change.findtext("r:Action", namespaces=ns) == "UPSERT"
    assert [v.text for v in change.iter(f"{{{R53}}}Value")] == ['"existing"', '"new"']
    get = next(r for r in rec.calls if r.url.path.endswith("/rrset"))
    assert get.url.params["name"] == CHAL + "." and get.url.params["type"] == "TXT"
    auth = rec.calls[0].headers["Authorization"]
    assert auth.startswith(f"AWS4-HMAC-SHA256 Credential={AWS_KEY}/") and "/us-east-1/route53/aws4_request" in auth
    assert "x-amz-date" in auth and rec.calls[0].headers["X-Amz-Date"]
    # last value removed -> DELETE with the exact live values and TTL
    state["values"] = ['"new"']
    p.cleanup(CHAL, "new")
    change = ET.fromstring(bodies[-1]).find(".//r:Change", ns)
    assert change.findtext("r:Action", namespaces=ns) == "DELETE"
    assert change.findtext(".//r:TTL", namespaces=ns) == "120"
    assert [v.text for v in change.iter(f"{{{R53}}}Value")] == ['"new"']


# ---- Azure -----------------------------------------------------------------------------------------------------
def test_azure_client_credentials_and_rrset(monkeypatch):
    for k, v in {"T": "tenant-1", "C": "client-1", "S": "azure-secret"}.items():
        monkeypatch.setenv(f"FARRIER_SECRET_AZ_{k}", v)
    state = {"record": None}
    zid = "/subscriptions/sub-1/resourceGroups/rg-dns/providers/Microsoft.Network/dnszones/example.com"

    def route(req):
        if req.url.host == "login.microsoftonline.com":
            return httpx.Response(200, json={"access_token": "az-access", "expires_in": 3600})
        if req.url.path == f"{zid}/TXT/_acme-challenge.www":
            if req.method == "GET":
                if state["record"] is None:
                    return httpx.Response(404)
                return httpx.Response(200, json=state["record"], headers={"ETag": "etag-1"})
            if req.method == "PUT":
                state["record"] = json.loads(req.content)
                return httpx.Response(201, json=state["record"])
            if req.method == "DELETE":
                state["record"] = None
                return httpx.Response(200)
        return httpx.Response(404)

    p, rec = make("azure", {"tenant_id": "env:FARRIER_SECRET_AZ_T", "client_id": "env:FARRIER_SECRET_AZ_C",
                            "client_secret": "env:FARRIER_SECRET_AZ_S"},
                  {"subscription_id": "sub-1", "resource_group": "rg-dns"}, route=route)
    p.present(CHAL, "v1")
    tok = rec.calls[0]
    assert tok.url.path == "/tenant-1/oauth2/v2.0/token"
    assert parse_qs(tok.content.decode()) == {"grant_type": ["client_credentials"], "client_id": ["client-1"],
                                              "client_secret": ["azure-secret"],
                                              "scope": ["https://management.azure.com/.default"]}
    put = next(r for r in rec.calls if r.method == "PUT")
    assert put.url.params["api-version"] == "2018-05-01"
    assert put.headers["Authorization"] == "Bearer az-access" and put.headers["If-None-Match"] == "*"
    assert json.loads(put.content) == {"properties": {"TTL": 60, "TXTRecords": [{"value": ["v1"]}]}}
    p.cleanup(CHAL, "v1")
    dele = rec.calls[-1]
    assert dele.method == "DELETE" and dele.headers["If-Match"] == "etag-1"
    assert sum(1 for r in rec.calls if r.url.host == "login.microsoftonline.com") == 1  # token cached


# ---- Google ----------------------------------------------------------------------------------------------------
def test_google_service_account_jwt_and_changes(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode()
    sa = tmp_path / "sa.json"
    sa.write_text(json.dumps({"type": "service_account", "project_id": "proj-1", "private_key_id": "kid1",
                              "private_key": pem, "client_email": "dns@proj-1.iam.gserviceaccount.com",
                              "token_uri": "https://oauth2.googleapis.com/token"}))
    state = {"rrsets": []}

    def route(req):
        if req.url.host == "oauth2.googleapis.com":
            return httpx.Response(200, json={"access_token": "g-access", "expires_in": 3600})
        p = req.url.path
        if p == "/dns/v1/projects/proj-1/managedZones":
            return httpx.Response(200, json={"managedZones": [{"name": "example-com", "dnsName": "example.com.",
                                                               "visibility": "public"}]})
        if p == "/dns/v1/projects/proj-1/managedZones/example-com/rrsets":
            return httpx.Response(200, json={"rrsets": state["rrsets"]})
        if p == "/dns/v1/projects/proj-1/managedZones/example-com/changes":
            return httpx.Response(200, json={"id": "1", "status": "pending"})
        return httpx.Response(404)

    p, rec = make("google", {"service_account": f"file:{sa}"}, route=route)
    p.present(CHAL, "v1")
    tok = rec.calls[0]
    form = parse_qs(tok.content.decode())
    assert form["grant_type"] == ["urn:ietf:params:oauth:grant-type:jwt-bearer"]
    h64, c64, s64 = form["assertion"][0].split(".")
    dec = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))  # noqa: E731
    claims = json.loads(dec(c64))
    assert json.loads(dec(h64)) == {"alg": "RS256", "typ": "JWT", "kid": "kid1"}
    assert claims["iss"] == "dns@proj-1.iam.gserviceaccount.com" and claims["aud"] == "https://oauth2.googleapis.com/token"
    assert claims["scope"] == "https://www.googleapis.com/auth/ndev.clouddns.readwrite"
    key.public_key().verify(dec(s64), f"{h64}.{c64}".encode(), padding.PKCS1v15(), hashes.SHA256())
    zq = rec.calls[1]
    assert zq.url.params["dnsName"] == "example.com." and zq.headers["Authorization"] == "Bearer g-access"
    change = json.loads(rec.calls[-1].content)
    assert change["additions"] == [{"name": CHAL + ".", "type": "TXT", "ttl": 60, "rrdatas": ['"v1"']}]
    assert "deletions" not in change
    state["rrsets"] = [{"name": CHAL + ".", "type": "TXT", "ttl": 300, "rrdatas": ['"v1"', '"v2"']}]
    p.cleanup(CHAL, "v1")
    change = json.loads(rec.calls[-1].content)
    assert change["deletions"] == [{"name": CHAL + ".", "type": "TXT", "ttl": 300, "rrdatas": ['"v1"', '"v2"']}]
    assert change["additions"] == [{"name": CHAL + ".", "type": "TXT", "ttl": 60, "rrdatas": ['"v2"']}]


# ---- DigitalOcean ----------------------------------------------------------------------------------------------
def test_digitalocean_requests(monkeypatch):
    monkeypatch.setenv("FARRIER_SECRET_DO", "do-token")
    recs = []

    def route(req):
        if req.method == "GET":
            return httpx.Response(200, json={"domain_records": recs, "links": {}})
        if req.method == "POST":
            b = json.loads(req.content)
            recs.append({"id": 77, "type": "TXT", "name": b["name"], "data": b["data"]})
            return httpx.Response(201, json={"domain_record": recs[-1]})
        return httpx.Response(204)

    p, rec = make("digitalocean", {"api_token": "env:FARRIER_SECRET_DO"}, route=route)
    p.present(CHAL, "v1")
    get, post = rec.calls
    assert get.url.path == "/v2/domains/example.com/records"
    assert get.url.params["type"] == "TXT" and get.url.params["name"] == CHAL
    assert post.headers["Authorization"] == "Bearer do-token"
    assert json.loads(post.content) == {"type": "TXT", "name": "_acme-challenge.www", "data": "v1", "ttl": 30}
    p.cleanup(CHAL, "v1")
    assert (rec.calls[-1].method, rec.calls[-1].url.path) == ("DELETE", "/v2/domains/example.com/records/77")


# ---- ACME-DNS --------------------------------------------------------------------------------------------------
def test_acme_dns_update(monkeypatch, tmp_path):
    regs = tmp_path / "acmedns.json"
    regs.write_text(json.dumps({"example.com": {"username": "u1", "password": "p1-secret", "subdomain": "sub-1",
                                                "fulldomain": "sub-1.auth.example.org"}}))
    p, rec = make("acme-dns", {"registrations": f"file:{regs}"}, {"api_url": "https://auth.example.org"},
                  route=lambda r: httpx.Response(200, json={"txt": "v"}))
    p.present("_acme-challenge.example.com", "v1")
    p.present("_acme-challenge.example.com", "v2")  # wildcard: acme-dns keeps the last two values
    r = rec.calls[0]
    assert (r.method, str(r.url)) == ("POST", "https://auth.example.org/update")
    assert r.headers["X-Api-User"] == "u1" and r.headers["X-Api-Key"] == "p1-secret"
    assert json.loads(r.content) == {"subdomain": "sub-1", "txt": "v1"}
    p.cleanup("_acme-challenge.example.com", "v1")
    assert len(rec.calls) == 2  # no delete API: cleanup is a no-op


# ---- RFC 2136 / TSIG -------------------------------------------------------------------------------------------
def test_rfc2136_update_encoding():
    msg = build_update("example.com", CHAL, "abc", add=True, ttl=60, qid=0x1234)
    name = b"\x0f_acme-challenge\x03www\x07example\x03com\x00"
    assert msg == (b"\x12\x34\x28\x00\x00\x01\x00\x00\x00\x01\x00\x00"       # id, opcode UPDATE, ZO=1 UP=1
                   + b"\x07example\x03com\x00\x00\x06\x00\x01"               # zone: example.com SOA IN
                   + name + b"\x00\x10\x00\x01\x00\x00\x00\x3c\x00\x04\x03abc")  # TXT IN ttl 60 "abc"
    rm = build_update("example.com", CHAL, "abc", add=False, ttl=60, qid=1)
    assert rm.endswith(name + b"\x00\x10\x00\xfe\x00\x00\x00\x00\x00\x04\x03abc")  # class NONE, ttl 0

    secret = b"0123456789abcdef"
    signed, mac = sign(msg, "farrier-key", "hmac-sha256", secret, time_signed=1700000000, fudge=300)
    expected = hmac.new(secret, msg + b"\x0bfarrier-key\x00" + b"\x00\xff\x00\x00\x00\x00" + b"\x0bhmac-sha256\x00"
                        + (1700000000).to_bytes(6, "big") + b"\x01\x2c\x00\x00\x00\x00", hashlib.sha256).digest()
    assert mac == expected
    assert struct.unpack_from("!H", signed, 10)[0] == 1  # ARCOUNT
    tsig = parse_message(signed).additional[0]
    assert tsig.type == 250 and tsig.name == "farrier-key" and expected in tsig.rdata


class FakeDnsServer:
    """UDP server on 127.0.0.1 that checks the TSIG on an UPDATE and answers NOERROR, signed."""

    def __init__(self, secret: bytes, key="farrier-key"):
        self.secret, self.key, self.updates = secret, key, []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.t = threading.Thread(target=self.serve, daemon=True)
        self.t.start()

    def serve(self):
        data, addr = self.sock.recvfrom(4096)
        msg = parse_message(data)
        tsig = msg.additional[-1]
        unsigned = bytearray(data[:tsig.start])
        struct.pack_into("!H", unsigned, 10, 0)
        rd = tsig.rdata
        o = len(b"\x0bhmac-sha256\x00")
        t = int.from_bytes(rd[o:o + 6], "big")
        mac_len = struct.unpack_from("!H", rd, o + 8)[0]
        req_mac = rd[o + 10:o + 10 + mac_len]
        want = hmac.new(self.secret, bytes(unsigned) + tsig_vars(self.key, "hmac-sha256", t, 300), hashlib.sha256).digest()
        rcode = 0 if hmac.compare_digest(want, req_mac) else 9
        self.updates.append((msg, rcode))
        resp = bytearray(data[:12 + len(b"\x07example\x03com\x00") + 4])
        struct.pack_into("!HHHHH", resp, 2, 0xA800 | rcode, 1, 0, 0, 0)
        resp = bytes(resp)
        rmac = hmac.new(self.secret, struct.pack("!H", len(req_mac)) + req_mac + resp
                        + tsig_vars(self.key, "hmac-sha256", t, 300), hashlib.sha256).digest()
        rdata = b"\x0bhmac-sha256\x00" + t.to_bytes(6, "big") + struct.pack("!HH", 300, len(rmac)) + rmac \
            + data[:2] + b"\x00\x00\x00\x00"
        out = bytearray(resp + b"\x0bfarrier-key\x00" + struct.pack("!HHIH", 250, 255, 0, len(rdata)) + rdata)
        struct.pack_into("!H", out, 10, 1)
        self.sock.sendto(bytes(out), addr)


def test_rfc2136_against_local_server(monkeypatch):
    secret = b"supersecret-tsig-key-32-bytes!!!"
    monkeypatch.setenv("FARRIER_SECRET_TSIG", base64.b64encode(secret).decode())
    srv = FakeDnsServer(secret)
    p = RFC2136("bind", {"tsig_secret": "env:FARRIER_SECRET_TSIG"},
                {"server": "127.0.0.1", "port": srv.port, "tsig_key": "farrier-key", "zone": "example.com"})
    p.present(CHAL, "token-value")
    srv.t.join(2)
    msg, rcode = srv.updates[0]
    assert rcode == 0 and msg.question == [("example.com", 6, 1)]
    upd = msg.authority[0]  # the update section sits where authority would
    assert (upd.name, upd.type, upd.cls, upd.value) == (CHAL, 16, 1, "token-value")
    with pytest.raises(DnsError):  # a response signed with another key does not verify
        verify_response(b"\x00" * 12, b"x" * 32, "farrier-key", "hmac-sha256", secret)


# ---- multi-account routing -------------------------------------------------------------------------------------
def accounts(cfg, resolver=None, route=None):
    rec = Recorder(route or (lambda r: httpx.Response(404)))
    return DnsAccounts.from_config(cfg, http=rec.client(), resolver=resolver or FakeResolver()), rec


BASE = {
    "cf-prod": {"provider": "cloudflare", "credentials": {"api_token": "env:FARRIER_SECRET_CF_PROD"},
                "zones": ["example.com"]},
    "cf-dev": {"provider": "cloudflare", "credentials": {"api_token": "env:FARRIER_SECRET_CF_DEV"},
               "zones": ["dev.example.com"]},
    "aws-a": {"provider": "route53", "credentials": {"access_key_id": "env:A_ID", "secret_access_key": "env:A_KEY"},
              "zones": ["example.net"]},
    "aws-b": {"provider": "aws", "credentials": {"access_key_id": "env:B_ID", "secret_access_key": "env:B_KEY"},
              "options": {"role_arn": "arn:aws:iam::222222222222:role/dns"}, "zones": ["validation.example.org"]},
    "acmedns": {"provider": "acme-dns", "credentials": {"registrations": "file:/etc/farrier/acmedns.json"},
                "options": {"api_url": "https://auth.example.org"}, "zones": ["legacy.example"]},
}


def test_longest_zone_match_explicit_and_ambiguity():
    acc, _ = accounts(BASE)
    assert acc.route("_acme-challenge.www.example.com")[0].account == "cf-prod"
    assert acc.route("_acme-challenge.api.dev.example.com")[0].account == "cf-dev"   # more specific wins
    assert acc.route("_acme-challenge.x.example.com")[0].account == "cf-prod"
    assert acc.route("_acme-challenge.host.example.net")[0].account == "aws-a"
    assert acc.route("_acme-challenge.host.example.net", "aws-b")[0].account == "aws-b"  # explicit
    with pytest.raises(DnsConfigError, match="no dns account covers"):
        acc.route("_acme-challenge.badexample.com")  # suffix, not substring
    with pytest.raises(DnsConfigError, match="no DNS account named"):
        acc.route(CHAL, "nope")
    dup = {**BASE, "cf-other": {**BASE["cf-prod"], "credentials": {"api_token": "env:X"}}}
    acc, _ = accounts(dup)
    with pytest.raises(DnsConfigError, match="several dns accounts"):
        acc.route(CHAL)


def test_cname_delegation_routes_to_target_account():
    res = FakeResolver({"_acme-challenge.shop.example.com": "shop-example-com.validation.example.org"})
    acc, _ = accounts(BASE, resolver=res)
    p, target = acc.route("_acme-challenge.shop.example.com")
    assert (p.account, target) == ("aws-b", "shop-example-com.validation.example.org")
    cfg = {**BASE, "aliases": {"_acme-challenge.www.example.com": "www.validation.example.org"}, "follow_cname": False}
    acc, _ = accounts(cfg, resolver=FakeResolver())
    assert acc.route(CHAL) == (acc.get("aws-b"), "www.validation.example.org")
    # delegating providers get the original name (they do the hop themselves)
    p, target = acc.route("_acme-challenge.app.legacy.example")
    assert (p.account, target) == ("acmedns", "_acme-challenge.app.legacy.example")
    res = FakeResolver({CHAL: "x.unmanaged.example"})
    acc, _ = accounts(BASE, resolver=res)
    with pytest.raises(DnsConfigError, match="delegated to x.unmanaged.example"):
        acc.route(CHAL)


@pytest.mark.parametrize("creds,msg", [
    ({"api_token": "cf-raw-token-value"}, "must be a reference"),
    ({"api_token": "env:"}, "must be a reference"),
    ({"api_token": "env:FARRIER_MASTER_KEY"}, "Farrier's own credentials"),
    ({"api_tokn": "env:X"}, "unknown credentials"),
    ({}, "needs credentials api_token or api_key\\+email"),
])
def test_inline_and_forbidden_secrets_refused(creds, msg):
    with pytest.raises(DnsConfigError, match=msg) as e:
        DnsAccounts.from_config({"a": {"provider": "cloudflare", "credentials": creds}})
    assert "cf-raw-token-value" not in str(e.value)


def test_config_errors_are_precise(monkeypatch):
    with pytest.raises(DnsConfigError, match="options.api_key looks like a secret"):
        DnsAccounts.from_config({"a": {"provider": "powerdns", "credentials": {"api_key": "env:K"},
                                       "options": {"api_url": "http://x", "api_key": "inline"}}})
    with pytest.raises(DnsConfigError, match="unknown DNS provider"):
        DnsAccounts.from_config({"a": {"provider": "nope"}})
    with pytest.raises(DnsConfigError, match="unknown keys"):
        DnsAccounts.from_config({"a": {"provider": "cloudflare", "credentials": {"api_token": "env:X"}, "api_token": "x"}})
    monkeypatch.setenv("FARRIER_SECRET_ENV_PREFIX", "FARRIER_SECRET_")
    with pytest.raises(DnsConfigError, match="outside FARRIER_SECRET_ENV_PREFIX"):
        DnsAccounts.from_config({"a": {"provider": "cloudflare", "credentials": {"api_token": "env:OTHER"}}})


def test_secret_resolved_at_use_time_not_load_time(monkeypatch):
    acc, _ = accounts({"a": BASE["cf-prod"]})  # FARRIER_SECRET_CF_PROD is not set: loading still works
    with pytest.raises(DnsConfigError, match="credential 'api_token'"):
        acc.get("a").present(CHAL, "v")


# ---- ACME integration: cleanup always ----------------------------------------------------------------------------
from test_acme import B, FakeAcme  # noqa: E402


def _acme_with_dns(tmp_path, srv, fake_cf, resolver):
    acc = DnsAccounts.from_config({"cf": BASE["cf-prod"]}, http=httpx.Client(transport=httpx.MockTransport(fake_cf)),
                                  resolver=resolver)
    return AcmeIssuer(tmp_path, f"{B}/directory", dns="auto", dns_accounts=acc,
                      http=httpx.Client(transport=httpx.MockTransport(srv.handler)), poll_interval=0)


def test_acme_issuance_via_provider_checks_propagation_and_cleans_up(tmp_path, monkeypatch):
    monkeypatch.setenv("FARRIER_SECRET_CF_PROD", "t")
    srv = FakeAcme(LocalCA(tmp_path))
    res = FakeResolver()
    acme = _acme_with_dns(tmp_path, srv, CloudflareFake(store=srv.dns), res)
    names = ["example.com", "*.example.com"]
    acme.issue(build_csr(generate_key(), names[0], names), names)
    assert len(res.waits) == 1 and len(res.waits[0]["_acme-challenge.example.com"]) == 2  # both values checked
    assert srv.dns["_acme-challenge.example.com"] == []


def test_acme_cleans_up_txt_when_validation_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("FARRIER_SECRET_CF_PROD", "t")
    srv = FakeAcme(LocalCA(tmp_path))
    fake = CloudflareFake(store=srv.dns)
    acme = _acme_with_dns(tmp_path, srv, fake, FakeResolver())
    srv.thumb = "wrong"
    orig = srv.handler

    def handler(req):  # CA computes the expected value from a different thumbprint -> authz invalid
        resp = orig(req)
        if req.url.path == "/order":
            srv.thumb = "wrong"
        return resp
    acme.http = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(AcmeError):
        acme.issue(build_csr(generate_key(), "a.example.com", ["a.example.com"]), ["a.example.com"])
    assert srv.dns["_acme-challenge.a.example.com"] == [] and fake.ids == {}


def test_acme_cleans_up_when_present_fails_midway(tmp_path, monkeypatch):
    monkeypatch.setenv("FARRIER_SECRET_CF_PROD", "t")
    srv = FakeAcme(LocalCA(tmp_path))
    fake = CloudflareFake(store=srv.dns, fail_create_for="_acme-challenge.b.example.com")
    acme = _acme_with_dns(tmp_path, srv, fake, FakeResolver())
    names = ["a.example.com", "b.example.com"]
    with pytest.raises(DnsError):
        acme.issue(build_csr(generate_key(), names[0], names), names)
    assert srv.dns["_acme-challenge.a.example.com"] == [] and fake.ids == {}


def test_acme_propagation_timeout_fails_and_cleans_up(tmp_path, monkeypatch):
    monkeypatch.setenv("FARRIER_SECRET_CF_PROD", "t")

    class Never(FakeResolver):
        def wait_for(self, records, **kw):
            raise DnsPropagationError("not visible")
    srv = FakeAcme(LocalCA(tmp_path))
    fake = CloudflareFake(store=srv.dns)
    acme = _acme_with_dns(tmp_path, srv, fake, Never())
    with pytest.raises(DnsPropagationError):
        acme.issue(build_csr(generate_key(), "a.example.com", ["a.example.com"]), ["a.example.com"])
    assert fake.ids == {}


def test_issuer_needs_dns_or_hook(tmp_path):
    with pytest.raises(ValueError, match="dns_hook"):
        AcmeIssuer(tmp_path, f"{B}/directory")
    with pytest.raises(DnsConfigError, match="no DNS account named"):
        AcmeIssuer(tmp_path, f"{B}/directory", dns="missing")


# ---- propagation check on authoritative servers -----------------------------------------------------------------
class ScriptedResolver(Resolver):
    def __init__(self, answers):
        super().__init__(nameservers=[], doh_urls=())
        self.answers = answers  # (server, name) -> list of (values, cname) per call

    def find_zone(self, fqdn):
        return "example.com" if fqdn.endswith("example.com") else "validation.example.org"

    def nameserver_ips(self, zone):
        return ["192.0.2.1", "192.0.2.2"] if zone == "example.com" else ["198.51.100.1"]

    def authoritative_txt(self, server, fqdn):
        seq = self.answers[(server, fqdn)]
        return seq.pop(0) if len(seq) > 1 else seq[0]


def test_propagation_waits_for_every_nameserver_and_follows_cname():
    r = ScriptedResolver({("192.0.2.1", CHAL): [({"v"}, None)],
                          ("192.0.2.2", CHAL): [(set(), None), ({"v"}, None)]})
    sleeps = []
    r.wait_for({CHAL: {"v"}}, timeout=60, interval=1, sleep=sleeps.append)
    assert sleeps == [1]  # one lagging nameserver -> exactly one more round
    r = ScriptedResolver({("192.0.2.1", CHAL): [(set(), "t.validation.example.org")],
                          ("192.0.2.2", CHAL): [(set(), "t.validation.example.org")],
                          ("198.51.100.1", "t.validation.example.org"): [({"v"}, None)]})
    assert r.check(CHAL, {"v"})[0]
    r = ScriptedResolver({("192.0.2.1", CHAL): [(set(), None)], ("192.0.2.2", CHAL): [(set(), None)]})
    with pytest.raises(DnsPropagationError, match="192.0.2.1"):
        r.wait_for({CHAL: {"v"}}, timeout=0, interval=0, sleep=lambda s: None)


def test_wire_parser_handles_compression():
    q = struct.pack("!HHHHHH", 7, 0x8180, 1, 1, 0, 0) + b"\x04_acm\x07example\x03com\x00\x00\x10\x00\x01"
    ans = b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 60, 8) + b"\x03abc\x03def"
    m = parse_message(q + ans)
    assert m.answer[0].name == "_acm.example.com" and m.answer[0].value == "abcdef"


# ---- CA presets ------------------------------------------------------------------------------------------------
def test_presets(tmp_path, monkeypatch):
    assert apply_preset("le", {"preset": "letsencrypt"})["directory_url"] == "https://acme-v02.api.letsencrypt.org/directory"
    assert PRESETS["zerossl"]["eab"] and PRESETS["google"]["eab"] and PRESETS["sslcom"]["eab"]
    with pytest.raises(ValueError, match="External Account Binding"):
        apply_preset("z", {"preset": "zerossl"})
    with pytest.raises(ValueError, match="needs \"directory_url\""):
        apply_preset("d", {"preset": "digicert", "eab_kid": "k", "eab_hmac_key": "h"})
    c = apply_preset("s", {"preset": "sectigo", "directory_url": "https://acme.sectigo.com/v2/OV",
                           "eab_kid": "k", "eab_hmac_key": "h"})
    assert c["type"] == "acme" and c["directory_url"] == "https://acme.sectigo.com/v2/OV"
    with pytest.raises(ValueError, match="unknown preset"):
        apply_preset("x", {"preset": "nope"})
    monkeypatch.setenv("FARRIER_SECRET_ZKID", "kid")
    monkeypatch.setenv("FARRIER_SECRET_ZHMAC", base64.urlsafe_b64encode(b"k").decode())
    (tmp_path / "issuers.json").write_text(json.dumps({
        "default": {"type": "local_ca"},
        "old": {"type": "acme", "directory_url": "https://acme.example/dir", "dns_hook": "true"},
        "z": {"preset": "zerossl", "eab_kid": "env:FARRIER_SECRET_ZKID", "eab_hmac_key": "env:FARRIER_SECRET_ZHMAC",
              "dns_hook": "true"}}))
    issuers = load_issuers(tmp_path)
    assert issuers["z"].directory_url == "https://acme.zerossl.com/v2/DV90" and issuers["z"].eab_kid == "kid"
    assert issuers["old"].propagation_seconds == 60  # historic default for hook issuers
