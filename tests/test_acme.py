"""ACME client against an in-process RFC 8555 server that checks signatures, nonces, EAB and DNS-01 values."""
import base64
import hashlib
import hmac
import json

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from farrier.issuers.acme import AcmeError, AcmeIssuer, b64u, b64u_decode, thumbprint
from farrier.issuers.local_ca import LocalCA
from farrier.x509util import build_csr, generate_key, parse_pem

B = "https://acme.test"


class FakeAcme:
    def __init__(self, ca: LocalCA, eab: tuple[str, bytes] | None = None):
        self.ca, self.eab = ca, eab
        self.nonces: set[str] = set()
        self.n = 0
        self.accounts: dict[str, dict] = {}
        self.dns: dict[str, list[str]] = {}
        self.authz: dict[str, dict] = {}
        self.order: dict = {}
        self.bad_nonce_once = True

    def nonce(self):
        self.n += 1
        v = f"n{self.n}"
        self.nonces.add(v)
        return v

    def dns_hook(self, action, name, value):
        recs = self.dns.setdefault(name, [])
        recs.append(value) if action == "present" else recs.remove(value)

    def _verify(self, req):
        jws = json.loads(req.content)
        prot = json.loads(b64u_decode(jws["protected"]))
        assert prot["url"] == str(req.url)
        if prot["nonce"] not in self.nonces:
            return None, None, "badNonce"
        self.nonces.discard(prot["nonce"])
        if self.bad_nonce_once:
            self.bad_nonce_once = False
            return None, None, "badNonce"
        jwk = prot.get("jwk") or self.accounts[prot["kid"]]
        pub = ec.EllipticCurvePublicNumbers(int.from_bytes(b64u_decode(jwk["x"]), "big"),
                                            int.from_bytes(b64u_decode(jwk["y"]), "big"),
                                            ec.SECP256R1()).public_key()
        sig = b64u_decode(jws["signature"])
        der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
        pub.verify(der, f"{jws['protected']}.{jws['payload']}".encode(), ec.ECDSA(hashes.SHA256()))
        payload = json.loads(b64u_decode(jws["payload"])) if jws["payload"] else None
        return jwk, payload, None

    def handler(self, req: httpx.Request) -> httpx.Response:
        p = req.url.path
        h = {"Replay-Nonce": self.nonce()}
        if p == "/directory":
            return httpx.Response(200, json={"newNonce": f"{B}/nonce", "newAccount": f"{B}/acct",
                                             "newOrder": f"{B}/order"})
        if p == "/nonce":
            return httpx.Response(200, headers=h)
        jwk, payload, err = self._verify(req)
        if err:
            return httpx.Response(400, json={"type": f"urn:ietf:params:acme:error:{err}"}, headers=h)
        if p == "/acct":
            if self.eab:
                e = payload.get("externalAccountBinding")
                if not e:
                    return httpx.Response(403, json={"type": "urn:ietf:params:acme:error:externalAccountRequired"},
                                          headers=h)
                mac = hmac.new(self.eab[1], f"{e['protected']}.{e['payload']}".encode(), hashlib.sha256).digest()
                assert b64u(mac) == e["signature"] and json.loads(b64u_decode(e["payload"])) == jwk
            self.accounts[f"{B}/acct/1"] = jwk
            return httpx.Response(201, json={"status": "valid"}, headers={**h, "Location": f"{B}/acct/1"})
        if p == "/order":
            self.thumb = thumbprint(jwk)
            for i, ident in enumerate(payload["identifiers"]):
                self.authz[f"{B}/authz/{i}"] = {"status": "pending", "identifier": ident, "challenges": [
                    {"type": "http-01", "url": f"{B}/chal/h{i}", "token": f"tokh{i}"},
                    {"type": "dns-01", "url": f"{B}/chal/{i}", "token": f"tok{i}"}]}
            self.order = {"status": "pending", "authorizations": list(self.authz), "finalize": f"{B}/finalize"}
            return httpx.Response(201, json=self.order, headers={**h, "Location": f"{B}/order/1"})
        if p.startswith("/authz/"):
            return httpx.Response(200, json=self.authz[str(req.url)], headers=h)
        if p.startswith("/chal/"):
            i = p.rsplit("/", 1)[1]
            a = self.authz[f"{B}/authz/{i}"]
            name = "_acme-challenge." + a["identifier"]["value"].removeprefix("*.")
            want = b64u(hashlib.sha256(f"tok{i}.{self.thumb}".encode()).digest())
            a["status"] = "valid" if want in self.dns.get(name, []) else "invalid"
            return httpx.Response(200, json={"status": "processing"}, headers=h)
        if p == "/order/1":
            if self.order["status"] == "pending" and all(a["status"] == "valid" for a in self.authz.values()):
                self.order["status"] = "ready"
            return httpx.Response(200, json=self.order, headers=h)
        if p == "/finalize":
            assert self.order["status"] == "ready"
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization
            csr = x509.load_der_x509_csr(b64u_decode(payload["csr"]))
            names = [i["value"] for i in (a["identifier"] for a in self.authz.values())]
            cert, chain = self.ca.issue(csr.public_bytes(serialization.Encoding.PEM).decode(), names)
            self.pem = cert + chain
            self.order.update(status="valid", certificate=f"{B}/cert/1")
            return httpx.Response(200, json=self.order, headers=h)
        if p == "/cert/1":
            return httpx.Response(200, text=self.pem, headers={**h, "Content-Type": "application/pem-certificate-chain"})
        return httpx.Response(404, headers=h)


def _issuer(tmp_path, srv, **kw):
    return AcmeIssuer(tmp_path, f"{B}/directory", dns_hook=srv.dns_hook, propagation_seconds=0,
                      http=httpx.Client(transport=httpx.MockTransport(srv.handler)), poll_interval=0, **kw)


def test_dns01_issuance_with_wildcard(tmp_path):
    srv = FakeAcme(LocalCA(tmp_path))
    acme = _issuer(tmp_path, srv)
    names = ["example.test", "*.example.test"]
    key = generate_key()
    cert, chain = acme.issue(build_csr(key, names[0], names), names)
    info = parse_pem(cert)
    assert sorted(info.sans) == sorted(names)
    assert "BEGIN CERTIFICATE" in chain
    assert srv.dns["_acme-challenge.example.test"] == []   # both TXT values cleaned up


def test_eab_required_and_used(tmp_path):
    secret = b"supersecret-hmac"
    srv = FakeAcme(LocalCA(tmp_path), eab=("kid-1", secret))
    with pytest.raises(AcmeError):
        _issuer(tmp_path, srv).ensure_account()
    srv2 = FakeAcme(LocalCA(tmp_path), eab=("kid-1", secret))
    acme = _issuer(tmp_path, srv2, eab_kid="kid-1", eab_hmac_key=base64.urlsafe_b64encode(secret).decode())
    acme.ensure_account()
    assert acme.kid.endswith("/acct/1")


def test_wrong_dns_value_fails_and_cleans_up(tmp_path):
    srv = FakeAcme(LocalCA(tmp_path))
    acme = _issuer(tmp_path, srv)
    acme.dns_hook = lambda action, name, value: srv.dns_hook(action, name, "WRONG" if action == "present" else "WRONG")
    with pytest.raises(AcmeError):
        acme.issue(build_csr(generate_key(), "a.test", ["a.test"]), ["a.test"])
    assert srv.dns["_acme-challenge.a.test"] == []


# ---- Let's Encrypt behaviours: profiles, ARI, alternate chains, rate limits ------------------------------

class LetsEncryptLike(FakeAcme):
    """FakeAcme plus what Let's Encrypt adds: meta.profiles, renewalInfo, alternate chains, rate limits."""

    def __init__(self, ca, **kw):
        super().__init__(ca, **kw)
        self.orders: list[dict] = []
        self.reject_replaces = False
        self.rate_limit = False
        self.busy_once = False
        self.window = ("2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z")
        self.ari_calls = 0

    def handler(self, req):
        p = req.url.path
        if p == "/directory":
            return httpx.Response(200, json={"newNonce": f"{B}/nonce", "newAccount": f"{B}/acct", "newOrder": f"{B}/order",
                                             "renewalInfo": f"{B}/ari",
                                             "meta": {"profiles": {"classic": "", "shortlived": ""}}})
        if p.startswith("/ari/"):
            self.ari_calls += 1
            self.ari_id = p.rsplit("/", 1)[1]
            return httpx.Response(200, json={"suggestedWindow": {"start": self.window[0], "end": self.window[1]}},
                                  headers={"Retry-After": "21600"})
        if p == "/order" and req.method == "POST":
            if self.busy_once:
                self.busy_once = False
                return httpx.Response(503, headers={"Retry-After": "0", "Replay-Nonce": self.nonce()})
            body = json.loads(b64u_decode(json.loads(req.content)["payload"]))
            if self.rate_limit:
                return httpx.Response(429, headers={"Retry-After": "3600", "Replay-Nonce": self.nonce()},
                                      json={"type": "urn:ietf:params:acme:error:rateLimited", "detail": "too many"})
            if self.reject_replaces and "replaces" in body:
                return httpx.Response(409, headers={"Replay-Nonce": self.nonce()},
                                      json={"type": "urn:ietf:params:acme:error:alreadyReplaced"})
            self.orders.append(body)
        if p == "/cert/1":
            alt = LocalCA(self.alt_dir, name="Alt Root")              # a second chain, as Let's Encrypt offers
            leaf = self.pem.split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n"
            self.alt_pem = leaf + alt.ca_pem
            r = super().handler(req)
            r.headers["Link"] = f'<{B}/cert/1/alt>;rel="alternate"'
            return r
        if p == "/cert/1/alt":
            return httpx.Response(200, text=self.alt_pem, headers={"Replay-Nonce": self.nonce()})
        return super().handler(req)


def _le(tmp_path, **kw):
    srv = LetsEncryptLike(LocalCA(tmp_path / "ca"))
    srv.alt_dir = tmp_path / "alt"
    srv.bad_nonce_once = False
    return srv, _issuer(tmp_path, srv, **kw)


def test_profile_is_sent_and_unknown_profiles_are_refused(tmp_path):
    srv, acme = _le(tmp_path, profile="shortlived")
    acme.issue(build_csr(generate_key(), "a.test", ["a.test"]), ["a.test"])
    assert srv.orders[-1]["profile"] == "shortlived"
    _, bad = _le(tmp_path / "2", profile="weekly")
    with pytest.raises(ValueError, match="offers no profile 'weekly'"):
        bad.issue(build_csr(generate_key(), "a.test", ["a.test"]), ["a.test"])


def test_ari_window_cert_id_and_replaces(tmp_path):
    from farrier.issuers.acme import ari_cert_id
    srv, acme = _le(tmp_path)
    cert, _ = acme.issue(build_csr(generate_key(), "a.test", ["a.test"]), ["a.test"])
    assert acme.renewal_window(cert) == srv.window
    assert srv.ari_id == ari_cert_id(cert) and "." in srv.ari_id
    acme.renewal_window(cert)
    assert srv.ari_calls == 1                                 # cached for the CA's Retry-After
    acme.issue(build_csr(generate_key(), "a.test", ["a.test"]), ["a.test"], replaces_pem=cert)
    assert srv.orders[-1]["replaces"] == ari_cert_id(cert)
    srv.reject_replaces = True                                # already replaced: order again without the hint
    acme.issue(build_csr(generate_key(), "a.test", ["a.test"]), ["a.test"], replaces_pem=cert)
    assert "replaces" not in srv.orders[-1]


def test_rate_limit_reports_when_to_retry_and_503_is_retried_once(tmp_path):
    srv, acme = _le(tmp_path)
    srv.busy_once = True
    acme.issue(build_csr(generate_key(), "a.test", ["a.test"]), ["a.test"])   # 503 Retry-After: 0, then fine
    srv.rate_limit = True
    with pytest.raises(AcmeError) as e:
        acme.issue(build_csr(generate_key(), "a.test", ["a.test"]), ["a.test"])
    assert e.value.type.endswith(":rateLimited") and e.value.retry_after == 3600 and "retry after 3600s" in str(e.value)


def test_engine_plans_inside_the_cas_ari_window(tmp_path, monkeypatch):
    from datetime import datetime, timedelta, timezone

    from farrier.engine import Engine
    eng = Engine(tmp_path / "data", issuers={"default": {"kind": "local"}})
    eid = eng.store.upsert_endpoint({"name": "a.test", "host": "127.0.0.1", "port": 1, "sni": "a.test",
                                     "window": {}, "tags": [], "enabled": True})
    now = datetime(2026, 11, 12, tzinfo=timezone.utc)
    nb, na = now - timedelta(days=10), now + timedelta(days=80)          # not due for weeks by lifetime policy

    class Cert:
        fingerprint, subject_cn, sans, issuer, key_type = "ab" * 32, "a.test", ["a.test"], "CA", "ec"
        not_before, not_after = nb, na
    eng.store.add_observation(eid, Cert)
    rid = eng.store.create_renewal(eid, now.isoformat(), None, None, "seed")
    eng.store.update_renewal(rid, state="done", new_fingerprint="ab" * 32, cert_pem="PEM")

    class Ari:
        supports_ari = True
        def renewal_window(self, pem):
            assert pem == "PEM"
            return ((now + timedelta(days=1)).isoformat(), (now + timedelta(days=2)).isoformat())
    monkeypatch.setattr(Engine, "issuers", property(lambda self: {"default": Ari()}))
    planned = eng.plan(now)
    assert len(planned) == 1
    r = eng.store.renewal(planned[0])
    assert "CA renewal window" in r["reason"]
    assert now + timedelta(days=1) <= datetime.fromisoformat(r["scheduled_for"]) <= now + timedelta(days=3)


def test_preferred_chain_is_chosen_from_the_alternates(tmp_path):
    _, acme = _le(tmp_path, preferred_chain="Alt Root")
    _, chain = acme.issue(build_csr(generate_key(), "a.test", ["a.test"]), ["a.test"])
    assert parse_pem(chain).subject_cn == "Alt Root"
    _, plain = _le(tmp_path / "2", preferred_chain="No Such Root")      # no match: keep the default chain
    _, chain2 = plain.issue(build_csr(generate_key(), "a.test", ["a.test"]), ["a.test"])
    assert parse_pem(chain2).subject_cn == "Farrier Local CA"
