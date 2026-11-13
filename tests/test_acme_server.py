"""Farrier's ACME server (RFC 8555), driven by Farrier's own ACME client over the real API."""
import hashlib
import hmac
import json

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from fastapi.testclient import TestClient

from farrier.api.app import create_app
from farrier.core.acme_server import validate
from farrier.core.engine import Engine
from farrier.core.x509util import build_csr, generate_key, parse_pem
from farrier.issuers.acme import AcmeError, AcmeIssuer, b64u, b64u_decode
from farrier.issuers.local_ca import LocalCA

B = "https://farrier.test"
ADMIN = {"Authorization": "Bearer admin"}


class RevocableCA(LocalCA):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.revoked = []

    def revoke(self, cert_pem, reason="unspecified"):
        self.revoked.append((parse_pem(cert_pem).fingerprint, reason))


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("FARRIER_API_TOKEN", "admin")
    rev = RevocableCA(tmp_path / "rev", name="Revocable CA")
    eng = Engine(tmp_path / "data", issuers={"default": LocalCA(tmp_path / "ca"), "rev": rev}, settings={
        "acme_server": {"internal": {"issuer": "default", "allowed_names": ["*.test"], "lifetime_days": 7},
                        "rev": {"issuer": "rev", "allowed_names": ["*.internal.test"], "orders_per_hour": 3}},
        "policy": {"default": {"allowed_names": ["*.internal.test"]}}})   # narrower than the "internal" profile
    return eng, TestClient(create_app(eng), base_url=B), rev


def eab(api, profile="internal", names=()):
    r = api.post("/api/acme-server/eab", json={"profile": profile, "names": list(names)}, headers=ADMIN)
    assert r.status_code == 200, r.text
    return r.json()["kid"], r.json()["hmac_key"]


def client(tmp_path, api, profile="internal", key=None, name="c"):
    (tmp_path / name).mkdir(exist_ok=True)
    kid, mac = key or (None, None)
    return AcmeIssuer(tmp_path / name, f"{B}/acme/{profile}/directory", dns_hook=lambda *a: None,
                      propagation_seconds=0, eab_kid=kid, eab_hmac_key=mac, http=api, poll_interval=0)


def issue(acme, names):
    return acme.issue(build_csr(generate_key(), names[0], names), names)


def test_account_order_finalize_download_and_inventory(tmp_path, env):
    eng, api, _ = env
    acme = client(tmp_path, api, key=eab(api))
    names = ["app.internal.test", "*.internal.test"]
    cert, chain = issue(acme, names)
    info = parse_pem(cert)
    assert sorted(info.sans) == sorted(names) and info.lifetime_days == 7          # the profile's lifetime
    assert parse_pem(chain).subject_cn == "Farrier Local CA"
    again = client(tmp_path, api)                     # same account key, no EAB: the existing account comes back
    again.ensure_account()
    assert again.kid == acme.kid
    rows = api.get("/api/acme-server/certificates", headers=ADMIN).json()
    assert rows[0]["fingerprint"] == info.fingerprint and rows[0]["issuer"] == "default"
    assert api.get("/api/acme-server/certificates").status_code == 401              # admin only
    assert eng.store.certificate_pems(info.fingerprint)["cert_pem"] == cert
    log = [e["message"] for e in eng.store.q("SELECT message FROM events")]
    assert any("issued by default to account" in m and info.fingerprint[:16] in m for m in log)
    d = api.get("/acme/internal/directory").json()
    assert d["meta"]["externalAccountRequired"] and d["newOrder"] == f"{B}/acme/internal/new-order"
    assert api.get("/acme/nope/directory").json()["type"].endswith(":malformed")


def test_revoke_where_the_issuer_can(tmp_path, env):
    eng, api, rev = env
    acme = client(tmp_path, api, "rev", eab(api, "rev"))
    cert, _ = issue(acme, ["a.internal.test"])
    acme.revoke(cert, "keyCompromise")
    assert rev.revoked == [(parse_pem(cert).fingerprint, "keyCompromise")]
    with pytest.raises(AcmeError) as e:                  # the client tolerates alreadyRevoked; the server says it
        acme.post(acme.directory["revokeCert"], {"certificate": b64u(_der(cert))})
    assert e.value.type.endswith(":alreadyRevoked")
    other = client(tmp_path, api, "rev", eab(api, "rev"), name="other")
    with pytest.raises(AcmeError) as e:                  # not the ordering account
        other.revoke(issue(acme, ["b.internal.test"])[0])
    assert e.value.status == 403
    local = client(tmp_path, api, key=eab(api), name="local")
    with pytest.raises(AcmeError) as e:                  # a local CA publishes no revocation
        local.revoke(issue(local, ["c.internal.test"])[0])
    assert e.value.type.endswith(":unauthorized") and "cannot revoke" in str(e.value)


def test_names_outside_policy_are_rejected_identifiers(tmp_path, env):
    eng, api, _ = env
    acme = client(tmp_path, api, key=eab(api))
    for name in ("a.example.com",                        # outside the profile
                 "a.other.test"):                        # in the profile, outside the global issuance policy
        with pytest.raises(AcmeError) as e:
            issue(acme, ["ok.internal.test", name])
        assert e.value.type.endswith(":rejectedIdentifier")
        assert e.value.problem["subproblems"][0]["identifier"]["value"] == name
    narrow = client(tmp_path, api, key=eab(api, names=["*.web.internal.test"]), name="narrow")
    issue(narrow, ["x.web.internal.test"])
    with pytest.raises(AcmeError) as e:                  # outside the EAB key's own patterns
        issue(narrow, ["x.db.internal.test"])
    assert e.value.type.endswith(":rejectedIdentifier")
    with pytest.raises(AcmeError) as e:
        issue(acme, ["bad_name.internal.test"])
    assert e.value.type.endswith(":rejectedIdentifier")


def test_external_account_binding(tmp_path, env):
    eng, api, _ = env
    with pytest.raises(AcmeError) as e:
        client(tmp_path, api, name="none").ensure_account()
    assert e.value.type.endswith(":externalAccountRequired")
    kid, mac = eab(api)
    with pytest.raises(AcmeError) as e:                  # wrong HMAC key
        client(tmp_path, api, key=(kid, b64u(b"x" * 32)), name="wrong").ensure_account()
    assert e.value.type.endswith(":unauthorized")
    with pytest.raises(AcmeError):                       # a key from another profile
        client(tmp_path, api, "rev", key=(kid, mac), name="otherprofile").ensure_account()
    first = client(tmp_path, api, key=(kid, mac), name="first")
    first.ensure_account()
    with pytest.raises(AcmeError) as e:                  # one account per key
        client(tmp_path, api, key=(kid, mac), name="second").ensure_account()
    assert "already registered" in str(e.value)
    assert api.delete(f"/api/acme-server/eab/{kid}", headers=ADMIN).json() == {"ok": True}
    with pytest.raises(AcmeError) as e:                  # deleting the key revokes its account
        issue(first, ["a.internal.test"])
    assert e.value.status == 401 and "revoked" in str(e.value)
    assert api.post("/api/acme-server/eab", json={"profile": "nope"}, headers=ADMIN).status_code == 400


def test_nonces_are_single_use_and_bad_ones_are_retried(tmp_path, env):
    eng, api, _ = env
    acme = client(tmp_path, api, key=eab(api))
    acme.ensure_account()
    acme._nonce = "made-up"                              # badNonce, then the client retries with the fresh one
    issue(acme, ["a.internal.test"])
    url = acme.directory["newOrder"]
    jws = json.dumps(acme._sign(url, {"identifiers": [{"type": "dns", "value": "b.internal.test"}]}, False))
    h = {"Content-Type": "application/jose+json"}
    assert api.post(url, content=jws, headers=h).status_code == 201
    replay = api.post(url, content=jws, headers=h)
    assert replay.status_code == 400 and replay.json()["type"].endswith(":badNonce") and replay.headers["Replay-Nonce"]
    acme._nonce = None
    stale = acme._sign(url, {"identifiers": [{"type": "dns", "value": "c.internal.test"}]}, False)
    eng.store.x("UPDATE acme_nonces SET expires='2000-01-01T00:00:00+00:00'")    # expired nonces are refused too
    assert api.post(url, content=json.dumps(stale), headers=h).json()["type"].endswith(":badNonce")


def test_url_header_must_match(tmp_path, env):
    _, api, _ = env
    acme = client(tmp_path, api, key=eab(api))
    acme.ensure_account()
    jws = acme._sign(f"{B}/acme/rev/new-order", {"identifiers": [{"type": "dns", "value": "a.internal.test"}]}, False)
    r = api.post(acme.directory["newOrder"], content=json.dumps(jws), headers={"Content-Type": "application/jose+json"})
    assert r.status_code == 401 and r.json()["type"].endswith(":unauthorized")
    assert r.headers["content-type"] == "application/problem+json"


def test_csr_must_match_the_order(tmp_path, env):
    _, api, _ = env
    acme = client(tmp_path, api, key=eab(api))
    acme.ensure_account()
    order = acme._new_order(["a.internal.test"], None).json()
    assert order["status"] == "ready"
    authz = acme.post(order["authorizations"][0]).json()
    assert authz["status"] == "valid" and authz["identifier"]["value"] == "a.internal.test"
    for names in (["b.internal.test"], ["a.internal.test", "b.internal.test"]):
        csr = build_csr(generate_key(), names[0], names)
        with pytest.raises(AcmeError) as e:
            acme.post(order["finalize"], {"csr": b64u(_csr_der(csr))})
        assert e.value.type.endswith(":badCSR")
    with pytest.raises(AcmeError) as e:                  # the account key may not be the certificate key
        acme.post(order["finalize"], {"csr": b64u(_csr_der(build_csr(acme.account_key, "a.internal.test",
                                                                          ["a.internal.test"])))})
    assert e.value.type.endswith(":badCSR")
    acme.post(order["finalize"], {"csr": b64u(_csr_der(build_csr(generate_key("rsa2048"), "a.internal.test",
                                                                  ["a.internal.test"])))})
    with pytest.raises(AcmeError) as e:                  # finalized once
        acme.post(order["finalize"], {"csr": b64u(_csr_der(build_csr(generate_key(), "a.internal.test",
                                                                      ["a.internal.test"])))})
    assert e.value.type.endswith(":orderNotReady")


def test_rate_limit_and_body_size(tmp_path, env):
    _, api, _ = env
    acme = client(tmp_path, api, "rev", eab(api, "rev"))
    acme.ensure_account()
    for i in range(3):
        acme._new_order([f"n{i}.internal.test"], None)
    with pytest.raises(AcmeError) as e:
        acme._new_order(["n4.internal.test"], None)
    assert e.value.status == 429 and e.value.type.endswith(":rateLimited") and e.value.retry_after
    r = api.post("/acme/rev/new-order", content=b"x" * 70000, headers={"Content-Type": "application/jose+json"})
    assert r.status_code == 413


# ---- account keys other than P-256: RS256 and EdDSA, signed by hand ---------------------------------------

def _jws(key, alg, url, payload, nonce, jwk=None, kid=None):
    prot = {"alg": alg, "nonce": nonce, "url": url, **({"jwk": jwk} if jwk else {"kid": kid})}
    p64, b64 = b64u(json.dumps(prot).encode()), b64u(json.dumps(payload).encode())
    data = f"{p64}.{b64}".encode()
    sig = key.sign(data, padding.PKCS1v15(), hashes.SHA256()) if alg == "RS256" else key.sign(data)
    return json.dumps({"protected": p64, "payload": b64, "signature": b64u(sig)})


def _eab(kid, mac, url, jwk):
    p, b = b64u(json.dumps({"alg": "HS256", "kid": kid, "url": url}).encode()), b64u(json.dumps(jwk).encode())
    return {"protected": p, "payload": b, "signature": b64u(hmac.new(b64u_decode(mac), f"{p}.{b}".encode(),
                                                                       hashlib.sha256).digest())}


def test_rsa_and_ed25519_account_keys(env):
    _, api, _ = env
    url, h = f"{B}/acme/internal/new-account", {"Content-Type": "application/jose+json"}
    rk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    n = rk.public_key().public_numbers()
    ek = ed25519.Ed25519PrivateKey.generate()
    keys = [(rk, "RS256", {"e": b64u(n.e.to_bytes(3, "big")), "kty": "RSA", "n": b64u(n.n.to_bytes(256, "big"))}),
            (ek, "EdDSA", {"crv": "Ed25519", "kty": "OKP", "x": b64u(ek.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw))})]
    for key, alg, jwk in keys:
        nonce = api.head("/acme/internal/new-nonce").headers["Replay-Nonce"]
        body = {"termsOfServiceAgreed": True, "externalAccountBinding": _eab(*eab(api), url, jwk)}
        r = api.post(url, content=_jws(key, alg, url, body, nonce, jwk=jwk), headers=h)
        assert r.status_code == 201, r.text
        nonce = r.headers["Replay-Nonce"]
        order = {"identifiers": [{"type": "dns", "value": "a.internal.test"}]}
        r = api.post(f"{B}/acme/internal/new-order", headers=h,
                     content=_jws(key, alg, f"{B}/acme/internal/new-order", order, nonce, kid=r.headers["Location"]))
        assert r.status_code == 201, r.text
    forged = ed25519.Ed25519PrivateKey.generate()        # signed by another key than the jwk names
    nonce = api.head("/acme/internal/new-nonce").headers["Replay-Nonce"]
    r = api.post(url, content=_jws(forged, "EdDSA", url, {}, nonce, jwk=keys[1][2]), headers=h)
    assert r.status_code == 400 and r.json()["detail"] == "JWS signature does not verify"
    r = api.post(url, content=_jws(ek, "ES256", url, {}, nonce, jwk=keys[1][2]), headers=h)   # alg/key mismatch
    assert r.json()["type"].endswith(":badPublicKey")
    r = api.post(url, content=_jws(ek, "HS256", url, {}, nonce, jwk=keys[1][2]), headers=h)
    assert r.json()["type"].endswith(":badSignatureAlgorithm")


def test_settings_are_validated():
    validate({"p": {"issuer": "default", "allowed_names": ["*.x.test"]}})
    for bad in ({"p": {"issuer": "default"}}, {"p": {"issuer": "default", "allowed_names": ["a"], "validation": "dns-01"}},
                {"P!": {"issuer": "default", "allowed_names": ["a"]}},
                {"p": {"issuer": "default", "allowed_names": ["a"], "base_url": "https://x/acme"}}):
        with pytest.raises(ValueError):
            validate(bad)


def test_cli_eab_create_list_delete(tmp_path, capsys):
    from farrier.cli import main
    (tmp_path / "settings.json").write_text(json.dumps({"acme_server": {"internal": {
        "issuer": "default", "allowed_names": ["*.internal.test"]}}}))
    main(["--data", str(tmp_path), "acme-server", "eab", "create", "internal", "--names", "*.a.internal.test", "--json"])
    key = json.loads(capsys.readouterr().out)
    assert key["kid"].startswith("fae_") and len(b64u_decode(key["hmac_key"])) == 32
    main(["--data", str(tmp_path), "acme-server", "eab", "list"])
    out = capsys.readouterr().out
    assert key["kid"] in out and key["hmac_key"] not in out and "*.a.internal.test" in out
    main(["--data", str(tmp_path), "acme-server", "eab", "delete", key["kid"]])
    assert "revoked" in capsys.readouterr().out


def _der(pem):
    from cryptography import x509
    return x509.load_pem_x509_certificate(pem.encode()).public_bytes(serialization.Encoding.DER)


def _csr_der(pem):
    from cryptography import x509
    return x509.load_pem_x509_csr(pem.encode()).public_bytes(serialization.Encoding.DER)


def test_eab_payload_may_carry_extra_jwk_members(env):
    """Some JOSE libraries put "alg"/"use" into the JWK they bind: same key, so the binding must be accepted."""
    _, api, _ = env
    url, h = f"{B}/acme/internal/new-account", {"Content-Type": "application/jose+json"}
    ek = ed25519.Ed25519PrivateKey.generate()
    jwk = {"crv": "Ed25519", "kty": "OKP", "x": b64u(ek.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw))}
    nonce = api.head("/acme/internal/new-nonce").headers["Replay-Nonce"]
    body = {"termsOfServiceAgreed": True, "externalAccountBinding": _eab(*eab(api), url, {**jwk, "alg": "EdDSA", "use": "sig"})}
    r = api.post(url, content=_jws(ek, "EdDSA", url, body, nonce, jwk=jwk), headers=h)
    assert r.status_code == 201, r.text
    other = ed25519.Ed25519PrivateKey.generate()        # but a binding over another key is still refused
    other_jwk = {**jwk, "x": b64u(other.public_key().public_bytes(serialization.Encoding.Raw,
                                                                  serialization.PublicFormat.Raw))}
    nonce = r.headers["Replay-Nonce"]
    k2 = ed25519.Ed25519PrivateKey.generate()
    jwk2 = {**jwk, "x": b64u(k2.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))}
    body = {"termsOfServiceAgreed": True, "externalAccountBinding": _eab(*eab(api), url, other_jwk)}
    assert api.post(url, content=_jws(k2, "EdDSA", url, body, nonce, jwk=jwk2), headers=h).status_code == 401
