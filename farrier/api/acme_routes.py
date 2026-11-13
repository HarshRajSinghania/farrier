"""RFC 8555 ACME server routes (farrier.core.acme_server), unauthenticated by bearer token: every POST is a
JWS signed by an account key, and accounts exist only through External Account Binding.

  GET       /acme/{profile}/directory
  HEAD|GET  /acme/{profile}/new-nonce
  POST      /acme/{profile}/new-account | new-order | revoke-cert
  POST      /acme/{profile}/acct/{id} | acct/{id}/orders | order/{id} | order/{id}/finalize
  POST      /acme/{profile}/authz/{order}/{n} | chall/{order}/{n} | cert/{order}

Admins (the API token, whole install):
  GET    /api/acme-server/eab            EAB keys (never the HMAC key)
  POST   /api/acme-server/eab            {"profile", "names": [...]} -> kid and HMAC key, shown once
  DELETE /api/acme-server/eab/{kid}      delete a key and revoke the account it registered
  GET    /api/acme-server/certificates   every certificate issued over ACME
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import re

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from fastapi import HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from farrier.core import issuance_policy
from farrier.core.acme_server import ORDERS_PER_HOUR, AcmeServer, bad_identifier
from farrier.core.replace import REASONS
from farrier.core.x509util import parse_pem, split_pem_chain
from farrier.db.store import now_iso
from farrier.issuers.acme import JWK_MEMBERS, b64u, b64u_decode, thumbprint

ERR = "urn:ietf:params:acme:error:"
MAX_BODY = 64 * 1024              # a CSR for an RSA-4096 key with 100 names is well under this
MAX_IDENTIFIERS = 100
CURVES = {"ES256": ("P-256", ec.SECP256R1(), 32, hashes.SHA256()), "ES384": ("P-384", ec.SECP384R1(), 48, hashes.SHA384())}
ALGS = (*CURVES, "RS256", "EdDSA")
EAB_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
KEY_TYPES = ("ec256", "ec384", "rsa2048", "rsa3072", "rsa4096")
POST_AS_GET = re.compile(r"^(acct|order|authz|chall|cert)/(\d+)(?:/(orders|finalize|\d+))?$")


class Problem(Exception):
    def __init__(self, status: int, kind: str, detail: str, **extra):
        self.status, self.body = status, {"type": ERR + kind, "detail": detail, "status": status, **extra}
        self.headers = {"Retry-After": "3600"} if kind == "rateLimited" else {}


class EabIn(BaseModel):
    profile: str
    names: list[str] = Field(default_factory=list, max_length=100)


def key_type(pub) -> str | None:
    if isinstance(pub, ec.EllipticCurvePublicKey) and pub.curve.name in ("secp256r1", "secp384r1"):
        return "ec" + str(pub.curve.key_size)
    if isinstance(pub, rsa.RSAPublicKey) and pub.key_size in (2048, 3072, 4096):
        return f"rsa{pub.key_size}"
    return None


def public_key(jwk, alg: str):
    """The account key a JWK describes, if it suits ``alg``; raises Problem(badPublicKey) otherwise."""
    try:
        if not isinstance(jwk, dict) or "d" in jwk:
            raise ValueError("not a public JWK")
        if alg in CURVES:
            crv, curve, size, _ = CURVES[alg]
            x, y = b64u_decode(jwk["x"]), b64u_decode(jwk["y"])
            if jwk["kty"] != "EC" or jwk["crv"] != crv or len(x) != size or len(y) != size:
                raise ValueError(f"{alg} needs an EC {crv} key")
            return ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), curve).public_key()
        if alg == "RS256":
            if jwk["kty"] != "RSA":
                raise ValueError("RS256 needs an RSA key")
            key = rsa.RSAPublicNumbers(int.from_bytes(b64u_decode(jwk["e"]), "big"),
                                       int.from_bytes(b64u_decode(jwk["n"]), "big")).public_key()
            if key.key_size < 2048:
                raise ValueError("RSA account keys must have at least 2048 bits")
            return key
        if jwk["kty"] != "OKP" or jwk["crv"] != "Ed25519":
            raise ValueError("EdDSA needs an Ed25519 key")
        return ed25519.Ed25519PublicKey.from_public_bytes(b64u_decode(jwk["x"]))
    except (KeyError, TypeError, ValueError, AttributeError) as e:
        raise Problem(400, "badPublicKey", f"account key: {e}") from None


def signature_ok(key, alg: str, data: bytes, sig: bytes) -> bool:
    try:
        if alg in CURVES:
            n = CURVES[alg][2]
            if len(sig) != 2 * n:
                return False
            der = encode_dss_signature(int.from_bytes(sig[:n], "big"), int.from_bytes(sig[n:], "big"))
            key.verify(der, data, ec.ECDSA(CURVES[alg][3]))
        elif alg == "RS256":
            key.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
        else:
            key.verify(sig, data)
        return True
    except InvalidSignature:
        return False


def spki(pub) -> bytes:
    return pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def contacts(payload: dict) -> list[str]:
    c = payload.get("contact", [])
    if not isinstance(c, list) or len(c) > 4 or not all(
            isinstance(x, str) and x.startswith("mailto:") and len(x) < 260 and "," not in x for x in c):
        raise Problem(400, "invalidContact", "contact: up to 4 mailto: addresses")
    return c


def mount(app, engine, lock, whole_install, actor) -> None:
    acme = AcmeServer(engine)
    S = engine.store

    @app.exception_handler(Problem)
    async def problem(request: Request, e: Problem):
        headers = {**e.headers, "Replay-Nonce": acme.new_nonce(), "Cache-Control": "no-store"}
        return JSONResponse(e.body, e.status, headers=headers, media_type="application/problem+json")

    def root(request: Request, profile: str) -> tuple[dict, str]:
        p = acme.profile(profile)
        if not p:
            raise Problem(404, "malformed", f"no ACME profile {profile!r}")
        return p, f"{p.get('base_url') or str(request.base_url).rstrip('/')}/acme/{profile}"

    def reply(base: str, body=None, status: int = 200, location: str | None = None, **kw) -> Response:
        headers = {"Replay-Nonce": acme.new_nonce(), "Cache-Control": "no-store", "Link": f'<{base}/directory>;rel="index"'}
        if location:
            headers["Location"] = location
        if body is None:
            return Response(status_code=status, headers=headers, **kw)
        return JSONResponse(body, status, headers=headers)

    @app.get("/acme/{profile}/directory", include_in_schema=False)
    def directory(profile: str, request: Request):
        _, base = root(request, profile)
        return JSONResponse({"newNonce": f"{base}/new-nonce", "newAccount": f"{base}/new-account",
                             "newOrder": f"{base}/new-order", "revokeCert": f"{base}/revoke-cert",
                             "meta": {"externalAccountRequired": True}})

    @app.api_route("/acme/{profile}/new-nonce", methods=["GET", "HEAD"], include_in_schema=False)
    def new_nonce(profile: str, request: Request):
        _, base = root(request, profile)
        return reply(base, status=200 if request.method == "HEAD" else 204)

    @app.post("/acme/{profile}/{path:path}", include_in_schema=False)
    async def post(profile: str, path: str, request: Request):
        if int(request.headers.get("content-length") or 0) > MAX_BODY:
            raise Problem(413, "malformed", f"request body over {MAX_BODY} bytes")
        body = b""
        async for chunk in request.stream():
            body += chunk
            if len(body) > MAX_BODY:
                raise Problem(413, "malformed", f"request body over {MAX_BODY} bytes")
        if request.headers.get("content-type", "").split(";")[0].strip() != "application/jose+json":
            raise Problem(415, "malformed", "Content-Type must be application/jose+json")
        return await run_in_threadpool(handle, profile, path, request, body)

    # ---- JWS (RFC 8555 6.2-6.5) ---------------------------------------------------------------------
    def verify(profile: str, base: str, url: str, body: bytes):
        try:
            jws = json.loads(body)
            prot = json.loads(b64u_decode(jws["protected"]))
            sig, payload64 = b64u_decode(jws["signature"]), jws["payload"]
            if set(jws) != {"protected", "payload", "signature"} or not isinstance(prot, dict) \
                    or not isinstance(payload64, str):
                raise ValueError
        except (ValueError, KeyError, TypeError, AttributeError):
            raise Problem(400, "malformed", "the body must be a flattened JWS with a protected header only") from None
        alg = prot.get("alg")
        if alg not in ALGS:
            raise Problem(400, "badSignatureAlgorithm", f"alg {alg!r} is not supported", algorithms=list(ALGS))
        if prot.get("url") != url:
            raise Problem(401, "unauthorized", "the JWS url header does not match the request URL")
        if ("jwk" in prot) == ("kid" in prot):
            raise Problem(400, "malformed", "the JWS needs exactly one of jwk and kid")
        if "jwk" in prot:
            key = public_key(prot["jwk"], alg)
            jwk = {k: prot["jwk"][k] for k in JWK_MEMBERS[prot["jwk"]["kty"]]}
            account = acme.account_by_key(profile, thumbprint(jwk))
        else:
            kid = prot["kid"]
            m = re.fullmatch(re.escape(base) + r"/acct/(\d+)", kid) if isinstance(kid, str) else None
            account = m and acme.account(profile, int(m.group(1)))
            if not account:
                raise Problem(400, "accountDoesNotExist", "no such account on this profile")
            jwk = json.loads(account["jwk"])
            key = public_key(jwk, alg)
        if not signature_ok(key, alg, f"{jws['protected']}.{payload64}".encode(), sig):
            raise Problem(400, "malformed", "JWS signature does not verify")
        if not acme.use_nonce(prot.get("nonce")):
            raise Problem(400, "badNonce", "unknown, used or expired nonce")
        if "kid" in prot and account["status"] != "valid":
            raise Problem(401, "unauthorized", f"account is {account['status']}")
        try:
            payload = json.loads(b64u_decode(payload64)) if payload64 else None
        except ValueError:
            raise Problem(400, "malformed", "payload is not JSON") from None
        return prot, jwk, key, account, payload

    def handle(profile: str, path: str, request: Request, body: bytes) -> Response:
        p, base = root(request, profile)
        try:
            prot, jwk, key, account, payload = verify(profile, base, f"{base}/{path}", body)
            if path == "new-account":
                return new_account(profile, p, base, prot, jwk, account, payload)
            if path == "revoke-cert":
                return revoke(profile, base, prot, key, account, payload)
            if "kid" not in prot:
                raise Problem(400, "malformed", "this request must be signed with the account's kid")
            if path == "new-order":
                return new_order(profile, p, base, account, payload)
            m = POST_AS_GET.match(path)
            if not m:
                raise Problem(404, "malformed", "no such resource")
            what, oid, sub = m.group(1), int(m.group(2)), m.group(3)
            if what == "acct":
                return account_resource(base, account, oid, sub, payload)
            order = acme.order(profile, oid)
            if not order or order["account_id"] != account["id"]:
                raise Problem(404, "malformed", "no such order for this account")
            if what == "order" and sub == "finalize":
                return finalize(profile, p, base, account, order, key, payload)
            if payload not in (None, {}):
                raise Problem(400, "malformed", "expected POST-as-GET (an empty payload)")
            if what == "order" and sub is None:
                return reply(base, order_body(base, order))
            if what == "cert" and sub is None:
                if order["status"] != "valid":
                    raise Problem(404, "malformed", "no certificate for this order yet")
                return reply(base, content=order["cert_pem"], media_type="application/pem-certificate-chain")
            if what in ("authz", "chall") and sub is not None and sub.isdigit() and int(sub) < len(order["identifiers"]):
                return authz(base, order, int(sub), what == "chall")
            raise Problem(404, "malformed", "no such resource")
        except Problem:
            raise
        except Exception as e:  # noqa: BLE001 - never a stack trace to the client; the log has it
            S.log(f"acme {profile}: {path} failed: {type(e).__name__}: {e}", level="error")
            raise Problem(500, "serverInternal", "internal error; the Farrier activity log has the reason") from None

    # ---- accounts ---------------------------------------------------------------------------------------
    def account_body(base: str, a: dict) -> dict:
        return {"status": a["status"], "contact": json.loads(a["contact"]), "orders": f"{base}/acct/{a['id']}/orders"}

    def new_account(profile, p, base, prot, jwk, account, payload):
        if "jwk" not in prot:
            raise Problem(400, "malformed", "newAccount must be signed with jwk")
        if not isinstance(payload, dict):
            raise Problem(400, "malformed", "newAccount needs a JSON object payload")
        if account:
            if account["status"] != "valid":
                raise Problem(401, "unauthorized", f"account is {account['status']}")
            return reply(base, account_body(base, account), 200, f"{base}/acct/{account['id']}")
        if payload.get("onlyReturnExisting"):
            raise Problem(400, "accountDoesNotExist", "no account for this key")
        contact = contacts(payload)
        eab = payload.get("externalAccountBinding")
        if not isinstance(eab, dict):
            raise Problem(403, "externalAccountRequired", "this server requires External Account Binding: "
                                                          "ask a Farrier admin for an EAB key for this profile")
        kid = check_eab(profile, base, eab, jwk)
        aid = acme.create_account(profile, jwk, thumbprint(jwk), kid, contact)
        if aid is None:
            raise Problem(401, "unauthorized", "this EAB key has already registered an account")
        S.log(f"acme {profile}: account {aid} registered with EAB key {kid}")
        return reply(base, account_body(base, acme.account(profile, aid)), 201, f"{base}/acct/{aid}")

    def check_eab(profile, base, eab, jwk) -> str:
        """RFC 8555 7.3.4: an HMAC JWS over the account key, by a key an admin gave out for this profile."""
        refused = Problem(401, "unauthorized", "the external account binding is not valid")
        try:
            eprot = json.loads(b64u_decode(eab["protected"]))
            row = acme.eab(eprot["kid"]) if isinstance(eprot.get("kid"), str) else None
            alg = EAB_ALGS.get(eprot.get("alg"))
            if (not row or row["profile"] != profile or not alg or "nonce" in eprot or eprot.get("url") != f"{base}/new-account"
                    or json.loads(b64u_decode(eab["payload"])) != jwk):
                raise refused
            mac = hmac.new(b64u_decode(row["hmac"]), f"{eab['protected']}.{eab['payload']}".encode(), alg).digest()
            if not hmac.compare_digest(mac, b64u_decode(eab["signature"])):
                raise refused
        except (KeyError, TypeError, ValueError, AttributeError):
            raise refused from None
        return row["kid"]

    def account_resource(base, account, aid, sub, payload):
        if aid != account["id"]:
            raise Problem(403, "unauthorized", "this is not your account")
        if sub == "orders":
            rows = S.q("SELECT id FROM acme_orders WHERE account_id=? ORDER BY id DESC LIMIT 1000", (aid,))
            return reply(base, {"orders": [f"{base}/order/{r['id']}" for r in rows]})
        if sub is not None:
            raise Problem(404, "malformed", "no such resource")
        payload = payload or {}
        if not isinstance(payload, dict):
            raise Problem(400, "malformed", "account update needs a JSON object payload")
        if "contact" in payload:
            S.x("UPDATE acme_accounts SET contact=? WHERE id=?", (json.dumps(contacts(payload)), aid))
        if payload.get("status") == "deactivated":
            S.x("UPDATE acme_accounts SET status='deactivated' WHERE id=?", (aid,))
            S.log(f"acme {account['profile']}: account {aid} deactivated by its owner")
        elif "status" in payload:
            raise Problem(400, "malformed", "an account can only be deactivated")
        return reply(base, account_body(base, S.q1("SELECT * FROM acme_accounts WHERE id=?", (aid,))))

    # ---- orders -------------------------------------------------------------------------------------------
    def order_body(base: str, o: dict) -> dict:
        body = {"status": o["status"], "expires": o["expires"],
                "identifiers": [{"type": "dns", "value": n} for n in o["identifiers"]],
                "authorizations": [f"{base}/authz/{o['id']}/{i}" for i in range(len(o["identifiers"]))],
                "finalize": f"{base}/order/{o['id']}/finalize"}
        if o["status"] == "valid":
            body["certificate"] = f"{base}/cert/{o['id']}"
        if o["status"] == "invalid" and o.get("error"):
            body["error"] = json.loads(o["error"])
        return body

    def authz(base, order, i, challenge: bool):
        name = order["identifiers"][i]
        chal = {"type": "dns-01", "url": f"{base}/chall/{order['id']}/{i}", "status": "valid",
                "token": b64u(hashlib.sha256(f"farrier-acme/{order['id']}/{i}".encode()).digest()),
                "validated": order["created_at"]}
        if challenge:   # authorized by policy when the order was created: nothing to validate
            return reply(base, chal)
        body = {"identifier": {"type": "dns", "value": name.removeprefix("*.")}, "status": "valid",
                "expires": order["expires"], "challenges": [chal]}
        if name.startswith("*."):
            body["wildcard"] = True
        return reply(base, body)

    def new_order(profile, p, base, account, payload):
        if not isinstance(payload, dict) or not isinstance(payload.get("identifiers"), list) \
                or not 0 < len(payload["identifiers"]) <= MAX_IDENTIFIERS:
            raise Problem(400, "malformed", f"newOrder needs 1 to {MAX_IDENTIFIERS} identifiers")
        if "notBefore" in payload or "notAfter" in payload:
            raise Problem(400, "malformed", "notBefore/notAfter are not supported; the profile sets the lifetime")
        names = []
        for ident in payload["identifiers"]:
            if not isinstance(ident, dict) or ident.get("type") != "dns" or not isinstance(ident.get("value"), str):
                raise Problem(400, "unsupportedIdentifier", "only dns identifiers are supported")
            n = ident["value"].lower().rstrip(".")
            if bad_identifier(n):
                raise Problem(400, "rejectedIdentifier", f"{ident['value']!r} is not a DNS name")
            names.append(n)
        names = list(dict.fromkeys(names))
        if acme.orders_last_hour(account["id"]) >= p.get("orders_per_hour", ORDERS_PER_HOUR):
            raise Problem(429, "rateLimited", "too many orders for this account in the last hour")
        if bad := acme.unauthorized_names(profile, account, names):
            S.log(f"acme {profile}: account {account['id']} refused names {', '.join(bad)} (not allowed by policy)",
                  level="warning")
            raise Problem(400, "rejectedIdentifier", f"not allowed by policy: {', '.join(bad)}", subproblems=[
                {"type": ERR + "rejectedIdentifier", "detail": "not allowed by policy",
                 "identifier": {"type": "dns", "value": n}} for n in bad])
        oid = acme.create_order(profile, account["id"], names)
        return reply(base, order_body(base, acme.order(profile, oid)), 201, f"{base}/order/{oid}")

    def finalize(profile, p, base, account, order, account_key, payload):
        if order["status"] != "ready":
            raise Problem(403, "orderNotReady", f"the order is {order['status']}")
        try:
            csr = x509.load_der_x509_csr(b64u_decode(payload["csr"]))
            if not csr.is_signature_valid:
                raise ValueError
        except (KeyError, TypeError, ValueError, AttributeError):
            raise Problem(400, "badCSR", "csr: a base64url DER PKCS#10 request with a valid signature") from None
        names = {a.value.lower() for a in csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)}
        try:
            san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        except x509.ExtensionNotFound:
            san = []
        if any(not isinstance(g, x509.DNSName) for g in san):
            raise Problem(400, "badCSR", "the CSR may only name DNS names")
        names |= {g.value.lower() for g in san}
        if names != set(order["identifiers"]):
            raise Problem(400, "badCSR", f"the CSR names {', '.join(sorted(names))}; the order is for "
                                         f"{', '.join(sorted(order['identifiers']))}")
        pub = csr.public_key()
        kt = key_type(pub)
        rules = issuance_policy.rules_for(engine.settings.get("policy"), p.get("project")) or {}
        if kt is None or kt not in rules.get("key_types", KEY_TYPES):
            raise Problem(400, "badCSR", f"key type not allowed (allowed: {', '.join(rules.get('key_types', KEY_TYPES))})")
        if spki(pub) == spki(account_key):
            raise Problem(400, "badCSR", "the certificate key must not be the account key")
        if bad := acme.unauthorized_names(profile, account, order["identifiers"]):  # policy may have changed
            raise Problem(400, "rejectedIdentifier", f"no longer allowed by policy: {', '.join(bad)}")
        issuer_name = p["issuer"]
        issuer = engine.issuers.get(issuer_name)
        if issuer is None or ("allowed_issuers" in rules and issuer_name not in rules["allowed_issuers"]):
            S.log(f"acme {profile}: issuer {issuer_name!r} is not configured or not allowed by policy", level="error")
            raise Problem(500, "serverInternal", "this profile's issuer is unavailable")
        if p.get("lifetime_days"):
            if not hasattr(issuer, "lifetime_days"):
                raise Problem(500, "serverInternal", f"issuer {issuer_name} does not take lifetime_days")
            issuer = copy.copy(issuer)
            issuer.lifetime_days = p["lifetime_days"]
        if not S._run("UPDATE acme_orders SET status='processing', issuer=? WHERE id=? AND status='ready'",
                      (issuer_name, order["id"]))[1]:
            raise Problem(403, "orderNotReady", "the order is already being finalized")
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
        try:
            with lock:   # issuers keep state (an upstream ACME account's nonce): one issuance at a time, like ticks
                cert_pem, chain_pem = issuer.issue(csr_pem, order["identifiers"])
            info = parse_pem(cert_pem)
        except Exception as e:  # noqa: BLE001
            err = {"type": ERR + "serverInternal", "detail": "the issuer refused or failed"}
            S.x("UPDATE acme_orders SET status='invalid', error=? WHERE id=?", (json.dumps(err), order["id"]))
            S.log(f"acme {profile}: issuance for account {account['id']} ({', '.join(order['identifiers'])}) by "
                  f"{issuer_name} failed: {type(e).__name__}: {e}", level="error")
            raise Problem(500, "serverInternal", "issuance failed; the Farrier activity log has the reason") from None
        S.x("UPDATE acme_orders SET status='valid', cert_pem=?, fingerprint=?, not_after=? WHERE id=?",
            (cert_pem + chain_pem, info.fingerprint, info.not_after.isoformat(), order["id"]))
        ders = [x509.load_pem_x509_certificate(c.encode()).public_bytes(serialization.Encoding.DER)
                for c in [cert_pem, *split_pem_chain(chain_pem)]]
        S.save_certificate(info.fingerprint, ders[0], ders[1:])   # the inventory's PEM store, by fingerprint
        S.log(f"acme {profile}: certificate {info.fingerprint[:16]} (serial {info.serial}) for "
              f"{', '.join(order['identifiers'])} issued by {issuer_name} to account {account['id']} "
              f"(EAB key {account['eab_kid']}), expires {info.not_after:%Y-%m-%d}")
        return reply(base, order_body(base, acme.order(profile, order["id"])), 200, f"{base}/order/{order['id']}")

    # ---- revocation (RFC 8555 7.6) --------------------------------------------------------------------------
    def revoke(profile, base, prot, key, account, payload):
        try:
            cert = x509.load_der_x509_certificate(b64u_decode(payload["certificate"]))
        except (KeyError, TypeError, ValueError, AttributeError):
            raise Problem(400, "malformed", "certificate: base64url DER") from None
        fp = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        order = S.q1("SELECT * FROM acme_orders WHERE fingerprint=? AND profile=?", (fp, profile))
        if not order:
            raise Problem(404, "malformed", "not a certificate this ACME profile issued")
        if "kid" in prot and order["account_id"] != account["id"]:
            raise Problem(403, "unauthorized", "only the account that ordered a certificate may revoke it")
        if "jwk" in prot and spki(key) != spki(cert.public_key()):
            raise Problem(403, "unauthorized", "a jwk-signed revocation must be signed by the certificate's key")
        if order["revoked_at"]:
            raise Problem(400, "alreadyRevoked", "the certificate is already revoked")
        code = payload.get("reason", 0)
        reason = {v: k for k, v in REASONS.items()}.get(code) if type(code) is int else None
        if reason is None:
            raise Problem(400, "badRevocationReason", f"reason: one of {sorted(REASONS.values())}")
        issuer = engine.issuers.get(order["issuer"])
        if not callable(getattr(issuer, "revoke", None)):
            raise Problem(403, "unauthorized", f"issuer {order['issuer']} cannot revoke certificates "
                                               "(a local CA publishes no revocation); ask a Farrier admin")
        with lock:
            issuer.revoke(order["cert_pem"], reason)
        S.x("UPDATE acme_orders SET revoked_at=? WHERE id=?", (now_iso(), order["id"]))
        who = f"account {account['id']}" if "kid" in prot else "the certificate's key"
        S.log(f"acme {profile}: certificate {fp[:16]} revoked ({reason}) by {who} through {order['issuer']}")
        return reply(base)

    # ---- admin ---------------------------------------------------------------------------------------------
    @app.get("/api/acme-server/eab", dependencies=whole_install)
    def list_eab():
        return acme.eab_keys()

    @app.post("/api/acme-server/eab", dependencies=whole_install)
    def create_eab(body: EabIn, request: Request):
        try:
            key = acme.create_eab(body.profile, body.names)
        except ValueError as e:
            raise HTTPException(400, str(e))
        S.log(f"acme {body.profile}: EAB key {key['kid']} created by {actor(request)}"
              + (f" for {', '.join(body.names)}" if body.names else ""))
        return key | {"directory": f"{str(request.base_url).rstrip('/')}/acme/{body.profile}/directory"}

    @app.delete("/api/acme-server/eab/{kid}", dependencies=whole_install)
    def delete_eab(kid: str, request: Request):
        if not acme.delete_eab(kid):
            raise HTTPException(404, "no such EAB key")
        S.log(f"acme: EAB key {kid} deleted by {actor(request)}; its account is revoked")
        return {"ok": True}

    @app.get("/api/acme-server/certificates", dependencies=whole_install)
    def acme_certificates():
        return acme.certificates()
