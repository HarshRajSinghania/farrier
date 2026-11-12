"""Minimal RFC 8555 ACME client, DNS-01 only.

The point of Farrier: the appliance never talks to the CA. Farrier proves domain
control through DNS on the appliance's behalf, gets the cert, then pushes it to the box.
Works with Let's Encrypt, Google Trust Services, and commercial CAs' ACME endpoints
(DigiCert, Sectigo, Entrust...) via External Account Binding.

DNS-01 is solved either by built-in providers (`dns`: "auto" or a named account from <data>/dns.json,
see farrier.dns; records are checked on the zone's authoritative nameservers before the CA is asked),
or by the original hook contract, kept unchanged for backward compatibility.

DNS hook contract (certbot-style), either a Python callable or a shell command:
    action in {"present", "cleanup"}, name="_acme-challenge.example.com", value="<txt>"
Shell hooks receive FARRIER_DNS_ACTION / FARRIER_DNS_NAME / FARRIER_DNS_VALUE. "present"
must ADD a TXT value (example.com and *.example.com share one record name).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from ..vault import load_private_key, save_private_key
from ..x509util import split_pem_chain

LETSENCRYPT = "https://acme-v02.api.letsencrypt.org/directory"
LETSENCRYPT_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class AcmeError(Exception):
    def __init__(self, status: int, problem: dict | str):
        self.status = status
        self.problem = problem
        super().__init__(f"ACME {status}: {problem}")

    @property
    def type(self) -> str:
        return self.problem.get("type", "") if isinstance(self.problem, dict) else ""


def jwk_of(key: ec.EllipticCurvePrivateKey) -> dict:
    nums = key.public_key().public_numbers()
    return {"crv": "P-256", "kty": "EC",
            "x": b64u(nums.x.to_bytes(32, "big")), "y": b64u(nums.y.to_bytes(32, "big"))}


def thumbprint(jwk: dict) -> str:
    canon = json.dumps({k: jwk[k] for k in ("crv", "kty", "x", "y")}, separators=(",", ":"), sort_keys=True)
    return b64u(hashlib.sha256(canon.encode()).digest())


def dns01_txt_value(token: str, account_thumbprint: str) -> str:
    key_auth = f"{token}.{account_thumbprint}"
    return b64u(hashlib.sha256(key_auth.encode()).digest())


def dns01_record_name(identifier: str) -> str:
    return "_acme-challenge." + identifier.removeprefix("*.")


DnsHook = Callable[[str, str, str], None]


def shell_dns_hook(command: str) -> DnsHook:
    def hook(action: str, name: str, value: str):
        env = {**os.environ, "FARRIER_DNS_ACTION": action, "FARRIER_DNS_NAME": name, "FARRIER_DNS_VALUE": value}
        subprocess.run(command, shell=True, check=True, env=env, timeout=300)
    return hook


class _HookSolver:
    """The original dns_hook flow: present, fixed sleep, clean up whatever was presented."""

    def __init__(self, hook: DnsHook, propagation_seconds: float):
        self.hook, self.propagation_seconds = hook, propagation_seconds
        self.presented: list[tuple[str, str]] = []

    def present(self, name: str, value: str):
        self.hook("present", name, value)
        self.presented.append((name, value))

    def wait(self):
        if self.propagation_seconds:
            time.sleep(self.propagation_seconds)

    def cleanup(self):
        for name, value in self.presented:
            try:
                self.hook("cleanup", name, value)
            except Exception:  # noqa: BLE001 - cleanup must not mask the real error
                pass
        self.presented.clear()


class AcmeIssuer:
    automated_dcv = True
    supports_dns_account = True  # issue() accepts dns_account= (per-endpoint override)

    def __init__(self, data_dir: Path, directory_url: str = LETSENCRYPT_STAGING, email: str | None = None,
                 dns_hook: DnsHook | str | None = None, propagation_seconds: float | None = None,
                 eab_kid: str | None = None, eab_hmac_key: str | None = None,
                 http: httpx.Client | None = None, poll_interval: float = 2.0, timeout: float = 600,
                 dns: str | None = None, dns_accounts=None):
        if dns_hook is None and not dns:
            raise ValueError('ACME issuer needs "dns" ("auto" or a dns.json account) or a dns_hook (command or callable)')
        if dns_hook is not None and dns:
            raise ValueError('ACME issuer: set either "dns" or "dns_hook", not both')
        self.dns_hook = None if dns_hook is None else shell_dns_hook(dns_hook) if isinstance(dns_hook, str) else dns_hook
        self.dns = dns
        self.data_dir = Path(data_dir)
        self._dns_accounts = dns_accounts
        if dns:
            accounts = self.dns_accounts  # validate dns.json (structure + secret refs) now, not at renewal time
            if dns != "auto":
                accounts.get(dns)
        self.directory_url = directory_url
        self.email = email
        # hook mode keeps its historic 60 s sleep; provider mode measures propagation instead of sleeping
        self.propagation_seconds = propagation_seconds if propagation_seconds is not None else (0 if dns else 60)
        self.eab_kid, self.eab_hmac_key = eab_kid, eab_hmac_key
        self.http = http or httpx.Client(timeout=30, headers={"User-Agent": "farrier-acme/0.1"})
        self.poll_interval, self.timeout = poll_interval, timeout
        slug = hashlib.sha256(directory_url.encode()).hexdigest()[:12]
        key_path = Path(data_dir) / f"acme-account-{slug}.key"
        if not key_path.exists():  # the account key is sealed under the master key, owner-only
            save_private_key(key_path, ec.generate_private_key(ec.SECP256R1()), data_dir)
        self.account_key = load_private_key(key_path, data_dir)
        self.jwk = jwk_of(self.account_key)
        self.kid: str | None = None
        self._dir: dict | None = None
        self._nonce: str | None = None

    @property
    def dns_accounts(self):
        if self._dns_accounts is None:
            from ..dns import DnsAccounts
            self._dns_accounts = DnsAccounts.load(self.data_dir)
        return self._dns_accounts

    def _solver(self, dns_account: str | None):
        if dns_account or self.dns_hook is None:
            solver = self.dns_accounts.solver(dns_account or self.dns)
            solver.extra_seconds = self.propagation_seconds
            return solver
        return _HookSolver(self.dns_hook, self.propagation_seconds)

    # ---- transport ---------------------------------------------------------
    @property
    def directory(self) -> dict:
        if self._dir is None:
            r = self.http.get(self.directory_url)
            r.raise_for_status()
            self._dir = r.json()
        return self._dir

    def _new_nonce(self) -> str:
        r = self.http.head(self.directory["newNonce"])
        return r.headers["Replay-Nonce"]

    def _sign(self, url: str, payload, use_jwk: bool) -> dict:
        protected = {"alg": "ES256", "nonce": self._nonce or self._new_nonce(), "url": url}
        self._nonce = None
        if use_jwk:
            protected["jwk"] = self.jwk
        else:
            protected["kid"] = self.kid
        p64 = b64u(json.dumps(protected).encode())
        body64 = "" if payload is None else b64u(json.dumps(payload).encode())
        der = self.account_key.sign(f"{p64}.{body64}".encode(), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return {"protected": p64, "payload": body64, "signature": b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))}

    def post(self, url: str, payload=None, use_jwk: bool = False, accept: str | None = None) -> httpx.Response:
        for attempt in range(4):
            headers = {"Content-Type": "application/jose+json"}
            if accept:
                headers["Accept"] = accept
            resp = self.http.post(url, content=json.dumps(self._sign(url, payload, use_jwk)), headers=headers)
            self._nonce = resp.headers.get("Replay-Nonce")
            if resp.status_code < 400:
                return resp
            try:
                problem = resp.json()
            except ValueError:
                problem = resp.text
            err = AcmeError(resp.status_code, problem)
            if err.type.endswith(":badNonce") and attempt < 3:
                continue
            raise err
        raise AssertionError("unreachable")

    # ---- protocol ----------------------------------------------------------
    def ensure_account(self):
        if self.kid:
            return
        payload: dict = {"termsOfServiceAgreed": True}
        if self.email:
            payload["contact"] = [f"mailto:{self.email}"]
        if self.eab_kid and self.eab_hmac_key:
            url = self.directory["newAccount"]
            prot = b64u(json.dumps({"alg": "HS256", "kid": self.eab_kid, "url": url}).encode())
            body = b64u(json.dumps(self.jwk).encode())
            sig = hmac.new(b64u_decode(self.eab_hmac_key), f"{prot}.{body}".encode(), hashlib.sha256).digest()
            payload["externalAccountBinding"] = {"protected": prot, "payload": body, "signature": b64u(sig)}
        resp = self.post(self.directory["newAccount"], payload, use_jwk=True)
        self.kid = resp.headers["Location"]

    def _poll(self, url: str, done: tuple[str, ...], fail: tuple[str, ...] = ("invalid",)) -> dict:
        deadline = time.monotonic() + self.timeout
        while True:
            obj = self.post(url).json()
            if obj["status"] in done:
                return obj
            if obj["status"] in fail:
                raise AcmeError(400, obj.get("error") or obj)
            if time.monotonic() > deadline:
                raise TimeoutError(f"ACME object {url} stuck in {obj['status']}")
            time.sleep(self.poll_interval)

    def issue(self, csr_pem: str, names: list[str], dns_account: str | None = None) -> tuple[str, str]:
        """dns_account: per-endpoint override ("auto" or a dns.json account); default is the issuer's setting."""
        self.ensure_account()
        resp = self.post(self.directory["newOrder"], {"identifiers": [{"type": "dns", "value": n} for n in names]})
        order, order_url = resp.json(), resp.headers["Location"]

        pending: list[tuple[str, str, str, str]] = []  # (challenge url, record name, txt value, authz url)
        tp = thumbprint(self.jwk)
        for authz_url in order["authorizations"]:
            authz = self.post(authz_url).json()
            if authz["status"] == "valid":
                continue
            chal = next((c for c in authz["challenges"] if c["type"] == "dns-01"), None)
            if chal is None:
                raise AcmeError(400, f"no dns-01 challenge offered for {authz['identifier']['value']}")
            pending.append((chal["url"], dns01_record_name(authz["identifier"]["value"]),
                            dns01_txt_value(chal["token"], tp), authz_url))

        solver = self._solver(dns_account) if pending else None
        try:
            for _, name, value, _ in pending:
                solver.present(name, value)
            if pending:
                solver.wait()
            for chal_url, _, _, _ in pending:
                self.post(chal_url, {})
            for _, _, _, authz_url in pending:
                self._poll(authz_url, ("valid",))
        finally:
            if solver is not None:
                solver.cleanup()  # every presented TXT value, on success and on any failure

        order = self._poll(order_url, ("ready", "valid"))
        if order["status"] == "ready":
            csr_der = x509.load_pem_x509_csr(csr_pem.encode()).public_bytes(serialization.Encoding.DER)
            self.post(order["finalize"], {"csr": b64u(csr_der)})
            order = self._poll(order_url, ("valid",))
        pem = self.post(order["certificate"], accept="application/pem-certificate-chain").text
        certs = split_pem_chain(pem)
        return certs[0], "".join(certs[1:])
