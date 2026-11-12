"""Minimal RFC 8555 ACME client, DNS-01 only.

The point of Farrier: the appliance never talks to the CA. Farrier proves domain
control through DNS on the appliance's behalf, gets the cert, then pushes it to the box.
Works with Let's Encrypt, Google Trust Services, and commercial CAs' ACME endpoints
(DigiCert, Sectigo, Entrust...) via External Account Binding.

Let's Encrypt specifics, all optional and harmless against CAs without them:
  * ARI (RFC 9773): renewal_window() asks the CA when to renew, and new orders say which
    certificate they replace, so CA-directed early renewal (incidents, revocations) works.
  * profile: "classic", "tlsserver" or "shortlived" (6-day certificates), checked against the
    directory's meta.profiles.
  * preferred_chain: pick an alternate chain (Link rel="alternate") by its root or issuer name.
  * Rate limits: a 503 with Retry-After is retried once; a 429 rateLimited error says when to retry;
    polling honours Retry-After.

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

from farrier.core.x509util import split_pem_chain
from farrier.security.vault import load_private_key, save_private_key

LETSENCRYPT = "https://acme-v02.api.letsencrypt.org/directory"
LETSENCRYPT_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"


def _version() -> str:
    from farrier import __version__
    return __version__


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class AcmeError(Exception):
    def __init__(self, status: int, problem: dict | str, retry_after: float | None = None):
        self.status = status
        self.problem = problem
        self.retry_after = retry_after
        hint = f" (retry after {int(retry_after)}s)" if retry_after else ""
        super().__init__(f"ACME {status}: {problem}{hint}")

    @property
    def type(self) -> str:
        return self.problem.get("type", "") if isinstance(self.problem, dict) else ""


def _retry_after(resp: httpx.Response) -> float | None:
    """Retry-After as seconds (delta form or HTTP date), or None."""
    v = resp.headers.get("Retry-After")
    if not v:
        return None
    try:
        return max(0.0, float(v))
    except ValueError:
        from email.utils import parsedate_to_datetime
        try:
            return max(0.0, parsedate_to_datetime(v).timestamp() - time.time())
        except (TypeError, ValueError):
            return None


def ari_cert_id(cert_pem: str) -> str:
    """RFC 9773 certificate identifier: base64url(AKI keyIdentifier) "." base64url(serial DER octets)."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier
    serial = cert.serial_number
    return f"{b64u(aki)}.{b64u(serial.to_bytes((serial.bit_length() + 8) // 8, 'big'))}"


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
                 dns: str | None = None, dns_accounts=None, profile: str | None = None,
                 preferred_chain: str | None = None):
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
        self.profile = profile
        self.preferred_chain = preferred_chain
        self._ari_cache: dict[str, tuple[float, tuple[str, str] | None]] = {}
        # hook mode keeps its historic 60 s sleep; provider mode measures propagation instead of sleeping
        self.propagation_seconds = propagation_seconds if propagation_seconds is not None else (0 if dns else 60)
        self.eab_kid, self.eab_hmac_key = eab_kid, eab_hmac_key
        self.http = http or httpx.Client(timeout=30, headers={"User-Agent": f"farrier-acme/{_version()}"})
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

    supports_ari = True

    @property
    def dns_accounts(self):
        if self._dns_accounts is None:
            from farrier.dns import DnsAccounts
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
            wait = _retry_after(resp)
            err = AcmeError(resp.status_code, problem, wait)
            if err.type.endswith(":badNonce") and attempt < 3:
                continue
            if resp.status_code == 503 and wait is not None and wait <= 60 and attempt < 1:
                time.sleep(wait)                 # the CA is briefly busy; once, then give up
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
            resp = self.post(url)
            obj = resp.json()
            if obj["status"] in done:
                return obj
            if obj["status"] in fail:
                raise AcmeError(400, obj.get("error") or obj)
            if time.monotonic() > deadline:
                raise TimeoutError(f"ACME object {url} stuck in {obj['status']}")
            hint = _retry_after(resp)
            time.sleep(min(max(self.poll_interval, hint or 0), 60) if self.poll_interval else 0)

    def _new_order(self, names: list[str], replaces: str | None):
        payload: dict = {"identifiers": [{"type": "dns", "value": n} for n in names]}
        if self.profile:
            offered = (self.directory.get("meta") or {}).get("profiles")
            if offered is not None and self.profile not in offered:
                raise ValueError(f"this CA offers no profile {self.profile!r}; it offers: {', '.join(offered) or 'none'}")
            payload["profile"] = self.profile
        if replaces and "renewalInfo" in self.directory:
            payload["replaces"] = replaces
        try:
            return self.post(self.directory["newOrder"], payload)
        except AcmeError as e:
            # the old certificate was already replaced, or the CA can't match it: order without the hint
            if "replaces" in payload and (e.type.endswith(":alreadyReplaced") or e.status == 409 or
                                          e.type.endswith(":malformed")):
                payload.pop("replaces")
                return self.post(self.directory["newOrder"], payload)
            raise

    def renewal_window(self, cert_pem: str) -> tuple[str, str] | None:
        """RFC 9773: the CA's suggested renewal window (start, end) for a certificate it issued, or None
        when the CA has no renewalInfo. Cached for as long as the CA's Retry-After asks (6 hours if unset)."""
        if "renewalInfo" not in self.directory:
            return None
        try:
            cid = ari_cert_id(cert_pem)
        except (ValueError, x509.ExtensionNotFound):
            return None                  # no key identifier to name it by: the lifetime policy plans it
        cached = self._ari_cache.get(cid)
        if cached and cached[0] > time.monotonic():
            return cached[1]
        r = self.http.get(f"{self.directory['renewalInfo'].rstrip('/')}/{cid}")
        r.raise_for_status()
        w = r.json().get("suggestedWindow") or {}
        window = (w["start"], w["end"]) if w.get("start") and w.get("end") else None
        ttl = _retry_after(r) or 6 * 3600
        self._ari_cache[cid] = (time.monotonic() + min(max(ttl, 60), 24 * 3600), window)
        return window

    def _chain_matches(self, pem: str) -> bool:
        certs = [x509.load_pem_x509_certificate(c.encode()) for c in split_pem_chain(pem)]
        top = certs[-1]
        names = {a.value for n in (top.issuer, top.subject) for a in n.get_attributes_for_oid(x509.NameOID.COMMON_NAME)}
        return self.preferred_chain in names

    def _download(self, url: str) -> str:
        resp = self.post(url, accept="application/pem-certificate-chain")
        pem = resp.text
        if self.preferred_chain and not self._chain_matches(pem):
            for link in resp.headers.get_list("link"):
                for part in link.split(","):
                    if 'rel="alternate"' in part and "<" in part:
                        alt = self.post(part[part.index("<") + 1:part.index(">")],
                                        accept="application/pem-certificate-chain").text
                        if self._chain_matches(alt):
                            return alt
        return pem  # the default chain when none matches: a renewal never fails over chain choice

    def issue(self, csr_pem: str, names: list[str], dns_account: str | None = None,
              replaces_pem: str | None = None) -> tuple[str, str]:
        """dns_account: per-endpoint override ("auto" or a dns.json account); default is the issuer's setting.
        replaces_pem: the certificate this one replaces (RFC 9773), when this CA issued it."""
        self.ensure_account()
        replaces = None
        if replaces_pem:
            try:
                replaces = ari_cert_id(replaces_pem)
            except (ValueError, x509.ExtensionNotFound):
                replaces = None
        resp = self._new_order(names, replaces)
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
        pem = self._download(order["certificate"])
        certs = split_pem_chain(pem)
        return certs[0], "".join(certs[1:])
