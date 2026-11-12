"""Domain health: a structured TLS report card for an endpoint or any host:port, and post-deploy verification.

Every check is ``{"id", "status": pass|warn|fail, "detail"}``. The report grades the whole:
A (all pass), B (one warning), C (two or three), D (more), F (any failure).

Probing uses only the standard library and ``cryptography``:
  * the served chain comes from a normal handshake (``get_unverified_chain``);
  * TLS 1.0/1.1 support and OCSP stapling come from a hand-built TLS ClientHello, because the local
    OpenSSL usually refuses to *offer* old protocol versions and Python does not expose stapled OCSP;
  * CAA records come from a plain DNS query over UDP, falling back to DNS-over-HTTPS (1.1.1.1).

``verify_deployment`` is the stricter check the engine can run after a deploy: the new fingerprint
AND a complete chain AND a hostname match, on every SNI name and every address (multi-VIP setups).
"""
from __future__ import annotations

import functools
import hashlib
import ipaddress
import os
import socket
import ssl
import struct
import warnings
import weakref
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, NameOID

from farrier.core import policy

PASS, WARN, FAIL = "pass", "warn", "fail"

# Names that never resolve in public DNS: CAA does not apply.
SPECIAL_TLDS = {"test", "local", "localhost", "internal", "invalid", "example", "lan", "home", "corp", "intranet",
                "localdomain", "arpa"}

# Issuer organisation keywords -> CAA identifiers that authorise them (best effort).
CAA_IDS = {
    "let's encrypt": {"letsencrypt.org"}, "digicert": {"digicert.com", "symantec.com", "geotrust.com", "thawte.com"},
    "sectigo": {"sectigo.com", "comodoca.com", "comodo.com", "usertrust.com", "trust-provider.com"},
    "zerossl": {"sectigo.com", "zerossl.com"}, "globalsign": {"globalsign.com"},
    "google trust services": {"pki.goog"}, "amazon": {"amazon.com", "amazontrust.com", "awstrust.com"},
    "entrust": {"entrust.net"}, "buypass": {"buypass.com", "buypass.no"}, "ssl.com": {"ssl.com"},
    "microsoft": {"microsoft.com"}, "godaddy": {"godaddy.com", "starfieldtech.com"},
}


def _check(cid: str, status: str, detail: str, **extra) -> dict:
    return {"id": cid, "status": status, "detail": detail, **extra}


def _fp(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def _cn(name: x509.Name) -> str:
    a = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return a[0].value if a else name.rfc4514_string()


def _is_ip(s: str | None) -> bool:
    try:
        ipaddress.ip_address(s or "")
        return True
    except ValueError:
        return False


# ---- trust store -----------------------------------------------------------------------------
@functools.lru_cache(maxsize=1)
def system_roots() -> tuple[x509.Certificate, ...]:
    """Self-signed roots from the OS/OpenSSL store (and certifi when installed). Intermediates are left out
    on purpose: a server that forgets to send its intermediate must not be rescued by the local store."""
    ders: list[bytes] = []
    try:
        ders += ssl.create_default_context().get_ca_certs(binary_form=True)
    except Exception:
        pass
    pems: list[bytes] = []
    for path in {ssl.get_default_verify_paths().cafile, ssl.get_default_verify_paths().openssl_cafile}:
        if path and os.path.isfile(path):
            try:
                pems.append(Path(path).read_bytes())
            except OSError:
                pass
    try:
        import certifi  # type: ignore
        pems.append(Path(certifi.where()).read_bytes())
    except Exception:
        pass
    out: dict[str, x509.Certificate] = {}
    with warnings.catch_warnings():  # some OS stores hold legacy roots with odd serial numbers
        warnings.simplefilter("ignore")
        _load_roots(ders, pems, out)
    return tuple(c for c in out.values() if c.subject == c.issuer)


def _load_roots(ders: list[bytes], pems: list[bytes], out: dict) -> None:
    for der in ders:
        try:
            c = x509.load_der_x509_certificate(der)
            out[_fp(c)] = c
        except ValueError:
            continue
    for pem in pems:
        try:
            for c in x509.load_pem_x509_certificates(pem):
                out[_fp(c)] = c
        except ValueError:
            continue


def load_pems(pem: str | bytes | None) -> list[x509.Certificate]:
    if not pem:
        return []
    data = pem.encode() if isinstance(pem, str) else pem
    try:
        return x509.load_pem_x509_certificates(data)
    except ValueError:
        return []


def farrier_anchors(data_dir: str | Path | None) -> list[x509.Certificate]:
    """Private roots Farrier knows about: its local CA and an optional FARRIER_TRUST_BUNDLE PEM file."""
    out = []
    if data_dir:
        out += load_pems(_read(Path(data_dir) / "local-ca" / "ca.pem"))
    bundle = os.environ.get("FARRIER_TRUST_BUNDLE")
    if bundle:
        out += load_pems(_read(Path(bundle)))
    return out


def _read(p: Path) -> bytes | None:
    try:
        return p.read_bytes() if p.is_file() else None
    except OSError:
        return None


# ---- probing ---------------------------------------------------------------------------------
def _ctx(version: ssl.TLSVersion | None = None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if version is not None:
        ctx.minimum_version = ctx.maximum_version = version
    return ctx


def _server_name(host: str, sni: str | None) -> str | None:
    return sni or (None if _is_ip(host) else host)


def handshake(host: str, port: int, sni: str | None, timeout: float = 5.0) -> dict:
    """Normal handshake: the presented chain (leaf first), protocol and cipher."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with _ctx().wrap_socket(sock, server_hostname=_server_name(host, sni)) as tls:
            if hasattr(tls, "get_unverified_chain"):
                raw = tls.get_unverified_chain() or []
            else:  # Python 3.11/3.12: the private accessor returns _ssl.Certificate objects
                raw = tls._sslobj.get_unverified_chain() or []  # type: ignore[union-attr]
            ders = [c if isinstance(c, bytes) else c.public_bytes(ssl._ssl.ENCODING_DER) for c in raw]  # type: ignore[attr-defined]
            if not ders:
                ders = [tls.getpeercert(binary_form=True)]
            return {"chain": [x509.load_der_x509_certificate(d) for d in ders], "version": tls.version(),
                    "cipher": (tls.cipher() or [None])[0]}


def _accepts(host: str, port: int, sni: str | None, version: ssl.TLSVersion, timeout: float) -> bool | None:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with _ctx(version).wrap_socket(sock, server_hostname=_server_name(host, sni)):
                return True
    except (OSError, ValueError):  # ssl.SSLError is an OSError
        return False


# A hand-built ClientHello. Used for TLS 1.0/1.1 probing and to request a stapled OCSP response.
_SUITES = [0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0x009E, 0x009F, 0xC009, 0xC013, 0xC00A, 0xC014,
           0xC023, 0xC027, 0xC024, 0xC028, 0x009C, 0x009D, 0x002F, 0x0035, 0x003C, 0x003D, 0x000A]
_SIGALGS = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0201, 0x0203]
TLS_NAMES = {0x0301: "TLSv1.0", 0x0302: "TLSv1.1", 0x0303: "TLSv1.2"}


def _client_hello(version: int, sni: str | None) -> bytes:
    def ext(t: int, data: bytes) -> bytes:
        return struct.pack(">HH", t, len(data)) + data

    exts = b""
    if sni:
        n = sni.encode("ascii", "ignore")
        entry = b"\x00" + struct.pack(">H", len(n)) + n
        exts += ext(0, struct.pack(">H", len(entry)) + entry)
    exts += ext(5, b"\x01\x00\x00\x00\x00")                       # status_request (OCSP)
    groups = b"".join(struct.pack(">H", g) for g in (0x001D, 0x0017, 0x0018, 0x0019))
    exts += ext(10, struct.pack(">H", len(groups)) + groups)       # supported_groups
    exts += ext(11, b"\x01\x00")                                   # ec_point_formats: uncompressed
    if version >= 0x0303:
        sa = b"".join(struct.pack(">H", s) for s in _SIGALGS)
        exts += ext(13, struct.pack(">H", len(sa)) + sa)           # signature_algorithms
    exts += ext(23, b"")                                           # extended_master_secret
    exts += ext(0xFF01, b"\x00")                                   # renegotiation_info
    suites = b"".join(struct.pack(">H", s) for s in _SUITES)
    sid = os.urandom(32)
    body = (struct.pack(">H", version) + os.urandom(32) + bytes([len(sid)]) + sid +
            struct.pack(">H", len(suites)) + suites + b"\x01\x00" + struct.pack(">H", len(exts)) + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def _recv(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def raw_hello(host: str, port: int, sni: str | None, version: int, timeout: float = 5.0) -> dict:
    """Send one ClientHello and read the plaintext part of the server's flight.

    Returns {"accepted": bool, "version": str|None, "chain": [DER...], "ocsp": DER|None, "error": str|None}.
    """
    out: dict = {"accepted": False, "version": None, "chain": [], "ocsp": None, "error": None}
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(_client_hello(version, _server_name(host, sni)))
            hs = b""
            for _ in range(64):
                rtype, _v, length = struct.unpack(">BHH", _recv(sock, 5))
                payload = _recv(sock, length)
                if rtype == 21:
                    out["error"] = f"alert {payload[-1] if payload else '?'}"
                    return out
                if rtype != 22:
                    return out
                hs += payload
                while len(hs) >= 4:
                    mtype, mlen = hs[0], int.from_bytes(hs[1:4], "big")
                    if len(hs) < 4 + mlen:
                        break
                    msg, hs = hs[4:4 + mlen], hs[4 + mlen:]
                    if mtype == 2:      # ServerHello
                        v = struct.unpack(">H", msg[:2])[0]
                        out["version"] = TLS_NAMES.get(v, hex(v))
                        out["accepted"] = v == version
                        if not out["accepted"]:
                            return out
                    elif mtype == 11:   # Certificate
                        total, i = int.from_bytes(msg[:3], "big"), 3
                        while i < 3 + total:
                            clen = int.from_bytes(msg[i:i + 3], "big")
                            out["chain"].append(msg[i + 3:i + 3 + clen])
                            i += 3 + clen
                    elif mtype == 22:   # CertificateStatus
                        if msg[0] == 1:
                            olen = int.from_bytes(msg[1:4], "big")
                            out["ocsp"] = msg[4:4 + olen]
                    elif mtype == 14:   # ServerHelloDone
                        return out
    except (OSError, ConnectionError, struct.error, ValueError) as e:
        out["error"] = f"{type(e).__name__}: {e}"
    return out


# ---- chain and name analysis -----------------------------------------------------------------
def _issued_by(child: x509.Certificate, parent: x509.Certificate) -> bool:
    if child.issuer != parent.subject:
        return False
    try:
        child.verify_directly_issued_by(parent)
        return True
    except Exception:
        return False


def _self_signed(c: x509.Certificate) -> bool:
    return _issued_by(c, c)


def analyse_chain(presented: list[x509.Certificate], anchors: list[x509.Certificate] | tuple,
                  now: datetime | None = None) -> dict:
    """Build leaf -> intermediates -> trust anchor using only the certs the server sent plus self-signed anchors.

    Returns {"status", "detail", "trusted", "complete", "ordered", "path": [subject CNs], "missing": issuer|None}.
    """
    now = now or policy.utcnow()
    leaf, others = presented[0], presented[1:]
    anchor_fps = {_fp(a) for a in anchors}
    by_subject: dict[bytes, list[x509.Certificate]] = {}
    for a in anchors:
        by_subject.setdefault(a.subject.public_bytes(), []).append(a)

    ordered = all(_issued_by(presented[i], presented[i + 1]) for i in range(len(presented) - 1))
    path, cur, used = [leaf], leaf, set()
    trusted = complete = False
    missing = None
    root = None
    for _ in range(10):
        if _fp(cur) in anchor_fps:
            trusted = complete = True
            root = cur
            break
        anchor = next((a for a in by_subject.get(cur.issuer.public_bytes(), []) if _issued_by(cur, a)), None)
        if anchor is not None:
            path.append(anchor)
            trusted = complete = True
            root = anchor
            break
        nxt = next((c for i, c in enumerate(others) if i not in used and c is not cur and _issued_by(cur, c)), None)
        if nxt is not None:
            used.add(others.index(nxt))
            path.append(nxt)
            cur = nxt
            continue
        if _self_signed(cur):
            complete, root = True, cur  # complete, but the root is not trusted here
        else:
            missing = _cn(cur.issuer)
        break

    names = [_cn(c.subject) for c in path]
    # certs not on the path; a cross-signed copy of a path cert (same subject, sent for old clients) is fine
    on_path = {c.subject for c in path}
    extra = [_cn(c.subject) for i, c in enumerate(others) if i not in used and c.subject not in on_path]
    expired = [_cn(c.subject) for c in path[1:] if c.not_valid_after_utc < now or c.not_valid_before_utc > now]
    shape = " -> ".join(names)
    if missing:
        status, detail = FAIL, f"incomplete chain: the server did not send the issuer of '{_cn(cur.subject)}' " \
                               f"('{missing}'); clients without it cached will fail ({shape})"
    elif not trusted:
        status, detail = FAIL, f"chain ends at '{_cn(root.subject)}', which is not in the trust store ({shape})"
    elif expired:
        status, detail = FAIL, f"expired or not-yet-valid CA certificate in the chain: {', '.join(expired)}"
    elif not ordered or extra:
        parts = []
        if not ordered:
            parts.append("certificates are not in leaf -> issuer order")
        if extra:
            parts.append(f"unneeded certificates sent: {', '.join(extra)}")
        status, detail = WARN, "; ".join(parts) + f" ({shape})"
    else:
        status, detail = PASS, f"complete and trusted: {shape}"
    return {"status": status, "detail": detail, "trusted": trusted, "complete": complete and not missing,
            "ordered": ordered, "path": names, "missing": missing}


def cert_names(cert: x509.Certificate) -> tuple[list[str], list[str]]:
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        return list(san.get_values_for_type(x509.DNSName)), [str(i) for i in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        return [], []


def name_matches(pattern: str, name: str) -> bool:
    """RFC 6125: exact match, or a wildcard in the whole left-most label covering exactly one label."""
    p, n = pattern.lower().rstrip("."), name.lower().rstrip(".")
    if p == n:
        return True
    if p.startswith("*.") and "." in n:
        rest = p[2:]
        return rest.count(".") >= 1 and n.split(".", 1)[1] == rest and n.split(".", 1)[0] != ""
    return False


def hostname_check(cert: x509.Certificate, names: list[str]) -> dict:
    dns, ips = cert_names(cert)
    names = [n for n in dict.fromkeys(names) if n]
    if not names:
        return _check("hostname", WARN, "no hostname to check (connected by IP without SNI and the endpoint has no "
                                        "configured names)")
    missing = []
    for n in names:
        if _is_ip(n):
            ok = any(ipaddress.ip_address(n) == ipaddress.ip_address(i) for i in ips)
        else:
            ok = any(name_matches(d, n) for d in dns)
        if not ok:
            missing.append(n)
    if not dns and not ips:
        return _check("hostname", FAIL, f"certificate has no subjectAltName (CN '{_cn(cert.subject)}' only); "
                                        "modern clients ignore the CN", missing=names)
    if missing:
        return _check("hostname", FAIL, f"not covered by the certificate: {', '.join(missing)} "
                                        f"(SANs: {', '.join(dns + ips)[:300]})", missing=missing)
    return _check("hostname", PASS, f"{', '.join(names)} covered by SANs", missing=[])


def expiry_check(cert: x509.Certificate, now: datetime) -> dict:
    nb, na = cert.not_valid_before_utc, cert.not_valid_after_utc
    left = policy.days_left(na, now)
    if na < now:
        return _check("expiry", FAIL, f"expired {abs(left):.1f} days ago ({na:%Y-%m-%d})", days_left=round(left, 1))
    if nb > now:
        return _check("expiry", FAIL, f"not valid until {nb:%Y-%m-%d %H:%M} UTC", days_left=round(left, 1))
    lifetime = (na - nb).total_seconds() / 86400
    warn_at = max(7.0, lifetime / 6)
    if left < warn_at:
        return _check("expiry", WARN, f"expires in {left:.1f} days ({na:%Y-%m-%d})", days_left=round(left, 1))
    return _check("expiry", PASS, f"{left:.0f} days left ({na:%Y-%m-%d})", days_left=round(left, 1))


def lifetime_check(cert: x509.Certificate, now: datetime) -> dict:
    nb, na = cert.not_valid_before_utc, cert.not_valid_after_utc
    days = round((na - nb).total_seconds() / 86400)
    at_issue, today = policy.max_lifetime_days(nb), policy.max_lifetime_days(now)
    if days > at_issue:
        return _check("lifetime", WARN, f"{days}-day lifetime exceeds the {at_issue}-day CA/B Forum maximum in force "
                                        "when it was issued; browsers reject such publicly trusted certificates",
                      lifetime_days=days, max_days=today)
    note = f"; the next one can be at most {today} days" if days > today else ""
    return _check("lifetime", PASS, f"{days}-day lifetime (maximum now {today} days){note}",
                  lifetime_days=days, max_days=today)


def key_check(cert: x509.Certificate) -> dict:
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        kt = f"RSA-{pub.key_size}"
        if pub.key_size < 2048:
            return _check("key", FAIL, f"{kt}: RSA keys under 2048 bits are breakable and refused by CAs", key=kt)
        return _check("key", PASS, kt, key=kt)
    if isinstance(pub, ec.EllipticCurvePublicKey):
        kt = f"EC-{pub.curve.name}"
        if pub.curve.key_size < 256:
            return _check("key", FAIL, f"{kt}: curve too small", key=kt)
        return _check("key", PASS, kt, key=kt)
    if isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        kt = type(pub).__name__.replace("PublicKey", "")
        return _check("key", WARN, f"{kt}: not supported by most browsers for TLS server certificates", key=kt)
    if isinstance(pub, dsa.DSAPublicKey):
        return _check("key", FAIL, "DSA keys are no longer accepted for TLS", key="DSA")
    return _check("key", WARN, f"unrecognised key type {type(pub).__name__}", key=type(pub).__name__)


def _sig_name(c: x509.Certificate) -> str:
    h = c.signature_hash_algorithm
    oid = c.signature_algorithm_oid._name  # e.g. ecdsa-with-SHA384, sha256WithRSAEncryption
    return oid if oid and oid != "Unknown OID" else (h.name if h else "unknown")


def signature_check(chain: list[x509.Certificate]) -> dict:
    weak = []
    for c in chain:
        if c.subject == c.issuer:  # a root's self-signature is never checked by clients
            continue
        h = c.signature_hash_algorithm
        if h is not None and isinstance(h, (hashes.SHA1, hashes.MD5)):
            weak.append(f"'{_cn(c.subject)}' ({_sig_name(c)})")
    if weak:
        return _check("signature", FAIL, f"weak signature hash: {', '.join(weak)}", algorithm=_sig_name(chain[0]))
    return _check("signature", PASS, _sig_name(chain[0]), algorithm=_sig_name(chain[0]))


def tls_versions_check(host: str, port: int, sni: str | None, timeout: float) -> dict:
    offered = {}
    for v in (0x0301, 0x0302):
        offered[TLS_NAMES[v]] = raw_hello(host, port, sni, v, timeout)["accepted"]
    offered["TLSv1.2"] = bool(_accepts(host, port, sni, ssl.TLSVersion.TLSv1_2, timeout))
    offered["TLSv1.3"] = bool(_accepts(host, port, sni, ssl.TLSVersion.TLSv1_3, timeout))
    on = [k for k, v in offered.items() if v]
    old = [k for k in ("TLSv1.0", "TLSv1.1") if offered[k]]
    if old:
        return _check("tls_versions", FAIL, f"deprecated protocol accepted: {', '.join(old)} (RFC 8996); "
                                            f"offered: {', '.join(on)}", offered=offered)
    if not on:
        return _check("tls_versions", WARN, "could not determine supported versions", offered=offered)
    return _check("tls_versions", PASS, f"offered: {', '.join(on)}", offered=offered)


def _ocsp_url(cert: x509.Certificate) -> str | None:
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    except x509.ExtensionNotFound:
        return None
    for d in aia:
        if d.access_method == AuthorityInformationAccessOID.OCSP:
            return d.access_location.value
    return None


def ocsp_check(leaf: x509.Certificate, probe: dict) -> dict:
    url = _ocsp_url(leaf)
    if probe.get("ocsp"):
        detail = "OCSP response stapled"
        try:
            from cryptography.x509 import ocsp
            resp = ocsp.load_der_ocsp_response(probe["ocsp"])
            if resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
                st = resp.certificate_status.name.lower()
                if st == "revoked":
                    return _check("ocsp_stapling", FAIL, "stapled OCSP response says the certificate is REVOKED")
                detail += f" (status {st})"
        except Exception:
            pass
        return _check("ocsp_stapling", PASS, detail, stapled=True)
    if not probe.get("accepted"):
        return _check("ocsp_stapling", PASS if not url else WARN,
                      "not observable (server would not complete a TLS 1.2 hello; TLS 1.3 encrypts the staple)"
                      + ("" if url else "; the certificate has no OCSP URL anyway"), stapled=None)
    if url:
        return _check("ocsp_stapling", WARN, f"no OCSP response stapled although the CA runs a responder ({url}); "
                                             "clients must contact the CA themselves", stapled=False)
    return _check("ocsp_stapling", PASS, "not applicable: the certificate has no OCSP responder URL", stapled=False)


# ---- CAA ---------------------------------------------------------------------------------------
def _resolvers() -> list[str]:
    env = os.environ.get("FARRIER_DNS_RESOLVER")
    if env:
        return [r.strip() for r in env.split(",") if r.strip()]
    out = []
    try:
        for line in Path("/etc/resolv.conf").read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver" and _is_ip(parts[1]):
                out.append(parts[1])
    except OSError:
        pass
    return out[:2] + ["1.1.1.1"]


def _skip_name(buf: bytes, i: int) -> int:
    while True:
        n = buf[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:
            return i + 2
        i += 1 + n


def dns_caa_udp(name: str, resolver: str, timeout: float = 2.0) -> tuple[int, list[tuple[int, str, str]]]:
    """One CAA query. Returns (rcode, [(flags, tag, value)]). Raises on timeout or truncation."""
    qid = int.from_bytes(os.urandom(2), "big")
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for label in name.rstrip(".").split("."):
        b = label.encode("idna") if label else b""
        q += bytes([len(b)]) + b
    q += b"\x00" + struct.pack(">HH", 257, 1)
    family = socket.AF_INET6 if ":" in resolver else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(q, (resolver, 53))
        for _ in range(5):
            resp, _addr = s.recvfrom(4096)
            if len(resp) >= 12 and struct.unpack(">H", resp[:2])[0] == qid:
                break
        else:
            raise TimeoutError("no matching DNS response")
    _id, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", resp[:12])
    if flags & 0x0200:
        raise ValueError("truncated DNS response")
    rcode = flags & 0x000F
    i = 12
    for _ in range(qd):
        i = _skip_name(resp, i) + 4
    records = []
    for _ in range(an):
        i = _skip_name(resp, i)
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", resp[i:i + 10])
        i += 10
        rd = resp[i:i + rdlen]
        i += rdlen
        if rtype == 257 and len(rd) >= 2:
            tl = rd[1]
            records.append((rd[0], rd[2:2 + tl].decode("ascii", "replace").lower(),
                            rd[2 + tl:].decode("utf-8", "replace")))
    return rcode, records


def dns_caa_doh(name: str, timeout: float = 3.0) -> tuple[int, list[tuple[int, str, str]]]:
    import httpx
    r = httpx.get("https://1.1.1.1/dns-query", params={"name": name, "type": "CAA"},
                  headers={"accept": "application/dns-json"}, timeout=timeout)
    r.raise_for_status()
    j = r.json()
    out = []
    for a in j.get("Answer") or []:
        if a.get("type") != 257:
            continue
        data = str(a.get("data", ""))
        parts = data.split(" ", 2)
        if len(parts) == 3 and parts[0].isdigit():
            out.append((int(parts[0]), parts[1].lower(), parts[2].strip('"')))
        elif data.startswith("\\#"):  # RFC 3597 generic form: "\# len hex..."
            raw = bytes.fromhex("".join(data.split()[2:]))
            tl = raw[1]
            out.append((raw[0], raw[2:2 + tl].decode().lower(), raw[2 + tl:].decode()))
    return int(j.get("Status", 0)), out


def lookup_caa(name: str) -> tuple[str, list[tuple[int, str, str]]] | None:
    """RFC 8659 tree climbing: the closest ancestor with CAA records wins. Returns (owner, records) or None."""
    labels = name.rstrip(".").lower().lstrip("*.").split(".")
    for i in range(len(labels) - 1):
        candidate = ".".join(labels[i:])
        result = None
        for r in _resolvers():
            try:
                result = dns_caa_udp(candidate, r)
                break
            except Exception:
                continue
        if result is None:
            result = dns_caa_doh(candidate)  # raises when DNS is entirely unreachable
        rcode, records = result
        if rcode not in (0, 3):
            raise RuntimeError(f"DNS error rcode {rcode} for {candidate}")
        if records:
            return candidate, records
    return None


def _publicly_resolvable(name: str) -> bool:
    if not name or _is_ip(name) or "." not in name.strip("."):
        return False
    return name.rstrip(".").rsplit(".", 1)[-1].lower() not in SPECIAL_TLDS


def caa_check(name: str | None, leaf: x509.Certificate | None) -> dict:
    if not name or not _publicly_resolvable(name):
        return _check("caa", PASS, f"not applicable: '{name or 'IP address'}' is not a public DNS name", records=[])
    try:
        found = lookup_caa(name)
    except Exception as e:
        return _check("caa", WARN, f"CAA lookup failed: {e}", records=[])
    if not found:
        return _check("caa", WARN, f"no CAA records for {name} or its parents: any CA may issue for it", records=[])
    owner, recs = found
    wild = name.startswith("*.")
    tags = [t for t in (("issuewild", "issue") if wild else ("issue",)) if any(r[1] == t for r in recs)][:1]
    allowed = {v.split(";")[0].strip().lower() for f, t, v in recs if tags and t == tags[0]}
    shown = [f"{f} {t} \"{v}\"" for f, t, v in recs]
    if leaf is not None and allowed:
        org = " ".join(a.value for a in leaf.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)).lower() \
            or _cn(leaf.issuer).lower()
        ids = set().union(*(v for k, v in CAA_IDS.items() if k in org)) if any(k in org for k in CAA_IDS) else set()
        if ids and not (ids & allowed):
            return _check("caa", WARN, f"CAA at {owner} allows {', '.join(sorted(allowed - {''})) or 'no CA'} "
                                       f"but the certificate was issued by '{org}': the next renewal from this CA "
                                       "will be refused", records=shown)
    return _check("caa", PASS, f"CAA at {owner}: {', '.join(shown)}", records=shown)


# ---- Farrier's own view ------------------------------------------------------------------------
def deployed_check(store, endpoint: dict, served_fp: str | None) -> dict:
    rows = store.q("""SELECT id, state, new_fingerprint, prev_fingerprint, updated_at FROM renewals
                      WHERE endpoint_id=? AND new_fingerprint IS NOT NULL ORDER BY id DESC LIMIT 20""",
                   (endpoint["id"],))
    done = next((r for r in rows if r["state"] == "done"), None)
    open_ = next((r for r in rows if r["state"] in ("issued", "deploying", "verifying", "awaiting_manual")), None)
    if served_fp and open_ and served_fp == open_["new_fingerprint"]:
        return _check("deployed_match", PASS, f"serving the certificate from renewal #{open_['id']} "
                                              f"(state {open_['state']}, not yet confirmed)")
    if done is None:
        return _check("deployed_match", PASS, "Farrier has not completed a renewal for this endpoint yet")
    if served_fp == done["new_fingerprint"]:
        return _check("deployed_match", PASS, f"serving the certificate Farrier deployed in renewal #{done['id']}")
    if served_fp and served_fp == done["prev_fingerprint"]:
        return _check("deployed_match", FAIL, f"serving the certificate renewal #{done['id']} replaced on "
                                              f"{done['updated_at'][:10]}: the change was reverted or a node was missed")
    if open_:
        return _check("deployed_match", WARN, f"serving a certificate Farrier did not deploy; renewal #{open_['id']} is "
                                              f"{open_['state']}")
    return _check("deployed_match", WARN, "serving a certificate Farrier did not deploy (replaced outside Farrier?)")


# ---- the report ----------------------------------------------------------------------------------
def grade(checks: list[dict]) -> str:
    if any(c["status"] == FAIL for c in checks):
        return "F"
    w = sum(1 for c in checks if c["status"] == WARN)
    return "A" if w == 0 else "B" if w == 1 else "C" if w <= 3 else "D"


def check(host: str, port: int = 443, sni: str | None = None, names: list[str] | None = None, *,
          anchors: list[x509.Certificate] | None = None, store=None, endpoint: dict | None = None,
          timeout: float = 5.0, caa: bool = True, now: datetime | None = None) -> dict:
    """Full health report for one host:port (optionally with SNI)."""
    now = now or policy.utcnow()
    target = {"host": host, "port": port, "sni": sni}
    checks: list[dict] = []
    try:
        hs = handshake(host, port, sni, timeout)
    except Exception as e:
        checks.append(_check("connect", FAIL, f"TLS handshake failed: {type(e).__name__}: {e}"))
        return {"target": target, "checked_at": now.isoformat(timespec="seconds"), "grade": "F",
                "summary": {"pass": 0, "warn": 0, "fail": 1}, "checks": checks, "certificate": None,
                "endpoint_id": endpoint and endpoint["id"]}
    chain = hs["chain"]
    leaf = chain[0]
    checks.append(_check("connect", PASS, f"{hs['version']} {hs['cipher']}"))
    roots = list(system_roots()) + list(anchors or [])
    checks.append({"id": "chain", **{k: v for k, v in analyse_chain(chain, roots, now).items() if k != "id"}})
    expected = list(names or [])
    sn = _server_name(host, sni)
    if sn:
        expected.insert(0, sn)
    elif not expected:
        expected = [host]  # an IP: check the IP SAN
    checks.append(hostname_check(leaf, expected))
    checks.append(expiry_check(leaf, now))
    checks.append(lifetime_check(leaf, now))
    checks.append(key_check(leaf))
    checks.append(signature_check(chain))
    checks.append(tls_versions_check(host, port, sni, timeout))
    checks.append(ocsp_check(leaf, raw_hello(host, port, sni, 0x0303, timeout)))
    if caa:
        caa_name = sn or next((n for n in expected if not _is_ip(n)), None)
        checks.append(caa_check(caa_name, leaf))
    served_fp = _fp(leaf)
    if store is not None and endpoint is not None:
        checks.append(deployed_check(store, endpoint, served_fp))
    dns, ips = cert_names(leaf)
    return {
        "target": target, "checked_at": now.isoformat(timespec="seconds"), "grade": grade(checks),
        "summary": {s: sum(1 for c in checks if c["status"] == s) for s in (PASS, WARN, FAIL)},
        "checks": checks, "endpoint_id": endpoint and endpoint["id"],
        "certificate": {"fingerprint": served_fp, "subject": _cn(leaf.subject), "issuer": _cn(leaf.issuer),
                        "sans": dns + ips, "serial": format(leaf.serial_number, "x"),
                        "not_before": leaf.not_valid_before_utc.isoformat(),
                        "not_after": leaf.not_valid_after_utc.isoformat(), "chain_length": len(chain)},
    }


# Last report per endpoint, for the farrier_health_check_failed gauge. Keyed by Store so tests stay isolated.
_LAST: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()


def last_reports(store) -> dict[int, dict]:
    return _LAST.setdefault(store, {})


def endpoint_names(ep: dict) -> list[str]:
    return [n for n in [ep.get("common_name"), *(ep.get("sans") or [])] if n]


def check_endpoint(engine, ep: dict, caa: bool = True) -> dict:
    report = check(ep["host"], ep["port"], ep.get("sni"), endpoint_names(ep), anchors=farrier_anchors(engine.data_dir),
                   store=engine.store, endpoint=ep, timeout=float(engine.settings.get("scan_timeout", 5.0)), caa=caa)
    report["endpoint"] = ep["name"]
    last_reports(engine.store)[ep["id"]] = report
    store_grade(engine.store, ep["id"], report["grade"], report["checked_at"])
    return report


def store_grade(store, endpoint_id: int, grade_: str, checked_at: str) -> None:
    """Keep the last grade per endpoint in the database, where health alert rules (on any replica) read it."""
    try:
        with store.transaction():
            if not store._run("UPDATE health_results SET grade=?, checked_at=? WHERE endpoint_id=?",
                              (grade_, checked_at, endpoint_id))[1]:
                store.x("INSERT INTO health_results(endpoint_id, grade, checked_at) VALUES (?,?,?)",
                        (endpoint_id, grade_, checked_at))
    except Exception:  # noqa: BLE001 - a report is still useful when it can't be stored
        pass


def check_targets(engine, targets: list[tuple[str, int, str | None]], caa: bool = True, workers: int = 8) -> list[dict]:
    """Health for arbitrary scan targets; a target that is an inventory endpoint gets the deployed_match check."""
    anchors = farrier_anchors(engine.data_dir)

    def one(t):
        host, port, sni = t
        ep = engine.store.endpoint_by_addr(host, port, sni)
        if ep:
            return check_endpoint(engine, ep, caa=caa)
        return check(host, port, sni, anchors=anchors, timeout=float(engine.settings.get("scan_timeout", 5.0)), caa=caa)

    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(targets)))) as pool:
        return list(pool.map(one, targets))


# ---- deployment verification -------------------------------------------------------------------
def _resolve(host: str, port: int) -> list[str]:
    if _is_ip(host):
        return [host]
    try:
        return list(dict.fromkeys(ai[4][0] for ai in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)))
    except OSError:
        return []


def verify_deployment(host: str, port: int, sni: str | None, expected_fingerprint: str,
                      expected_names: list[str] | None = None, *, addresses: list[str] | None = None,
                      resolve_all: bool = True, trust_pems: str | None = None, require_trusted: bool = True,
                      timeout: float = 5.0, max_probes: int = 64) -> dict:
    """Is the new certificate really live everywhere it should be?

    Checks, on every (address, SNI) combination:
      * the served leaf has ``expected_fingerprint`` (sha256 of the DER, as CertInfo.fingerprint);
    and on the primary handshake:
      * the chain is complete (every intermediate sent) and reaches a trust anchor: the system roots plus the
        self-signed certificates in ``trust_pems`` (pass the renewal's chain_pem for a private CA);
      * every name in ``expected_names`` is covered by the certificate.

    ``addresses`` adds more VIPs/nodes to probe ("10.0.0.5", "10.0.0.6:8443"); with ``resolve_all`` every A/AAAA
    record of ``host`` is probed too, so one stale node behind round-robin DNS is caught.
    """
    names = [n for n in dict.fromkeys(expected_names or []) if n]
    primary_sni = _server_name(host, sni)
    # every concrete name the certificate should carry is also tried as SNI (wildcards cannot be sent)
    sni_names = list(dict.fromkeys([primary_sni] + [n for n in names if not _is_ip(n) and "*" not in n]))
    conns: list[tuple[str, int]] = [(host, port)]
    if resolve_all:
        conns += [(ip, port) for ip in _resolve(host, port)]
    for a in addresses or []:
        h, _, p = a.rpartition(":") if a.count(":") == 1 else (a, "", "")
        conns.append((h or a, int(p) if p else port))
    # an IP that the hostname resolves to is the same node; keep the explicit ones and drop exact duplicates
    conns = list(dict.fromkeys(conns))
    probes, problems = [], []
    combos = [(c, s) for c in conns for s in sni_names][:max_probes]

    def probe(item):
        (h, p), s = item
        try:
            hs = handshake(h, p, s, timeout)
            fp = _fp(hs["chain"][0])
            return {"address": f"{h}:{p}", "sni": s, "fingerprint": fp, "ok": fp == expected_fingerprint,
                    "error": None, "_hs": hs}
        except Exception as e:
            return {"address": f"{h}:{p}", "sni": s, "fingerprint": None, "ok": False,
                    "error": f"{type(e).__name__}: {e}", "_hs": None}

    with ThreadPoolExecutor(max_workers=max(1, min(16, len(combos)))) as pool:
        results = list(pool.map(probe, combos))
    primary = results[0] if results else None
    primary_hs = None
    for r in results:
        hs = r.pop("_hs")
        if r is primary:
            primary_hs = hs
        probes.append(r)
        if not r["ok"]:
            problems.append(f"{r['address']} (SNI {r['sni'] or '-'}) " +
                            (f"failed: {r['error']}" if r["error"] else f"serves {r['fingerprint'][:16]}"))
    fingerprint_ok = bool(probes) and all(p["ok"] for p in probes)

    chain_res = hostname_res = None
    if primary is not None and primary_hs is not None and primary["ok"]:
        anchors = list(system_roots()) + [c for c in load_pems(trust_pems) if c.subject == c.issuer]
        chain_res = analyse_chain(primary_hs["chain"], anchors)
        if not chain_res["complete"] or (require_trusted and not chain_res["trusted"]):
            problems.append(f"chain: {chain_res['detail']}")
        hostname_res = hostname_check(primary_hs["chain"][0], names or ([primary_sni] if primary_sni else [host]))
        if hostname_res["status"] == FAIL:
            problems.append(f"hostname: {hostname_res['detail']}")
    chain_ok = bool(chain_res) and chain_res["complete"] and (chain_res["trusted"] or not require_trusted)
    hostname_ok = bool(hostname_res) and hostname_res["status"] != FAIL
    return {"ok": fingerprint_ok and chain_ok and hostname_ok, "fingerprint_ok": fingerprint_ok,
            "chain_ok": chain_ok, "hostname_ok": hostname_ok, "chain": chain_res, "hostname": hostname_res,
            "probes": probes, "problems": problems}


__all__ = [
    "analyse_chain",
    "check",
    "check_endpoint",
    "check_targets",
    "grade",
    "hostname_check",
    "last_reports",
    "lookup_caa",
    "name_matches",
    "raw_hello",
    "verify_deployment",
]
