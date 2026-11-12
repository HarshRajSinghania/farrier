"""Agentless TLS cryptography probe: what a server negotiates, from the outside.

Per target, at most seven short connections, each bounded by ``timeout``:

  1. a normal handshake (stdlib ssl) for the certificate chain: key and signature algorithms
  2-4. hand-built legacy ClientHellos at exactly TLS 1.0, 1.1 and 1.2: accepted? which cipher?
  5. if any legacy version is accepted: the same hello offering only CBC/3DES/RC4 suites
  6. a TLS 1.3-only hello (key share X25519): accepted? cipher, and the group the server picks
     (a HelloRetryRequest names the group it prefers instead)
  7. a TLS 1.3-only hello offering only X25519MLKEM768 (0x11EC): does the server select it?

If the first handshake cannot even connect, the rest are skipped. Results are plain JSON-able dicts.
"""
from __future__ import annotations

import socket
import ssl
import time
from datetime import UTC, datetime

from cryptography import x509

from farrier.core.discovery import _is_ip, peer_chain_der
from farrier.crypto import tls_wire as W
from farrier.crypto.algorithms import cert_summary, is_self_signed, is_sha1_signed

PQC_PROBE_GROUP = W.X25519MLKEM768


def target_label(host: str, port: int, sni: str | None) -> str:
    return (f"{sni}@" if sni else "") + f"{host}:{port}"


def _server_name(host: str, sni: str | None) -> str | None:
    return sni or (None if _is_ip(host) else host)


def send_hello(host: str, port: int, hello: bytes, timeout: float) -> W.ServerReply:
    """Send one ClientHello and read until the server's answer is known. The whole exchange is bounded
    by ``timeout`` (connect included), not just each read."""
    deadline = time.monotonic() + timeout
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(hello)
        reader = W.FlightReader()
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("no ServerHello before the timeout")
            sock.settimeout(left)
            chunk = sock.recv(16384)
            if not chunk:
                return W.ServerReply("unexpected", detail="connection closed without an answer")
            reply = reader.feed(chunk)
            if reply is not None:
                return reply


def _try(host: str, port: int, hello: bytes, timeout: float) -> W.ServerReply:
    try:
        return send_hello(host, port, hello, timeout)
    except (OSError, ValueError) as e:      # socket.timeout and ConnectionError are OSErrors
        return W.ServerReply("error", detail=f"{type(e).__name__}: {e}")


def _certificate(host: str, port: int, sni: str | None, timeout: float) -> tuple[dict, list[x509.Certificate]]:
    """Normal handshake: negotiated version/cipher and the presented chain (leaf first)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock,             ctx.wrap_socket(sock, server_hostname=_server_name(host, sni)) as tls:
        ders = peer_chain_der(tls) or [tls.getpeercert(binary_form=True)]
        info = {"version": tls.version(), "cipher": (tls.cipher() or [None])[0]}
    return info, [x509.load_der_x509_certificate(d) for d in ders]


def _legacy(reply: W.ServerReply, version: int) -> dict:
    ok = reply.kind == "server_hello" and reply.version == version
    return {"accepted": ok, "cipher": W.suite_name(reply.cipher_suite) if ok else None,
            "answer": reply.kind if ok else (reply.detail or reply.kind)}


def probe_tls(host: str, port: int, sni: str | None = None, timeout: float = 5.0) -> dict:
    """Probe one TLS target. Never raises for network problems: ``error`` is set instead."""
    name = _server_name(host, sni)
    out: dict = {"kind": "tls", "target": target_label(host, port, sni), "host": host, "port": port, "sni": sni,
                 "observed_at": datetime.now(UTC).isoformat(timespec="seconds"), "error": None,
                 "handshake": None, "versions": {}, "weak_cipher": None, "tls13_group": None,
                 "pqc": {"group": W.group_name(PQC_PROBE_GROUP), "outcome": "not_tested", "selected": False,
                         "detail": None},
                 "certificate": None, "chain": []}
    try:
        out["handshake"], chain = _certificate(host, port, sni, timeout)
    except ssl.SSLError as e:      # reachable but no handshake we could complete; the raw probes may still learn
        out["handshake"], chain = {"error": f"SSLError: {e.reason or e}"}, []
    except (OSError, ValueError) as e:
        out["error"] = f"{type(e).__name__}: {e}"
        out["pqc"]["outcome"] = "error"
        return out
    if chain:
        out["certificate"] = cert_summary(chain[0]) | {"self_signed": is_self_signed(chain[0])}
        out["certificate"]["sha1_in_chain"] = any(is_sha1_signed(c) and not is_self_signed(c) for c in chain)
        out["chain"] = [{"subject": c.subject.rfc4514_string(), "issuer": c.issuer.rfc4514_string()}
                        for c in chain[1:]]

    for v in (W.TLS10, W.TLS11, W.TLS12):
        out["versions"][W.VERSION_NAMES[v]] = _legacy(_try(host, port, W.client_hello(version=v, sni=name), timeout), v)
    legacy_ok = [v for v in (W.TLS12, W.TLS11, W.TLS10) if out["versions"][W.VERSION_NAMES[v]]["accepted"]]
    if legacy_ok:
        weak = _try(host, port, W.client_hello(version=legacy_ok[0], sni=name, suites=W.WEAK_SUITES), timeout)
        if weak.kind == "server_hello" and weak.version == legacy_ok[0]:
            out["weak_cipher"] = W.suite_name(weak.cipher_suite)

    r13 = _try(host, port, W.client_hello(version=W.TLS13, sni=name, key_shares=[W.X25519]), timeout)
    ok13 = r13.kind in ("server_hello", "hello_retry") and r13.version == W.TLS13
    out["versions"]["TLSv1.3"] = {"accepted": ok13, "cipher": W.suite_name(r13.cipher_suite) if ok13 else None,
                                  "answer": r13.kind if ok13 else (r13.detail or r13.kind)}
    if ok13:
        out["tls13_group"] = W.group_name(r13.group)

    pq = _try(host, port, W.client_hello(version=W.TLS13, sni=name, groups=[PQC_PROBE_GROUP],
                                         key_shares=[PQC_PROBE_GROUP]), timeout)
    out["pqc"].update(pqc_outcome(pq))
    return out


def pqc_outcome(reply: W.ServerReply) -> dict:
    """Interpret the answer to a ClientHello that offered only the PQC hybrid group (pure)."""
    if reply.kind == "server_hello" and reply.version == W.TLS13 and reply.group == PQC_PROBE_GROUP:
        return {"outcome": "selected", "selected": True, "detail": f"key share of {reply.key_share_length} bytes"}
    if reply.kind == "hello_retry":
        return {"outcome": "hello_retry", "selected": False,
                "detail": f"server asked for {W.group_name(reply.group)} instead"}
    if reply.kind == "alert":
        return {"outcome": "alert", "selected": False, "detail": reply.detail}
    if reply.kind == "server_hello":
        return {"outcome": "not_selected", "selected": False,
                "detail": f"server answered with {reply.version_name} / {W.group_name(reply.group)}"}
    return {"outcome": reply.kind, "selected": False, "detail": reply.detail}
