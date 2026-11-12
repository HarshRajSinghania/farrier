"""Unauthenticated SSH probe: identification string, the server's KEXINIT, and its host keys.

For each host-key type the server offers, one connection runs the key exchange only as far as the
server's KEX reply, which carries the host key (K_S) and the server's signature over the exchange hash.
The signature is verified, so a recorded key is one the server proved it holds. Nothing is ever
authenticated and NEWKEYS is never sent. Supported exchanges: curve25519-sha256 (and the @libssh.org
alias) and ecdh-sha2-nistp256/384/521. A server offering none of them (OpenSSH < 5.7 era) falls back to
``ssh-keyscan`` when that binary exists; otherwise only the offered algorithms are recorded.
``ProbeResult.method`` says which path ran: "kex", "ssh-keyscan" or "algorithms".
"""
from __future__ import annotations

import hashlib
import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519

from farrier.ssh import wire
from farrier.ssh.keys import SIG_TO_KEY, PublicKey, parse_blob, verify

CLIENT_ID = "SSH-2.0-Farrier_probe"

_ECDH = {"ecdh-sha2-nistp256": (ec.SECP256R1, hashlib.sha256), "ecdh-sha2-nistp384": (ec.SECP384R1, hashlib.sha384),
         "ecdh-sha2-nistp521": (ec.SECP521R1, hashlib.sha512)}
SUPPORTED_KEX = ("curve25519-sha256", "curve25519-sha256@libssh.org", *_ECDH)
# One signature algorithm per key type, strongest first (the RSA key is the same for every rsa-* name).
_HOSTKEY_PREFERENCE = ("ssh-ed25519", "ecdsa-sha2-nistp521", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp256",
                       "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa", "ssh-dss")


class ProbeError(Exception):
    pass


@dataclass
class ProbeResult:
    host: str
    port: int
    banner: wire.Banner | None = None
    kexinit: wire.KexInit | None = None
    host_keys: list[PublicKey] = field(default_factory=list)
    method: str = "algorithms"
    error: str | None = None
    notes: list[str] = field(default_factory=list)


# ---- connection ---------------------------------------------------------------------------------------
class _Conn:
    """A socket with a read buffer: SSH mixes a text line and binary packets in one stream."""

    def __init__(self, host: str, port: int, timeout: float):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.buf = b""

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def _fill(self) -> None:
        chunk = self.sock.recv(65536)
        if not chunk:
            raise ProbeError("connection closed by server")
        self.buf += chunk

    def read_line(self) -> bytes:
        while b"\n" not in self.buf:
            if len(self.buf) > wire.MAX_BANNER_LINE:
                raise ProbeError("identification line too long")
            self._fill()
        line, self.buf = self.buf.split(b"\n", 1)
        return line

    def read_exact(self, n: int) -> bytes:
        while len(self.buf) < n:
            self._fill()
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def read_payload(self) -> bytes:
        """Next message, skipping IGNORE/DEBUG; DISCONNECT becomes an error."""
        while True:
            n = wire.packet_length(self.read_exact(4))
            payload = wire.unframe(self.read_exact(n))
            if not payload:
                raise ProbeError("empty packet")
            if payload[0] in (wire.MSG_IGNORE, wire.MSG_DEBUG):
                continue
            if payload[0] == wire.MSG_DISCONNECT:
                r = wire.Reader(payload[1:])
                r.uint32()
                raise ProbeError(f"server disconnected: {r.string().decode('utf-8', 'replace')[:200]}")
            return payload

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)


def _handshake(c: _Conn) -> tuple[wire.Banner, wire.KexInit | None]:
    c.send((CLIENT_ID + "\r\n").encode())
    for _ in range(wire.MAX_PRE_BANNER_LINES):
        line = c.read_line().decode("utf-8", "replace")
        if line.startswith("SSH-"):
            banner = wire.parse_banner(line)
            break
    else:
        raise ProbeError("no SSH identification string")
    if not banner.proto.startswith(("2.", "1.99")):
        return banner, None  # SSH-1 only: no KEXINIT to read
    return banner, wire.parse_kexinit(c.read_payload())


def _pick_kex(server: wire.KexInit) -> str | None:
    return next((k for k in SUPPORTED_KEX if k in server.kex), None)


def _fetch_host_key(host: str, port: int, kex: str, hostkey_alg: str, timeout: float) -> PublicKey:
    """One connection: KEXINIT exchange + ECDH, up to and including the server's signed reply."""
    c = _Conn(host, port, timeout)
    try:
        banner, server = _handshake(c)
        if server is None:
            raise ProbeError("SSH-1 only server")
        ours = wire.build_kexinit([kex], [hostkey_alg], server.ciphers, server.macs, server.compression)
        c.send(wire.frame(ours))
        if kex.startswith("curve25519"):
            priv = x25519.X25519PrivateKey.generate()
            q_c = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            hasher = hashlib.sha256
        else:
            curve, hasher = _ECDH[kex]
            priv = ec.generate_private_key(curve())
            q_c = priv.public_key().public_bytes(serialization.Encoding.X962,
                                                 serialization.PublicFormat.UncompressedPoint)
        c.send(wire.frame(bytes([wire.MSG_KEX_ECDH_INIT]) + wire.string(q_c)))
        reply = c.read_payload()
        if reply[0] != wire.MSG_KEX_ECDH_REPLY:
            raise ProbeError(f"expected KEX reply, got message {reply[0]}")
        r = wire.Reader(reply[1:])
        k_s, q_s, sig = r.string(), r.string(), r.string()
        if kex.startswith("curve25519"):
            shared = priv.exchange(x25519.X25519PublicKey.from_public_bytes(q_s))
        else:
            shared = priv.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(_ECDH[kex][0](), q_s))
        h = hasher(wire.string(CLIENT_ID) + wire.string(banner.raw) + wire.string(ours) + wire.string(server.payload)
                   + wire.string(k_s) + wire.string(q_c) + wire.string(q_s)
                   + wire.mpint(int.from_bytes(shared, "big"))).digest()
        if not verify(k_s, sig, h):
            raise ProbeError(f"{hostkey_alg} host key signature does not verify")
        return parse_blob(k_s)
    finally:
        c.close()


def keyscan(host: str, port: int, timeout: float) -> list[PublicKey]:
    """Host keys via the ssh-keyscan binary (fallback). Empty when it is not installed."""
    exe = shutil.which("ssh-keyscan")
    if not exe:
        return []
    p = subprocess.run([exe, "-T", str(max(1, int(timeout))), "-p", str(port), "-t", "rsa,ecdsa,ed25519,dsa", "--", host],
                       capture_output=True, text=True, timeout=timeout * 4 + 5)
    return parse_keyscan(p.stdout)


def parse_keyscan(text: str) -> list[PublicKey]:
    import base64
    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3 and not line.startswith("#"):
            try:
                out.append(parse_blob(base64.b64decode(parts[2], validate=True)))
            except (ValueError, wire.WireError):
                continue
    return out


def probe(host: str, port: int = 22, timeout: float = 5.0, fetch_keys: bool = True,
          use_keyscan: bool = True) -> ProbeResult:
    res = ProbeResult(host, port)
    try:
        c = _Conn(host, port, timeout)
        try:
            res.banner, res.kexinit = _handshake(c)
        finally:
            c.close()
    except (OSError, ProbeError, wire.WireError) as e:
        res.error = f"{type(e).__name__}: {e}"
        return res
    if res.kexinit is None or not fetch_keys:
        return res
    kex = _pick_kex(res.kexinit)
    if kex:
        seen: set[str] = set()
        for alg in _HOSTKEY_PREFERENCE:
            ktype = SIG_TO_KEY[alg]
            if alg not in res.kexinit.host_key or ktype in seen:
                continue
            seen.add(ktype)
            try:
                res.host_keys.append(_fetch_host_key(host, port, kex, alg, timeout))
            except (OSError, ProbeError, wire.WireError, ValueError) as e:
                res.notes.append(f"{alg}: {type(e).__name__}: {e}")
        if res.host_keys:
            res.method = "kex"
            return res
    if use_keyscan:
        try:
            res.host_keys = keyscan(host, port, timeout)
        except (OSError, subprocess.SubprocessError) as e:
            res.notes.append(f"ssh-keyscan: {type(e).__name__}: {e}")
        if res.host_keys:
            res.method = "ssh-keyscan"
            return res
    res.notes.append("host keys not obtained: no supported key exchange offered and ssh-keyscan unavailable"
                     if not kex else "host keys not obtained")
    return res


def probe_many(targets: list[tuple[str, int]], workers: int = 32, timeout: float = 5.0) -> list[ProbeResult]:
    if not targets:
        return []
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(targets)))) as pool:
        return list(pool.map(lambda t: probe(t[0], t[1], timeout), targets))
