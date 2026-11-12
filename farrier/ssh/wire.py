"""SSH wire format (RFC 4251/4253): pure encoding and parsing, no I/O.

Covers what an unauthenticated probe needs: the identification string, the binary packet framing used
before NEWKEYS (no encryption, no MAC), the data types and SSH_MSG_KEXINIT.
"""
from __future__ import annotations

import os
import re
import struct
from dataclasses import dataclass, field

MSG_DISCONNECT = 1
MSG_IGNORE = 2
MSG_UNIMPLEMENTED = 3
MSG_DEBUG = 4
MSG_KEXINIT = 20
MSG_KEX_ECDH_INIT = 30
MSG_KEX_ECDH_REPLY = 31

MAX_PACKET = 256 * 1024          # a KEXINIT or KEX reply is a few KiB; anything larger is not SSH
MAX_BANNER_LINE = 255            # RFC 4253 4.2, including CR LF
MAX_PRE_BANNER_LINES = 32


class WireError(ValueError):
    """Bytes that are not valid SSH."""


# ---- data types -------------------------------------------------------------------------------------
class Reader:
    def __init__(self, data: bytes):
        self.data, self.pos = data, 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise WireError("truncated SSH message")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def byte(self) -> int:
        return self.take(1)[0]

    def boolean(self) -> bool:
        return self.byte() != 0

    def uint32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def string(self) -> bytes:
        return self.take(self.uint32())

    def mpint(self) -> int:
        return int.from_bytes(self.string(), "big", signed=True)

    def name_list(self) -> list[str]:
        raw = self.string()
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError:
            raise WireError("name-list is not ASCII") from None
        return [n for n in text.split(",") if n]

    def rest(self) -> bytes:
        return self.take(len(self.data) - self.pos)


def string(b: bytes | str) -> bytes:
    if isinstance(b, str):
        b = b.encode()
    return struct.pack(">I", len(b)) + b


def mpint(n: int) -> bytes:
    if n == 0:
        return string(b"")
    raw = n.to_bytes((n.bit_length() + 8) // 8, "big", signed=True)   # keeps a leading 0 for positives
    return string(raw)


def name_list(names: list[str]) -> bytes:
    return string(",".join(names))


def uint32(n: int) -> bytes:
    return struct.pack(">I", n)


# ---- identification string --------------------------------------------------------------------------
@dataclass(frozen=True)
class Banner:
    raw: str
    proto: str          # "2.0", "1.99", "1.5"
    software: str       # "OpenSSH_9.6p1"
    comments: str = ""

    @property
    def openssh_version(self) -> tuple[int, int] | None:
        m = re.match(r"OpenSSH_(\d+)\.(\d+)", self.software)
        return (int(m.group(1)), int(m.group(2))) if m else None


def parse_banner(line: str) -> Banner:
    line = line.rstrip("\r\n")
    m = re.match(r"^SSH-([0-9.]+)-(\S+)(?: (.*))?$", line)
    if not m:
        raise WireError(f"not an SSH identification string: {line[:80]!r}")
    return Banner(raw=line, proto=m.group(1), software=m.group(2), comments=m.group(3) or "")


# ---- packets (before NEWKEYS: no cipher, no MAC) -----------------------------------------------------
def frame(payload: bytes, block: int = 8) -> bytes:
    pad = block - (len(payload) + 5) % block
    if pad < 4:
        pad += block
    return struct.pack(">IB", len(payload) + pad + 1, pad) + payload + os.urandom(pad)


def packet_length(header: bytes) -> int:
    """Validated length of the packet whose first 4 bytes are ``header``."""
    (n,) = struct.unpack(">I", header)
    if n < 5 or n > MAX_PACKET:
        raise WireError(f"implausible packet length {n}")
    return n


def unframe(body: bytes) -> bytes:
    """Payload of a packet, given everything after its length field."""
    pad = body[0]
    if pad < 4 or pad + 1 > len(body):
        raise WireError("bad padding length")
    return body[1:len(body) - pad]


# ---- KEXINIT ----------------------------------------------------------------------------------------
@dataclass
class KexInit:
    kex: list[str]
    host_key: list[str]
    ciphers_c2s: list[str]
    ciphers_s2c: list[str]
    macs_c2s: list[str]
    macs_s2c: list[str]
    compression_c2s: list[str]
    compression_s2c: list[str]
    languages_c2s: list[str] = field(default_factory=list)
    languages_s2c: list[str] = field(default_factory=list)
    first_kex_follows: bool = False
    payload: bytes = b""            # the exact message, needed for the exchange hash

    @property
    def ciphers(self) -> list[str]:
        return _union(self.ciphers_c2s, self.ciphers_s2c)

    @property
    def macs(self) -> list[str]:
        return _union(self.macs_c2s, self.macs_s2c)

    @property
    def compression(self) -> list[str]:
        return _union(self.compression_c2s, self.compression_s2c)


def _union(a: list[str], b: list[str]) -> list[str]:
    return list(dict.fromkeys(a + b))


def parse_kexinit(payload: bytes) -> KexInit:
    r = Reader(payload)
    if r.byte() != MSG_KEXINIT:
        raise WireError("expected SSH_MSG_KEXINIT")
    r.take(16)                                  # cookie
    lists = [r.name_list() for _ in range(10)]
    follows = r.boolean()
    r.uint32()                                  # reserved
    return KexInit(*lists, first_kex_follows=follows, payload=payload)


def build_kexinit(kex: list[str], host_key: list[str], ciphers: list[str], macs: list[str],
                  compression: list[str]) -> bytes:
    body = bytes([MSG_KEXINIT]) + os.urandom(16)
    for names in (kex, host_key, ciphers, ciphers, macs, macs, compression, compression, [], []):
        body += name_list(names)
    return body + b"\x00" + uint32(0)
