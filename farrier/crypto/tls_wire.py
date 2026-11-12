"""TLS handshake bytes, built and parsed by hand (no OpenSSL involved).

Only the plaintext start of a handshake is needed to learn what a server negotiates: we send one
ClientHello and read records until the ServerHello (or a HelloRetryRequest, or an alert). Nothing here
touches the network, so every branch is unit-testable with crafted bytes.

RFC 8446 (TLS 1.3), RFC 5246 (TLS 1.2), draft-ietf-tls-ecdhe-mlkem (X25519MLKEM768 = 0x11EC).
"""
from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass

# ---- versions ----------------------------------------------------------------------------------
TLS10, TLS11, TLS12, TLS13 = 0x0301, 0x0302, 0x0303, 0x0304
VERSION_NAMES = {TLS10: "TLSv1.0", TLS11: "TLSv1.1", TLS12: "TLSv1.2", TLS13: "TLSv1.3"}

# ---- named groups (IANA "TLS Supported Groups") -----------------------------------------------
X25519, SECP256R1, SECP384R1, SECP521R1, X448 = 0x001D, 0x0017, 0x0018, 0x0019, 0x001E
FFDHE2048, FFDHE3072 = 0x0100, 0x0101
X25519MLKEM768, SECP256R1MLKEM768, SECP384R1MLKEM1024 = 0x11EC, 0x11EB, 0x11ED
MLKEM512, MLKEM768, MLKEM1024 = 0x0200, 0x0201, 0x0202
X25519KYBER768_DRAFT = 0x6399
GROUP_NAMES = {
    X25519: "x25519", SECP256R1: "secp256r1", SECP384R1: "secp384r1", SECP521R1: "secp521r1", X448: "x448",
    FFDHE2048: "ffdhe2048", FFDHE3072: "ffdhe3072",
    X25519MLKEM768: "X25519MLKEM768", SECP256R1MLKEM768: "SecP256r1MLKEM768",
    SECP384R1MLKEM1024: "SecP384r1MLKEM1024", MLKEM512: "MLKEM512", MLKEM768: "MLKEM768", MLKEM1024: "MLKEM1024",
    X25519KYBER768_DRAFT: "X25519Kyber768Draft00",
}
PQC_GROUPS = frozenset({X25519MLKEM768, SECP256R1MLKEM768, SECP384R1MLKEM1024, MLKEM512, MLKEM768, MLKEM1024,
                        X25519KYBER768_DRAFT})

# ---- cipher suites (IANA names) ----------------------------------------------------------------
SUITE_NAMES = {
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384", 0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", 0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCAA: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", 0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256", 0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", 0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", 0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", 0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", 0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA", 0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256", 0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", 0xC008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", 0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA", 0xC007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA", 0x0004: "TLS_RSA_WITH_RC4_128_MD5",
}
TLS13_SUITES = [0x1302, 0x1301, 0x1303]
# Strong first, so a server that honours client order still shows what it would pick for a modern client.
LEGACY_SUITES = [0xC02C, 0xC02B, 0xC030, 0xC02F, 0xCCA9, 0xCCA8, 0x009F, 0x009E, 0xCCAA, 0xC024, 0xC023, 0xC028,
                 0xC027, 0xC00A, 0xC009, 0xC014, 0xC013, 0x0039, 0x0033, 0x009D, 0x009C, 0x003D, 0x003C, 0x0035,
                 0x002F, 0xC012, 0xC008, 0x0016, 0x000A]
# Offered alone to learn whether the server will still agree to an obsolete cipher at all.
WEAK_SUITES = [0xC014, 0xC013, 0xC00A, 0xC009, 0xC028, 0xC027, 0xC024, 0xC023, 0x0039, 0x0033, 0x0035, 0x002F,
               0x003D, 0x003C, 0xC012, 0xC008, 0x0016, 0x000A, 0xC011, 0xC007, 0x0005, 0x0004]

# signature_algorithms: classical, then ML-DSA (draft-ietf-tls-mldsa) so a PQC-certificate server can pick it
SIGALGS = [0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601,
           0x0904, 0x0905, 0x0906, 0x0201, 0x0203]

# ---- record / handshake / extension codes -----------------------------------------------------
REC_CCS, REC_ALERT, REC_HANDSHAKE = 20, 21, 22
HS_SERVER_HELLO = 2
EXT_SNI, EXT_GROUPS, EXT_POINT_FORMATS, EXT_SIGALGS = 0, 10, 11, 13
EXT_EMS, EXT_SUPPORTED_VERSIONS, EXT_PSK_MODES, EXT_KEY_SHARE, EXT_RENEGOTIATION = 23, 43, 45, 51, 0xFF01
HRR_RANDOM = hashlib.sha256(b"HelloRetryRequest").digest()   # RFC 8446 4.1.3
ALERT_NAMES = {0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 40: "handshake_failure",
               47: "illegal_parameter", 50: "decode_error", 51: "decrypt_error", 70: "protocol_version",
               71: "insufficient_security", 80: "internal_error", 86: "inappropriate_fallback",
               109: "missing_extension", 110: "unsupported_extension", 112: "unrecognized_name"}

MAX_RECORD = 16384 + 2048


def suite_name(code: int | None) -> str | None:
    return None if code is None else SUITE_NAMES.get(code, f"0x{code:04X}")


def group_name(code: int | None) -> str | None:
    return None if code is None else GROUP_NAMES.get(code, f"0x{code:04X}")


# ---- building ----------------------------------------------------------------------------------
def _ext(ext_type: int, data: bytes) -> bytes:
    return struct.pack(">HH", ext_type, len(data)) + data


def _u16_list(values: list[int]) -> bytes:
    body = b"".join(struct.pack(">H", v) for v in values)
    return struct.pack(">H", len(body)) + body


def mlkem768_encapsulation_key() -> bytes:
    """A well-formed ML-KEM-768 encapsulation key (FIPS 203): 3 x 256 coefficients < q=3329, packed
    12 bits each, then a 32-byte seed. Servers run the FIPS 203 modulus check on it, so random bytes
    would be refused with illegal_parameter instead of telling us whether the group is supported.
    We never decapsulate: the handshake is abandoned after the ServerHello."""
    q = 3329
    coeffs: list[int] = []
    while len(coeffs) < 768:   # rejection sampling: ~81% of 12-bit values are < q
        coeffs += [v & 0x0FFF for v in struct.unpack(">256H", os.urandom(512)) if v & 0x0FFF < q]
    coeffs = coeffs[:768]
    out = bytearray()
    for a, b in zip(coeffs[0::2], coeffs[1::2]):
        out += bytes([a & 0xFF, (a >> 8) | ((b & 0x0F) << 4), b >> 4])
    return bytes(out) + os.urandom(32)


def key_share_for(group: int) -> bytes:
    """Client key_share bytes for a group. X25519 accepts any 32 bytes as a public value; the hybrid
    X25519MLKEM768 share is the ML-KEM-768 encapsulation key followed by the X25519 share."""
    if group == X25519:
        return os.urandom(32)
    if group == X25519MLKEM768:
        return mlkem768_encapsulation_key() + os.urandom(32)
    raise ValueError(f"no key share generator for group {group_name(group)}")


def client_hello(*, version: int, sni: str | None, suites: list[int] | None = None,
                 groups: list[int] | None = None, key_shares: list[int] | None = None) -> bytes:
    """One ClientHello record.

    ``version`` < TLS13: a legacy hello at exactly that version (no supported_versions extension).
    ``version`` == TLS13: a TLS 1.3-only hello (supported_versions = [1.3], TLS 1.3 suites only)
    with key shares for ``key_shares`` (each must be in ``groups``).
    """
    tls13 = version == TLS13
    suites = suites or (TLS13_SUITES if tls13 else LEGACY_SUITES)
    groups = groups or ([X25519, SECP256R1, SECP384R1, SECP521R1, X448, FFDHE2048, FFDHE3072] if tls13
                        else [X25519, SECP256R1, SECP384R1, SECP521R1])
    exts = b""
    if sni:
        name = sni.encode("idna") if not sni.isascii() else sni.encode("ascii")
        entry = b"\x00" + struct.pack(">H", len(name)) + name
        exts += _ext(EXT_SNI, struct.pack(">H", len(entry)) + entry)
    exts += _ext(EXT_GROUPS, _u16_list(groups))
    exts += _ext(EXT_POINT_FORMATS, b"\x01\x00")
    if version >= TLS12:
        exts += _ext(EXT_SIGALGS, _u16_list(SIGALGS))
    exts += _ext(EXT_EMS, b"")
    exts += _ext(EXT_RENEGOTIATION, b"\x00")
    if tls13:
        exts += _ext(EXT_SUPPORTED_VERSIONS, b"\x02" + struct.pack(">H", TLS13))
        exts += _ext(EXT_PSK_MODES, b"\x01\x01")
        shares = b""
        for g in key_shares or []:
            if g not in groups:
                raise ValueError("a key share must be for an offered group")
            k = key_share_for(g)
            shares += struct.pack(">HH", g, len(k)) + k
        exts += _ext(EXT_KEY_SHARE, struct.pack(">H", len(shares)) + shares)
    sid = os.urandom(32)
    body = (struct.pack(">H", TLS12 if tls13 else version) + os.urandom(32) + bytes([len(sid)]) + sid
            + _u16_list(suites) + b"\x01\x00" + struct.pack(">H", len(exts)) + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return struct.pack(">BHH", REC_HANDSHAKE, TLS10, len(hs)) + hs


# ---- parsing -----------------------------------------------------------------------------------
@dataclass(frozen=True)
class ServerReply:
    """What the server answered to one ClientHello.

    kind: "server_hello" | "hello_retry" | "alert" | "unexpected"
    """
    kind: str
    version: int | None = None        # negotiated (supported_versions wins over legacy_version)
    cipher_suite: int | None = None
    group: int | None = None          # key_share group (selected in ServerHello, requested in HRR)
    key_share_length: int | None = None
    alert: int | None = None
    detail: str | None = None

    @property
    def version_name(self) -> str | None:
        return None if self.version is None else VERSION_NAMES.get(self.version, f"0x{self.version:04X}")


def parse_server_hello(msg: bytes) -> ServerReply:
    """Parse a ServerHello handshake body (without the 4-byte handshake header)."""
    if len(msg) < 38:
        raise ValueError("ServerHello too short")
    legacy_version = struct.unpack(">H", msg[:2])[0]
    random = msg[2:34]
    sid_len = msg[34]
    i = 35 + sid_len
    if len(msg) < i + 3:
        raise ValueError("ServerHello truncated")
    suite = struct.unpack(">H", msg[i:i + 2])[0]
    i += 3                                       # cipher suite + compression method
    version, group, share_len = legacy_version, None, None
    hrr = random == HRR_RANDOM
    if len(msg) >= i + 2:
        ext_end = i + 2 + struct.unpack(">H", msg[i:i + 2])[0]
        if ext_end > len(msg):
            raise ValueError("ServerHello extensions truncated")
        i += 2
        while i + 4 <= ext_end:
            etype, elen = struct.unpack(">HH", msg[i:i + 4])
            data = msg[i + 4:i + 4 + elen]
            if len(data) != elen:
                raise ValueError("ServerHello extension truncated")
            if etype == EXT_SUPPORTED_VERSIONS and elen == 2:
                version = struct.unpack(">H", data)[0]
            elif etype == EXT_KEY_SHARE and elen >= 2:
                group = struct.unpack(">H", data[:2])[0]
                if not hrr and elen >= 4:
                    share_len = struct.unpack(">H", data[2:4])[0]
            i += 4 + elen
    return ServerReply("hello_retry" if hrr else "server_hello", version=version, cipher_suite=suite,
                       group=group, key_share_length=share_len)


class FlightReader:
    """Incremental reader of the server's first flight: feed bytes until ``feed`` returns a reply."""

    def __init__(self) -> None:
        self._buf = b""
        self._hs = b""

    def feed(self, data: bytes) -> ServerReply | None:
        self._buf += data
        while len(self._buf) >= 5:
            rtype, _rver, length = struct.unpack(">BHH", self._buf[:5])
            if rtype not in (REC_CCS, REC_ALERT, REC_HANDSHAKE) or length > MAX_RECORD:
                return ServerReply("unexpected", detail="not a TLS response")
            if len(self._buf) < 5 + length:
                return None
            payload, self._buf = self._buf[5:5 + length], self._buf[5 + length:]
            if rtype == REC_ALERT:
                desc = payload[1] if len(payload) >= 2 else None
                return ServerReply("alert", alert=desc, detail=ALERT_NAMES.get(desc, f"alert {desc}"))
            if rtype == REC_CCS:
                continue
            self._hs += payload
            if len(self._hs) >= 4:
                mtype, mlen = self._hs[0], int.from_bytes(self._hs[1:4], "big")
                if mtype != HS_SERVER_HELLO:
                    return ServerReply("unexpected", detail=f"handshake message {mtype} before ServerHello")
                if len(self._hs) >= 4 + mlen:
                    try:
                        return parse_server_hello(self._hs[4:4 + mlen])
                    except (ValueError, struct.error) as e:
                        return ServerReply("unexpected", detail=str(e))
        return None


def parse_flight(data: bytes) -> ServerReply | None:
    """Parse a complete byte string (for tests and replay); None when it holds no full answer."""
    return FlightReader().feed(data)
