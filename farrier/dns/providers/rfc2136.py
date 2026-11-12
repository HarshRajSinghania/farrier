"""RFC 2136 dynamic update with RFC 8945 TSIG, implemented on the socket module (no dnspython).
Works with BIND, Knot, PowerDNS, Technitium, Windows DNS (TSIG-capable setups).

credentials: tsig_secret (base64, as in the BIND key file)
options:     server (host or IP, required), port (53), tsig_key (key name, required),
             tsig_algorithm (hmac-sha256 | hmac-sha512 | hmac-sha384 | hmac-sha224 | hmac-sha1 | hmac-md5),
             zone (else configured zones / SOA lookup), tcp (default false)
Responses are TSIG-verified: a reply that is unsigned or wrongly signed counts as a failure.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
import struct
import time

from farrier.dns.base import DnsConfigError, DnsError, Provider, norm
from farrier.dns.resolver import (
    CLASS_ANY,
    CLASS_IN,
    CLASS_NONE,
    RCODES,
    SOA,
    TXT,
    encode_name,
    exchange,
    parse_message,
    txt_rdata,
)

TSIG = 250
OPCODE_UPDATE = 5
ALGORITHMS = {
    "hmac-md5": ("hmac-md5.sig-alg.reg.int", hashlib.md5),
    "hmac-sha1": ("hmac-sha1", hashlib.sha1),
    "hmac-sha224": ("hmac-sha224", hashlib.sha224),
    "hmac-sha256": ("hmac-sha256", hashlib.sha256),
    "hmac-sha384": ("hmac-sha384", hashlib.sha384),
    "hmac-sha512": ("hmac-sha512", hashlib.sha512),
}


def _rr(name: str, rtype: int, rclass: int, ttl: int, rdata: bytes) -> bytes:
    return encode_name(name) + struct.pack("!HHIH", rtype, rclass, ttl, len(rdata)) + rdata


def build_update(zone: str, fqdn: str, value: str, add: bool, ttl: int, qid: int) -> bytes:
    """UPDATE message (no TSIG): zone section = zone SOA IN; one update RR.
    add:    <fqdn> <ttl> IN   TXT "value"
    delete: <fqdn> 0     NONE TXT "value"   (RFC 2136 2.5.4: delete exactly this RR)"""
    header = struct.pack("!HHHHHH", qid, OPCODE_UPDATE << 11, 1, 0, 1, 0)
    zone_sec = encode_name(zone) + struct.pack("!HH", SOA, CLASS_IN)
    update = _rr(fqdn, TXT, CLASS_IN if add else CLASS_NONE, ttl if add else 0, txt_rdata(value))
    return header + zone_sec + update


def _time48(t: int) -> bytes:
    return struct.pack("!HI", t >> 32, t & 0xFFFFFFFF)


def tsig_vars(key_name, alg, time_signed, fudge, error=0, other=b"") -> bytes:
    return (encode_name(key_name, lower=True) + struct.pack("!HI", CLASS_ANY, 0) + encode_name(alg, lower=True)
            + _time48(time_signed) + struct.pack("!HHH", fudge, error, len(other)) + other)


def sign(message: bytes, key_name: str, algorithm: str, secret: bytes, time_signed: int | None = None,
         fudge: int = 300) -> tuple[bytes, bytes]:
    """Append a TSIG RR to `message`; return (signed message, MAC)."""
    alg, digest = ALGORITHMS[algorithm]
    time_signed = int(time.time()) if time_signed is None else time_signed
    mac = hmac.new(secret, message + tsig_vars(key_name, alg, time_signed, fudge), digest).digest()
    qid = message[:2]
    rdata = encode_name(alg, lower=True) + _time48(time_signed) + struct.pack("!HH", fudge, len(mac)) + mac \
        + qid + struct.pack("!HH", 0, 0)
    arcount = struct.unpack_from("!H", message, 10)[0] + 1
    signed = message[:10] + struct.pack("!H", arcount) + message[12:] + _rr(key_name, TSIG, CLASS_ANY, 0, rdata)
    return signed, mac


def verify_response(data: bytes, request_mac: bytes, key_name: str, algorithm: str, secret: bytes) -> None:
    msg = parse_message(data)
    if not msg.additional or msg.additional[-1].type != TSIG:
        raise DnsError(f"update {RCODES.get(msg.rcode, msg.rcode)}; response is not TSIG-signed")
    rr = msg.additional[-1]
    rd = rr.rdata
    alg_end = 0
    while rd[alg_end] != 0:
        alg_end += 1 + rd[alg_end]
    alg_wire, o = rd[:alg_end + 1], alg_end + 1
    t_hi, t_lo, fudge, mac_len = struct.unpack_from("!HIHH", rd, o)
    o += 10
    mac = rd[o:o + mac_len]
    o += mac_len
    orig_id, error, other_len = struct.unpack_from("!HHH", rd, o)
    other = rd[o + 6:o + 6 + other_len]
    if error:
        raise DnsError(f"server rejected TSIG: {RCODES.get(error, error)}")
    alg, digest = ALGORITHMS[algorithm]
    if alg_wire.lower() != encode_name(alg, lower=True):
        raise DnsError("response TSIG uses a different algorithm")
    stripped = bytearray(data[:rr.start])
    struct.pack_into("!H", stripped, 0, orig_id)
    struct.pack_into("!H", stripped, 10, len(msg.additional) - 1)
    t = (t_hi << 32) | t_lo
    want = hmac.new(secret, struct.pack("!H", len(request_mac)) + request_mac + bytes(stripped)
                    + tsig_vars(key_name, alg, t, fudge, error, other), digest).digest()
    if not hmac.compare_digest(want, mac):
        raise DnsError("response TSIG signature does not verify")
    if abs(time.time() - t) > fudge:
        raise DnsError("response TSIG time is outside the fudge window")


class RFC2136(Provider):
    name = "rfc2136"
    required = ("tsig_secret",)
    options_known = ("server", "port", "tsig_key", "tsig_algorithm", "zone", "tcp")

    def _update(self, fqdn: str, value: str, add: bool):
        server, key = self.opts.get("server"), self.opts.get("tsig_key")
        if not server or not key:
            raise DnsConfigError(f"dns account {self.account!r}: options.server and options.tsig_key are required")
        algorithm = self.opts.get("tsig_algorithm", "hmac-sha256").lower().rstrip(".")
        if algorithm not in ALGORITHMS:
            raise DnsConfigError(f"dns account {self.account!r}: unsupported tsig_algorithm {algorithm!r}")
        try:
            secret = base64.b64decode(self.secret("tsig_secret"), validate=True)
        except (binascii.Error, ValueError):
            raise DnsConfigError(f"dns account {self.account!r}: tsig_secret is not base64") from None
        zone = norm(self.opts["zone"]) if self.opts.get("zone") else self.find_zone(fqdn).name
        wire = build_update(zone, norm(fqdn), value, add, self.ttl, secrets.randbits(16))
        signed, mac = sign(wire, key, algorithm, secret)
        try:
            resp = exchange(server, signed, port=int(self.opts.get("port", 53)), tcp=bool(self.opts.get("tcp")))
        except OSError as e:
            raise DnsError(f"{self.label}: update to {server} failed: {type(e).__name__}") from None
        rcode = parse_message(resp).rcode
        try:
            verify_response(resp, mac, key, algorithm, secret)
        except DnsError as e:
            raise DnsError(f"{self.label}: {e}") from None
        if rcode != 0:
            raise DnsError(f"{self.label}: update refused: {RCODES.get(rcode, rcode)}")

    def present(self, fqdn, value):
        self._update(fqdn, value, add=True)

    def cleanup(self, fqdn, value):
        self._update(fqdn, value, add=False)
