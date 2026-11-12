"""Small DNS client: RFC 1035 wire format over UDP (TCP on truncation), plus DoH JSON fallback.

Used to find a name's zone (SOA walk), its authoritative nameservers, follow `_acme-challenge` CNAME
delegations, and check that TXT values are visible on *every* authoritative server before the CA is
asked to validate. Fixed sleeps are a guess; this is a measurement.
"""
from __future__ import annotations

import logging
import os
import secrets
import socket
import struct
import time
from dataclasses import dataclass, field

import httpx

from farrier.dns.base import (
    USER_AGENT,
    DnsError,
    DnsPropagationError,
    in_zone,
    norm,
    unquote_txt,
)

log = logging.getLogger("farrier.dns")

A, NS, CNAME, SOA, TXT, AAAA, ANY = 1, 2, 5, 6, 16, 28, 255
TYPE_NAMES = {"A": A, "NS": NS, "CNAME": CNAME, "SOA": SOA, "TXT": TXT, "AAAA": AAAA}
CLASS_IN, CLASS_NONE, CLASS_ANY = 1, 254, 255
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED",
          6: "YXDOMAIN", 7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE",
          16: "BADSIG", 17: "BADKEY", 18: "BADTIME"}
DOH_URLS = ("https://1.1.1.1/dns-query", "https://8.8.8.8/resolve")


class DnsWireError(DnsError):
    pass


# ---- wire format ------------------------------------------------------------------------------------------
def encode_name(name: str, lower: bool = False) -> bytes:
    name = name.strip().rstrip(".")
    out = bytearray()
    if name:
        for label in name.split("."):
            b = label.encode("ascii") if label.isascii() else label.encode("idna")
            if lower:
                b = b.lower()
            if not 0 < len(b) < 64:
                raise DnsWireError(f"invalid DNS label in {name!r}")
            out += bytes([len(b)]) + b
    out += b"\0"
    if len(out) > 255:
        raise DnsWireError("DNS name too long")
    return bytes(out)


def decode_name(msg: bytes, off: int) -> tuple[str, int]:
    labels, end, hops = [], None, 0
    while True:
        if off >= len(msg):
            raise DnsWireError("truncated name")
        n = msg[off]
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(msg):
                raise DnsWireError("truncated pointer")
            if end is None:
                end = off + 2
            off = ((n & 0x3F) << 8) | msg[off + 1]
            hops += 1
            if hops > 64:
                raise DnsWireError("name compression loop")
            continue
        if n == 0:
            off += 1
            break
        labels.append(msg[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n
    return ".".join(labels).lower(), end if end is not None else off


def txt_rdata(value: str) -> bytes:
    b = value.encode()
    out = bytearray()
    for i in range(0, max(len(b), 1), 255):
        chunk = b[i:i + 255]
        out += bytes([len(chunk)]) + chunk
    return bytes(out)


@dataclass
class RR:
    name: str
    type: int
    cls: int
    ttl: int
    rdata: bytes
    value: object = None
    start: int = 0     # offset of the RR in the message (TSIG verification strips the last one)


@dataclass
class Message:
    id: int
    flags: int
    question: list = field(default_factory=list)
    answer: list = field(default_factory=list)
    authority: list = field(default_factory=list)
    additional: list = field(default_factory=list)

    @property
    def rcode(self) -> int:
        return self.flags & 0xF

    @property
    def truncated(self) -> bool:
        return bool(self.flags & 0x0200)


def _decode_rdata(msg: bytes, off: int, t: int, ln: int):
    if t == TXT:
        parts, i = [], off
        while i < off + ln:
            n = msg[i]
            parts.append(msg[i + 1:i + 1 + n].decode("utf-8", "replace"))
            i += 1 + n
        return "".join(parts)
    if t in (NS, CNAME):
        return decode_name(msg, off)[0]
    if t == SOA:
        return decode_name(msg, off)[0]
    if t == A and ln == 4:
        return socket.inet_ntop(socket.AF_INET, msg[off:off + 4])
    if t == AAAA and ln == 16:
        return socket.inet_ntop(socket.AF_INET6, msg[off:off + 16])
    return None


def parse_message(data: bytes) -> Message:
    if len(data) < 12:
        raise DnsWireError("short DNS message")
    qid, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", data, 0)
    msg, off = Message(qid, flags), 12
    try:
        for _ in range(qd):
            name, off = decode_name(data, off)
            qt, qc = struct.unpack_from("!HH", data, off)
            off += 4
            msg.question.append((name, qt, qc))
        for section, count in ((msg.answer, an), (msg.authority, ns), (msg.additional, ar)):
            for _ in range(count):
                start = off
                name, off = decode_name(data, off)
                t, c, ttl, ln = struct.unpack_from("!HHIH", data, off)
                off += 10
                if off + ln > len(data):
                    raise DnsWireError("truncated rdata")
                section.append(RR(name, t, c, ttl, data[off:off + ln], _decode_rdata(data, off, t, ln), start))
                off += ln
    except struct.error:
        raise DnsWireError("malformed DNS message") from None
    return msg


def build_query(name: str, qtype: int, qid: int | None = None, rd: bool = True) -> bytes:
    qid = secrets.randbits(16) if qid is None else qid
    return (struct.pack("!HHHHHH", qid, 0x0100 if rd else 0, 1, 0, 0, 0)
            + encode_name(name) + struct.pack("!HH", qtype, CLASS_IN))


def _recv_exact(s: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise DnsWireError("connection closed")
        buf += chunk
    return buf


def exchange(server: str, wire: bytes, port: int = 53, timeout: float = 3.0, tcp: bool = False) -> bytes:
    """Send one DNS message, return the raw response (matching ID and source address only)."""
    infos = socket.getaddrinfo(server, port, type=socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
    family, _, _, _, addr = infos[0]
    if tcp:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(addr)
            s.sendall(struct.pack("!H", len(wire)) + wire)
            (ln,) = struct.unpack("!H", _recv_exact(s, 2))
            return _recv_exact(s, ln)
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(wire, addr)
        deadline = time.monotonic() + timeout
        while True:
            s.settimeout(max(0.05, deadline - time.monotonic()))
            data, src = s.recvfrom(65535)
            if src[0] == addr[0] and data[:2] == wire[:2]:
                break
            if time.monotonic() > deadline:
                raise TimeoutError("no matching response")
    if len(data) > 2 and data[2] & 0x02:  # TC: retry over TCP
        return exchange(server, wire, port, timeout, tcp=True)
    return data


def system_nameservers() -> list[str]:
    env = os.environ.get("FARRIER_DNS_RESOLVERS")
    if env:
        return [x.strip() for x in env.replace(",", " ").split() if x.strip()]
    try:
        with open("/etc/resolv.conf") as f:
            return [ln.split()[1] for ln in f if ln.startswith("nameserver") and len(ln.split()) > 1]
    except OSError:
        return []  # Windows and sandboxes: DoH is used for recursive lookups


# ---- resolver ---------------------------------------------------------------------------------------------
class Resolver:
    def __init__(self, nameservers: list[str] | None = None, doh_urls=DOH_URLS, http: httpx.Client | None = None,
                 timeout: float = 3.0):
        self.nameservers = list(nameservers) if nameservers is not None else system_nameservers()
        self.doh_urls = tuple(doh_urls)
        self._http = http
        self.timeout = timeout

    @property
    def http(self) -> httpx.Client:
        if self._http is None:
            self._http = httpx.Client(timeout=10, headers={"User-Agent": USER_AGENT})
        return self._http

    def _doh(self, url: str, name: str, qtype: int) -> Message:
        tname = next(k for k, v in TYPE_NAMES.items() if v == qtype)
        r = self.http.get(url, params={"name": name, "type": tname}, headers={"Accept": "application/dns-json"})
        r.raise_for_status()
        j = r.json()
        msg = Message(0, int(j.get("Status", 2)))

        def rr(a):
            t, data = int(a.get("type", 0)), str(a.get("data", ""))
            if t == TXT:
                val = unquote_txt(data)
            elif t == SOA:
                val = norm(data.split()[0]) if data else ""
            elif t in (NS, CNAME):
                val = norm(data)
            else:
                val = data
            return RR(norm(a.get("name", "")), t, CLASS_IN, int(a.get("TTL", 0)), b"", val)

        msg.answer = [rr(a) for a in j.get("Answer", [])]
        msg.authority = [rr(a) for a in j.get("Authority", [])]
        return msg

    def query(self, name: str, qtype: int) -> Message:
        """Recursive lookup: configured/system resolvers over UDP, then DoH."""
        wire = build_query(name, qtype)
        for ns in self.nameservers:
            try:
                msg = parse_message(exchange(ns, wire, timeout=self.timeout))
                if msg.rcode in (0, 3):
                    return msg
            except (OSError, DnsWireError):
                continue
        for url in self.doh_urls:
            try:
                msg = self._doh(url, name, qtype)
                if msg.rcode in (0, 3):
                    return msg
            except (httpx.HTTPError, ValueError, KeyError):
                continue
        raise DnsError(f"no DNS resolver answered for {name}")

    def find_zone(self, fqdn: str) -> str:
        name = norm(fqdn)
        while name:
            msg = self.query(name, SOA)
            for rr in msg.answer:
                if rr.type == SOA and rr.name == name:
                    return rr.name
            for rr in msg.authority:
                if rr.type == SOA and in_zone(name, rr.name) and rr.name:
                    return rr.name
            name = name.partition(".")[2]
        raise DnsError(f"could not find the DNS zone of {fqdn}")

    def cname(self, fqdn: str) -> str | None:
        msg = self.query(fqdn, CNAME)
        for rr in msg.answer:
            if rr.type == CNAME and rr.name == norm(fqdn):
                return rr.value
        return None

    def nameserver_ips(self, zone: str) -> list[str]:
        hosts = [rr.value for rr in self.query(zone, NS).answer if rr.type == NS and rr.value]
        ips: list[str] = []
        for h in hosts:
            try:
                for info in socket.getaddrinfo(h, 53, type=socket.SOCK_DGRAM):
                    if info[4][0] not in ips:
                        ips.append(info[4][0])
            except OSError:
                continue
        return ips

    def authoritative_txt(self, server: str, fqdn: str) -> tuple[set[str], str | None]:
        msg = parse_message(exchange(server, build_query(fqdn, TXT, rd=False), timeout=self.timeout))
        if msg.rcode not in (0, 3):
            raise DnsError(f"{server} answered {RCODES.get(msg.rcode, msg.rcode)}")
        name = norm(fqdn)
        values = {rr.value for rr in msg.answer if rr.type == TXT and rr.name == name}
        cname = next((rr.value for rr in msg.answer if rr.type == CNAME and rr.name == name), None)
        return values, cname

    def public_txt(self, fqdn: str) -> list[set[str]]:
        out = []
        for url in self.doh_urls:
            try:
                msg = self._doh(url, fqdn, TXT)
                out.append({rr.value for rr in msg.answer if rr.type == TXT})
            except (httpx.HTTPError, ValueError, KeyError):
                continue
        return out

    def check(self, fqdn: str, values: set[str], cache: dict | None = None) -> tuple[bool, str]:
        """Are all `values` visible at fqdn on every reachable authoritative server? Follows CNAMEs."""
        cache = {} if cache is None else cache
        name = norm(fqdn)
        for _ in range(8):
            if name not in cache:
                zone = self.find_zone(name)
                cache[name] = self.nameserver_ips(zone)
            ips = cache[name]
            results, cname = [], None
            for ip in ips:
                try:
                    vals, c = self.authoritative_txt(ip, name)
                except (OSError, DnsError):
                    continue
                results.append((ip, vals))
                cname = cname or c
            if cname and not any(v for _, v in results):
                name = cname
                continue
            if not results:  # authoritative servers unreachable (firewalled UDP/53): ask public resolvers
                seen = self.public_txt(name)
                if not seen:
                    return False, f"{name}: no authoritative or public resolver reachable"
                ok = all(values <= s for s in seen)
                return ok, f"{name}: public resolvers {'see' if ok else 'do not yet see'} the record"
            lagging = [ip for ip, v in results if not values <= v]
            return not lagging, (f"{name}: visible on all {len(results)} nameservers" if not lagging
                                 else f"{name}: not yet on {', '.join(lagging)}")
        return False, f"{fqdn}: CNAME chain too long"

    def wait_for(self, records: dict[str, set[str]], timeout: float = 300, interval: float = 5,
                 sleep=time.sleep) -> None:
        deadline = time.monotonic() + timeout
        pending = {norm(k): set(v) for k, v in records.items()}
        cache: dict = {}
        detail = ""
        while True:
            for name in list(pending):
                try:
                    ok, detail = self.check(name, pending[name], cache)
                except DnsError as e:
                    ok, detail = False, str(e)
                if ok:
                    log.info("dns propagation: %s", detail)
                    pending.pop(name)
            if not pending:
                return
            if time.monotonic() >= deadline:
                raise DnsPropagationError(f"TXT records not visible after {timeout:.0f}s ({detail})")
            sleep(interval)
