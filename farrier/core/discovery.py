"""Find what is actually being served: TLS handshake against host:port, read the leaf cert."""
from __future__ import annotations

import ipaddress
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from farrier.core.x509util import CertInfo, parse_der


@dataclass
class ScanResult:
    host: str
    port: int
    sni: str | None
    cert: CertInfo | None = None
    error: str | None = None


def fetch_cert(host: str, port: int = 443, sni: str | None = None, timeout: float = 5.0) -> CertInfo:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we want to see expired / self-signed / private-CA certs too
    with socket.create_connection((host, port), timeout=timeout) as sock:
        server_hostname = sni or (None if _is_ip(host) else host)
        with ctx.wrap_socket(sock, server_hostname=server_hostname) as tls:
            der = tls.getpeercert(binary_form=True)
    return parse_der(der)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


_LABEL = re.compile(r"^(?!-)[A-Za-z0-9_-]{1,63}(?<!-)$")


def _is_hostname(name: str) -> bool:
    """RFC 1123 hostname (underscores tolerated: they appear in internal DNS)."""
    name = name.rstrip(".")
    return 0 < len(name) <= 253 and all(_LABEL.match(label) for label in name.split("."))


def expand_targets(spec: str) -> list[tuple[str, int, str | None]]:
    """Accepts comma/whitespace separated items:
         host            -> host:443
         host:8443
         10.0.0.0/28:443|8443
         sni@10.0.0.5:443  (connect to IP, send SNI)
    """
    out: list[tuple[str, int, str | None]] = []
    for item in spec.replace(",", " ").split():
        sni = None
        if "@" in item:
            sni, item = item.split("@", 1)
            if not _is_hostname(sni):
                raise ValueError(f"{sni!r} is not a valid SNI hostname")
        if item.count(":") == 1:
            host, ports = item.split(":")
        else:
            host, ports = item, "443"
        try:
            port_list = [int(p) for p in ports.split("|")]
        except ValueError:
            raise ValueError(f"bad port list in {item!r}") from None
        if any(not 0 < p < 65536 for p in port_list):
            raise ValueError(f"port out of range in {item!r}")
        if "/" in host:
            try:
                net = ipaddress.ip_network(host, strict=False)
            except ValueError:
                raise ValueError(f"{host!r} is not a valid CIDR range") from None
            if net.num_addresses > 65536:
                raise ValueError(f"{host} is too large to scan in one go")
            hosts = [str(h) for h in (net.hosts() if net.num_addresses > 2 else net)]
        elif _is_ip(host) or _is_hostname(host):
            hosts = [host]
        else:
            raise ValueError(f"{host!r} is not a valid host, IP or CIDR range")
        for h in hosts:
            for p in port_list:
                out.append((h, p, sni))
    return out


def scan(targets: list[tuple[str, int, str | None]], workers: int = 64, timeout: float = 3.0) -> list[ScanResult]:
    def one(t):
        host, port, sni = t
        try:
            return ScanResult(host, port, sni, cert=fetch_cert(host, port, sni, timeout))
        except Exception as e:  # noqa: BLE001 - every failure is a scan result
            return ScanResult(host, port, sni, error=f"{type(e).__name__}: {e}")

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(one, targets))
