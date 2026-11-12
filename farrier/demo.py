"""A self-contained demo estate: one local TLS listener serving dozens of hostnames by SNI.

Every "device" is a real TLS endpoint with a real certificate on disk, so discovery,
renewal, deployment, verification and the manual close-the-loop flow all run for real.
Half the estate is "manual" (VPN concentrators, ADCs, IIS, vCenter): install a change pack
by copying its fullchain.pem/key.pem into demo-data/devices/<name>/ and watch it close.
"""
from __future__ import annotations

import json
import random
import socket
import ssl
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from farrier.core.engine import Engine
from farrier.core.x509util import generate_key, key_to_pem
from farrier.issuers.local_ca import LocalCA

FLEET = [
    # (prefix, count, connector, runbook, window, lead_days)
    ("web", 10, "files", None, {}, 0),
    ("haproxy", 4, "files", None, {}, 0),
    ("api-gw", 4, "files", None, {"days": ["tue", "thu"], "start": "22:00", "hours": 3}, 0),
    ("vpn-asa", 6, "manual", "cisco-asa", {"days": ["sat"], "start": "02:00", "hours": 4}, 10),
    ("adc", 6, "manual", "citrix-adc", {"days": ["sun"], "start": "01:00", "hours": 4}, 10),
    ("iis", 8, "manual", "windows-iis", {"days": ["wed", "sat"], "start": "20:00", "hours": 4}, 7),
    ("vcenter", 3, "manual", "vmware-vcenter", {"days": ["sat"], "start": "06:00", "hours": 6}, 14),
]


class SNIServer:
    def __init__(self, devices_dir: Path, port: int = 0):
        self.dir = devices_dir
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(64)
        self.sock.settimeout(0.5)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        threading.Thread(target=self._loop, daemon=True, name="demo-tls").start()

    def _ctx(self, name: str):
        d = self.dir / name
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(d / "fullchain.pem", d / "key.pem")
        return ctx

    def _loop(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except (TimeoutError, OSError):
                continue
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        names = sorted(p.name for p in self.dir.iterdir() if p.is_dir())
        base = self._ctx(names[0])

        def pick(sslobj, server_name, _ctx):
            if server_name and (self.dir / server_name).is_dir():
                try:
                    sslobj.context = self._ctx(server_name)
                except Exception:  # noqa: BLE001 - half-copied files during a manual install
                    pass

        base.sni_callback = pick
        try:
            conn.settimeout(3)
            with base.wrap_socket(conn, server_side=True):
                pass
        except Exception:  # noqa: BLE001
            conn.close()


def _issue_backdated(ca: LocalCA, cn: str, not_before: datetime, days: int, key) -> str:
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .issuer_name(ca.cert.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before).not_valid_after(not_before + timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca.key, hashes.SHA384()))
    return cert.public_bytes(serialization.Encoding.PEM).decode() + ca.ca_pem


def seed(data_dir: Path, simulate_date: str | None = None, seed_value: int = 7) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    issuers = {"default": {"type": "local_ca"}}
    if simulate_date:
        issuers["default"]["simulate_date"] = simulate_date
    (data_dir / "issuers.json").write_text(json.dumps(issuers, indent=2))
    (data_dir / "settings.json").write_text(json.dumps({"horizon_days": 21, "manual_daily_cap": 4,
                                                        "verify_retry_seconds": 0.3}, indent=2))
    ca = LocalCA(data_dir)
    devices = data_dir / "devices"
    rng = random.Random(seed_value)
    now = datetime.now(UTC)
    eng = Engine(data_dir)
    for prefix, count, connector, runbook, window, lead in FLEET:
        for i in range(1, count + 1):
            name = f"{prefix}-{i:02d}.corp.test"
            d = devices / name
            d.mkdir(parents=True, exist_ok=True)
            lifetime = rng.choice([398, 398, 200, 200, 90])
            days_left = rng.choice([rng.randint(-3, 12), rng.randint(5, 30), rng.randint(20, 120),
                                    rng.randint(60, min(lifetime, 200))])
            days_left = min(days_left, lifetime - 1)
            key = generate_key("ec256")
            nb = now - timedelta(days=lifetime - days_left)
            (d / "fullchain.pem").write_text(_issue_backdated(ca, name, nb, lifetime, key))
            (d / "key.pem").write_text(key_to_pem(key))
            cfg = ({"fullchain_path": str(d / "fullchain.pem"), "cert_path": str(d / "cert.pem"),
                    "key_path": str(d / "key.pem")} if connector == "files" else {"runbook": runbook})
            eng.store.upsert_endpoint({
                "name": name, "host": "127.0.0.1", "port": 0, "sni": name, "common_name": name, "sans": [name],
                "connector": connector, "connector_config": cfg, "window": window, "lead_days": lead,
                "owner": "network-team" if connector == "manual" else "platform-team", "tags": [prefix]})


def start(data_dir: Path, simulate_date: str | None = None) -> tuple[Engine, SNIServer]:
    if not (data_dir / "devices").exists():
        seed(data_dir, simulate_date)
    srv = SNIServer(data_dir / "devices")
    eng = Engine(data_dir)
    eng.store.x("UPDATE endpoints SET port=? WHERE host='127.0.0.1'", (srv.port,))
    return eng, srv
