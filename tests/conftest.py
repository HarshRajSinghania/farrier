from __future__ import annotations

import socket
import ssl
import threading
from pathlib import Path

import pytest

from farrier.engine import Engine
from farrier.issuers.local_ca import LocalCA
from farrier.x509util import build_csr, generate_key, key_to_pem


class TLSServer:
    """Serves whatever cert/key is on disk *at handshake time*, so writing new files = a reload."""

    def __init__(self, cert_path: Path, key_path: Path):
        self.cert_path, self.key_path = cert_path, key_path
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self.t = threading.Thread(target=self._loop, daemon=True)
        self.t.start()

    def _loop(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except (TimeoutError, OSError):
                continue
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(self.cert_path, self.key_path)
                conn.settimeout(2)
                with ctx.wrap_socket(conn, server_side=True):
                    pass
            except Exception:  # noqa: BLE001
                conn.close()

    def close(self):
        self._stop.set()
        self.t.join(timeout=2)
        self.sock.close()


def issue_initial(ca: LocalCA, cn: str, days: int) -> tuple[str, str]:
    key = generate_key("ec256")
    saved = ca.lifetime_days
    ca.lifetime_days = days
    cert, chain = ca.issue(build_csr(key, cn, [cn]), [cn])
    ca.lifetime_days = saved
    return key_to_pem(key), cert + chain


@pytest.fixture
def data_dir(tmp_path):
    d = tmp_path / "data"
    d.mkdir()
    return d


@pytest.fixture
def engine(data_dir):
    ca = LocalCA(data_dir)
    return Engine(data_dir, issuers={"default": ca}, settings={"verify_retry_seconds": 0.05})


@pytest.fixture
def served(tmp_path, engine):
    """A live TLS endpoint with a 9-day cert from the local CA on disk at srv/."""
    srv = tmp_path / "srv"
    srv.mkdir()
    key, fullchain = issue_initial(engine.issuers["default"], "app.internal.test", days=9)
    (srv / "key.pem").write_text(key)
    (srv / "fullchain.pem").write_text(fullchain)
    s = TLSServer(srv / "fullchain.pem", srv / "key.pem")
    yield s, srv
    s.close()
