"""Agentless SSH: wire parsing, discovery against an in-process server, authorized_keys, findings,
collection/removal over a fake transport, TOFU, routes, and secrets staying out of logs."""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import socket
import struct
import threading

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa, x25519
from fastapi.testclient import TestClient

from farrier.api.app import create_app
from farrier.core.engine import Engine
from farrier.ssh import access, collect, db, scan, ssh_crypto_assets
from farrier.ssh.authorized_keys import (InvalidLine, authorized_keys_files, expand_pattern, parse_authorized_keys,
                                         parse_line, parse_options, remove_line)
from farrier.ssh.findings import authorized_key_findings, host_findings
from farrier.ssh.keys import PublicKey, fingerprint, parse_blob
from farrier.ssh.probe import ProbeResult, probe
from farrier.ssh.transport import CommandResult, HostKeyMismatch, SSHBinaryTransport, wrap
from farrier.ssh.wire import WireError, build_kexinit, parse_banner, parse_kexinit

ADMIN = {"Authorization": "Bearer admin-tok", "X-Farrier-Actor": "alice"}
READ = {"Authorization": "Bearer read-tok"}


# ---- independent SSH encoding for the fake server (deliberately not farrier.ssh.wire) ----------------
def _s(b: bytes | str) -> bytes:
    b = b.encode() if isinstance(b, str) else b
    return struct.pack(">I", len(b)) + b


def _mp(n: int) -> bytes:
    if n == 0:
        return _s(b"")
    return _s(n.to_bytes((n.bit_length() + 8) // 8, "big"))


def _nl(names) -> bytes:
    return _s(",".join(names))


def _packet(payload: bytes) -> bytes:
    pad = 8 - (len(payload) + 5) % 8
    pad += 8 if pad < 4 else 0
    return struct.pack(">IB", len(payload) + pad + 1, pad) + payload + b"\0" * pad


def _kexinit(kex, hostkey, ciphers, macs, comp=("none",)) -> bytes:
    out = b"\x14" + b"C" * 16
    for lst in (kex, hostkey, ciphers, ciphers, macs, macs, comp, comp, (), ()):
        out += _nl(lst)
    return out + b"\0" + b"\0\0\0\0"


def ed_blob(k: ed25519.Ed25519PrivateKey) -> bytes:
    raw = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return _s("ssh-ed25519") + _s(raw)


def rsa_blob(k: rsa.RSAPrivateKey) -> bytes:
    n = k.public_key().public_numbers()
    return _s("ssh-rsa") + _mp(n.e) + _mp(n.n)


def dsa_blob(bits: int = 1024) -> bytes:
    p = (1 << (bits - 1)) | 12345
    return _s("ssh-dss") + _mp(p) + _mp((1 << 159) | 7) + _mp(3) + _mp(5)


def openssh_line(blob: bytes, comment: str = "", options: str = "") -> str:
    ktype = struct.unpack(">I", blob[:4])[0]
    kt = blob[4:4 + ktype].decode()
    return " ".join(x for x in (options, kt, base64.b64encode(blob).decode(), comment) if x)


ED = ed25519.Ed25519PrivateKey.generate()
RSA2048 = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class FakeSSHServer:
    """Speaks just enough SSH: identification, KEXINIT, and a signed curve25519 KEX reply."""

    def __init__(self, banner="SSH-2.0-OpenSSH_7.9p1 Debian-10", kex=None, hostkeys=None, ciphers=None,
                 macs=None, bad_signature=False, keys=None):
        self.banner = banner
        self.kex = kex or ["curve25519-sha256", "sntrup761x25519-sha512@openssh.com",
                           "diffie-hellman-group14-sha1", "kex-strict-s-v00@openssh.com"]
        self.hostkeys = hostkeys or ["ssh-ed25519", "rsa-sha2-512", "ssh-rsa"]
        self.ciphers = ciphers or ["aes128-ctr", "aes256-cbc", "chacha20-poly1305@openssh.com"]
        self.macs = macs or ["hmac-sha2-256-etm@openssh.com", "hmac-sha1"]
        self.keys = keys or {"ssh-ed25519": ED, "rsa": RSA2048}
        self.bad_signature = bad_signature
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
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    @staticmethod
    def _read_packet(f) -> bytes:
        n = struct.unpack(">I", f.read(4))[0]
        body = f.read(n)
        return body[1:len(body) - body[0]]

    def _serve(self, conn):
        try:
            conn.settimeout(3)
            f = conn.makefile("rb")
            conn.sendall(b"a pre-banner line\r\n" + self.banner.encode() + b"\r\n")
            v_c = f.readline().rstrip(b"\r\n")
            i_s = _kexinit(self.kex, self.hostkeys, self.ciphers, self.macs)
            conn.sendall(_packet(i_s))
            i_c = self._read_packet(f)
            init = self._read_packet(f)
            assert init[0] == 30
            q_c = init[5:5 + struct.unpack(">I", init[1:5])[0]]
            # the client's host-key list is the 2nd name-list after the cookie
            off = 17
            off += 4 + struct.unpack(">I", i_c[off:off + 4])[0]
            hk_len = struct.unpack(">I", i_c[off:off + 4])[0]
            alg = i_c[off + 4:off + 4 + hk_len].decode().split(",")[0]
            eph = x25519.X25519PrivateKey.generate()
            q_s = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            shared = eph.exchange(x25519.X25519PublicKey.from_public_bytes(q_c))
            if alg == "ssh-ed25519":
                k_s = ed_blob(self.keys["ssh-ed25519"])
            else:
                k_s = rsa_blob(self.keys["rsa"])
            h = hashlib.sha256(_s(v_c) + _s(self.banner) + _s(i_c) + _s(i_s) + _s(k_s) + _s(q_c) + _s(q_s)
                               + _mp(int.from_bytes(shared, "big"))).digest()
            if self.bad_signature:
                h = hashlib.sha256(b"not the exchange hash").digest()
            if alg == "ssh-ed25519":
                sig = _s("ssh-ed25519") + _s(self.keys["ssh-ed25519"].sign(h))
            else:
                sig = _s(alg) + _s(self.keys["rsa"].sign(h, padding.PKCS1v15(), hashes.SHA512()))
            conn.sendall(_packet(b"\x1f" + _s(k_s) + _s(q_s) + _s(sig)))
            f.read(1)   # wait for the client to hang up
        except Exception:  # noqa: BLE001
            pass
        finally:
            conn.close()

    def close(self):
        self._stop.set()
        self.t.join(timeout=2)
        self.sock.close()


@pytest.fixture
def ssh_server():
    s = FakeSSHServer()
    yield s
    s.close()


# ---- wire -------------------------------------------------------------------------------------------
def test_banner_parsing():
    b = parse_banner("SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2\r\n")
    assert (b.proto, b.software, b.comments, b.openssh_version) == ("2.0", "OpenSSH_7.9p1", "Debian-10+deb10u2", (7, 9))
    assert parse_banner("SSH-1.99-Cisco-1.25").openssh_version is None
    with pytest.raises(WireError):
        parse_banner("HTTP/1.1 400 Bad Request")


def test_kexinit_parsing_with_crafted_bytes():
    payload = _kexinit(["curve25519-sha256", "ext-info-s"], ["ssh-ed25519"], ["aes128-ctr", "aes256-cbc"],
                       ["hmac-sha2-256"])
    k = parse_kexinit(payload)
    assert k.kex == ["curve25519-sha256", "ext-info-s"] and k.host_key == ["ssh-ed25519"]
    assert k.ciphers == ["aes128-ctr", "aes256-cbc"] and k.macs == ["hmac-sha2-256"] and k.compression == ["none"]
    assert k.payload == payload and not k.first_kex_follows
    with pytest.raises(WireError):
        parse_kexinit(payload[:30])                     # truncated
    with pytest.raises(WireError):
        parse_kexinit(b"\x15" + payload[1:])            # wrong message number
    ours = parse_kexinit(build_kexinit(["curve25519-sha256"], ["ssh-ed25519"], ["aes128-ctr"], ["hmac-sha1"], ["none"]))
    assert ours.kex == ["curve25519-sha256"] and ours.ciphers_s2c == ["aes128-ctr"]


def test_key_blobs_and_fingerprints():
    blob = ed_blob(ED)
    k = parse_blob(blob)
    assert (k.type, k.bits, k.algorithm) == ("ssh-ed25519", 256, "Ed25519")
    expected = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    assert k.fingerprint_sha256 == expected == fingerprint(blob)
    # agrees with cryptography's own OpenSSH serialisation
    line = ED.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    assert base64.b64decode(line.split()[1]) == blob
    assert parse_blob(rsa_blob(RSA2048)).bits == 2048
    assert parse_blob(dsa_blob()).bits == 1024


# ---- discovery --------------------------------------------------------------------------------------
def test_probe_reads_banner_kexinit_and_verified_host_keys(ssh_server):
    r = probe("127.0.0.1", ssh_server.port, timeout=3, use_keyscan=False)
    assert r.error is None and r.method == "kex"
    assert r.banner.software == "OpenSSH_7.9p1"
    assert "sntrup761x25519-sha512@openssh.com" in r.kexinit.kex
    got = {k.type: k for k in r.host_keys}
    assert set(got) == {"ssh-ed25519", "ssh-rsa"}                 # one connection per key type
    assert got["ssh-ed25519"].fingerprint_sha256 == fingerprint(ed_blob(ED))
    assert got["ssh-rsa"].bits == 2048
    rec = scan.host_record(r)
    ids = {f["id"]: f["severity"] for f in rec["findings"]}
    assert ids["outdated-openssh"] == "warning"
    assert ids["weak-kex:diffie-hellman-group14-sha1"] == "warning"
    assert ids["weak-cipher:aes256-cbc"] == "warning"
    assert ids["weak-mac:hmac-sha1"] == "warning"
    assert ids["weak-hostkey-alg:ssh-rsa"] == "warning"
    assert ids["host-key-rsa-small"] == "warning"
    assert "terrapin" not in ids and "no-pqc-kex" not in ids     # strict kex and sntrup offered
    assert rec["kex"] == ["curve25519-sha256", "sntrup761x25519-sha512@openssh.com", "diffie-hellman-group14-sha1"]
    assert rec["kex_extensions"] == ["kex-strict-s-v00@openssh.com"]


def test_probe_rejects_a_bad_signature():
    s = FakeSSHServer(bad_signature=True)
    try:
        r = probe("127.0.0.1", s.port, timeout=3, use_keyscan=False)
    finally:
        s.close()
    assert r.banner is not None and r.host_keys == [] and r.method == "algorithms"
    assert any("does not verify" in n for n in r.notes)


def test_probe_of_closed_port_is_an_error_not_an_exception():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    r = probe("127.0.0.1", port, timeout=1)
    assert r.banner is None and r.error


# ---- authorized_keys --------------------------------------------------------------------------------
def test_authorized_keys_parser():
    ed = openssh_line(ed_blob(ED), "alice@laptop")
    text = "\n".join([
        "# managed by hand",
        "",
        ed,
        'from="10.0.0.1,10.0.0.2",command="echo \\"hi, there\\"",no-pty ' + openssh_line(rsa_blob(RSA2048), "deploy key"),
        "restrict,permitopen=\"a:1\",permitopen=\"b:2\" " + openssh_line(ed_blob(ED)),
        "ssh-ed25519 !!!notbase64!!! x",
        "ssh-rsa " + base64.b64encode(ed_blob(ED)).decode(),     # type mismatch
        'from="unterminated ' + ed,
        "ssh-foo AAAA",
        "   ",
    ])
    p = parse_authorized_keys(text)
    assert len(p.keys) == 3 and len(p.invalid) == 4
    a, b, c = p.keys
    assert (a.line_no, a.comment, a.options, a.key.type) == (3, "alice@laptop", {}, "ssh-ed25519")
    assert b.options == {"from": "10.0.0.1,10.0.0.2", "command": 'echo "hi, there"', "no-pty": True}
    assert b.comment == "deploy key" and b.key.bits == 2048
    assert c.options == {"restrict": True, "permitopen": ["a:1", "b:2"]} and c.comment == ""
    assert {i.line_no for i in p.invalid} == {6, 7, 8, 9}
    assert parse_line("# comment") is None and parse_line("") is None
    assert isinstance(parse_line("ssh-ed25519-cert-v01@openssh.com AAAA"), InvalidLine)
    with pytest.raises(ValueError):
        parse_options('a="x')


def test_remove_line_touches_exactly_one_line():
    lines = ["# keep", openssh_line(ed_blob(ED), "a"), openssh_line(rsa_blob(RSA2048), "b"), ""]
    text = "\n".join(lines)
    target = parse_authorized_keys(text).keys[1].line_sha256
    new, n = remove_line(text, target)
    assert n == 3 and new == "\n".join(lines[:2] + lines[3:])
    with pytest.raises(ValueError):
        remove_line(text + "\n" + lines[2], target)      # duplicate line: refuse to guess
    with pytest.raises(ValueError):
        remove_line(text, "0" * 64)


def test_sshd_config_and_patterns():
    assert authorized_keys_files(None) == [".ssh/authorized_keys", ".ssh/authorized_keys2"]
    cfg = "# x\nPort 22\nAuthorizedKeysFile .ssh/authorized_keys /etc/ssh/keys/%u\nMatch User bob\n  AuthorizedKeysFile none\n"
    assert authorized_keys_files(cfg) == [".ssh/authorized_keys", "/etc/ssh/keys/%u"]
    assert authorized_keys_files("AuthorizedKeysFile=/k/%u") == ["/k/%u"]
    assert expand_pattern(".ssh/authorized_keys", "bob", "/home/bob", 1001) == "/home/bob/.ssh/authorized_keys"
    assert expand_pattern("/etc/ssh/keys/%u.%U%%", "bob", "/home/bob", 1001) == "/etc/ssh/keys/bob.1001%"


# ---- findings ---------------------------------------------------------------------------------------
@pytest.mark.parametrize("kex,cipher,mac,expect", [
    ("diffie-hellman-group1-sha1", "aes128-ctr", "hmac-sha2-256-etm@openssh.com", {"weak-kex:diffie-hellman-group1-sha1": "critical"}),
    ("diffie-hellman-group-exchange-sha1", "aes128-ctr", "hmac-sha2-256-etm@openssh.com", {"weak-kex:diffie-hellman-group-exchange-sha1": "warning"}),
    ("curve25519-sha256", "arcfour256", "hmac-sha2-256-etm@openssh.com", {"weak-cipher:arcfour256": "critical"}),
    ("curve25519-sha256", "3des-cbc", "hmac-sha2-256-etm@openssh.com", {"weak-cipher:3des-cbc": "warning"}),
    ("curve25519-sha256", "aes128-ctr", "hmac-md5", {"weak-mac:hmac-md5": "warning"}),
    ("curve25519-sha256", "aes128-ctr", "hmac-sha2-256", {"weak-mac:hmac-sha2-256": "info"}),
    ("mlkem768x25519-sha256", "aes128-ctr", "hmac-sha2-256-etm@openssh.com", {}),
])
def test_host_findings_table(kex, cipher, mac, expect):
    k = parse_kexinit(_kexinit([kex, "kex-strict-s-v00@openssh.com"], ["ssh-ed25519"], [cipher], [mac]))
    got = {f["id"]: f["severity"] for f in host_findings(parse_banner("SSH-2.0-OpenSSH_9.9"), k, [])}
    got.pop("no-pqc-kex", None)
    assert got == expect


def test_host_findings_keys_banner_pqc_terrapin():
    k = parse_kexinit(_kexinit(["curve25519-sha256"], ["ssh-dss"], ["chacha20-poly1305@openssh.com"],
                               ["hmac-sha2-256-etm@openssh.com"]))
    f = {x["id"]: x["severity"] for x in host_findings(
        parse_banner("SSH-2.0-OpenSSH_7.2"), k, [parse_blob(dsa_blob()), PublicKey("ssh-rsa", 1024, b"")])}
    assert f["outdated-openssh"] == "critical" and f["host-key-dsa"] == "critical"
    assert f["host-key-rsa-small"] == "critical" and f["weak-hostkey-alg:ssh-dss"] == "critical"
    assert f["terrapin"] == "warning" and f["no-pqc-kex"] == "info"


def test_authorized_key_findings_table():
    base = {"type": "ssh-ed25519", "bits": 256, "fingerprint_sha256": "SHA256:x", "comment": "", "options": {},
            "user": "deploy", "user_uid": 1000, "user_shell": "/bin/bash"}

    def ids(row, **kw):
        kw = {"duplicate_count": 1, "approved": None, "fleet_users": None} | kw
        return {f["id"]: f["severity"] for f in authorized_key_findings(base | row, **kw)}

    assert ids({}) == {}
    assert ids({"type": "ssh-dss", "bits": 1024}) == {"key-dsa": "critical"}
    assert ids({"type": "ssh-rsa", "bits": 2048}) == {"key-rsa-small": "warning"}
    assert ids({}, duplicate_count=3) == {"duplicate": "warning"}
    assert ids({}, approved={"SHA256:other"}) == {"unknown": "warning"}
    assert ids({"user_shell": "/usr/sbin/nologin"}) == {"orphaned-no-shell": "info"}
    assert ids({"never_logged_in": True}) == {"orphaned-never-logged-in": "info"}
    assert ids({"comment": "mallory@old-laptop"}, fleet_users={"deploy"}) == {"orphaned-comment": "info"}
    assert ids({"user": "root", "user_uid": 0}) == {"root-unrestricted": "warning"}
    assert ids({"user": "root", "user_uid": 0, "options": {"from": "10.0.0.1"}}) == {}


# ---- collection and removal over a fake transport -----------------------------------------------------
PASSWD = ("root:x:0:0:root:/root:/bin/bash\ndeploy:x:1000:1000::/home/deploy:/bin/bash\n"
          "svc:x:998:998::/var/lib/svc:/usr/sbin/nologin\nnobody:x:65534:65534::/nonexistent:/usr/sbin/nologin\n")
SSHD = "AuthorizedKeysFile .ssh/authorized_keys\n"
LASTLOG = "Username Port From Latest\nroot pts/0 1.2.3.4 Mon\nsvc **Never logged in**\n"


class FakeHost:
    """A host filesystem plus a shell that understands collect's scripts (never runs a real shell)."""

    def __init__(self, files: dict[str, bytes], login="deploy", sudo_ok=True):
        self.files, self.login, self.sudo_ok = dict(files), login, sudo_ok
        self.commands: list[tuple[str, bool]] = []
        self.closed = 0

    def _readable(self, path: str, sudo: bool) -> bool:
        return sudo or path.startswith(f"/home/{self.login}/")

    def run(self, script, stdin=None, sudo=False, timeout=60.0):
        self.commands.append((script, sudo))
        wrap(script, sudo)      # what a real transport would send
        if sudo and not self.sudo_ok:
            return CommandResult(1, b"", "sudo: a password is required")
        if script == "true":
            return CommandResult(0, b"", "")
        b64 = lambda s: base64.encodebytes(s.encode() if isinstance(s, str) else s)  # noqa: E731
        if script == collect._ENV_SCRIPT:
            out = f"{self.login}\n1000\n@@\n".encode() + b64(PASSWD) + b"@@\n" + b64(SSHD) + b"@@\n" + b64(LASTLOG)
            return CommandResult(0, out, "")
        if script == collect._READ_SCRIPT:
            out = b""
            for i, p in enumerate(stdin.decode().splitlines()):
                if p in self.files:
                    out += f"@@F {i}\n".encode()
                    out += b64(self.files[p]) if self._readable(p, sudo) else f"@@E {i}\n".encode()
            return CommandResult(0, out, "")
        if script == collect._WRITE_SCRIPT:
            f, user, want, content = stdin.split(b"\n", 3)
            f = f.decode()
            if not self._readable(f, sudo):
                return CommandResult(1, b"", "Permission denied")
            if hashlib.sha256(self.files[f]).hexdigest() != want.decode():
                return CommandResult(3, b"", "file changed since it was read")
            b = f"{f}.farrier-bak-{len(self.files):08d}"
            self.files[b] = self.files[f]
            self.files[f] = content
            return CommandResult(0, f"{b}\n".encode(), "")
        raise AssertionError(f"unexpected script: {script[:40]}")

    def close(self):
        self.closed += 1


@pytest.fixture
def eng(data_dir):
    return Engine(data_dir)


def _prober(keys):
    def p(host, port):
        from farrier.ssh.wire import parse_banner as pb
        return ProbeResult(host, port, banner=pb("SSH-2.0-OpenSSH_9.8"),
                           kexinit=parse_kexinit(_kexinit(["mlkem768x25519-sha256"], ["ssh-ed25519"],
                                                          ["aes256-gcm@openssh.com"], ["hmac-sha2-256-etm@openssh.com"])),
                           host_keys=[parse_blob(b) for b in keys], method="kex")
    return p


ROOT_KEY = openssh_line(rsa_blob(RSA2048), "ops@bastion")
DEPLOY_KEYS = "\n".join(["# deploy keys", openssh_line(ed_blob(ED), "alice@laptop"), ROOT_KEY, ""])


def _profile(eng, name="fleet", **kw):
    body = {"username": "deploy", "private_key": "vault:ssh-fleet", "port": 22, "hosts": ["web1.internal"],
            "sudo": True, "known_hosts_policy": "tofu"} | kw
    eng.items.put(access.KIND, name, access.validate(body), "test")


def test_collection_and_removal_with_backup(eng):
    host = FakeHost({"/home/deploy/.ssh/authorized_keys": DEPLOY_KEYS.encode(),
                     "/root/.ssh/authorized_keys": (ROOT_KEY + "\n").encode()})
    _profile(eng)
    factory = lambda prof, h, port, known: host  # noqa: E731
    out = collect.collect(eng.store, eng.items, factory=factory, prober=_prober([ed_blob(ED)]))
    assert out["ok"] == 1 and out["keys"] == 3
    keys = db.keys(eng.store)
    by_user = {(k["username"], k["comment"]): k for k in keys}
    root = by_user[("root", "ops@bastion")]
    # "ops" and "alice" are not accounts on any collected host
    assert {f["id"] for f in root["findings"]} == {"key-rsa-small", "root-unrestricted", "orphaned-comment"}
    assert {f["id"] for f in by_user[("deploy", "alice@laptop")]["findings"]} == {"orphaned-comment"}
    assert any(sudo for _, sudo in host.commands)               # other users' files read with sudo
    assert db.pins(eng.store, "web1.internal", 22)[0]["source"] == "tofu"

    # dry run changes nothing
    target = by_user[("deploy", "ops@bastion")]
    before = dict(host.files)
    r = collect.remove_key(eng.store, eng.items, target["id"], "alice", dry_run=True,
                           factory=factory, prober=_prober([ed_blob(ED)]))
    assert r["dry_run"] and not r["removed"] and r["line_no"] == 3 and host.files == before

    r = collect.remove_key(eng.store, eng.items, target["id"], "alice", factory=factory, prober=_prober([ed_blob(ED)]))
    assert r["removed"] and r["verified"]
    path = "/home/deploy/.ssh/authorized_keys"
    assert host.files[r["backup"]] == DEPLOY_KEYS.encode()           # backup of the original
    old_lines, new_lines = DEPLOY_KEYS.split("\n"), host.files[path].decode().split("\n")
    assert new_lines == old_lines[:2] + old_lines[3:]                  # exactly one line gone
    assert host.files["/root/.ssh/authorized_keys"] == (ROOT_KEY + "\n").encode()   # other files untouched
    assert db.key(eng.store, target["id"]) is None
    ev = [e["message"] for e in eng.store.q("SELECT message FROM events ORDER BY id")]
    assert any("removed from deploy@web1.internal:22" in m and "by alice" in m for m in ev)
    assert host.closed >= 3


def test_removal_refuses_when_the_file_changed(eng):
    host = FakeHost({"/home/deploy/.ssh/authorized_keys": DEPLOY_KEYS.encode()})
    _profile(eng, sudo=False)
    factory = lambda prof, h, port, known: host  # noqa: E731
    collect.collect(eng.store, eng.items, factory=factory, prober=_prober([ed_blob(ED)]))
    k = next(k for k in db.keys(eng.store) if k["comment"] == "ops@bastion")
    host.files["/home/deploy/.ssh/authorized_keys"] = b"# rewritten by someone\n"
    with pytest.raises(collect.Conflict):
        collect.remove_key(eng.store, eng.items, k["id"], "alice", factory=factory, prober=_prober([ed_blob(ED)]))
    assert not any(p.startswith("/home/deploy/.ssh/authorized_keys.farrier-bak") for p in host.files)


def test_collection_without_sudo_reads_only_the_login_user(eng):
    host = FakeHost({"/home/deploy/.ssh/authorized_keys": DEPLOY_KEYS.encode(),
                     "/root/.ssh/authorized_keys": (ROOT_KEY + "\n").encode()})
    _profile(eng, sudo=False)
    collect.collect(eng.store, eng.items, factory=lambda *a: host, prober=_prober([ed_blob(ED)]))
    assert {k["username"] for k in db.keys(eng.store)} == {"deploy"}
    assert not any(sudo for _, sudo in host.commands)


def test_tofu_mismatch_is_an_error_and_never_connects(eng):
    host = FakeHost({"/home/deploy/.ssh/authorized_keys": DEPLOY_KEYS.encode()})
    _profile(eng)
    collect.collect(eng.store, eng.items, factory=lambda *a: host, prober=_prober([ed_blob(ED)]))
    host.commands.clear()
    other = ed25519.Ed25519PrivateKey.generate()
    out = collect.collect(eng.store, eng.items, factory=lambda *a: host, prober=_prober([ed_blob(other)]))
    assert out["ok"] == 0 and "HostKeyMismatch" in out["results"][0]["error"]
    assert host.commands == []                                        # no login attempted
    assert db.pins(eng.store, "web1.internal", 22)[0]["fingerprint"] == fingerprint(ed_blob(ED))   # pin unchanged
    err = eng.store.q("SELECT message FROM events WHERE level='error'")
    assert any("MISMATCH" in e["message"] for e in err)
    with pytest.raises(HostKeyMismatch):
        collect.verified_known_keys(eng.store, "web1.internal", 22, "tofu", _prober([ed_blob(other)]))


def test_strict_policy_needs_an_explicit_trust(eng):
    with pytest.raises(collect.HostKeyPolicyError):
        collect.verified_known_keys(eng.store, "h", 22, "strict", _prober([ed_blob(ED)]))
    collect.trust_host(eng.store, "h", 22, [parse_blob(ed_blob(ED))], "alice")
    assert collect.verified_known_keys(eng.store, "h", 22, "strict", _prober([ed_blob(ED)])) == \
        [("ssh-ed25519", base64.b64encode(ed_blob(ED)).decode())]


def test_duplicate_and_approved_findings_are_fleet_wide(eng):
    shared = openssh_line(ed_blob(ED), "ci@runner")
    hosts = {h: FakeHost({"/home/deploy/.ssh/authorized_keys": (shared + "\n").encode()})
             for h in ("a.internal", "b.internal", "c.internal")}
    _profile(eng, hosts=list(hosts))
    collect.collect(eng.store, eng.items, factory=lambda p, h, port, k: hosts[h], prober=_prober([ed_blob(ED)]))
    assert all({f["id"] for f in k["findings"]} == {"duplicate", "orphaned-comment"} for k in db.keys(eng.store))
    eng.items.put(access.APPROVED_KIND, access.APPROVED_NAME, {"fingerprints": ["SHA256:" + "A" * 43]})
    collect.refresh_findings(eng.store, eng.items)
    assert all("unknown" in {f["id"] for f in k["findings"]} for k in db.keys(eng.store))


# ---- secrets ----------------------------------------------------------------------------------------
SECRET = "-----BEGIN OPENSSH PRIVATE KEY-----\nTOPSECRETKEYMATERIAL\n-----END OPENSSH PRIVATE KEY-----"


def test_secret_never_reaches_logs_or_command_lines(eng, caplog, monkeypatch):
    eng.secrets.put("ssh-fleet", SECRET)
    _profile(eng, hosts=["ok.internal", "bad.internal"])
    seen = {}

    def factory(profile, h, port, known):
        from farrier.security.vault import resolve_secret
        seen[h] = resolve_secret(profile["private_key"])
        if h == "bad.internal":
            raise collect.CollectError("connection refused")
        return FakeHost({"/home/deploy/.ssh/authorized_keys": DEPLOY_KEYS.encode()})

    with caplog.at_level(logging.DEBUG):
        out = collect.collect(eng.store, eng.items, factory=factory, prober=_prober([ed_blob(ED)]))
    assert seen["ok.internal"] == SECRET and out["ok"] == 1
    events = json.dumps(eng.store.q("SELECT * FROM events"))
    assert "TOPSECRET" not in events and "TOPSECRET" not in caplog.text
    assert "TOPSECRET" not in json.dumps(out)
    assert "TOPSECRET" not in json.dumps(eng.items.all(access.KIND))   # only the reference is stored


@pytest.mark.skipif(not __import__("shutil").which("ssh"), reason="no ssh client")
def test_ssh_binary_transport_keeps_the_key_off_the_command_line():
    t = SSHBinaryTransport("h.internal", 2222, "deploy", SECRET, [("ssh-ed25519", "AAAA"), ("ssh-rsa", "BBBB")])
    try:
        argv = t._argv(wrap("true", sudo=True))
        assert not any("TOPSECRET" in a for a in argv)
        assert "StrictHostKeyChecking=yes" in argv and "HostKeyAlgorithms=ssh-ed25519,rsa-sha2-512,rsa-sha2-256" in argv
        assert argv[-1] == "sudo -n -- sh -c true"
        assert (t._dir / "id").read_text().strip() == SECRET
        assert (t._dir / "known_hosts").read_text() == "farrier-target ssh-ed25519 AAAA\nfarrier-target ssh-rsa BBBB\n"
    finally:
        t.close()
    assert not t._dir.exists()


# ---- routes -----------------------------------------------------------------------------------------
@pytest.fixture
def api(data_dir, monkeypatch):
    monkeypatch.setenv("FARRIER_API_TOKEN", "admin-tok")
    monkeypatch.setenv("FARRIER_API_READ_TOKEN", "read-tok")
    e = Engine(data_dir)
    return e, TestClient(create_app(e))


def test_access_profile_routes(api):
    eng, c = api
    good = {"username": "deploy", "private_key": "vault:ssh-fleet", "hosts": ["10.0.0.0/30", "bastion:2222"]}
    assert c.put("/api/ssh/access/fleet", json=good, headers=READ).status_code == 403
    for bad, msg in [({**good, "private_key": SECRET}, "secret reference"),
                     ({**good, "hosts": ["not a host!"]}, "not a valid host"),
                     ({**good, "hosts": ["sni@10.0.0.1:443"]}, "SNI"),
                     ({**good, "username": "root;rm"}, "username"),
                     ({**good, "known_hosts_policy": "yolo"}, "known_hosts_policy"),
                     ({**good, "extra": 1}, "unknown fields")]:
        r = c.put("/api/ssh/access/fleet", json=bad, headers=ADMIN)
        assert r.status_code == 400 and msg in r.text, (bad, r.text)
        assert "TOPSECRET" not in r.text
    r = c.put("/api/ssh/access/fleet", json=good, headers=ADMIN)
    assert r.status_code == 200 and r.json()["private_key"] == "vault:ssh-fleet" and r.json()["sudo"] is False
    assert access.expand_hosts(r.json()["hosts"], 22) == [("10.0.0.1", 22), ("10.0.0.2", 22), ("bastion", 2222)]
    # the reference is kept when not re-sent
    r = c.put("/api/ssh/access/fleet", json={k: v for k, v in good.items() if k != "private_key"} | {"sudo": True},
              headers=ADMIN)
    assert r.json()["private_key"] == "vault:ssh-fleet" and r.json()["sudo"] is True
    assert [p["name"] for p in c.get("/api/ssh/access", headers=READ).json()] == ["fleet"]
    assert c.get("/api/ssh/access/fleet", headers=READ).status_code == 200
    assert c.post("/api/ssh/collect", json={"access": "nope"}, headers=ADMIN).status_code == 404
    assert c.delete("/api/ssh/access/fleet", headers=READ).status_code == 403
    assert c.delete("/api/ssh/access/fleet", headers=ADMIN).status_code == 200
    assert c.get("/api/ssh/access/fleet", headers=READ).status_code == 404
    ev = [e["message"] for e in eng.store.q("SELECT message FROM events")]
    assert any("ssh access profile fleet added by alice" in m for m in ev)


def test_scan_route_and_summary_and_assets(api, ssh_server):
    eng, c = api
    assert c.post("/api/ssh/scan", json={"targets": "127.0.0.1"}, headers=READ).status_code == 403
    assert c.post("/api/ssh/scan", json={"targets": "bad host!"}, headers=ADMIN).status_code == 400
    r = c.post("/api/ssh/scan", json={"targets": f"127.0.0.1:{ssh_server.port}"}, headers=ADMIN)
    assert r.status_code == 200 and r.json()["ssh"] == 1
    hosts = c.get("/api/ssh/hosts", headers=READ).json()
    assert len(hosts) == 1
    h = hosts[0]
    assert set(h) >= {"id", "host", "port", "banner", "host_keys", "kex", "ciphers", "macs", "pqc_kex", "findings",
                      "observed_at"}
    assert h["pqc_kex"] is True and h["banner"].startswith("SSH-2.0-OpenSSH_7.9p1")
    assert {k["type"] for k in h["host_keys"]} == {"ssh-ed25519", "ssh-rsa"}
    assert all(set(f) == {"id", "severity", "detail"} for f in h["findings"])
    s = c.get("/api/ssh/summary", headers=READ).json()
    assert s["hosts"] == 1 and s["keys"] == 0 and s["pqc_kex_hosts"] == 1 and s["weak_host_keys"] == 1
    assert set(s["by_severity"]) == {"critical", "warning", "info"}
    [asset] = ssh_crypto_assets(eng.store)
    assert asset["id"] == f"ssh-{h['id']}" and asset["kind"] == "ssh" and asset["endpoint_id"] is None
    assert asset["target"] == f"127.0.0.1:{ssh_server.port}" and asset["protocol_versions"] == ["SSH-2.0"]
    assert asset["pqc_key_exchange"] is True and asset["pqc"]["status"] == "hybrid"
    assert asset["cert_key"] == {"algorithm": "Ed25519", "size": 256} and asset["signature_algorithm"] is None
    assert asset["weak"] and asset["cipher_suites"] == h["ciphers"]

    # explicit trust pins what the inventory showed
    r = c.post(f"/api/ssh/hosts/{h['id']}/trust", headers=ADMIN)
    assert r.status_code == 200 and len(r.json()["pinned"]) == 2
    pins = c.get(f"/api/ssh/hosts/{h['id']}/pins", headers=READ).json()
    assert {p["source"] for p in pins} == {"trusted by alice"}


def test_key_routes_with_fake_transport(api, monkeypatch):
    eng, c = api
    host = FakeHost({"/home/deploy/.ssh/authorized_keys": DEPLOY_KEYS.encode()})
    monkeypatch.setattr(collect, "default_transport", lambda *a: host)
    monkeypatch.setattr(collect, "default_prober", _prober([ed_blob(ED)]))
    c.put("/api/ssh/access/fleet", json={"username": "deploy", "private_key": "vault:k", "hosts": ["web1"]},
          headers=ADMIN)
    assert c.post("/api/ssh/access/fleet/test", headers=ADMIN).json() == {"ok": True, "host": "web1", "port": 22}
    assert c.post("/api/ssh/collect", json={}, headers=ADMIN).json()["keys"] == 2
    keys = c.get("/api/ssh/keys", headers=READ).json()
    k = next(k for k in keys if k["comment"] == "ops@bastion")
    assert set(k) >= {"id", "host", "user", "type", "bits", "fingerprint_sha256", "comment", "options", "first_seen",
                      "last_seen", "findings"}
    assert c.post(f"/api/ssh/keys/{k['id']}/remove", json={"dry_run": True}, headers=READ).status_code == 403
    r = c.post(f"/api/ssh/keys/{k['id']}/remove", json={"dry_run": True}, headers=ADMIN)
    assert r.status_code == 200 and r.json()["removed"] is False
    r = c.post(f"/api/ssh/keys/{k['id']}/remove", headers=ADMIN)
    assert r.status_code == 200 and r.json()["removed"] is True
    assert c.post(f"/api/ssh/keys/{k['id']}/remove", headers=ADMIN).status_code == 404
    assert len(c.get("/api/ssh/keys", headers=READ).json()) == 1


def test_periodic_run_is_due_once_per_interval(eng, monkeypatch):
    from datetime import UTC, datetime

    from farrier.ssh import schedule
    now = datetime.now(UTC)
    assert schedule.run_due(eng, now, background=False) is None          # nothing configured: no-op
    host = FakeHost({"/home/deploy/.ssh/authorized_keys": DEPLOY_KEYS.encode()})
    _profile(eng)
    orig = collect.collect
    scanned = []
    monkeypatch.setattr(collect, "collect", lambda store, items: orig(store, items, factory=lambda *a: host,
                                                                       prober=_prober([ed_blob(ED)])))
    monkeypatch.setattr(scan, "scan", lambda store, targets: scanned.append(targets) or {"ssh": 0, "scanned": len(targets)})
    assert schedule.run_due(eng, now, background=False) == "scan+collect"
    assert scanned == [[("web1.internal", 22)]] and len(db.keys(eng.store)) == 2
    assert schedule.run_due(eng, now, background=False) is None          # not due again for 24h


def _posix_sh():
    """argv prefix for a real POSIX sh with real symlinks: sh itself, or WSL's on Windows; None if neither."""
    import os
    import shutil
    import subprocess
    if os.name != "nt":
        return ["sh", "-c"] if shutil.which("sh") else None
    if shutil.which("wsl.exe"):
        try:
            p = subprocess.run(["wsl.exe", "-e", "sh", "-c", "echo ok"], capture_output=True, timeout=60)
            if p.stdout.strip() == b"ok":
                return ["wsl.exe", "-e", "sh", "-c"]
        except (OSError, subprocess.TimeoutExpired):
            pass
    return None


class LocalSh:
    """A Transport that runs scripts with a local POSIX sh. ``sudo`` is a fake on PATH that logs its
    arguments and runs the command as the current user."""

    def __init__(self, argv, bindir: str):
        self.argv, self.bindir = argv, bindir

    def run(self, script, stdin=None, sudo=False, timeout=60.0):
        import subprocess
        script = f'PATH="{self.bindir}:$PATH"; export PATH\n' + wrap(script, sudo)
        b64 = base64.b64encode(script.encode()).decode()
        p = subprocess.run(self.argv + [f'eval "$(echo {b64} | base64 -d)"'], input=stdin or b"",
                           capture_output=True, timeout=timeout)
        return CommandResult(p.returncode, p.stdout, p.stderr.decode("utf-8", "replace"))

    def close(self):
        pass


def test_key_removal_write_never_follows_planted_links_and_runs_as_the_account():
    from datetime import UTC, datetime, timedelta
    argv = _posix_sh()
    if argv is None:
        pytest.skip("no POSIX sh with symlinks (sh or WSL)")
    sh = LocalSh(argv, "/nonexistent")
    d = sh.run("mktemp -d").stdout.decode().strip()
    sh.bindir = f"{d}/bin"
    f = f"{d}/home/.ssh/authorized_keys"
    now = datetime.now(UTC)
    # the attacker owns ~/.ssh: links at every backup name the old code could pick in the next minute
    stamps = " ".join((now + timedelta(seconds=i)).strftime("%Y%m%dT%H%M%SZ") for i in range(-2, 60))
    setup = sh.run(f"""set -e
mkdir -p "{d}/home/.ssh" "{d}/etc" "{d}/bin"
echo root-owned-original > "{d}/etc/victim"
printf 'ssh-ed25519 AAAAOLD old\nssh-ed25519 AAAAKEEP keep\n' > "{f}"
for s in {stamps}; do ln -s "{d}/etc/victim" "{f}.farrier-bak-$s"; done
printf '#!/bin/sh\necho "$@" > "{d}/bin/sudo.log"\nwhile [ "$1" != "--" ]; do shift; done; shift\nexec "$@"\n' > "{d}/bin/sudo"
chmod +x "{d}/bin/sudo"
""")
    assert setup.ok, setup.stderr
    try:
        before = b"ssh-ed25519 AAAAOLD old\nssh-ed25519 AAAAKEEP keep\n"
        new = b"ssh-ed25519 AAAAKEEP keep\n"
        backup = collect.write_file(sh, f, "mallory", before, new)          # through sudo, as mallory
        out = sh.run(f'cat "{d}/etc/victim"; echo @@; cat "{f}"; echo @@; cat "{backup}"; echo @@; '
                     f'[ -L "{backup}" ] && echo LINK; cat "{d}/bin/sudo.log"').stdout.decode()
        victim, now_f, saved, rest = out.split("@@\n")
        assert victim == "root-owned-original\n"                  # nothing written through a planted link
        assert now_f.encode() == new and saved.encode() == before
        assert "LINK" not in rest and backup.startswith(f + ".farrier-bak-")
        assert "-u mallory -- sh -c" in rest                        # file operations run as the account
        # the file itself replaced by a link: refused, the target untouched
        sh.run(f'rm -f "{f}"; ln -s "{d}/etc/victim" "{f}"')
        with pytest.raises(collect.CollectError, match="not a regular file"):
            collect.write_file(sh, f, "", b"root-owned-original\n", b"x\n")
        assert sh.run(f'cat "{d}/etc/victim"').stdout == b"root-owned-original\n"
    finally:
        sh.run(f'rm -rf "{d}"')


def test_probe_is_bounded_against_a_server_trickling_ignore_messages():
    import time

    from farrier.ssh import wire
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def evil():          # never sends KEXINIT: an IGNORE every 0.2 s keeps each recv() under its timeout
        while not stop.is_set():
            try:
                c, _ = srv.accept()
            except OSError:
                return
            def feed(c=c):
                try:
                    c.sendall(b"SSH-2.0-evil\r\n")
                    while not stop.is_set():
                        c.sendall(wire.frame(bytes([wire.MSG_IGNORE]) + b"\0\0\0\0"))
                        time.sleep(0.2)
                except OSError:
                    pass
                finally:
                    c.close()
            threading.Thread(target=feed, daemon=True).start()

    threading.Thread(target=evil, daemon=True).start()
    try:
        done = {}
        t = threading.Thread(target=lambda: done.setdefault("r", probe("127.0.0.1", port, timeout=1.0)), daemon=True)
        t0 = time.monotonic()
        t.start()
        t.join(10)
        assert "r" in done, "probe still running after 10 s"
        assert time.monotonic() - t0 < 5 and done["r"].error and "Timeout" in done["r"].error
    finally:
        stop.set()
        srv.close()
