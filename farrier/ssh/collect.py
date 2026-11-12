"""Authorized-key collection and removal over SSH with a stored access profile (agentless).

What a host needs: an account the profile's key can log in to, a POSIX ``sh`` with ``base64``,
``getent`` (or a readable /etc/passwd), and for removal ``cp``, ``mktemp``, ``mv`` and ``sha256sum``
(or ``shasum``). With ``sudo: true``, passwordless ``sudo -n`` to read other users' files.

Host keys: before every connection the host's keys are probed (farrier.ssh.probe) and compared with the
keys pinned for host:port. No pin yet: "tofu" pins what the host presents now; "strict" refuses until a
key is trusted explicitly. A pinned key type presenting a different key is a HostKeyMismatch, logged as
an error and never accepted; ssh itself then runs with only the pinned keys as known hosts.

Remote scripts read their variable inputs (paths, hashes, file content) from stdin, never from the command
line, so nothing taken from a host or the API is interpolated into a shell command.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
from collections import Counter
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

from farrier.security.vault import resolve_secret
from farrier.ssh import access, db, scan
from farrier.ssh.authorized_keys import (Account, authorized_keys_files, expand_pattern, parse_authorized_keys,
                                         parse_passwd, remove_line)
from farrier.ssh.findings import authorized_key_findings
from farrier.ssh.keys import PublicKey
from farrier.ssh.probe import ProbeResult, probe
from farrier.ssh.transport import HostKeyMismatch, SSHBinaryTransport, Transport, TransportError

TransportFactory = Callable[[dict, str, int, list[tuple[str, str]]], Transport]
HostProber = Callable[[str, int], ProbeResult]

_ENV_SCRIPT = r"""id -un
id -u
printf '@@\n'
(getent passwd 2>/dev/null || cat /etc/passwd) | base64
printf '@@\n'
if [ -r /etc/ssh/sshd_config ]; then base64 < /etc/ssh/sshd_config; fi
printf '@@\n'
(lastlog 2>/dev/null || true) | base64
"""

# stdin: one path per line. Output: "@@F <n>" then the file as base64, or "@@E <n>" if unreadable.
_READ_SCRIPT = r"""i=0
while IFS= read -r p; do
  if [ -f "$p" ]; then
    printf '@@F %s\n' "$i"
    base64 < "$p" || printf '@@E %s\n' "$i"
  fi
  i=$((i+1))
done
"""

# stdin: path, backup path, expected sha256 of the current file, then the new content.
_WRITE_SCRIPT = r"""set -eu
IFS= read -r f
IFS= read -r b
IFS= read -r want
have=$( (sha256sum 2>/dev/null || shasum -a 256) < "$f" | cut -d' ' -f1)
if [ "$have" != "$want" ]; then echo "file changed since it was read" >&2; exit 3; fi
cp -p -- "$f" "$b"
t=$(mktemp "$f.farrier-XXXXXX")
cp -p -- "$f" "$t"
cat > "$t"
mv -f -- "$t" "$f"
"""


class CollectError(Exception):
    pass


class HostKeyPolicyError(CollectError):
    pass


class Conflict(CollectError):
    """The file no longer matches what was collected (HTTP 409)."""


def default_transport(profile: dict, host: str, port: int, known: list[tuple[str, str]]) -> Transport:
    return SSHBinaryTransport(host, port, profile["username"], resolve_secret(profile["private_key"]), known)


def default_prober(host: str, port: int) -> ProbeResult:
    return probe(host, port, timeout=5.0)


# ---- host-key verification --------------------------------------------------------------------------
def verified_known_keys(store, host: str, port: int, policy: str, prober: HostProber = default_prober
                        ) -> list[tuple[str, str]]:
    """(key type, base64) pairs ssh may accept for host:port. Raises on a mismatch or untrusted host."""
    res = prober(host, port)
    if res.banner is not None:
        scan.save_probe(store, res)             # a login is also a fresh discovery result
    pinned = db.pins(store, host, port)
    offered = {k.type: k for k in res.host_keys}
    if pinned:
        for p in pinned:
            k = offered.get(p["key_type"])
            if k is not None and k.b64 != p["key_b64"]:
                store.log(f"ssh host key MISMATCH for {host}:{port}: {p['key_type']} pinned {p['fingerprint']}, "
                          f"presented {k.fingerprint_sha256}; not connecting", level="error")
                raise HostKeyMismatch(f"{host}:{port} presented {p['key_type']} {k.fingerprint_sha256}, but "
                                      f"{p['fingerprint']} is pinned")
        return [(p["key_type"], p["key_b64"]) for p in pinned]
    if policy == "strict":
        raise HostKeyPolicyError(f"{host}:{port} has no trusted host key (strict policy); trust it first")
    if not res.host_keys:
        raise CollectError(f"could not read the host key of {host}:{port}: {res.error or '; '.join(res.notes)}")
    db.add_pins(store, host, port, res.host_keys, "tofu")
    store.log(f"ssh host keys of {host}:{port} pinned on first contact (TOFU): "
              + ", ".join(f"{k.type} {k.fingerprint_sha256}" for k in res.host_keys))
    return [(k.type, k.b64) for k in res.host_keys]


def trust_host(store, host: str, port: int, keys: list[PublicKey], actor: str) -> None:
    """Pin exactly these keys (replacing any pins): the explicit trust step for "strict" profiles and the
    recovery path after a legitimate host-key change."""
    db.replace_pins(store, host, port, keys, f"trusted by {actor}")
    store.log(f"ssh host keys of {host}:{port} trusted by {actor}: "
              + ", ".join(f"{k.type} {k.fingerprint_sha256}" for k in keys))


# ---- remote reads -----------------------------------------------------------------------------------
def _b64(lines: list[str]) -> bytes:
    try:
        return base64.b64decode("".join(x.strip() for x in lines), validate=True)
    except (binascii.Error, ValueError):
        raise CollectError("unreadable base64 from host") from None


def parse_env(out: bytes) -> tuple[str, int, list[Account], str, set[str]]:
    """(login user, login uid, accounts, sshd_config text, users that never logged in)."""
    parts = out.decode("utf-8", "replace").split("@@\n")
    if len(parts) < 4:
        raise CollectError("unexpected output from host (is the login shell POSIX sh compatible?)")
    head = parts[0].split("\n")
    if len(head) < 2 or not head[1].strip().isdigit():
        raise CollectError("could not read the login identity")
    passwd = _b64(parts[1].splitlines()).decode("utf-8", "replace")
    sshd = _b64(parts[2].splitlines()).decode("utf-8", "replace")
    lastlog = _b64(parts[3].splitlines()).decode("utf-8", "replace")
    never = {ln.split()[0] for ln in lastlog.splitlines()[1:] if ln.split() and "**Never logged in**" in ln}
    return head[0].strip(), int(head[1]), parse_passwd(passwd), sshd, never


def parse_read(out: bytes, count: int) -> dict[int, bytes | None]:
    """index -> content (None: exists but unreadable). Missing files are absent."""
    files: dict[int, bytes | None] = {}
    cur: int | None = None
    buf: list[str] = []

    def flush():
        if cur is not None and cur not in files:
            files[cur] = _b64(buf)

    for line in out.decode("ascii", "replace").splitlines():
        if line.startswith("@@F "):
            flush()
            cur, buf = int(line[4:]), []
        elif line.startswith("@@E "):
            files[int(line[4:])] = None
            cur, buf = None, []
        else:
            buf.append(line)
    flush()
    return {i: c for i, c in files.items() if 0 <= i < count}


def _read_files(t: Transport, paths: list[str], sudo: bool) -> dict[int, bytes | None]:
    if any("\n" in p or "\r" in p for p in paths):
        raise CollectError("refusing a path containing a newline")
    r = t.run(_READ_SCRIPT, stdin=("\n".join(paths) + "\n").encode(), sudo=sudo, timeout=120)
    if not r.ok:
        raise CollectError(f"reading authorized_keys failed (exit {r.rc}): {r.stderr[-200:]}")
    return parse_read(r.stdout, len(paths))


def _targets(login: str, accounts: list[Account], sudo: bool, patterns: list[str]) -> list[tuple[Account, str]]:
    users = [a for a in accounts if a.home and a.home not in ("/", "/nonexistent")]
    if not sudo:
        users = [a for a in users if a.name == login]
    out = []
    for a in users:
        for pat in patterns:
            out.append((a, expand_pattern(pat, a.name, a.home, a.uid)))
    return list(dict.fromkeys(out))


# ---- collection -------------------------------------------------------------------------------------
def collect_host(store, name: str, profile: dict, host: str, port: int,
                 factory: TransportFactory = default_transport, prober: HostProber = default_prober) -> dict:
    known = verified_known_keys(store, host, port, profile["known_hosts_policy"], prober)
    t = factory(profile, host, port, known)
    try:
        env = t.run(_ENV_SCRIPT, timeout=60)
        if not env.ok:
            raise CollectError(f"reading accounts failed (exit {env.rc}): {env.stderr[-200:]}")
        login, _uid, accounts, sshd, never = parse_env(env.stdout)
        targets = _targets(login, accounts, profile["sudo"], authorized_keys_files(sshd))
        contents = _read_files(t, [p for _, p in targets], profile["sudo"])
    finally:
        t.close()
    rows, unreadable, invalid = [], [], 0
    for i, (acct, path) in enumerate(targets):
        if i not in contents:
            continue
        if contents[i] is None:
            unreadable.append(path)
            continue
        parsed = parse_authorized_keys(contents[i].decode("utf-8", "surrogateescape"))
        invalid += len(parsed.invalid)
        for k in parsed.keys:
            rows.append({"username": acct.name, "path": path, "line_sha256": k.line_sha256,
                         "fingerprint": k.key.fingerprint_sha256,
                         "data": {"type": k.key.type, "bits": k.key.bits, "comment": k.comment, "options": k.options,
                                  "line_no": k.line_no, "user_uid": acct.uid, "user_shell": acct.shell,
                                  "never_logged_in": acct.name in never, "findings": []}})
    sync = db.sync_host_keys(store, host, port, name, rows, frozenset(unreadable))
    db.set_host_accounts(store, host, port, sorted(a.name for a in accounts))
    return {"host": host, "port": port, "ok": True, **sync, "invalid_lines": invalid, "unreadable": unreadable}


def collect(store, items, only: str | None = None, factory: TransportFactory = default_transport,
            prober: HostProber = default_prober, workers: int = 8) -> dict:
    profs = access.profiles(items)
    if only is not None:
        if only not in profs:
            raise KeyError(only)
        profs = {only: profs[only]}
    jobs = [(n, p, h, port) for n, p in profs.items() for h, port in access.expand_hosts(p["hosts"], p["port"])]

    def one(job):
        n, p, h, port = job
        try:
            return collect_host(store, n, p, h, port, factory, prober)
        except (CollectError, TransportError, KeyError, OSError) as e:
            # KeyError: an unset secret reference. Messages never contain secret values.
            level = "error" if isinstance(e, HostKeyMismatch) else "warning"
            store.log(f"ssh collection from {h}:{port} ({n}) failed: {type(e).__name__}: {e}", level=level)
            return {"host": h, "port": port, "ok": False, "error": f"{type(e).__name__}: {e}"}

    results = []
    if jobs:
        with ThreadPoolExecutor(max_workers=max(1, min(workers, len(jobs)))) as pool:
            results = list(pool.map(one, jobs))
    refresh_findings(store, items)
    db.mark_run(store, "collect")
    return {"hosts": len(jobs), "ok": sum(1 for r in results if r["ok"]),
            "keys": sum(r.get("keys", 0) for r in results), "results": results}


def refresh_findings(store, items) -> None:
    """Recompute per-key findings over the whole inventory (duplicates and orphans are fleet-wide)."""
    rows = db.keys(store)
    pairs: dict[str, set] = {}
    for r in rows:
        pairs.setdefault(r["fingerprint"], set()).add((r["host"], r["port"], r["username"]))
    dup = Counter({fp: len(s) for fp, s in pairs.items()})
    approved = access.approved_fingerprints(items) or None
    fleet = {u for h in db.hosts(store) for u in (h.get("accounts") or [])} or None
    for r in rows:
        f = authorized_key_findings({**r, "fingerprint_sha256": r["fingerprint"], "user": r["username"]},
                                    duplicate_count=dup[r["fingerprint"]], approved=approved, fleet_users=fleet)
        if f != r.get("findings"):
            db.set_key_findings(store, r["id"], f)


# ---- removal ----------------------------------------------------------------------------------------
def remove_key(store, items, kid: int, actor: str, dry_run: bool = False,
               factory: TransportFactory = default_transport, prober: HostProber = default_prober) -> dict:
    row = db.key(store, kid)
    if row is None:
        raise KeyError(kid)
    profile = items.get(access.KIND, row["access"])
    if profile is None:
        raise CollectError(f"access profile {row['access']} no longer exists")
    other_user = row["username"] != profile["username"]
    if other_user and not profile["sudo"]:
        raise CollectError(f"{row['username']}'s file needs sudo, which profile {row['access']} does not have")
    host, port, path = row["host"], row["port"], row["path"]
    known = verified_known_keys(store, host, port, profile["known_hosts_policy"], prober)
    t = factory(profile, host, port, known)
    try:
        before = _read_files(t, [path], other_user).get(0)
        if before is None:
            raise Conflict(f"{path} is gone or unreadable")
        text = before.decode("utf-8", "surrogateescape")
        try:
            new_text, line_no = remove_line(text, row["line_sha256"])
        except ValueError as e:
            raise Conflict(f"{path}: {e}; collect again") from None
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        backup = f"{path}.farrier-bak-{stamp}"
        out = {"id": kid, "host": host, "port": port, "user": row["username"], "path": path, "line_no": line_no,
               "fingerprint_sha256": row["fingerprint"], "backup": backup, "dry_run": dry_run}
        where = f"{row['username']}@{host}:{port} {path} line {line_no}"
        if dry_run:
            store.log(f"ssh key {row['fingerprint']} removal dry-run on {where} by {actor}")
            return out | {"removed": False}
        new = new_text.encode("utf-8", "surrogateescape")
        header = f"{path}\n{backup}\n{hashlib.sha256(before).hexdigest()}\n".encode()
        w = t.run(_WRITE_SCRIPT, stdin=header + new, sudo=other_user, timeout=60)
        if w.rc == 3:
            raise Conflict(f"{path} changed while removing; nothing was written")
        if not w.ok:
            raise CollectError(f"writing {path} failed (exit {w.rc}): {w.stderr[-200:]}")
        after = _read_files(t, [path], other_user).get(0)
    finally:
        t.close()
    if after != new:
        store.log(f"ssh key removal on {where} by {actor} could not be verified; backup at {backup}", level="error")
        raise CollectError(f"{path} does not hold the expected content after the write; backup at {backup}")
    db.delete_key(store, kid)
    store.log(f"ssh key {row['fingerprint']} ({row['type']}) removed from {where} by {actor}; backup {backup}")
    refresh_findings(store, items)
    return out | {"removed": True, "verified": True}
