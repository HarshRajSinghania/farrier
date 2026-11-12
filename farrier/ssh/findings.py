"""Findings for SSH servers and authorized keys. Pure functions over parsed data; no I/O.

A finding is ``{"id", "severity": "critical"|"warning"|"info", "detail"}``; ids are stable so the
dashboard can group and suppress them.
"""
from __future__ import annotations

from collections.abc import Iterable

from farrier.ssh.keys import PublicKey
from farrier.ssh.wire import Banner, KexInit

CRITICAL, WARNING, INFO = "critical", "warning", "info"
SEVERITIES = (CRITICAL, WARNING, INFO)

PQC_KEX = ("sntrup761x25519-sha512@openssh.com", "sntrup761x25519-sha512", "mlkem768x25519-sha256")
# Pseudo-algorithms that signal extensions, not real key exchanges.
_KEX_PSEUDO = ("ext-info-", "kex-strict-", "kex-guess")

WEAK_KEX = {
    "diffie-hellman-group1-sha1": (CRITICAL, "1024-bit Diffie-Hellman with SHA-1 (Logjam range)"),
    "diffie-hellman-group14-sha1": (WARNING, "Diffie-Hellman with SHA-1"),
    "diffie-hellman-group-exchange-sha1": (WARNING, "group exchange with SHA-1"),
    "gss-group1-sha1-": (CRITICAL, "GSSAPI 1024-bit Diffie-Hellman with SHA-1"),
    "gss-group14-sha1-": (WARNING, "GSSAPI Diffie-Hellman with SHA-1"),
    "gss-gex-sha1-": (WARNING, "GSSAPI group exchange with SHA-1"),
    "rsa1024-sha1": (CRITICAL, "RSA-1024 key transport with SHA-1"),
}
WEAK_HOSTKEY_ALGS = {
    "ssh-dss": (CRITICAL, "DSA host key signatures (1024-bit, SHA-1)"),
    "ssh-rsa": (WARNING, "RSA host key signatures with SHA-1 (ssh-rsa)"),
}


def _f(fid: str, severity: str, detail: str) -> dict:
    return {"id": fid, "severity": severity, "detail": detail}


def real_kex(kex: Iterable[str]) -> list[str]:
    return [k for k in kex if not k.startswith(_KEX_PSEUDO)]


def offers_pqc(kex: Iterable[str]) -> bool:
    return any(k in PQC_KEX for k in kex)


def _cipher_weakness(name: str) -> tuple[str, str] | None:
    n = name.lower()
    if n == "none":
        return CRITICAL, "no encryption"
    if n.startswith(("arcfour", "des-", "des@")) or n in ("des", "blowfish-cbc", "cast128-cbc", "rijndael-cbc@lysator.liu.se"):
        return CRITICAL, "broken or 64-bit-block cipher"
    if n.startswith("3des"):
        return WARNING, "3DES (64-bit block, Sweet32)"
    if n.endswith("-cbc"):
        return WARNING, "CBC mode (plaintext recovery attacks on SSH)"
    return None


def _mac_weakness(name: str) -> tuple[str, str] | None:
    n = name.lower()
    if n == "none":
        return CRITICAL, "no integrity protection"
    if "md5" in n:
        return WARNING, "MD5-based MAC"
    if n.endswith("-96") or n.startswith("umac-64"):
        return WARNING, "truncated MAC"
    if "sha1" in n:
        return WARNING, "SHA-1-based MAC"
    if not n.endswith("-etm@openssh.com"):
        return INFO, "encrypt-and-MAC (prefer the -etm variant)"
    return None


def host_findings(banner: Banner | None, kexinit: KexInit | None, host_keys: list[PublicKey]) -> list[dict]:
    out: list[dict] = []
    if banner is not None:
        if not banner.proto.startswith("2."):
            sev = CRITICAL if banner.proto.startswith("1.") and banner.proto != "1.99" else WARNING
            out.append(_f("ssh-protocol-1", sev, f"server speaks SSH protocol {banner.proto}"))
        v = banner.openssh_version
        if v and v < (8, 0):
            sev = CRITICAL if v < (7, 4) else WARNING
            out.append(_f("outdated-openssh", sev, f"{banner.software} is older than OpenSSH 8.0"))
    if kexinit is not None:
        for k in kexinit.kex:
            for name, (sev, why) in WEAK_KEX.items():
                if k == name or (name.endswith("-") and k.startswith(name)):
                    out.append(_f(f"weak-kex:{k}", sev, f"key exchange {k}: {why}"))
        for alg in kexinit.host_key:
            if alg in WEAK_HOSTKEY_ALGS:
                sev, why = WEAK_HOSTKEY_ALGS[alg]
                out.append(_f(f"weak-hostkey-alg:{alg}", sev, why))
        for c in kexinit.ciphers:
            if w := _cipher_weakness(c):
                out.append(_f(f"weak-cipher:{c}", w[0], f"cipher {c}: {w[1]}"))
        for m in kexinit.macs:
            if w := _mac_weakness(m):
                out.append(_f(f"weak-mac:{m}", w[0], f"MAC {m}: {w[1]}"))
        vulnerable_modes = any(c == "chacha20-poly1305@openssh.com" for c in kexinit.ciphers) or \
            any(m.endswith("-etm@openssh.com") for m in kexinit.macs)
        if vulnerable_modes and "kex-strict-s-v00@openssh.com" not in kexinit.kex:
            out.append(_f("terrapin", WARNING, "ChaCha20-Poly1305 or -etm MACs offered without strict key "
                                               "exchange (Terrapin, CVE-2023-48795)"))
        if not offers_pqc(kexinit.kex):
            out.append(_f("no-pqc-kex", INFO, "no post-quantum hybrid key exchange (sntrup761x25519, "
                                              "mlkem768x25519) offered"))
    for k in host_keys:
        out += key_strength_findings(k, prefix="host-key")
    return out


def key_strength_findings(k: PublicKey, prefix: str = "key") -> list[dict]:
    if k.type == "ssh-dss":
        return [_f(f"{prefix}-dsa", CRITICAL, "DSA key (1024-bit, SHA-1 signatures; removed from OpenSSH)")]
    if k.type == "ssh-rsa" and k.bits < 2048:
        return [_f(f"{prefix}-rsa-small", CRITICAL, f"RSA key of {k.bits} bits (< 2048)")]
    if k.type == "ssh-rsa" and k.bits < 3072:
        return [_f(f"{prefix}-rsa-small", WARNING, f"RSA key of {k.bits} bits (< 3072)")]
    return []


# ---- authorized keys ---------------------------------------------------------------------------------
_RESTRICTING = ("from", "restrict", "command")
_NO_SHELL = ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false", "/bin/nologin")


def authorized_key_findings(row: dict, *, duplicate_count: int, approved: set[str] | None,
                            fleet_users: set[str] | None) -> list[dict]:
    """``row`` has type, bits, fingerprint_sha256, comment, options (dict), user, user_uid,
    user_shell, never_logged_in. ``duplicate_count`` is how many (host, user) pairs carry the key."""
    out = key_strength_findings(PublicKey(row["type"], row["bits"] or 0, b""))
    if duplicate_count >= 3:
        out.append(_f("duplicate", WARNING, f"same key authorizes {duplicate_count} host/user pairs"))
    if approved and row["fingerprint_sha256"] not in approved:
        out.append(_f("unknown", WARNING, "not in the approved keys list"))
    if (row.get("user_shell") or "") in _NO_SHELL:
        out.append(_f("orphaned-no-shell", INFO, f"user {row['user']} has no login shell ({row['user_shell']})"))
    elif row.get("never_logged_in"):
        out.append(_f("orphaned-never-logged-in", INFO, f"user {row['user']} has never logged in (lastlog)"))
    comment = row.get("comment") or ""
    if fleet_users is not None and "@" in comment:
        who = comment.split("@", 1)[0].strip()
        if who and who not in fleet_users:
            out.append(_f("orphaned-comment", INFO, f"comment names {who!r}, an account not found on any collected host"))
    opts = row.get("options") or {}
    if (row.get("user") == "root" or row.get("user_uid") == 0) and not any(o in opts for o in _RESTRICTING):
        out.append(_f("root-unrestricted", WARNING, "authorizes root with no from=, command= or restrict"))
    return out


def by_severity(findings: Iterable[dict]) -> dict[str, int]:
    counts = dict.fromkeys(SEVERITIES, 0)
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts
