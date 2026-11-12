"""Parsers for what collection reads off a host: authorized_keys, sshd_config and passwd. Pure.

authorized_keys format (sshd(8)): ``[options] keytype base64 [comment]``. Options are comma-separated
with no spaces, except inside double quotes, where ``\\"`` is a literal quote.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass, field

from farrier.ssh.keys import KEY_TYPES, PublicKey, parse_blob
from farrier.ssh.wire import WireError

DEFAULT_AUTHORIZED_KEYS_FILES = (".ssh/authorized_keys", ".ssh/authorized_keys2")
_KNOWN_TYPES = set(KEY_TYPES) | {t.removesuffix("@openssh.com") + "-cert-v01@openssh.com" for t in KEY_TYPES}


@dataclass
class AuthorizedKey:
    line_no: int
    line_sha256: str            # identifies the exact line for removal
    options: dict[str, str | bool | list[str]]
    key: PublicKey
    comment: str


@dataclass
class InvalidLine:
    line_no: int
    reason: str


@dataclass
class ParsedFile:
    keys: list[AuthorizedKey] = field(default_factory=list)
    invalid: list[InvalidLine] = field(default_factory=list)


def line_hash(line: str) -> str:
    return hashlib.sha256(line.rstrip("\r\n").encode()).hexdigest()


def split_options(text: str) -> tuple[str, str]:
    """(options, rest): the options prefix ends at the first whitespace outside double quotes."""
    in_q = esc = False
    for i, ch in enumerate(text):
        if esc:
            esc = False
        elif in_q and ch == "\\":
            esc = True
        elif ch == '"':
            in_q = not in_q
        elif not in_q and ch in " \t":
            return text[:i], text[i:].lstrip()
    if in_q:
        raise ValueError("unterminated quote in options")
    return text, ""


def parse_options(opts: str) -> dict[str, str | bool | list[str]]:
    out: dict[str, str | bool | list[str]] = {}
    items, cur, in_q, esc = [], "", False, False
    for ch in opts:
        if esc:
            cur += ch
            esc = False
        elif in_q and ch == "\\":
            esc = True
        elif ch == '"':
            in_q = not in_q
        elif ch == "," and not in_q:
            items.append(cur)
            cur = ""
        else:
            cur += ch
    if in_q:
        raise ValueError("unterminated quote in options")
    items.append(cur)
    for item in items:
        if not item:
            raise ValueError("empty option")
        name, eq, value = item.partition("=")
        name = name.lower()
        if not name.replace("-", "").isalnum():
            raise ValueError(f"bad option name {name[:32]!r}")
        v: str | bool = value if eq else True
        if name in out:
            prev = out[name]
            out[name] = (prev if isinstance(prev, list) else [str(prev)]) + [str(v)]
        else:
            out[name] = v
    return out


def parse_line(line: str, line_no: int = 1) -> AuthorizedKey | InvalidLine | None:
    """None for blank and comment lines."""
    text = line.rstrip("\r\n").strip()
    if not text or text.startswith("#"):
        return None
    try:
        first = text.split(None, 1)[0]
        if first in _KNOWN_TYPES:
            options: dict = {}
            rest = text
        else:
            raw_opts, rest = split_options(text)
            options = parse_options(raw_opts)
        parts = rest.split(None, 2)
        if len(parts) < 2:
            return InvalidLine(line_no, "missing key type or key data")
        ktype, b64 = parts[0], parts[1]
        comment = parts[2].strip() if len(parts) > 2 else ""
        if ktype not in _KNOWN_TYPES:
            return InvalidLine(line_no, f"unknown key type {ktype[:40]!r}")
        if ktype.endswith("-cert-v01@openssh.com"):
            return InvalidLine(line_no, "certificates belong in TrustedUserCAKeys, not authorized_keys")
        blob = base64.b64decode(b64, validate=True)
        key = parse_blob(blob)
        if key.type != ktype:
            return InvalidLine(line_no, f"key data is {key.type}, line says {ktype}")
    except (ValueError, binascii.Error, WireError) as e:
        return InvalidLine(line_no, str(e) or "unparseable")
    return AuthorizedKey(line_no, line_hash(line), options, key, comment)


def parse_authorized_keys(text: str) -> ParsedFile:
    out = ParsedFile()
    for i, line in enumerate(text.split("\n"), 1):
        r = parse_line(line, i)
        if isinstance(r, AuthorizedKey):
            out.keys.append(r)
        elif isinstance(r, InvalidLine):
            out.invalid.append(r)
    return out


def remove_line(text: str, sha256: str) -> tuple[str, int]:
    """Content with the one line whose hash is ``sha256`` removed, and its 1-based line number.
    Raises ValueError unless exactly one line matches (never guesses)."""
    lines = text.split("\n")
    hits = [i for i, line in enumerate(lines) if line.strip() and line_hash(line) == sha256]
    if len(hits) != 1:
        raise ValueError(f"expected exactly one matching line, found {len(hits)}")
    i = hits[0]
    del lines[i]
    return "\n".join(lines), i + 1


# ---- sshd_config / passwd ---------------------------------------------------------------------------
def authorized_keys_files(sshd_config: str | None) -> list[str]:
    """AuthorizedKeysFile patterns (first occurrence wins, as in sshd); defaults when unset.
    ``Match`` blocks are not evaluated: only the global setting is used."""
    for raw in (sshd_config or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        word, rest = (line.split(None, 1) + [""])[:2]
        if "=" in word:                         # sshd also accepts "Keyword=value"
            word, _, first = word.partition("=")
            rest = f"{first} {rest}"
        if word.lower() == "match":
            break
        if word.lower() == "authorizedkeysfile":
            pats = rest.split()
            return [] if pats == ["none"] else pats
    return list(DEFAULT_AUTHORIZED_KEYS_FILES)


def expand_pattern(pattern: str, user: str, home: str, uid: int) -> str:
    out, i = "", 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "%" and i + 1 < len(pattern):
            nxt = pattern[i + 1]
            out += {"%": "%", "h": home, "u": user, "U": str(uid)}.get(nxt, "%" + nxt)
            i += 2
            continue
        out += ch
        i += 1
    if out.startswith("~/"):
        out = home.rstrip("/") + out[1:]
    elif not out.startswith("/"):
        out = home.rstrip("/") + "/" + out
    return out


@dataclass(frozen=True)
class Account:
    name: str
    uid: int
    home: str
    shell: str


def parse_passwd(text: str) -> list[Account]:
    out = []
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) < 7 or not parts[0]:
            continue
        try:
            uid = int(parts[2])
        except ValueError:
            continue
        out.append(Account(parts[0], uid, parts[5], parts[6]))
    return out
