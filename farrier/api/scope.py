"""Project scope: which projects one API request may see or change.

The dashboard signs in users with SSO and works out which projects each may use (from their groups and
each project's member groups). It tells the engine with one header per request:

    X-Farrier-Scope: v1;<ids>;<ts>;<sig>

    ids  "*" (every project: a global admin) or comma-separated project ids, possibly none ("")
    ts   unix seconds when the dashboard signed it; accepted for MAX_AGE seconds either way (clock skew)
    sig  hex HMAC-SHA256 over "v1\\n<METHOD>\\n<path>\\n<ids>\\n<ts>" with a key derived from
         FARRIER_API_TOKEN: HMAC-SHA256(key=<token>, msg="farrier-scope-v1")

The signature binds the header to one method and path, so a scope minted for a read cannot authorize a
renewal, and the ids cannot be changed without the token. The dashboard sends, for each call, only the
projects in which the user's role allows that call, so the engine only has to ask "is this row's project
in the scope?". Requests without the header keep the access their token gives (the admin token used
directly by the CLI or automation, the read token by monitoring); a header that is present but does not
verify is refused, never ignored.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import time

from fastapi import HTTPException, Request

HEADER = "x-farrier-scope"
MAX_AGE = 60
_IDS = re.compile(r"^(\*|\d{1,12}(,\d{1,12}){0,999}|)$")


class ScopeError(ValueError):
    """A scope header that is malformed, expired or not signed with this install's token."""


def key_for(token: str) -> bytes:
    return hmac.new(token.encode(), b"farrier-scope-v1", hashlib.sha256).digest()


def signature(key: bytes, method: str, path: str, ids: str, ts: int | str) -> str:
    msg = f"v1\n{method.upper()}\n{path}\n{ids}\n{ts}".encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def sign(token: str, method: str, path: str, ids: str, ts: int | None = None) -> str:
    """The header value (tests and tooling; the dashboard has its own copy in web/src/lib/auth/scope.ts)."""
    ts = int(time.time()) if ts is None else ts
    return f"v1;{ids};{ts};{signature(key_for(token), method, path, ids, ts)}"


class Scope:
    """``ids`` None: every project. Otherwise the project ids this request may touch."""

    def __init__(self, ids: frozenset[int] | None = None, default_id: int = 1):
        self.ids = ids
        self.default_id = default_id

    @property
    def all(self) -> bool:
        return self.ids is None

    def has(self, project_id: int | None) -> bool:
        return self.ids is None or (self.default_id if project_id is None else project_id) in self.ids

    def has_row(self, row: dict | None) -> bool:
        return row is not None and self.has(row.get("project_id"))

    def sql(self, column: str) -> tuple[str, tuple]:
        """(" AND <column in scope>", args) to append to a WHERE clause; empty for every project."""
        if self.ids is None:
            return "", ()
        if not self.ids:
            return " AND 1=0", ()
        ids = sorted(self.ids)
        return f" AND COALESCE({column}, ?) IN ({','.join('?' * len(ids))})", (self.default_id, *ids)

    def only(self, project_id: int) -> Scope:
        """This scope narrowed to one project (empty when it is not in it)."""
        return Scope(frozenset({project_id}) if self.has(project_id) else frozenset(), self.default_id)


ALL = Scope()


def parse(value: str, token: str | None, method: str, path: str, default_id: int = 1,
          now: float | None = None) -> Scope:
    """Verify a header value. Raises ScopeError for anything that is not a fresh, correctly signed scope."""
    if not token:
        raise ScopeError("a project scope needs FARRIER_API_TOKEN on the engine to verify it")
    parts = value.split(";")
    if len(parts) != 4 or parts[0] != "v1":
        raise ScopeError("malformed project scope")
    _, ids, ts, sig = parts
    if not _IDS.match(ids) or not ts.isdigit() or not re.fullmatch(r"[0-9a-f]{64}", sig):
        raise ScopeError("malformed project scope")
    want = signature(key_for(token), method, path, ids, ts)
    if not hmac.compare_digest(want, sig):
        raise ScopeError("project scope signature does not verify")
    now = time.time() if now is None else now
    if abs(now - int(ts)) > MAX_AGE:
        raise ScopeError("project scope expired")
    if ids == "*":
        return Scope(None, default_id)
    return Scope(frozenset(int(i) for i in ids.split(",") if i), default_id)


class Guard:
    """Route helpers: the request's scope, and rows looked up through it.

    Reads of a row outside the scope answer 404 (its existence is not confirmed); changes answer 403.
    """

    def __init__(self, store):
        self.S = store

    @staticmethod
    def of(request) -> Scope:
        return getattr(request.state, "scope", ALL)

    def global_only(self, request: Request) -> None:
        """For changes that affect every project (settings, issuers, channels, a full cycle...)."""
        if not self.of(request).all:
            raise HTTPException(403, "this changes the whole install, not one project; it needs a global admin")

    def endpoint(self, request, eid: int, write: bool = False) -> dict:
        ep = self.S.endpoint(eid)
        if not ep or not (write or self.of(request).has_row(ep)):
            raise HTTPException(404)
        if not self.of(request).has_row(ep):
            raise HTTPException(403, f"endpoint {eid} is in project {ep['project']}, outside your access")
        return ep

    def renewal(self, request, rid: int, write: bool = False) -> dict:
        """The renewal; its project is its endpoint's."""
        r = self.S.renewal(rid)
        if not r:
            raise HTTPException(404)
        self.endpoint(request, r["endpoint_id"], write)
        return r

    def project_id(self, request, name: str | None) -> int:
        """Where new rows go (discovery, scans, a new endpoint): ``name`` if given and allowed; otherwise
        the caller's only project, or "default" for full access."""
        sc = self.of(request)
        if name:
            p = self.S.project(name) if isinstance(name, str) else None
            if not p:
                raise HTTPException(400, f"no project named {name}")
            if not sc.has(p["id"]):
                raise HTTPException(403, f"you can't add to project {name}")
            return p["id"]
        if sc.all:
            return self.S.default_project_id()
        if len(sc.ids) == 1:
            return next(iter(sc.ids))
        if not sc.ids:
            raise HTTPException(403, "you have no project you can add to")
        raise HTTPException(400, "choose a project: set project in the request body")
