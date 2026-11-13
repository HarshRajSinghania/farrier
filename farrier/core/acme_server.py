"""Farrier as an ACME server (RFC 8555): certbot, cert-manager, lego, acme.sh and win-acme get certificates
for internal names from a Farrier issuer, under Farrier's issuance policy, and every one lands in the log.

settings.json:
  "acme_server": {
    "internal": {"issuer": "default", "allowed_names": ["*.internal.example.com"],
                 "lifetime_days": 30, "project": "platform", "orders_per_hour": 100,
                 "base_url": "https://farrier.example.com"}
  }
Directory: <base_url or the request's origin>/acme/<profile>/directory.

Authorization is policy, not challenges (like AWS ACM's PRE_APPROVED endpoints): a name is authorized
when the profile's allowed_names, the EAB key's own patterns (if any) and the global issuance policy
(farrier.core.issuance_policy, for the profile's project) all allow it. Authorizations are created valid;
an order with any other name fails with rejectedIdentifier. Who may order at all is decided by External
Account Binding: every account needs an EAB key an admin created for that profile, and each key
registers one account. Deleting the key revokes the account.
"""
from __future__ import annotations

import json
import re
import secrets
from datetime import UTC, datetime, timedelta

from farrier.core.issuance_policy import name_allowed
from farrier.db.store import now_iso
from farrier.issuers.acme import b64u

PROFILE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
KEYS = {"issuer", "allowed_names", "lifetime_days", "project", "orders_per_hour", "base_url"}
NONCE_TTL = timedelta(hours=1)
ORDER_TTL = timedelta(days=7)
ORDERS_PER_HOUR = 100
DNS_NAME = re.compile(r"^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def validate(cfg) -> None:
    """Raise ValueError for a malformed "acme_server" block, at engine start rather than at request time."""
    if cfg is None:
        return
    if not isinstance(cfg, dict):
        raise ValueError('settings.json "acme_server" must be an object of profile name -> settings')
    for name, p in cfg.items():
        if not PROFILE.match(name):
            raise ValueError(f"acme_server profile {name!r}: lowercase letters, digits and dashes")
        if not isinstance(p, dict) or set(p) - KEYS:
            raise ValueError(f"acme_server {name!r}: an object with {', '.join(sorted(KEYS))} "
                             "(names are authorized by policy; challenge validation is not supported)")
        if not isinstance(p.get("issuer"), str) or not p["issuer"]:
            raise ValueError(f"acme_server {name!r}: \"issuer\" (an issuers.json name) is required")
        names = p.get("allowed_names")
        if not isinstance(names, list) or not names or not all(isinstance(n, str) and n for n in names):
            raise ValueError(f"acme_server {name!r}: \"allowed_names\" must be a non-empty list of name patterns")
        for k in ("lifetime_days", "orders_per_hour"):
            if k in p and (isinstance(p[k], bool) or not isinstance(p[k], int) or p[k] < 1):
                raise ValueError(f"acme_server {name!r}: {k} must be a positive whole number")
        for k in ("project", "base_url"):
            if k in p and not isinstance(p[k], str):
                raise ValueError(f"acme_server {name!r}: {k} must be a string")
        if p.get("base_url") and not re.match(r"^https?://[^/]+$", p["base_url"]):
            raise ValueError(f"acme_server {name!r}: base_url is an origin, e.g. https://farrier.example.com")


def _ts(delta: timedelta = timedelta()) -> str:
    return (datetime.now(UTC) + delta).isoformat(timespec="seconds")


def bad_identifier(name: str) -> bool:
    return len(name) > 253 or not DNS_NAME.match(name)


class AcmeServer:
    def __init__(self, engine):
        self.engine = engine
        self.store = engine.store

    def profile(self, name: str) -> dict | None:
        return (self.engine.settings.get("acme_server") or {}).get(name)

    # ---- EAB keys (admins) ------------------------------------------------------------------------
    def create_eab(self, profile: str, names: list[str] | None = None) -> dict:
        """A new EAB key for ``profile``, optionally limited to ``names`` patterns. The HMAC key is shown once."""
        if not self.profile(profile):
            raise ValueError(f"no acme_server profile {profile!r} in settings.json")
        names = names or []
        if not all(isinstance(n, str) and n for n in names):
            raise ValueError("names: a list of name patterns, e.g. *.web.internal.example.com")
        kid, key = "fae_" + secrets.token_urlsafe(12), b64u(secrets.token_bytes(32))
        self.store.x("INSERT INTO acme_eab(kid, profile, hmac, names, created_at) VALUES (?,?,?,?,?)",
                     (kid, profile, self.store.vault.seal(key), json.dumps(names), now_iso()))
        return {"profile": profile, "kid": kid, "hmac_key": key, "names": names}

    def eab_keys(self) -> list[dict]:
        rows = self.store.q("SELECT kid, profile, names, account_id, created_at FROM acme_eab ORDER BY created_at")
        return [r | {"names": json.loads(r["names"])} for r in rows]

    def delete_eab(self, kid: str) -> bool:
        """Delete a key; the account it registered stops working at once."""
        with self.store.transaction():
            gone = self.store._run("DELETE FROM acme_eab WHERE kid=?", (kid,))[1] > 0
            self.store.x("UPDATE acme_accounts SET status='revoked' WHERE eab_kid=?", (kid,))
        return gone

    def eab(self, kid: str) -> dict | None:
        row = self.store.q1("SELECT * FROM acme_eab WHERE kid=?", (kid,))
        return row and row | {"hmac": self.store.vault.open(row["hmac"]), "names": json.loads(row["names"])}

    # ---- nonces: one use each, any replica ----------------------------------------------------------
    def new_nonce(self) -> str:
        n = secrets.token_urlsafe(16)
        self.store.x("INSERT INTO acme_nonces(nonce, expires) VALUES (?,?)", (n, _ts(NONCE_TTL)))
        if secrets.randbelow(50) == 0:
            self.store.x("DELETE FROM acme_nonces WHERE expires < ?", (_ts(),))
        return n

    def use_nonce(self, nonce) -> bool:
        if not isinstance(nonce, str) or not nonce:
            return False
        return self.store._run("DELETE FROM acme_nonces WHERE nonce=? AND expires > ?", (nonce, _ts()))[1] == 1

    # ---- accounts and orders ------------------------------------------------------------------------
    def account(self, profile: str, aid: int) -> dict | None:
        return self.store.q1("SELECT * FROM acme_accounts WHERE id=? AND profile=?", (aid, profile))

    def account_by_key(self, profile: str, thumb: str) -> dict | None:
        return self.store.q1("SELECT * FROM acme_accounts WHERE profile=? AND thumbprint=?", (profile, thumb))

    def create_account(self, profile: str, jwk: dict, thumb: str, kid: str, contact: list) -> int | None:
        """Register an account bound to EAB key ``kid``; None when that key already registered one."""
        try:
            with self.store.transaction():
                aid = self.store.x("INSERT INTO acme_accounts(profile, thumbprint, jwk, eab_kid, status, contact, "
                                   "created_at) VALUES (?,?,?,?,?,?,?)", (profile, thumb, json.dumps(jwk), kid, "valid",
                                                                          json.dumps(contact), now_iso()))
                if not self.store._run("UPDATE acme_eab SET account_id=? WHERE kid=? AND profile=? AND "
                                       "account_id IS NULL", (aid, kid, profile))[1]:
                    raise _Taken    # rolls the account back
        except _Taken:
            return None
        return aid

    def unauthorized_names(self, profile: str, account: dict, names: list[str]) -> list[str]:
        """Names that the profile, the account's EAB key or the global issuance policy does not allow."""
        from farrier.core.issuance_policy import rules_for
        p = self.profile(profile)
        eab = self.store.q1("SELECT names FROM acme_eab WHERE kid=?", (account["eab_kid"],))
        own = json.loads(eab["names"]) if eab else []
        rules = rules_for(self.engine.settings.get("policy"), p.get("project")) or {}
        return [n for n in names if not name_allowed(n, p["allowed_names"]) or (own and not name_allowed(n, own))
                or (rules.get("allowed_names") is not None and not name_allowed(n, rules["allowed_names"]))]

    def orders_last_hour(self, aid: int) -> int:
        return self.store.q1("SELECT COUNT(*) AS n FROM acme_orders WHERE account_id=? AND created_at > ?",
                             (aid, _ts(-timedelta(hours=1))))["n"]

    def create_order(self, profile: str, aid: int, names: list[str]) -> int:
        return self.store.x("INSERT INTO acme_orders(account_id, profile, identifiers, status, expires, created_at) "
                            "VALUES (?,?,?,?,?,?)", (aid, profile, json.dumps(names), "ready", _ts(ORDER_TTL), now_iso()))

    def order(self, profile: str, oid: int) -> dict | None:
        row = self.store.q1("SELECT * FROM acme_orders WHERE id=? AND profile=?", (oid, profile))
        if row:
            row["identifiers"] = json.loads(row["identifiers"])
            if row["status"] in ("ready", "pending") and row["expires"] < _ts():
                row["status"] = "invalid"
        return row

    def certificates(self) -> list[dict]:
        """Every certificate the ACME server issued: the inventory of otherwise unmanaged ACME clients."""
        rows = self.store.q("SELECT o.id, o.profile, o.issuer, o.identifiers, o.fingerprint, o.not_after, o.revoked_at, "
                            "o.created_at, o.account_id, a.eab_kid FROM acme_orders o JOIN acme_accounts a "
                            "ON a.id = o.account_id WHERE o.fingerprint IS NOT NULL ORDER BY o.id")
        return [r | {"identifiers": json.loads(r["identifiers"])} for r in rows]


class _Taken(Exception):
    """The EAB key was used by another account (raised inside the transaction to roll it back)."""
