"""Named DNS accounts (<data_dir>/dns.json), zone routing, CNAME delegation and the per-order solver.

dns.json:
{
  "cf-prod":    {"provider": "cloudflare", "credentials": {"api_token": "env:FARRIER_SECRET_CF_PROD"},
                 "zones": ["example.com"]},
  "aws-shared": {"provider": "route53",
                 "credentials": {"access_key_id": "env:FARRIER_SECRET_AWS_ID", "secret_access_key": "env:FARRIER_SECRET_AWS_KEY"},
                 "options": {"role_arn": "arn:aws:iam::123456789012:role/dns01"}, "zones": ["corp.example.net"]},
  "aliases":    {"_acme-challenge.legacy.example.org": "legacy.acme.example.com"},
  "follow_cname": true
}

Every credential is a reference (env:NAME / file:/path), checked against vault.check_secret_ref at load
and resolved only when a request is made. Inline values are refused.

Account selection for a challenge name:
  1. an explicit account (issuer "dns": "<name>" or endpoint "dns_account": "<name>"), else
  2. "auto": the account whose zones contain the name most specifically (longest suffix, label-wise).
     Two accounts claiming the same most-specific zone is an error, never a silent pick.
CNAME delegation: if `_acme-challenge.<name>` is listed in "aliases", or (follow_cname, default on) is a
CNAME in DNS, the TXT goes to the target and the account is chosen by the *target's* zone. Delegating
providers (acme-dns) receive the original name and handle the hop themselves.
"""
from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path

import httpx

from ..vault import SecretRefused, check_secret_ref
from .base import DnsConfigError, DnsError, Provider, in_zone, norm
from .providers import ALTERNATIVES, canonical, provider_class

log = logging.getLogger("farrier.dns")

ACCOUNT_KEYS = {"provider", "credentials", "zones", "options", "propagation_check", "propagation_timeout",
                "propagation_seconds", "description"}
COMMON_OPTIONS = {"ttl", "verify_tls"}
RESERVED = {"aliases", "follow_cname", "resolvers"}
SECRETISH = re.compile(r"pass(word|phrase)?|secret|token|api[_-]?key|hmac|private[_-]?key|credential", re.IGNORECASE)
ACCOUNT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _is_ref(v) -> bool:
    return isinstance(v, str) and (v.startswith("env:") and len(v) > 4 or v.startswith("file:") and len(v) > 5)


def _check_ref(account: str, where: str, v) -> None:
    try:
        check_secret_ref(v)
    except SecretRefused as e:
        raise DnsConfigError(f"dns account {account!r}: {where}: {e}") from None


def validate_account(name: str, cfg) -> dict:
    """Normalise one dns.json entry; raise DnsConfigError with a precise message on any problem."""
    if not ACCOUNT_NAME.match(str(name)):
        raise DnsConfigError(f"dns account name {name!r} must be 1-64 of A-Z a-z 0-9 . _ -")
    if not isinstance(cfg, dict):
        raise DnsConfigError(f"dns account {name!r} must be an object")
    unknown = set(cfg) - ACCOUNT_KEYS
    if unknown:
        raise DnsConfigError(f"dns account {name!r}: unknown keys {sorted(unknown)} "
                             "(provider settings go under \"options\", secrets under \"credentials\")")
    if "provider" not in cfg:
        raise DnsConfigError(f"dns account {name!r}: \"provider\" is required")
    provider = canonical(cfg["provider"])
    cls = provider_class(provider)
    creds = cfg.get("credentials") or {}
    if not isinstance(creds, dict):
        raise DnsConfigError(f"dns account {name!r}: credentials must be an object")
    for k, v in creds.items():
        if not _is_ref(v):
            raise DnsConfigError(
                f"dns account {name!r}: credentials.{k} must be a reference (\"env:NAME\" or \"file:/path\"); "
                "inline secrets are refused so they never land in config files, backups or the API")
        _check_ref(name, f"credentials.{k}", v)
    if provider != "script":
        allowed = set(cls.required) | set(cls.optional)
        extra = set(creds) - allowed
        if extra:
            raise DnsConfigError(f"dns account {name!r}: unknown credentials {sorted(extra)} for {provider} "
                                 f"(expected {sorted(allowed)})")
        alts = ALTERNATIVES.get(provider)
        if alts:
            if not any(all(k in creds for k in alt) for alt in alts):
                raise DnsConfigError(f"dns account {name!r}: {provider} needs credentials "
                                     + " or ".join("+".join(a) for a in alts))
        else:
            missing = [k for k in cls.required if k not in creds]
            if missing:
                raise DnsConfigError(f"dns account {name!r}: {provider} needs credentials {missing}")
    opts = cfg.get("options") or {}
    if not isinstance(opts, dict):
        raise DnsConfigError(f"dns account {name!r}: options must be an object")
    known = set(cls.options_known) | COMMON_OPTIONS
    for k, v in opts.items():
        if SECRETISH.search(k) and not _is_ref(v) and k not in ("tsig_key",):
            raise DnsConfigError(f"dns account {name!r}: options.{k} looks like a secret; put it under credentials "
                                 "as an env:/file: reference")
        if k not in known:
            raise DnsConfigError(f"dns account {name!r}: unknown option {k!r} for {provider} (known: {sorted(known)})")
        if _is_ref(v):
            _check_ref(name, f"options.{k}", v)
    zones = cfg.get("zones") or []
    if not isinstance(zones, list) or not all(isinstance(z, str) and z.strip() for z in zones):
        raise DnsConfigError(f"dns account {name!r}: zones must be a list of domain names")
    return {"provider": provider, "credentials": dict(creds), "options": dict(opts),
            "zones": [norm(z) for z in zones],
            "propagation_check": bool(cfg.get("propagation_check", True)),
            "propagation_timeout": float(cfg.get("propagation_timeout", 300)),
            "propagation_seconds": float(cfg.get("propagation_seconds", 0))}


class DnsAccounts:
    def __init__(self, providers: dict[str, Provider], settings: dict[str, dict], aliases: dict[str, str] | None = None,
                 follow_cname: bool = True, resolver=None):
        self.providers = providers
        self.settings = settings
        self.aliases = {norm(k): norm(v) for k, v in (aliases or {}).items()}
        self.follow_cname = follow_cname
        self._resolver = resolver
        self._discovered: dict[str, list[str]] = {}

    # ---- loading -------------------------------------------------------------------------------------------
    @classmethod
    def from_config(cls, cfg: dict, http: httpx.Client | None = None, resolver=None) -> DnsAccounts:
        if not isinstance(cfg, dict):
            raise DnsConfigError("dns.json must be an object of named accounts")
        aliases = cfg.get("aliases") or {}
        if not isinstance(aliases, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in aliases.items()):
            raise DnsConfigError("dns.json aliases must map challenge names to target names")
        if resolver is None and cfg.get("resolvers"):
            from .resolver import Resolver
            resolver = Resolver(nameservers=list(cfg["resolvers"]), http=http)
        providers, settings = {}, {}
        for name, raw in cfg.items():
            if name in RESERVED:
                continue
            acc = validate_account(name, raw)
            providers[name] = provider_class(acc["provider"])(name, acc["credentials"], acc["options"], acc["zones"],
                                                              http=http, resolver=resolver)
            settings[name] = acc
        return cls(providers, settings, aliases, bool(cfg.get("follow_cname", True)), resolver)

    @classmethod
    def load(cls, data_dir: Path, **kw) -> DnsAccounts:
        path = Path(data_dir) / "dns.json"
        if not path.exists():
            return cls({}, {}, resolver=kw.get("resolver"))
        try:
            cfg = json.loads(path.read_text())
        except ValueError as e:
            raise DnsConfigError(f"dns.json is not valid JSON: {e}") from None
        return cls.from_config(cfg, **kw)

    @property
    def resolver(self):
        if self._resolver is None:
            from .resolver import Resolver
            self._resolver = Resolver()
        return self._resolver

    # ---- routing ---------------------------------------------------------------------------------------------
    def get(self, name: str) -> Provider:
        if name not in self.providers:
            raise DnsConfigError(f"no DNS account named {name!r} in dns.json")
        return self.providers[name]

    def _zones_of(self, name: str) -> list[str]:
        p = self.providers[name]
        if p.zones:
            return p.zones
        if name not in self._discovered:
            try:
                self._discovered[name] = [z.name for z in p.list_zones()]
            except NotImplementedError:
                self._discovered[name] = []
            except DnsError as e:
                log.warning("dns account %r: zone discovery failed: %s", name, e)
                return []
        return self._discovered[name]

    def match(self, fqdn: str) -> Provider | None:
        fqdn = norm(fqdn)
        best, best_len, tied = None, -1, []
        for name in self.providers:
            for z in self._zones_of(name):
                if in_zone(fqdn, z):
                    if len(z) > best_len:
                        best, best_len, tied = name, len(z), [name]
                    elif len(z) == best_len and name not in tied:
                        tied.append(name)
        if len(tied) > 1:
            raise DnsConfigError(f"{fqdn} matches the same zone in several dns accounts ({', '.join(tied)}); "
                                 "set \"dns_account\" explicitly")
        return self.providers[best] if best else None

    def alias_of(self, fqdn: str) -> str | None:
        fqdn = norm(fqdn)
        if fqdn in self.aliases:
            return self.aliases[fqdn]
        if not self.follow_cname:
            return None
        target, seen = None, {fqdn}
        name = fqdn
        for _ in range(5):
            try:
                nxt = self.resolver.cname(name)
            except DnsError as e:
                log.warning("dns: CNAME lookup for %r failed (%s); using the name as is", name, e)
                break
            if not nxt or nxt in seen:
                break
            seen.add(nxt)
            target = name = nxt
        return target

    def route(self, fqdn: str, account: str | None = "auto") -> tuple[Provider, str]:
        """(provider, name to write the TXT at) for one challenge name."""
        fqdn = norm(fqdn)
        if account and account != "auto":
            p = self.get(account)
            if p.delegating:
                return p, fqdn
            return p, self.alias_of(fqdn) or fqdn
        original = self.match(fqdn)
        if original is not None and original.delegating:
            return original, fqdn
        target = self.alias_of(fqdn)
        if target:
            p = self.match(target)
            if p is None:
                raise DnsConfigError(f"{fqdn} is delegated to {target}, but no dns account covers that zone")
            return p, target
        if original is None:
            raise DnsConfigError(f"no dns account covers {fqdn}; add its zone to an account in dns.json")
        return original, fqdn

    def solver(self, account: str | None = "auto", sleep=time.sleep) -> DnsSolver:
        return DnsSolver(self, account, sleep=sleep)


class DnsSolver:
    """Tracks the TXT records of one ACME order: present, wait until visible, always clean up."""

    def __init__(self, accounts: DnsAccounts, account: str | None = "auto", sleep=time.sleep, interval: float = 5):
        self.accounts, self.account = accounts, account or "auto"
        self.sleep, self.interval = sleep, interval
        self.extra_seconds = 0.0  # fixed wait after the check (issuer-level propagation_seconds)
        self.records: list[tuple[str, Provider, str, str]] = []  # (account, provider, target, value)

    def present(self, name: str, value: str) -> None:
        provider, target = self.accounts.route(name, self.account)
        # recorded before the call: a provider that fails half-way (record created, then an error) still
        # gets a cleanup attempt; cleanup of a value that is not there is a no-op
        self.records.append((provider.account, provider, target, value))
        log.info("dns-01: present %s via %s", target, provider.label)
        provider.present(target, value)

    def wait(self) -> None:
        checks: dict[str, set[str]] = {}
        timeout, extra = 0.0, float(self.extra_seconds or 0)
        for acct, provider, target, value in self.records:
            s = self.accounts.settings.get(acct, {})
            extra = max(extra, s.get("propagation_seconds", 0))
            if s.get("propagation_check", True):
                checks.setdefault(target, set()).add(value)
                timeout = max(timeout, s.get("propagation_timeout", 300))
        if checks:
            self.accounts.resolver.wait_for(checks, timeout=timeout, interval=self.interval, sleep=self.sleep)
        if extra:
            self.sleep(extra)

    def cleanup(self) -> list[str]:
        """Remove every presented value. Never raises: returns the (secret-free) errors instead."""
        errors = []
        for acct, provider, target, value in reversed(self.records):
            try:
                provider.cleanup(target, value)
            except Exception as e:  # noqa: BLE001 - cleanup must not mask the real outcome
                msg = provider.redact(str(e)) if isinstance(e, DnsError) else f"{type(e).__name__}"
                log.warning("dns-01: cleanup of %s via %s failed: %s", target, provider.label, msg)
                errors.append(f"{target}: {msg}")
        self.records.clear()
        return errors
