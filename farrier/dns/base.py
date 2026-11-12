"""DNS-01 provider interface.

A provider is one *account* at one DNS host. It publishes and removes TXT values:

    present(fqdn, value)   ADD `value` to the TXT RRset at fqdn (never replaces other values:
                           example.com and *.example.com share `_acme-challenge.example.com`)
    cleanup(fqdn, value)   remove exactly `value`; other values (a parallel order, a wildcard) stay

Credentials are references ("env:NAME" / "file:/path") resolved through farrier.vault.resolve_secret
at the moment of use, never at load time, never cached on disk, never logged, never put in exceptions
(errors are built from method + path + status only, with every resolved secret redacted).
"""
from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from ..vault import REF_PREFIXES, SecretRefused, resolve_secret

log = logging.getLogger("farrier.dns")
USER_AGENT = "farrier-dns/0.1"


class DnsError(Exception):
    """A DNS provider or lookup failed. Messages never contain credentials."""


class DnsConfigError(DnsError, ValueError):
    """dns.json or a provider account is misconfigured."""


class DnsPropagationError(DnsError):
    """TXT records did not become visible on the authoritative nameservers in time."""


def norm(name: str) -> str:
    return name.strip().rstrip(".").lower()


def in_zone(fqdn: str, zone: str) -> bool:
    fqdn, zone = norm(fqdn), norm(zone)
    return fqdn == zone or fqdn.endswith("." + zone)


def relative(fqdn: str, zone: str) -> str:
    """Name relative to the zone; "" for the apex."""
    fqdn, zone = norm(fqdn), norm(zone)
    if fqdn == zone:
        return ""
    if not fqdn.endswith("." + zone):
        raise DnsError(f"{fqdn} is not inside zone {zone}")
    return fqdn[: -len(zone) - 1]


def longest_zone(fqdn: str, zones) -> str | None:
    """Most specific zone that contains fqdn (label-wise suffix match, never a substring match)."""
    best = None
    for z in zones:
        z = norm(z)
        if in_zone(fqdn, z) and (best is None or len(z) > len(best)):
            best = z
    return best


def unquote_txt(v: str) -> str:
    """'"abc"' -> 'abc'; '"ab" "c"' -> 'abc' (APIs return presentation format inconsistently)."""
    v = v.strip()
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        parts, cur, inq, i = [], [], False, 0
        while i < len(v):
            ch = v[i]
            if ch == "\\" and i + 1 < len(v):
                cur.append(v[i + 1])
                i += 2
                continue
            if ch == '"':
                if inq:
                    parts.append("".join(cur))
                    cur = []
                inq = not inq
            elif inq:
                cur.append(ch)
            i += 1
        return "".join(parts)
    return v


def quote_txt(v: str) -> str:
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'


@dataclass(frozen=True)
class Zone:
    name: str
    id: str | None = None


class Provider:
    """Base class. Subclasses set `name`, `required` (credential keys) and implement present/cleanup."""

    name = ""
    required: tuple[str, ...] = ()       # credential keys that must be configured
    optional: tuple[str, ...] = ()       # credential keys that may be configured
    options_known: tuple[str, ...] = ()  # non-secret option keys (validated at load)
    default_ttl = 60
    # True when the provider takes the *original* challenge name and handles delegation itself (acme-dns)
    delegating = False
    # False for providers whose API cannot remove a value (they reset it instead)
    supports_delete = True

    def __init__(self, account: str, credentials: dict | None = None, options: dict | None = None,
                 zones=(), http: httpx.Client | None = None, resolver=None):
        self.account = account
        self._refs = dict(credentials or {})
        self.opts = dict(options or {})
        self.zones = [norm(z) for z in zones]
        self._http = http
        self._resolver = resolver
        self._zone_cache: dict[str, Zone] = {}
        self._zone_list: list[Zone] | None = None
        self._locks: dict[str, threading.Lock] = defaultdict(threading.Lock)
        self._locks_guard = threading.Lock()
        self._redact: set[str] = set()
        self._ttls: dict[str, int] = {}     # live TTL per name (APIs whose delete must match exactly)
        self._etags: dict[str, str] = {}    # ETag per name (optimistic concurrency)
        self.sleep = time.sleep
        self.ttl = int(self.opts.get("ttl", self.default_ttl))

    # ---- identity / config --------------------------------------------------
    @property
    def label(self) -> str:
        return f"{self.name}[{self.account}]"

    def secret(self, key: str, default=None) -> str:
        """Resolve a credential reference now. Errors name the field, never the value."""
        ref = self._refs.get(key)
        if ref is None:
            if default is not None:
                return default
            raise DnsConfigError(f"dns account {self.account!r}: credential {key!r} is not configured")
        try:
            val = resolve_secret(ref)
        except SecretRefused as e:
            raise DnsConfigError(f"dns account {self.account!r}: credential {key!r} refused: {e}") from None
        except KeyError as e:
            raise DnsConfigError(f"dns account {self.account!r}: credential {key!r}: {e.args[0]}") from None
        except OSError as e:
            raise DnsConfigError(f"dns account {self.account!r}: credential {key!r}: cannot read the referenced "
                                 f"file ({type(e).__name__})") from None
        if not isinstance(val, str) or not val:
            raise DnsConfigError(f"dns account {self.account!r}: credential {key!r} is empty")
        if len(val) >= 4:
            self._redact.add(val)
        return val

    def has_secret(self, key: str) -> bool:
        return key in self._refs

    def opt(self, key: str, default=None):
        v = self.opts.get(key, default)
        if isinstance(v, str) and v.startswith(REF_PREFIXES):
            return resolve_secret(v)
        return v

    def redact(self, text: str) -> str:
        for s in sorted(self._redact, key=len, reverse=True):
            text = text.replace(s, "***")
        return text

    def lock(self, key: str) -> threading.Lock:
        with self._locks_guard:
            return self._locks[norm(key)]

    @property
    def resolver(self):
        if self._resolver is None:
            from .resolver import Resolver
            self._resolver = Resolver(http=self._http)
        return self._resolver

    # ---- HTTP ---------------------------------------------------------------
    @property
    def http(self) -> httpx.Client:
        if self._http is None:
            verify = self.opts.get("verify_tls", True)
            self._http = httpx.Client(timeout=30, headers={"User-Agent": USER_AGENT}, verify=verify)
        return self._http

    def request(self, method: str, url: str, *, ok=(200, 201, 202, 204), allow=(), retries: int = 3,
                **kw) -> httpx.Response:
        """HTTP call with retry on 429/5xx/transport errors. The raised error contains the method, the URL
        path (never the query string, which some APIs use for credentials) and the redacted response."""
        path = urlsplit(url).path
        for attempt in range(retries):
            last = attempt == retries - 1
            try:
                r = self.http.request(method, url, **kw)
            except httpx.HTTPError as e:
                if not last:
                    self.sleep(min(2 ** attempt, 10))
                    continue
                raise DnsError(f"{self.label}: {method} {path} failed: {type(e).__name__}") from None
            if (r.status_code == 429 or r.status_code >= 500) and not last:
                try:
                    wait = float(r.headers.get("Retry-After", ""))
                except ValueError:
                    wait = 2 ** attempt
                self.sleep(max(0.0, min(wait, 30)))
                continue
            if r.status_code in ok or r.status_code in allow:
                return r
            body = r.text[:300].replace("\n", " ")
            raise DnsError(f"{self.label}: {method} {path} -> HTTP {r.status_code}: {self.redact(body)}")
        raise AssertionError("unreachable")

    # ---- zones ----------------------------------------------------------------
    def list_zones(self) -> list[Zone]:
        """Zones this account can edit. Providers whose API lists zones override this."""
        raise NotImplementedError

    def zone_id(self, name: str) -> str | None:
        """Provider zone id for a zone name, for APIs that need one. Default: look it up in list_zones."""
        return None

    def _zone_id_from_list(self, name: str) -> str:
        for z in self._listed_zones():
            if z.name == norm(name):
                return z.id or z.name
        raise DnsError(f"{self.label}: zone {name} not found in this account")

    def _listed_zones(self) -> list[Zone]:
        if self._zone_list is None:
            self._zone_list = self.list_zones()
        return self._zone_list

    def find_zone(self, fqdn: str) -> Zone:
        """Zone containing fqdn: configured zones first, then the provider's zone list, then the SOA in DNS."""
        fqdn = norm(fqdn)
        if fqdn in self._zone_cache:
            return self._zone_cache[fqdn]
        z = longest_zone(fqdn, self.zones)
        if z:
            zone = Zone(z, self.zone_id(z))
        else:
            try:
                listed = self._listed_zones()
            except NotImplementedError:
                listed = None
            if listed is not None:
                best = longest_zone(fqdn, [x.name for x in listed])
                if best is None:
                    raise DnsError(f"{self.label}: no zone in this account contains {fqdn}")
                zone = next(x for x in listed if x.name == best)
            else:
                name = self.resolver.find_zone(fqdn)
                zone = Zone(name, self.zone_id(name))
        self._zone_cache[fqdn] = zone
        return zone

    # ---- interface ----------------------------------------------------------------
    def present(self, fqdn: str, value: str) -> None:
        raise NotImplementedError

    def cleanup(self, fqdn: str, value: str) -> None:
        raise NotImplementedError

    def close(self):
        pass


class RecordProvider(Provider):
    """APIs where each TXT value is its own record with an id (Cloudflare, DigitalOcean, Linode...)."""

    def _records(self, zone: Zone, fqdn: str) -> list[tuple[str, str]]:
        """[(record_id, unquoted value)] of TXT records at exactly fqdn."""
        raise NotImplementedError

    def _create(self, zone: Zone, fqdn: str, value: str) -> None:
        raise NotImplementedError

    def _delete(self, zone: Zone, fqdn: str, record_id: str) -> None:
        raise NotImplementedError

    def present(self, fqdn: str, value: str) -> None:
        zone = self.find_zone(fqdn)
        with self.lock(fqdn):
            if any(v == value for _, v in self._records(zone, norm(fqdn))):
                return
            self._create(zone, norm(fqdn), value)

    def cleanup(self, fqdn: str, value: str) -> None:
        zone = self.find_zone(fqdn)
        with self.lock(fqdn):
            for rid, v in self._records(zone, norm(fqdn)):
                if v == value:
                    self._delete(zone, norm(fqdn), rid)


class RRsetProvider(Provider):
    """APIs that treat all TXT values on a name as one set (Route 53, Azure, Google, PowerDNS, Gandi...).
    present/cleanup are read-modify-write under a per-name lock; other values are preserved."""

    def _get(self, zone: Zone, fqdn: str) -> list[str]:
        """Current unquoted TXT values at fqdn ([] if none)."""
        raise NotImplementedError

    def _put(self, zone: Zone, fqdn: str, values: list[str], current: list[str]) -> None:
        raise NotImplementedError

    def _remove(self, zone: Zone, fqdn: str, current: list[str]) -> None:
        raise NotImplementedError

    def present(self, fqdn: str, value: str) -> None:
        zone = self.find_zone(fqdn)
        with self.lock(fqdn):
            cur = self._get(zone, norm(fqdn))
            if value in cur:
                return
            self._put(zone, norm(fqdn), cur + [value], cur)

    def cleanup(self, fqdn: str, value: str) -> None:
        zone = self.find_zone(fqdn)
        with self.lock(fqdn):
            cur = self._get(zone, norm(fqdn))
            if value not in cur:
                return
            rest = [v for v in cur if v != value]
            if rest:
                self._put(zone, norm(fqdn), rest, cur)
            else:
                self._remove(zone, norm(fqdn), cur)
