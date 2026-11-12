"""HTTP for cloud APIs: one shared client, a timeout on every call, bounded retries, errors without secrets.

Every adapter in farrier.cloud_auth, farrier.secret_backends, farrier.storage and farrier.publishers goes
through ``request``. Errors name the operation, the host and path (never the query string) and the
provider's error code/message, never a request body, header or token.
"""
from __future__ import annotations

import json
import threading
import time
from urllib.parse import urlsplit

import httpx

TIMEOUT = httpx.Timeout(10.0, connect=5.0)
USER_AGENT = "farrier/1"
RETRY_STATUS = {429, 500, 502, 503, 504}
MAX_RETRIES = 3

_client: httpx.Client | None = None
_override: httpx.Client | None = None
_lock = threading.Lock()
sleep = time.sleep     # replaced in tests


class CloudError(RuntimeError):
    """A cloud call failed. ``code`` is the provider's error code when it gave one."""

    def __init__(self, message: str, status: int | None = None, code: str | None = None):
        super().__init__(message)
        self.status = status
        self.code = code


class CloudConfigError(CloudError, ValueError):
    """A setting is missing or invalid. The message names the setting to fix."""


def client() -> httpx.Client:
    """The process-wide client (or the one a test installed with ``set_client``)."""
    global _client
    if _override is not None:
        return _override
    with _lock:
        if _client is None:
            _client = httpx.Client(timeout=TIMEOUT, headers={"User-Agent": USER_AGENT})
        return _client


def client_with_ca(cafile: str | None) -> httpx.Client:
    """A client that trusts a private CA (HashiCorp Vault behind an internal PKI)."""
    if _override is not None or not cafile:
        return client()
    import ssl
    ctx = ssl.create_default_context(cafile=cafile)
    return httpx.Client(timeout=TIMEOUT, headers={"User-Agent": USER_AGENT}, verify=ctx)


def set_client(c: httpx.Client | None) -> None:
    """Route every cloud call through ``c`` (tests: an httpx.MockTransport). None restores the default."""
    global _override
    _override = c


def _detail(r: httpx.Response) -> tuple[str, str | None]:
    """(short message, error code) from a provider error body: JSON error fields only, else a snippet."""
    try:
        j = r.json()
    except ValueError:
        text = " ".join(r.text.split())[:200]
        return text, None
    if not isinstance(j, dict):
        return "", None
    code = j.get("__type") or j.get("code") or j.get("Code")
    err = j.get("error")
    msg = j.get("message") or j.get("Message") or j.get("error_description") or ""
    if isinstance(err, dict):
        code = code or err.get("code") or err.get("status")
        msg = msg or err.get("message") or ""
    elif isinstance(err, str):
        code = code or err
    if isinstance(j.get("errors"), list):           # HashiCorp Vault
        msg = msg or "; ".join(str(e) for e in j["errors"])
    if isinstance(code, str) and "#" in code:        # com.amazonaws...#ResourceNotFoundException
        code = code.rsplit("#", 1)[1]
    return " ".join(str(msg).split())[:200], (str(code) if code else None)


def request(method: str, url: str, *, what: str, http: httpx.Client | None = None, ok=(200, 201, 202, 204),
            allow=(), retries: int = MAX_RETRIES, **kw) -> httpx.Response:
    """One cloud call with a timeout and up to ``retries`` attempts on transport errors, 429 and 5xx.

    Statuses in ``ok`` or ``allow`` are returned; anything else raises CloudError (with the provider's
    error code, so callers can branch on e.g. ResourceNotFoundException)."""
    c = http or client()
    parts = urlsplit(url)
    where = f"{parts.netloc}{parts.path}"
    kw.setdefault("timeout", TIMEOUT)
    for attempt in range(retries):
        last = attempt == retries - 1
        try:
            r = c.request(method, url, **kw)
        except httpx.HTTPError as e:
            if not last:
                sleep(min(0.5 * 2 ** attempt, 5))
                continue
            raise CloudError(f"{what}: {method} {where} failed: {type(e).__name__}") from None
        if r.status_code in RETRY_STATUS and not last:
            try:
                wait = float(r.headers.get("Retry-After", ""))
            except ValueError:
                wait = 0.5 * 2 ** attempt
            sleep(max(0.0, min(wait, 10)))
            continue
        if r.status_code in ok or r.status_code in allow:
            return r
        msg, code = _detail(r)
        raise CloudError(f"{what}: {method} {where} -> HTTP {r.status_code}"
                         + (f" {code}" if code else "") + (f": {msg}" if msg else ""), r.status_code, code)
    raise AssertionError("unreachable")


def json_body(r: httpx.Response, what: str) -> dict:
    try:
        j = r.json()
    except (ValueError, json.JSONDecodeError):
        raise CloudError(f"{what}: the response was not JSON") from None
    if not isinstance(j, dict):
        raise CloudError(f"{what}: unexpected response")
    return j


class TokenCache:
    """A value with an expiry, refreshed ``margin`` seconds early, safe across threads."""

    def __init__(self, margin: float = 300):
        self.margin = margin
        self._items: dict = {}
        self._lock = threading.Lock()

    def get(self, key, fetch):
        """``fetch() -> (value, expires_at_epoch | None)``; None = never expires."""
        with self._lock:
            hit = self._items.get(key)
            if hit and (hit[1] is None or hit[1] - self.margin > time.time()):
                return hit[0]
            value, expires = fetch()
            self._items[key] = (value, expires)
            return value

    def clear(self) -> None:
        with self._lock:
            self._items.clear()
