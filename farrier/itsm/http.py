"""The one HTTP client every ITSM / observability adapter uses: httpx, timeouts, bounded retries.

Retries: at most ``attempts`` tries. 429 and 503 (the request was not processed) are retried for every
method; 502/504 and transport errors only for idempotent requests (GET, PUT, DELETE) or when the caller
says the request is safe to repeat (``idempotent=True``: it carries its own idempotency key). Backoff is
exponential with full jitter; a Retry-After header (seconds or an HTTP date) is honoured, and one longer
than ``max_wait`` ends the retries rather than stalling a renewal.

Errors are raised as ItsmError, whose text names the method, host and path and the status code (plus the
vendor's short error message), never a query string, a request body or a credential: known secret values
are scrubbed from it as well.
"""
from __future__ import annotations

import email.utils
import random
import time
from datetime import UTC, datetime

import httpx

RETRY_ALWAYS = {429, 503}
RETRY_IDEMPOTENT = {502, 504}
IDEMPOTENT_METHODS = {"GET", "HEAD", "PUT", "DELETE", "OPTIONS"}
TIMEOUT = httpx.Timeout(15.0, connect=5.0)

# Test hooks: a transport (httpx.MockTransport) every new client uses, and the sleep function.
transport_override: httpx.BaseTransport | None = None
SLEEP = time.sleep


class ItsmError(Exception):
    """A failure safe to show and log: no URL query, body or credential."""

    def __init__(self, message: str, status: int | None = None, retry_after: float | None = None):
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


def retry_after_seconds(value: str | None) -> float | None:
    if not value:
        return None
    value = value.strip()
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return max(0.0, (when - datetime.now(UTC)).total_seconds())


def _vendor_message(r: httpx.Response) -> str:
    """The vendor's own short error text (ServiceNow error.message, Jira errorMessages/errors, Datadog
    errors, Splunk text), if the body is JSON."""
    try:
        j = r.json()
    except ValueError:
        return ""
    if not isinstance(j, dict):
        return ""
    parts: list[str] = []
    err = j.get("error")
    if isinstance(err, dict):
        parts += [str(err.get("message") or ""), str(err.get("detail") or "")]
    elif isinstance(err, str):
        parts.append(err)
    for k in ("errorMessages", "errors"):
        v = j.get(k)
        if isinstance(v, list):
            parts += [str(x) for x in v[:3]]
        elif isinstance(v, dict):
            parts += [f"{a}: {b}" for a, b in list(v.items())[:3]]
    if j.get("text") and j.get("code") not in (None, 0):
        parts.append(str(j["text"]))
    return "; ".join(p for p in parts if p)[:300]


class Http:
    """A small client bound to one base URL with fixed auth headers (built per adapter)."""

    def __init__(self, base_url: str, headers: dict | None = None, *, verify=True, secrets=(),
                 attempts: int = 4, max_wait: float = 60.0, timeout=TIMEOUT, transport=None,
                 auth_refresh=None):
        self.base_url = base_url.rstrip("/")
        self.headers = dict(headers or {})
        self.attempts = max(1, attempts)
        self.max_wait = max_wait
        self._secrets = [s for s in secrets if s and len(s) >= 4]
        self.auth_refresh = auth_refresh      # callable() -> headers, for OAuth tokens (called on 401 once)
        self.client = httpx.Client(timeout=timeout, verify=verify,
                                   transport=transport or transport_override, follow_redirects=False)

    def redact(self, text: str) -> str:
        for s in self._secrets:
            text = text.replace(s, "***")
        return text

    def close(self) -> None:
        self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def url(self, path: str) -> str:
        return path if path.startswith(("https://", "http://")) else f"{self.base_url}{path}"

    def request(self, method: str, path: str, *, idempotent: bool | None = None, expect=(200, 201, 202, 204),
                **kw) -> httpx.Response:
        method = method.upper()
        safe = method in IDEMPOTENT_METHODS if idempotent is None else idempotent
        url = self.url(path)
        where = f"{method} {httpx.URL(url).host}{httpx.URL(url).path}"
        extra_headers = kw.pop("headers", None) or {}
        refreshed = False
        last: ItsmError | None = None
        for attempt in range(1, self.attempts + 1):
            wait = None
            try:
                r = self.client.request(method, url, headers={**self.headers, **extra_headers}, **kw)
            except httpx.TransportError as e:
                last = ItsmError(f"{where}: {type(e).__name__}")
                if not safe and not isinstance(e, httpx.ConnectError):
                    raise last from None          # the request may have arrived: never repeat a create
            else:
                if r.status_code == 401 and self.auth_refresh and not refreshed:
                    refreshed = True
                    self.headers.update(self.auth_refresh())
                    continue
                if r.status_code in expect:
                    return r
                msg = _vendor_message(r)
                ra = retry_after_seconds(r.headers.get("Retry-After"))
                if r.status_code == 429 and ra is None:     # Datadog/Jira style reset headers
                    ra = retry_after_seconds(r.headers.get("X-RateLimit-Reset"))
                last = ItsmError(self.redact(f"{where}: HTTP {r.status_code}" + (f": {msg}" if msg else "")),
                                 status=r.status_code, retry_after=ra)
                retryable = r.status_code in RETRY_ALWAYS or (safe and r.status_code in RETRY_IDEMPOTENT)
                if not retryable:
                    raise last
                wait = ra
            if attempt == self.attempts:
                break
            if wait is None:
                wait = random.uniform(0, min(8.0, 0.5 * 2 ** (attempt - 1)))   # full jitter
            if wait > self.max_wait:
                raise ItsmError(f"{last}; the server asked to wait {wait:.0f}s, more than {self.max_wait:.0f}s",
                                status=last.status if last else None, retry_after=wait)
            SLEEP(wait)
        assert last is not None
        raise last

    def get(self, path: str, **kw) -> httpx.Response:
        return self.request("GET", path, **kw)

    def post(self, path: str, **kw) -> httpx.Response:
        return self.request("POST", path, **kw)

    def patch(self, path: str, **kw) -> httpx.Response:
        return self.request("PATCH", path, **kw)
