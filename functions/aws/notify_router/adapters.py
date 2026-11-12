"""Thin adapters: HTTPS via urllib, DynamoDB idempotency store, cached secrets."""

from __future__ import annotations

import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any

from farrier_aws import SecretsManagerStore, aws_call, translate
from farrier_events import TransientError

USER_AGENT = "farrier-notify-router/1"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # A redirect could forward the signed body (or a Slack URL's path) elsewhere.
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class UrllibPoster:
    def __init__(self, timeout_s: float = 10.0) -> None:
        self._timeout = timeout_s
        self._opener = urllib.request.build_opener(_NoRedirect())

    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> int:
        req = urllib.request.Request(url, data=body, method="POST", headers={**headers, "User-Agent": USER_AGENT})
        try:
            with self._opener.open(req, timeout=self._timeout) as resp:
                return int(resp.status)
        except urllib.error.HTTPError as exc:
            return int(exc.code)
        except (TimeoutError, urllib.error.URLError, ConnectionError) as exc:
            # Never include the URL: for Slack it is the credential.
            raise TransientError(f"HTTP request failed: {type(exc).__name__}") from None


class CachedSecret:
    """Reads a secret once per container; ``__call__`` returns the value."""

    def __init__(self, store: SecretsManagerStore, arn: str, ttl_s: float = 300.0) -> None:
        self._store, self._arn, self._ttl = store, arn, ttl_s
        self._value: str | None = None
        self._fetched = 0.0
        self._lock = threading.Lock()

    def __call__(self) -> str:
        with self._lock:
            if self._value is None or time.monotonic() - self._fetched > self._ttl:
                self._value = self._store.get_secret(self._arn).strip()
                self._fetched = time.monotonic()
            return self._value


def _error_code(exc: BaseException) -> str | None:
    response = getattr(exc, "response", None)
    return ((response or {}).get("Error") or {}).get("Code") if isinstance(response, dict) else None


class DynamoDbIdempotencyStore:
    """Lease-based claims in a table with string hash key ``pk`` and TTL on ``expires_at``."""

    def __init__(
        self, ddb_client: Any, table: str, retention_s: int = 7 * 24 * 3600, clock: Callable[[], float] = time.time
    ) -> None:
        self._ddb, self._table, self._retention, self._clock = ddb_client, table, retention_s, clock

    def claim(self, key: str, *, lease_seconds: int) -> bool:
        now = int(self._clock())
        try:
            self._ddb.put_item(
                TableName=self._table,
                Item={
                    "pk": {"S": key},
                    "status": {"S": "inflight"},
                    "lease_until": {"N": str(now + lease_seconds)},
                    "expires_at": {"N": str(now + self._retention)},
                },
                ConditionExpression="attribute_not_exists(pk) OR (#s = :inflight AND lease_until < :now)",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":inflight": {"S": "inflight"}, ":now": {"N": str(now)}},
            )
        except Exception as exc:
            if _error_code(exc) == "ConditionalCheckFailedException":
                return False  # already done, or another attempt holds a live lease
            raise translate(exc, "dynamodb:PutItem") from None
        return True

    def complete(self, key: str) -> None:
        now = int(self._clock())
        with aws_call("dynamodb:UpdateItem"):
            self._ddb.update_item(
                TableName=self._table,
                Key={"pk": {"S": key}},
                UpdateExpression="SET #s = :done, expires_at = :exp",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":done": {"S": "done"}, ":exp": {"N": str(now + self._retention)}},
            )

    def release(self, key: str) -> None:
        try:
            self._ddb.delete_item(
                TableName=self._table,
                Key={"pk": {"S": key}},
                ConditionExpression="#s = :inflight",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":inflight": {"S": "inflight"}},
            )
        except Exception as exc:
            if _error_code(exc) == "ConditionalCheckFailedException":
                return
            raise translate(exc, "dynamodb:DeleteItem") from None
