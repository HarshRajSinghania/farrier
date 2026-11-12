"""Lambda entrypoint: ``notify_router.handler.handler``.

Environment:
    NOTIFY_SINKS               comma list: slack, webhook (and any you register)
    SLACK_WEBHOOK_SECRET_ARN   secret holding the Slack incoming-webhook URL
    WEBHOOK_URL                https endpoint for the generic webhook sink
    WEBHOOK_SECRET_ARN         secret holding the webhook HMAC key
    IDEMPOTENCY_TABLE          DynamoDB table for per-sink dedupe (falls back to in-memory)
    FARRIER_DASHBOARD_URL      optional, adds an "Open renewals" link
    LOG_LEVEL                  default INFO
"""

from __future__ import annotations

import os
from functools import cache
from typing import Any

from farrier_aws import SecretsManagerStore, client
from farrier_events import IdempotencyStore, InMemoryIdempotencyStore, get_logger

from .adapters import CachedSecret, DynamoDbIdempotencyStore, UrllibPoster
from .core import Config, Deps, handle
from .sinks import HttpPoster, build_sinks

log = get_logger("notify_router", level=os.environ.get("LOG_LEVEL", "INFO"))


class _Runtime:
    def __init__(self) -> None:
        self.http: HttpPoster = UrllibPoster()
        self._sm = SecretsManagerStore(client("secretsmanager"))

    def secret(self, arn: str) -> CachedSecret:
        return CachedSecret(self._sm, arn)


@cache
def _deps() -> Deps:
    table = os.environ.get("IDEMPOTENCY_TABLE")
    store: IdempotencyStore
    if table:
        store = DynamoDbIdempotencyStore(client("dynamodb"), table)
    else:
        log.warning("IDEMPOTENCY_TABLE not set; deduplicating per container only")
        store = InMemoryIdempotencyStore()
    return Deps(sinks=build_sinks(os.environ, _Runtime()), store=store)


@cache
def _config() -> Config:
    return Config(dashboard_url=os.environ.get("FARRIER_DASHBOARD_URL") or None)


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    request_log = log.bind(aws_request_id=getattr(context, "aws_request_id", None))
    return handle(event, _deps(), _config(), request_log)
