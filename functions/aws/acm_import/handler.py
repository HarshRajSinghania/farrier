"""Lambda entrypoint: ``acm_import.handler.handler``.

Environment:
    ACM_NAME_PATTERN       optional glob on endpoint names to import without an acm: tag
    ACM_DISCOVERY          "true" (default) to find the certificate tagged for an endpoint
    ALLOWED_REF_PREFIXES   optional comma list; chain/key refs must start with one
    LOG_LEVEL              default INFO
"""

from __future__ import annotations

import os
from functools import cache
from typing import Any

from farrier_aws import SecretsManagerStore, client
from farrier_events import get_logger, parse_prefixes

from .adapters import AcmAdapter, S3ChainStore
from .core import Config, Deps, handle

log = get_logger("acm_import", level=os.environ.get("LOG_LEVEL", "INFO"))


@cache
def _config() -> Config:
    return Config(
        region=os.environ["AWS_REGION"],
        name_pattern=os.environ.get("ACM_NAME_PATTERN") or None,
        allowed_prefixes=parse_prefixes(os.environ.get("ALLOWED_REF_PREFIXES")),
        discovery=os.environ.get("ACM_DISCOVERY", "true").lower() != "false",
    )


@cache
def _deps() -> Deps:
    # Built once per container and reused across invocations.
    return Deps(
        chains=S3ChainStore(client("s3")),
        secrets=SecretsManagerStore(client("secretsmanager")),
        acm=AcmAdapter(client("acm")),
    )


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    request_log = log.bind(aws_request_id=getattr(context, "aws_request_id", None))
    return handle(event, _deps(), _config(), request_log)
