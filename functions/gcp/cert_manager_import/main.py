"""Cloud Functions (2nd gen) entrypoint, copied to ``main.py`` at the source root by build.sh.

Deploy (see README): runtime python312, entry point ``on_renewal_event``,
Pub/Sub trigger on the Farrier topic, retries enabled.

Environment:
    GCP_CM_PROJECT         project of target certificates (default: GOOGLE_CLOUD_PROJECT)
    GCP_CM_LOCATION        default "global"
    GCP_CM_NAME_PATTERN    optional glob on endpoint names to upload without a gcp-cm: tag
    ALLOWED_REF_PREFIXES   optional comma list; chain/key refs must start with one
    LOG_LEVEL              default INFO
"""

from __future__ import annotations

import os
from functools import cache
from typing import Any

import functions_framework
from farrier_events import get_logger, parse_prefixes

from cert_manager_import.adapters import (
    AuthorizedSessionClient,
    RestCertificateManager,
    RestSecretManager,
    RestStorage,
)
from cert_manager_import.core import Config, Deps, handle

log = get_logger("cert_manager_import", level=os.environ.get("LOG_LEVEL", "INFO"))


@cache
def _deps() -> Deps:
    http = AuthorizedSessionClient()
    return Deps(secrets=RestSecretManager(http), chains=RestStorage(http), cm=RestCertificateManager(http))


@cache
def _config() -> Config:
    return Config(
        project=os.environ.get("GCP_CM_PROJECT") or os.environ["GOOGLE_CLOUD_PROJECT"],
        location=os.environ.get("GCP_CM_LOCATION", "global"),
        name_pattern=os.environ.get("GCP_CM_NAME_PATTERN") or None,
        allowed_prefixes=parse_prefixes(os.environ.get("ALLOWED_REF_PREFIXES")),
    )


@functions_framework.cloud_event
def on_renewal_event(cloud_event: Any) -> None:
    """Raising nacks the message: Pub/Sub redelivers, then dead-letters after max attempts."""
    message = (cloud_event.data or {}).get("message", {})
    handle(message, _deps(), _config(), log.bind(pubsub_message_id=message.get("messageId")))
