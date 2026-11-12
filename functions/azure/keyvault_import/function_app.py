"""Azure Functions (Python v2 programming model) app, copied to the app root by build.sh.

Event Grid trigger on a subscription that uses the CloudEvents 1.0 schema,
filtered to ``dev.farrier.renewal.done``. Raising makes Event Grid retry with
its own backoff; after the subscription's max attempts / TTL the event is
dead-lettered to the configured storage container.

App settings:
    KEYVAULT_URL           default vault, https://<vault>.vault.azure.net
    AKV_NAME_PATTERN       optional glob on endpoint names to import without an akv: tag
    ALLOWED_REF_PREFIXES   optional comma list; chain/key refs must start with one
    LOG_LEVEL              default INFO
"""

from __future__ import annotations

import os
from functools import cache

import azure.functions as func
from farrier_events import get_logger, parse_prefixes

from keyvault_import.adapters import BlobChainReader, KeyVaultCertificateStore, KeyVaultSecretReader
from keyvault_import.core import Config, Deps, envelope_from_binding, handle

log = get_logger("keyvault_import", level=os.environ.get("LOG_LEVEL", "INFO"))
app = func.FunctionApp()


@cache
def _deps() -> Deps:
    return Deps(secrets=KeyVaultSecretReader(), chains=BlobChainReader(), vault=KeyVaultCertificateStore())


@cache
def _config() -> Config:
    return Config(
        vault_url=(os.environ.get("KEYVAULT_URL") or "").rstrip("/") or None,
        name_pattern=os.environ.get("AKV_NAME_PATTERN") or None,
        allowed_prefixes=parse_prefixes(os.environ.get("ALLOWED_REF_PREFIXES")),
    )


@app.function_name(name="farrier_keyvault_import")
@app.event_grid_trigger(arg_name="event")
def farrier_keyvault_import(event: func.EventGridEvent) -> None:
    envelope = envelope_from_binding(
        id=event.id,
        event_type=event.event_type,
        subject=event.subject,
        event_time=event.event_time,
        topic=event.topic,
        data=event.get_json(),
    )
    handle(envelope, _deps(), _config(), log)
