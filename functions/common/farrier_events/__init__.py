"""Shared building blocks for Farrier event-driven functions.

Standard library only, so it can be copied into any Lambda zip, Cloud Function
source directory or Azure Function app without a network install.
"""

from .errors import FarrierEventError, InvalidEvent, InvalidReference, PermanentError, TransientError
from .event import (
    ATTENTION_STATES,
    ISSUED_STATES,
    STATES,
    SUPPORTED_SCHEMA_VERSION,
    Certificate,
    Endpoint,
    Renewal,
    RenewalEvent,
    event_type,
    parse_event,
    validate,
)
from .idempotency import IdempotencyStore, InMemoryIdempotencyStore, run_once
from .log import Logger, get_logger, redact
from .refs import (
    AwsSecretRef,
    AzureBlobRef,
    AzureKeyVaultSecretRef,
    GcpSecretRef,
    GcsObjectRef,
    ObjectRef,
    S3ObjectRef,
    SecretRef,
    ensure_allowed,
    parse_object_ref,
    parse_prefixes,
    parse_secret_ref,
)
from .retry import RetryPolicy, backoff_delays, call_with_retry, retry

__version__ = "1.0.0"

__all__ = [
    "ATTENTION_STATES",
    "ISSUED_STATES",
    "STATES",
    "SUPPORTED_SCHEMA_VERSION",
    "AwsSecretRef",
    "AzureBlobRef",
    "AzureKeyVaultSecretRef",
    "Certificate",
    "Endpoint",
    "FarrierEventError",
    "GcpSecretRef",
    "GcsObjectRef",
    "IdempotencyStore",
    "InMemoryIdempotencyStore",
    "InvalidEvent",
    "InvalidReference",
    "Logger",
    "ObjectRef",
    "PermanentError",
    "Renewal",
    "RetryPolicy",
    "RenewalEvent",
    "S3ObjectRef",
    "SecretRef",
    "TransientError",
    "backoff_delays",
    "call_with_retry",
    "ensure_allowed",
    "event_type",
    "get_logger",
    "parse_event",
    "parse_object_ref",
    "parse_prefixes",
    "parse_secret_ref",
    "redact",
    "retry",
    "run_once",
    "validate",
]
