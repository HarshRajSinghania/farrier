"""Classify botocore exceptions without importing botocore.

botocore's ``ClientError`` carries ``response["Error"]["Code"]`` and the HTTP
status; connection-level failures are distinct exception classes. Matching on
names keeps this module importable (and testable) without boto3 installed.
"""

from __future__ import annotations

from farrier_events import PermanentError, TransientError

TRANSIENT_CODES = frozenset(
    {
        "Throttling",
        "ThrottlingException",
        "TooManyRequestsException",
        "RequestLimitExceeded",
        "RequestTimeout",
        "RequestTimeoutException",
        "InternalFailure",
        "InternalError",
        "InternalServiceError",
        "InternalServiceErrorException",
        "ServiceUnavailable",
        "ServiceUnavailableException",
        "SlowDown",
        "ProvisionedThroughputExceededException",
    }
)
TRANSIENT_EXCEPTION_NAMES = frozenset(
    {
        "EndpointConnectionError",
        "ConnectTimeoutError",
        "ReadTimeoutError",
        "ConnectionClosedError",
        "ConnectionError",
        "TimeoutError",
    }
)


def classify(code: str | None, status: int | None) -> type[TransientError] | type[PermanentError]:
    if code in TRANSIENT_CODES:
        return TransientError
    if status is not None and (status >= 500 or status == 429):
        return TransientError
    return PermanentError


def translate(exc: BaseException, operation: str) -> TransientError | PermanentError:
    """Map any exception raised by a boto3 call to our taxonomy.

    The message names the operation and error code only. botocore messages can
    echo request parameters, so they are deliberately dropped.
    """
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        error = response.get("Error") or {}
        code = error.get("Code")
        status = (response.get("ResponseMetadata") or {}).get("HTTPStatusCode")
        cls = classify(code, status)
        return cls(f"{operation} failed: {code or 'unknown'} (HTTP {status or '?'})")
    if type(exc).__name__ in TRANSIENT_EXCEPTION_NAMES:
        return TransientError(f"{operation} failed: {type(exc).__name__}")
    return PermanentError(f"{operation} failed: {type(exc).__name__}")
