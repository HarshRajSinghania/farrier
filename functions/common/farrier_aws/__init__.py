"""AWS helpers shared by the Lambda functions (vendored next to farrier_events).

``boto3`` is imported lazily: it ships with the Lambda Python runtime and the
unit tests never need it.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from farrier_events import AwsSecretRef, PermanentError, TransientError

from .errors import classify, translate

__all__ = ["SecretsManagerStore", "aws_call", "boto_config", "client", "classify", "translate"]


def boto_config() -> Any:
    """Short timeouts and no botocore retries: ``RetryPolicy`` owns retrying."""
    from botocore.config import Config

    return Config(connect_timeout=5, read_timeout=15, retries={"total_max_attempts": 1, "mode": "standard"})


def client(service: str) -> Any:
    import boto3

    return boto3.client(service, config=boto_config())


@contextmanager
def aws_call(operation: str) -> Iterator[None]:
    """Translate whatever a boto3 call raises into Transient/PermanentError."""
    try:
        yield
    except (TransientError, PermanentError):
        raise
    except Exception as exc:
        raise translate(exc, operation) from None


class SecretsManagerStore:
    """Reads a secret's value. Callers must never log what this returns."""

    def __init__(self, sm_client: Any) -> None:
        self._sm = sm_client

    def get_secret(self, ref: AwsSecretRef | str) -> str:
        secret_id = ref.arn if isinstance(ref, AwsSecretRef) else ref
        with aws_call("secretsmanager:GetSecretValue"):
            resp = self._sm.get_secret_value(SecretId=secret_id)
        if "SecretString" in resp:
            return str(resp["SecretString"])
        try:
            return bytes(resp["SecretBinary"]).decode("ascii")
        except (KeyError, UnicodeDecodeError):
            raise PermanentError("secret is neither a string nor ASCII bytes") from None
