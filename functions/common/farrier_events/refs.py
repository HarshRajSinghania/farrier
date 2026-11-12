"""Parse the references Farrier puts in events.

Events carry *references* to key material and certificate chains, never the
material itself. Each reference parses into a small frozen dataclass so the
cloud adapters never do string surgery.

Secret references (``private_key_ref``)::

    aws-sm:arn:aws:secretsmanager:<region>:<account>:secret:<name>
    gcp-sm:projects/<project>/secrets/<secret>/versions/<version|latest>
    azure-kv:https://<vault>.vault.azure.net/secrets/<name>[/<version>]

Object references (``certificate.chain_ref``)::

    s3://<bucket>/<key>
    gs://<bucket>/<object>
    azblob://<account>/<container>/<blob>
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .errors import InvalidReference

_AWS_SM_ARN = re.compile(
    r"^arn:(?P<partition>aws[a-z-]*):secretsmanager:(?P<region>[a-z0-9-]+):(?P<account>\d{12})"
    r":secret:(?P<name>[A-Za-z0-9/_+=.@-]+)$"
)
_GCP_SECRET = re.compile(
    r"^projects/(?P<project>[a-z0-9-]{1,63}|\d+)/secrets/(?P<secret>[A-Za-z0-9_-]{1,255})"
    r"/versions/(?P<version>latest|\d+)$"
)
_AZURE_VAULT_SUFFIXES = (
    ".vault.azure.net",
    ".vault.azure.cn",
    ".vault.usgovcloudapi.net",
    ".vault.microsoftazure.de",
)
_AZURE_NAME = re.compile(r"^[0-9A-Za-z-]{1,127}$")
_AZURE_VERSION = re.compile(r"^[0-9a-f]{32}$")
_S3_BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_GCS_BUCKET = re.compile(r"^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$")
_AZ_ACCOUNT = re.compile(r"^[a-z0-9]{3,24}$")
_AZ_CONTAINER = re.compile(r"^(\$root|[a-z0-9](?:-?[a-z0-9]){2,62})$")


@dataclass(frozen=True, slots=True)
class AwsSecretRef:
    arn: str
    region: str


@dataclass(frozen=True, slots=True)
class GcpSecretRef:
    name: str  # projects/<p>/secrets/<s>/versions/<v>
    project: str


@dataclass(frozen=True, slots=True)
class AzureKeyVaultSecretRef:
    vault_url: str  # https://<vault>.vault.azure.net
    name: str
    version: str | None


@dataclass(frozen=True, slots=True)
class S3ObjectRef:
    bucket: str
    key: str


@dataclass(frozen=True, slots=True)
class GcsObjectRef:
    bucket: str
    name: str


@dataclass(frozen=True, slots=True)
class AzureBlobRef:
    account: str
    container: str
    blob: str

    @property
    def account_url(self) -> str:
        return f"https://{self.account}.blob.core.windows.net"


type SecretRef = AwsSecretRef | GcpSecretRef | AzureKeyVaultSecretRef
type ObjectRef = S3ObjectRef | GcsObjectRef | AzureBlobRef


def parse_secret_ref(ref: str) -> SecretRef:
    """Parse a ``private_key_ref``. Raises :class:`InvalidReference`."""
    if not isinstance(ref, str) or any(c.isspace() for c in ref):
        raise InvalidReference("secret reference must be a string without whitespace")
    scheme, sep, rest = ref.partition(":")
    if not sep:
        raise InvalidReference("secret reference has no scheme")
    match scheme:
        case "aws-sm":
            m = _AWS_SM_ARN.match(rest)
            if not m:
                raise InvalidReference("aws-sm reference is not a Secrets Manager secret ARN")
            return AwsSecretRef(arn=rest, region=m["region"])
        case "gcp-sm":
            m = _GCP_SECRET.match(rest)
            if not m:
                raise InvalidReference("gcp-sm reference is not projects/<p>/secrets/<s>/versions/<v>")
            return GcpSecretRef(name=rest, project=m["project"])
        case "azure-kv":
            return _parse_azure_kv(rest)
        case _:
            raise InvalidReference(f"unknown secret reference scheme {scheme!r}")


def _parse_azure_kv(url: str) -> AzureKeyVaultSecretRef:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if (
        parts.scheme != "https"
        or parts.username
        or parts.password
        or parts.port
        or parts.query
        or parts.fragment
        or not host.endswith(_AZURE_VAULT_SUFFIXES)
    ):
        raise InvalidReference("azure-kv reference must be https://<vault>.vault.azure.net/secrets/<name>[/<version>]")
    segments = [s for s in parts.path.split("/") if s]
    if len(segments) not in (2, 3) or segments[0] != "secrets" or not _AZURE_NAME.match(segments[1]):
        raise InvalidReference("azure-kv reference path must be /secrets/<name>[/<version>]")
    version = segments[2] if len(segments) == 3 else None
    if version is not None and not _AZURE_VERSION.match(version):
        raise InvalidReference("azure-kv secret version must be 32 lowercase hex characters")
    return AzureKeyVaultSecretRef(vault_url=f"https://{host}", name=segments[1], version=version)


def parse_object_ref(ref: str) -> ObjectRef:
    """Parse a ``chain_ref``. Raises :class:`InvalidReference`."""
    if not isinstance(ref, str) or any(c.isspace() for c in ref):
        raise InvalidReference("object reference must be a string without whitespace")
    scheme, sep, rest = ref.partition("://")
    if not sep:
        raise InvalidReference("object reference has no scheme")
    if "?" in rest or "#" in rest:
        raise InvalidReference("object reference must not carry a query or fragment")
    match scheme:
        case "s3":
            bucket, _, key = rest.partition("/")
            if not _S3_BUCKET.match(bucket) or not key:
                raise InvalidReference("s3 reference must be s3://<bucket>/<key>")
            return S3ObjectRef(bucket=bucket, key=key)
        case "gs":
            bucket, _, name = rest.partition("/")
            if not _GCS_BUCKET.match(bucket) or not name:
                raise InvalidReference("gs reference must be gs://<bucket>/<object>")
            return GcsObjectRef(bucket=bucket, name=name)
        case "azblob":
            account, _, tail = rest.partition("/")
            container, _, blob = tail.partition("/")
            if not _AZ_ACCOUNT.match(account) or not _AZ_CONTAINER.match(container) or not blob:
                raise InvalidReference("azblob reference must be azblob://<account>/<container>/<blob>")
            return AzureBlobRef(account=account, container=container, blob=blob)
        case _:
            raise InvalidReference(f"unknown object reference scheme {scheme!r}")


def ensure_allowed(ref: str, allowed_prefixes: tuple[str, ...]) -> None:
    """Defence in depth: refuse references outside the configured prefixes.

    IAM is the real boundary; this stops a forged or misrouted event from
    making a function with broad read access fetch an unrelated object. An
    empty tuple allows everything.
    """
    if allowed_prefixes and not any(ref.startswith(p) for p in allowed_prefixes):
        raise InvalidReference("reference is outside the allowed prefixes")


def parse_prefixes(raw: str | None) -> tuple[str, ...]:
    """Split a comma-separated environment value into prefixes."""
    return tuple(p.strip() for p in (raw or "").split(",") if p.strip())
