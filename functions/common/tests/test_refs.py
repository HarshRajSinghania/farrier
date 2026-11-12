from __future__ import annotations

import pytest
from farrier_events import (
    AwsSecretRef,
    AzureBlobRef,
    AzureKeyVaultSecretRef,
    GcpSecretRef,
    GcsObjectRef,
    InvalidReference,
    PermanentError,
    S3ObjectRef,
    ensure_allowed,
    parse_object_ref,
    parse_prefixes,
    parse_secret_ref,
)


@pytest.mark.parametrize(
    ("ref", "expected"),
    [
        (
            "aws-sm:arn:aws:secretsmanager:eu-west-1:123456789012:secret:farrier/keys/2041-AbCdEf",
            AwsSecretRef("arn:aws:secretsmanager:eu-west-1:123456789012:secret:farrier/keys/2041-AbCdEf", "eu-west-1"),
        ),
        (
            "aws-sm:arn:aws-us-gov:secretsmanager:us-gov-west-1:123456789012:secret:farrier/keys/1",
            AwsSecretRef(
                "arn:aws-us-gov:secretsmanager:us-gov-west-1:123456789012:secret:farrier/keys/1", "us-gov-west-1"
            ),
        ),
        (
            "gcp-sm:projects/acme-prod/secrets/farrier-key-2041/versions/1",
            GcpSecretRef("projects/acme-prod/secrets/farrier-key-2041/versions/1", "acme-prod"),
        ),
        (
            "gcp-sm:projects/123456/secrets/k/versions/latest",
            GcpSecretRef("projects/123456/secrets/k/versions/latest", "123456"),
        ),
        (
            "azure-kv:https://acme-kv.vault.azure.net/secrets/farrier-key-2041",
            AzureKeyVaultSecretRef("https://acme-kv.vault.azure.net", "farrier-key-2041", None),
        ),
        (
            "azure-kv:https://ACME-kv.vault.azure.net/secrets/k/0123456789abcdef0123456789abcdef",
            AzureKeyVaultSecretRef("https://acme-kv.vault.azure.net", "k", "0123456789abcdef0123456789abcdef"),
        ),
    ],
)
def test_secret_refs_parse(ref: str, expected: object) -> None:
    assert parse_secret_ref(ref) == expected


@pytest.mark.parametrize(
    "ref",
    [
        "",
        "plain-string",
        "vault:secret/x",
        "aws-sm:arn:aws:s3:::bucket/key",
        "aws-sm:arn:aws:secretsmanager:eu-west-1:12345:secret:x",
        "aws-sm:arn:aws:secretsmanager:eu-west-1:123456789012:secret:has space",
        "gcp-sm:projects/p/secrets/s",
        "gcp-sm:projects/p/secrets/s/versions/abc",
        "azure-kv:http://acme.vault.azure.net/secrets/k",
        "azure-kv:https://evil.example.com/secrets/k",
        "azure-kv:https://acme.vault.azure.net.evil.com/secrets/k",
        "azure-kv:https://user:pw@acme.vault.azure.net/secrets/k",
        "azure-kv:https://acme.vault.azure.net/keys/k",
        "azure-kv:https://acme.vault.azure.net/secrets/k?api-version=7.4",
        "azure-kv:https://acme.vault.azure.net/secrets/k/not-a-version",
    ],
)
def test_bad_secret_refs_raise_permanent(ref: str) -> None:
    with pytest.raises(InvalidReference) as info:
        parse_secret_ref(ref)
    assert isinstance(info.value, PermanentError)


@pytest.mark.parametrize(
    ("ref", "expected"),
    [
        ("s3://farrier-certs/prod/2041/fullchain.pem", S3ObjectRef("farrier-certs", "prod/2041/fullchain.pem")),
        ("gs://acme_certs/farrier/2041/fullchain.pem", GcsObjectRef("acme_certs", "farrier/2041/fullchain.pem")),
        ("azblob://acmecerts/farrier/2041/fullchain.pem", AzureBlobRef("acmecerts", "farrier", "2041/fullchain.pem")),
    ],
)
def test_object_refs_parse(ref: str, expected: object) -> None:
    assert parse_object_ref(ref) == expected


def test_azblob_account_url() -> None:
    ref = parse_object_ref("azblob://acmecerts/farrier/a.pem")
    assert isinstance(ref, AzureBlobRef)
    assert ref.account_url == "https://acmecerts.blob.core.windows.net"


@pytest.mark.parametrize(
    "ref",
    [
        "s3://bucket",
        "s3://bucket/",
        "s3://UPPER/key",
        "s3://bucket/key?versionId=1",
        "gs://b/",
        "azblob://acmecerts/farrier",
        "azblob://Acme/c/b",
        "https://bucket.s3.amazonaws.com/key",
        "file:///etc/passwd",
    ],
)
def test_bad_object_refs_raise(ref: str) -> None:
    with pytest.raises(InvalidReference):
        parse_object_ref(ref)


def test_allowed_prefixes() -> None:
    prefixes = parse_prefixes(
        " s3://farrier-certs/prod/ , aws-sm:arn:aws:secretsmanager:eu-west-1:123456789012:secret:farrier/keys/ ,"
    )
    assert len(prefixes) == 2
    ensure_allowed("s3://farrier-certs/prod/1/fullchain.pem", prefixes)
    ensure_allowed("anything", ())
    with pytest.raises(InvalidReference):
        ensure_allowed("s3://other-bucket/x", prefixes)
