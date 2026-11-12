"""Object storage for change packs, runbooks, certificate chains and backups.

    FARRIER_STORAGE_URL = file:///path            (default: file://<data>/objects)
                        | s3://bucket/prefix      FARRIER_STORAGE_S3_REGION (else AWS_REGION),
                                                  FARRIER_STORAGE_S3_ENDPOINT (MinIO / S3-compatible, path-style),
                                                  FARRIER_STORAGE_KMS_KEY (SSE-KMS key id/ARN for every object)
                        | gs://bucket/prefix
                        | azblob://account/container/prefix   (FARRIER_STORAGE_AZBLOB_ENDPOINT overrides
                                                  https://<account>.blob.core.windows.net, e.g. Azurite)

Cloud stores authenticate with the platform identity (farrier.cloud_auth). Nothing here encrypts: callers
that store key material seal it with the master key first (farrier.storage.packs), so no bucket ever
holds a plaintext private key.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

KEY = re.compile(r"^[A-Za-z0-9!_.*'()=+@,;:-]+(/[A-Za-z0-9!_.*'()=+@,;:-]+)*$")


class ObjectStorage:
    """put/get/delete/list by key (``a/b/c.pem``), relative to the store's prefix."""

    scheme = ""

    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
        """Write (replace) an object; return its URL (``s3://bucket/prefix/key``...)."""
        raise NotImplementedError

    def get(self, key: str) -> bytes | None:
        raise NotImplementedError

    def delete(self, key: str) -> None:
        """Remove an object; a missing one is not an error."""
        raise NotImplementedError

    def list(self, prefix: str = "") -> list[str]:
        """Keys (relative to the store) that start with ``prefix``, sorted."""
        raise NotImplementedError

    def url(self, key: str) -> str:
        raise NotImplementedError

    def describe(self) -> str:
        return self.url("").rstrip("/")


def check_key(key: str) -> str:
    if not isinstance(key, str) or not KEY.match(key) or any(p in (".", "..") for p in key.split("/")):
        raise ValueError(f"invalid object key {key!r}")
    return key


def join(prefix: str, key: str) -> str:
    return f"{prefix.strip('/')}/{key}" if prefix.strip("/") else key


def from_url(url: str, data_dir: Path | None = None) -> ObjectStorage:
    """A store for a storage URL. Errors name FARRIER_STORAGE_URL."""
    p = urlsplit(url.strip())
    if p.scheme == "file":
        from farrier.storage.local import FileStorage
        path = unquote(p.path)
        if re.match(r"^/[A-Za-z]:", path):          # file:///C:/x on Windows
            path = path[1:]
        return FileStorage(Path(p.netloc + path if p.netloc and p.netloc != "localhost" else path))
    if p.scheme == "s3" and p.netloc:
        from farrier.storage.s3 import S3Storage
        return S3Storage(p.netloc, p.path.strip("/"))
    if p.scheme == "gs" and p.netloc:
        from farrier.storage.gcs import GcsStorage
        return GcsStorage(p.netloc, p.path.strip("/"))
    if p.scheme == "azblob" and p.netloc:
        from farrier.storage.azblob import AzureBlobStorage
        container, _, prefix = p.path.strip("/").partition("/")
        if not container:
            raise ValueError("FARRIER_STORAGE_URL azblob://<account>/<container>[/prefix] needs a container")
        return AzureBlobStorage(p.netloc, container, prefix)
    raise ValueError(f"FARRIER_STORAGE_URL must be file:///path, s3://bucket/prefix, gs://bucket/prefix or "
                     f"azblob://account/container/prefix (got scheme {p.scheme or 'none'!r})")


def explicit() -> bool:
    """True when the operator chose a store (FARRIER_STORAGE_URL is set)."""
    return bool(os.environ.get("FARRIER_STORAGE_URL", "").strip())


def configured(data_dir: Path) -> ObjectStorage:
    url = os.environ.get("FARRIER_STORAGE_URL", "").strip()
    if url:
        return from_url(url, data_dir)
    from farrier.storage.local import FileStorage
    return FileStorage(Path(data_dir) / "objects")


def is_remote(storage: ObjectStorage) -> bool:
    """Object URLs other systems can fetch (s3, gs, azblob), as opposed to a local directory."""
    return storage.scheme in ("s3", "gs", "azblob")
