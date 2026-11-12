"""Amazon S3 and S3-compatible stores (MinIO, Ceph RGW...), SigV4-signed with the AWS credential chain.

AWS: virtual-hosted URLs (path-style for bucket names with dots). FARRIER_STORAGE_S3_ENDPOINT: path-style
against that endpoint, region FARRIER_STORAGE_S3_REGION (default us-east-1). FARRIER_STORAGE_KMS_KEY:
every object is written with SSE-KMS under that key.
"""
from __future__ import annotations

import hashlib
import os
import xml.etree.ElementTree as ET
from urllib.parse import quote, urlencode

from ..cloud_auth import aws
from ..cloud_auth.http import CloudConfigError
from . import ObjectStorage, check_key, join

NS = {"s": "http://s3.amazonaws.com/doc/2006-03-01/"}


class S3Storage(ObjectStorage):
    scheme = "s3"

    def __init__(self, bucket: str, prefix: str = "", env=None, http=None, creds=None):
        env = os.environ if env is None else env
        self.bucket, self.prefix = bucket, prefix
        self.endpoint = (env.get("FARRIER_STORAGE_S3_ENDPOINT") or "").rstrip("/") or None
        if self.endpoint and not self.endpoint.startswith(("https://", "http://")):
            raise CloudConfigError("FARRIER_STORAGE_S3_ENDPOINT must be a URL, e.g. https://minio.internal:9000")
        if self.endpoint:
            self.region = env.get("FARRIER_STORAGE_S3_REGION") or env.get("AWS_REGION") or "us-east-1"
        else:
            self.region = aws.region_for("FARRIER_STORAGE_S3_REGION", env.get("FARRIER_STORAGE_S3_REGION"), env)
        self.kms_key = env.get("FARRIER_STORAGE_KMS_KEY") or None
        self.http = http
        self.creds = creds or (aws.default_provider() if env is os.environ else aws.AwsCredentialProvider(env, http))

    def _base(self) -> str:
        if self.endpoint:
            return f"{self.endpoint}/{self.bucket}"
        if "." in self.bucket:
            return f"https://s3.{self.region}.amazonaws.com/{self.bucket}"
        return f"https://{self.bucket}.s3.{self.region}.amazonaws.com"

    def _object_url(self, key: str) -> str:
        return f"{self._base()}/{quote(join(self.prefix, check_key(key)), safe='/-_.~')}"

    def _call(self, method: str, url: str, what: str, body: bytes = b"", headers: dict | None = None, **kw):
        h = {"x-amz-content-sha256": hashlib.sha256(body).hexdigest(), **(headers or {})}
        return aws.signed_request(method, url, service="s3", region=self.region, what=f"S3 {what}", body=body,
                                  headers=h, creds=self.creds, http=self.http, **kw)

    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
        h = {"Content-Type": content_type}
        if self.kms_key:
            h["x-amz-server-side-encryption"] = "aws:kms"
            h["x-amz-server-side-encryption-aws-kms-key-id"] = self.kms_key
        self._call("PUT", self._object_url(key), "put object", data, h)
        return self.url(key)

    def get(self, key: str) -> bytes | None:
        r = self._call("GET", self._object_url(key), "get object", allow=(404,))
        return None if r.status_code == 404 else r.content

    def delete(self, key: str) -> None:
        self._call("DELETE", self._object_url(key), "delete object", allow=(404,))

    def list(self, prefix: str = "") -> list[str]:
        full = join(self.prefix, prefix) if prefix else (self.prefix.strip("/") + "/" if self.prefix.strip("/") else "")
        cut = len(self.prefix.strip("/")) + 1 if self.prefix.strip("/") else 0
        keys, token = [], None
        while True:
            params = {"list-type": "2", "prefix": full, **({"continuation-token": token} if token else {})}
            url = f"{self._base()}/?{urlencode(params, quote_via=quote)}" if not self.endpoint else \
                f"{self._base()}?{urlencode(params, quote_via=quote)}"
            root = ET.fromstring(self._call("GET", url, "list objects").content)
            keys += [k.text[cut:] for k in root.findall(".//s:Contents/s:Key", NS) if k.text]
            if root.findtext("s:IsTruncated", "false", NS) != "true":
                return sorted(keys)
            token = root.findtext("s:NextContinuationToken", None, NS)

    def url(self, key: str) -> str:
        return f"s3://{self.bucket}/{join(self.prefix, key)}" if key else f"s3://{self.bucket}/{self.prefix}"
