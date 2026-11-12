"""Azure Blob Storage (block blobs) with an Entra ID token for https://storage.azure.com."""
from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET
from urllib.parse import quote

from ..cloud_auth import azure
from ..cloud_auth.http import CloudConfigError, request
from . import ObjectStorage, check_key, join

API_VERSION = "2023-11-03"
ACCOUNT = re.compile(r"^[a-z0-9]{3,24}$")


class AzureBlobStorage(ObjectStorage):
    scheme = "azblob"

    def __init__(self, account: str, container: str, prefix: str = "", env=None, http=None, tokens=None):
        env = os.environ if env is None else env
        if not ACCOUNT.match(account):
            raise CloudConfigError("FARRIER_STORAGE_URL: the Azure storage account name must be 3-24 lowercase "
                                   "letters and digits")
        self.account, self.container, self.prefix = account, container, prefix
        self.endpoint = (env.get("FARRIER_STORAGE_AZBLOB_ENDPOINT") or f"https://{account}.blob.core.windows.net").rstrip("/")
        self.http = http
        self.tokens = tokens or (azure.default_provider() if env is os.environ else azure.AzureTokenProvider(env, http))

    def _h(self, **extra) -> dict:
        return {"Authorization": f"Bearer {self.tokens.token(azure.STORAGE_SCOPE)}", "x-ms-version": API_VERSION,
                **extra}

    def _blob(self, key: str) -> str:
        return f"{self.endpoint}/{self.container}/{quote(join(self.prefix, check_key(key)), safe='/-_.~')}"

    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
        request("PUT", self._blob(key), what="Azure Blob put", http=self.http, content=data,
                headers=self._h(**{"x-ms-blob-type": "BlockBlob", "Content-Type": content_type}))
        return self.url(key)

    def get(self, key: str) -> bytes | None:
        r = request("GET", self._blob(key), what="Azure Blob get", http=self.http, headers=self._h(), allow=(404,))
        return None if r.status_code == 404 else r.content

    def delete(self, key: str) -> None:
        request("DELETE", self._blob(key), what="Azure Blob delete", http=self.http, headers=self._h(), allow=(404,))

    def list(self, prefix: str = "") -> list[str]:
        full = join(self.prefix, prefix) if prefix else (self.prefix.strip("/") + "/" if self.prefix.strip("/") else "")
        cut = len(self.prefix.strip("/")) + 1 if self.prefix.strip("/") else 0
        keys, marker = [], None
        while True:
            params = {"restype": "container", "comp": "list", "prefix": full, **({"marker": marker} if marker else {})}
            r = request("GET", f"{self.endpoint}/{self.container}", what="Azure Blob list", http=self.http,
                        params=params, headers=self._h())
            root = ET.fromstring(r.content)
            keys += [n.text[cut:] for n in root.iter("Name") if n.text]
            marker = root.findtext("NextMarker")
            if not marker:
                return sorted(keys)

    def url(self, key: str) -> str:
        base = f"azblob://{self.account}/{self.container}"
        return f"{base}/{join(self.prefix, key)}" if key else f"{base}/{self.prefix}"
