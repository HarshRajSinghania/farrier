"""Google Cloud Storage through the JSON API, authenticated with the Google credential chain."""
from __future__ import annotations

import os
from urllib.parse import quote

from farrier.security.cloud_auth import google
from farrier.security.cloud_auth.http import json_body, request
from farrier.storage import ObjectStorage, check_key, join

API = "https://storage.googleapis.com/storage/v1"
UPLOAD = "https://storage.googleapis.com/upload/storage/v1"
SCOPE = "https://www.googleapis.com/auth/devstorage.read_write"


class GcsStorage(ObjectStorage):
    scheme = "gs"

    def __init__(self, bucket: str, prefix: str = "", env=None, http=None, tokens=None):
        env = os.environ if env is None else env
        self.bucket, self.prefix = bucket, prefix
        self.http = http
        self.tokens = tokens or (google.default_provider() if env is os.environ else google.GoogleTokenProvider(env, http))

    def _h(self) -> dict:
        return {"Authorization": f"Bearer {self.tokens.token(SCOPE)}"}

    def _obj(self, key: str) -> str:
        return f"{API}/b/{self.bucket}/o/{quote(join(self.prefix, check_key(key)), safe='')}"

    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
        name = join(self.prefix, check_key(key))
        request("POST", f"{UPLOAD}/b/{self.bucket}/o", what="GCS upload", http=self.http,
                params={"uploadType": "media", "name": name}, content=data,
                headers={**self._h(), "Content-Type": content_type})
        return self.url(key)

    def get(self, key: str) -> bytes | None:
        r = request("GET", self._obj(key), what="GCS download", http=self.http, params={"alt": "media"},
                    headers=self._h(), allow=(404,))
        return None if r.status_code == 404 else r.content

    def delete(self, key: str) -> None:
        request("DELETE", self._obj(key), what="GCS delete", http=self.http, headers=self._h(), allow=(404,))

    def list(self, prefix: str = "") -> list[str]:
        full = join(self.prefix, prefix) if prefix else (self.prefix.strip("/") + "/" if self.prefix.strip("/") else "")
        cut = len(self.prefix.strip("/")) + 1 if self.prefix.strip("/") else 0
        keys, token = [], None
        while True:
            params = {"prefix": full, **({"pageToken": token} if token else {})}
            j = json_body(request("GET", f"{API}/b/{self.bucket}/o", what="GCS list", http=self.http, params=params,
                                  headers=self._h()), "GCS list")
            keys += [o["name"][cut:] for o in j.get("items", [])]
            token = j.get("nextPageToken")
            if not token:
                return sorted(keys)

    def url(self, key: str) -> str:
        return f"gs://{self.bucket}/{join(self.prefix, key)}" if key else f"gs://{self.bucket}/{self.prefix}"
