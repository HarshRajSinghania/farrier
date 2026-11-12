"""A directory as object store (file:///path). Writes are atomic (temp file + rename), owner-only."""
from __future__ import annotations

import os
from pathlib import Path

from . import ObjectStorage, check_key


class FileStorage(ObjectStorage):
    scheme = "file"

    def __init__(self, root: Path):
        self.root = Path(root)

    def _path(self, key: str) -> Path:
        return self.root.joinpath(*check_key(key).split("/"))

    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
        return self.url(key)

    def get(self, key: str) -> bytes | None:
        path = self._path(key)
        return path.read_bytes() if path.is_file() else None

    def delete(self, key: str) -> None:
        path = self._path(key)
        path.unlink(missing_ok=True)
        for parent in path.parents:              # drop directories the delete left empty
            if parent == self.root or self.root not in parent.parents:
                break
            try:
                parent.rmdir()
            except OSError:
                break

    def list(self, prefix: str = "") -> list[str]:
        if not self.root.is_dir():
            return []
        keys = (p.relative_to(self.root).as_posix() for p in self.root.rglob("*") if p.is_file())
        return sorted(k for k in keys if k.startswith(prefix) and not k.endswith(".tmp"))

    def url(self, key: str) -> str:
        return (self.root.resolve() / key).as_uri() if key else self.root.resolve().as_uri()
