"""Change packs (cert, chain, key, PFX, passphrase, RUNBOOK.md) for renewals a person installs.

Without FARRIER_STORAGE_URL a pack is a directory <data>/packs/<renewal id>/, exactly as before. With it,
a pack is the objects change-packs/<renewal id>/<file> in that store (a prefix bucket lifecycle rules
can expire), and every file that holds key material
(key.pem, bundle.pfx, passphrase.txt) is sealed client-side with the master key before upload and
stored as <file>.sealed: a bucket never holds a plaintext private key. Reading a pack opens them again.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from cryptography.fernet import Fernet

from farrier.storage import ObjectStorage, configured, explicit

SEALED = frozenset({"key.pem", "bundle.pfx", "passphrase.txt"})
SUFFIX = ".sealed"
PREFIX = "change-packs/"


class LocalPacks:
    """<data>/packs/<rid>/<file>: text written as text, binaries as bytes (byte-for-byte the old layout)."""

    def __init__(self, data_dir: Path):
        self.root = Path(data_dir) / "packs"

    def location(self, rid: int) -> str:
        return str(self.root / str(rid))

    def write(self, rid: int, files: dict[str, str | bytes]) -> str:
        d = self.root / str(rid)
        d.mkdir(parents=True, exist_ok=True)
        for name, content in files.items():
            if isinstance(content, bytes):
                (d / name).write_bytes(content)
            else:
                (d / name).write_text(content)
        return str(d)

    def read(self, rid: int) -> dict[str, bytes] | None:
        d = self.root / str(rid)
        if not d.is_dir():
            return None
        return {f.name: f.read_bytes() for f in sorted(d.iterdir()) if f.is_file()}

    def read_text(self, rid: int, name: str) -> str | None:
        f = self.root / str(rid) / name
        return f.read_text() if f.is_file() else None

    def delete(self, rid: int) -> None:
        shutil.rmtree(self.root / str(rid), ignore_errors=True)

    def ids(self) -> list[int]:
        if not self.root.is_dir():
            return []
        return sorted(int(d.name) for d in self.root.iterdir() if d.name.isdigit())


class ObjectPacks:
    def __init__(self, storage: ObjectStorage, master_key: bytes):
        self.storage = storage
        self._f = Fernet(master_key)

    def location(self, rid: int) -> str:
        return self.storage.url(f"{PREFIX}{rid}/")

    def write(self, rid: int, files: dict[str, str | bytes]) -> str:
        for name, content in files.items():
            data = content.encode() if isinstance(content, str) else content
            if name in SEALED:
                self.storage.put(f"{PREFIX}{rid}/{name}{SUFFIX}", self._f.encrypt(data), "application/octet-stream")
            else:
                ctype = "text/markdown" if name.endswith(".md") else \
                    "application/x-pem-file" if name.endswith(".pem") else "application/octet-stream"
                self.storage.put(f"{PREFIX}{rid}/{name}", data, ctype)
        return self.location(rid)

    def read(self, rid: int) -> dict[str, bytes] | None:
        keys = self.storage.list(f"{PREFIX}{rid}/")
        if not keys:
            return None
        out = {}
        for k in keys:
            data = self.storage.get(k)
            if data is None:
                continue
            name = k.rsplit("/", 1)[1]
            if name.endswith(SUFFIX):
                name, data = name[: -len(SUFFIX)], self._f.decrypt(data)
            out[name] = data
        return dict(sorted(out.items()))

    def read_text(self, rid: int, name: str) -> str | None:
        data = self.storage.get(f"{PREFIX}{rid}/{name}")
        return None if data is None else data.decode()

    def delete(self, rid: int) -> None:
        for k in self.storage.list(f"{PREFIX}{rid}/"):
            self.storage.delete(k)

    def ids(self) -> list[int]:
        return sorted({int(p) for k in self.storage.list(PREFIX) if (p := k.split("/")[1]).isdigit()})


def pack_store(data_dir: Path):
    """LocalPacks unless FARRIER_STORAGE_URL is set."""
    if not explicit():
        return LocalPacks(data_dir)
    from farrier.security.vault import master_key
    return ObjectPacks(configured(data_dir), master_key(data_dir))
