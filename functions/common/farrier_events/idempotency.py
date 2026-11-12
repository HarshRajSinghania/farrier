"""At-least-once delivery means every handler must tolerate duplicates.

Prefer *natural* idempotency (compare the target's current state with the
event, as the import functions do with the certificate fingerprint). When the
side effect cannot be observed afterwards -- posting a chat message -- use a
store keyed by the CloudEvent id with lease semantics:

* ``claim`` succeeds if the key is new, or a previous claim's lease expired
  (the earlier attempt crashed mid-way).
* ``complete`` marks it done for good; later claims fail.
* ``release`` gives the key back after a failure so the retry can proceed.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

DEFAULT_LEASE_SECONDS = 300


class IdempotencyStore(Protocol):
    def claim(self, key: str, *, lease_seconds: int) -> bool: ...
    def complete(self, key: str) -> None: ...
    def release(self, key: str) -> None: ...


@dataclass(slots=True)
class _Entry:
    done: bool
    lease_until: float


class InMemoryIdempotencyStore:
    """Per-process store. Good for tests and as a warm-container fallback."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._entries: dict[str, _Entry] = {}

    def claim(self, key: str, *, lease_seconds: int) -> bool:
        now = self._clock()
        entry = self._entries.get(key)
        if entry is not None and (entry.done or entry.lease_until > now):
            return False
        self._entries[key] = _Entry(done=False, lease_until=now + lease_seconds)
        return True

    def complete(self, key: str) -> None:
        self._entries[key] = _Entry(done=True, lease_until=float("inf"))

    def release(self, key: str) -> None:
        entry = self._entries.get(key)
        if entry is not None and not entry.done:
            del self._entries[key]


def run_once[R](
    store: IdempotencyStore, key: str, fn: Callable[[], R], *, lease_seconds: int = DEFAULT_LEASE_SECONDS
) -> tuple[bool, R | None]:
    """Run ``fn`` unless ``key`` was already processed. Returns ``(ran, result)``."""
    if not store.claim(key, lease_seconds=lease_seconds):
        return False, None
    try:
        result = fn()
    except BaseException:
        store.release(key)
        raise
    store.complete(key)
    return True, result
