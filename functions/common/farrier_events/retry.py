"""Bounded retries with exponential backoff and full jitter.

Only :class:`TransientError` (or whatever ``retry_on`` names) is retried; a
``PermanentError`` propagates at once. Keep in-process attempts small: the
platform redelivers the whole event afterwards, and a Lambda has a timeout.
"""

from __future__ import annotations

import functools
import random
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .errors import TransientError


def backoff_delays(attempts: int, base: float, cap: float, rng: Callable[[], float]) -> list[float]:
    """Delays slept *between* ``attempts`` tries (AWS "full jitter")."""
    return [rng() * min(cap, base * (2**n)) for n in range(max(0, attempts - 1))]


def retry[**P, R](
    *,
    attempts: int = 4,
    base_delay: float = 0.25,
    max_delay: float = 4.0,
    retry_on: tuple[type[BaseException], ...] = (TransientError,),
    sleep: Callable[[float], None] = time.sleep,
    rng: Callable[[], float] = random.random,
    on_retry: Callable[[int, BaseException, float], None] | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    if attempts < 1:
        raise ValueError("attempts must be >= 1")

    def decorate(fn: Callable[P, R]) -> Callable[P, R]:
        @functools.wraps(fn)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            delays = backoff_delays(attempts, base_delay, max_delay, rng)
            for attempt in range(1, attempts + 1):
                try:
                    return fn(*args, **kwargs)
                except retry_on as exc:
                    if attempt == attempts:
                        raise
                    delay = delays[attempt - 1]
                    if on_retry is not None:
                        on_retry(attempt, exc, delay)
                    sleep(delay)
            raise AssertionError("unreachable")  # pragma: no cover

        return wrapper

    return decorate


def call_with_retry[R](fn: Callable[[], R], **options: Any) -> R:
    """``retry`` for a one-off call: ``call_with_retry(lambda: s3.get(ref))``."""
    return retry(**options)(fn)()


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """A retry configuration handlers carry in their config (tests pass ``sleep=lambda _: None``)."""

    attempts: int = 4
    base_delay: float = 0.25
    max_delay: float = 4.0
    sleep: Callable[[float], None] = time.sleep

    def run[R](self, fn: Callable[[], R], log: Any = None) -> R:
        def on_retry(attempt: int, exc: BaseException, delay: float) -> None:
            if log is not None:
                log.warning(
                    "retrying after transient error",
                    attempt=attempt,
                    error_type=type(exc).__name__,
                    delay_s=round(delay, 3),
                )

        return call_with_retry(
            fn,
            attempts=self.attempts,
            base_delay=self.base_delay,
            max_delay=self.max_delay,
            sleep=self.sleep,
            on_retry=on_retry,
        )
