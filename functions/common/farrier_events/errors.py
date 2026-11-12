"""Error taxonomy shared by every function.

Handlers raise; the platform decides what happens next:

* ``TransientError`` -- the operation may succeed if tried again (throttling,
  5xx, timeouts). Retried in-process by :func:`farrier_events.retry.retry`,
  then raised so the platform redelivers the event.
* ``PermanentError`` -- retrying the same event cannot succeed (malformed
  event, missing reference, fingerprint mismatch, access denied). Raised so the
  platform's bounded retries run out quickly and the event lands on the
  dead-letter queue for a human.
"""

from __future__ import annotations


class FarrierEventError(Exception):
    """Base class for every error raised by the shared package."""


class TransientError(FarrierEventError):
    """May succeed if the same operation is retried."""


class PermanentError(FarrierEventError):
    """Will not succeed on retry. The event belongs on the dead-letter queue."""


class InvalidEvent(PermanentError):
    """The payload is not a valid Farrier renewal event."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = list(problems)
        super().__init__("invalid event: " + "; ".join(self.problems))


class InvalidReference(PermanentError):
    """A storage or secret reference could not be parsed or is not allowed."""
