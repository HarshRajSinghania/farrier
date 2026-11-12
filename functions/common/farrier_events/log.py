"""Structured JSON logging with redaction.

One JSON object per line on stdout, which CloudWatch Logs, Cloud Logging and
Application Insights all parse. Every value passes through :func:`redact`
before it is written, so a PEM block, a Slack webhook URL or a field named
like a secret never reaches the log even if a caller passes one by mistake.

    log = get_logger("acm_import").bind(event_id=ev.id)
    log.info("imported", certificate_arn=arn)
"""

from __future__ import annotations

import json
import logging
import re
import sys
import traceback
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

REDACTED = "[REDACTED]"
_PEM_BLOCK = re.compile(r"-----BEGIN [A-Z0-9 ]+-----.*?(-----END [A-Z0-9 ]+-----|$)", re.DOTALL)
_SECRET_URLS = re.compile(
    r"https://(hooks\.slack\.com/(services|workflows|triggers)/|[^\s/]+\.webhook\.office\.com/)\S*",
    re.IGNORECASE,
)
_SECRET_KEY = re.compile(
    r"(secret|password|passwd|token|private_?key|pem|pfx|credential|authorization|signature|webhook_url|api_?key)",
    re.IGNORECASE,
)
_MAX_STRING = 2048


def _is_secret_key(key: str) -> bool:
    # References (private_key_ref, *_arn) name where a secret lives; they are safe.
    return bool(_SECRET_KEY.search(key)) and not key.endswith(("_ref", "_arn", "_name", "_id"))


def redact(value: Any, *, key: str | None = None) -> Any:
    """Return ``value`` with secrets removed. Pure; never mutates."""
    if key is not None and _is_secret_key(key):
        return REDACTED
    if isinstance(value, Mapping):
        return {str(k): redact(v, key=str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [redact(v) for v in value]
    if isinstance(value, (bytes, bytearray)):
        return f"<{len(value)} bytes>"
    if isinstance(value, str):
        return _redact_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _redact_text(str(value))


def _redact_text(text: str) -> str:
    text = _PEM_BLOCK.sub("[REDACTED PEM]", text)
    text = _SECRET_URLS.sub(REDACTED, text)
    if len(text) > _MAX_STRING:
        text = text[:_MAX_STRING] + "...[truncated]"
    return text


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": _redact_text(record.getMessage()),
        }
        fields = getattr(record, "fields", None)
        if isinstance(fields, Mapping):
            for k, v in redact(fields).items():
                entry.setdefault(k, v)
        if record.exc_info and record.exc_info[1] is not None:
            exc = record.exc_info[1]
            entry["error_type"] = type(exc).__name__
            entry["error"] = _redact_text(str(exc))
            entry["stack"] = _redact_text("".join(traceback.format_tb(record.exc_info[2])))
        return json.dumps(entry, default=str, separators=(",", ":"))


class _StdoutHandler(logging.Handler):
    """Writes to whatever ``sys.stdout`` is at emit time (plays well with capture)."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            sys.stdout.write(self.format(record) + "\n")
            sys.stdout.flush()
        except Exception:  # pragma: no cover - logging must never raise
            self.handleError(record)


class Logger:
    """Small wrapper: ``log.info("msg", key=value)`` and ``log.bind(...)``."""

    def __init__(self, inner: logging.Logger, context: Mapping[str, Any] | None = None) -> None:
        self._inner = inner
        self._context = dict(context or {})

    def bind(self, **fields: Any) -> Logger:
        return Logger(self._inner, {**self._context, **fields})

    def _log(self, level: int, msg: str, exc_info: bool, fields: dict[str, Any]) -> None:
        if self._inner.isEnabledFor(level):
            self._inner.log(level, msg, exc_info=exc_info, extra={"fields": {**self._context, **fields}})

    def debug(self, msg: str, **fields: Any) -> None:
        self._log(logging.DEBUG, msg, False, fields)

    def info(self, msg: str, **fields: Any) -> None:
        self._log(logging.INFO, msg, False, fields)

    def warning(self, msg: str, **fields: Any) -> None:
        self._log(logging.WARNING, msg, False, fields)

    def error(self, msg: str, *, exc_info: bool = False, **fields: Any) -> None:
        self._log(logging.ERROR, msg, exc_info, fields)


def get_logger(name: str, *, level: str | int = "INFO") -> Logger:
    inner = logging.getLogger(f"farrier.{name}")
    if not any(isinstance(h, _StdoutHandler) for h in inner.handlers):
        handler = _StdoutHandler()
        handler.setFormatter(JsonFormatter())
        inner.addHandler(handler)
        inner.propagate = False  # keep platform root handlers from logging a second, unredacted copy
    inner.setLevel(level if isinstance(level, int) else level.upper())
    return Logger(inner)
