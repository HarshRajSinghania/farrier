"""Unwrap the CloudEvent from each cloud's delivery envelope.

* AWS EventBridge: ``{"source": "farrier", "detail-type": <type>, "detail": <CloudEvent>}``
* Google Pub/Sub (via Eventarc): ``message.data`` is base64 CloudEvent JSON,
  attributes carry ``ce-type`` and ``ce-id``.
* Azure Event Grid (CloudEvents 1.0 schema): the binding exposes the envelope
  fields; the event's ``data`` is our ``data``.

Idempotency always keys on the CloudEvent ``id``, never the transport's own
message id (EventBridge and Pub/Sub assign a new one if the publisher retries).
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Mapping
from typing import Any

from .errors import InvalidEvent

EVENTBRIDGE_SOURCE = "farrier"


def from_eventbridge(envelope: Mapping[str, Any]) -> Mapping[str, Any]:
    if not isinstance(envelope, Mapping) or "detail" not in envelope:
        raise InvalidEvent(["$: not an EventBridge event (no detail)"])
    if envelope.get("source") != EVENTBRIDGE_SOURCE:
        raise InvalidEvent(["$.source: EventBridge source must be 'farrier'"])
    detail = envelope["detail"]
    if not isinstance(detail, Mapping):
        raise InvalidEvent(["$.detail: must be an object"])
    if envelope.get("detail-type") != detail.get("type"):
        raise InvalidEvent(["$.detail-type: does not match detail.type"])
    return detail


def from_pubsub(message: Mapping[str, Any]) -> Mapping[str, Any]:
    """``message`` is the Pub/Sub message (``cloud_event.data["message"]``)."""
    if not isinstance(message, Mapping) or "data" not in message:
        raise InvalidEvent(["$.message: has no data"])
    try:
        body = json.loads(base64.b64decode(message["data"], validate=True))
    except (binascii.Error, ValueError, TypeError):
        raise InvalidEvent(["$.message.data: is not base64 JSON"]) from None
    if not isinstance(body, Mapping):
        raise InvalidEvent(["$.message.data: must decode to an object"])
    attrs = message.get("attributes") or {}
    for attr, field in (("ce-type", "type"), ("ce-id", "id")):
        if attr in attrs and attrs[attr] != body.get(field):
            raise InvalidEvent([f"$.message.attributes.{attr}: does not match the event {field}"])
    return body


def from_eventgrid(
    *, id: str, type: str, subject: str | None, time: str | None, source: str | None, data: Any
) -> dict[str, Any]:
    """Rebuild the structured CloudEvent from Event Grid binding fields."""
    return {
        "specversion": "1.0",
        "id": id,
        "source": source,
        "type": type,
        "time": time,
        "subject": subject,
        "datacontenttype": "application/json",
        "data": data,
    }
