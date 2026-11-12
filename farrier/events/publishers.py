"""Event publishing to cloud event buses: notifier types eventbridge, pubsub and eventgrid.

    {"type": "eventbridge", "bus": "farrier-events" | "arn:aws:events:eu-west-1:123456789012:event-bus/x",
     "region": "eu-west-1"}                           PutEvents: Source "farrier", DetailType = CloudEvent type,
                                                      Detail = the CloudEvent JSON (AWS credential chain)
    {"type": "pubsub", "topic": "projects/p/topics/t"}   publish: data = the CloudEvent JSON, attributes
                                                      ce-id, ce-type, ce-source, ce-specversion (Google chain)
    {"type": "eventgrid", "endpoint": "https://<topic>.<region>-1.eventgrid.azure.net/api/events",
     "key": "vault:eg-key"}                           CloudEvents batch POST; "key" (a secret reference) sends
                                                      aeg-sas-key, without it the Azure identity is used

Each publish has a 5 second timeout per attempt and at most 2 attempts.
"""
from __future__ import annotations

import base64
import json
import re
from urllib.parse import urlsplit

from farrier.security.cloud_auth import aws, azure, google
from farrier.security.cloud_auth.http import (
    CloudConfigError,
    CloudError,
    json_body,
    request,
)

EVENT_TYPES = ("eventbridge", "pubsub", "eventgrid")
TIMEOUT = 5.0
ATTEMPTS = 2
BUS_ARN = re.compile(r"^arn:aws[a-z-]*:events:(?P<region>[a-z0-9-]+):\d{12}:event-bus/[A-Za-z0-9/._-]+$")
BUS_NAME = re.compile(r"^[A-Za-z0-9/._-]{1,256}$")
# Without a key, Farrier sends its own Azure identity token: only to Event Grid itself.
EVENTGRID_HOSTS = (".eventgrid.azure.net", ".eventgrid.azure.us", ".eventgrid.chinacloudapi.cn")
TOPIC = re.compile(r"^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/topics/[A-Za-z][A-Za-z0-9._~%+-]{2,254}$")


def check(cfg: dict) -> None:
    """Validate a channel config; errors name the field."""
    kind = cfg.get("type")
    if kind == "eventbridge":
        bus = str(cfg.get("bus") or "")
        if not (BUS_ARN.match(bus) or BUS_NAME.match(bus)):
            raise ValueError("bus must be an EventBridge bus name or ARN")
        if not BUS_ARN.match(bus):
            aws.region_for("region", cfg.get("region"))     # a bus name needs a region (or AWS_REGION)
    elif kind == "pubsub":
        if not TOPIC.match(str(cfg.get("topic") or "")):
            raise ValueError("topic must be projects/<project>/topics/<topic>")
    elif kind == "eventgrid":
        u = urlsplit(str(cfg.get("endpoint") or ""))
        if u.scheme != "https" or not u.hostname:
            raise ValueError("endpoint must be the topic's https:// endpoint")
        if not cfg.get("key") and not u.hostname.lower().endswith(EVENTGRID_HOSTS):
            raise ValueError("endpoint must be an Event Grid host (*.eventgrid.azure.net, *.eventgrid.azure.us or "
                             "*.eventgrid.chinacloudapi.cn) when no key is set: Farrier's Azure identity token is sent "
                             "to it")


def publish(cfg: dict, event: dict) -> None:
    {"eventbridge": _eventbridge, "pubsub": _pubsub, "eventgrid": _eventgrid}[cfg["type"]](cfg, event)


def _eventbridge(cfg: dict, event: dict) -> None:
    bus = cfg["bus"]
    m = BUS_ARN.match(bus)
    region = m["region"] if m else aws.region_for("region (eventbridge channel)", cfg.get("region"))
    j = aws.json_call("events", "PutEvents", {"Entries": [{
        "Source": "farrier", "DetailType": event["type"], "Detail": json.dumps(event), "EventBusName": bus}]},
        region=region, what="EventBridge PutEvents")
    if j.get("FailedEntryCount"):
        e = (j.get("Entries") or [{}])[0]
        raise CloudError(f"EventBridge PutEvents rejected the event: {e.get('ErrorCode')} {e.get('ErrorMessage', '')}"
                         .strip(), code=e.get("ErrorCode"))


def _pubsub(cfg: dict, event: dict) -> None:
    topic = cfg["topic"]
    if not TOPIC.match(topic):
        raise CloudConfigError("topic must be projects/<project>/topics/<topic>")
    tok = google.default_provider().token(google.CLOUD_PLATFORM)
    msg = {"data": base64.b64encode(json.dumps(event).encode()).decode(),
           "attributes": {"ce-id": event["id"], "ce-type": event["type"], "ce-source": event["source"],
                          "ce-specversion": event["specversion"]}}
    j = json_body(request("POST", f"https://pubsub.googleapis.com/v1/{topic}:publish", what="Pub/Sub publish",
                          json={"messages": [msg]}, headers={"Authorization": f"Bearer {tok}"},
                          timeout=TIMEOUT, retries=ATTEMPTS), "Pub/Sub publish")
    if not j.get("messageIds"):
        raise CloudError("Pub/Sub publish returned no message id")


def _eventgrid(cfg: dict, event: dict) -> None:
    from farrier.security.vault import resolve_secret
    if cfg.get("key"):
        h = {"aeg-sas-key": resolve_secret(cfg["key"])}
    else:
        try:
            check(cfg)                      # a channel saved before the host rule must not get the token either
        except ValueError as e:
            raise CloudConfigError(str(e)) from None
        h = {"Authorization": f"Bearer {azure.default_provider().token(azure.EVENTGRID_SCOPE)}"}
    h["Content-Type"] = "application/cloudevents-batch+json; charset=utf-8"
    request("POST", cfg["endpoint"], what="Event Grid publish", content=json.dumps([event]).encode(), headers=h,
            timeout=TIMEOUT, retries=ATTEMPTS)
