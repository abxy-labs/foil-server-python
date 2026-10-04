from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any

from .types import WebhookEventEnvelope

WEBHOOK_EVENT_TYPES = {
    "session.fingerprint.calculated",
    "session.result.persisted",
    "webhook.test",
}


def verify_webhook_signature(
    *,
    secret: str,
    timestamp: str,
    raw_body: str,
    signature: str,
    max_age_seconds: int = 5 * 60,
    now_seconds: int | None = None,
) -> bool:
    try:
        parsed_timestamp = int(timestamp)
    except ValueError:
        return False
    current = now_seconds if now_seconds is not None else int(time.time())
    if abs(current - parsed_timestamp) > max_age_seconds:
        return False
    expected = hmac.new(secret.encode("utf-8"), f"{timestamp}.{raw_body}".encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def parse_webhook_event(raw_body: str | bytes | dict[str, Any]) -> WebhookEventEnvelope:
    if isinstance(raw_body, bytes):
        value = json.loads(raw_body.decode("utf-8"))
    elif isinstance(raw_body, str):
        value = json.loads(raw_body)
    else:
        value = raw_body
    if not isinstance(value, dict):
        raise ValueError("webhook event envelope must be an object")
    if value.get("object") != "webhook_event":
        raise ValueError("webhook event object must be webhook_event")
    if not isinstance(value.get("id"), str) or not value["id"]:
        raise ValueError("webhook event id is required")
    if not isinstance(value.get("type"), str) or not value["type"]:
        raise ValueError("webhook event type is required")
    if value["type"] not in WEBHOOK_EVENT_TYPES:
        raise ValueError(f"unsupported webhook event type: {value['type']}")
    if not isinstance(value.get("created"), str) or not value["created"]:
        raise ValueError("webhook event created timestamp is required")
    data = value.get("data")
    if not isinstance(data, dict):
        raise ValueError("webhook event data must be an object")
    return WebhookEventEnvelope(
        id=value["id"],
        object="webhook_event",
        type=value["type"],
        created=value["created"],
        data=data,
    )


def verify_and_parse_webhook_event(
    *,
    secret: str,
    timestamp: str,
    raw_body: str,
    signature: str,
    max_age_seconds: int = 5 * 60,
    now_seconds: int | None = None,
) -> WebhookEventEnvelope:
    if not verify_webhook_signature(
        secret=secret,
        timestamp=timestamp,
        raw_body=raw_body,
        signature=signature,
        max_age_seconds=max_age_seconds,
        now_seconds=now_seconds,
    ):
        raise ValueError("Invalid Foil webhook signature")
    return parse_webhook_event(raw_body)
