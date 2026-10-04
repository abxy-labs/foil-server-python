from __future__ import annotations

import json
import unittest

from foil_server import (
    parse_webhook_event,
    verify_and_parse_webhook_event,
    verify_webhook_signature,
)
from tests.test_helpers import load_fixture


class WebhookTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = load_fixture("webhooks/signature.json")

    def _verify(self, **overrides: object) -> bool:
        params = {
            "secret": self.fixture["secret"],
            "timestamp": self.fixture["timestamp"],
            "raw_body": self.fixture["raw_body"],
            "signature": self.fixture["signature"],
            "now_seconds": self.fixture["now_seconds"],
            **overrides,
        }
        return verify_webhook_signature(**params)  # type: ignore[arg-type]

    def test_valid_signature_verifies(self) -> None:
        self.assertTrue(self._verify())

    def test_tampered_signature_body_or_secret_is_rejected(self) -> None:
        self.assertFalse(self._verify(signature=self.fixture["invalid_signature"]))
        self.assertFalse(self._verify(signature="short"))
        self.assertFalse(self._verify(raw_body=self.fixture["raw_body"] + " "))
        self.assertFalse(self._verify(secret="whsec_other"))

    def test_expired_and_malformed_timestamps_are_rejected(self) -> None:
        self.assertFalse(self._verify(timestamp=self.fixture["expired_timestamp"]))
        self.assertFalse(self._verify(timestamp="not-a-timestamp"))

    def test_custom_max_age_is_honored(self) -> None:
        self.assertTrue(self._verify(now_seconds=self.fixture["now_seconds"] + 600, max_age_seconds=900))

    def test_parse_session_result_persisted_event(self) -> None:
        for raw in (self.fixture["raw_body"], self.fixture["raw_body"].encode("utf-8"), json.loads(self.fixture["raw_body"])):
            event = parse_webhook_event(raw)
            self.assertEqual(event.object, "webhook_event")
            self.assertEqual(event.type, "session.result.persisted")
            self.assertEqual(event.id, "wevt_0123456789abcdef0123456789abcdef")
            self.assertEqual(event.data["session"]["id"], "sid_0123456789abcdefghjkmnpqrs")

    def test_parse_webhook_test_event(self) -> None:
        event = parse_webhook_event(
            {
                "id": "wevt_0123456789abcdefghjkmnpqrs",
                "object": "webhook_event",
                "type": "webhook.test",
                "created": "2026-04-27T00:00:00.000Z",
                "data": {},
            }
        )
        self.assertEqual(event.type, "webhook.test")

    def test_parse_rejects_unsupported_or_malformed_events(self) -> None:
        base = {
            "id": "wevt_0123456789abcdefghjkmnpqrs",
            "object": "webhook_event",
            "type": "session.result.persisted",
            "created": "2026-04-27T00:00:00.000Z",
            "data": {},
        }
        with self.assertRaisesRegex(ValueError, "unsupported webhook event type"):
            parse_webhook_event({**base, "type": "unknown.event"})
        with self.assertRaisesRegex(ValueError, "webhook_event"):
            parse_webhook_event({**base, "object": "event"})
        with self.assertRaisesRegex(ValueError, "data must be an object"):
            parse_webhook_event({**base, "data": []})
        with self.assertRaisesRegex(ValueError, "must be an object"):
            parse_webhook_event(json.dumps([base]))

    def test_verify_and_parse_checks_signature_first(self) -> None:
        event = verify_and_parse_webhook_event(
            secret=self.fixture["secret"],
            timestamp=self.fixture["timestamp"],
            raw_body=self.fixture["raw_body"],
            signature=self.fixture["signature"],
            now_seconds=self.fixture["now_seconds"],
        )
        self.assertEqual(event.type, "session.result.persisted")
        with self.assertRaisesRegex(ValueError, "Invalid Foil webhook signature"):
            verify_and_parse_webhook_event(
                secret=self.fixture["secret"],
                timestamp=self.fixture["timestamp"],
                raw_body=self.fixture["raw_body"],
                signature=self.fixture["invalid_signature"],
                now_seconds=self.fixture["now_seconds"],
            )


if __name__ == "__main__":
    unittest.main()
