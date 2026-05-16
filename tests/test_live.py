from __future__ import annotations

import os
import time
import unittest

from tripwire_server import Tripwire, safe_verify_tripwire_token
from tripwire_server.errors import TripwireApiError
from tests.test_helpers import load_fixture


def require_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"{name} is required for the live smoke suite.")
    return value


def best_effort_revoke(client: Tripwire, organization_id: str, key_id: str | None) -> None:
    if not key_id:
        return
    try:
        client.organizations.api_keys.revoke(organization_id, key_id)
    except TripwireApiError as error:
        if error.status == 404 or error.code == "request.not_found":
            return
        raise


def find_api_key(client: Tripwire, organization_id: str, key_id: str):
    cursor: str | None = None
    while True:
        page = client.organizations.api_keys.list(organization_id, limit=100, cursor=cursor)
        for item in page.items:
            if item.id == key_id:
                return item
        if not page.has_more or not page.next_cursor:
            return None
        cursor = page.next_cursor


@unittest.skipUnless(os.getenv("FOIL_LIVE_SMOKE") == "1", "Set FOIL_LIVE_SMOKE=1 to run live smoke tests.")
class LiveSmokeTests(unittest.TestCase):
    def test_public_server_surface(self) -> None:
        client = Tripwire(
            secret_key=require_env("FOIL_SMOKE_SECRET_KEY"),
            base_url=os.getenv("FOIL_SMOKE_BASE_URL", "https://api.tripwirejs.com"),
        )
        organization_id = require_env("FOIL_SMOKE_ORGANIZATION_ID")

        created_key_id: str | None = None
        rotated_key_id: str | None = None

        try:
            sessions = client.sessions.list(limit=1)
            self.assertGreater(len(sessions.items), 0, "Smoke organization must have at least one session for the live smoke suite.")
            session_summary = sessions.items[0]
            session = client.sessions.get(session_summary.id)
            self.assertEqual(session.id, session_summary.id)

            fingerprints = client.fingerprints.list(limit=1)
            self.assertGreater(
                len(fingerprints.items),
                0,
                "Smoke organization must have at least one fingerprint for the live smoke suite.",
            )
            fingerprint_summary = fingerprints.items[0]
            fingerprint = client.fingerprints.get(fingerprint_summary.id)
            self.assertEqual(fingerprint.id, fingerprint_summary.id)

            organization = client.organizations.get(organization_id)
            self.assertEqual(organization.id, organization_id)
            updated_organization = client.organizations.update(organization_id, name=organization.name, status=organization.status)
            self.assertEqual(updated_organization.name, organization.name)
            self.assertEqual(updated_organization.status, organization.status)

            created_key = client.organizations.api_keys.create(
                organization_id,
                name=f"sdk-smoke-{int(time.time() * 1000):x}",
                environment="test",
            )
            created_key_id = created_key.id
            self.assertTrue(created_key.revealed_key.startswith("sk_"))

            listed_key = find_api_key(client, organization_id, created_key.id)
            self.assertIsNotNone(listed_key)
            if listed_key is not None:
                self.assertEqual(listed_key.id, created_key.id)

            rotated_key = client.organizations.api_keys.rotate(organization_id, created_key.id)
            rotated_key_id = rotated_key.id
            self.assertTrue(rotated_key.revealed_key.startswith("sk_"))

            fixture = load_fixture("sealed-token/vector.v1.json")
            verified = safe_verify_tripwire_token(fixture["token"], fixture["secretKey"])
            self.assertTrue(verified.ok)
            if verified.ok and verified.data is not None:
                self.assertEqual(verified.data.session_id, fixture["payload"]["session_id"])
                self.assertEqual(verified.data.decision.event_id, fixture["payload"]["decision"]["event_id"])
        finally:
            best_effort_revoke(client, organization_id, rotated_key_id)
            if created_key_id != rotated_key_id:
                best_effort_revoke(client, organization_id, created_key_id)
            client.close()
