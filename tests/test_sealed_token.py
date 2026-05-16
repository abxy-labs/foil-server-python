from __future__ import annotations

import os
import unittest

from tripwire_server import safe_verify_tripwire_token, verify_tripwire_token
from tripwire_server.errors import TripwireConfigurationError, TripwireTokenVerificationError
from tests.test_helpers import load_fixture


class SealedTokenTests(unittest.TestCase):
    def test_verify_vector_with_plaintext_secret(self) -> None:
        fixture = load_fixture("sealed-token/vector.v1.json")
        verified = verify_tripwire_token(fixture["token"], fixture["secretKey"])
        self.assertEqual(verified.raw, fixture["payload"])

    def test_verify_vector_with_secret_hash(self) -> None:
        fixture = load_fixture("sealed-token/vector.v1.json")
        verified = verify_tripwire_token(fixture["token"], fixture["secretHash"])
        self.assertEqual(verified.raw, fixture["payload"])

    def test_invalid_token_returns_failure_result(self) -> None:
        fixture = load_fixture("sealed-token/invalid.json")
        result = safe_verify_tripwire_token(fixture["token"], "sk_live_fixture_secret")
        self.assertFalse(result.ok)
        self.assertIsInstance(result.error, TripwireTokenVerificationError)

    def test_missing_secret_raises_configuration_error(self) -> None:
        fixture = load_fixture("sealed-token/vector.v1.json")
        original = os.environ.pop("FOIL_SECRET_KEY", None)
        try:
            with self.assertRaises(TripwireConfigurationError):
                verify_tripwire_token(fixture["token"])
        finally:
            if original is not None:
                os.environ["FOIL_SECRET_KEY"] = original
