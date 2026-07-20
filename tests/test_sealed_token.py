from __future__ import annotations

import os
import unittest

from foil_server import safe_verify_foil_token, verify_foil_token
from foil_server.errors import FoilConfigurationError, FoilTokenVerificationError
from tests.test_helpers import load_fixture


class SealedTokenTests(unittest.TestCase):
    def test_verify_vector_with_plaintext_secret(self) -> None:
        fixture = load_fixture("sealed-token/vector.v1.json")
        verified = verify_foil_token(fixture["token"], fixture["secretKey"])
        self.assertEqual(verified.raw, fixture["payload"])

    def test_verify_vector_with_secret_hash(self) -> None:
        fixture = load_fixture("sealed-token/vector.v1.json")
        verified = verify_foil_token(fixture["token"], fixture["secretHash"])
        self.assertEqual(verified.raw, fixture["payload"])

    def test_verify_multi_recipient_vector_with_every_active_key(self) -> None:
        fixture = load_fixture("sealed-token/vector.v2.json")
        for secret in fixture["secretKeys"] + fixture["secretHashes"]:
            verified = verify_foil_token(fixture["token"], secret)
            self.assertEqual(verified.raw, fixture["payload"])

    def test_invalid_token_returns_failure_result(self) -> None:
        fixture = load_fixture("sealed-token/invalid.json")
        result = safe_verify_foil_token(fixture["token"], "sk_live_fixture_secret")
        self.assertFalse(result.ok)
        self.assertIsInstance(result.error, FoilTokenVerificationError)

    def test_missing_secret_raises_configuration_error(self) -> None:
        fixture = load_fixture("sealed-token/vector.v1.json")
        original = os.environ.pop("FOIL_SECRET_KEY", None)
        try:
            with self.assertRaises(FoilConfigurationError):
                verify_foil_token(fixture["token"])
        finally:
            if original is not None:
                os.environ["FOIL_SECRET_KEY"] = original
