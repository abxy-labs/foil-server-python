from __future__ import annotations

import base64
import hashlib
import json
import os
import unittest
import zlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from foil_server import safe_verify_foil_token, verify_foil_token
from foil_server.errors import FoilConfigurationError, FoilTokenVerificationError
from tests.test_helpers import load_fixture

CAP_TEST_SECRET = "sk_live_cap_test"


def seal_legacy_token(payload: dict[str, object], secret_key: str) -> str:
    secret_hash = hashlib.sha256(secret_key.encode("utf-8")).hexdigest()
    key = hashlib.sha256(f"{secret_hash}\0sealed-results".encode("utf-8")).digest()
    nonce = os.urandom(12)
    sealed = AESGCM(key).encrypt(nonce, zlib.compress(json.dumps(payload).encode("utf-8")), None)
    return base64.b64encode(b"\x01" + nonce + sealed).decode("ascii")


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

    def test_accepts_payload_just_under_size_cap(self) -> None:
        payload = dict(load_fixture("sealed-token/vector.v1.json")["payload"])
        payload["padding"] = "a" * (1024 * 1024 - len(json.dumps(payload)) - 64)
        verified = verify_foil_token(seal_legacy_token(payload, CAP_TEST_SECRET), CAP_TEST_SECRET)
        self.assertEqual(verified.raw, payload)

    def test_rejects_authentic_token_that_decompresses_past_size_cap(self) -> None:
        payload = dict(load_fixture("sealed-token/vector.v1.json")["payload"])
        payload["padding"] = "a" * (2 * 1024 * 1024)
        with self.assertRaisesRegex(FoilTokenVerificationError, "^Foil token payload is too large\\.$"):
            verify_foil_token(seal_legacy_token(payload, CAP_TEST_SECRET), CAP_TEST_SECRET)

    def test_missing_secret_raises_configuration_error(self) -> None:
        fixture = load_fixture("sealed-token/vector.v1.json")
        original = os.environ.pop("FOIL_SECRET_KEY", None)
        try:
            with self.assertRaises(FoilConfigurationError):
                verify_foil_token(fixture["token"])
        finally:
            if original is not None:
                os.environ["FOIL_SECRET_KEY"] = original
