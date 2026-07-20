from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .client import _parse_decision, _parse_request_context, _parse_score_breakdown, _parse_visitor_fingerprint_link
from .errors import FoilConfigurationError, FoilTokenVerificationError
from .types import Attribution, VerificationResult, VerifiedFoilSignal, VerifiedFoilToken

LEGACY_VERSION = 0x01
MULTI_RECIPIENT_VERSION = 0x02
NONCE_BYTES = 12
TAG_BYTES = 16
CONTENT_KEY_BYTES = 32
RECIPIENT_ID_BYTES = 32
MAX_RECIPIENTS = 256
V2_HEADER_BYTES = 1 + 2 + NONCE_BYTES + 4
V2_RECIPIENT_BYTES = RECIPIENT_ID_BYTES + NONCE_BYTES + CONTENT_KEY_BYTES + TAG_BYTES
V2_PAYLOAD_AAD_PREFIX = b"foil-sealed-results-v2\0payload\0"
V2_WRAP_AAD_PREFIX = b"foil-sealed-results-v2\0recipient\0"


def _resolve_secret(secret_key: str | None) -> str:
    resolved = secret_key or os.getenv("FOIL_SECRET_KEY")
    if not resolved:
        raise FoilConfigurationError(
            "Missing Foil secret key. Pass secret_key explicitly or set FOIL_SECRET_KEY."
        )
    return resolved


def _normalize_secret(secret_key_or_hash: str) -> str:
    if len(secret_key_or_hash) == 64 and all(char in "0123456789abcdefABCDEF" for char in secret_key_or_hash):
        return secret_key_or_hash.lower()
    return hashlib.sha256(secret_key_or_hash.encode("utf-8")).hexdigest()


def _derive_key(secret_key_or_hash: str) -> bytes:
    material = f"{_normalize_secret(secret_key_or_hash)}\0sealed-results".encode("utf-8")
    return hashlib.sha256(material).digest()


def _decrypt_gcm(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
    if aad:
        decryptor.authenticate_additional_data(aad)
    return decryptor.update(ciphertext) + decryptor.finalize()


def _decrypt_payload(raw: bytes, secret_key: str) -> bytes:
    version = raw[0]
    if version == LEGACY_VERSION:
        return _decrypt_gcm(raw[13:-TAG_BYTES], _derive_key(secret_key), raw[1:13], raw[-TAG_BYTES:])
    if version != MULTI_RECIPIENT_VERSION:
        raise FoilTokenVerificationError(f"Unsupported Foil token version: {version}")
    if len(raw) < V2_HEADER_BYTES + TAG_BYTES + V2_RECIPIENT_BYTES:
        raise FoilTokenVerificationError("Foil token is too short.")

    recipient_count = int.from_bytes(raw[1:3], "big")
    if recipient_count < 1 or recipient_count > MAX_RECIPIENTS:
        raise FoilTokenVerificationError("Foil token has an invalid recipient count.")
    payload_length = int.from_bytes(raw[15:19], "big")
    payload_start = V2_HEADER_BYTES
    payload_tag_start = payload_start + payload_length
    recipients_start = payload_tag_start + TAG_BYTES
    if payload_length < 1 or recipients_start + recipient_count * V2_RECIPIENT_BYTES != len(raw):
        raise FoilTokenVerificationError("Foil token has an invalid length.")

    expected_id = hashlib.sha256(
        f"{_normalize_secret(secret_key)}\0sealed-results-recipient-id".encode("utf-8")
    ).digest()
    recipient_ids = b"".join(
        raw[
            recipients_start + index * V2_RECIPIENT_BYTES :
            recipients_start + index * V2_RECIPIENT_BYTES + RECIPIENT_ID_BYTES
        ]
        for index in range(recipient_count)
    )
    content_key: bytes | None = None
    for index in range(recipient_count):
        entry_start = recipients_start + index * V2_RECIPIENT_BYTES
        recipient_id = raw[entry_start : entry_start + RECIPIENT_ID_BYTES]
        if not hmac.compare_digest(recipient_id, expected_id):
            continue
        nonce_start = entry_start + RECIPIENT_ID_BYTES
        wrapped_key_start = nonce_start + NONCE_BYTES
        tag_start = wrapped_key_start + CONTENT_KEY_BYTES
        content_key = _decrypt_gcm(
            raw[wrapped_key_start:tag_start],
            _derive_key(secret_key),
            raw[nonce_start:wrapped_key_start],
            raw[tag_start : tag_start + TAG_BYTES],
            V2_WRAP_AAD_PREFIX + recipient_id,
        )
        break
    if content_key is None or len(content_key) != CONTENT_KEY_BYTES:
        raise FoilTokenVerificationError("Secret key is not a recipient of this Foil token.")

    return _decrypt_gcm(
        raw[payload_start:payload_tag_start],
        content_key,
        raw[3:15],
        raw[payload_tag_start:recipients_start],
        V2_PAYLOAD_AAD_PREFIX + raw[:V2_HEADER_BYTES] + recipient_ids,
    )


def _build_verified_token(payload: dict[str, object]) -> VerifiedFoilToken:
    request_raw = payload.get("request")
    decision_raw = payload.get("decision")
    if not isinstance(request_raw, dict) or not isinstance(decision_raw, dict):
        raise FoilTokenVerificationError("Foil token payload is invalid.")

    signals: list[VerifiedFoilSignal] = []
    for signal_raw in payload.get("signals", []):
        if not isinstance(signal_raw, dict):
            continue
        signals.append(
            VerifiedFoilSignal(
                id=str(signal_raw.get("id", "")),
                category=str(signal_raw.get("category", "")),
                confidence=str(signal_raw.get("confidence", "")),
                score=int(signal_raw.get("score", 0)),
                raw=dict(signal_raw),
            )
        )

    attribution_raw = payload.get("attribution")
    attribution_dict = dict(attribution_raw) if isinstance(attribution_raw, dict) else {}
    bot_attribution = attribution_dict.get("bot")

    score_breakdown_raw = payload.get("score_breakdown")
    score_breakdown = _parse_score_breakdown(dict(score_breakdown_raw)) if isinstance(score_breakdown_raw, dict) else _parse_score_breakdown({})

    return VerifiedFoilToken(
        object=str(payload.get("object", "")),
        session_id=str(payload.get("session_id", "")),
        decision=_parse_decision(dict(decision_raw)),
        request=_parse_request_context(dict(request_raw)),
        visitor_fingerprint=_parse_visitor_fingerprint_link(
            dict(payload["visitor_fingerprint"]) if isinstance(payload.get("visitor_fingerprint"), dict) else None
        ),
        signals=signals,
        score_breakdown=score_breakdown,
        attribution=Attribution(
            bot=dict(bot_attribution) if isinstance(bot_attribution, dict) else None,
            raw=attribution_dict,
        ),
        embed=dict(payload["embed"]) if isinstance(payload.get("embed"), dict) else None,
        raw=dict(payload),
    )


def verify_foil_token(sealed_token: str, secret_key: str | None = None) -> VerifiedFoilToken:
    try:
        resolved_secret = _resolve_secret(secret_key)
        raw = base64.b64decode(sealed_token)
        if len(raw) < 29:
            raise FoilTokenVerificationError("Foil token is too short.")

        compressed = _decrypt_payload(raw, resolved_secret)
        payload = json.loads(zlib.decompress(compressed).decode("utf-8"))
        if not isinstance(payload, dict):
            raise FoilTokenVerificationError("Foil token payload is invalid.")
        return _build_verified_token(payload)
    except (FoilConfigurationError, FoilTokenVerificationError):
        raise
    except Exception as error:  # noqa: BLE001
        raise FoilTokenVerificationError("Failed to verify Foil token.") from error


def safe_verify_foil_token(
    sealed_token: str,
    secret_key: str | None = None,
) -> VerificationResult:
    try:
        return VerificationResult(ok=True, data=verify_foil_token(sealed_token, secret_key))
    except (FoilConfigurationError, FoilTokenVerificationError) as error:
        return VerificationResult(ok=False, error=error)
