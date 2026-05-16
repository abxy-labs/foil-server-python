from __future__ import annotations

import base64
import hashlib
import json
import os
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .client import _parse_decision, _parse_request_context, _parse_score_breakdown, _parse_visitor_fingerprint_link
from .errors import TripwireConfigurationError, TripwireTokenVerificationError
from .types import Attribution, VerificationResult, VerifiedTripwireSignal, VerifiedTripwireToken

VERSION = 0x01


def _resolve_secret(secret_key: str | None) -> str:
    resolved = secret_key or os.getenv("FOIL_SECRET_KEY")
    if not resolved:
        raise TripwireConfigurationError(
            "Missing Tripwire secret key. Pass secret_key explicitly or set FOIL_SECRET_KEY."
        )
    return resolved


def _normalize_secret(secret_key_or_hash: str) -> str:
    if len(secret_key_or_hash) == 64 and all(char in "0123456789abcdefABCDEF" for char in secret_key_or_hash):
        return secret_key_or_hash.lower()
    return hashlib.sha256(secret_key_or_hash.encode("utf-8")).hexdigest()


def _derive_key(secret_key_or_hash: str) -> bytes:
    material = f"{_normalize_secret(secret_key_or_hash)}\0sealed-results".encode("utf-8")
    return hashlib.sha256(material).digest()


def _build_verified_token(payload: dict[str, object]) -> VerifiedTripwireToken:
    request_raw = payload.get("request")
    decision_raw = payload.get("decision")
    if not isinstance(request_raw, dict) or not isinstance(decision_raw, dict):
        raise TripwireTokenVerificationError("Tripwire token payload is invalid.")

    signals: list[VerifiedTripwireSignal] = []
    for signal_raw in payload.get("signals", []):
        if not isinstance(signal_raw, dict):
            continue
        signals.append(
            VerifiedTripwireSignal(
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

    return VerifiedTripwireToken(
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


def verify_tripwire_token(sealed_token: str, secret_key: str | None = None) -> VerifiedTripwireToken:
    try:
        resolved_secret = _resolve_secret(secret_key)
        raw = base64.b64decode(sealed_token)
        if len(raw) < 29:
            raise TripwireTokenVerificationError("Tripwire token is too short.")

        version = raw[0]
        if version != VERSION:
            raise TripwireTokenVerificationError(f"Unsupported Tripwire token version: {version}")

        nonce = raw[1:13]
        ciphertext = raw[13:-16]
        tag = raw[-16:]

        decryptor = Cipher(
            algorithms.AES(_derive_key(resolved_secret)),
            modes.GCM(nonce, tag),
        ).decryptor()
        compressed = decryptor.update(ciphertext) + decryptor.finalize()
        payload = json.loads(zlib.decompress(compressed).decode("utf-8"))
        if not isinstance(payload, dict):
            raise TripwireTokenVerificationError("Tripwire token payload is invalid.")
        return _build_verified_token(payload)
    except (TripwireConfigurationError, TripwireTokenVerificationError):
        raise
    except Exception as error:  # noqa: BLE001
        raise TripwireTokenVerificationError("Failed to verify Tripwire token.") from error


def safe_verify_tripwire_token(
    sealed_token: str,
    secret_key: str | None = None,
) -> VerificationResult:
    try:
        return VerificationResult(ok=True, data=verify_tripwire_token(sealed_token, secret_key))
    except (TripwireConfigurationError, TripwireTokenVerificationError) as error:
        return VerificationResult(ok=False, error=error)
