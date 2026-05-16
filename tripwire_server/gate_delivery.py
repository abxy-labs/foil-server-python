from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from dataclasses import asdict
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .types import (
    GateApprovedWebhookPayload,
    GateApprovedWebhookTripwire,
    GateDeliveryEnvelope,
    GateDeliveryPayload,
    GateDeliveryRequest,
    GateEncryptedDeliveryResponse,
    GeneratedDeliveryKeyPair,
    WebhookEventEnvelope,
)

GATE_DELIVERY_VERSION = 1
GATE_DELIVERY_ALGORITHM = "x25519-hkdf-sha256/aes-256-gcm"
GATE_AGENT_TOKEN_ENV_SUFFIX = "_GATE_AGENT_TOKEN"
BLOCKED_GATE_ENV_VAR_KEYS = {
    "BASH_ENV",
    "BROWSER",
    "CDPATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "EDITOR",
    "ENV",
    "GIT_ASKPASS",
    "GIT_SSH_COMMAND",
    "HOME",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "NODE_OPTIONS",
    "NODE_PATH",
    "PATH",
    "PERL5OPT",
    "PERLLIB",
    "PROMPT_COMMAND",
    "PYTHONHOME",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "RUBYLIB",
    "RUBYOPT",
    "SHELLOPTS",
    "SSH_ASKPASS",
    "VISUAL",
    "XDG_CONFIG_HOME",
}
BLOCKED_GATE_ENV_VAR_PREFIXES = ("NPM_CONFIG_", "BUN_CONFIG_", "GIT_CONFIG_")
GATE_DELIVERY_HKDF_INFO = b"tripwire-gate-delivery:v1"
WEBHOOK_EVENT_TYPES = {
    "session.fingerprint.calculated",
    "session.result.persisted",
    "gate.session.approved",
    "webhook.test",
}


def derive_gate_agent_token_env_key(service_id: str) -> str:
    normalized = "_".join(filter(None, "".join(ch if ch.isalnum() else "_" for ch in service_id.strip()).split("_"))).upper()
    if not normalized:
        raise ValueError("service_id is required to derive a Gate agent token env key")
    if normalized in {"TRIPWIRE", "FOIL"}:
        return f"FOIL{GATE_AGENT_TOKEN_ENV_SUFFIX}"
    return f"{normalized}{GATE_AGENT_TOKEN_ENV_SUFFIX}"


def is_gate_managed_env_var_key(key: str) -> bool:
    return key == "FOIL_AGENT_TOKEN" or key.endswith(GATE_AGENT_TOKEN_ENV_SUFFIX)


def is_blocked_gate_env_var_key(key: str) -> bool:
    normalized = key.strip().upper()
    return normalized in BLOCKED_GATE_ENV_VAR_KEYS or any(normalized.startswith(prefix) for prefix in BLOCKED_GATE_ENV_VAR_PREFIXES)


def key_id_for_raw_x25519_public_key(raw_public_key: bytes) -> str:
    if len(raw_public_key) != 32:
        raise ValueError("X25519 public key must be 32 bytes")
    return _b64url_encode(hashlib.sha256(raw_public_key).digest())


def create_delivery_key_pair() -> GeneratedDeliveryKeyPair:
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return GeneratedDeliveryKeyPair(
        delivery=GateDeliveryRequest(
            version=GATE_DELIVERY_VERSION,
            algorithm=GATE_DELIVERY_ALGORITHM,
            key_id=key_id_for_raw_x25519_public_key(public_key),
            public_key=_b64url_encode(public_key),
        ),
        private_key=private_key,
    )


def export_delivery_private_key_pkcs8(private_key: X25519PrivateKey) -> str:
    return _b64url_encode(
        private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def import_delivery_private_key_pkcs8(value: str) -> X25519PrivateKey:
    private_key = serialization.load_der_private_key(_b64url_decode(value, "delivery.private_key_pkcs8"), password=None)
    if not isinstance(private_key, X25519PrivateKey):
        raise ValueError("delivery.private_key_pkcs8 must contain an X25519 private key")
    return private_key


def validate_gate_delivery_request(value: GateDeliveryRequest | dict[str, Any]) -> GateDeliveryRequest:
    candidate = _coerce_gate_delivery_request(value)
    if candidate.version != GATE_DELIVERY_VERSION:
        raise ValueError("delivery.version must be 1")
    if candidate.algorithm != GATE_DELIVERY_ALGORITHM:
        raise ValueError(f"delivery.algorithm must be {GATE_DELIVERY_ALGORITHM}")
    if not candidate.public_key:
        raise ValueError("delivery.public_key is required")
    if not candidate.key_id:
        raise ValueError("delivery.key_id is required")
    raw_public_key = _b64url_decode(candidate.public_key, "delivery.public_key")
    if len(raw_public_key) != 32:
        raise ValueError("delivery.public_key must be a raw X25519 public key")
    if key_id_for_raw_x25519_public_key(raw_public_key) != candidate.key_id:
        raise ValueError("delivery.key_id does not match delivery.public_key")
    return GateDeliveryRequest(
        version=GATE_DELIVERY_VERSION,
        algorithm=GATE_DELIVERY_ALGORITHM,
        key_id=candidate.key_id,
        public_key=candidate.public_key,
    )


def create_encrypted_delivery_response(input: dict[str, Any]) -> GateEncryptedDeliveryResponse:
    return GateEncryptedDeliveryResponse(
        encrypted_delivery=encrypt_gate_delivery_payload(
            input["delivery"],
            GateDeliveryPayload(version=GATE_DELIVERY_VERSION, outputs=dict(input["outputs"])),
        )
    )


def create_gate_approved_webhook_response(input: dict[str, Any]) -> GateEncryptedDeliveryResponse:
    return create_encrypted_delivery_response(input)


def validate_encrypted_gate_delivery_envelope(value: GateDeliveryEnvelope | dict[str, Any]) -> GateDeliveryEnvelope:
    candidate = _coerce_gate_delivery_envelope(value)
    if candidate.version != GATE_DELIVERY_VERSION:
        raise ValueError("encrypted_delivery.version must be 1")
    if candidate.algorithm != GATE_DELIVERY_ALGORITHM:
        raise ValueError(f"encrypted_delivery.algorithm must be {GATE_DELIVERY_ALGORITHM}")
    for field in ("key_id", "ephemeral_public_key", "salt", "iv", "ciphertext", "tag"):
        if not getattr(candidate, field):
            raise ValueError(f"encrypted_delivery.{field} is required")
    if len(_b64url_decode(candidate.ephemeral_public_key, "encrypted_delivery.ephemeral_public_key")) != 32:
        raise ValueError("encrypted_delivery.ephemeral_public_key must be 32 bytes")
    if len(_b64url_decode(candidate.salt, "encrypted_delivery.salt")) != 32:
        raise ValueError("encrypted_delivery.salt must be 32 bytes")
    if len(_b64url_decode(candidate.iv, "encrypted_delivery.iv")) != 12:
        raise ValueError("encrypted_delivery.iv must be 12 bytes")
    if len(_b64url_decode(candidate.tag, "encrypted_delivery.tag")) != 16:
        raise ValueError("encrypted_delivery.tag must be 16 bytes")
    return candidate


def encrypt_gate_delivery_payload(
    delivery: GateDeliveryRequest | dict[str, Any],
    payload: GateDeliveryPayload | dict[str, Any],
) -> GateDeliveryEnvelope:
    validated_delivery = validate_gate_delivery_request(delivery)
    payload_value = _coerce_gate_delivery_payload(payload)
    if payload_value.version != GATE_DELIVERY_VERSION:
        raise ValueError("Gate delivery payload version must be 1")
    recipient_public_key = X25519PublicKey.from_public_bytes(
        _b64url_decode(validated_delivery.public_key, "delivery.public_key")
    )
    ephemeral_private_key = X25519PrivateKey.generate()
    shared_secret = ephemeral_private_key.exchange(recipient_public_key)
    salt = os.urandom(32)
    iv = os.urandom(12)
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=GATE_DELIVERY_HKDF_INFO,
    ).derive(shared_secret)
    sealed = AESGCM(key).encrypt(iv, json.dumps(_gate_payload_to_dict(payload_value), separators=(",", ":")).encode("utf-8"), None)
    return GateDeliveryEnvelope(
        version=GATE_DELIVERY_VERSION,
        algorithm=GATE_DELIVERY_ALGORITHM,
        key_id=validated_delivery.key_id,
        ephemeral_public_key=_b64url_encode(
            ephemeral_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ),
        salt=_b64url_encode(salt),
        iv=_b64url_encode(iv),
        ciphertext=_b64url_encode(sealed[:-16]),
        tag=_b64url_encode(sealed[-16:]),
    )


def decrypt_gate_delivery_envelope(
    private_key: X25519PrivateKey,
    envelope: GateDeliveryEnvelope | dict[str, Any],
) -> GateDeliveryPayload:
    validated = validate_encrypted_gate_delivery_envelope(envelope)
    shared_secret = private_key.exchange(
        X25519PublicKey.from_public_bytes(
            _b64url_decode(validated.ephemeral_public_key, "encrypted_delivery.ephemeral_public_key")
        )
    )
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_b64url_decode(validated.salt, "encrypted_delivery.salt"),
        info=GATE_DELIVERY_HKDF_INFO,
    ).derive(shared_secret)
    plaintext = AESGCM(key).decrypt(
        _b64url_decode(validated.iv, "encrypted_delivery.iv"),
        _b64url_decode(validated.ciphertext, "encrypted_delivery.ciphertext")
        + _b64url_decode(validated.tag, "encrypted_delivery.tag"),
        None,
    )
    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except Exception as error:  # noqa: BLE001
        raise ValueError("encrypted_delivery decrypted to invalid JSON") from error
    if not isinstance(payload, dict):
        raise ValueError("encrypted_delivery payload must be an object")
    return _coerce_gate_delivery_payload(payload)


def validate_gate_approved_webhook_payload(value: GateApprovedWebhookPayload | dict[str, Any]) -> GateApprovedWebhookPayload:
    payload = _coerce_gate_approved_webhook_payload(value)
    if not payload.service_id:
        raise ValueError("service_id is required")
    if not payload.gate_session_id:
        raise ValueError("gate_session_id is required")
    if not payload.gate_account_id:
        raise ValueError("gate_account_id is required")
    if not payload.account_name:
        raise ValueError("account_name is required")
    if payload.tripwire.verdict not in {"bot", "human", "inconclusive"}:
        raise ValueError("tripwire.verdict is invalid")
    return GateApprovedWebhookPayload(
        service_id=payload.service_id,
        gate_session_id=payload.gate_session_id,
        gate_account_id=payload.gate_account_id,
        account_name=payload.account_name,
        metadata=dict(payload.metadata) if payload.metadata is not None else None,
        tripwire=GateApprovedWebhookTripwire(
            verdict=payload.tripwire.verdict,
            score=payload.tripwire.score,
        ),
        delivery=validate_gate_delivery_request(payload.delivery),
    )


def verify_gate_webhook_signature(
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
    current = now_seconds if now_seconds is not None else int(__import__("time").time())
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
    parsed_data: dict[str, Any] | GateApprovedWebhookPayload
    if value["type"] == "gate.session.approved":
        parsed_data = validate_gate_approved_webhook_payload(data)
    else:
        parsed_data = data
    return WebhookEventEnvelope(
        id=value["id"],
        object="webhook_event",
        type=value["type"],
        created=value["created"],
        data=parsed_data,
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
    if not verify_gate_webhook_signature(
        secret=secret,
        timestamp=timestamp,
        raw_body=raw_body,
        signature=signature,
        max_age_seconds=max_age_seconds,
        now_seconds=now_seconds,
    ):
        raise ValueError("Invalid Tripwire webhook signature")
    return parse_webhook_event(raw_body)


def _coerce_gate_delivery_request(value: GateDeliveryRequest | dict[str, Any]) -> GateDeliveryRequest:
    if isinstance(value, GateDeliveryRequest):
        return value
    return GateDeliveryRequest(
        version=int(value.get("version", 0)),
        algorithm=str(value.get("algorithm", "")),
        key_id=str(value.get("key_id", "")),
        public_key=str(value.get("public_key", "")),
    )


def _coerce_gate_delivery_envelope(value: GateDeliveryEnvelope | dict[str, Any]) -> GateDeliveryEnvelope:
    if isinstance(value, GateDeliveryEnvelope):
        return value
    return GateDeliveryEnvelope(
        version=int(value.get("version", 0)),
        algorithm=str(value.get("algorithm", "")),
        key_id=str(value.get("key_id", "")),
        ephemeral_public_key=str(value.get("ephemeral_public_key", "")),
        salt=str(value.get("salt", "")),
        iv=str(value.get("iv", "")),
        ciphertext=str(value.get("ciphertext", "")),
        tag=str(value.get("tag", "")),
    )


def _coerce_gate_delivery_payload(value: GateDeliveryPayload | dict[str, Any]) -> GateDeliveryPayload:
    if isinstance(value, GateDeliveryPayload):
        return value
    outputs = value.get("outputs")
    if not isinstance(outputs, dict):
        raise ValueError("encrypted_delivery payload outputs must be an object")
    normalized_outputs: dict[str, str] = {}
    for key, item in outputs.items():
        if not isinstance(item, str):
            raise ValueError(f"encrypted_delivery output {key} must be a string")
        normalized_outputs[str(key)] = item
    return GateDeliveryPayload(
        version=int(value.get("version", 0)),
        outputs=normalized_outputs,
        ack_token=str(value["ack_token"]) if isinstance(value.get("ack_token"), str) else None,
    )


def _coerce_gate_approved_webhook_payload(value: GateApprovedWebhookPayload | dict[str, Any]) -> GateApprovedWebhookPayload:
    if isinstance(value, GateApprovedWebhookPayload):
        return value
    if "event" in value:
        raise ValueError("webhook payload must not include event; use the webhook event envelope type")
    tripwire = value.get("tripwire")
    if not isinstance(tripwire, dict):
        raise ValueError("tripwire must be an object")
    metadata = value.get("metadata")
    if metadata is not None and not isinstance(metadata, dict):
        raise ValueError("metadata must be an object or null")
    return GateApprovedWebhookPayload(
        service_id=str(value.get("service_id", "")),
        gate_session_id=str(value.get("gate_session_id", "")),
        gate_account_id=str(value.get("gate_account_id", "")),
        account_name=str(value.get("account_name", "")),
        metadata=dict(metadata) if isinstance(metadata, dict) else None,
        tripwire=GateApprovedWebhookTripwire(
            verdict=str(tripwire.get("verdict", "")),
            score=float(tripwire["score"]) if isinstance(tripwire.get("score"), (float, int)) else None,
        ),
        delivery=_coerce_gate_delivery_request(value.get("delivery", {})),
    )


def _gate_payload_to_dict(payload: GateDeliveryPayload) -> dict[str, Any]:
    data = {
        "version": payload.version,
        "outputs": payload.outputs,
    }
    if payload.ack_token:
        data["ack_token"] = payload.ack_token
    return data


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("utf-8")


def _b64url_decode(value: str, label: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        return base64.urlsafe_b64decode((value + padding).encode("utf-8"))
    except Exception as error:  # noqa: BLE001
        raise ValueError(f"invalid {label}") from error
