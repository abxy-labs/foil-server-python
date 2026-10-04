from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Generic, TypeVar

T = TypeVar("T")


@dataclass(frozen=True)
class ListResult(Generic[T]):
    items: list[T]
    limit: int
    has_more: bool
    next_cursor: str | None = None


@dataclass(frozen=True)
class DecisionManipulation:
    score: int | None
    verdict: str | None


@dataclass(frozen=True)
class Decision:
    event_id: str
    verdict: str
    risk_score: int
    phase: str | None
    is_provisional: bool | None
    manipulation: DecisionManipulation | None
    evaluation_duration_ms: int | None
    evaluated_at: str


@dataclass(frozen=True)
class VisitorFingerprintLink:
    object: str
    id: str
    confidence: int | None
    identified_at: str | None


@dataclass(frozen=True)
class RequestContext:
    user_agent: str
    url: str
    screen_size: str | None
    is_touch_capable: bool | None
    ip_address: str


@dataclass(frozen=True)
class SessionDetailRequest:
    url: str
    referrer: str | None
    user_agent: str


@dataclass(frozen=True)
class SessionDecision:
    event_id: str
    automation_status: str
    risk_score: int
    evaluation_phase: str | None
    decision_status: str
    evaluated_at: str


@dataclass(frozen=True)
class SessionSummary:
    object: str
    id: str
    created_at: str | None
    client_user_id: str | None
    latest_decision: Decision
    visitor_fingerprint: VisitorFingerprintLink | None


@dataclass(frozen=True)
class SessionDetail:
    object: str
    id: str
    created_at: str | None
    client_user_id: str | None
    decision: SessionDecision
    highlights: list[dict[str, Any]]
    attribution: dict[str, Any] | None
    web_bot_auth: dict[str, Any] | None
    network: dict[str, Any]
    runtime_integrity: dict[str, Any]
    native_runtime_integrity: dict[str, Any] | None
    native_app: dict[str, Any] | None
    native_carrier: dict[str, Any] | None
    native_motion_print: dict[str, Any] | None
    device_identity: dict[str, Any] | None
    install_id: str | None
    visitor_fingerprint: dict[str, Any] | None
    connection_fingerprint: dict[str, Any]
    previous_decisions: list[SessionDecision]
    request: SessionDetailRequest
    browser: dict[str, Any]
    device: dict[str, Any]
    analysis_coverage: dict[str, bool]
    signals_fired: list[dict[str, Any]]
    client_telemetry: dict[str, Any]


@dataclass(frozen=True)
class VisitorFingerprintLifecycle:
    first_seen_at: str
    last_seen_at: str
    seen_count: int
    expires_at: str


@dataclass(frozen=True)
class VisitorFingerprintLatestRequest:
    user_agent: str
    ip_address: str


@dataclass(frozen=True)
class VisitorFingerprintStorage:
    cookies: bool
    local_storage: bool
    indexed_db: bool
    service_worker: bool
    window_name: bool


@dataclass(frozen=True)
class VisitorFingerprintAnchors:
    webgl_hash: str | None
    parameters_hash: str | None
    audio_hash: str | None


@dataclass(frozen=True)
class VisitorFingerprintSummary:
    object: str
    id: str
    lifecycle: VisitorFingerprintLifecycle
    latest_request: VisitorFingerprintLatestRequest
    storage: VisitorFingerprintStorage
    anchors: VisitorFingerprintAnchors


@dataclass(frozen=True)
class ScoreBreakdown:
    categories: dict[str, int]


@dataclass(frozen=True)
class VisitorFingerprintSessionSummary:
    session_id: str
    decision: Decision
    request: RequestContext
    score_breakdown: ScoreBreakdown


@dataclass(frozen=True)
class VisitorFingerprintComponents:
    vector: list[int]


@dataclass(frozen=True)
class VisitorFingerprintActivity:
    sessions: list[VisitorFingerprintSessionSummary]


@dataclass(frozen=True)
class VisitorFingerprintDetail(VisitorFingerprintSummary):
    components: VisitorFingerprintComponents
    activity: VisitorFingerprintActivity


@dataclass(frozen=True)
class Organization:
    object: str
    id: str
    name: str
    slug: str
    status: str
    created_at: str
    updated_at: str | None


@dataclass(frozen=True)
class ApiKey:
    object: str
    id: str
    type: str
    name: str
    environment: str
    allowed_origins: list[str] | None
    scopes: list[str] | None
    rate_limit: int | None
    status: str
    key_preview: str
    display_key: str | None
    last_used_at: str | None
    created_at: str
    rotated_at: str | None
    revoked_at: str | None
    grace_expires_at: str | None


@dataclass(frozen=True)
class IssuedApiKey(ApiKey):
    revealed_key: str


@dataclass(frozen=True)
class WebhookEndpoint:
    object: str
    id: str
    name: str
    url: str
    status: str
    event_types: list[str]
    created_at: str
    updated_at: str
    signing_secret: str | None = None


@dataclass(frozen=True)
class WebhookDelivery:
    object: str
    id: str
    event_id: str
    endpoint_id: str
    event_type: str
    status: str
    attempts: int
    response_status: int | None
    response_body: str | None
    error: str | None
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class EventSubject:
    type: str
    id: str


@dataclass(frozen=True)
class Event:
    object: str
    id: str
    type: str
    subject: EventSubject
    data: dict[str, Any]
    webhook_deliveries: list[WebhookDelivery]
    created_at: str


@dataclass(frozen=True)
class WebhookTest:
    object: str
    event_id: str
    delivery_ids: list[str]
    latest_delivery: WebhookDelivery | None


@dataclass(frozen=True)
class WebhookEventEnvelope:
    id: str
    object: str
    type: str
    created: str
    data: dict[str, Any]


@dataclass(frozen=True)
class VerifiedFoilSignal:
    id: str
    category: str
    confidence: str
    score: int
    raw: dict[str, Any]


@dataclass(frozen=True)
class Attribution:
    bot: dict[str, Any] | None
    raw: dict[str, Any]


@dataclass(frozen=True)
class VerifiedFoilToken:
    object: str
    session_id: str
    decision: Decision
    request: RequestContext
    visitor_fingerprint: VisitorFingerprintLink | None
    signals: list[VerifiedFoilSignal]
    score_breakdown: ScoreBreakdown
    attribution: Attribution
    embed: dict[str, Any] | None
    raw: dict[str, Any]


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    data: VerifiedFoilToken | None = None
    error: Exception | None = None
