from __future__ import annotations

import os
from typing import Any, Iterator

import httpx

from .errors import TripwireApiError, TripwireConfigurationError
from .types import (
    ApiKey,
    AgentTokenVerification,
    Attribution,
    Decision,
    DecisionManipulation,
    Event,
    EventSubject,
    GateDashboardLogin,
    GateDeliveryBundle,
    GateDeliveryEnvelope,
    GateLoginSession,
    GateManagedService,
    GateRegistryEntry,
    GateServiceBranding,
    GateServiceConsent,
    GateServiceEnvVar,
    GateServiceSdkInstall,
    GateSessionCreate,
    GateSessionDeliveryAcknowledgement,
    GateSessionPollData,
    IssuedApiKey,
    ListResult,
    RequestContext,
    ScoreBreakdown,
    SessionDetail,
    SessionDecision,
    SessionDetailRequest,
    SessionSummary,
    Organization,
    VerifiedTripwireSignal,
    VerificationResult,
    VerifiedTripwireToken,
    VisitorFingerprintActivity,
    VisitorFingerprintAnchors,
    VisitorFingerprintComponents,
    VisitorFingerprintDetail,
    VisitorFingerprintLatestRequest,
    VisitorFingerprintLifecycle,
    VisitorFingerprintLink,
    VisitorFingerprintSessionSummary,
    VisitorFingerprintStorage,
    VisitorFingerprintSummary,
    WebhookDelivery,
    WebhookEndpoint,
    WebhookTest,
)

DEFAULT_BASE_URL = "https://api.tripwirejs.com"
DEFAULT_TIMEOUT = 30.0
SDK_CLIENT_HEADER = "tripwire-server-python/0.1.0"


def _compact_query(query: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in query.items() if value is not None}


def _parse_decision(data: dict[str, Any]) -> Decision:
    manipulation_raw = data.get("manipulation")
    manipulation = None
    if isinstance(manipulation_raw, dict):
        manipulation = DecisionManipulation(
            score=int(manipulation_raw["score"]) if isinstance(manipulation_raw.get("score"), int) else None,
            verdict=manipulation_raw.get("verdict")
            if isinstance(manipulation_raw.get("verdict"), str) or manipulation_raw.get("verdict") is None
            else None,
        )

    return Decision(
        event_id=str(data["event_id"]),
        verdict=str(data["verdict"]),
        risk_score=int(data["risk_score"]),
        phase=data.get("phase") if isinstance(data.get("phase"), str) or data.get("phase") is None else None,
        is_provisional=data.get("is_provisional")
        if isinstance(data.get("is_provisional"), bool) or data.get("is_provisional") is None
        else None,
        manipulation=manipulation,
        evaluation_duration_ms=int(data["evaluation_duration_ms"])
        if isinstance(data.get("evaluation_duration_ms"), int)
        else None,
        evaluated_at=str(data["evaluated_at"]),
    )


def _parse_request_context(data: dict[str, Any]) -> RequestContext:
    return RequestContext(
        user_agent=str(data["user_agent"]),
        url=str(data["url"]),
        screen_size=data.get("screen_size")
        if isinstance(data.get("screen_size"), str) or data.get("screen_size") is None
        else None,
        is_touch_capable=data.get("is_touch_capable")
        if isinstance(data.get("is_touch_capable"), bool) or data.get("is_touch_capable") is None
        else None,
        ip_address=str(data["ip_address"]),
    )


def _parse_session_detail_request(data: dict[str, Any]) -> SessionDetailRequest:
    return SessionDetailRequest(
        url=str(data["url"]),
        referrer=data.get("referrer")
        if isinstance(data.get("referrer"), str) or data.get("referrer") is None
        else None,
        user_agent=str(data["user_agent"]),
    )


def _parse_session_decision(data: dict[str, Any]) -> SessionDecision:
    return SessionDecision(
        event_id=str(data["event_id"]),
        automation_status=str(data["automation_status"]),
        risk_score=int(data["risk_score"]),
        evaluation_phase=data.get("evaluation_phase")
        if isinstance(data.get("evaluation_phase"), str) or data.get("evaluation_phase") is None
        else None,
        decision_status=str(data["decision_status"]),
        evaluated_at=str(data["evaluated_at"]),
    )


def _parse_visitor_fingerprint_link(data: dict[str, Any] | None) -> VisitorFingerprintLink | None:
    if data is None:
        return None
    return VisitorFingerprintLink(
        object=str(data["object"]),
        id=str(data["id"]),
        confidence=int(data["confidence"]) if isinstance(data.get("confidence"), int) else None,
        identified_at=data.get("identified_at")
        if isinstance(data.get("identified_at"), str) or data.get("identified_at") is None
        else None,
    )


def _parse_session_summary(data: dict[str, Any]) -> SessionSummary:
    return SessionSummary(
        object=str(data["object"]),
        id=str(data["id"]),
        created_at=data.get("created_at"),
        latest_decision=_parse_decision(dict(data["latest_decision"])),
        visitor_fingerprint=_parse_visitor_fingerprint_link(data.get("visitor_fingerprint")),
    )


def _parse_session_detail(data: dict[str, Any]) -> SessionDetail:
    return SessionDetail(
        object=str(data["object"]),
        id=str(data["id"]),
        created_at=data.get("created_at"),
        decision=_parse_session_decision(dict(data["decision"])),
        highlights=[dict(item) for item in data.get("highlights", []) if isinstance(item, dict)],
        attribution=dict(data.get("attribution")) if isinstance(data.get("attribution"), dict) else None,
        web_bot_auth=dict(data.get("web_bot_auth")) if isinstance(data.get("web_bot_auth"), dict) else None,
        network=dict(data.get("network", {})) if isinstance(data.get("network"), dict) else {},
        runtime_integrity=dict(data.get("runtime_integrity", {}))
        if isinstance(data.get("runtime_integrity"), dict)
        else {},
        native_runtime_integrity=dict(data.get("native_runtime_integrity"))
        if isinstance(data.get("native_runtime_integrity"), dict)
        else None,
        native_app=dict(data.get("native_app")) if isinstance(data.get("native_app"), dict) else None,
        native_carrier=dict(data.get("native_carrier")) if isinstance(data.get("native_carrier"), dict) else None,
        native_motion_print=dict(data.get("native_motion_print"))
        if isinstance(data.get("native_motion_print"), dict)
        else None,
        device_identity=dict(data.get("device_identity")) if isinstance(data.get("device_identity"), dict) else None,
        install_id=data.get("install_id") if isinstance(data.get("install_id"), str) else None,
        visitor_fingerprint=dict(data.get("visitor_fingerprint"))
        if isinstance(data.get("visitor_fingerprint"), dict)
        else None,
        connection_fingerprint=dict(data.get("connection_fingerprint", {}))
        if isinstance(data.get("connection_fingerprint"), dict)
        else {},
        previous_decisions=[_parse_session_decision(dict(item)) for item in data.get("previous_decisions", [])],
        request=_parse_session_detail_request(dict(data["request"])),
        browser=dict(data.get("browser", {})) if isinstance(data.get("browser"), dict) else {},
        device=dict(data.get("device", {})) if isinstance(data.get("device"), dict) else {},
        analysis_coverage={
            str(key): bool(value)
            for key, value in dict(data.get("analysis_coverage", {})).items()
            if isinstance(key, str)
        }
        if isinstance(data.get("analysis_coverage"), dict)
        else {},
        signals_fired=[dict(item) for item in data.get("signals_fired", []) if isinstance(item, dict)],
        client_telemetry=dict(data.get("client_telemetry", {}))
        if isinstance(data.get("client_telemetry"), dict)
        else {},
    )


def _parse_visitor_fingerprint_summary(data: dict[str, Any]) -> VisitorFingerprintSummary:
    lifecycle_raw = dict(data["lifecycle"])
    latest_request_raw = dict(data["latest_request"])
    storage_raw = dict(data["storage"])
    anchors_raw = dict(data["anchors"])

    return VisitorFingerprintSummary(
        object=str(data["object"]),
        id=str(data["id"]),
        lifecycle=VisitorFingerprintLifecycle(
            first_seen_at=str(lifecycle_raw["first_seen_at"]),
            last_seen_at=str(lifecycle_raw["last_seen_at"]),
            seen_count=int(lifecycle_raw["seen_count"]),
            expires_at=str(lifecycle_raw["expires_at"]),
        ),
        latest_request=VisitorFingerprintLatestRequest(
            user_agent=str(latest_request_raw["user_agent"]),
            ip_address=str(latest_request_raw["ip_address"]),
        ),
        storage=VisitorFingerprintStorage(
            cookies=bool(storage_raw["cookies"]),
            local_storage=bool(storage_raw["local_storage"]),
            indexed_db=bool(storage_raw["indexed_db"]),
            service_worker=bool(storage_raw["service_worker"]),
            window_name=bool(storage_raw["window_name"]),
        ),
        anchors=VisitorFingerprintAnchors(
            webgl_hash=anchors_raw.get("webgl_hash")
            if isinstance(anchors_raw.get("webgl_hash"), str) or anchors_raw.get("webgl_hash") is None
            else None,
            parameters_hash=anchors_raw.get("parameters_hash")
            if isinstance(anchors_raw.get("parameters_hash"), str) or anchors_raw.get("parameters_hash") is None
            else None,
            audio_hash=anchors_raw.get("audio_hash")
            if isinstance(anchors_raw.get("audio_hash"), str) or anchors_raw.get("audio_hash") is None
            else None,
        ),
    )


def _parse_score_breakdown(data: dict[str, Any]) -> ScoreBreakdown:
    categories_raw = data.get("categories", {})
    categories = (
        {str(key): int(value) for key, value in dict(categories_raw).items()}
        if isinstance(categories_raw, dict)
        else {}
    )
    return ScoreBreakdown(categories=categories)


def _parse_visitor_fingerprint_detail(data: dict[str, Any]) -> VisitorFingerprintDetail:
    summary = _parse_visitor_fingerprint_summary(data)
    components_raw = dict(data.get("components", {}))
    activity_raw = dict(data.get("activity", {}))

    sessions = [
        VisitorFingerprintSessionSummary(
            session_id=str(item["session_id"]),
            decision=_parse_decision(dict(item["decision"])),
            request=_parse_request_context(dict(item["request"])),
            score_breakdown=_parse_score_breakdown(dict(item["score_breakdown"])),
        )
        for item in activity_raw.get("sessions", [])
    ]

    return VisitorFingerprintDetail(
        **summary.__dict__,
        components=VisitorFingerprintComponents(
            vector=[int(value) for value in components_raw.get("vector", [])],
        ),
        activity=VisitorFingerprintActivity(sessions=sessions),
    )


def _parse_organization(data: dict[str, Any]) -> Organization:
    return Organization(
        object=str(data["object"]),
        id=str(data["id"]),
        name=str(data["name"]),
        slug=str(data["slug"]),
        status=str(data["status"]),
        created_at=str(data["created_at"]),
        updated_at=data.get("updated_at"),
    )


def _parse_api_key(data: dict[str, Any]) -> ApiKey:
    return ApiKey(
        object=str(data["object"]),
        id=str(data["id"]),
        type=str(data["type"]),
        name=str(data["name"]),
        environment=str(data["environment"]),
        allowed_origins=[str(value) for value in data.get("allowed_origins", [])]
        if data.get("allowed_origins") is not None
        else None,
        scopes=[str(value) for value in data.get("scopes", [])] if data.get("scopes") is not None else None,
        rate_limit=int(data["rate_limit"]) if isinstance(data.get("rate_limit"), int) else None,
        status=str(data["status"]),
        key_preview=str(data["key_preview"]),
        display_key=data.get("display_key"),
        last_used_at=data.get("last_used_at"),
        created_at=str(data["created_at"]),
        rotated_at=data.get("rotated_at"),
        revoked_at=data.get("revoked_at"),
        grace_expires_at=data.get("grace_expires_at"),
    )


def _parse_issued_api_key(data: dict[str, Any]) -> IssuedApiKey:
    api_key = _parse_api_key(data)
    return IssuedApiKey(**api_key.__dict__, revealed_key=str(data["revealed_key"]))


def _parse_gate_service_env_var(data: dict[str, Any]) -> GateServiceEnvVar:
    return GateServiceEnvVar(
        name=str(data["name"]),
        key=str(data["key"]),
        secret=bool(data["secret"]),
    )


def _parse_gate_service_sdk_install(data: dict[str, Any]) -> GateServiceSdkInstall:
    return GateServiceSdkInstall(
        label=str(data["label"]),
        install=str(data["install"]),
        url=str(data["url"]),
    )


def _parse_gate_service_branding(data: dict[str, Any] | None) -> GateServiceBranding:
    payload = data or {}
    return GateServiceBranding(
        verified=bool(payload.get("verified", False)),
        logo_url=payload.get("logo_url") if isinstance(payload.get("logo_url"), str) else None,
        primary_color=payload.get("primary_color") if isinstance(payload.get("primary_color"), str) else None,
        secondary_color=payload.get("secondary_color") if isinstance(payload.get("secondary_color"), str) else None,
        ascii_art=payload.get("ascii_art") if isinstance(payload.get("ascii_art"), str) else None,
    )


def _parse_gate_service_consent(data: dict[str, Any] | None) -> GateServiceConsent:
    payload = data or {}
    return GateServiceConsent(
        terms_url=payload.get("terms_url") if isinstance(payload.get("terms_url"), str) else None,
        privacy_url=payload.get("privacy_url") if isinstance(payload.get("privacy_url"), str) else None,
    )


def _parse_gate_registry_entry(data: dict[str, Any]) -> GateRegistryEntry:
    return GateRegistryEntry(
        id=str(data["id"]),
        status=str(data["status"]),
        discoverable=bool(data["discoverable"]),
        name=str(data["name"]),
        description=str(data["description"]),
        website=str(data["website"]),
        env_vars=[_parse_gate_service_env_var(dict(item)) for item in data.get("env_vars", [])],
        docs_url=str(data["docs_url"]),
        sdks=[_parse_gate_service_sdk_install(dict(item)) for item in data.get("sdks", [])],
        branding=_parse_gate_service_branding(dict(data["branding"])) if isinstance(data.get("branding"), dict) else _parse_gate_service_branding(None),
        consent=_parse_gate_service_consent(dict(data["consent"])) if isinstance(data.get("consent"), dict) else _parse_gate_service_consent(None),
        dashboard_login_url=data.get("dashboard_login_url")
        if isinstance(data.get("dashboard_login_url"), str) or data.get("dashboard_login_url") is None
        else None,
    )


def _parse_gate_managed_service(data: dict[str, Any]) -> GateManagedService:
    entry = _parse_gate_registry_entry(data)
    return GateManagedService(
        **entry.__dict__,
        object=str(data["object"]),
        webhook_endpoint_id=data.get("webhook_endpoint_id")
        if isinstance(data.get("webhook_endpoint_id"), str) or data.get("webhook_endpoint_id") is None
        else None,
        created_at=str(data["created_at"]),
        updated_at=str(data["updated_at"]),
    )


def _parse_webhook_endpoint(data: dict[str, Any]) -> WebhookEndpoint:
    return WebhookEndpoint(
        object=str(data["object"]),
        id=str(data["id"]),
        name=str(data["name"]),
        url=str(data["url"]),
        status=str(data["status"]),
        event_types=[str(item) for item in data.get("event_types", [])],
        signing_secret=data.get("signing_secret") if isinstance(data.get("signing_secret"), str) else None,
        created_at=str(data["created_at"]),
        updated_at=str(data["updated_at"]),
    )


def _parse_webhook_delivery(data: dict[str, Any]) -> WebhookDelivery:
    return WebhookDelivery(
        object=str(data["object"]),
        id=str(data["id"]),
        event_id=str(data["event_id"]),
        endpoint_id=str(data["endpoint_id"]),
        event_type=str(data["event_type"]),
        status=str(data["status"]),
        attempts=int(data["attempts"]),
        response_status=int(data["response_status"]) if isinstance(data.get("response_status"), int) else None,
        response_body=data.get("response_body")
        if isinstance(data.get("response_body"), str) or data.get("response_body") is None
        else None,
        error=data.get("error") if isinstance(data.get("error"), str) or data.get("error") is None else None,
        created_at=str(data["created_at"]),
        updated_at=str(data["updated_at"]),
    )


def _parse_event_subject(data: dict[str, Any]) -> EventSubject:
    return EventSubject(
        type=str(data["type"]),
        id=str(data["id"]),
    )


def _parse_event(data: dict[str, Any]) -> Event:
    return Event(
        object=str(data["object"]),
        id=str(data["id"]),
        type=str(data["type"]),
        subject=_parse_event_subject(dict(data["subject"])),
        data=dict(data.get("data", {})) if isinstance(data.get("data"), dict) else {},
        webhook_deliveries=[
            _parse_webhook_delivery(dict(item))
            for item in data.get("webhook_deliveries", [])
            if isinstance(item, dict)
        ],
        created_at=str(data["created_at"]),
    )


def _parse_webhook_test(data: dict[str, Any]) -> WebhookTest:
    latest_delivery = data.get("latest_delivery")
    return WebhookTest(
        object=str(data["object"]),
        event_id=str(data["event_id"]),
        delivery_ids=[str(item) for item in data.get("delivery_ids", [])],
        latest_delivery=_parse_webhook_delivery(dict(latest_delivery)) if isinstance(latest_delivery, dict) else None,
    )


def _parse_gate_delivery_envelope(data: dict[str, Any]) -> GateDeliveryEnvelope:
    return GateDeliveryEnvelope(
        version=int(data["version"]),
        algorithm=str(data["algorithm"]),
        key_id=str(data["key_id"]),
        ephemeral_public_key=str(data["ephemeral_public_key"]),
        salt=str(data["salt"]),
        iv=str(data["iv"]),
        ciphertext=str(data["ciphertext"]),
        tag=str(data["tag"]),
    )


def _parse_gate_delivery_bundle(data: dict[str, Any] | None) -> GateDeliveryBundle | None:
    if data is None:
        return None
    return GateDeliveryBundle(
        integrator=_parse_gate_delivery_envelope(dict(data["integrator"])),
        gate=_parse_gate_delivery_envelope(dict(data["gate"])),
    )


def _parse_gate_session_create(data: dict[str, Any]) -> GateSessionCreate:
    return GateSessionCreate(
        object=str(data["object"]),
        id=str(data["id"]),
        status=str(data["status"]),
        poll_token=str(data["poll_token"]),
        consent_url=str(data["consent_url"]),
        expires_at=str(data["expires_at"]),
    )


def _parse_gate_session_poll(data: dict[str, Any]) -> GateSessionPollData:
    return GateSessionPollData(
        object=str(data["object"]),
        id=str(data["id"]),
        status=str(data["status"]),
        expires_at=data.get("expires_at") if isinstance(data.get("expires_at"), str) or data.get("expires_at") is None else None,
        gate_account_id=data.get("gate_account_id") if isinstance(data.get("gate_account_id"), str) or data.get("gate_account_id") is None else None,
        account_name=data.get("account_name") if isinstance(data.get("account_name"), str) or data.get("account_name") is None else None,
        delivery_bundle=_parse_gate_delivery_bundle(dict(data["delivery_bundle"])) if isinstance(data.get("delivery_bundle"), dict) else None,
        docs_url=data.get("docs_url") if isinstance(data.get("docs_url"), str) or data.get("docs_url") is None else None,
    )


def _parse_gate_session_delivery_acknowledgement(data: dict[str, Any]) -> GateSessionDeliveryAcknowledgement:
    return GateSessionDeliveryAcknowledgement(
        object=str(data["object"]),
        gate_session_id=str(data["gate_session_id"]),
        status=str(data["status"]),
    )


def _parse_gate_login_session(data: dict[str, Any]) -> GateLoginSession:
    return GateLoginSession(
        object=str(data["object"]),
        id=str(data["id"]),
        status=str(data["status"]),
        consent_url=str(data["consent_url"]),
        expires_at=str(data["expires_at"]),
    )


def _parse_gate_dashboard_login(data: dict[str, Any]) -> GateDashboardLogin:
    return GateDashboardLogin(
        object=str(data["object"]),
        gate_account_id=str(data["gate_account_id"]),
        account_name=str(data["account_name"]),
    )


def _parse_agent_token_verification(data: dict[str, Any]) -> AgentTokenVerification:
    return AgentTokenVerification(
        valid=bool(data["valid"]),
        gate_account_id=data.get("gate_account_id") if isinstance(data.get("gate_account_id"), str) or data.get("gate_account_id") is None else None,
        status=data.get("status") if isinstance(data.get("status"), str) or data.get("status") is None else None,
        created_at=data.get("created_at") if isinstance(data.get("created_at"), str) or data.get("created_at") is None else None,
        expires_at=data.get("expires_at") if isinstance(data.get("expires_at"), str) or data.get("expires_at") is None else None,
    )


def _normalize_list(items: list[Any], pagination: dict[str, Any]) -> ListResult[Any]:
    return ListResult(
        items=items,
        limit=int(pagination["limit"]),
        has_more=bool(pagination["has_more"]),
        next_cursor=pagination.get("next_cursor"),
    )


class _BaseAPI:
    def __init__(self, client: "Tripwire") -> None:
        self._client = client


class SessionsAPI(_BaseAPI):
    def list(
        self,
        *,
        limit: int | None = None,
        cursor: str | None = None,
        verdict: str | None = None,
        search: str | None = None,
    ) -> ListResult[SessionSummary]:
        response = self._client._request_json(
            "GET",
            "/v1/sessions",
            query=_compact_query(
                {
                    "limit": limit,
                    "cursor": cursor,
                    "verdict": verdict,
                    "search": search,
                }
            ),
        )
        return _normalize_list(
            [_parse_session_summary(dict(item)) for item in response["data"]],
            dict(response["pagination"]),
        )

    def get(self, session_id: str) -> SessionDetail:
        response = self._client._request_json("GET", f"/v1/sessions/{session_id}")
        return _parse_session_detail(dict(response["data"]))

    def iter(
        self,
        *,
        limit: int | None = None,
        verdict: str | None = None,
        search: str | None = None,
    ) -> Iterator[SessionSummary]:
        cursor: str | None = None
        while True:
            page = self.list(limit=limit, cursor=cursor, verdict=verdict, search=search)
            for item in page.items:
                yield item
            if not page.has_more or not page.next_cursor:
                break
            cursor = page.next_cursor


class FingerprintsAPI(_BaseAPI):
    def list(
        self,
        *,
        limit: int | None = None,
        cursor: str | None = None,
        search: str | None = None,
        sort: str | None = None,
    ) -> ListResult[VisitorFingerprintSummary]:
        response = self._client._request_json(
            "GET",
            "/v1/fingerprints",
            query=_compact_query(
                {
                    "limit": limit,
                    "cursor": cursor,
                    "search": search,
                    "sort": sort,
                }
            ),
        )
        return _normalize_list(
            [_parse_visitor_fingerprint_summary(dict(item)) for item in response["data"]],
            dict(response["pagination"]),
        )

    def get(self, visitor_id: str) -> VisitorFingerprintDetail:
        response = self._client._request_json("GET", f"/v1/fingerprints/{visitor_id}")
        return _parse_visitor_fingerprint_detail(dict(response["data"]))

    def iter(
        self,
        *,
        limit: int | None = None,
        search: str | None = None,
        sort: str | None = None,
    ) -> Iterator[VisitorFingerprintSummary]:
        cursor: str | None = None
        while True:
            page = self.list(limit=limit, cursor=cursor, search=search, sort=sort)
            for item in page.items:
                yield item
            if not page.has_more or not page.next_cursor:
                break
            cursor = page.next_cursor


class ApiKeysAPI(_BaseAPI):
    def create(
        self,
        organization_id: str,
        *,
        name: str,
        type: str | None = None,
        environment: str | None = None,
        allowed_origins: list[str] | None = None,
        scopes: list[str] | None = None,
    ) -> IssuedApiKey:
        response = self._client._request_json(
            "POST",
            f"/v1/organizations/{organization_id}/api-keys",
            body=_compact_query(
                {
                    "name": name,
                    "type": type,
                    "environment": environment,
                    "allowed_origins": allowed_origins,
                    "scopes": scopes,
                }
            ),
        )
        return _parse_issued_api_key(dict(response["data"]))

    def list(
        self,
        organization_id: str,
        *,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> ListResult[ApiKey]:
        response = self._client._request_json(
            "GET",
            f"/v1/organizations/{organization_id}/api-keys",
            query=_compact_query({"limit": limit, "cursor": cursor}),
        )
        return _normalize_list(
            [_parse_api_key(dict(item)) for item in response["data"]],
            dict(response["pagination"]),
        )

    def update(
        self,
        organization_id: str,
        key_id: str,
        *,
        name: str | None = None,
        allowed_origins: list[str] | None = None,
        scopes: list[str] | None = None,
    ) -> ApiKey:
        response = self._client._request_json(
            "PATCH",
            f"/v1/organizations/{organization_id}/api-keys/{key_id}",
            body=_compact_query({"name": name, "allowed_origins": allowed_origins, "scopes": scopes}),
        )
        return _parse_api_key(dict(response["data"]))

    def revoke(self, organization_id: str, key_id: str) -> ApiKey:
        response = self._client._request_json(
            "DELETE",
            f"/v1/organizations/{organization_id}/api-keys/{key_id}",
        )
        return _parse_api_key(dict(response["data"]))

    def rotate(self, organization_id: str, key_id: str) -> IssuedApiKey:
        response = self._client._request_json(
            "POST",
            f"/v1/organizations/{organization_id}/api-keys/{key_id}/rotations",
        )
        return _parse_issued_api_key(dict(response["data"]))


class OrganizationsAPI(_BaseAPI):
    def __init__(self, client: "Tripwire") -> None:
        super().__init__(client)
        self.api_keys = ApiKeysAPI(client)

    def create(self, *, name: str, slug: str) -> Organization:
        response = self._client._request_json(
            "POST",
            "/v1/organizations",
            body={"name": name, "slug": slug},
        )
        return _parse_organization(dict(response["data"]))

    def get(self, organization_id: str) -> Organization:
        response = self._client._request_json("GET", f"/v1/organizations/{organization_id}")
        return _parse_organization(dict(response["data"]))

    def update(
        self,
        organization_id: str,
        *,
        name: str | None = None,
        status: str | None = None,
    ) -> Organization:
        response = self._client._request_json(
            "PATCH",
            f"/v1/organizations/{organization_id}",
            body=_compact_query({"name": name, "status": status}),
        )
        return _parse_organization(dict(response["data"]))


class GateRegistryAPI(_BaseAPI):
    def list(self) -> list[GateRegistryEntry]:
        response = self._client._request_json("GET", "/v1/gate/registry", auth_mode="none")
        return [_parse_gate_registry_entry(dict(item)) for item in response["data"]]

    def get(self, service_id: str) -> GateRegistryEntry:
        response = self._client._request_json("GET", f"/v1/gate/registry/{service_id}", auth_mode="none")
        return _parse_gate_registry_entry(dict(response["data"]))


class GateServicesAPI(_BaseAPI):
    def list(self) -> list[GateManagedService]:
        response = self._client._request_json("GET", "/v1/gate/services")
        return [_parse_gate_managed_service(dict(item)) for item in response["data"]]

    def get(self, service_id: str) -> GateManagedService:
        response = self._client._request_json("GET", f"/v1/gate/services/{service_id}")
        return _parse_gate_managed_service(dict(response["data"]))

    def create(self, **body: Any) -> GateManagedService:
        response = self._client._request_json("POST", "/v1/gate/services", body=body)
        return _parse_gate_managed_service(dict(response["data"]))

    def update(self, service_id: str, **body: Any) -> GateManagedService:
        response = self._client._request_json("PATCH", f"/v1/gate/services/{service_id}", body=body)
        return _parse_gate_managed_service(dict(response["data"]))

    def disable(self, service_id: str) -> GateManagedService:
        response = self._client._request_json("DELETE", f"/v1/gate/services/{service_id}")
        return _parse_gate_managed_service(dict(response["data"]))


class GateSessionsAPI(_BaseAPI):
    def create(
        self,
        *,
        service_id: str,
        account_name: str,
        delivery: dict[str, Any],
        metadata: dict[str, Any] | None = None,
    ) -> GateSessionCreate:
        body = {
            "service_id": service_id,
            "account_name": account_name,
            "delivery": delivery,
        }
        if metadata is not None:
            body["metadata"] = metadata
        response = self._client._request_json("POST", "/v1/gate/sessions", body=body, auth_mode="none")
        return _parse_gate_session_create(dict(response["data"]))

    def poll(self, gate_session_id: str, *, poll_token: str) -> GateSessionPollData:
        response = self._client._request_json(
            "GET",
            f"/v1/gate/sessions/{gate_session_id}",
            auth_mode="bearer",
            bearer_token=poll_token,
        )
        return _parse_gate_session_poll(dict(response["data"]))

    def acknowledge(self, gate_session_id: str, *, poll_token: str, ack_token: str) -> GateSessionDeliveryAcknowledgement:
        response = self._client._request_json(
            "POST",
            f"/v1/gate/sessions/{gate_session_id}/ack",
            body={"ack_token": ack_token},
            auth_mode="bearer",
            bearer_token=poll_token,
        )
        return _parse_gate_session_delivery_acknowledgement(dict(response["data"]))


class GateLoginSessionsAPI(_BaseAPI):
    def create(self, *, service_id: str, agent_token: str) -> GateLoginSession:
        response = self._client._request_json(
            "POST",
            "/v1/gate/login-sessions",
            body={"service_id": service_id},
            auth_mode="bearer",
            bearer_token=agent_token,
        )
        return _parse_gate_login_session(dict(response["data"]))

    def consume(self, *, code: str) -> GateDashboardLogin:
        response = self._client._request_json(
            "POST",
            "/v1/gate/login-sessions/consume",
            body={"code": code},
        )
        return _parse_gate_dashboard_login(dict(response["data"]))


class GateAgentTokensAPI(_BaseAPI):
    def verify(self, *, agent_token: str) -> AgentTokenVerification:
        response = self._client._request_json(
            "POST",
            "/v1/gate/agent-tokens/verify",
            body={"agent_token": agent_token},
        )
        return _parse_agent_token_verification(dict(response["data"]))

    def revoke(self, *, agent_token: str) -> None:
        self._client._request_json(
            "POST",
            "/v1/gate/agent-tokens/revoke",
            body={"agent_token": agent_token},
            expect_content=False,
        )


class GateAPI(_BaseAPI):
    def __init__(self, client: "Tripwire") -> None:
        super().__init__(client)
        self.registry = GateRegistryAPI(client)
        self.services = GateServicesAPI(client)
        self.sessions = GateSessionsAPI(client)
        self.login_sessions = GateLoginSessionsAPI(client)
        self.agent_tokens = GateAgentTokensAPI(client)


class WebhooksAPI(_BaseAPI):
    def list_endpoints(self, organization_id: str) -> ListResult[WebhookEndpoint]:
        response = self._client._request_json("GET", f"/v1/organizations/{organization_id}/webhooks/endpoints")
        return _normalize_list(
            [_parse_webhook_endpoint(dict(item)) for item in response["data"]],
            dict(response["pagination"]),
        )

    def create_endpoint(
        self,
        organization_id: str,
        *,
        name: str,
        url: str,
        event_types: list[str],
    ) -> WebhookEndpoint:
        response = self._client._request_json(
            "POST",
            f"/v1/organizations/{organization_id}/webhooks/endpoints",
            body={"name": name, "url": url, "event_types": event_types},
        )
        return _parse_webhook_endpoint(dict(response["data"]))

    def update_endpoint(self, organization_id: str, endpoint_id: str, **body: Any) -> WebhookEndpoint:
        response = self._client._request_json(
            "PATCH",
            f"/v1/organizations/{organization_id}/webhooks/endpoints/{endpoint_id}",
            body=body,
        )
        return _parse_webhook_endpoint(dict(response["data"]))

    def disable_endpoint(self, organization_id: str, endpoint_id: str) -> WebhookEndpoint:
        response = self._client._request_json(
            "DELETE",
            f"/v1/organizations/{organization_id}/webhooks/endpoints/{endpoint_id}",
        )
        return _parse_webhook_endpoint(dict(response["data"]))

    def rotate_secret(self, organization_id: str, endpoint_id: str) -> WebhookEndpoint:
        response = self._client._request_json(
            "POST",
            f"/v1/organizations/{organization_id}/webhooks/endpoints/{endpoint_id}/rotations",
        )
        return _parse_webhook_endpoint(dict(response["data"]))

    def send_test(self, organization_id: str, endpoint_id: str) -> WebhookTest:
        response = self._client._request_json(
            "POST",
            f"/v1/organizations/{organization_id}/webhooks/endpoints/{endpoint_id}/test",
        )
        return _parse_webhook_test(dict(response["data"]))

    def list_events(
        self,
        organization_id: str,
        *,
        endpoint_id: str | None = None,
        type: str | None = None,
        limit: int | None = None,
    ) -> ListResult[Event]:
        response = self._client._request_json(
            "GET",
            f"/v1/organizations/{organization_id}/events",
            query=_compact_query({"endpoint_id": endpoint_id, "type": type, "limit": limit}),
        )
        return _normalize_list(
            [_parse_event(dict(item)) for item in response["data"]],
            dict(response["pagination"]),
        )

    def retrieve_event(self, organization_id: str, event_id: str) -> Event:
        response = self._client._request_json("GET", f"/v1/organizations/{organization_id}/events/{event_id}")
        return _parse_event(dict(response["data"]))


class Tripwire:
    def __init__(
        self,
        *,
        secret_key: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
        user_agent: str | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        resolved_secret = secret_key or os.getenv("FOIL_SECRET_KEY")
        headers = {
            "Accept": "application/json",
            "X-Tripwire-Client": SDK_CLIENT_HEADER,
        }
        if user_agent:
            headers["User-Agent"] = user_agent

        self._secret_key = resolved_secret
        self._client = httpx.Client(
            base_url=base_url or DEFAULT_BASE_URL,
            timeout=timeout,
            transport=transport,
            headers=headers,
        )
        self.sessions = SessionsAPI(self)
        self.fingerprints = FingerprintsAPI(self)
        self.organizations = OrganizationsAPI(self)
        self.gate = GateAPI(self)
        self.webhooks = WebhooksAPI(self)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "Tripwire":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
        expect_content: bool = True,
        auth_mode: str = "secret",
        bearer_token: str | None = None,
    ) -> dict[str, Any]:
        headers: dict[str, str] = {}
        if auth_mode == "bearer":
            if not bearer_token:
                raise TripwireConfigurationError("Missing bearer token for this Tripwire request.")
            headers["Authorization"] = f"Bearer {bearer_token}"
        elif auth_mode == "secret":
            if not self._secret_key:
                raise TripwireConfigurationError(
                    "Missing Tripwire secret key. Pass secret_key explicitly or set FOIL_SECRET_KEY."
                )
            headers["Authorization"] = f"Bearer {self._secret_key}"
        response = self._client.request(method, path, params=query, json=body, headers=headers)
        request_id = response.headers.get("x-request-id")

        if response.status_code >= 400:
            payload: dict[str, Any]
            try:
                payload = response.json()
            except ValueError:
                payload = {}

            if isinstance(payload.get("error"), dict):
                error = payload["error"]
                details = error.get("details")
                raise TripwireApiError(
                    status=response.status_code,
                    code=str(error.get("code", "request.failed")),
                    message=str(error.get("message", response.text or response.reason_phrase)),
                    request_id=request_id or error.get("request_id"),
                    field_errors=list(details.get("fields", [])) if isinstance(details, dict) else [],
                    docs_url=error.get("docs_url"),
                    body=payload,
                )

            raise TripwireApiError(
                status=response.status_code,
                code="request.failed",
                message=response.text or response.reason_phrase,
                request_id=request_id,
                body=payload,
            )

        if not expect_content or response.status_code == 204:
            return {}
        return response.json()
