from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def strip_examples(value):
    if isinstance(value, list):
        return [strip_examples(item) for item in value]
    if isinstance(value, dict):
        return {
            key: strip_examples(item)
            for key, item in value.items()
            if key != "example"
        }
    return value


class ContractTests(unittest.TestCase):
    @staticmethod
    def _read_spec() -> dict:
        return json.loads((ROOT / "spec" / "openapi.json").read_text())

    def test_only_supported_public_paths_are_exposed(self) -> None:
        spec = self._read_spec()
        self.assertEqual(
            sorted(spec["paths"].keys()),
            [
                "/v1/fingerprints",
                "/v1/fingerprints/{visitorId}",
                "/v1/gate/agent-tokens/revoke",
                "/v1/gate/agent-tokens/verify",
                "/v1/gate/login-sessions",
                "/v1/gate/login-sessions/consume",
                "/v1/gate/registry",
                "/v1/gate/registry/{serviceId}",
                "/v1/gate/services",
                "/v1/gate/services/{serviceId}",
                "/v1/gate/sessions",
                "/v1/gate/sessions/{gateSessionId}",
                "/v1/gate/sessions/{gateSessionId}/ack",
                "/v1/organizations",
                "/v1/organizations/{organizationId}",
                "/v1/organizations/{organizationId}/api-keys",
                "/v1/organizations/{organizationId}/api-keys/{keyId}",
                "/v1/organizations/{organizationId}/api-keys/{keyId}/rotations",
                "/v1/organizations/{organizationId}/events",
                "/v1/organizations/{organizationId}/events/{eventId}",
                "/v1/organizations/{organizationId}/webhooks/endpoints",
                "/v1/organizations/{organizationId}/webhooks/endpoints/{endpointId}",
                "/v1/organizations/{organizationId}/webhooks/endpoints/{endpointId}/rotations",
                "/v1/organizations/{organizationId}/webhooks/endpoints/{endpointId}/test",
                "/v1/sessions",
                "/v1/sessions/{sessionId}",
            ],
        )

    def test_collect_endpoints_are_excluded(self) -> None:
        spec = self._read_spec()
        self.assertFalse(any(path.startswith("/v1/collect/") for path in spec["paths"]))

    def test_expected_success_fixtures_exist(self) -> None:
        fixtures = [
            "api/sessions/list.json",
            "api/sessions/detail.json",
            "api/fingerprints/list.json",
            "api/fingerprints/detail.json",
            "api/gate/registry-list.json",
            "api/gate/registry-detail.json",
            "api/gate/services-list.json",
            "api/gate/service-detail.json",
            "api/gate/service-create.json",
            "api/gate/service-update.json",
            "api/gate/service-disable.json",
            "api/gate/session-create.json",
            "api/gate/session-poll.json",
            "api/gate/session-ack.json",
            "api/gate/login-session-create.json",
            "api/gate/login-session-consume.json",
            "api/gate/agent-token-verify.json",
            "api/gate/agent-token-revoke.json",
            "api/organizations/organization.json",
            "api/organizations/organization-create.json",
            "api/organizations/organization-update.json",
            "api/organizations/api-key-create.json",
            "api/organizations/api-key-list.json",
            "api/organizations/api-key-update.json",
            "api/organizations/api-key-rotate.json",
            "api/organizations/api-key-revoke.json",
        ]
        for relative_path in fixtures:
            with self.subTest(relative_path=relative_path):
                self.assertTrue((ROOT / "spec" / "fixtures" / relative_path).exists())

    def test_schema_constraints_are_tightened_for_sdk_consumers(self) -> None:
        schemas = self._read_spec()["components"]["schemas"]

        self.assertEqual(schemas["SessionId"]["pattern"], "^sid_[0123456789abcdefghjkmnpqrstvwxyz]{26}$")
        self.assertEqual(schemas["FingerprintId"]["pattern"], "^vid_[0123456789abcdefghjkmnpqrstvwxyz]{26}$")
        self.assertEqual(schemas["OrganizationId"]["pattern"], "^org_[0123456789abcdefghjkmnpqrstvwxyz]{26}$")
        self.assertEqual(schemas["ApiKeyId"]["pattern"], "^key_[0123456789abcdefghjkmnpqrstvwxyz]{26}$")

        self.assertEqual(strip_examples(schemas["SessionSummary"]["properties"]["id"]), {"$ref": "#/components/schemas/SessionId"})
        self.assertEqual(
            strip_examples(schemas["SessionSummary"]["properties"]["client_user_id"]),
            {
                "type": ["string", "null"],
                "maxLength": 256,
                "description": "Customer-supplied identifier for the end user associated with this Foil session. Set with PATCH /v1/sessions/{sessionId}.",
            },
        )
        self.assertEqual(strip_examples(schemas["Organization"]["properties"]["status"]), {"$ref": "#/components/schemas/OrganizationStatus"})
        self.assertEqual(strip_examples(schemas["ApiKey"]["properties"]["status"]), {"$ref": "#/components/schemas/ApiKeyStatus"})
        self.assertEqual(
            schemas["PublicError"]["properties"]["code"]["x-foil-known-values-ref"],
            "#/components/schemas/KnownPublicErrorCode",
        )
        self.assertEqual(schemas["OrganizationStatus"]["enum"], ["active", "suspended", "deleted"])
        self.assertEqual(schemas["ApiKeyStatus"]["enum"], ["active", "rotating", "revoked"])
        self.assertTrue(
            {"client_user_id", "decision", "highlights", "attribution", "web_bot_auth", "network", "runtime_integrity", "visitor_fingerprint", "connection_fingerprint", "previous_decisions", "request", "browser", "device", "analysis_coverage", "signals_fired", "client_telemetry"}.issubset(
                set(schemas["SessionDetail"]["required"])
            )
        )
        self.assertEqual(
            strip_examples(schemas["SessionDetail"]["properties"]["request"]),
            {"$ref": "#/components/schemas/SessionDetailRequest"},
        )
        self.assertEqual(
            strip_examples(schemas["SessionDetail"]["properties"]["client_telemetry"]),
            {"$ref": "#/components/schemas/SessionClientTelemetry"},
        )
        self.assertEqual(
            strip_examples(schemas["SessionDetail"]["properties"]["attribution"]),
            {"anyOf": [{"$ref": "#/components/schemas/SessionAttribution"}, {"type": "null"}]},
        )
        self.assertEqual(
            strip_examples(schemas["SessionDetail"]["properties"]["signals_fired"]),
            {"type": "array", "items": {"$ref": "#/components/schemas/SessionSignalFired"}},
        )
        self.assertEqual(schemas["SessionSignalFired"]["properties"]["signal"]["type"], "string")
        self.assertTrue(
            {
                "type",
                "allowed_origins",
                "scopes",
                "key_preview",
                "last_used_at",
                "rate_limit",
                "rotated_at",
                "revoked_at",
                "grace_expires_at",
            }.issubset(set(schemas["ApiKey"]["required"]))
        )
        self.assertIn("revealed_key", schemas["IssuedApiKey"]["required"])
        self.assertNotIn("team_id", schemas["GateManagedService"]["properties"])
        self.assertNotIn("webhook_secret", schemas["GateManagedService"]["properties"])
        self.assertNotIn("CollectBatchResponse", schemas)

    def test_public_operations_have_stable_ids_and_tags(self) -> None:
        paths = self._read_spec()["paths"]

        self.assertEqual(paths["/v1/sessions"]["get"]["operationId"], "listSessions")
        self.assertEqual(paths["/v1/sessions"]["get"]["tags"], ["Sessions"])
        self.assertEqual(paths["/v1/sessions/{sessionId}"]["patch"]["operationId"], "updateSession")
        self.assertEqual(paths["/v1/sessions/{sessionId}"]["patch"]["tags"], ["Sessions"])
        self.assertEqual(paths["/v1/fingerprints/{visitorId}"]["get"]["operationId"], "getVisitorFingerprint")
        self.assertEqual(paths["/v1/fingerprints/{visitorId}"]["get"]["tags"], ["Visitor fingerprints"])
        self.assertEqual(paths["/v1/organizations/{organizationId}"]["patch"]["operationId"], "updateOrganization")
        self.assertEqual(paths["/v1/organizations/{organizationId}"]["patch"]["tags"], ["Organizations"])
        self.assertEqual(
            paths["/v1/organizations/{organizationId}/api-keys/{keyId}"]["patch"]["operationId"],
            "updateOrganizationApiKey",
        )
        self.assertEqual(paths["/v1/organizations/{organizationId}/api-keys/{keyId}"]["patch"]["tags"], ["API Keys"])
        self.assertEqual(
            paths["/v1/organizations/{organizationId}/api-keys/{keyId}/rotations"]["post"]["operationId"],
            "rotateOrganizationApiKey",
        )
        self.assertEqual(paths["/v1/organizations/{organizationId}/api-keys/{keyId}/rotations"]["post"]["tags"], ["API Keys"])
        self.assertEqual(paths["/v1/gate/services"]["post"]["operationId"], "createManagedGateService")
        self.assertEqual(paths["/v1/gate/services"]["post"]["tags"], ["Gate"])
        self.assertEqual(paths["/v1/gate/sessions/{gateSessionId}"]["get"]["operationId"], "pollGateSession")
        self.assertEqual(paths["/v1/gate/sessions/{gateSessionId}"]["get"]["tags"], ["Gate"])
        self.assertEqual(paths["/v1/gate/agent-tokens/revoke"]["post"]["operationId"], "revokeGateAgentToken")
        self.assertEqual(paths["/v1/gate/agent-tokens/revoke"]["post"]["tags"], ["Gate"])
