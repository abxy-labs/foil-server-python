from __future__ import annotations

import json
import os
import unittest

import httpx

from tests.test_helpers import load_fixture
from foil_server import Foil
from foil_server.errors import FoilApiError, FoilConfigurationError


def json_response(
    body: object,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    return httpx.Response(
        status_code=status_code,
        headers={"content-type": "application/json", **(headers or {})},
        json=body,
    )


class ClientTests(unittest.TestCase):
    def test_env_secret_fallback(self) -> None:
        original = os.environ.get("FOIL_SECRET_KEY")
        os.environ["FOIL_SECRET_KEY"] = "sk_env_default"
        fixture = load_fixture("api/sessions/list.json")

        transport = httpx.MockTransport(lambda _request: json_response(fixture))
        try:
            client = Foil(transport=transport)
            result = client.sessions.list()
            self.assertEqual(len(result.items), 1)
        finally:
            client.close()
            if original is None:
                os.environ.pop("FOIL_SECRET_KEY", None)
            else:
                os.environ["FOIL_SECRET_KEY"] = original

    def test_missing_secret_raises(self) -> None:
        original = os.environ.pop("FOIL_SECRET_KEY", None)
        try:
            client = Foil()
            self.assertIsNotNone(client.gate)
            client.close()
        finally:
            if original is not None:
                os.environ["FOIL_SECRET_KEY"] = original

    def test_secret_endpoints_raise_at_request_time_when_no_secret_is_configured(self) -> None:
        original = os.environ.pop("FOIL_SECRET_KEY", None)
        try:
            client = Foil(transport=httpx.MockTransport(lambda _request: json_response({})))
            with self.assertRaises(FoilConfigurationError):
                client.sessions.list()
            client.close()
        finally:
            if original is not None:
                os.environ["FOIL_SECRET_KEY"] = original

    def test_base_url_timeout_and_headers_are_applied(self) -> None:
        fixture = load_fixture("api/sessions/list.json")

        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(str(request.url), "https://example.foil.dev/v1/sessions?limit=5")
            self.assertEqual(request.headers["Authorization"], "Bearer sk_live_test")
            self.assertEqual(request.headers["X-Foil-Client"], "foil-server-python/0.1.0")
            self.assertEqual(request.headers["User-Agent"], "custom-foil-client")
            return json_response(fixture)

        client = Foil(
            secret_key="sk_live_test",
            base_url="https://example.foil.dev",
            timeout=5.0,
            user_agent="custom-foil-client",
            transport=httpx.MockTransport(handler),
        )
        try:
            client.sessions.list(limit=5)
            self.assertEqual(client._client.timeout.connect, 5.0)
        finally:
            client.close()

    def test_sessions_list_and_iter(self) -> None:
        first_page = load_fixture("api/sessions/list.json")
        second_page = {
            "data": [
                {
                    **first_page["data"][0],
                    "id": "sid_123456789abcdefghjkmnpqrst",
                    "latest_decision": {
                        **first_page["data"][0]["latest_decision"],
                        "event_id": "evt_3456789abcdefghjkmnpqrstvw",
                        "evaluated_at": "2026-03-24T20:01:05.000Z",
                    },
                }
            ],
            "pagination": {
                "limit": 50,
                "has_more": False,
            },
            "meta": {
                "request_id": "req_0123456789abcdef0123456789abcdef",
            },
        }

        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.headers["Authorization"], "Bearer sk_live_test")
            cursor = request.url.params.get("cursor")
            return json_response(second_page if cursor else first_page)

        client = Foil(secret_key="sk_live_test", transport=httpx.MockTransport(handler))
        try:
            page = client.sessions.list(verdict="bot", limit=25)
            self.assertEqual(page.limit, 50)
            self.assertTrue(page.has_more)
            self.assertEqual(page.next_cursor, "cur_sessions_page_2")
            self.assertEqual(
                [item.id for item in client.sessions.iter(verdict="human")],
                ["sid_0123456789abcdefghjkmnpqrs", "sid_123456789abcdefghjkmnpqrst"],
            )
        finally:
            client.close()

    def test_session_detail_and_fingerprint_endpoints(self) -> None:
        session_fixture = load_fixture("api/sessions/detail.json")
        fp_list_fixture = load_fixture("api/fingerprints/list.json")
        fp_detail_fixture = load_fixture("api/fingerprints/detail.json")

        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path.endswith("/v1/sessions/sid_0123456789abcdefghjkmnpqrs"):
                return json_response(session_fixture)
            if path.endswith("/v1/fingerprints/vid_456789abcdefghjkmnpqrstvwx"):
                return json_response(fp_detail_fixture)
            return json_response(fp_list_fixture)

        client = Foil(secret_key="sk_live_test", transport=httpx.MockTransport(handler))
        try:
            session = client.sessions.get("sid_0123456789abcdefghjkmnpqrs")
            self.assertEqual(session.id, "sid_0123456789abcdefghjkmnpqrs")
            self.assertEqual(session.client_user_id, "user_123")
            self.assertIsNone(session.native_runtime_integrity)
            self.assertIsNone(session.native_app)
            self.assertIsNone(session.native_carrier)
            self.assertIsNone(session.native_motion_print)
            self.assertIsNone(session.device_identity)
            self.assertIsNone(session.install_id)
            fp_page = client.fingerprints.list()
            self.assertEqual(fp_page.items[0].id, "vid_456789abcdefghjkmnpqrstvwx")
            fp_detail = client.fingerprints.get("vid_456789abcdefghjkmnpqrstvwx")
            self.assertEqual(fp_detail.id, "vid_456789abcdefghjkmnpqrstvwx")
        finally:
            client.close()

    def test_attach_and_clear_client_user_id(self) -> None:
        session_fixture = load_fixture("api/sessions/detail.json")
        seen_bodies: list[dict[str, object]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.method, "PATCH")
            self.assertEqual(request.url.path, "/v1/sessions/sid_0123456789abcdefghjkmnpqrs")
            self.assertEqual(request.headers["Authorization"], "Bearer sk_live_test")
            seen_bodies.append(json.loads(request.content.decode("utf-8")))
            return json_response(session_fixture)

        client = Foil(secret_key="sk_live_test", transport=httpx.MockTransport(handler))
        try:
            attached = client.sessions.attach_client_user("sid_0123456789abcdefghjkmnpqrs", "user_123")
            cleared = client.sessions.clear_client_user("sid_0123456789abcdefghjkmnpqrs")
            self.assertEqual(attached.id, "sid_0123456789abcdefghjkmnpqrs")
            self.assertEqual(cleared.id, "sid_0123456789abcdefghjkmnpqrs")
            self.assertEqual(seen_bodies, [{"client_user_id": "user_123"}, {"client_user_id": None}])
        finally:
            client.close()

    def test_organizations_and_api_keys(self) -> None:
        organization_fixture = load_fixture("api/organizations/organization.json")
        organization_create_fixture = load_fixture("api/organizations/organization-create.json")
        organization_update_fixture = load_fixture("api/organizations/organization-update.json")
        key_create_fixture = load_fixture("api/organizations/api-key-create.json")
        key_list_fixture = load_fixture("api/organizations/api-key-list.json")
        key_update_fixture = load_fixture("api/organizations/api-key-update.json")
        key_rotate_fixture = load_fixture("api/organizations/api-key-rotate.json")

        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            method = request.method
            if path.endswith("/v1/organizations") and method == "POST":
                return json_response(organization_create_fixture, status_code=201)
            if path.endswith("/v1/organizations/org_56789abcdefghjkmnpqrstvwxy") and method == "PATCH":
                return json_response(organization_update_fixture)
            if path.endswith("/v1/organizations/org_56789abcdefghjkmnpqrstvwxy") and method == "GET":
                return json_response(organization_fixture)
            if path.endswith("/v1/organizations/org_56789abcdefghjkmnpqrstvwxy/api-keys/key_6789abcdefghjkmnpqrstvwxyz/rotations"):
                return json_response(key_rotate_fixture, status_code=201)
            if path.endswith("/v1/organizations/org_56789abcdefghjkmnpqrstvwxy/api-keys/key_6789abcdefghjkmnpqrstvwxyz") and method == "PATCH":
                return json_response(key_update_fixture)
            if path.endswith("/v1/organizations/org_56789abcdefghjkmnpqrstvwxy/api-keys/key_6789abcdefghjkmnpqrstvwxyz"):
                return json_response(load_fixture("api/organizations/api-key-revoke.json"))
            if path.endswith("/v1/organizations/org_56789abcdefghjkmnpqrstvwxy/api-keys") and method == "POST":
                return json_response(key_create_fixture, status_code=201)
            if path.endswith("/v1/organizations/org_56789abcdefghjkmnpqrstvwxy/api-keys"):
                return json_response(key_list_fixture)
            raise AssertionError(f"Unexpected request: {method} {path}")

        client = Foil(secret_key="sk_live_test", transport=httpx.MockTransport(handler))
        try:
            self.assertEqual(client.organizations.get("org_56789abcdefghjkmnpqrstvwxy").id, "org_56789abcdefghjkmnpqrstvwxy")
            self.assertEqual(
                client.organizations.create(name="Example Organization", slug="example-organization").updated_at,
                "2026-03-24T19:10:00.000Z",
            )
            self.assertEqual(
                client.organizations.update("org_56789abcdefghjkmnpqrstvwxy", name="Updated Example Organization").name,
                "Example Organization",
            )
            self.assertEqual(
                client.organizations.api_keys.create("org_56789abcdefghjkmnpqrstvwxy", name="Production").revealed_key,
                "sk_live_[example_secret_key]",
            )
            self.assertEqual(client.organizations.api_keys.list("org_56789abcdefghjkmnpqrstvwxy").items[0].id, "key_6789abcdefghjkmnpqrstvwxyz")
            self.assertEqual(
                client.organizations.api_keys.update(
                    "org_56789abcdefghjkmnpqrstvwxy",
                    "key_6789abcdefghjkmnpqrstvwxyz",
                    name="Updated Web App",
                ).name,
                "Updated Web App",
            )
            self.assertEqual(
                client.organizations.api_keys.revoke("org_56789abcdefghjkmnpqrstvwxy", "key_6789abcdefghjkmnpqrstvwxyz").id,
                "key_6789abcdefghjkmnpqrstvwxyz",
            )
            self.assertEqual(
                client.organizations.api_keys.rotate("org_56789abcdefghjkmnpqrstvwxy", "key_6789abcdefghjkmnpqrstvwxyz").revealed_key,
                "sk_live_[rotated_example_secret_key]",
            )
        finally:
            client.close()

    def test_webhooks_use_event_history_endpoints(self) -> None:
        delivery = {
            "object": "webhook_delivery",
            "id": "wdlv_0123456789abcdef0123456789abcdef",
            "event_id": "wevt_0123456789abcdef0123456789abcdef",
            "endpoint_id": "we_0123456789abcdef0123456789abcdef",
            "event_type": "session.fingerprint.calculated",
            "status": "succeeded",
            "attempts": 1,
            "response_status": 200,
            "response_body": "{}",
            "error": None,
            "created_at": "2026-03-24T20:00:00.000Z",
            "updated_at": "2026-03-24T20:00:05.000Z",
        }
        event = {
            "object": "event",
            "id": "wevt_0123456789abcdef0123456789abcdef",
            "type": "session.fingerprint.calculated",
            "subject": {"type": "session", "id": "sid_0123456789abcdefghjkmnpqrs"},
            "data": {"source": "waitForFingerprint"},
            "webhook_deliveries": [delivery],
            "created_at": "2026-03-24T20:00:00.000Z",
        }
        list_response = {
            "data": [event],
            "pagination": {"limit": 25, "has_more": False},
            "meta": {"request_id": "req_0123456789abcdef0123456789abcdef"},
        }
        detail_response = {
            "data": event,
            "meta": {"request_id": "req_0123456789abcdef0123456789abcdef"},
        }

        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.headers["Authorization"], "Bearer sk_live_test")
            if request.url.path == "/v1/organizations/org_56789abcdefghjkmnpqrstvwxy/events":
                self.assertEqual(request.url.params.get("endpoint_id"), "we_0123456789abcdef0123456789abcdef")
                self.assertEqual(request.url.params.get("type"), "session.fingerprint.calculated")
                return json_response(list_response)
            if request.url.path == "/v1/organizations/org_56789abcdefghjkmnpqrstvwxy/events/wevt_0123456789abcdef0123456789abcdef":
                return json_response(detail_response)
            raise AssertionError(f"Unexpected request: {request.method} {request.url.path}")

        client = Foil(secret_key="sk_live_test", transport=httpx.MockTransport(handler))
        try:
            page = client.webhooks.list_events(
                "org_56789abcdefghjkmnpqrstvwxy",
                endpoint_id="we_0123456789abcdef0123456789abcdef",
                type="session.fingerprint.calculated",
                limit=25,
            )
            self.assertEqual(page.items[0].subject.id, "sid_0123456789abcdefghjkmnpqrs")
            self.assertEqual(page.items[0].webhook_deliveries[0].status, "succeeded")
            fetched = client.webhooks.retrieve_event(
                "org_56789abcdefghjkmnpqrstvwxy",
                "wevt_0123456789abcdef0123456789abcdef",
            )
            self.assertEqual(fetched.type, "session.fingerprint.calculated")
        finally:
            client.close()

    def test_gate_namespace_supports_public_bearer_and_secret_flows(self) -> None:
        registry_list_fixture = load_fixture("api/gate/registry-list.json")
        registry_detail_fixture = load_fixture("api/gate/registry-detail.json")
        services_list_fixture = load_fixture("api/gate/services-list.json")
        service_detail_fixture = load_fixture("api/gate/service-detail.json")
        service_create_fixture = load_fixture("api/gate/service-create.json")
        service_update_fixture = load_fixture("api/gate/service-update.json")
        service_disable_fixture = load_fixture("api/gate/service-disable.json")
        session_create_fixture = load_fixture("api/gate/session-create.json")
        session_poll_fixture = load_fixture("api/gate/session-poll.json")
        session_ack_fixture = load_fixture("api/gate/session-ack.json")
        login_create_fixture = load_fixture("api/gate/login-session-create.json")
        login_consume_fixture = load_fixture("api/gate/login-session-consume.json")
        agent_verify_fixture = load_fixture("api/gate/agent-token-verify.json")

        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            auth = request.headers.get("Authorization")
            if path == "/v1/gate/registry":
                self.assertIsNone(auth)
                return json_response(registry_list_fixture)
            if path == "/v1/gate/registry/foil":
                self.assertIsNone(auth)
                return json_response(registry_detail_fixture)
            if path == "/v1/gate/services" and request.method == "GET":
                self.assertEqual(auth, "Bearer sk_live_test")
                return json_response(services_list_fixture)
            if path == "/v1/gate/services/foil" and request.method == "GET":
                self.assertEqual(auth, "Bearer sk_live_test")
                return json_response(service_detail_fixture)
            if path == "/v1/gate/services" and request.method == "POST":
                self.assertEqual(auth, "Bearer sk_live_test")
                return json_response(service_create_fixture, status_code=201)
            if path == "/v1/gate/services/acme_prod" and request.method == "PATCH":
                self.assertEqual(auth, "Bearer sk_live_test")
                return json_response(service_update_fixture)
            if path == "/v1/gate/services/acme_prod" and request.method == "DELETE":
                self.assertEqual(auth, "Bearer sk_live_test")
                return json_response(service_disable_fixture)
            if path == "/v1/gate/sessions":
                self.assertIsNone(auth)
                return json_response(session_create_fixture, status_code=201)
            if path == "/v1/gate/sessions/gate_0123456789abcdefghjkmnpqrs":
                self.assertEqual(auth, "Bearer gtpoll_0123456789abcdefghjkmnpqrs")
                return json_response(session_poll_fixture)
            if path == "/v1/gate/sessions/gate_0123456789abcdefghjkmnpqrs/ack":
                self.assertEqual(auth, "Bearer gtpoll_0123456789abcdefghjkmnpqrs")
                return json_response(session_ack_fixture)
            if path == "/v1/gate/login-sessions":
                self.assertEqual(auth, "Bearer agt_0123456789abcdefghjkmnpqrs")
                return json_response(login_create_fixture, status_code=201)
            if path == "/v1/gate/login-sessions/consume":
                self.assertEqual(auth, "Bearer sk_live_test")
                return json_response(login_consume_fixture)
            if path == "/v1/gate/agent-tokens/verify":
                self.assertEqual(auth, "Bearer sk_live_test")
                return json_response(agent_verify_fixture)
            if path == "/v1/gate/agent-tokens/revoke":
                self.assertEqual(auth, "Bearer sk_live_test")
                return httpx.Response(status_code=204)
            raise AssertionError(f"Unexpected request: {request.method} {path}")

        client = Foil(secret_key="sk_live_test", transport=httpx.MockTransport(handler))
        try:
            self.assertEqual(client.gate.registry.list()[0].id, "foil")
            self.assertEqual(client.gate.registry.get("foil").id, "foil")
            self.assertEqual(client.gate.services.list()[0].id, "acme_prod")
            self.assertEqual(client.gate.services.get("foil").id, "acme_prod")
            self.assertEqual(
                client.gate.services.create(
                    id="acme_prod",
                    name="Acme Production",
                    description="Acme production signup flow",
                    website="https://acme.example.com",
                    webhook_endpoint_id="we_0123456789abcdef0123456789abcdef",
                ).id,
                "acme_prod",
            )
            self.assertTrue(client.gate.services.update("acme_prod", discoverable=True).discoverable)
            self.assertEqual(client.gate.services.disable("acme_prod").status, "disabled")
            self.assertEqual(
                client.gate.sessions.create(
                    service_id="foil",
                    account_name="my-project",
                    delivery={
                        "version": 1,
                        "algorithm": "x25519-hkdf-sha256/aes-256-gcm",
                        "key_id": "kid_integrator_0123456789abcdefgh",
                        "public_key": "public_key_integrator",
                    },
                ).id,
                "gate_0123456789abcdefghjkmnpqrs",
            )
            self.assertEqual(
                client.gate.sessions.poll(
                    "gate_0123456789abcdefghjkmnpqrs",
                    poll_token="gtpoll_0123456789abcdefghjkmnpqrs",
                ).status,
                "approved",
            )
            self.assertEqual(
                client.gate.sessions.acknowledge(
                    "gate_0123456789abcdefghjkmnpqrs",
                    poll_token="gtpoll_0123456789abcdefghjkmnpqrs",
                    ack_token="gtack_0123456789abcdefghjkmnpqrs",
                ).status,
                "acknowledged",
            )
            self.assertEqual(
                client.gate.login_sessions.create(
                    service_id="foil",
                    agent_token="agt_0123456789abcdefghjkmnpqrs",
                ).object,
                "gate_login_session",
            )
            self.assertEqual(
                client.gate.login_sessions.consume(code="gate_code_0123456789abcdefghjkm").object,
                "gate_dashboard_login",
            )
            self.assertTrue(client.gate.agent_tokens.verify(agent_token="agt_0123456789abcdefghjkmnpqrs").valid)
            self.assertIsNone(client.gate.agent_tokens.revoke(agent_token="agt_0123456789abcdefghjkmnpqrs"))
        finally:
            client.close()

    def test_validation_errors_are_parsed(self) -> None:
        fixture = load_fixture("errors/validation-error.json")
        self._assert_api_error_fixture(fixture, expected_field_errors=True)

    def test_auth_and_not_found_errors_are_parsed(self) -> None:
        for name in ("errors/missing-api-key.json", "errors/invalid-api-key.json", "errors/not-found.json"):
            with self.subTest(name=name):
                self._assert_api_error_fixture(load_fixture(name))

    def _assert_api_error_fixture(
        self,
        fixture: dict[str, object],
        *,
        expected_field_errors: bool = False,
    ) -> None:
        error = fixture["error"]
        assert isinstance(error, dict)
        client = Foil(
            secret_key="sk_live_test",
            transport=httpx.MockTransport(
                lambda _request: json_response(
                    fixture,
                    status_code=int(error["status"]),
                    headers={"x-request-id": str(error["request_id"])},
                )
            ),
        )
        try:
            with self.assertRaises(FoilApiError) as exc:
                client.sessions.list(limit=999)
            self.assertEqual(exc.exception.code, error["code"])
            self.assertEqual(exc.exception.request_id, error["request_id"])
            self.assertEqual(exc.exception.docs_url, error.get("docs_url"))
            self.assertEqual(bool(exc.exception.field_errors), expected_field_errors)
        finally:
            client.close()
