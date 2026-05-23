# Foil Python Library

![Preview](https://img.shields.io/badge/status-preview-111827)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)
![License: MIT](https://img.shields.io/badge/license-MIT-0f766e.svg)

The Foil Python library provides convenient access to the Foil API from applications written in Python. It includes a synchronous client for Sessions, Fingerprints, Organizations, Organization API key management, sealed token verification, Gate, and Gate delivery/webhook helpers.

The library also provides:

- a fast configuration path using `FOIL_SECRET_KEY`
- iterator helpers for cursor-based pagination
- structured API errors and built-in sealed token verification
- webhook endpoint management, test sends, and event delivery history
- public, bearer-token, and secret-key auth modes for Gate flows
- Gate delivery/webhook helpers

## Documentation

See the [Foil docs](https://usefoil.com/docs) and [API reference](https://usefoil.com/docs/api-reference/introduction).

## Installation

You don't need this source code unless you want to modify the package. If you just want to use the package, run:

```bash
pip install foil-server
```

## Requirements

- Python 3.10+

## Usage

Use `FOIL_SECRET_KEY` or `secret_key=...` for core detect APIs. For public or bearer-auth Gate flows, the client can also be created without a secret key:

```python
from foil_server import Foil

client = Foil(secret_key="sk_live_...")

page = client.sessions.list(verdict="bot", limit=25)
session = client.sessions.get("sid_123")
client.sessions.attach_client_user("sid_123", "user_123")
client.sessions.clear_client_user("sid_123")
```

### Sealed token verification

```python
from foil_server import safe_verify_foil_token

result = safe_verify_foil_token(
    sealed_token,
    "sk_live_...",
)

if result.ok:
    print(result.data.verdict, result.data.score)
else:
    print(result.error)
```

### Pagination

```python
for session in client.sessions.iter(search="signup"):
    print(session.id, session.latest_decision.verdict)
```

### Fingerprints

```python
page = client.fingerprints.list(sort="seen_count")
fingerprint = client.fingerprints.get("vid_123")
```

### Organizations

```python
organization = client.organizations.get("org_123")
updated = client.organizations.update("org_123", name="New Name")
```

### Organization API keys

```python
created = client.organizations.api_keys.create(
    "org_123",
    name="Production",
    type="secret",
    scopes=["sessions:list", "sessions:read"],
)

client.organizations.api_keys.revoke("org_123", created.id)
```

### Webhooks

```python
endpoint = client.webhooks.create_endpoint(
    "org_123",
    name="Production alerts",
    url="https://example.com/foil/webhook",
    event_types=["session.result.persisted", "gate.session.approved"],
)

events = client.webhooks.list_events(
    "org_123",
    endpoint_id=endpoint.id,
    type="session.result.persisted",
)

print(events.items[0].webhook_deliveries[0].status)
```

### Gate APIs

```python
from foil_server import Foil, create_delivery_key_pair

client = Foil()
services = client.gate.registry.list()
session = client.gate.sessions.create(
    service_id="foil",
    account_name="my-project",
    delivery=create_delivery_key_pair().delivery,
)

print(services[0].id, session.consent_url)
```

### Gate delivery and webhook helpers

```python
from foil_server import (
    create_delivery_key_pair,
    create_gate_approved_webhook_response,
    decrypt_gate_delivery_envelope,
    parse_webhook_event,
    verify_gate_webhook_signature,
)

key_pair = create_delivery_key_pair()
response = create_gate_approved_webhook_response(
    {
        "delivery": key_pair.delivery,
        "outputs": {
            "FOIL_PUBLISHABLE_KEY": "pk_live_...",
            "FOIL_SECRET_KEY": "sk_live_...",
        },
    }
)
payload = decrypt_gate_delivery_envelope(key_pair.private_key, response.encrypted_delivery)
print(payload.outputs["FOIL_SECRET_KEY"])
raw_body = '{"id":"wevt_123","object":"webhook_event","type":"webhook.test","created":"2026-04-26T00:00:00.000Z","data":{}}'
print(
    verify_gate_webhook_signature(
        secret="whsec_test",
        timestamp="1735776000",
        raw_body=raw_body,
        signature="…",
    )
)
event = parse_webhook_event(raw_body)
print(event.type)
```

### Error handling

```python
from foil_server import FoilApiError

try:
    client.sessions.list(limit=999)
except FoilApiError as error:
    print(error.status, error.code, error.message)
```

## Support

If you need help integrating Foil, start with [usefoil.com/docs](https://usefoil.com/docs).
