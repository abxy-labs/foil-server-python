# Foil Python Library

![Preview](https://img.shields.io/badge/status-preview-111827)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)
![License: MIT](https://img.shields.io/badge/license-MIT-0f766e.svg)

The Foil Python library provides convenient access to the Foil API from applications written in Python. It includes a synchronous client for Sessions, Fingerprints, Organizations, Organization API key management, webhook endpoints, and sealed token verification.

The library also provides:

- a fast configuration path using `FOIL_SECRET_KEY`
- iterator helpers for cursor-based pagination
- structured API errors and built-in sealed token verification
- webhook endpoint management, test sends, event delivery history, and webhook signature verification

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

Use `FOIL_SECRET_KEY` or `secret_key=...`:

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
    event_types=["session.result.persisted"],
)

events = client.webhooks.list_events(
    "org_123",
    endpoint_id=endpoint.id,
    type="session.result.persisted",
)

print(events.items[0].webhook_deliveries[0].status)
```

#### Verifying webhook deliveries

Every webhook delivery is signed with your endpoint's signing secret. Verify the `X-Foil-Timestamp` and `X-Foil-Signature` headers against the raw request body before trusting the payload:

```python
import os

from foil_server import parse_webhook_event, verify_and_parse_webhook_event, verify_webhook_signature

valid = verify_webhook_signature(
    secret=os.environ["FOIL_WEBHOOK_SECRET"],
    timestamp=request.headers["X-Foil-Timestamp"],
    raw_body=raw_body,
    signature=request.headers["X-Foil-Signature"],
)

# Verify and parse in one step. Raises ValueError if the signature is invalid or expired.
event = verify_and_parse_webhook_event(
    secret=os.environ["FOIL_WEBHOOK_SECRET"],
    timestamp=request.headers["X-Foil-Timestamp"],
    raw_body=raw_body,
    signature=request.headers["X-Foil-Signature"],
)

if event.type == "session.result.persisted":
    print(event.data)

# Parse a payload you have already verified.
parsed = parse_webhook_event(raw_body)
```

Signatures older than five minutes are rejected by default. Pass `max_age_seconds` to change the tolerance.

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
