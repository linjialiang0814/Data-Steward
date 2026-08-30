# Shared Session Transport v1

## Scope

P0-S1-T02B adapts the T02A `EventStore` to a single-process FastAPI/Uvicorn
transport. It is strictly loopback-only and unauthenticated. It must not be
exposed to a phone, LAN, or public network.

The durable ordering field remains `conversation_seq`. Delivery semantics are
at-least-once delivery plus client-side idempotent consumption by `event_id`,
not network exactly-once.

## REST

### `GET /health`

Returns only:

```json
{
  "status": "ok",
  "protocol_version": 1,
  "database_ready": true,
  "transport_scope": "loopback_only"
}
```

### `POST /v1/conversations`

Input:

```json
{"title": "Shared session", "conversation_id": "optional-id"}
```

Success is `201`.

### `POST /v1/conversations/{conversation_id}/messages`

Input contains `client_message_id`, `actor_device_id`, `role`, `content`, and
optional `causation_id` / `correlation_id`.

- new durable event: `201`, `deduplicated=false`;
- identical durable retry: `200`, `deduplicated=true`;
- reused key with changed input: `409 idempotency_conflict`;
- missing conversation: `404 conversation_not_found`.

Only a newly committed event is broadcast. A deduplicated retry is not
broadcast again.

### `GET /v1/conversations/{conversation_id}/events`

Query parameters:

- `after_seq`: exclusive cursor, integer `>= 0`;
- `limit`: `1..500`.

The response contains ordered `events` and `last_conversation_seq`. An empty
page at the server watermark returns that server watermark.

The server watermark is `conversation.next_seq - 1`. If `after_seq` is greater
than it, REST returns:

```json
{
  "error": {
    "code": "cursor_ahead",
    "message": "replay cursor exceeds server state",
    "server_last_conversation_seq": 20
  }
}
```

The status is `409`. The server does not echo the invalid cursor or silently
clamp it because either behavior could hide a damaged client projection. A
client recovers by retrying from its last verified `conversation_seq`.

## Stable errors

REST errors use:

```json
{"error": {"code": "stable_code", "message": "sanitized message"}}
```

Supported codes include `validation_error`, `conversation_not_found`,
`conversation_already_exists`, `idempotency_conflict`, and
`persistence_unavailable`. `cursor_ahead` additionally returns only the
server's durable watermark. Validation and persistence responses omit input
values, database paths, stack traces, and internal exception text.

## Wire event

The transport parses T02A `payload_json` into a JSON object named `payload`.
It does not expose the internal serialized string.

`payload_sha256` is copied unchanged. It continues to mean SHA-256 over the
exact T02A stable UTF-8 `payload_json`; the adapter does not redefine or
recompute it over a different representation.

Before conversion, the adapter:

1. recomputes SHA-256 over the exact original `payload_json` UTF-8 bytes;
2. compares it deterministically with stored `payload_sha256`;
3. requires a valid JSON object matching strict `WirePayload` fields/types;
4. requires `payload.accepted_seq == event.conversation_seq`.

Any mismatch fails closed as a sanitized persistence error. REST returns
`503`; WebSocket closes with `1011` before sending the corrupt event. Error
output never contains payload text, either hash, database path, or message ID.

## WebSocket

Path:

`/v1/conversations/{conversation_id}/events/ws?after_seq=N`

Frames:

```json
{"kind": "event", "delivery": "replay", "event": {}}
```

```json
{"kind": "ready", "last_conversation_seq": 20}
```

Connection algorithm:

1. verify the conversation and register a bounded subscription queue;
2. replay SQLite events after the exclusive cursor;
3. send replay frames in increasing `conversation_seq`;
4. drain registration-time notifications and reread durable gaps, deduplicating
   by sequence;
5. send `ready`;
6. for each live notification, reread from the last sent sequence and send
   durable events in order;
7. concurrently listen for WebSocket disconnect and unregister reliably.

Before step 1, the server reads the durable watermark. An ahead cursor is
accepted only long enough to send:

```json
{
  "kind": "error",
  "error": {
    "code": "cursor_ahead",
    "message": "replay cursor exceeds server state",
    "server_last_conversation_seq": 20
  }
}
```

It then closes with `1008` without registering a subscription. A subsequent
connection with a verified cursor can replay and continue live delivery.

SQLite, not the queue, is the fact source. This closes the replay/live race:
notifications only wake the connection, while any gap is recovered from
persistence.

WebSocket is delivery-only. Client data frames are rejected; messages are
submitted through REST.

## Slow clients

Each connection has a bounded queue. On overflow the subscription is removed
and the connection closes with code `1013`, requiring REST or WebSocket replay
from the last persisted cursor. The server never grows an unbounded queue.

Broadcast occurs only after commit. Broadcast failure does not roll back a
successful database transaction; reconnect replay recovers it.

## Process and network boundary

- host is exactly `127.0.0.1`;
- `0.0.0.0`, hostnames, IPv6, LAN, and public addresses are rejected;
- one worker, reload disabled;
- proxy headers and access logs disabled;
- no permissive CORS;
- no firewall modification;
- no file browsing, arbitrary file API, command execution, debug eval, or
  WebSocket message submission.

The database path is supplied by process argument or environment and never
returned by the API.

## Before T02C

Any LAN exposure requires a separate authorized task that adds device
authentication, pairing approval, scoped credentials, TLS, certificate
fingerprint verification, revocation, origin policy, and threat-focused
testing. Until those controls pass, this transport must remain loopback-only.
