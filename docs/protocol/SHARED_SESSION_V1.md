# Shared Session Protocol v1

## Status and scope

P0-S1-T02A defines the durable domain contract and SQLite event-store
semantics only. It does not define or implement HTTP, WebSocket, TLS, pairing,
device registration, presence, realtime push, or Flutter integration.

The canonical ordering field is `conversation_seq`. The protocol and database
do not expose a parallel `session_seq` field.

## Message append input

`append_message` accepts:

- `conversation_id`
- `client_message_id`
- `actor_device_id`
- `role`
- `content`
- optional `causation_id`
- optional `correlation_id`

Identifiers and text must be nonempty and must not contain surrounding
whitespace. Identifiers and `actor_device_id` are limited to 128 characters,
title to 200 characters, and content to 65,536 characters. Supported roles are
`user`, `assistant`, `system`, and `tool`.

The domain core stores no IP address, credential, token, complete device serial
number, or user file content outside the explicit message content supplied by
the caller.

## Event envelope

T02A supports `conversation.message.accepted`:

```json
{
  "event_id": "uuid",
  "protocol_version": 1,
  "event_type": "conversation.message.accepted",
  "conversation_id": "conversation-id",
  "conversation_seq": 42,
  "actor_device_id": "logical-device-id",
  "causation_id": "client-message-id",
  "correlation_id": "conversation-id",
  "occurred_at": "2026-07-28T02:00:00.000Z",
  "payload_json": "{\"accepted_seq\":42,\"client_message_id\":\"...\"}",
  "payload_sha256": "lowercase-sha256"
}
```

`occurred_at` is UTC RFC3339 with a `Z` suffix. `payload_json` uses UTF-8,
sorted object keys, compact separators, and no ASCII coercion.
`payload_sha256` is SHA-256 over the exact UTF-8 payload bytes.

## Sequence and transaction boundary

Each conversation stores `next_seq`. A new append runs inside
`BEGIN IMMEDIATE` and:

1. verifies that the conversation exists;
2. checks `(conversation_id, client_message_id)`;
3. reads and increments `next_seq`;
4. inserts the message with `accepted_seq`;
5. inserts its `conversation.message.accepted` event with the same
   `conversation_seq`;
6. commits all changes together.

Any failure rolls back the sequence update, message, and event. Sequence
allocation does not use SQLite `AUTOINCREMENT`. Database constraints enforce
unique `(conversation_id, conversation_seq)`, unique
`(conversation_id, client_message_id)`, and unique `event_id`.

SQLite runs in WAL mode. Every operation enables `foreign_keys` and a bounded
`busy_timeout`.

## Durable idempotency and conflict behavior

Resubmitting the same `(conversation_id, client_message_id)` with the same
actor, role, content, causation, and correlation returns the originally stored
message and event with `deduplicated=true`. It does not insert another row or
advance `next_seq`.

Reusing that key with different persisted input is an idempotency conflict and
fails closed. It is never accepted as a normal duplicate.

This is durable idempotent write behavior, not a claim of network
exactly-once.

## Replay

`replay_events(conversation_id, after_seq, limit)` returns events ordered by
strictly increasing `conversation_seq`.

- `after_seq` is an exclusive cursor and must be an integer greater than or
  equal to zero;
- `limit` must be between 1 and 500;
- an existing conversation with no later events returns an empty list;
- a missing conversation returns a domain error rather than an empty success.

For pagination, the next request uses the last returned event's
`conversation_seq` as `after_seq`. A client must not use the returned item
count as its cursor. A final short page is valid; the next request after the
last event returns an empty list.

Future transport semantics are **at-least-once delivery plus idempotent
consumption**. Clients persist `last_conversation_seq`, replay gaps, and apply
events idempotently by `event_id`; the network layer must not claim
exactly-once delivery.

## Reproducible evidence

`semantic_projection_hash` is SHA-256 over stable event meaning:

- `protocol_version`
- `event_type`
- `conversation_seq`
- `actor_device_id`
- `causation_id`
- `correlation_id`
- payload `accepted_seq`, `client_message_id`, `role`, and `content`

It intentionally excludes random `event_id`, random payload `message_id`,
`occurred_at`, and the derived `payload_sha256`. This makes the logical
projection reproducible across independent runs without changing production
UUID or timestamp generation.

This semantic hash is not a substitute for persistence verification. Within
one smoke run, the complete `ConversationEvent` list before database close and
after reopening the same database must compare equal. That full comparison
includes event IDs, timestamps, complete payload JSON, and payload SHA-256.

## S6-G-R1 unified gateway acknowledgement contract

For an authenticated user message handled by the unified conversation
gateway, the durable user message is appended before any Hermes planning,
catalog query, content analysis, archive-memory lookup, or action preparation
starts. The REST acknowledgement therefore describes the accepted user
message only; it does not wait for, or falsely acknowledge, the derived work.

Derived work is owned by the Hub lifecycle and is single-flight. Reusing the
same idempotency key attaches to the existing work and never creates a second
assistant result. When a different request arrives while the one-slot gateway
is occupied, the Hub appends a visible safe assistant result explaining that
the request was accepted but its derived work was not run. The Hub does not
silently drop the work and does not retry it automatically. Any later retry is
an explicit user action with a new client message identity.

Exact supported file operations are parsed deterministically by the trusted
Host before the optional model planner. Fuzzy requests may use the configured
Hermes planner, but model output remains a plan which is validated and
executed through the existing capability, snapshot, preview, confirmation,
receipt, and undo boundaries.

## Deferred work

P0-S1-T02A does not verify realtime network delivery or communication among
three physical clients. REST/WebSocket transport, authentication, pairing,
device presence, Flutter projection, reconnect behavior, and true
Windows/phone/pad communication remain future tasks.
