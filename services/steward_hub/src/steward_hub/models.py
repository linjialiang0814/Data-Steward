"""Immutable domain models for shared-session persistence."""

from dataclasses import dataclass


PROTOCOL_VERSION = 1
MESSAGE_ACCEPTED_EVENT = "conversation.message.accepted"


@dataclass(frozen=True, slots=True)
class Conversation:
    conversation_id: str
    title: str
    next_seq: int
    created_at: str
    updated_at: str


@dataclass(frozen=True, slots=True)
class ConversationMessage:
    message_id: str
    conversation_id: str
    client_message_id: str
    actor_device_id: str
    role: str
    content: str
    accepted_seq: int
    occurred_at: str


@dataclass(frozen=True, slots=True)
class ConversationEvent:
    event_id: str
    protocol_version: int
    event_type: str
    conversation_id: str
    conversation_seq: int
    actor_device_id: str
    causation_id: str
    correlation_id: str
    occurred_at: str
    payload_json: str
    payload_sha256: str


@dataclass(frozen=True, slots=True)
class AppendMessageResult:
    message: ConversationMessage
    event: ConversationEvent
    deduplicated: bool
