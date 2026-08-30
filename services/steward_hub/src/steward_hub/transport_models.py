"""Pydantic wire models for the loopback-only transport."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictWireModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class HealthResponse(StrictWireModel):
    status: Literal["ok"]
    protocol_version: int
    database_ready: bool
    transport_scope: Literal[
        "loopback_only",
        "private_lan_pairing_only",
        "private_lan_authenticated_service",
    ]


class DeviceSelfResponse(StrictWireModel):
    protocol_version: Literal["pairing_auth/1"]
    hub_id: str
    device_id: str
    status: Literal["ACTIVE"]
    capability_epoch: int = Field(ge=1)
    granted_capabilities: list[str]
    display_name: str | None
    platform: str


class CreateConversationRequest(StrictWireModel):
    title: str = Field(min_length=1, max_length=200)
    conversation_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
    )


class ConversationResponse(StrictWireModel):
    conversation_id: str
    title: str
    next_seq: int
    created_at: str
    updated_at: str


class AppendMessageRequest(StrictWireModel):
    client_message_id: str = Field(min_length=1, max_length=128)
    actor_device_id: str = Field(min_length=1, max_length=128)
    role: Literal["user", "assistant", "system", "tool"]
    content: str = Field(min_length=1, max_length=65_536)
    causation_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
    )
    correlation_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
    )


class WirePayload(StrictWireModel):
    accepted_seq: int
    client_message_id: str
    message_id: str
    role: str
    content: str


class WireEvent(StrictWireModel):
    event_id: str
    protocol_version: int
    event_type: str
    conversation_id: str
    conversation_seq: int
    actor_device_id: str
    causation_id: str
    correlation_id: str
    occurred_at: str
    payload: WirePayload
    payload_sha256: str


class AppendMessageResponse(StrictWireModel):
    message_id: str
    deduplicated: bool
    event: WireEvent


class ProductActionResponse(StrictWireModel):
    action_id: str
    assistant_message_id: str
    kind: str
    label: str
    description: str
    risk: str
    requires_confirmation: bool
    required_capability: str
    status: str


class ProductActionListResponse(StrictWireModel):
    actions: list[ProductActionResponse]


class ProductActionExecutionResponse(StrictWireModel):
    status: str
    event: WireEvent
    actions: list[ProductActionResponse]


class MemoryCenterResponse(StrictWireModel):
    status: Literal["none", "learning", "candidate", "active", "forgotten"]
    support_count: int = Field(ge=0)
    activation_threshold: int = Field(ge=1)
    version: int | None
    actions: list[ProductActionResponse]


class EventListResponse(StrictWireModel):
    events: list[WireEvent]
    last_conversation_seq: int


class ErrorBody(StrictWireModel):
    code: str
    message: str


class ErrorResponse(StrictWireModel):
    error: ErrorBody


class CursorAheadErrorBody(ErrorBody):
    server_last_conversation_seq: int


class CursorAheadErrorResponse(StrictWireModel):
    error: CursorAheadErrorBody
