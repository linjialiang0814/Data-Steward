"""Strict wire models for trusted local credential administration."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .pairing_codec import canonicalize_capabilities


class StrictOperatorModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class RevokeCredentialRequest(StrictOperatorModel):
    expected_capability_epoch: int = Field(ge=1, le=9_223_372_036_854_775_807)


class UpdateCapabilitiesRequest(StrictOperatorModel):
    expected_capability_epoch: int = Field(ge=1, le=9_223_372_036_854_775_807)
    granted_capabilities: list[str] = Field(min_length=1, max_length=32)

    @field_validator("granted_capabilities")
    @classmethod
    def _canonical_capabilities(cls, value: list[str]) -> list[str]:
        ordered, _, _ = canonicalize_capabilities(value)
        return ordered


class CredentialTransitionResponse(StrictOperatorModel):
    device_id: str
    status: Literal["ACTIVE", "REVOKED"]
    capability_epoch: int = Field(ge=1)
    granted_capabilities: list[str]
    changed: bool
    closed_connection_count: int = Field(ge=0)


class CredentialStatusResponse(StrictOperatorModel):
    device_id: str
    status: Literal["PENDING", "ACTIVE", "REVOKED", "EXPIRED"]
    capability_epoch: int = Field(ge=0)
    requested_capabilities: list[str]
    granted_capabilities: list[str]
    display_name: str | None
    platform: str


class CredentialListResponse(StrictOperatorModel):
    devices: list[CredentialStatusResponse] = Field(max_length=32)


class CreatePairingSessionRequest(StrictOperatorModel):
    pairing_token_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    ttl_seconds: int = Field(ge=60, le=900)


class CreatePairingSessionResponse(StrictOperatorModel):
    protocol_version: Literal["pairing_auth/1"]
    hub_id: str
    cert_fingerprint: str
    pairing_session_id: str
    state: Literal["PAIRING_ACTIVE"]
    expires_at_server: str


class ConfirmPairingSessionRequest(StrictOperatorModel):
    granted_capabilities: list[str] = Field(min_length=1, max_length=32)

    @field_validator("granted_capabilities")
    @classmethod
    def _canonical_grants(cls, value: list[str]) -> list[str]:
        ordered, _, _ = canonicalize_capabilities(value)
        return ordered


class OperatorPairingStatusResponse(StrictOperatorModel):
    protocol_version: Literal["pairing_auth/1"]
    pairing_session_id: str
    hub_id: str
    state: str
    expires_at_server: str
    terminal_reason: str | None
    pairing_attempt_id: str | None
    device_id: str | None
    short_verification_code: str | None
    requested_capabilities: list[str]
    granted_capabilities: list[str]
    display_name: str | None
    platform: str | None
    client_confirmed: bool
    hub_confirmed: bool
    credential_status: str | None
    capability_epoch: int = Field(ge=0)


class CancelPairingSessionResponse(StrictOperatorModel):
    protocol_version: Literal["pairing_auth/1"]
    pairing_session_id: str
    state: str
    cancelled: bool
