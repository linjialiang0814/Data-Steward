"""Strict Pydantic wire models for pairing HTTP (extra=forbid, strict)."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

PROTOCOL_VERSION_LITERAL = Literal["pairing_auth/1"]
CREDENTIAL_STATUS_HELLO = Literal["PENDING"]
CREDENTIAL_STATUS_CONFIRM = Literal["PENDING", "ACTIVE"]
CREDENTIAL_STATUS_STATUS = Literal[
    "PENDING", "ACTIVE", "UNKNOWN", "EXPIRED", "REVOKED"
]
SESSION_STATE = Literal[
    "PAIRING_ACTIVE",
    "AWAITING_CONFIRM",
    "ACTIVE_PAIR",
    "ABORTED_TIMEOUT",
    "ABORTED_CANCEL",
    "ABORTED_MISMATCH",
    "ABORTED_HUB_RESTART",
    "ABORTED_PROTOCOL",
]

_ULID_RE = re.compile(r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$")
_HUMAN32_RE = re.compile(r"^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{8}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


class StrictPairingModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class PairingErrorBody(StrictPairingModel):
    error_code: str
    message_key: str


class ClientHelloRequest(StrictPairingModel):
    protocol_version: str
    pairing_attempt_id: str = Field(min_length=26, max_length=26)
    pairing_token: str = Field(min_length=43, max_length=43)
    claim_secret: str = Field(min_length=43, max_length=43)
    device_credential_digest: str = Field(min_length=64, max_length=64)
    client_nonce: str = Field(min_length=22, max_length=22)
    requested_capabilities: list[str] = Field(min_length=1, max_length=32)
    platform: str = Field(min_length=1, max_length=32)
    display_name: str | None = Field(default=None, min_length=1, max_length=64)

    @field_validator("pairing_attempt_id")
    @classmethod
    def _attempt_ulid(cls, value: str) -> str:
        if not _ULID_RE.fullmatch(value):
            raise ValueError("pairing_attempt_id_invalid")
        return value

    @field_validator("device_credential_digest")
    @classmethod
    def _cred_digest(cls, value: str) -> str:
        if not _DIGEST_RE.fullmatch(value):
            raise ValueError("device_credential_digest_invalid")
        return value


class ClientHelloResponse(StrictPairingModel):
    protocol_version: PROTOCOL_VERSION_LITERAL
    pairing_session_id: str
    pairing_attempt_id: str
    device_id: str
    credential_status: CREDENTIAL_STATUS_HELLO
    short_verification_code: str
    server_time: str
    pending_expires_at_hint: str

    @field_validator(
        "pairing_session_id", "pairing_attempt_id", "device_id"
    )
    @classmethod
    def _ulids(cls, value: str) -> str:
        if not _ULID_RE.fullmatch(value):
            raise ValueError("ulid_invalid")
        return value

    @field_validator("short_verification_code")
    @classmethod
    def _human32(cls, value: str) -> str:
        if not _HUMAN32_RE.fullmatch(value):
            raise ValueError("short_code_invalid")
        return value


class ClientConfirmRequest(StrictPairingModel):
    protocol_version: str
    pairing_attempt_id: str = Field(min_length=26, max_length=26)
    short_verification_code: str = Field(min_length=8, max_length=8)

    @field_validator("pairing_attempt_id")
    @classmethod
    def _attempt_ulid(cls, value: str) -> str:
        if not _ULID_RE.fullmatch(value):
            raise ValueError("pairing_attempt_id_invalid")
        return value

    @field_validator("short_verification_code")
    @classmethod
    def _human32(cls, value: str) -> str:
        if not _HUMAN32_RE.fullmatch(value):
            raise ValueError("short_code_invalid")
        return value


class ClientConfirmResponse(StrictPairingModel):
    protocol_version: PROTOCOL_VERSION_LITERAL
    pairing_attempt_id: str
    device_id: str
    credential_status: CREDENTIAL_STATUS_CONFIRM
    granted_capabilities: list[str]
    capability_epoch: int = Field(ge=0)

    @field_validator("pairing_attempt_id", "device_id")
    @classmethod
    def _ulids(cls, value: str) -> str:
        if not _ULID_RE.fullmatch(value):
            raise ValueError("ulid_invalid")
        return value


class PairingStatusResponse(StrictPairingModel):
    protocol_version: PROTOCOL_VERSION_LITERAL
    pairing_session_id: str
    pairing_attempt_id: str
    session_state: SESSION_STATE
    credential_status: CREDENTIAL_STATUS_STATUS
    device_id: str | None
    capability_epoch: int = Field(ge=0)

    @field_validator("pairing_session_id", "pairing_attempt_id")
    @classmethod
    def _ulids(cls, value: str) -> str:
        if not _ULID_RE.fullmatch(value):
            raise ValueError("ulid_invalid")
        return value

    @field_validator("device_id")
    @classmethod
    def _optional_device(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _ULID_RE.fullmatch(value):
            raise ValueError("ulid_invalid")
        return value
