"""Dataclasses for pairing storage views (digest-safe / redacted)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


SESSION_PAIRING_ACTIVE = "PAIRING_ACTIVE"
SESSION_AWAITING_CONFIRM = "AWAITING_CONFIRM"
SESSION_ACTIVE_PAIR = "ACTIVE_PAIR"
SESSION_ABORTED_TIMEOUT = "ABORTED_TIMEOUT"
SESSION_ABORTED_CANCEL = "ABORTED_CANCEL"
SESSION_ABORTED_MISMATCH = "ABORTED_MISMATCH"
SESSION_ABORTED_HUB_RESTART = "ABORTED_HUB_RESTART"
SESSION_ABORTED_PROTOCOL = "ABORTED_PROTOCOL"

OPEN_SESSION_STATES = frozenset(
    {SESSION_PAIRING_ACTIVE, SESSION_AWAITING_CONFIRM}
)
TERMINAL_SESSION_STATES = frozenset(
    {
        SESSION_ACTIVE_PAIR,
        SESSION_ABORTED_TIMEOUT,
        SESSION_ABORTED_CANCEL,
        SESSION_ABORTED_MISMATCH,
        SESSION_ABORTED_HUB_RESTART,
        SESSION_ABORTED_PROTOCOL,
    }
)

CREDENTIAL_PENDING = "PENDING"
CREDENTIAL_ACTIVE = "ACTIVE"
CREDENTIAL_REVOKED = "REVOKED"
CREDENTIAL_EXPIRED = "EXPIRED"


@dataclass(frozen=True)
class HubIdentity:
    hub_id: str
    cert_fingerprint: str
    tls_storage_kind: str
    tls_key_ref_id: str
    created_at: str
    rotated_at: str | None


@dataclass(frozen=True)
class HubRuntime:
    boot_id: str
    hub_id: str
    started_at: str
    stopped_at: str | None


@dataclass(frozen=True)
class PairingSessionView:
    pairing_session_id: str
    hub_id: str
    boot_id: str
    state: str
    expires_at_server: str
    terminal_reason: str | None
    created_at: str
    consumed_at: str | None


@dataclass(frozen=True)
class HelloResult:
    pairing_session_id: str
    pairing_attempt_id: str
    device_id: str
    short_verification_code: str
    pending_expires_at: str
    state: str
    deduplicated: bool


@dataclass(frozen=True)
class ConfirmResult:
    pairing_session_id: str
    pairing_attempt_id: str
    device_id: str
    state: str
    credential_status: str
    capability_epoch: int
    granted_capabilities: list[str]
    activated: bool
    deduplicated: bool


@dataclass(frozen=True)
class RedactedPairingStatus:
    pairing_session_id: str
    pairing_attempt_id: str
    state: str
    credential_status: str | None
    device_id: str | None
    capability_epoch: int | None
    granted_capabilities: list[str] | None
    pending_expires_at: str | None
    expires_at_server: str
    terminal_reason: str | None


@dataclass(frozen=True)
class OperatorPairingView:
    """Loopback-operator view; contains identifiers and Human32, never secrets."""

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
    capability_epoch: int


@dataclass(frozen=True)
class DeviceCredentialView:
    device_id: str
    hub_id: str
    pairing_attempt_id: str
    status: str
    requested_capabilities: list[str]
    granted_capabilities: list[str]
    capability_epoch: int
    display_name: str | None
    platform: str
    paired_at: str | None
    revoked_at: str | None
    last_auth_at: str | None


@dataclass(frozen=True)
class CredentialTransitionResult:
    credential: DeviceCredentialView
    changed: bool


@dataclass(frozen=True)
class AuthVerifyResult:
    device_id: str
    hub_id: str
    status: str
    capability_epoch: int
    granted_capabilities: list[str]
    display_name: str | None
    platform: str


def audit_detail(allowed: dict[str, Any]) -> str:
    import json

    return json.dumps(allowed, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
