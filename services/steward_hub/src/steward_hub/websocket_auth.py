"""Strict first-frame codec for authenticated shared-session WebSockets."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, NoReturn

from .device_auth import AuthenticatedDevice, DeviceAuthError
from .pairing_codec import PROTOCOL_VERSION as PAIRING_PROTOCOL_VERSION
from .pairing_codec import require_ulid
from .pairing_errors import PairingValidationError
from .pairing_http_codec import PairingHttpCodecError, digest_secret_b64url

AUTH_FRAME_KIND = "auth"
AUTH_OK_KIND = "auth_ok"
AUTH_FAILED_KIND = "auth_failed"
MAX_AUTH_FRAME_BYTES = 4096
DEFAULT_AUTH_FRAME_TIMEOUT_S = 10.0
MAX_AUTH_FRAME_TIMEOUT_S = 30.0
MAX_SQLITE_INTEGER = (1 << 63) - 1

_AUTH_FRAME_KEYS = frozenset(
    {
        "kind",
        "protocol_version",
        "device_id",
        "capability_epoch",
        "credential",
    }
)
_AUTH_FAILURE_CODES = frozenset(
    {
        "protocol_version_rejected",
        "auth_invalid",
        "auth_revoked",
        "capability_denied",
        "capability_epoch_stale",
        "policy_violation",
        "payload_too_large",
        "auth_unavailable",
    }
)


@dataclass(frozen=True, slots=True)
class WebSocketAuthCredentials:
    device_id: str
    credential_digest: str
    capability_epoch: int


class WebSocketAuthFrameError(Exception):
    """Stable frame failure that never contains raw input."""

    def __init__(self, error_code: str, close_code: int) -> None:
        self.error_code = error_code
        self.close_code = close_code
        super().__init__(error_code)


def validate_auth_frame_timeout_s(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("websocket auth timeout must be a positive number")
    number = float(value)
    if (
        number <= 0.0
        or number > MAX_AUTH_FRAME_TIMEOUT_S
        or number != number
        or number in (float("inf"), float("-inf"))
    ):
        raise ValueError("websocket auth timeout is outside the allowed range")
    return number


def _reject_constant(_value: str) -> NoReturn:
    raise ValueError("non_finite_number")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_key")
        result[key] = value
    return result


def decode_websocket_auth_message(
    message: Mapping[str, Any],
) -> WebSocketAuthCredentials:
    if not isinstance(message, Mapping) or message.get("type") != "websocket.receive":
        raise WebSocketAuthFrameError("auth_invalid", 1008)
    if message.get("bytes") is not None:
        raise WebSocketAuthFrameError("auth_invalid", 1008)
    text = message.get("text")
    if not isinstance(text, str):
        raise WebSocketAuthFrameError("auth_invalid", 1008)
    try:
        encoded_size = len(text.encode("utf-8"))
    except UnicodeError:
        raise WebSocketAuthFrameError("auth_invalid", 1008) from None
    if encoded_size > MAX_AUTH_FRAME_BYTES:
        raise WebSocketAuthFrameError("payload_too_large", 1009)

    payload: dict[str, Any] | None = None
    try:
        decoded = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
        if not isinstance(decoded, dict) or set(decoded) != _AUTH_FRAME_KEYS:
            raise ValueError("frame_shape")
        payload = decoded
        if payload["kind"] != AUTH_FRAME_KIND:
            raise ValueError("frame_kind")
        if payload["protocol_version"] != PAIRING_PROTOCOL_VERSION:
            raise WebSocketAuthFrameError("protocol_version_rejected", 1008)
        try:
            device_id = require_ulid("device_id", payload["device_id"])
        except PairingValidationError:
            raise ValueError("device_id") from None
        capability_epoch = payload["capability_epoch"]
        if (
            isinstance(capability_epoch, bool)
            or not isinstance(capability_epoch, int)
            or capability_epoch < 1
            or capability_epoch > MAX_SQLITE_INTEGER
        ):
            raise ValueError("capability_epoch")
        credential = payload["credential"]
        if not isinstance(credential, str):
            raise ValueError("credential")
        try:
            credential_digest = digest_secret_b64url(credential)
        except PairingHttpCodecError:
            raise ValueError("credential") from None
        return WebSocketAuthCredentials(
            device_id=device_id,
            credential_digest=credential_digest,
            capability_epoch=capability_epoch,
        )
    except WebSocketAuthFrameError:
        raise
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        raise WebSocketAuthFrameError("auth_invalid", 1008) from None
    finally:
        if payload is not None:
            payload.clear()


def auth_ok_frame(device: AuthenticatedDevice) -> dict[str, object]:
    return {
        "kind": AUTH_OK_KIND,
        "protocol_version": PAIRING_PROTOCOL_VERSION,
        "capability_epoch": device.capability_epoch,
    }


def auth_failed_frame(error_code: str) -> dict[str, str]:
    if error_code not in _AUTH_FAILURE_CODES:
        raise ValueError("websocket auth error code is invalid")
    return {
        "kind": AUTH_FAILED_KIND,
        "error_code": error_code,
        "message_key": f"auth.{error_code}",
    }


def websocket_error_from_device(error: DeviceAuthError) -> WebSocketAuthFrameError:
    error_code = error.error_code
    if error_code not in _AUTH_FAILURE_CODES:
        error_code = "auth_unavailable"
    close_code = 1013 if error_code == "auth_unavailable" else 1008
    return WebSocketAuthFrameError(error_code, close_code)
