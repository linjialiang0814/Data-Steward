"""Strict device-credential authentication for protected Hub routes."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse

from .pairing_codec import PROTOCOL_VERSION as PAIRING_PROTOCOL_VERSION
from .pairing_codec import require_ulid
from .pairing_errors import (
    PairingAuthExpiredError,
    PairingAuthInvalidError,
    PairingAuthRevokedError,
    PairingCapabilityDeniedError,
    PairingCapabilityEpochStaleError,
    PairingClosedError,
    PairingPersistenceError,
    PairingValidationError,
)
from .pairing_http_codec import PairingHttpCodecError, digest_secret_b64url
from .pairing_models import AuthVerifyResult
from .pairing_store import PairingStore
from .pairing_store_executor import (
    PairingStoreExecutor,
    PairingStoreExecutorClosedError,
    PairingStoreSaturatedError,
)

AUTH_MODE_LOOPBACK_COMPAT = "loopback_compat"
AUTH_MODE_REQUIRED = "authenticated_service"
AUTH_MODES = frozenset({AUTH_MODE_LOOPBACK_COMPAT, AUTH_MODE_REQUIRED})

AUTHORIZATION_HEADER = b"authorization"
PROTOCOL_HEADER = b"x-datasteward-protocol"
DEVICE_ID_HEADER = b"x-datasteward-device-id"
CAPABILITY_EPOCH_HEADER = b"x-datasteward-capability-epoch"

SESSION_SYNC_CAPABILITY = "session.sync"
CATALOG_SYNC_CAPABILITY = "catalog.sync"
CONTENT_ANALYZE_CAPABILITY = "content.analyze"
ARTIFACT_EXPORT_CAPABILITY = "artifact.export"
AUTHENTICATED_MESSAGE_ROLES = frozenset({"user"})
PROTECTED_REST_PREFIX = "/v1/conversations"
CATALOG_REST_PREFIX = "/v1/catalog"
CONTENT_REST_PREFIX = "/v1/content"
ARTIFACT_REST_PREFIX = "/v1/artifacts"
SUGGESTION_REST_PREFIX = "/v1/suggestions"
DEFAULT_DEVICE_AUTH_TIMEOUT_S = 10.0
MAX_DEVICE_AUTH_TIMEOUT_S = 30.0

_BEARER_RE = re.compile(r"^Bearer ([A-Za-z0-9_-]{43})$")
_EPOCH_RE = re.compile(r"^[1-9][0-9]{0,18}$")
_MAX_SQLITE_INTEGER = (1 << 63) - 1


@dataclass(frozen=True)
class AuthenticatedDevice:
    device_id: str
    hub_id: str
    capability_epoch: int
    granted_capabilities: tuple[str, ...]
    display_name: str | None
    platform: str


class DeviceAuthError(Exception):
    """Stable error with no request header or secret material."""

    def __init__(self, error_code: str, status_code: int) -> None:
        self.error_code = error_code
        self.status_code = status_code
        super().__init__(error_code)


def validate_auth_mode(value: object) -> str:
    if not isinstance(value, str) or value not in AUTH_MODES:
        raise ValueError("business_auth_mode is invalid")
    return value


def validate_device_auth_timeout_s(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("device_auth_timeout_s must be a positive number")
    number = float(value)
    if (
        number <= 0.0
        or number > MAX_DEVICE_AUTH_TIMEOUT_S
        or number != number
        or number in (float("inf"), float("-inf"))
    ):
        raise ValueError("device_auth_timeout_s is outside the allowed range")
    return number


def required_rest_capability(path: str) -> str | None:
    """Fail-closed namespace policy for protected REST surfaces."""
    if path == SUGGESTION_REST_PREFIX or path.startswith(
        f"{SUGGESTION_REST_PREFIX}/"
    ):
        return SESSION_SYNC_CAPABILITY
    if path == ARTIFACT_REST_PREFIX or path.startswith(f"{ARTIFACT_REST_PREFIX}/"):
        return ARTIFACT_EXPORT_CAPABILITY
    if path == CONTENT_REST_PREFIX or path.startswith(f"{CONTENT_REST_PREFIX}/"):
        return CONTENT_ANALYZE_CAPABILITY
    if path == CATALOG_REST_PREFIX or path.startswith(f"{CATALOG_REST_PREFIX}/"):
        return CATALOG_SYNC_CAPABILITY
    if path == PROTECTED_REST_PREFIX or path.startswith(
        f"{PROTECTED_REST_PREFIX}/"
    ):
        return SESSION_SYNC_CAPABILITY
    return None


def device_auth_openapi_extra(
    auth_mode: str,
    required_capability: str = SESSION_SYNC_CAPABILITY,
) -> dict[str, Any] | None:
    if auth_mode != AUTH_MODE_REQUIRED:
        return None
    return {
        "security": [{"DeviceBearer": []}],
        "x-datasteward-required-capability": required_capability,
        "parameters": [
            {
                "name": "X-DataSteward-Protocol",
                "in": "header",
                "required": True,
                "schema": {
                    "type": "string",
                    "const": PAIRING_PROTOCOL_VERSION,
                },
            },
            {
                "name": "X-DataSteward-Device-Id",
                "in": "header",
                "required": True,
                "schema": {"type": "string", "minLength": 26, "maxLength": 26},
            },
            {
                "name": "X-DataSteward-Capability-Epoch",
                "in": "header",
                "required": True,
                "schema": {"type": "integer", "minimum": 1},
            },
        ],
    }


def install_device_auth_openapi_scheme(app: Any, auth_mode: str) -> None:
    if auth_mode != AUTH_MODE_REQUIRED:
        return
    original_openapi = app.openapi

    def openapi() -> dict[str, Any]:
        schema = original_openapi()
        components = schema.setdefault("components", {})
        schemes = components.setdefault("securitySchemes", {})
        schemes["DeviceBearer"] = {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "DataSteward device credential",
            "description": (
                "Requires device id, protocol, and capability epoch headers."
            ),
        }
        return schema

    app.openapi = openapi


def _single_ascii_header(
    scope: dict[str, Any],
    name: bytes,
    *,
    error_code: str = "auth_invalid",
    status_code: int = 401,
) -> str:
    raw_headers = scope.get("headers", ())
    values = [value for key, value in raw_headers if key.lower() == name]
    if len(values) != 1:
        raise DeviceAuthError(error_code, status_code)
    try:
        return values[0].decode("ascii")
    except (UnicodeDecodeError, AttributeError):
        raise DeviceAuthError(error_code, status_code) from None


def parse_device_auth_headers(scope: dict[str, Any]) -> tuple[str, str, int]:
    device_id, credential_digest = parse_device_identity_headers(scope)

    epoch_text = _single_ascii_header(scope, CAPABILITY_EPOCH_HEADER)
    if _EPOCH_RE.fullmatch(epoch_text) is None:
        raise DeviceAuthError("auth_invalid", 401)
    capability_epoch = int(epoch_text)
    if capability_epoch > _MAX_SQLITE_INTEGER:
        raise DeviceAuthError("auth_invalid", 401)
    return device_id, credential_digest, capability_epoch


def parse_device_identity_headers(scope: dict[str, Any]) -> tuple[str, str]:
    """Parse proof-of-possession headers without trusting a cached epoch."""
    protocol = _single_ascii_header(
        scope,
        PROTOCOL_HEADER,
        error_code="protocol_version_rejected",
        status_code=400,
    )
    if protocol != PAIRING_PROTOCOL_VERSION:
        raise DeviceAuthError("protocol_version_rejected", 400)

    authorization = _single_ascii_header(scope, AUTHORIZATION_HEADER)
    bearer = _BEARER_RE.fullmatch(authorization)
    if bearer is None:
        raise DeviceAuthError("auth_invalid", 401)
    try:
        credential_digest = digest_secret_b64url(bearer.group(1))
    except PairingHttpCodecError:
        raise DeviceAuthError("auth_invalid", 401) from None

    device_id = _single_ascii_header(scope, DEVICE_ID_HEADER)
    try:
        device_id = require_ulid("device_id", device_id)
    except PairingValidationError:
        raise DeviceAuthError("auth_invalid", 401) from None
    return device_id, credential_digest


def _context_from_result(result: AuthVerifyResult) -> AuthenticatedDevice:
    if result.status != "ACTIVE":
        raise DeviceAuthError("auth_invalid", 401)
    return AuthenticatedDevice(
        device_id=result.device_id,
        hub_id=result.hub_id,
        capability_epoch=result.capability_epoch,
        granted_capabilities=tuple(result.granted_capabilities),
        display_name=result.display_name,
        platform=result.platform,
    )


async def authenticate_device_request(
    request: Request,
    *,
    pairing_store: PairingStore,
    store_executor: PairingStoreExecutor,
    required_capability: str,
    timeout_s: float,
) -> AuthenticatedDevice:
    device_id, credential_digest, capability_epoch = parse_device_auth_headers(
        request.scope
    )
    return await authenticate_device_digest(
        pairing_store=pairing_store,
        store_executor=store_executor,
        device_id=device_id,
        credential_digest=credential_digest,
        capability_epoch=capability_epoch,
        required_capability=required_capability,
        timeout_s=timeout_s,
    )


async def authenticate_device_digest(
    *,
    pairing_store: PairingStore,
    store_executor: PairingStoreExecutor,
    device_id: str,
    credential_digest: str,
    capability_epoch: int,
    required_capability: str,
    timeout_s: float,
) -> AuthenticatedDevice:
    """Authenticate a pre-digested credential for REST or WebSocket."""
    try:
        result = await store_executor.run(
            pairing_store.verify_active_credential_digest,
            device_id=device_id,
            credential_digest=credential_digest,
            capability_epoch=capability_epoch,
            required_capability=required_capability,
            timeout_s=timeout_s,
        )
    except PairingAuthRevokedError:
        raise DeviceAuthError("auth_revoked", 401) from None
    except PairingCapabilityDeniedError:
        raise DeviceAuthError("capability_denied", 403) from None
    except PairingCapabilityEpochStaleError:
        raise DeviceAuthError("capability_epoch_stale", 409) from None
    except (
        PairingAuthInvalidError,
        PairingAuthExpiredError,
        PairingValidationError,
    ):
        raise DeviceAuthError("auth_invalid", 401) from None
    except (
        PairingPersistenceError,
        PairingClosedError,
        PairingStoreSaturatedError,
        PairingStoreExecutorClosedError,
        TimeoutError,
    ):
        raise DeviceAuthError("auth_unavailable", 503) from None
    except DeviceAuthError:
        raise
    except Exception:
        raise DeviceAuthError("auth_unavailable", 503) from None
    return _context_from_result(result)


async def refresh_device_authorization_digest(
    *,
    pairing_store: PairingStore,
    store_executor: PairingStoreExecutor,
    device_id: str,
    credential_digest: str,
    timeout_s: float,
) -> AuthenticatedDevice:
    """Return current authorization only after credential possession succeeds."""
    try:
        result = await store_executor.run(
            pairing_store.refresh_active_credential_digest,
            device_id=device_id,
            credential_digest=credential_digest,
            timeout_s=timeout_s,
        )
    except PairingAuthRevokedError:
        raise DeviceAuthError("auth_revoked", 401) from None
    except (
        PairingAuthInvalidError,
        PairingAuthExpiredError,
        PairingValidationError,
    ):
        raise DeviceAuthError("auth_invalid", 401) from None
    except (
        PairingPersistenceError,
        PairingClosedError,
        PairingStoreSaturatedError,
        PairingStoreExecutorClosedError,
        TimeoutError,
    ):
        raise DeviceAuthError("auth_unavailable", 503) from None
    except DeviceAuthError:
        raise
    except Exception:
        raise DeviceAuthError("auth_unavailable", 503) from None
    return _context_from_result(result)


def device_self_openapi_extra() -> dict[str, Any]:
    """OpenAPI proof-of-possession contract for authorization refresh."""
    return {
        "security": [{"DeviceBearer": []}],
        "parameters": [
            {
                "name": "X-DataSteward-Protocol",
                "in": "header",
                "required": True,
                "schema": {
                    "type": "string",
                    "const": PAIRING_PROTOCOL_VERSION,
                },
            },
            {
                "name": "X-DataSteward-Device-Id",
                "in": "header",
                "required": True,
                "schema": {"type": "string", "minLength": 26, "maxLength": 26},
            },
        ],
    }


def device_auth_error_response(error: DeviceAuthError) -> JSONResponse:
    return JSONResponse(
        status_code=error.status_code,
        content={
            "error_code": error.error_code,
            "message_key": f"auth.{error.error_code}",
        },
    )
