"""Feature-gated, operator-authenticated credential transition endpoints."""

from __future__ import annotations

import asyncio
import hmac
import json
import re
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError as PydanticValidationError

from .credential_transition import DeviceAuthorizationService, PairingOperatorService
from .credential_transition_models import (
    CredentialTransitionResponse,
    CredentialListResponse,
    CredentialStatusResponse,
    RevokeCredentialRequest,
    UpdateCapabilitiesRequest,
    CancelPairingSessionResponse,
    ConfirmPairingSessionRequest,
    CreatePairingSessionRequest,
    CreatePairingSessionResponse,
    OperatorPairingStatusResponse,
)
from .device_connection_registry import DeviceConnectionRegistryError
from .pairing_codec import PROTOCOL_VERSION, require_digest
from .pairing_errors import (
    PairingCapabilityEpochStaleError,
    PairingBusyError,
    PairingExpiredError,
    PairingClosedError,
    PairingNotFoundError,
    PairingPersistenceError,
    PairingStateError,
    PairingValidationError,
)
from .pairing_http_codec import PairingHttpCodecError, digest_secret_b64url
from .pairing_http_models import PairingErrorBody
from .pairing_store_executor import (
    PairingStoreExecutorClosedError,
    PairingStoreSaturatedError,
)

MAX_OPERATOR_BODY_BYTES = 4_096
OPERATOR_BODY_TIMEOUT_S = 10.0
PROTOCOL_HEADER = b"x-datasteward-protocol"
AUTHORIZATION_HEADER = b"authorization"
_OPERATOR_AUTH_RE = re.compile(
    r"^DataSteward-Operator[ \t]+([A-Za-z0-9_-]{43})$"
)


class OperatorAuthError(Exception):
    pass


class OperatorPayloadError(Exception):
    pass


def _error(error_code: str, status_code: int) -> JSONResponse:
    body = PairingErrorBody(
        error_code=error_code,
        message_key=f"operator.{error_code}",
    )
    return JSONResponse(status_code=status_code, content=body.model_dump())


def _single_ascii_header(scope: dict[str, Any], name: bytes) -> str:
    values = [value for key, value in scope.get("headers", ()) if key.lower() == name]
    if len(values) != 1:
        raise OperatorAuthError()
    try:
        return values[0].decode("ascii")
    except (AttributeError, UnicodeDecodeError):
        raise OperatorAuthError() from None


def _authorize_operator(request: Request, expected_digest: str) -> None:
    protocol = _single_ascii_header(request.scope, PROTOCOL_HEADER)
    if protocol != PROTOCOL_VERSION:
        raise OperatorAuthError()
    authorization = _single_ascii_header(request.scope, AUTHORIZATION_HEADER)
    match = _OPERATOR_AUTH_RE.fullmatch(authorization)
    if match is None:
        raise OperatorAuthError()
    try:
        actual = digest_secret_b64url(match.group(1))
    except PairingHttpCodecError:
        raise OperatorAuthError() from None
    if not hmac.compare_digest(actual, expected_digest):
        raise OperatorAuthError()


async def _strict_json_body(request: Request) -> dict[str, Any]:
    content_type = _single_content_type(request.scope)
    if content_type != "application/json":
        raise OperatorPayloadError()
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            length = int(content_length)
        except ValueError:
            raise OperatorPayloadError() from None
        if length < 0 or length > MAX_OPERATOR_BODY_BYTES:
            raise OperatorPayloadError()
    try:
        raw = await asyncio.wait_for(
            _read_bounded_body(request),
            timeout=OPERATOR_BODY_TIMEOUT_S,
        )
    except TimeoutError:
        raise OperatorPayloadError() from None

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise OperatorPayloadError()
            result[key] = value
        return result

    try:
        decoded = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
        )
    except OperatorPayloadError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        raise OperatorPayloadError() from None
    if not isinstance(decoded, dict):
        raise OperatorPayloadError()
    return decoded


def _single_content_type(scope: dict[str, Any]) -> str:
    values = [
        value
        for key, value in scope.get("headers", ())
        if key.lower() == b"content-type"
    ]
    if len(values) != 1:
        raise OperatorPayloadError()
    try:
        return values[0].decode("ascii").split(";", 1)[0].strip().lower()
    except (AttributeError, UnicodeDecodeError):
        raise OperatorPayloadError() from None


async def _read_bounded_body(request: Request) -> bytes:
    chunks: list[bytes] = []
    total = 0
    more = True
    while more:
        message = await request.receive()
        if message.get("type") != "http.request":
            continue
        chunk = message.get("body", b"")
        if not isinstance(chunk, (bytes, bytearray)):
            raise OperatorPayloadError()
        total += len(chunk)
        if total > MAX_OPERATOR_BODY_BYTES:
            raise OperatorPayloadError()
        if chunk:
            chunks.append(bytes(chunk))
        more = bool(message.get("more_body", False))
    return b"".join(chunks)


def _response(result: Any) -> JSONResponse:
    transition = result.value
    credential = transition.credential
    body = CredentialTransitionResponse(
        device_id=credential.device_id,
        status=credential.status,
        capability_epoch=credential.capability_epoch,
        granted_capabilities=credential.granted_capabilities,
        changed=transition.changed,
        closed_connection_count=result.closed_connection_count,
    )
    return JSONResponse(status_code=200, content=body.model_dump())


def _status_response(credential: Any) -> JSONResponse:
    body = CredentialStatusResponse(
        device_id=credential.device_id,
        status=credential.status,
        capability_epoch=credential.capability_epoch,
        requested_capabilities=credential.requested_capabilities,
        granted_capabilities=credential.granted_capabilities,
        display_name=credential.display_name,
        platform=credential.platform,
    )
    return JSONResponse(status_code=200, content=body.model_dump())


def _pairing_status_response(value: Any) -> JSONResponse:
    body = OperatorPairingStatusResponse(
        protocol_version=PROTOCOL_VERSION,
        pairing_session_id=value.pairing_session_id,
        hub_id=value.hub_id,
        state=value.state,
        expires_at_server=value.expires_at_server,
        terminal_reason=value.terminal_reason,
        pairing_attempt_id=value.pairing_attempt_id,
        device_id=value.device_id,
        short_verification_code=value.short_verification_code,
        requested_capabilities=value.requested_capabilities,
        granted_capabilities=value.granted_capabilities,
        display_name=value.display_name,
        platform=value.platform,
        client_confirmed=value.client_confirmed,
        hub_confirmed=value.hub_confirmed,
        credential_status=value.credential_status,
        capability_epoch=value.capability_epoch,
    )
    return JSONResponse(status_code=200, content=body.model_dump())


def _map_error(exc: BaseException) -> JSONResponse:
    if isinstance(exc, OperatorAuthError):
        return _error("operator_invalid", 401)
    if isinstance(exc, (OperatorPayloadError, PydanticValidationError, PairingValidationError)):
        return _error("operator_validation_error", 400)
    if isinstance(exc, PairingNotFoundError):
        return _error("credential_not_found", 404)
    if isinstance(exc, PairingCapabilityEpochStaleError):
        return _error("capability_epoch_stale", 409)
    if isinstance(exc, PairingStateError):
        return _error("credential_state_invalid", 409)
    if isinstance(
        exc,
        (
            PairingPersistenceError,
            PairingClosedError,
            PairingStoreSaturatedError,
            PairingStoreExecutorClosedError,
            DeviceConnectionRegistryError,
        ),
    ):
        return _error("operator_unavailable", 503)
    return _error("operator_internal_error", 500)


def _map_pairing_operator_error(exc: BaseException) -> JSONResponse:
    if isinstance(exc, OperatorAuthError):
        return _error("operator_invalid", 401)
    if isinstance(
        exc,
        (OperatorPayloadError, PydanticValidationError, PairingValidationError),
    ):
        return _error("operator_validation_error", 400)
    if isinstance(exc, PairingNotFoundError):
        return _error("pairing_not_found", 404)
    if isinstance(exc, PairingBusyError):
        return _error("pairing_busy", 409)
    if isinstance(exc, (PairingExpiredError, PairingStateError)):
        return _error("pairing_state_invalid", 409)
    if isinstance(
        exc,
        (
            PairingPersistenceError,
            PairingClosedError,
            PairingStoreSaturatedError,
            PairingStoreExecutorClosedError,
        ),
    ):
        return _error("operator_unavailable", 503)
    return _error("operator_internal_error", 500)


def _operator_openapi_extra(model: type[Any] | None = None) -> dict[str, Any]:
    value: dict[str, Any] = {
        "security": [{"DataStewardOperator": []}],
        "parameters": [
            {
                "name": "X-DataSteward-Protocol",
                "in": "header",
                "required": True,
                "schema": {"type": "string", "const": PROTOCOL_VERSION},
            }
        ],
    }
    if model is not None:
        value["requestBody"] = {
            "required": True,
            "content": {
                "application/json": {
                    "schema": model.model_json_schema()
                }
            },
        }
    return value


def install_operator_openapi_scheme(app: Any) -> None:
    original_openapi = app.openapi

    def openapi() -> dict[str, Any]:
        schema = original_openapi()
        components = schema.setdefault("components", {})
        schemes = components.setdefault("securitySchemes", {})
        schemes["DataStewardOperator"] = {
            "type": "apiKey",
            "in": "header",
            "name": "Authorization",
            "description": (
                "Per-process DataSteward-Operator bearer; never a device "
                "credential."
            ),
        }
        return schema

    app.openapi = openapi


def create_credential_transition_router(
    *,
    service: DeviceAuthorizationService | None,
    pairing_service: PairingOperatorService,
    operator_token_digest: str,
    include_device_transitions: bool = True,
) -> APIRouter:
    expected_digest = require_digest("operator_token_digest", operator_token_digest)
    router = APIRouter()
    responses = {
        400: {"model": PairingErrorBody},
        401: {"model": PairingErrorBody},
        404: {"model": PairingErrorBody},
        409: {"model": PairingErrorBody},
        500: {"model": PairingErrorBody},
        503: {"model": PairingErrorBody},
    }

    @router.post(
        "/v1/operator/pairing/sessions",
        response_model=CreatePairingSessionResponse,
        status_code=201,
        responses=responses,
        openapi_extra=_operator_openapi_extra(CreatePairingSessionRequest),
    )
    async def create_pairing_session(request: Request) -> JSONResponse:
        try:
            _authorize_operator(request, expected_digest)
            model = CreatePairingSessionRequest.model_validate(
                await _strict_json_body(request)
            )
            identity, session = await pairing_service.create(
                pairing_token_digest=model.pairing_token_digest,
                ttl_seconds=model.ttl_seconds,
            )
            body = CreatePairingSessionResponse(
                protocol_version=PROTOCOL_VERSION,
                hub_id=identity.hub_id,
                cert_fingerprint=identity.cert_fingerprint,
                pairing_session_id=session.pairing_session_id,
                state="PAIRING_ACTIVE",
                expires_at_server=session.expires_at_server,
            )
            return JSONResponse(status_code=201, content=body.model_dump())
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return _map_pairing_operator_error(exc)

    @router.get(
        "/v1/operator/pairing/sessions/{pairing_session_id}",
        response_model=OperatorPairingStatusResponse,
        responses=responses,
        openapi_extra=_operator_openapi_extra(),
    )
    async def get_pairing_session(
        request: Request,
        pairing_session_id: str,
    ) -> JSONResponse:
        try:
            _authorize_operator(request, expected_digest)
            return _pairing_status_response(
                await pairing_service.status(pairing_session_id=pairing_session_id)
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return _map_pairing_operator_error(exc)

    @router.post(
        "/v1/operator/pairing/sessions/{pairing_session_id}/attempts/"
        "{pairing_attempt_id}/confirm",
        response_model=OperatorPairingStatusResponse,
        responses=responses,
        openapi_extra=_operator_openapi_extra(ConfirmPairingSessionRequest),
    )
    async def confirm_pairing_session(
        request: Request,
        pairing_session_id: str,
        pairing_attempt_id: str,
    ) -> JSONResponse:
        try:
            _authorize_operator(request, expected_digest)
            model = ConfirmPairingSessionRequest.model_validate(
                await _strict_json_body(request)
            )
            await pairing_service.confirm(
                pairing_session_id=pairing_session_id,
                pairing_attempt_id=pairing_attempt_id,
                granted_capabilities=model.granted_capabilities,
            )
            return _pairing_status_response(
                await pairing_service.status(pairing_session_id=pairing_session_id)
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return _map_pairing_operator_error(exc)

    @router.post(
        "/v1/operator/pairing/sessions/{pairing_session_id}/cancel",
        response_model=CancelPairingSessionResponse,
        responses=responses,
        openapi_extra=_operator_openapi_extra(),
    )
    async def cancel_pairing_session(
        request: Request,
        pairing_session_id: str,
    ) -> JSONResponse:
        try:
            _authorize_operator(request, expected_digest)
            session = await pairing_service.cancel(
                pairing_session_id=pairing_session_id
            )
            body = CancelPairingSessionResponse(
                protocol_version=PROTOCOL_VERSION,
                pairing_session_id=session.pairing_session_id,
                state=session.state,
                cancelled=True,
            )
            return JSONResponse(status_code=200, content=body.model_dump())
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return _map_pairing_operator_error(exc)

    if not include_device_transitions:
        return router
    if service is None:
        raise ValueError("device authorization service is required")

    @router.get(
        "/v1/operator/devices",
        response_model=CredentialListResponse,
        responses=responses,
        openapi_extra=_operator_openapi_extra(),
    )
    async def list_devices(request: Request) -> JSONResponse:
        try:
            _authorize_operator(request, expected_digest)
            devices = await service.list(limit=32)
            body = CredentialListResponse(
                devices=[
                    CredentialStatusResponse(
                        device_id=value.device_id,
                        status=value.status,
                        capability_epoch=value.capability_epoch,
                        requested_capabilities=value.requested_capabilities,
                        granted_capabilities=value.granted_capabilities,
                        display_name=value.display_name,
                        platform=value.platform,
                    )
                    for value in devices
                ]
            )
            return JSONResponse(status_code=200, content=body.model_dump())
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return _map_error(exc)

    @router.get(
        "/v1/operator/devices/{device_id}",
        response_model=CredentialStatusResponse,
        responses=responses,
        openapi_extra=_operator_openapi_extra(),
    )
    async def get_status(request: Request, device_id: str) -> JSONResponse:
        try:
            _authorize_operator(request, expected_digest)
            return _status_response(await service.get(device_id=device_id))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return _map_error(exc)

    @router.post(
        "/v1/operator/devices/{device_id}/revoke",
        response_model=CredentialTransitionResponse,
        responses=responses,
        openapi_extra=_operator_openapi_extra(RevokeCredentialRequest),
    )
    async def revoke(request: Request, device_id: str) -> JSONResponse:
        try:
            _authorize_operator(request, expected_digest)
            model = RevokeCredentialRequest.model_validate(
                await _strict_json_body(request)
            )
            result = await service.revoke(
                device_id=device_id,
                expected_capability_epoch=model.expected_capability_epoch,
            )
            return _response(result)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return _map_error(exc)

    @router.put(
        "/v1/operator/devices/{device_id}/capabilities",
        response_model=CredentialTransitionResponse,
        responses=responses,
        openapi_extra=_operator_openapi_extra(UpdateCapabilitiesRequest),
    )
    async def update_capabilities(request: Request, device_id: str) -> JSONResponse:
        try:
            _authorize_operator(request, expected_digest)
            model = UpdateCapabilitiesRequest.model_validate(
                await _strict_json_body(request)
            )
            result = await service.update_capabilities(
                device_id=device_id,
                expected_capability_epoch=model.expected_capability_epoch,
                granted_capabilities=model.granted_capabilities,
            )
            return _response(result)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return _map_error(exc)

    return router


def create_pairing_operator_router(
    *,
    pairing_service: PairingOperatorService,
    operator_token_digest: str,
) -> APIRouter:
    """Minimal loopback control surface with no credential-admin routes."""
    return create_credential_transition_router(
        service=None,
        pairing_service=pairing_service,
        operator_token_digest=operator_token_digest,
        include_device_transitions=False,
    )
