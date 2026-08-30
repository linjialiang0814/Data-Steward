"""Operator and authenticated REST surfaces for proactive suggestions."""

from __future__ import annotations

import asyncio
from typing import Awaitable, Callable

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from .credential_transition_api import (
    OperatorAuthError,
    OperatorPayloadError,
    _authorize_operator,
    _error as _operator_error,
    _operator_openapi_extra,
    _strict_json_body,
)
from .device_auth import (
    AUTH_MODE_REQUIRED,
    CONTENT_ANALYZE_CAPABILITY,
    AuthenticatedDevice,
    DeviceAuthError,
    device_auth_openapi_extra,
)
from .pairing_codec import require_digest
from .proactive_suggestion import (
    ProactiveSuggestion,
    ProactiveSuggestionError,
    ProactiveSuggestionService,
)


def create_suggestion_operator_router(
    *, service: ProactiveSuggestionService, operator_token_digest: str
) -> APIRouter:
    expected = require_digest("operator_token_digest", operator_token_digest)
    router = APIRouter(prefix="/v1/operator/suggestions", tags=["suggestions-operator"])

    async def authorize(request: Request) -> AuthenticatedDevice | None:
        _authorize_operator(request, expected)
        return None

    _attach_routes(router, service=service, authorize=authorize, operator=True)
    return router


def create_suggestion_device_router(
    *, service: ProactiveSuggestionService
) -> APIRouter:
    router = APIRouter(prefix="/v1/suggestions", tags=["suggestions"])

    async def authorize(request: Request) -> AuthenticatedDevice | None:
        authenticated = getattr(request.state, "authenticated_device", None)
        if not isinstance(authenticated, AuthenticatedDevice):
            raise DeviceAuthError("auth_context_missing", 401)
        return authenticated

    _attach_routes(router, service=service, authorize=authorize, operator=False)
    return router


def _attach_routes(
    router: APIRouter,
    *,
    service: ProactiveSuggestionService,
    authorize: Callable[[Request], Awaitable[AuthenticatedDevice | None]],
    operator: bool,
) -> None:
    openapi = (
        _operator_openapi_extra()
        if operator
        else device_auth_openapi_extra(AUTH_MODE_REQUIRED)
    )

    @router.get("/settings", openapi_extra=openapi)
    async def settings(request: Request) -> JSONResponse:
        try:
            await authorize(request)
            value = await asyncio.to_thread(service.store.settings)
            return JSONResponse(value.wire())
        except (OperatorAuthError, DeviceAuthError, ProactiveSuggestionError) as exc:
            return _error(exc, operator=operator)

    @router.put("/settings", openapi_extra=openapi)
    async def update_settings(request: Request) -> JSONResponse:
        try:
            await authorize(request)
            body = await _strict_json_body(request)
            if set(body) != {"enabled", "disabled_categories"}:
                raise OperatorPayloadError()
            value = await asyncio.to_thread(
                service.store.update_settings,
                enabled=body["enabled"],
                disabled_categories=body["disabled_categories"],
            )
            return JSONResponse(value.wire())
        except (OperatorAuthError, DeviceAuthError, OperatorPayloadError, ProactiveSuggestionError) as exc:
            return _error(exc, operator=operator)

    @router.get("/inbox", openapi_extra=openapi)
    async def inbox(request: Request) -> JSONResponse:
        try:
            await authorize(request)
            rows = await asyncio.to_thread(service.store.inbox)
            return JSONResponse(
                {
                    "schema_version": "data-steward.proactive-action-card/v1",
                    "suggestions": [item.wire() for item in rows],
                }
            )
        except (OperatorAuthError, DeviceAuthError, ProactiveSuggestionError) as exc:
            return _error(exc, operator=operator)

    @router.post("/observe", openapi_extra=openapi)
    async def observe(request: Request) -> JSONResponse:
        try:
            authenticated = await authorize(request)
            body = await _strict_json_body(request)
            if body:
                raise OperatorPayloadError()
            if (
                authenticated is not None
                and CONTENT_ANALYZE_CAPABILITY
                not in authenticated.granted_capabilities
            ):
                raise DeviceAuthError("capability_denied", 403)
            result = await asyncio.to_thread(service.observe)
            return JSONResponse(result.wire())
        except (OperatorAuthError, DeviceAuthError, OperatorPayloadError, ProactiveSuggestionError) as exc:
            return _error(exc, operator=operator)

    @router.post("/{suggestion_id}/{operation}", openapi_extra=openapi)
    async def transition(
        suggestion_id: str, operation: str, request: Request
    ) -> JSONResponse:
        try:
            authenticated = await authorize(request)
            body = await _strict_json_body(request)
            if body or operation not in {"accept", "dismiss", "disable-category"}:
                raise OperatorPayloadError()
            if operation == "accept":
                current = next(
                    (
                        item
                        for item in await asyncio.to_thread(service.store.inbox)
                        if item.suggestion_id == suggestion_id
                    ),
                    None,
                )
                if current is None:
                    raise ProactiveSuggestionError("suggestion_not_found")
                _require_action_capabilities(current, authenticated)
                result = await asyncio.to_thread(service.accept, suggestion_id)
                return JSONResponse(result.accepted_wire())
            if operation == "dismiss":
                result = await asyncio.to_thread(service.dismiss, suggestion_id)
                return JSONResponse(result.wire())
            value = await asyncio.to_thread(
                service.store.disable_category, suggestion_id
            )
            return JSONResponse(value.wire())
        except (OperatorAuthError, DeviceAuthError, OperatorPayloadError, ProactiveSuggestionError) as exc:
            return _error(exc, operator=operator)


def _require_action_capabilities(
    suggestion: ProactiveSuggestion,
    authenticated: AuthenticatedDevice | None,
) -> None:
    if authenticated is None:
        return
    required = (
        {"catalog.sync", "files.organize"}
        if suggestion.action_type == "organize_selected"
        else {"content.analyze", "artifact.export"}
    )
    if not required.issubset(authenticated.granted_capabilities):
        raise DeviceAuthError("capability_denied", 403)


def _error(
    exc: Exception,
    *,
    operator: bool,
) -> JSONResponse:
    if isinstance(exc, OperatorAuthError):
        code, status = "operator_invalid", 401
    elif isinstance(exc, DeviceAuthError):
        code, status = exc.error_code, exc.status_code
    elif isinstance(exc, OperatorPayloadError):
        code, status = "suggestion_request_invalid", 400
    else:
        assert isinstance(exc, ProactiveSuggestionError)
        code = exc.code
        status = (
            400
            if code in {"suggestion_request_invalid", "suggestion_proposal_invalid"}
            else 404
            if code == "suggestion_not_found"
            else 409
            if code == "suggestion_closed"
            else 503
        )
    if operator:
        return _operator_error(code, status)
    return JSONResponse({"error_code": code, "message_key": code}, status_code=status)
