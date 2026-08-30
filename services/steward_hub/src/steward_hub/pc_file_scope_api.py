"""Loopback-only operator API for the ephemeral PC file scope."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Literal

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .credential_transition_api import (
    OperatorAuthError,
    OperatorPayloadError,
    _authorize_operator,
    _error,
    _operator_openapi_extra,
    _strict_json_body,
)
from .pairing_codec import require_digest
from .pairing_http_models import PairingErrorBody
from .pc_file_scope import PcFileScopeError, PcFileScopeService, PcFileScopeView


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class AuthorizePcFileScopeRequest(_StrictModel):
    path: str = Field(min_length=1, max_length=1_024)
    remember: bool = True


class PcFileScopeResponse(_StrictModel):
    configured: bool
    root_id: str | None
    display_name: str | None
    authorized_at: str | None
    remembered: bool
    restore_status: Literal["not_configured", "active", "restored", "unavailable"]
    scan_mode: Literal["direct_children_metadata_only"]


def _response(view: PcFileScopeView) -> JSONResponse:
    body = PcFileScopeResponse(
        configured=view.configured,
        root_id=view.root_id,
        display_name=view.display_name,
        authorized_at=view.authorized_at,
        remembered=view.remembered,
        restore_status=view.restore_status,
        scan_mode="direct_children_metadata_only",
    )
    return JSONResponse(status_code=200, content=body.model_dump())


def _map_error(exc: BaseException) -> JSONResponse:
    if isinstance(exc, OperatorAuthError):
        return _error("operator_invalid", 401)
    if isinstance(exc, (OperatorPayloadError, ValidationError)):
        return _error("operator_validation_error", 400)
    if isinstance(exc, PcFileScopeError):
        if exc.code == "file_scope_invalid":
            return _error(exc.code, 400)
        return _error("file_scope_unavailable", 503)
    return _error("operator_internal_error", 500)


def create_pc_file_scope_router(
    *,
    service: PcFileScopeService,
    operator_token_digest: str,
    before_authorize: Callable[[], object] | None = None,
    before_revoke: Callable[[], object] | None = None,
) -> APIRouter:
    expected_digest = require_digest("operator_token_digest", operator_token_digest)
    router = APIRouter()
    responses = {
        400: {"model": PairingErrorBody},
        401: {"model": PairingErrorBody},
        500: {"model": PairingErrorBody},
        503: {"model": PairingErrorBody},
    }

    @router.get(
        "/v1/operator/file-scope",
        response_model=PcFileScopeResponse,
        responses=responses,
        openapi_extra=_operator_openapi_extra(),
    )
    async def status(request: Request) -> JSONResponse:
        try:
            _authorize_operator(request, expected_digest)
            return _response(service.status())
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return _map_error(exc)

    @router.put(
        "/v1/operator/file-scope",
        response_model=PcFileScopeResponse,
        responses=responses,
        openapi_extra=_operator_openapi_extra(AuthorizePcFileScopeRequest),
    )
    async def authorize(request: Request) -> JSONResponse:
        try:
            _authorize_operator(request, expected_digest)
            model = AuthorizePcFileScopeRequest.model_validate(
                await _strict_json_body(request)
            )
            if model.remember is not True:
                raise OperatorPayloadError("operator_validation_error")
            if before_authorize is not None:
                await asyncio.to_thread(before_authorize)
            return _response(await asyncio.to_thread(service.authorize, model.path))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return _map_error(exc)

    @router.delete(
        "/v1/operator/file-scope",
        response_model=PcFileScopeResponse,
        responses=responses,
        openapi_extra=_operator_openapi_extra(),
    )
    async def revoke(request: Request) -> JSONResponse:
        try:
            _authorize_operator(request, expected_digest)
            if before_revoke is not None:
                await asyncio.to_thread(before_revoke)
            return _response(service.revoke())
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return _map_error(exc)

    return router
