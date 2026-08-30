"""Operator and authenticated REST surfaces for knowledge-pack export."""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from .artifact_export import (
    ARTIFACT_EXPORT_SCHEMA,
    ArtifactExportError,
    KnowledgeArtifactCoordinator,
)
from .content_understanding import ContentUnderstandingError
from .credential_transition_api import (
    OperatorAuthError,
    OperatorPayloadError,
    _authorize_operator,
    _error as _operator_error,
    _operator_openapi_extra,
    _strict_json_body,
)
from .device_auth import (
    ARTIFACT_EXPORT_CAPABILITY,
    AUTH_MODE_REQUIRED,
    CONTENT_ANALYZE_CAPABILITY,
    AuthenticatedDevice,
    DeviceAuthError,
    device_auth_openapi_extra,
)
from .knowledge_pack import KnowledgePackError
from .pairing_codec import require_digest


def create_artifact_operator_router(
    *,
    coordinator: KnowledgeArtifactCoordinator,
    operator_token_digest: str,
) -> APIRouter:
    expected = require_digest("operator_token_digest", operator_token_digest)
    router = APIRouter(prefix="/v1/operator/artifacts", tags=["artifacts-operator"])

    async def authorize(request: Request) -> None:
        _authorize_operator(request, expected)

    _attach_routes(router, coordinator=coordinator, authorize=authorize, operator=True)
    return router


def create_artifact_device_router(
    *, coordinator: KnowledgeArtifactCoordinator
) -> APIRouter:
    router = APIRouter(prefix="/v1/artifacts", tags=["artifacts"])

    async def authorize(request: Request) -> None:
        authenticated = getattr(request.state, "authenticated_device", None)
        if not isinstance(authenticated, AuthenticatedDevice):
            raise DeviceAuthError("auth_context_missing", 401)

    _attach_routes(router, coordinator=coordinator, authorize=authorize, operator=False)
    return router


def _attach_routes(
    router: APIRouter,
    *,
    coordinator: KnowledgeArtifactCoordinator,
    authorize: Any,
    operator: bool,
) -> None:
    openapi = (
        _operator_openapi_extra()
        if operator
        else device_auth_openapi_extra(AUTH_MODE_REQUIRED, ARTIFACT_EXPORT_CAPABILITY)
    )

    @router.post("/prepare", openapi_extra=openapi)
    async def prepare(request: Request) -> JSONResponse:
        try:
            await authorize(request)
            if not operator:
                authenticated = _authenticated(request)
                if CONTENT_ANALYZE_CAPABILITY not in authenticated.granted_capabilities:
                    raise DeviceAuthError("capability_denied", 403)
            body = await _strict_json_body(request)
            if set(body) != {"kind", "request"}:
                raise OperatorPayloadError()
            kind = body["kind"]
            prompt = body["request"]
            if (
                not isinstance(kind, str)
                or not isinstance(prompt, str)
                or not prompt.strip()
                or len(prompt) > 500
            ):
                raise OperatorPayloadError()
            result = await asyncio.to_thread(
                coordinator.prepare,
                kind=kind,
                request=prompt,
            )
            return JSONResponse(result.wire())
        except OperatorAuthError:
            return _artifact_error("operator_invalid", operator=operator, status=401)
        except DeviceAuthError as exc:
            return _artifact_error(
                exc.error_code, operator=operator, status=exc.status_code
            )
        except OperatorPayloadError:
            return _artifact_error("artifact_request_invalid", operator=operator, status=400)
        except (ArtifactExportError, KnowledgePackError, ContentUnderstandingError) as exc:
            return _artifact_error(exc.code, operator=operator)

    @router.post("/execute", openapi_extra=openapi)
    async def execute(request: Request) -> JSONResponse:
        try:
            await authorize(request)
            body = await _strict_json_body(request)
            if set(body) != {
                "schema_version",
                "kind",
                "pack_id",
                "preview_sha256",
                "idempotency_key",
            } or body["schema_version"] != ARTIFACT_EXPORT_SCHEMA:
                raise OperatorPayloadError()
            if not all(
                isinstance(body[key], str)
                for key in ("kind", "pack_id", "preview_sha256", "idempotency_key")
            ):
                raise OperatorPayloadError()
            result = await asyncio.to_thread(
                coordinator.execute,
                kind=body["kind"],
                pack_id=body["pack_id"],
                preview_sha256=body["preview_sha256"],
                idempotency_key=body["idempotency_key"],
            )
            return JSONResponse(result.wire())
        except OperatorAuthError:
            return _artifact_error("operator_invalid", operator=operator, status=401)
        except DeviceAuthError as exc:
            return _artifact_error(
                exc.error_code, operator=operator, status=exc.status_code
            )
        except OperatorPayloadError:
            return _artifact_error("artifact_request_invalid", operator=operator, status=400)
        except (ArtifactExportError, KnowledgePackError, ContentUnderstandingError) as exc:
            return _artifact_error(exc.code, operator=operator)

    @router.get("/status", openapi_extra=openapi)
    async def status(request: Request) -> JSONResponse:
        try:
            await authorize(request)
            result = await asyncio.to_thread(coordinator.status)
            return JSONResponse(result.wire())
        except OperatorAuthError:
            return _artifact_error("operator_invalid", operator=operator, status=401)
        except DeviceAuthError as exc:
            return _artifact_error(
                exc.error_code, operator=operator, status=exc.status_code
            )
        except ArtifactExportError as exc:
            return _artifact_error(exc.code, operator=operator)

    @router.post("/undo", openapi_extra=openapi)
    async def undo(request: Request) -> JSONResponse:
        try:
            await authorize(request)
            body = await _strict_json_body(request)
            if set(body) != {"schema_version", "undo_token"} or body[
                "schema_version"
            ] != ARTIFACT_EXPORT_SCHEMA or not isinstance(body["undo_token"], str):
                raise OperatorPayloadError()
            result = await asyncio.to_thread(
                coordinator.undo,
                undo_token=body["undo_token"],
            )
            return JSONResponse(result.wire())
        except OperatorAuthError:
            return _artifact_error("operator_invalid", operator=operator, status=401)
        except DeviceAuthError as exc:
            return _artifact_error(
                exc.error_code, operator=operator, status=exc.status_code
            )
        except OperatorPayloadError:
            return _artifact_error("artifact_request_invalid", operator=operator, status=400)
        except ArtifactExportError as exc:
            return _artifact_error(exc.code, operator=operator)


def _authenticated(request: Request) -> AuthenticatedDevice:
    value = getattr(request.state, "authenticated_device", None)
    if not isinstance(value, AuthenticatedDevice):
        raise DeviceAuthError("auth_context_missing", 401)
    return value


def _artifact_error(
    code: str,
    *,
    operator: bool,
    status: int | None = None,
) -> JSONResponse:
    if status is None:
        status = (
            400
            if code in {"artifact_request_invalid", "knowledge_pack_kind_invalid"}
            else 403
            if code == "capability_denied"
            else 404
            if code in {"knowledge_pack_unavailable", "artifact_undo_unavailable"}
            else 409
            if code
            in {
                "knowledge_pack_snapshot_stale",
                "knowledge_pack_citation_invalid",
                "artifact_preview_stale",
                "artifact_target_exists",
                "artifact_modified",
                "artifact_scope_changed",
                "artifact_scope_unconfigured",
                "artifact_recovery_required",
                "artifact_already_undone",
                "artifact_idempotency_conflict",
            }
            else 503
        )
    if operator:
        return _operator_error(code, status)
    return JSONResponse(
        {"error_code": code, "message_key": code},
        status_code=status,
    )
