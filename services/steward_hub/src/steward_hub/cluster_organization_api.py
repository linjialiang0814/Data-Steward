"""Authenticated and loopback-operator APIs for cluster organization."""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from .catalog_api import _authenticated, _body, _error, _strict_json
from .catalog_models import CatalogValidationError
from .cluster_organization import ClusterOrganizationError, ClusterOrganizationService
from .credential_transition_api import (
    OperatorAuthError,
    _authorize_operator,
    _operator_openapi_extra,
)
from .device_auth import AUTH_MODE_REQUIRED, device_auth_openapi_extra

FILES_ORGANIZE_CAPABILITY = "files.organize"
SCHEMA = ClusterOrganizationService.SCHEMA


def create_cluster_organization_device_router(
    service: ClusterOrganizationService,
) -> APIRouter:
    router = APIRouter(prefix="/v1/catalog/organization", tags=["catalog"])
    openapi = device_auth_openapi_extra(AUTH_MODE_REQUIRED, FILES_ORGANIZE_CAPABILITY)

    @router.post("/preview", openapi_extra=openapi)
    async def preview(request: Request) -> JSONResponse:
        if FILES_ORGANIZE_CAPABILITY not in _authenticated(
            request
        ).granted_capabilities:
            return _error("capability_denied", 403)
        return await _run_preview(service, request)

    @router.post("/execute", openapi_extra=openapi)
    async def execute(request: Request) -> JSONResponse:
        if FILES_ORGANIZE_CAPABILITY not in _authenticated(
            request
        ).granted_capabilities:
            return _error("capability_denied", 403)
        return await _run_execute(service, request)

    @router.post("/undo", openapi_extra=openapi)
    async def undo(request: Request) -> JSONResponse:
        if FILES_ORGANIZE_CAPABILITY not in _authenticated(
            request
        ).granted_capabilities:
            return _error("capability_denied", 403)
        return await _run_undo(service, request)

    @router.get("/status", openapi_extra=openapi)
    async def status(request: Request) -> JSONResponse:
        if FILES_ORGANIZE_CAPABILITY not in _authenticated(
            request
        ).granted_capabilities:
            return _error("capability_denied", 403)
        return await _run_status(service)

    return router


def create_cluster_organization_operator_router(
    *, service: ClusterOrganizationService, operator_token_digest: str
) -> APIRouter:
    router = APIRouter(prefix="/v1/operator/catalog/organization", tags=["catalog-operator"])

    async def authorized(request: Request) -> JSONResponse | None:
        try:
            _authorize_operator(request, operator_token_digest)
            return None
        except OperatorAuthError:
            return _error("operator_invalid", 401)

    @router.post("/preview", openapi_extra=_operator_openapi_extra())
    async def preview(request: Request) -> JSONResponse:
        denied = await authorized(request)
        return denied or await _run_preview(service, request)

    @router.post("/execute", openapi_extra=_operator_openapi_extra())
    async def execute(request: Request) -> JSONResponse:
        denied = await authorized(request)
        return denied or await _run_execute(service, request)

    @router.post("/undo", openapi_extra=_operator_openapi_extra())
    async def undo(request: Request) -> JSONResponse:
        denied = await authorized(request)
        return denied or await _run_undo(service, request)

    @router.get("/status", openapi_extra=_operator_openapi_extra())
    async def status(request: Request) -> JSONResponse:
        denied = await authorized(request)
        return denied or await _run_status(service)

    return router


async def _run_preview(
    service: ClusterOrganizationService, request: Request
) -> JSONResponse:
    try:
        value = _mapping(await _payload(request), {"schema_version", "cluster_id", "projection_sha256"})
        result = await asyncio.to_thread(
            service.preview,
            cluster_id=_string(value, "cluster_id"),
            projection_sha256=_string(value, "projection_sha256"),
        )
        return JSONResponse(result.wire())
    except CatalogValidationError as exc:
        return _error(str(exc), 400)
    except ClusterOrganizationError as exc:
        return _organization_error(exc)


async def _run_execute(
    service: ClusterOrganizationService, request: Request
) -> JSONResponse:
    try:
        value = _mapping(
            await _payload(request),
            {"schema_version", "cluster_id", "projection_sha256", "preview_sha256"},
        )
        result = await asyncio.to_thread(
            service.execute,
            cluster_id=_string(value, "cluster_id"),
            projection_sha256=_string(value, "projection_sha256"),
            preview_sha256=_string(value, "preview_sha256"),
        )
        return JSONResponse(result.wire())
    except CatalogValidationError as exc:
        return _error(str(exc), 400)
    except ClusterOrganizationError as exc:
        return _organization_error(exc)


async def _run_undo(
    service: ClusterOrganizationService, request: Request
) -> JSONResponse:
    try:
        value = _mapping(await _payload(request), {"schema_version", "undo_token"})
        result = await asyncio.to_thread(
            service.undo,
            undo_token=_string(value, "undo_token"),
        )
        return JSONResponse(result.wire())
    except CatalogValidationError as exc:
        return _error(str(exc), 400)
    except ClusterOrganizationError as exc:
        return _organization_error(exc)


async def _run_status(service: ClusterOrganizationService) -> JSONResponse:
    try:
        return JSONResponse((await asyncio.to_thread(service.status)).wire())
    except ClusterOrganizationError as exc:
        return _organization_error(exc)


async def _payload(request: Request) -> Any:
    return _strict_json(await _body(request, 10.0))


def _mapping(value: Any, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise CatalogValidationError("organization_request_invalid")
    if value.get("schema_version") != SCHEMA:
        raise CatalogValidationError("organization_schema_invalid")
    return value


def _string(value: dict[str, Any], name: str) -> str:
    result = value.get(name)
    if not isinstance(result, str) or not result or len(result) > 128:
        raise CatalogValidationError("organization_request_invalid")
    return result


def _organization_error(exc: ClusterOrganizationError) -> JSONResponse:
    code = str(exc)
    if code in {
        "catalog_projection_stale",
        "organization_preview_stale",
        "cluster_not_found",
        "cluster_has_no_pc_files",
        "file_scope_unconfigured",
        "organizer_undo_required",
        "organizer_undo_unavailable",
        "organizer_selection_stale",
    }:
        return _error(code, 409)
    if code in {"cluster_request_invalid", "organizer_selection_invalid"}:
        return _error(code, 400)
    return _error(code, 503)
