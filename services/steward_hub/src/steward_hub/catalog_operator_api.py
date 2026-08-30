"""Loopback operator controls for PC catalog refresh and unified summary."""

from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import asdict

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from .catalog_clustering import CatalogClusteringError, build_today_materials
from .catalog_store import CatalogStore, CatalogStoreError
from .credential_transition_api import (
    OperatorAuthError,
    _authorize_operator,
    _error,
    _operator_openapi_extra,
)
from .pairing_codec import require_digest, require_ulid
from .pairing_errors import PairingValidationError
from .pairing_store_executor import (
    PairingStoreExecutor,
    PairingStoreExecutorClosedError,
    PairingStoreSaturatedError,
)
from .pc_file_scope import PcFileScopeError, PcFileScopeService


def create_catalog_operator_router(
    *,
    store: CatalogStore,
    file_scope: PcFileScopeService,
    windows_device_id: str,
    operator_token_digest: str,
    store_executor: PairingStoreExecutor,
) -> APIRouter:
    expected_digest = require_digest("operator_token_digest", operator_token_digest)
    try:
        windows_device_id = require_ulid("windows_device_id", windows_device_id)
    except PairingValidationError:
        raise ValueError("windows_device_id is invalid") from None
    if not isinstance(store_executor, PairingStoreExecutor):
        raise ValueError("catalog_store_executor is invalid")
    router = APIRouter(prefix="/v1/operator/catalog", tags=["catalog-operator"])

    @router.post("/refresh-pc", openapi_extra=_operator_openapi_extra())
    async def refresh_pc(request: Request) -> JSONResponse:
        try:
            _authorize_operator(request, expected_digest)
            status = file_scope.status()
            if not status.configured or status.root_id is None:
                return _error("file_scope_unconfigured", 409)
            base_seq = await store_executor.run(
                store.current_seq,
                windows_device_id,
                status.root_id,
                timeout_s=10.0,
            )
            batch = await asyncio.to_thread(
                file_scope.catalog_snapshot,
                base_seq=base_seq,
                idempotency_key="pc-refresh-" + secrets.token_hex(12),
                generated_at_ms=int(time.time() * 1000),
            )
            result = await store_executor.run_completion_certain(
                store.apply_snapshot,
                device_id=windows_device_id,
                batch=batch,
                replace_other_roots=True,
            )
            return JSONResponse(asdict(result))
        except OperatorAuthError:
            return _error("operator_invalid", 401)
        except PcFileScopeError as exc:
            status_code = 409 if exc.code == "file_scope_unconfigured" else 503
            return _error(exc.code, status_code)
        except (
            CatalogStoreError,
            PairingStoreExecutorClosedError,
            PairingStoreSaturatedError,
            TimeoutError,
        ):
            return _error("catalog_persistence_unavailable", 503)

    @router.get("/summary", openapi_extra=_operator_openapi_extra())
    async def summary(request: Request) -> JSONResponse:
        try:
            _authorize_operator(request, expected_digest)
            roots = await store_executor.run(store.list_roots, timeout_s=10.0)
            assets = await store_executor.run(store.list_assets, timeout_s=10.0)
            projection = await store_executor.run(
                store.projection_sha256,
                timeout_s=10.0,
            )
            return JSONResponse(
                {
                    "roots": [asdict(root) for root in roots],
                    "assets": [asdict(asset) for asset in assets],
                    "root_count": len(roots),
                    "asset_count": len(assets),
                    "projection_sha256": projection,
                }
            )
        except OperatorAuthError:
            return _error("operator_invalid", 401)
        except (
            CatalogStoreError,
            PairingStoreExecutorClosedError,
            PairingStoreSaturatedError,
            TimeoutError,
        ):
            return _error("catalog_persistence_unavailable", 503)

    @router.get("/today", openapi_extra=_operator_openapi_extra())
    async def today_materials(request: Request) -> JSONResponse:
        try:
            _authorize_operator(request, expected_digest)
            roots, assets, source_projection = await store_executor.run(
                store.current_view,
                timeout_s=10.0,
            )
            projection = build_today_materials(
                roots=roots,
                assets=assets,
                source_projection_sha256=source_projection,
                now_ms=int(time.time() * 1000),
            )
            return JSONResponse(projection.wire())
        except OperatorAuthError:
            return _error("operator_invalid", 401)
        except CatalogClusteringError as exc:
            return _error(str(exc), 503)
        except (
            CatalogStoreError,
            PairingStoreExecutorClosedError,
            PairingStoreSaturatedError,
            TimeoutError,
        ):
            return _error("catalog_persistence_unavailable", 503)

    return router
