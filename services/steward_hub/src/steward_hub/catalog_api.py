"""Authenticated metadata-only Catalog Sync V1 HTTP surface."""

from __future__ import annotations

import asyncio
import json
import math
import threading
import time
from dataclasses import asdict
from typing import Any, Callable

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from .catalog_clustering import CatalogClusteringError, build_today_materials
from .catalog_models import CatalogValidationError, catalog_batch_from_mapping
from .catalog_store import CatalogCursorConflict, CatalogStore, CatalogStoreError
from .device_auth import (
    AUTH_MODE_REQUIRED,
    CATALOG_SYNC_CAPABILITY,
    AuthenticatedDevice,
    device_auth_openapi_extra,
)
from .pairing_store_executor import (
    PairingStoreExecutor,
    PairingStoreExecutorClosedError,
    PairingStoreSaturatedError,
)

MAX_CATALOG_BODY_BYTES = 768 * 1024
DEFAULT_CATALOG_TIMEOUT_S = 10.0


class CatalogRateLimiter:
    """Small fail-closed in-memory limiter keyed by authenticated device."""

    def __init__(
        self,
        *,
        write_limit: int = 12,
        read_limit: int = 60,
        window_s: float = 60.0,
        max_keys: int = 512,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if min(write_limit, read_limit, max_keys) <= 0 or window_s <= 0:
            raise ValueError("catalog rate limit is invalid")
        self._limits = {"write": write_limit, "read": read_limit}
        self._window_s = float(window_s)
        self._max_keys = max_keys
        self._clock = clock
        self._entries: dict[tuple[str, str], tuple[float, int]] = {}
        self._lock = threading.Lock()

    def consume(self, device_id: str, kind: str) -> int | None:
        now = self._clock()
        key = (device_id, kind)
        with self._lock:
            started, count = self._entries.get(key, (now, 0))
            if now - started >= self._window_s:
                started, count = now, 0
            if key not in self._entries and len(self._entries) >= self._max_keys:
                return max(1, math.ceil(self._window_s))
            if count >= self._limits[kind]:
                return max(1, math.ceil(self._window_s - (now - started)))
            self._entries[key] = (started, count + 1)
        return None


def _error(code: str, status: int, *, extra: dict[str, Any] | None = None) -> JSONResponse:
    body: dict[str, Any] = {"error_code": code, "message_key": code}
    if extra:
        body.update(extra)
    return JSONResponse(body, status_code=status)


def _strict_json(raw: bytes) -> Any:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise CatalogValidationError("catalog_duplicate_json_key")
            result[key] = value
        return result

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except CatalogValidationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise CatalogValidationError("catalog_json_invalid") from None


async def _body(request: Request, timeout_s: float) -> bytes:
    content_types = [
        value
        for key, value in request.scope.get("headers", ())
        if key.lower() == b"content-type"
    ]
    if len(content_types) != 1:
        raise CatalogValidationError("catalog_content_type_invalid")
    try:
        content_type = content_types[0].decode("ascii").lower()
    except (AttributeError, UnicodeDecodeError):
        raise CatalogValidationError("catalog_content_type_invalid") from None
    if content_type not in {"application/json", "application/json; charset=utf-8"}:
        raise CatalogValidationError("catalog_content_type_invalid")
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            length = int(content_length)
        except ValueError:
            raise CatalogValidationError("catalog_body_invalid") from None
        if length <= 0 or length > MAX_CATALOG_BODY_BYTES:
            raise CatalogValidationError("catalog_body_invalid")

    async def read_bounded() -> bytes:
        result = bytearray()
        async for chunk in request.stream():
            if len(result) + len(chunk) > MAX_CATALOG_BODY_BYTES:
                raise CatalogValidationError("catalog_body_invalid")
            result.extend(chunk)
        return bytes(result)

    try:
        raw = await asyncio.wait_for(read_bounded(), timeout=timeout_s)
    except TimeoutError:
        raise CatalogStoreError("catalog_timeout") from None
    if not raw or len(raw) > MAX_CATALOG_BODY_BYTES:
        raise CatalogValidationError("catalog_body_invalid")
    return raw


def _authenticated(request: Request) -> AuthenticatedDevice:
    value = getattr(request.state, "authenticated_device", None)
    if not isinstance(value, AuthenticatedDevice):
        raise CatalogStoreError("catalog_auth_context_missing")
    return value


def create_catalog_router(
    *,
    store: CatalogStore,
    store_executor: PairingStoreExecutor,
    rate_limiter: CatalogRateLimiter | None = None,
    timeout_s: float = DEFAULT_CATALOG_TIMEOUT_S,
) -> APIRouter:
    if not isinstance(store, CatalogStore):
        raise ValueError("catalog_store is invalid")
    if not isinstance(store_executor, PairingStoreExecutor):
        raise ValueError("catalog_store_executor is invalid")
    if timeout_s <= 0 or timeout_s > 30:
        raise ValueError("catalog timeout is invalid")
    limiter = rate_limiter or CatalogRateLimiter()
    router = APIRouter(prefix="/v1/catalog", tags=["catalog"])
    auth_openapi = device_auth_openapi_extra(
        AUTH_MODE_REQUIRED,
        CATALOG_SYNC_CAPABILITY,
    )

    @router.post("/snapshots", openapi_extra=auth_openapi)
    async def apply_snapshot(request: Request) -> JSONResponse:
        device = _authenticated(request)
        retry_after = limiter.consume(device.device_id, "write")
        if retry_after is not None:
            response = _error("catalog_rate_limited", 429)
            response.headers["Retry-After"] = str(retry_after)
            return response
        try:
            batch = catalog_batch_from_mapping(
                _strict_json(await _body(request, timeout_s))
            )
            if device.platform != batch.platform:
                return _error("catalog_platform_mismatch", 400)
            result = await store_executor.run_completion_certain(
                store.apply_snapshot,
                device_id=device.device_id,
                batch=batch,
            )
            return JSONResponse(asdict(result), status_code=200)
        except CatalogValidationError as exc:
            return _error(str(exc), 400)
        except CatalogCursorConflict as exc:
            return _error(
                exc.code,
                409,
                extra={"server_catalog_seq": exc.server_catalog_seq},
            )
        except CatalogStoreError as exc:
            status = (
                409
                if exc.code
                in {"catalog_idempotency_conflict", "catalog_root_binding_conflict"}
                else 503
            )
            return _error(exc.code, status)
        except (PairingStoreExecutorClosedError, PairingStoreSaturatedError):
            return _error("catalog_persistence_unavailable", 503)
        except TimeoutError:
            return _error("catalog_timeout", 503)

    @router.get("/roots", openapi_extra=auth_openapi)
    async def list_roots(request: Request) -> JSONResponse:
        device = _authenticated(request)
        retry_after = limiter.consume(device.device_id, "read")
        if retry_after is not None:
            response = _error("catalog_rate_limited", 429)
            response.headers["Retry-After"] = str(retry_after)
            return response
        try:
            roots = await store_executor.run(store.list_roots, timeout_s=timeout_s)
            return JSONResponse({"roots": [asdict(root) for root in roots]})
        except (
            CatalogStoreError,
            PairingStoreExecutorClosedError,
            PairingStoreSaturatedError,
            TimeoutError,
        ):
            return _error("catalog_persistence_unavailable", 503)

    @router.get("/assets", openapi_extra=auth_openapi)
    async def list_assets(request: Request) -> JSONResponse:
        device = _authenticated(request)
        retry_after = limiter.consume(device.device_id, "read")
        if retry_after is not None:
            response = _error("catalog_rate_limited", 429)
            response.headers["Retry-After"] = str(retry_after)
            return response
        try:
            assets = await store_executor.run(store.list_assets, timeout_s=timeout_s)
            return JSONResponse({"assets": [asdict(asset) for asset in assets]})
        except (
            CatalogStoreError,
            PairingStoreExecutorClosedError,
            PairingStoreSaturatedError,
            TimeoutError,
        ):
            return _error("catalog_persistence_unavailable", 503)

    @router.get("/today", openapi_extra=auth_openapi)
    async def today_materials(request: Request) -> JSONResponse:
        device = _authenticated(request)
        retry_after = limiter.consume(device.device_id, "read")
        if retry_after is not None:
            response = _error("catalog_rate_limited", 429)
            response.headers["Retry-After"] = str(retry_after)
            return response
        try:
            roots, assets, source_projection = await store_executor.run(
                store.current_view,
                timeout_s=timeout_s,
            )
            projection = build_today_materials(
                roots=roots,
                assets=assets,
                source_projection_sha256=source_projection,
                now_ms=int(time.time() * 1000),
            )
            return JSONResponse(projection.wire())
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
