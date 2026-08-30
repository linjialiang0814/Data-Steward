"""Authenticated bounded Android OCR upload surface."""

from __future__ import annotations

import asyncio
import json
from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from .android_ocr_store import (
    AndroidOcrStore,
    AndroidOcrStoreError,
    android_ocr_batch_from_mapping,
)
from .device_auth import AUTH_MODE_REQUIRED, CONTENT_ANALYZE_CAPABILITY, AuthenticatedDevice, device_auth_openapi_extra
from .pairing_store_executor import PairingStoreExecutor, PairingStoreExecutorClosedError, PairingStoreSaturatedError

MAX_OCR_BODY_BYTES = 192 * 1024
OCR_REQUEST_TIMEOUT_S = 12.0


def create_android_ocr_router(*, store: AndroidOcrStore, executor: PairingStoreExecutor) -> APIRouter:
    router = APIRouter(prefix="/v1/content/android-ocr", tags=["android-ocr"])
    auth = device_auth_openapi_extra(AUTH_MODE_REQUIRED, CONTENT_ANALYZE_CAPABILITY)

    @router.post("", openapi_extra=auth)
    async def upload(request: Request) -> JSONResponse:
        try:
            device = _authenticated(request)
            if device.platform != "android":
                return _error("ocr_platform_mismatch", 400)
            batch = android_ocr_batch_from_mapping(await _body(request))
            receipt = await executor.run_completion_certain(
                store.apply, device_id=device.device_id, batch=batch,
            )
            return JSONResponse(asdict(receipt))
        except AndroidOcrStoreError as exc:
            status = 409 if exc.code in {
                "ocr_snapshot_stale", "ocr_revision_changed", "ocr_catalog_binding_invalid",
                "ocr_idempotency_conflict",
            } else 400 if exc.code == "ocr_request_invalid" else 503
            return _error(exc.code, status)
        except (PairingStoreExecutorClosedError, PairingStoreSaturatedError, TimeoutError):
            return _error("ocr_persistence_unavailable", 503)

    @router.delete("/{root_id}", openapi_extra=auth)
    async def forget(root_id: str, request: Request) -> JSONResponse:
        try:
            device = _authenticated(request)
            deleted = await executor.run_completion_certain(
                store.forget_root, device_id=device.device_id, root_id=root_id,
            )
            return JSONResponse({"status": "forgotten", "deleted_count": deleted})
        except AndroidOcrStoreError as exc:
            return _error(exc.code, 400 if exc.code == "ocr_request_invalid" else 503)
        except (PairingStoreExecutorClosedError, PairingStoreSaturatedError, TimeoutError):
            return _error("ocr_persistence_unavailable", 503)

    return router


async def _body(request: Request) -> Any:
    content_types = [value for key, value in request.scope.get("headers", ()) if key.lower() == b"content-type"]
    if len(content_types) != 1:
        raise AndroidOcrStoreError("ocr_request_invalid")
    try:
        if content_types[0].decode("ascii").lower() not in {"application/json", "application/json; charset=utf-8"}:
            raise AndroidOcrStoreError("ocr_request_invalid")
        length = request.headers.get("content-length")
        if length is not None and not 0 < int(length) <= MAX_OCR_BODY_BYTES:
            raise AndroidOcrStoreError("ocr_request_invalid")
    except (UnicodeDecodeError, ValueError):
        raise AndroidOcrStoreError("ocr_request_invalid") from None

    async def read() -> bytes:
        result = bytearray()
        async for chunk in request.stream():
            if len(result) + len(chunk) > MAX_OCR_BODY_BYTES:
                raise AndroidOcrStoreError("ocr_request_invalid")
            result.extend(chunk)
        return bytes(result)

    try:
        raw = await asyncio.wait_for(read(), timeout=OCR_REQUEST_TIMEOUT_S)
        if not raw:
            raise AndroidOcrStoreError("ocr_request_invalid")

        def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in values:
                if key in result:
                    raise AndroidOcrStoreError("ocr_request_invalid")
                result[key] = value
            return result

        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except AndroidOcrStoreError:
        raise
    except (TimeoutError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise AndroidOcrStoreError("ocr_request_invalid") from None


def _authenticated(request: Request) -> AuthenticatedDevice:
    value = getattr(request.state, "authenticated_device", None)
    if not isinstance(value, AuthenticatedDevice):
        raise AndroidOcrStoreError("ocr_auth_context_missing")
    return value


def _error(code: str, status: int) -> JSONResponse:
    return JSONResponse({"error_code": code, "message_key": code}, status_code=status)
