"""Loopback pairing HTTP contract adapter over PairingStore (no real listener)."""

from __future__ import annotations

import asyncio
import json
import math
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse
from pydantic import ValidationError as PydanticValidationError

from .pairing_codec import PROTOCOL_VERSION, require_digest, require_ulid
from .pairing_errors import (
    PairingAttemptConflictError,
    PairingBusyError,
    PairingClaimInvalidError,
    PairingClosedError,
    PairingError,
    PairingExpiredError,
    PairingNotFoundError,
    PairingPersistenceError,
    PairingRejectedError,
    PairingShortCodeMismatchError,
    PairingStateError,
    PairingValidationError,
)
from .pairing_http_codec import (
    PairingHttpCodecError,
    digest_secret_b64url,
    parse_pairing_authorization,
    require_protocol_version,
)
from .pairing_http_models import (
    ClientConfirmRequest,
    ClientConfirmResponse,
    ClientHelloRequest,
    ClientHelloResponse,
    PairingErrorBody,
    PairingStatusResponse,
)
from .pairing_rate_limit import PairingRateLimiter, normalize_source_key
from .pairing_store import PairingStore
from .pairing_store_executor import (
    DEFAULT_MAX_QUEUED,
    DEFAULT_MAX_WORKERS,
    PairingStoreExecutor,
    PairingStoreExecutorClosedError,
    PairingStoreSaturatedError,
)

MAX_PAIRING_BODY_BYTES = 16_384
DEFAULT_PAIRING_TIMEOUT_S = 10.0
MAX_PAIRING_TIMEOUT_S = 30.0
PROTOCOL_HEADER = "X-DataSteward-Protocol"
ENDPOINT_HELLO = "client_hello"
ENDPOINT_CONFIRM = "client_confirm"
ENDPOINT_STATUS = "status"

DEFAULT_RATE_LIMITS = {
    ENDPOINT_HELLO: 10,
    ENDPOINT_CONFIRM: 20,
    ENDPOINT_STATUS: 30,
}

_HTTP_STATUS: dict[str, int] = {
    "protocol_version_rejected": 400,
    "pairing_validation_error": 400,
    "policy_violation": 400,
    "claim_missing": 401,
    "claim_invalid": 401,
    "claim_expired": 401,
    "short_code_mismatch": 401,
    "pairing_rejected": 409,
    "pairing_busy": 409,
    "pairing_attempt_conflict": 409,
    "pairing_expired": 410,
    "payload_too_large": 413,
    "rate_limited": 429,
    "pairing_persistence_error": 503,
    "pairing_unavailable": 503,
}

_ERROR_RESPONSES = {
    400: {"model": PairingErrorBody},
    401: {"model": PairingErrorBody},
    409: {"model": PairingErrorBody},
    410: {"model": PairingErrorBody},
    413: {"model": PairingErrorBody},
    429: {"model": PairingErrorBody},
    500: {"model": PairingErrorBody},
    503: {"model": PairingErrorBody},
}


class PairingRequestTimeout(Exception):
    error_code = "pairing_request_timeout"


class PairingPayloadTooLarge(Exception):
    error_code = "payload_too_large"


class PairingWireContractError(Exception):
    """Store returned a value that cannot be represented on the wire."""

    error_code = "pairing_internal_error"


def validate_request_timeout_s(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("pairing_request_timeout_s must be a finite positive number")
    number = float(value)
    if not math.isfinite(number) or number <= 0 or number > MAX_PAIRING_TIMEOUT_S:
        raise ValueError(
            "pairing_request_timeout_s must be finite, > 0, and "
            f"<= {MAX_PAIRING_TIMEOUT_S}"
        )
    return number


def pairing_error_response(
    error_code: str,
    *,
    retry_after: int | None = None,
) -> JSONResponse:
    status = _HTTP_STATUS.get(error_code, 500)
    if status == 500:
        body = PairingErrorBody(
            error_code="pairing_internal_error",
            message_key="pairing.internal_error",
        )
        status = 500
    else:
        body = PairingErrorBody(
            error_code=error_code,
            message_key=f"pairing.{error_code}",
        )
    headers: dict[str, str] = {}
    if error_code == "rate_limited" and retry_after is not None:
        headers["Retry-After"] = str(max(1, int(retry_after)))
    return JSONResponse(status_code=status, content=body.model_dump(), headers=headers)


def map_pairing_exception(exc: BaseException) -> JSONResponse:
    if isinstance(exc, PairingHttpCodecError):
        return pairing_error_response(exc.error_code)
    if isinstance(exc, PairingPayloadTooLarge):
        return pairing_error_response("payload_too_large")
    if isinstance(
        exc,
        (
            PairingRequestTimeout,
            asyncio.TimeoutError,
            TimeoutError,
            PairingStoreSaturatedError,
            PairingStoreExecutorClosedError,
        ),
    ):
        return pairing_error_response("pairing_unavailable")
    if isinstance(exc, PairingWireContractError):
        return pairing_error_response("pairing_internal_error")
    if isinstance(exc, PairingClaimInvalidError):
        return pairing_error_response("claim_invalid")
    if isinstance(exc, PairingShortCodeMismatchError):
        return pairing_error_response("short_code_mismatch")
    if isinstance(exc, PairingExpiredError):
        return pairing_error_response("pairing_expired")
    if isinstance(exc, PairingRejectedError):
        return pairing_error_response("pairing_rejected")
    if isinstance(exc, PairingBusyError):
        return pairing_error_response("pairing_busy")
    if isinstance(exc, PairingAttemptConflictError):
        return pairing_error_response("pairing_attempt_conflict")
    if isinstance(exc, (PairingNotFoundError, PairingStateError)):
        return pairing_error_response("pairing_expired")
    if isinstance(exc, PairingValidationError):
        return pairing_error_response("pairing_validation_error")
    if isinstance(exc, (PairingPersistenceError, PairingClosedError)):
        return pairing_error_response("pairing_persistence_error")
    if isinstance(exc, PairingError):
        code = getattr(exc, "error_code", "pairing_internal_error")
        if code in _HTTP_STATUS:
            return pairing_error_response(code)
        return pairing_error_response("pairing_internal_error")
    if isinstance(exc, PydanticValidationError):
        return pairing_error_response("pairing_validation_error")
    return pairing_error_response("pairing_internal_error")


def default_source_key(request: Request) -> str:
    """ASGI peer host; never trusts X-Forwarded-For / Forwarded."""
    resolver = getattr(request.app.state, "pairing_source_key_fn", None)
    if callable(resolver):
        return normalize_source_key(str(resolver(request)))
    client = request.client
    if client is None:
        return "unknown"
    return normalize_source_key(str(client.host))


def _openapi_body(model: type[Any]) -> dict[str, Any]:
    return {
        "required": True,
        "content": {
            "application/json": {
                "schema": model.model_json_schema(ref_template="#/components/schemas/{model}")
            }
        },
    }


def create_pairing_router(
    *,
    get_store: Callable[[], PairingStore],
    store_executor: PairingStoreExecutor,
    rate_limiter: PairingRateLimiter | None = None,
    request_timeout_s: float = DEFAULT_PAIRING_TIMEOUT_S,
    clock: Callable[[], float] | None = None,
    wall_clock: Callable[[], datetime] | None = None,
) -> APIRouter:
    router = APIRouter(tags=["pairing"])
    limiter = rate_limiter or PairingRateLimiter(limits=DEFAULT_RATE_LIMITS)
    mono = clock or time.monotonic
    wall = wall_clock or (lambda: datetime.now(timezone.utc))
    default_timeout = validate_request_timeout_s(request_timeout_s)

    def _deadline(timeout_s: float) -> float:
        return mono() + float(timeout_s)

    def _remaining(deadline: float) -> float:
        return deadline - mono()

    def _ensure_time(deadline: float) -> None:
        if _remaining(deadline) <= 0:
            raise PairingRequestTimeout()

    async def _read_body(request: Request, *, deadline: float) -> bytes:
        content_type = request.headers.get("content-type", "")
        media = content_type.split(";", 1)[0].strip().lower()
        if media != "application/json":
            raise PairingHttpCodecError("pairing_validation_error")
        cl_raw = request.headers.get("content-length")
        if cl_raw is not None:
            try:
                content_length = int(cl_raw)
            except ValueError as exc:
                raise PairingHttpCodecError("pairing_validation_error") from exc
            if content_length < 0:
                raise PairingHttpCodecError("pairing_validation_error")
            if content_length > MAX_PAIRING_BODY_BYTES:
                raise PairingPayloadTooLarge()

        chunks: list[bytes] = []
        total = 0
        more_body = True
        receive = request.receive
        while more_body:
            remaining = _remaining(deadline)
            if remaining <= 0:
                raise PairingRequestTimeout()
            try:
                message = await asyncio.wait_for(receive(), timeout=remaining)
            except asyncio.TimeoutError as exc:
                raise PairingRequestTimeout() from exc
            if message.get("type") != "http.request":
                continue
            chunk = message.get("body", b"")
            if not isinstance(chunk, (bytes, bytearray)):
                raise PairingHttpCodecError("pairing_validation_error")
            if chunk:
                total += len(chunk)
                if total > MAX_PAIRING_BODY_BYTES:
                    raise PairingPayloadTooLarge()
                chunks.append(bytes(chunk))
            more_body = bool(message.get("more_body", False))
        return b"".join(chunks)

    def _parse_json_object(raw: bytes) -> dict[str, Any]:
        def _reject_duplicates(
            pairs: list[tuple[str, Any]],
        ) -> dict[str, Any]:
            out: dict[str, Any] = {}
            for key, value in pairs:
                if key in out:
                    raise PairingHttpCodecError("pairing_validation_error")
                out[key] = value
            return out

        try:
            data = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_reject_duplicates,
            )
        except PairingHttpCodecError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise PairingHttpCodecError("pairing_validation_error") from exc
        if not isinstance(data, dict):
            raise PairingHttpCodecError("pairing_validation_error")
        return data

    def _check_protocol_header(request: Request) -> None:
        header = request.headers.get(PROTOCOL_HEADER)
        if header != PROTOCOL_VERSION:
            raise PairingHttpCodecError("protocol_version_rejected")

    def _rate_limit(request: Request, endpoint: str) -> JSONResponse | None:
        decision = limiter.check_and_consume(
            endpoint=endpoint,
            source_key=default_source_key(request),
        )
        if decision.allowed:
            return None
        return pairing_error_response(
            "rate_limited",
            retry_after=decision.retry_after_seconds,
        )

    async def _call_store(
        fn: Callable[..., Any],
        /,
        *args: Any,
        deadline: float,
        **kwargs: Any,
    ) -> Any:
        remaining = _remaining(deadline)
        if remaining <= 0:
            raise PairingRequestTimeout()
        # Bounded pool: started SQLite work is not force-cancelled; queued may cancel.
        try:
            return await store_executor.run(
                fn,
                *args,
                timeout_s=remaining,
                **kwargs,
            )
        except TimeoutError as exc:
            raise PairingRequestTimeout() from exc

    def _server_time() -> str:
        now = wall()
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        return (
            now.astimezone(timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )

    def _resolve_timeout(request: Request) -> float:
        configured = getattr(
            request.app.state, "pairing_request_timeout_s", default_timeout
        )
        return validate_request_timeout_s(configured)

    @router.post(
        "/v1/pairing/sessions/{pairing_session_id}/client_hello",
        response_model=ClientHelloResponse,
        responses=_ERROR_RESPONSES,
        openapi_extra={"requestBody": _openapi_body(ClientHelloRequest)},
    )
    async def client_hello(
        pairing_session_id: str,
        request: Request,
    ) -> Response:
        limited = _rate_limit(request, ENDPOINT_HELLO)
        if limited is not None:
            return limited
        deadline = _deadline(_resolve_timeout(request))
        try:
            require_ulid("pairing_session_id", pairing_session_id)
            raw = await _read_body(request, deadline=deadline)
            _ensure_time(deadline)
            payload = _parse_json_object(raw)
            model = ClientHelloRequest.model_validate(payload)
            require_protocol_version(model.protocol_version)
            ott_digest = digest_secret_b64url(model.pairing_token)
            claim_digest = digest_secret_b64url(model.claim_secret)
            cred_digest = require_digest(
                "device_credential_digest", model.device_credential_digest
            )
            store = get_store()
            result = await _call_store(
                store.register_client_hello_digest,
                pairing_session_id=pairing_session_id,
                pairing_attempt_id=model.pairing_attempt_id,
                pairing_token_digest=ott_digest,
                claim_secret_digest=claim_digest,
                device_credential_digest=cred_digest,
                client_nonce=model.client_nonce,
                requested_capabilities=model.requested_capabilities,
                display_name=model.display_name,
                platform=model.platform,
                deadline=deadline,
            )
            try:
                body = ClientHelloResponse(
                    protocol_version="pairing_auth/1",
                    pairing_session_id=result.pairing_session_id,
                    pairing_attempt_id=result.pairing_attempt_id,
                    device_id=result.device_id,
                    credential_status="PENDING",
                    short_verification_code=result.short_verification_code,
                    server_time=_server_time(),
                    pending_expires_at_hint=result.pending_expires_at,
                )
            except PydanticValidationError as exc:
                raise PairingWireContractError() from exc
            return JSONResponse(status_code=200, content=body.model_dump())
        except Exception as exc:  # noqa: BLE001
            return map_pairing_exception(exc)

    @router.post(
        "/v1/pairing/sessions/{pairing_session_id}/client_confirm",
        response_model=ClientConfirmResponse,
        responses=_ERROR_RESPONSES,
        openapi_extra={"requestBody": _openapi_body(ClientConfirmRequest)},
    )
    async def client_confirm(
        pairing_session_id: str,
        request: Request,
    ) -> Response:
        limited = _rate_limit(request, ENDPOINT_CONFIRM)
        if limited is not None:
            return limited
        deadline = _deadline(_resolve_timeout(request))
        try:
            require_ulid("pairing_session_id", pairing_session_id)
            _check_protocol_header(request)
            claim_digest = parse_pairing_authorization(
                request.headers.get("authorization")
            )
            raw = await _read_body(request, deadline=deadline)
            _ensure_time(deadline)
            payload = _parse_json_object(raw)
            if "claim_secret" in payload:
                raise PairingHttpCodecError("pairing_validation_error")
            model = ClientConfirmRequest.model_validate(payload)
            require_protocol_version(model.protocol_version)
            store = get_store()
            result = await _call_store(
                store.record_client_confirmation_digest,
                pairing_session_id=pairing_session_id,
                pairing_attempt_id=model.pairing_attempt_id,
                claim_secret_digest=claim_digest,
                short_verification_code=model.short_verification_code,
                deadline=deadline,
            )
            try:
                body = ClientConfirmResponse(
                    protocol_version="pairing_auth/1",
                    pairing_attempt_id=result.pairing_attempt_id,
                    device_id=result.device_id,
                    credential_status=result.credential_status,
                    granted_capabilities=list(result.granted_capabilities),
                    capability_epoch=int(result.capability_epoch),
                )
            except (PydanticValidationError, ValueError, TypeError) as exc:
                raise PairingWireContractError() from exc
            return JSONResponse(status_code=200, content=body.model_dump())
        except Exception as exc:  # noqa: BLE001
            return map_pairing_exception(exc)

    @router.get(
        "/v1/pairing/sessions/{pairing_session_id}/status",
        response_model=PairingStatusResponse,
        responses=_ERROR_RESPONSES,
    )
    async def pairing_status(
        pairing_session_id: str,
        request: Request,
    ) -> Response:
        limited = _rate_limit(request, ENDPOINT_STATUS)
        if limited is not None:
            return limited
        deadline = _deadline(_resolve_timeout(request))
        try:
            require_ulid("pairing_session_id", pairing_session_id)
            _check_protocol_header(request)
            claim_digest = parse_pairing_authorization(
                request.headers.get("authorization")
            )
            attempt_id = request.query_params.get("pairing_attempt_id")
            if attempt_id is None:
                raise PairingHttpCodecError("pairing_validation_error")
            require_ulid("pairing_attempt_id", attempt_id)
            store = get_store()
            status = await _call_store(
                store.get_redacted_pairing_status,
                pairing_session_id=pairing_session_id,
                pairing_attempt_id=attempt_id,
                claim_secret_digest=claim_digest,
                deadline=deadline,
            )
            cred = status.credential_status if status.credential_status else "UNKNOWN"
            epoch = int(status.capability_epoch or 0)
            try:
                body = PairingStatusResponse(
                    protocol_version="pairing_auth/1",
                    pairing_session_id=status.pairing_session_id,
                    pairing_attempt_id=status.pairing_attempt_id,
                    session_state=status.state,  # type: ignore[arg-type]
                    credential_status=cred,  # type: ignore[arg-type]
                    device_id=status.device_id,
                    capability_epoch=epoch,
                )
            except (PydanticValidationError, ValueError, TypeError) as exc:
                raise PairingWireContractError() from exc
            return JSONResponse(status_code=200, content=body.model_dump())
        except Exception as exc:  # noqa: BLE001
            return map_pairing_exception(exc)

    return router


def attach_pairing_api(
    app: Any,
    *,
    pairing_store: PairingStore,
    rate_limiter: PairingRateLimiter | None = None,
    request_timeout_s: float = DEFAULT_PAIRING_TIMEOUT_S,
    source_key_fn: Callable[[Request], str] | None = None,
    close_pairing_store: bool = False,
    clock: Callable[[], float] | None = None,
    wall_clock: Callable[[], datetime] | None = None,
    store_max_workers: int = DEFAULT_MAX_WORKERS,
    store_max_queued: int = DEFAULT_MAX_QUEUED,
    store_executor: PairingStoreExecutor | None = None,
) -> PairingStoreExecutor:
    """Install pairing router and app.state hooks on an existing FastAPI app."""
    timeout = validate_request_timeout_s(request_timeout_s)
    executor = store_executor or PairingStoreExecutor(
        max_workers=store_max_workers,
        max_queued=store_max_queued,
    )
    app.state.pairing_store = pairing_store
    app.state.pairing_request_timeout_s = timeout
    app.state.close_pairing_store = bool(close_pairing_store)
    app.state.pairing_store_executor = executor
    if source_key_fn is not None:
        app.state.pairing_source_key_fn = source_key_fn
    limiter = rate_limiter or PairingRateLimiter(limits=DEFAULT_RATE_LIMITS)
    app.state.pairing_rate_limiter = limiter

    def get_store() -> PairingStore:
        store = getattr(app.state, "pairing_store", None)
        if store is None:
            raise PairingClosedError()
        return store

    app.include_router(
        create_pairing_router(
            get_store=get_store,
            store_executor=executor,
            rate_limiter=limiter,
            request_timeout_s=timeout,
            clock=clock,
            wall_clock=wall_clock,
        )
    )
    return executor


async def shutdown_pairing_store_executor(app: Any) -> None:
    """
    Ordered shutdown:
    1) stop accepting 2) cancel queued 3) wait started 4) active==0
    Callers must close PairingStore only after this returns.
    """
    executor = getattr(app.state, "pairing_store_executor", None)
    if isinstance(executor, PairingStoreExecutor):
        await asyncio.to_thread(executor.shutdown, wait=True, cancel_queued=True)


# Backward-compatible alias used by older call sites during R1→R2 transition.
async def drain_pairing_late_tasks(app: Any, *, timeout_s: float = 2.0) -> None:
    _ = timeout_s
    await shutdown_pairing_store_executor(app)
