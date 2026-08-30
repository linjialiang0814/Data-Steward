"""Operator and authenticated REST surfaces for bounded study insights."""

from __future__ import annotations

import asyncio
import re
from dataclasses import asdict
from typing import Any, Protocol

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from .agent_planning import AgentPlanningError
from .autonomy_job import AutonomyJobError, AutonomyJobStore
from .content_understanding import (
    ContentUnderstandingError,
    ContentUnderstandingService,
    StudyPack,
    build_study_pack,
)
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
    device_auth_openapi_extra,
)
from .pairing_codec import require_digest

MAX_ANALYSIS_REQUEST_CHARS = 500
_WORD_RE = re.compile(r"[\u3400-\u9fff]{2,8}|[A-Za-z][A-Za-z0-9_-]{2,24}")


class StudyPackPlanner(Protocol):
    def analyze_study_pack(
        self, *, user_text: str, snapshot_sha256: str
    ) -> StudyPack: ...


class ContentInsightCoordinator:
    """One attempt only; Provider failure degrades to deterministic output."""

    def __init__(
        self,
        *,
        content: ContentUnderstandingService,
        planner: StudyPackPlanner | None,
        job_store: AutonomyJobStore | None = None,
    ) -> None:
        self._content = content
        self._planner = planner
        self._job_store = job_store

    @property
    def content(self) -> ContentUnderstandingService:
        return self._content

    def generate(self, user_text: str) -> StudyPack:
        request = _validate_request_text(user_text)
        snapshot = self._content.current_snapshot()
        allowed = tuple(
            asset.asset_id
            for asset in self._content.list_safe_assets(snapshot_sha256=snapshot)
        )
        if not allowed:
            raise ContentUnderstandingError("content_no_supported_files")
        lease = None
        job_store = self._job_store
        if job_store is not None:
            try:
                lease = job_store.begin(
                    snapshot_sha256=snapshot,
                    normalized_request=request,
                )
                if lease.cached_result is not None:
                    return self._content.save_study_pack(
                        lease.cached_result,
                        allowed_asset_ids=allowed,
                    )
                job_store.transition(
                    lease.job_id, expected="QUEUED", target="SNAPSHOT_BOUND"
                )
                job_store.transition(
                    lease.job_id, expected="SNAPSHOT_BOUND", target="RUNNING"
                )
            except AutonomyJobError as exc:
                raise ContentUnderstandingError(exc.code) from None
        planner = self._planner
        used_hermes = False
        planner_outcome = "planner_not_configured"
        pack: StudyPack | None = None
        if planner is not None:
            try:
                pack = planner.analyze_study_pack(
                    user_text=request,
                    snapshot_sha256=snapshot,
                )
                used_hermes = True
            except AgentPlanningError as exc:
                # One failed Provider attempt only. Fall through locally.
                planner_outcome = exc.code
        try:
            if pack is None:
                excerpts = self._content.extract_assets(snapshot_sha256=snapshot)
                topics: list[str] = []
                for item in excerpts:
                    for token in _WORD_RE.findall(
                        item.display_name + " " + item.excerpt
                    ):
                        normalized = token.casefold()
                        if normalized not in topics:
                            topics.append(normalized)
                        if len(topics) == 5:
                            break
                    if len(topics) == 5:
                        break
                if not topics:
                    topics = ["今日资料"]
                names = "、".join(item.display_name for item in excerpts[:3])
                pack = build_study_pack(
                    snapshot_sha256=snapshot,
                    title="今日学习资料要点",
                    summary=f"已在本机受控读取 {len(excerpts)} 份文本资料，可优先结合 {names} 进行复习。",
                    topics=topics,
                    review_points=(
                        "先按今日资料分组核对课程主题",
                        "再结合课堂笔记与课程安排逐项复习",
                    ),
                    cited_asset_ids=tuple(item.asset_id for item in excerpts),
                    source="deterministic_fallback",
                )
            if job_store is not None and lease is not None:
                job_store.transition(
                    lease.job_id, expected="RUNNING", target="VALIDATING"
                )
            saved = self._content.save_study_pack(
                pack.wire(include_internal=True),
                allowed_asset_ids=allowed,
            )
            if job_store is not None and lease is not None:
                job_store.complete(
                    lease.job_id,
                    state="SUCCEEDED" if used_hermes else "DEGRADED",
                    result=saved.wire(include_internal=True),
                    outcome_code=(
                        "hermes_success" if used_hermes else planner_outcome
                    ),
                )
            return saved
        except AutonomyJobError as exc:
            if job_store is not None and lease is not None:
                try:
                    job_store.fail_safe(lease.job_id)
                except AutonomyJobError:
                    pass
            raise ContentUnderstandingError(exc.code) from None
        except Exception:
            if job_store is not None and lease is not None:
                try:
                    job_store.fail_safe(lease.job_id)
                except AutonomyJobError:
                    pass
            raise


def create_content_operator_router(
    *,
    coordinator: ContentInsightCoordinator,
    operator_token_digest: str,
) -> APIRouter:
    expected_digest = require_digest("operator_token_digest", operator_token_digest)
    router = APIRouter(prefix="/v1/operator/content", tags=["content-operator"])

    @router.get("/status", openapi_extra=_operator_openapi_extra())
    async def status(request: Request) -> JSONResponse:
        try:
            _authorize_operator(request, expected_digest)
            view = await asyncio.to_thread(coordinator.content.status)
            return JSONResponse(asdict(view))
        except OperatorAuthError:
            return _operator_error("operator_invalid", 401)
        except ContentUnderstandingError as exc:
            return _content_error(exc.code)

    @router.post("/opt-in", openapi_extra=_operator_openapi_extra())
    async def opt_in(request: Request) -> JSONResponse:
        try:
            _authorize_operator(request, expected_digest)
            body = await _strict_json_body(request)
            if set(body) != {"enabled"} or not isinstance(body["enabled"], bool):
                raise OperatorPayloadError()
            view = await asyncio.to_thread(
                coordinator.content.set_opt_in, body["enabled"]
            )
            return JSONResponse(asdict(view))
        except OperatorAuthError:
            return _operator_error("operator_invalid", 401)
        except OperatorPayloadError:
            return _operator_error("content_request_invalid", 400)
        except ContentUnderstandingError as exc:
            return _content_error(exc.code)

    @router.post("/study-pack", openapi_extra=_operator_openapi_extra())
    async def generate(request: Request) -> JSONResponse:
        try:
            _authorize_operator(request, expected_digest)
            body = await _strict_json_body(request)
            if set(body) != {"request"}:
                raise OperatorPayloadError()
            pack = await asyncio.to_thread(coordinator.generate, body["request"])
            return JSONResponse(pack.wire())
        except OperatorAuthError:
            return _operator_error("operator_invalid", 401)
        except (OperatorPayloadError, ValueError):
            return _operator_error("content_request_invalid", 400)
        except ContentUnderstandingError as exc:
            return _content_error(exc.code)

    @router.get("/study-pack", openapi_extra=_operator_openapi_extra())
    async def latest(request: Request) -> JSONResponse:
        try:
            _authorize_operator(request, expected_digest)
            pack = await asyncio.to_thread(coordinator.content.latest_study_pack)
            if pack is None:
                return _operator_error("content_insight_unavailable", 404)
            return JSONResponse(pack.wire())
        except OperatorAuthError:
            return _operator_error("operator_invalid", 401)
        except ContentUnderstandingError as exc:
            return _content_error(exc.code)

    return router


def create_content_device_router(
    *, coordinator: ContentInsightCoordinator
) -> APIRouter:
    router = APIRouter(prefix="/v1/content", tags=["content"])
    auth = device_auth_openapi_extra(AUTH_MODE_REQUIRED, CONTENT_ANALYZE_CAPABILITY)

    @router.post("/study-pack", openapi_extra=auth)
    async def generate(request: Request) -> JSONResponse:
        try:
            _authenticated(request)
            body = await _strict_json_body(request)
            if set(body) != {"request"}:
                raise OperatorPayloadError()
            pack = await asyncio.to_thread(coordinator.generate, body["request"])
            return JSONResponse(pack.wire())
        except OperatorPayloadError:
            return _plain_error("content_request_invalid", 400)
        except ContentUnderstandingError as exc:
            return _content_error(exc.code, operator=False)

    @router.get("/study-pack", openapi_extra=auth)
    async def latest(request: Request) -> JSONResponse:
        try:
            _authenticated(request)
            pack = await asyncio.to_thread(coordinator.content.latest_study_pack)
            if pack is None:
                return _plain_error("content_insight_unavailable", 404)
            return JSONResponse(pack.wire())
        except ContentUnderstandingError as exc:
            return _content_error(exc.code, operator=False)

    return router


def _authenticated(request: Request) -> AuthenticatedDevice:
    value = getattr(request.state, "authenticated_device", None)
    if not isinstance(value, AuthenticatedDevice):
        raise ContentUnderstandingError("content_auth_context_missing")
    return value


def _validate_request_text(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > MAX_ANALYSIS_REQUEST_CHARS
        or any(ord(char) < 32 and char not in {"\t", "\n", "\r"} for char in value)
    ):
        raise ValueError("content_request_invalid")
    normalized = " ".join(value.split())
    if not normalized or len(normalized) > MAX_ANALYSIS_REQUEST_CHARS:
        raise ValueError("content_request_invalid")
    return normalized


def _plain_error(code: str, status: int) -> JSONResponse:
    return JSONResponse(
        {"error_code": code, "message_key": code}, status_code=status
    )


def _content_error(code: str, *, operator: bool = True) -> JSONResponse:
    status = (
        409
        if code
        in {
            "content_scope_unconfigured",
            "content_opt_in_required",
            "content_no_supported_files",
            "content_snapshot_stale",
            "content_revision_changed",
            "content_document_encrypted",
            "content_document_external_reference",
            "content_document_embedded_object",
            "content_document_invalid",
            "content_document_limit_exceeded",
            "content_document_text_layer_missing",
            "autonomy_job_busy",
        }
        else 503
    )
    return _operator_error(code, status) if operator else _plain_error(code, status)
