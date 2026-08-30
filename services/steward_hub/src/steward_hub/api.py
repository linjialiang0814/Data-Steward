"""Loopback-only FastAPI adapter over the durable EventStore."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import sqlite3
from dataclasses import asdict
from collections.abc import AsyncIterator, Awaitable, Callable, Coroutine
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, Query, Request, Response, WebSocket
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.websockets import WebSocketDisconnect

from .authenticated_websocket import (
    AuthenticatedWebSocketContext,
    WebSocketAuthenticationTerminated,
    authenticate_websocket,
    cleanup_authenticated_websocket,
)
from .agent_planning import (
    AgentPlanningError,
    ReadOnlyIntentPlanner,
    ReadOnlyPlan,
    validate_readonly_plan_for_execution,
)
from .action_projection import ActionProjectionError, ActionProjectionService
from .android_ocr_api import create_android_ocr_router
from .android_ocr_store import AndroidOcrStore
from .artifact_export import KnowledgeArtifactCoordinator
from .artifact_export_api import (
    create_artifact_device_router,
    create_artifact_operator_router,
)
from .archive_memory import (
    ArchiveIntent,
    ArchiveMemoryError,
    ArchiveMemoryService,
    MEMORY_ACTIVATION_THRESHOLD,
    parse_archive_intent,
)
from .credential_transition import DeviceAuthorizationService, PairingOperatorService
from .credential_transition_api import (
    create_credential_transition_router,
    install_operator_openapi_scheme,
)
from .catalog_api import CatalogRateLimiter, create_catalog_router
from .cluster_organization import ClusterOrganizationService
from .cluster_organization_api import (
    create_cluster_organization_device_router,
    create_cluster_organization_operator_router,
)
from .catalog_operator_api import create_catalog_operator_router
from .catalog_store import CatalogStore
from .content_api import (
    ContentInsightCoordinator,
    create_content_device_router,
    create_content_operator_router,
)
from .device_auth import (
    AUTH_MODE_LOOPBACK_COMPAT,
    AUTH_MODE_REQUIRED,
    AUTHENTICATED_MESSAGE_ROLES,
    DEFAULT_DEVICE_AUTH_TIMEOUT_S,
    AuthenticatedDevice,
    DeviceAuthError,
    authenticate_device_digest,
    device_self_openapi_extra,
    device_auth_error_response,
    device_auth_openapi_extra,
    install_device_auth_openapi_scheme,
    parse_device_auth_headers,
    parse_device_identity_headers,
    refresh_device_authorization_digest,
    required_rest_capability,
    validate_auth_mode,
    validate_device_auth_timeout_s,
)
from .device_connection_registry import (
    DeviceConnectionAuthorizationChangedError,
    DeviceConnectionRegistry,
    DeviceConnectionRegistryCapacityError,
    DeviceConnectionRegistryClosedError,
    DeviceConnectionRegistryError,
    DeviceConnectionSendTimeout,
)
from .errors import (
    ConversationAlreadyExistsError,
    ConversationNotFoundError,
    IdempotencyConflictError,
    PersistenceError,
    ValidationError,
)
from .models import PROTOCOL_VERSION, ConversationEvent, ConversationMessage
from .pairing_api import (
    DEFAULT_PAIRING_TIMEOUT_S,
    attach_pairing_api,
    shutdown_pairing_store_executor,
    validate_request_timeout_s,
)
from .pairing_http_models import PairingErrorBody
from .pairing_rate_limit import PairingRateLimiter
from .pairing_store import PairingStore
from .pairing_codec import require_digest
from .pairing_store_executor import (
    DEFAULT_MAX_QUEUED,
    DEFAULT_MAX_WORKERS,
    PairingStoreExecutor,
)
from .content_understanding import ContentUnderstandingError, StudyPack
from .proactive_suggestion import ProactiveSuggestionService
from .proactive_suggestion_api import (
    create_suggestion_device_router,
    create_suggestion_operator_router,
)
from .pc_file_scope import (
    PcFileScopeError,
    PcFileScopeService,
    parse_pc_file_query_intent,
)
from .pc_file_scope_api import create_pc_file_scope_router
from .store import EventStore
from .subscriptions import (
    Subscription,
    SubscriptionManager,
    SubscriptionOverflowError,
    cancel_and_drain_tasks,
)
from .listen_policy import (
    TRANSPORT_SCOPE_LOOPBACK,
    TRANSPORT_SCOPE_PRIVATE_LAN_AUTHENTICATED,
    TRANSPORT_SCOPE_PRIVATE_LAN_PAIRING,
)
from .transport_models import (
    AppendMessageRequest,
    AppendMessageResponse,
    ConversationResponse,
    CreateConversationRequest,
    CursorAheadErrorResponse,
    DeviceSelfResponse,
    ErrorResponse,
    EventListResponse,
    HealthResponse,
    MemoryCenterResponse,
    ProductActionExecutionResponse,
    ProductActionListResponse,
    ProductActionResponse,
    WireEvent,
    WirePayload,
)
from .websocket_auth import (
    DEFAULT_AUTH_FRAME_TIMEOUT_S,
    validate_auth_frame_timeout_s,
)


def _archive_error_text(error: ArchiveMemoryError | PcFileScopeError) -> str:
    code = error.code
    if code == "file_scope_unconfigured":
        return "PC 尚未授权专用目录，请先在 Windows 端完成目录授权。"
    if code == "archive_memory_insufficient_evidence":
        return "该习惯尚未积累三次独立接受，暂不能批准。"
    if code == "archive_memory_not_active":
        return "当前授权目录没有已批准的整理习惯，请先生成并明确接受建议。"
    if code in {"archive_suggestion_not_found", "archive_memory_not_found"}:
        return "未找到对应的归档建议或习惯记忆，请核对脱敏标识。"
    if code in {"archive_suggestion_closed", "archive_memory_forgotten"}:
        return "该建议或习惯已经关闭，系统不会自动恢复或覆盖。"
    return "智能归档未完成：本次操作已安全停止，未改动任何文件。"


_MATERIAL_TARGET_TERMS = (
    "资料",
    "文件",
    "文档",
    "笔记",
    "课件",
    "照片",
    "图片",
    "课程",
    "复习",
    "会议",
    "项目",
    "学习",
    "工作",
    "今天",
    "今日",
)
_MATERIAL_ANALYSIS_TERMS = (
    "汇总",
    "总结",
    "分析",
    "理解",
    "提炼",
    "要点",
    "资料包",
    "简报",
    "回顾",
    "下一步",
    "看看",
    "看一下",
    "学了什么",
    "做了什么",
    "设计",
    "问题",
    "检查",
    "计划",
    "顺序",
    "说明",
)


def _looks_like_material_analysis_request(value: str) -> bool:
    text = value.casefold()
    return any(term in text for term in _MATERIAL_TARGET_TERMS) and any(
        term in text for term in _MATERIAL_ANALYSIS_TERMS
    )


def _study_pack_conversation_text(pack: StudyPack) -> str:
    source = "Hermes 受控分析" if pack.source == "hermes" else "本机安全摘要"
    topics = "、".join(pack.topics[:5])
    points = "\n".join(f"{index}. {item}" for index, item in enumerate(pack.review_points[:6], 1))
    sections = [pack.title, pack.summary]
    if topics:
        sections.append(f"主题：{topics}")
    if points:
        sections.append(f"建议下一步：\n{points}")
    sections.append(f"来源：{source}。仅使用已授权资料的安全投影，未修改任何文件。")
    return "\n\n".join(sections)


def _content_gateway_error_text(error: ContentUnderstandingError) -> str:
    if error.code == "content_no_supported_files":
        return "当前授权资料中没有可安全理解的内容。你可以先在“今日资料”中检查目录和内容理解开关。"
    if error.code in {
        "content_policy_disabled",
        "content_consent_required",
        "content_root_not_authorized",
    }:
        return "内容理解尚未授权。请先在“今日资料”中为当前目录开启内容理解；系统不会读取未授权正文。"
    return "本次资料理解已安全停止，没有修改文件，也不会自动重试。请检查资料状态后再试。"


class _UnifiedGatewayTaskManager:
    """Own detached agent replies without coupling them to HTTP acknowledgement."""

    def __init__(self, *, max_pending: int = 1, drain_timeout_s: float = 80.0) -> None:
        if max_pending != 1:
            raise ValueError("unified_gateway_single_flight_required")
        self._max_pending = max_pending
        self._drain_timeout_s = drain_timeout_s
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._accepting = True

    @property
    def pending_count(self) -> int:
        return len(self._tasks)

    def schedule(
        self,
        *,
        operation_key: str,
        operation: Coroutine[object, object, None],
    ) -> str:
        for key, completed in tuple(self._tasks.items()):
            if completed.done():
                self._consume(key, completed)
        if operation_key in self._tasks:
            operation.close()
            return "duplicate"
        if not self._accepting or len(self._tasks) >= self._max_pending:
            operation.close()
            return "rejected"
        task = asyncio.create_task(operation, name="unified-conversation-gateway")
        self._tasks[operation_key] = task
        task.add_done_callback(
            lambda completed, key=operation_key: self._consume(key, completed)
        )
        return "scheduled"

    def _consume(self, operation_key: str, task: asyncio.Task[None]) -> None:
        if self._tasks.get(operation_key) is task:
            self._tasks.pop(operation_key, None)
        if not task.cancelled():
            task.exception()

    async def stop_accepting_and_drain(self) -> None:
        self._accepting = False
        tasks = tuple(self._tasks.values())
        if not tasks:
            return
        _done, pending = await asyncio.wait(
            tasks,
            timeout=self._drain_timeout_s,
        )
        if pending:
            raise RuntimeError("unified_gateway_shutdown_timeout")


class CursorAheadError(Exception):
    def __init__(self, server_last_conversation_seq: int) -> None:
        self.server_last_conversation_seq = server_last_conversation_seq
        super().__init__("replay cursor exceeds server state")


class AuthorizationChangedError(Exception):
    """The registered device lease is no longer authorized."""


def _is_pairing_surface_route(route: object) -> bool:
    """Support direct and FastAPI 0.139 included-router representations."""
    path = str(getattr(route, "path", ""))
    if path.startswith("/v1/pairing/"):
        return True
    if path:
        return False
    original_router = getattr(route, "original_router", None)
    nested_routes = getattr(original_router, "routes", None)
    if not isinstance(nested_routes, list) or not nested_routes:
        return False
    return all(
        str(getattr(nested, "path", "")).startswith("/v1/pairing/")
        for nested in nested_routes
    )


def create_app(
    *,
    database_path: str | Path | None = None,
    event_store: EventStore | None = None,
    subscription_manager: SubscriptionManager | None = None,
    queue_size: int = 128,
    pairing_store: PairingStore | None = None,
    close_pairing_store: bool = False,
    pairing_rate_limiter: PairingRateLimiter | None = None,
    pairing_request_timeout_s: float = DEFAULT_PAIRING_TIMEOUT_S,
    pairing_source_key_fn: Callable[[Request], str] | None = None,
    pairing_store_max_workers: int = DEFAULT_MAX_WORKERS,
    pairing_store_max_queued: int = DEFAULT_MAX_QUEUED,
    pairing_store_executor: PairingStoreExecutor | None = None,
    business_auth_mode: str = AUTH_MODE_LOOPBACK_COMPAT,
    device_auth_timeout_s: float = DEFAULT_DEVICE_AUTH_TIMEOUT_S,
    device_connection_registry: DeviceConnectionRegistry | None = None,
    websocket_auth_timeout_s: float = DEFAULT_AUTH_FRAME_TIMEOUT_S,
    operator_token_digest: str | None = None,
    pc_file_scope_service: PcFileScopeService | None = None,
    read_only_intent_planner: ReadOnlyIntentPlanner | None = None,
    archive_memory_service: ArchiveMemoryService | None = None,
    action_projection_service: ActionProjectionService | None = None,
    catalog_store: CatalogStore | None = None,
    close_catalog_store: bool = False,
    catalog_rate_limiter: CatalogRateLimiter | None = None,
    cluster_organization_service: ClusterOrganizationService | None = None,
    content_insight_coordinator: ContentInsightCoordinator | None = None,
    knowledge_artifact_coordinator: KnowledgeArtifactCoordinator | None = None,
    proactive_suggestion_service: ProactiveSuggestionService | None = None,
    android_ocr_store: AndroidOcrStore | None = None,
    close_android_ocr_store: bool = False,
    business_routes_enabled: bool = True,
    pairing_routes_enabled: bool = True,
    transport_scope: str = TRANSPORT_SCOPE_LOOPBACK,
) -> FastAPI:
    if (database_path is None) == (event_store is None):
        raise ValueError("provide exactly one event store source")
    if not isinstance(business_routes_enabled, bool):
        raise ValueError("business_routes_enabled is invalid")
    if not isinstance(pairing_routes_enabled, bool):
        raise ValueError("pairing_routes_enabled is invalid")
    if not isinstance(close_catalog_store, bool):
        raise ValueError("close_catalog_store is invalid")
    if not isinstance(close_android_ocr_store, bool):
        raise ValueError("close_android_ocr_store is invalid")
    if (
        catalog_store is not None
        and business_auth_mode != AUTH_MODE_REQUIRED
        and (operator_token_digest is None or pc_file_scope_service is None)
    ):
        raise ValueError("loopback catalog requires operator file scope")
    if pairing_store is None and not pairing_routes_enabled:
        raise ValueError("pairing route policy requires pairing_store")
    allowed_transport_scopes = {
        TRANSPORT_SCOPE_LOOPBACK,
        TRANSPORT_SCOPE_PRIVATE_LAN_PAIRING,
        TRANSPORT_SCOPE_PRIVATE_LAN_AUTHENTICATED,
    }
    if transport_scope not in allowed_transport_scopes:
        raise ValueError("transport_scope is invalid")
    if transport_scope != TRANSPORT_SCOPE_LOOPBACK and operator_token_digest is not None:
        raise ValueError("operator routes are loopback-only")
    if transport_scope == TRANSPORT_SCOPE_PRIVATE_LAN_PAIRING:
        if business_routes_enabled or pairing_store is None:
            raise ValueError("pairing-only surface is invalid")
    if transport_scope == TRANSPORT_SCOPE_PRIVATE_LAN_AUTHENTICATED:
        if not business_routes_enabled or business_auth_mode != AUTH_MODE_REQUIRED:
            raise ValueError("authenticated LAN surface is invalid")
    if pairing_store is not None:
        pairing_request_timeout_s = validate_request_timeout_s(
            pairing_request_timeout_s
        )
    business_auth_mode = validate_auth_mode(business_auth_mode)
    device_auth_timeout_s = validate_device_auth_timeout_s(
        device_auth_timeout_s
    )
    websocket_auth_timeout_s = validate_auth_frame_timeout_s(
        websocket_auth_timeout_s
    )
    if business_auth_mode == AUTH_MODE_REQUIRED and pairing_store is None:
        raise ValueError("authenticated_service requires pairing_store")
    if operator_token_digest is not None:
        operator_token_digest = require_digest(
            "operator_token_digest",
            operator_token_digest,
        )
        if pairing_store is None or transport_scope != TRANSPORT_SCOPE_LOOPBACK:
            raise ValueError("operator transitions require loopback pairing store")
    if device_connection_registry is not None and not isinstance(
        device_connection_registry,
        DeviceConnectionRegistry,
    ):
        raise ValueError("device_connection_registry is invalid")
    if operator_token_digest is not None and device_connection_registry is None:
        # Fail before attach_pairing_api creates non-daemon store workers.
        raise ValueError("operator transitions require registry")
    if business_auth_mode == AUTH_MODE_LOOPBACK_COMPAT and (
        device_connection_registry is not None and operator_token_digest is None
    ):
        raise ValueError("loopback registry requires operator transitions")
    registry = device_connection_registry
    if registry is None and business_auth_mode == AUTH_MODE_REQUIRED:
        registry = DeviceConnectionRegistry()
    owns_store = event_store is None
    store = event_store or EventStore(database_path)  # type: ignore[arg-type]
    subscriptions = subscription_manager or SubscriptionManager(
        queue_size=queue_size
    )

    @asynccontextmanager
    async def lifespan(app_ref: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            shutdown_errors: list[BaseException] = []
            gateway_ok = True
            gateway_tasks = getattr(
                app_ref.state,
                "unified_gateway_tasks",
                None,
            )
            if gateway_tasks is not None:
                try:
                    await gateway_tasks.stop_accepting_and_drain()
                except BaseException as exc:  # noqa: BLE001
                    gateway_ok = False
                    shutdown_errors.append(exc)
            connection_registry = getattr(
                app_ref.state,
                "device_connection_registry",
                None,
            )
            if connection_registry is not None:
                try:
                    await connection_registry.stop_accepting_and_close_all()
                except BaseException as exc:  # noqa: BLE001
                    shutdown_errors.append(exc)
            # Stop store workers before closing any SQLite handles.
            # Incomplete executor shutdown must not close PairingStore.
            executor_ok = True
            try:
                await shutdown_pairing_store_executor(app_ref)
            except BaseException as exc:  # noqa: BLE001
                executor_ok = False
                shutdown_errors.append(exc)
            if executor_ok and gateway_ok:
                if getattr(app_ref.state, "close_pairing_store", False):
                    pairing = getattr(app_ref.state, "pairing_store", None)
                    if pairing is not None:
                        try:
                            pairing.close()
                        except BaseException as exc:  # noqa: BLE001
                            shutdown_errors.append(exc)
                if owns_store:
                    try:
                        store.close()
                    except BaseException as exc:  # noqa: BLE001
                        shutdown_errors.append(exc)
                if getattr(app_ref.state, "close_catalog_store", False):
                    catalog = getattr(app_ref.state, "catalog_store", None)
                    if catalog is not None:
                        try:
                            catalog.close()
                        except BaseException as exc:  # noqa: BLE001
                            shutdown_errors.append(exc)
                if getattr(app_ref.state, "close_android_ocr_store", False):
                    ocr_store = getattr(app_ref.state, "android_ocr_store", None)
                    if ocr_store is not None:
                        try:
                            ocr_store.close()
                        except BaseException as exc:  # noqa: BLE001
                            shutdown_errors.append(exc)
            if shutdown_errors:
                raise shutdown_errors[0]

    app = FastAPI(
        title="Data Steward Local Hub",
        version="1",
        lifespan=lifespan,
    )
    app.state.event_store = store
    app.state.subscriptions = subscriptions
    app.state.business_auth_mode = business_auth_mode
    app.state.device_auth_timeout_s = device_auth_timeout_s
    app.state.websocket_auth_timeout_s = websocket_auth_timeout_s
    app.state.device_connection_registry = registry
    app.state.business_routes_enabled = business_routes_enabled
    app.state.transport_scope = transport_scope
    app.state.pc_file_scope_service = pc_file_scope_service
    app.state.read_only_intent_planner = read_only_intent_planner
    app.state.archive_memory_service = archive_memory_service
    app.state.action_projection_service = action_projection_service
    app.state.catalog_store = catalog_store
    app.state.cluster_organization_service = cluster_organization_service
    app.state.content_insight_coordinator = content_insight_coordinator
    # The configured Hermes planner is intentionally single-flight. Serialize
    # conversation insight generation so a concurrent idempotent retry cannot
    # race into a second Provider call or persist a lower-quality busy fallback.
    app.state.unified_gateway_lock = asyncio.Lock()
    app.state.unified_gateway_tasks = _UnifiedGatewayTaskManager()
    app.state.knowledge_artifact_coordinator = knowledge_artifact_coordinator
    app.state.proactive_suggestion_service = proactive_suggestion_service
    app.state.android_ocr_store = android_ocr_store
    app.state.close_android_ocr_store = close_android_ocr_store
    app.state.close_catalog_store = close_catalog_store
    business_auth_openapi = device_auth_openapi_extra(business_auth_mode)
    business_auth_responses = (
        {
            401: {"model": PairingErrorBody},
            403: {"model": PairingErrorBody},
            503: {"model": PairingErrorBody},
        }
        if business_auth_mode == AUTH_MODE_REQUIRED
        else {}
    )
    validation_error_model = (
        ErrorResponse | PairingErrorBody
        if business_auth_mode == AUTH_MODE_REQUIRED
        else ErrorResponse
    )
    conflict_error_model = validation_error_model
    cursor_conflict_error_model = (
        CursorAheadErrorResponse | PairingErrorBody
        if business_auth_mode == AUTH_MODE_REQUIRED
        else CursorAheadErrorResponse
    )

    if pairing_store is not None:
        attach_pairing_api(
            app,
            pairing_store=pairing_store,
            rate_limiter=pairing_rate_limiter,
            request_timeout_s=pairing_request_timeout_s,
            source_key_fn=pairing_source_key_fn,
            close_pairing_store=close_pairing_store,
            store_max_workers=pairing_store_max_workers,
            store_max_queued=pairing_store_max_queued,
            store_executor=pairing_store_executor,
        )
        if not pairing_routes_enabled:
            app.router.routes = [
                route
                for route in app.router.routes
                if not _is_pairing_surface_route(route)
            ]
            if any(_is_pairing_surface_route(route) for route in app.router.routes):
                raise RuntimeError("pairing_route_removal_failed")
        if operator_token_digest is not None:
            if registry is None:
                raise ValueError("operator transitions require registry")
            authorization_service = DeviceAuthorizationService(
                pairing_store=pairing_store,
                store_executor=app.state.pairing_store_executor,
                registry=registry,
            )
            app.state.device_authorization_service = authorization_service
            pairing_operator_service = PairingOperatorService(
                pairing_store=pairing_store,
                store_executor=app.state.pairing_store_executor,
            )
            app.state.pairing_operator_service = pairing_operator_service
            app.include_router(
                create_credential_transition_router(
                    service=authorization_service,
                    pairing_service=pairing_operator_service,
                    operator_token_digest=operator_token_digest,
                )
            )
            if pc_file_scope_service is not None:
                app.include_router(
                    create_pc_file_scope_router(
                        service=pc_file_scope_service,
                        operator_token_digest=operator_token_digest,
                        before_authorize=(
                            content_insight_coordinator.content.forget_current_root_if_configured
                            if content_insight_coordinator is not None
                            else None
                        ),
                        before_revoke=(
                            content_insight_coordinator.content.forget_current_root
                            if content_insight_coordinator is not None
                            else None
                        ),
                    )
                )
                if catalog_store is not None:
                    identity = pairing_store.get_hub_identity()
                    app.include_router(
                        create_catalog_operator_router(
                            store=catalog_store,
                            file_scope=pc_file_scope_service,
                            windows_device_id=identity.hub_id,
                            operator_token_digest=operator_token_digest,
                            store_executor=app.state.pairing_store_executor,
                        )
                    )
                    if cluster_organization_service is not None:
                        app.include_router(
                            create_cluster_organization_operator_router(
                                service=cluster_organization_service,
                                operator_token_digest=operator_token_digest,
                            )
                        )
                if content_insight_coordinator is not None:
                    app.include_router(
                        create_content_operator_router(
                            coordinator=content_insight_coordinator,
                            operator_token_digest=operator_token_digest,
                        )
                    )
                if knowledge_artifact_coordinator is not None:
                    app.include_router(
                        create_artifact_operator_router(
                            coordinator=knowledge_artifact_coordinator,
                            operator_token_digest=operator_token_digest,
                        )
                    )
                if proactive_suggestion_service is not None:
                    app.include_router(
                        create_suggestion_operator_router(
                            service=proactive_suggestion_service,
                            operator_token_digest=operator_token_digest,
                        )
                    )
            install_operator_openapi_scheme(app)

    if catalog_store is not None and business_auth_mode == AUTH_MODE_REQUIRED:
        app.include_router(
            create_catalog_router(
                store=catalog_store,
                store_executor=app.state.pairing_store_executor,
                rate_limiter=catalog_rate_limiter,
            )
        )
        if cluster_organization_service is not None:
            app.include_router(
                create_cluster_organization_device_router(
                    cluster_organization_service
                )
            )
    if (
        content_insight_coordinator is not None
        and business_auth_mode == AUTH_MODE_REQUIRED
    ):
        app.include_router(
            create_content_device_router(coordinator=content_insight_coordinator)
        )
    if android_ocr_store is not None and business_auth_mode == AUTH_MODE_REQUIRED:
        app.include_router(
            create_android_ocr_router(
                store=android_ocr_store,
                executor=app.state.pairing_store_executor,
            )
        )
    if (
        knowledge_artifact_coordinator is not None
        and business_auth_mode == AUTH_MODE_REQUIRED
    ):
        app.include_router(
            create_artifact_device_router(coordinator=knowledge_artifact_coordinator)
        )
    if (
        proactive_suggestion_service is not None
        and business_auth_mode == AUTH_MODE_REQUIRED
    ):
        app.include_router(
            create_suggestion_device_router(service=proactive_suggestion_service)
        )

    @app.middleware("http")
    async def device_auth_gate(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        required_capability = required_rest_capability(request.url.path)
        if (
            app.state.business_auth_mode == AUTH_MODE_REQUIRED
            and required_capability is not None
        ):
            operation_lease = None
            try:
                device_id, credential_digest, capability_epoch = (
                    parse_device_auth_headers(request.scope)
                )

                async def verifier() -> AuthenticatedDevice:
                    return await authenticate_device_digest(
                        pairing_store=app.state.pairing_store,
                        store_executor=app.state.pairing_store_executor,
                        device_id=device_id,
                        credential_digest=credential_digest,
                        capability_epoch=capability_epoch,
                        required_capability=required_capability,
                        timeout_s=app.state.device_auth_timeout_s,
                    )

                authenticated, operation_lease = await (
                    app.state.device_connection_registry
                    .authenticate_and_acquire_operation(
                        device_id=device_id,
                        verifier=verifier,
                    )
                )
            except DeviceAuthError as error:
                return device_auth_error_response(error)
            except (
                DeviceConnectionRegistryCapacityError,
                DeviceConnectionRegistryClosedError,
                DeviceConnectionRegistryError,
            ):
                return device_auth_error_response(
                    DeviceAuthError("auth_unavailable", 503)
                )
            request.state.authenticated_device = authenticated
            try:
                operation_task = asyncio.create_task(call_next(request))
                try:
                    return await asyncio.shield(operation_task)
                except asyncio.CancelledError:
                    # Business handlers use thread-backed SQLite. Do not let
                    # request cancellation release the authorization lease
                    # while an accepted write may still finish later.
                    await _drain_operation_after_cancellation(operation_task)
                    raise
            finally:
                await operation_lease.release()
        return await call_next(request)

    _install_error_handlers(app)

    @app.exception_handler(DeviceAuthError)
    async def device_auth_error_handler(
        _request: Request,
        error: DeviceAuthError,
    ) -> JSONResponse:
        return device_auth_error_response(error)

    @app.exception_handler(ActionProjectionError)
    async def action_projection_error_handler(
        _request: Request,
        error: ActionProjectionError,
    ) -> JSONResponse:
        status = 404 if error.code == "action_not_found" else 409
        if error.code in {"action_persistence_failed", "action_service_closed"}:
            status = 503
        return JSONResponse(
            status_code=status,
            content={
                "error": {
                    "code": error.code,
                    "message": "The requested action is unavailable.",
                }
            },
        )

    @app.get(
        "/health",
        response_model=HealthResponse,
        tags=["system"],
    )
    async def health() -> HealthResponse:
        await asyncio.to_thread(store.database_settings)
        return HealthResponse(
            status="ok",
            protocol_version=PROTOCOL_VERSION,
            database_ready=True,
            transport_scope=app.state.transport_scope,
        )

    if business_auth_mode == AUTH_MODE_REQUIRED:

        @app.get(
            "/v1/device/self",
            response_model=DeviceSelfResponse,
            responses={
                400: {"model": PairingErrorBody},
                401: {"model": PairingErrorBody},
                503: {"model": PairingErrorBody},
            },
            tags=["device"],
            openapi_extra=device_self_openapi_extra(),
        )
        async def device_self(request: Request) -> DeviceSelfResponse:
            device_id, credential_digest = parse_device_identity_headers(
                request.scope
            )
            authenticated = await refresh_device_authorization_digest(
                pairing_store=app.state.pairing_store,
                store_executor=app.state.pairing_store_executor,
                device_id=device_id,
                credential_digest=credential_digest,
                timeout_s=app.state.device_auth_timeout_s,
            )
            return DeviceSelfResponse(
                protocol_version="pairing_auth/1",
                hub_id=authenticated.hub_id,
                device_id=authenticated.device_id,
                status="ACTIVE",
                capability_epoch=authenticated.capability_epoch,
                granted_capabilities=list(authenticated.granted_capabilities),
                display_name=authenticated.display_name,
                platform=authenticated.platform,
            )

    @app.post(
        "/v1/conversations",
        response_model=ConversationResponse,
        status_code=201,
        responses={
            400: {"model": validation_error_model},
            409: {"model": conflict_error_model},
            **business_auth_responses,
        },
        tags=["conversations"],
        openapi_extra=business_auth_openapi,
    )
    async def create_conversation(
        request: CreateConversationRequest,
    ) -> ConversationResponse:
        conversation = await asyncio.to_thread(
            store.create_conversation,
            request.title,
            conversation_id=request.conversation_id,
        )
        return ConversationResponse(
            conversation_id=conversation.conversation_id,
            title=conversation.title,
            next_seq=conversation.next_seq,
            created_at=conversation.created_at,
            updated_at=conversation.updated_at,
        )

    if (
        action_projection_service is not None
        and archive_memory_service is not None
        and pc_file_scope_service is not None
    ):

        @app.get(
            "/v1/conversations/{conversation_id}/memory",
            response_model=MemoryCenterResponse,
            tags=["memory"],
            openapi_extra=business_auth_openapi,
        )
        async def memory_center(conversation_id: str) -> MemoryCenterResponse:
            try:
                view = await asyncio.to_thread(archive_memory_service.status)
            except ArchiveMemoryError:
                raise ActionProjectionError("action_persistence_failed") from None
            _, actions = await asyncio.to_thread(
                action_projection_service.register_memory_view,
                conversation_id=conversation_id,
                view=view,
            )
            return MemoryCenterResponse(
                status=view.status,
                support_count=view.support_count,
                activation_threshold=MEMORY_ACTIVATION_THRESHOLD,
                version=view.version,
                actions=[ProductActionResponse(**asdict(action)) for action in actions],
            )

        @app.get(
            "/v1/conversations/{conversation_id}/messages/{assistant_message_id}/actions",
            response_model=ProductActionListResponse,
            tags=["actions"],
            openapi_extra=business_auth_openapi,
        )
        async def list_product_actions(
            conversation_id: str,
            assistant_message_id: str,
            http_request: Request,
        ) -> ProductActionListResponse:
            actions = await asyncio.to_thread(
                action_projection_service.list_for_message,
                conversation_id=conversation_id,
                assistant_message_id=assistant_message_id,
            )
            authenticated = getattr(http_request.state, "authenticated_device", None)
            if isinstance(authenticated, AuthenticatedDevice):
                actions = tuple(
                    action
                    for action in actions
                    if action.required_capability in authenticated.granted_capabilities
                )
            return ProductActionListResponse(
                actions=[ProductActionResponse(**asdict(action)) for action in actions]
            )

        @app.post(
            "/v1/conversations/{conversation_id}/messages/{assistant_message_id}/actions/{action_id}",
            response_model=ProductActionExecutionResponse,
            tags=["actions"],
            openapi_extra=business_auth_openapi,
        )
        async def execute_product_action(
            conversation_id: str,
            assistant_message_id: str,
            action_id: str,
            http_request: Request,
        ) -> ProductActionExecutionResponse:
            available = await asyncio.to_thread(
                action_projection_service.list_for_message,
                conversation_id=conversation_id,
                assistant_message_id=assistant_message_id,
            )
            selected = next((item for item in available if item.action_id == action_id), None)
            if selected is None:
                raise ActionProjectionError("action_not_found")
            authenticated = getattr(http_request.state, "authenticated_device", None)
            if (
                isinstance(authenticated, AuthenticatedDevice)
                and selected.required_capability not in authenticated.granted_capabilities
            ):
                raise DeviceAuthError("capability_denied", 403)
            result_client_message_id = "action-result-" + hashlib.sha256(
                f"{conversation_id}\n{action_id}".encode("utf-8")
            ).hexdigest()
            if selected.status == "completed":
                existing = await asyncio.to_thread(
                    store.get_message_by_client_id,
                    conversation_id=conversation_id,
                    client_message_id=result_client_message_id,
                )
                if existing is None:
                    raise ActionProjectionError("action_unavailable")
                result = await asyncio.to_thread(
                    store.append_message,
                    conversation_id=conversation_id,
                    client_message_id=result_client_message_id,
                    actor_device_id="data-steward-action",
                    role="assistant",
                    content=existing.content,
                    causation_id=assistant_message_id,
                    correlation_id=action_id,
                )
                actions = await asyncio.to_thread(
                    action_projection_service.list_for_message,
                    conversation_id=conversation_id,
                    assistant_message_id=result.message.message_id,
                )
                return ProductActionExecutionResponse(
                    status="completed",
                    event=wire_event(result.event),
                    actions=[ProductActionResponse(**asdict(action)) for action in actions],
                )
            source_ref = "action-" + hashlib.sha256(
                f"{conversation_id}\n{assistant_message_id}\n{action_id}".encode("utf-8")
            ).hexdigest()
            try:
                receipt = await asyncio.to_thread(
                    action_projection_service.execute_action,
                    conversation_id=conversation_id,
                    assistant_message_id=assistant_message_id,
                    action_id=action_id,
                    archive_memory=archive_memory_service,
                    file_scope=pc_file_scope_service,
                    source_message_ref=source_ref,
                )
            except (ArchiveMemoryError, PcFileScopeError):
                raise ActionProjectionError("action_unavailable") from None
            result = await asyncio.to_thread(
                store.append_message,
                conversation_id=conversation_id,
                client_message_id=result_client_message_id,
                actor_device_id="data-steward-action",
                role="assistant",
                content=receipt.conversation_text(),
                causation_id=assistant_message_id,
                correlation_id=action_id,
            )
            await asyncio.to_thread(
                action_projection_service.mark_completed,
                action_id,
            )
            actions = await asyncio.to_thread(
                action_projection_service.register_receipt,
                conversation_id=conversation_id,
                assistant_message_id=result.message.message_id,
                receipt=receipt,
            )
            if not result.deduplicated:
                await subscriptions.publish(result.event)
            return ProductActionExecutionResponse(
                status="completed",
                event=wire_event(result.event),
                actions=[ProductActionResponse(**asdict(action)) for action in actions],
            )

    @app.post(
        "/v1/conversations/{conversation_id}/messages",
        response_model=AppendMessageResponse,
        status_code=201,
        responses={
            400: {"model": validation_error_model},
            404: {"model": ErrorResponse},
            409: {"model": conflict_error_model},
            **business_auth_responses,
        },
        tags=["messages"],
        openapi_extra=business_auth_openapi,
    )
    async def append_message(
        conversation_id: str,
        request: AppendMessageRequest,
        response: Response,
        http_request: Request,
        background_tasks: BackgroundTasks,
    ) -> AppendMessageResponse:
        file_intent = None
        file_plan: ReadOnlyPlan | None = None
        archive_plan: ReadOnlyPlan | None = None
        material_analysis_requested = False
        archive_intent = (
            parse_archive_intent(request.content) if request.role == "user" else None
        )
        if app.state.archive_memory_service is None:
            archive_intent = None
        authenticated = None
        if app.state.business_auth_mode == AUTH_MODE_REQUIRED:
            authenticated = getattr(
                http_request.state,
                "authenticated_device",
                None,
            )
            if (
                not isinstance(authenticated, AuthenticatedDevice)
                or request.actor_device_id != authenticated.device_id
                or request.role not in AUTHENTICATED_MESSAGE_ROLES
            ):
                raise DeviceAuthError("policy_violation", 400)
        has_files_read = (
            authenticated is None
            or "files.read" in authenticated.granted_capabilities
        )
        if app.state.content_insight_coordinator is not None and request.role == "user":
            material_analysis_requested = _looks_like_material_analysis_request(
                request.content
            )
            if material_analysis_requested and (
                authenticated is not None
                and "content.analyze" not in authenticated.granted_capabilities
            ):
                raise DeviceAuthError("capability_denied", 403)
        if archive_intent is not None and not has_files_read:
            raise DeviceAuthError("capability_denied", 403)
        if (
            request.role == "user"
            and app.state.pc_file_scope_service is not None
            and archive_intent is None
        ):
            file_intent = parse_pc_file_query_intent(request.content)
            if file_intent is not None and not has_files_read:
                raise DeviceAuthError("capability_denied", 403)
        result = await asyncio.to_thread(
            store.append_message,
            conversation_id=conversation_id,
            client_message_id=request.client_message_id,
            actor_device_id=request.actor_device_id,
            role=request.role,
            content=request.content,
            causation_id=request.causation_id,
            correlation_id=request.correlation_id,
        )
        if result.deduplicated:
            response.status_code = 200
        else:
            await subscriptions.publish(result.event)
        derived_result_client_message_id = "gateway-result-" + hashlib.sha256(
            (
                f"{conversation_id}\n{request.client_message_id}\n"
                "unified-conversation-gateway-v2"
            ).encode("utf-8")
        ).hexdigest()
        allowed_derived_actors = {
            "data-steward-agent",
            "data-steward-memory",
            "windows-pc-executor",
        }

        async def existing_derived_result():
            existing = await asyncio.to_thread(
                store.get_message_by_client_id,
                conversation_id=conversation_id,
                client_message_id=derived_result_client_message_id,
            )
            if existing is not None and (
                existing.role != "assistant"
                or existing.actor_device_id not in allowed_derived_actors
            ):
                raise IdempotencyConflictError(
                    "unified gateway result id conflicts with persisted input"
                )
            return existing

        async def append_derived_result(
            *,
            actor_device_id: str,
            content: str,
            publish: bool = True,
            transaction_hook: Callable[
                [sqlite3.Connection, ConversationMessage], None
            ]
            | None = None,
        ):
            existing = await existing_derived_result()
            if existing is not None:
                return existing, False, None
            try:
                appended = await asyncio.to_thread(
                    store.append_message,
                    conversation_id=conversation_id,
                    client_message_id=derived_result_client_message_id,
                    actor_device_id=actor_device_id,
                    role="assistant",
                    content=content,
                    causation_id=result.message.message_id,
                    correlation_id=(
                        request.correlation_id or request.client_message_id
                    ),
                    transaction_hook=transaction_hook,
                )
            except IdempotencyConflictError:
                concurrent = await existing_derived_result()
                if concurrent is None:
                    raise
                return concurrent, False, None
            event = None if appended.deduplicated else appended.event
            if publish and event is not None:
                await subscriptions.publish(appended.event)
            return appended.message, not appended.deduplicated, event

        async def process_derived_result() -> None:
            async with app.state.unified_gateway_lock:
                if await existing_derived_result() is not None:
                    return
                resolved_file_intent = file_intent
                resolved_file_plan = file_plan
                resolved_archive_intent = archive_intent
                resolved_archive_plan = archive_plan
                planner = app.state.read_only_intent_planner
                if (
                    resolved_file_intent is None
                    and resolved_archive_intent is None
                    and not material_analysis_requested
                    and planner is not None
                    and has_files_read
                    and app.state.pc_file_scope_service is not None
                ):
                    scope_view = await asyncio.to_thread(
                        app.state.pc_file_scope_service.status
                    )
                    try:
                        proposed = await asyncio.to_thread(
                            planner.plan,
                            user_text=request.content,
                            scope=scope_view,
                        )
                    except AgentPlanningError:
                        proposed = None
                    if proposed is not None:
                        try:
                            validated = validate_readonly_plan_for_execution(
                                plan=proposed,
                                user_text=request.content,
                                scope=scope_view,
                            )
                        except AgentPlanningError:
                            validated = None
                        if validated is not None:
                            archive_operation = validated.archive_operation()
                            if (
                                archive_operation is not None
                                and app.state.archive_memory_service is not None
                            ):
                                resolved_archive_plan = validated
                                resolved_archive_intent = ArchiveIntent(
                                    archive_operation
                                )
                            else:
                                resolved_file_plan = validated
                                resolved_file_intent = validated.to_executor_intent()

                if resolved_file_intent is not None:
                    try:
                        receipt = await asyncio.to_thread(
                            app.state.pc_file_scope_service.execute,
                            resolved_file_intent,
                        )
                        content = (
                            resolved_file_plan.conversation_prefix()
                            if resolved_file_plan
                            else ""
                        ) + receipt.conversation_text()
                    except PcFileScopeError as error:
                        content = (
                            "PC 尚未授权查询目录，请先在 Windows 端选择专用目录。"
                            if error.code == "file_scope_unconfigured"
                            else "PC 文件查询未完成：授权目录当前不可用或条目超出安全上限。"
                        )
                    await append_derived_result(
                        actor_device_id="windows-pc-executor",
                        content=content,
                    )
                    return

                if resolved_archive_intent is not None:
                    archive_receipt = None
                    try:
                        archive_receipt = await asyncio.to_thread(
                            app.state.archive_memory_service.execute,
                            resolved_archive_intent,
                            source_message_ref="msg-"
                            + hashlib.sha256(
                                (
                                    f"{conversation_id}\n{request.client_message_id}"
                                ).encode("utf-8")
                            ).hexdigest(),
                        )
                        content = (
                            resolved_archive_plan.conversation_prefix()
                            if resolved_archive_plan
                            else ""
                        ) + archive_receipt.conversation_text()
                    except (ArchiveMemoryError, PcFileScopeError) as error:
                        content = _archive_error_text(error)
                    projection_service = app.state.action_projection_service
                    prepared_projection = (
                        projection_service.prepare_receipt_projection(archive_receipt)
                        if archive_receipt is not None
                        and projection_service is not None
                        else None
                    )

                    def register_projection(
                        connection: sqlite3.Connection,
                        message: ConversationMessage,
                    ) -> None:
                        if prepared_projection is None or projection_service is None:
                            return
                        projection_service.register_prepared_in_transaction(
                            connection,
                            conversation_id=conversation_id,
                            assistant_message_id=message.message_id,
                            projection=prepared_projection,
                        )

                    _message, _created, archive_event = await append_derived_result(
                        actor_device_id="data-steward-memory",
                        content=content,
                        publish=False,
                        transaction_hook=register_projection,
                    )
                    if archive_event is not None:
                        await subscriptions.publish(archive_event)
                    return

                if material_analysis_requested:
                    try:
                        pack = await asyncio.to_thread(
                            app.state.content_insight_coordinator.generate,
                            request.content,
                        )
                        content = _study_pack_conversation_text(pack)
                    except ContentUnderstandingError as error:
                        content = _content_gateway_error_text(error)
                else:
                    content = (
                        "我可以帮你汇总跨设备资料、查询电脑文件、生成整理建议，"
                        "或准备带来源的资料包。涉及移动和导出时，我会先展示预览并等待你确认。"
                    )
                await append_derived_result(
                    actor_device_id="data-steward-agent",
                    content=content,
                )

        async def safely_process_derived_result() -> None:
            try:
                await process_derived_result()
            except Exception:  # noqa: BLE001
                try:
                    await append_derived_result(
                        actor_device_id="data-steward-agent",
                        content=(
                            "本次智能处理已安全停止，用户消息已保留；"
                            "没有修改文件，也不会自动重试。"
                        ),
                    )
                except Exception:  # noqa: BLE001
                    return

        needs_derived_result = request.role == "user" and (
            file_intent is not None
            or archive_intent is not None
            or material_analysis_requested
            or (
                app.state.read_only_intent_planner is not None
                and has_files_read
                and app.state.pc_file_scope_service is not None
            )
            or app.state.content_insight_coordinator is not None
        )
        async def schedule_derived_result_after_response() -> None:
            if await existing_derived_result() is not None:
                return
            operation_key = f"{conversation_id}:{request.client_message_id}"
            scheduled = app.state.unified_gateway_tasks.schedule(
                operation_key=operation_key,
                operation=safely_process_derived_result(),
            )
            if scheduled == "rejected":
                await append_derived_result(
                    actor_device_id="data-steward-agent",
                    content=(
                        "当前已有一项智能任务正在处理。本条消息已安全确认，"
                        "但本次派生任务未执行；请等待当前结果后再发起，系统不会自动重试。"
                    ),
                )

        if needs_derived_result:
            # Starlette executes this callback only after the response body has
            # been sent. Derived planning and execution therefore cannot delay
            # or race ahead of the durable user-message acknowledgement.
            background_tasks.add_task(schedule_derived_result_after_response)
        return AppendMessageResponse(
            message_id=result.message.message_id,
            deduplicated=result.deduplicated,
            event=wire_event(result.event),
        )

    @app.get(
        "/v1/conversations/{conversation_id}/events",
        response_model=EventListResponse,
        responses={
            400: {"model": validation_error_model},
            404: {"model": ErrorResponse},
            409: {"model": cursor_conflict_error_model},
            **business_auth_responses,
        },
        tags=["events"],
        openapi_extra=business_auth_openapi,
    )
    async def replay_events(
        conversation_id: str,
        after_seq: int = Query(default=0, ge=0),
        limit: int = Query(default=100, ge=1, le=500),
    ) -> EventListResponse:
        conversation = await asyncio.to_thread(
            store.get_conversation,
            conversation_id,
        )
        server_last_conversation_seq = conversation.next_seq - 1
        if after_seq > server_last_conversation_seq:
            raise CursorAheadError(server_last_conversation_seq)
        events = await asyncio.to_thread(
            store.replay_events,
            conversation_id=conversation_id,
            after_seq=after_seq,
            limit=limit,
        )
        return EventListResponse(
            events=[wire_event(event) for event in events],
            last_conversation_seq=(
                events[-1].conversation_seq
                if events
                else server_last_conversation_seq
            ),
        )

    @app.websocket("/v1/conversations/{conversation_id}/events/ws")
    async def conversation_events(
        websocket: WebSocket,
        conversation_id: str,
        after_seq: int = Query(default=0),
    ) -> None:
        if app.state.business_auth_mode == AUTH_MODE_REQUIRED:
            context: AuthenticatedWebSocketContext | None = None
            try:
                context = await authenticate_websocket(
                    websocket,
                    after_seq=after_seq,
                    pairing_store=app.state.pairing_store,
                    store_executor=app.state.pairing_store_executor,
                    registry=app.state.device_connection_registry,
                    auth_timeout_s=app.state.websocket_auth_timeout_s,
                )
                await _serve_conversation_events(
                    websocket,
                    store=store,
                    subscriptions=subscriptions,
                    conversation_id=conversation_id,
                    after_seq=after_seq,
                    transport_accepted=True,
                    authorization_changed_task=(
                        context.authorization_changed_task
                    ),
                    authorized_send_json=lambda payload: context.send_json(
                        websocket,
                        payload,
                    ),
                )
            except WebSocketAuthenticationTerminated:
                return
            except asyncio.CancelledError:
                return
            finally:
                if context is not None:
                    await cleanup_authenticated_websocket(context)
            return
        await _serve_conversation_events(
            websocket,
            store=store,
            subscriptions=subscriptions,
            conversation_id=conversation_id,
            after_seq=after_seq,
            transport_accepted=False,
        )

    if not business_routes_enabled:
        app.router.routes = [
            route
            for route in app.router.routes
            if (
                str(getattr(route, "path", "")) == "/health"
                or _is_pairing_surface_route(route)
            )
        ]
        if any(
            str(getattr(route, "path", "")) != "/health"
            and not _is_pairing_surface_route(route)
            for route in app.router.routes
        ):
            raise RuntimeError("pairing_only_route_removal_failed")
    if business_routes_enabled:
        install_device_auth_openapi_scheme(app, business_auth_mode)
    return app


async def _drain_operation_after_cancellation(
    task: asyncio.Task[Response],
) -> None:
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            continue
        except Exception:
            break
    if task.done() and not task.cancelled():
        try:
            task.result()
        except Exception:
            pass


async def _serve_conversation_events(
    websocket: WebSocket,
    *,
    store: EventStore,
    subscriptions: SubscriptionManager,
    conversation_id: str,
    after_seq: int,
    transport_accepted: bool,
    authorization_changed_task: asyncio.Task[None] | None = None,
    authorized_send_json: Callable[[object], Awaitable[None]] | None = None,
) -> None:
    subscription: Subscription | None = None
    send_json = authorized_send_json or websocket.send_json
    try:
        _raise_if_authorization_changed(authorization_changed_task)
        if after_seq < 0:
            await websocket.close(code=1008)
            return
        try:
            conversation = await asyncio.to_thread(
                store.get_conversation,
                conversation_id,
            )
        except ConversationNotFoundError:
            _raise_if_authorization_changed(authorization_changed_task)
            await websocket.close(code=4404)
            return

        _raise_if_authorization_changed(authorization_changed_task)
        if not transport_accepted:
            await websocket.accept()
        _raise_if_authorization_changed(authorization_changed_task)
        server_last_conversation_seq = conversation.next_seq - 1
        if after_seq > server_last_conversation_seq:
            _raise_if_authorization_changed(authorization_changed_task)
            await send_json(
                {
                    "kind": "error",
                    "error": {
                        "code": "cursor_ahead",
                        "message": "replay cursor exceeds server state",
                        "server_last_conversation_seq": (
                            server_last_conversation_seq
                        ),
                    },
                }
            )
            await websocket.close(code=1008)
            return
        _raise_if_authorization_changed(authorization_changed_task)
        subscription = await subscriptions.register(conversation_id)
        _raise_if_authorization_changed(authorization_changed_task)
        last_sent = after_seq
        replayed = await asyncio.to_thread(
            _replay_all,
            store,
            conversation_id,
            last_sent,
        )
        last_sent = await _send_events(
            websocket,
            replayed,
            last_sent=last_sent,
            delivery="replay",
            authorization_changed_task=authorization_changed_task,
            authorized_send_json=send_json,
        )

        while not subscription.queue.empty():
            _raise_if_authorization_changed(authorization_changed_task)
            subscription.queue.get_nowait()
            catch_up = await asyncio.to_thread(
                _replay_all,
                store,
                conversation_id,
                last_sent,
            )
            last_sent = await _send_events(
                websocket,
                catch_up,
                last_sent=last_sent,
                delivery="replay",
                authorization_changed_task=authorization_changed_task,
                authorized_send_json=send_json,
            )
        if subscription.overflowed.is_set():
            raise SubscriptionOverflowError

        _raise_if_authorization_changed(authorization_changed_task)
        await send_json(
            {
                "kind": "ready",
                "last_conversation_seq": last_sent,
            }
        )

        while True:
            await _next_event_or_disconnect(
                websocket,
                subscriptions,
                subscription,
                authorization_changed_task=authorization_changed_task,
            )
            _raise_if_authorization_changed(authorization_changed_task)
            catch_up = await asyncio.to_thread(
                _replay_all,
                store,
                conversation_id,
                last_sent,
            )
            last_sent = await _send_events(
                websocket,
                catch_up,
                last_sent=last_sent,
                delivery="live",
                authorization_changed_task=authorization_changed_task,
                authorized_send_json=send_json,
            )
    except (
        AuthorizationChangedError,
        DeviceConnectionAuthorizationChangedError,
    ):
        pass
    except DeviceConnectionSendTimeout:
        await websocket.close(code=1013, reason="send deadline exceeded")
    except SubscriptionOverflowError:
        await websocket.close(
            code=1013,
            reason="reconnect and replay required",
        )
    except asyncio.CancelledError:
        return
    except WebSocketDisconnect:
        pass
    except PersistenceError:
        await websocket.close(code=1011)
    finally:
        if subscription is not None:
            await subscriptions.unregister(subscription)
            while not subscription.queue.empty():
                subscription.queue.get_nowait()


def _raise_if_authorization_changed(
    authorization_changed_task: asyncio.Task[None] | None,
) -> None:
    if authorization_changed_task is not None and authorization_changed_task.done():
        raise AuthorizationChangedError()


def wire_event(event: ConversationEvent) -> WireEvent:
    try:
        computed_hash = hashlib.sha256(
            event.payload_json.encode("utf-8")
        ).hexdigest()
        if (
            not isinstance(event.payload_sha256, str)
            or not hmac.compare_digest(
                computed_hash,
                event.payload_sha256,
            )
        ):
            raise ValueError
        payload_data = json.loads(event.payload_json)
        if not isinstance(payload_data, dict):
            raise ValueError
        payload = WirePayload.model_validate(payload_data)
        if payload.accepted_seq != event.conversation_seq:
            raise ValueError
    except (json.JSONDecodeError, ValueError, TypeError):
        raise PersistenceError("persisted event payload is invalid") from None
    return WireEvent(
        event_id=event.event_id,
        protocol_version=event.protocol_version,
        event_type=event.event_type,
        conversation_id=event.conversation_id,
        conversation_seq=event.conversation_seq,
        actor_device_id=event.actor_device_id,
        causation_id=event.causation_id,
        correlation_id=event.correlation_id,
        occurred_at=event.occurred_at,
        payload=payload,
        payload_sha256=event.payload_sha256,
    )


def _replay_all(
    store: EventStore,
    conversation_id: str,
    after_seq: int,
) -> list[ConversationEvent]:
    events: list[ConversationEvent] = []
    cursor = after_seq
    while True:
        page = store.replay_events(
            conversation_id=conversation_id,
            after_seq=cursor,
            limit=500,
        )
        if not page:
            return events
        events.extend(page)
        cursor = page[-1].conversation_seq
        if len(page) < 500:
            return events


async def _send_events(
    websocket: WebSocket,
    events: list[ConversationEvent],
    *,
    last_sent: int,
    delivery: str,
    authorization_changed_task: asyncio.Task[None] | None = None,
    authorized_send_json: Callable[[object], Awaitable[None]] | None = None,
) -> int:
    send_json = authorized_send_json or websocket.send_json
    for event in events:
        if event.conversation_seq <= last_sent:
            continue
        _raise_if_authorization_changed(authorization_changed_task)
        await send_json(
            {
                "kind": "event",
                "delivery": delivery,
                "event": wire_event(event).model_dump(mode="json"),
            }
        )
        last_sent = event.conversation_seq
    return last_sent


async def _next_event_or_disconnect(
    websocket: WebSocket,
    subscriptions: SubscriptionManager,
    subscription: Subscription,
    *,
    authorization_changed_task: asyncio.Task[None] | None = None,
) -> ConversationEvent:
    event_task = asyncio.create_task(
        subscriptions.next_event(subscription)
    )
    receive_task = asyncio.create_task(websocket.receive())
    try:
        waiters = {event_task, receive_task}
        if authorization_changed_task is not None:
            waiters.add(authorization_changed_task)
        done, _ = await asyncio.wait(
            waiters,
            return_when=asyncio.FIRST_COMPLETED,
        )
        if (
            authorization_changed_task is not None
            and authorization_changed_task in done
        ):
            raise AuthorizationChangedError()
        if receive_task in done:
            message = receive_task.result()
            if message["type"] == "websocket.disconnect":
                raise WebSocketDisconnect(
                    code=int(message.get("code") or 1000)
                )
            await websocket.close(code=1008)
            raise WebSocketDisconnect(code=1008)
        return event_task.result()
    finally:
        await cancel_and_drain_tasks(event_task, receive_task)


def _install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(RequestValidationError)
    async def request_validation_error(
        _: Request,
        __: RequestValidationError,
    ) -> JSONResponse:
        return _error_response(
            422,
            "validation_error",
            "request validation failed",
        )

    @app.exception_handler(ValidationError)
    async def domain_validation_error(
        _: Request,
        __: ValidationError,
    ) -> JSONResponse:
        return _error_response(
            400,
            "validation_error",
            "request validation failed",
        )

    @app.exception_handler(ConversationNotFoundError)
    async def conversation_not_found(
        _: Request,
        __: ConversationNotFoundError,
    ) -> JSONResponse:
        return _error_response(
            404,
            "conversation_not_found",
            "conversation not found",
        )

    @app.exception_handler(ConversationAlreadyExistsError)
    async def conversation_exists(
        _: Request,
        __: ConversationAlreadyExistsError,
    ) -> JSONResponse:
        return _error_response(
            409,
            "conversation_already_exists",
            "conversation already exists",
        )

    @app.exception_handler(IdempotencyConflictError)
    async def idempotency_conflict(
        _: Request,
        __: IdempotencyConflictError,
    ) -> JSONResponse:
        return _error_response(
            409,
            "idempotency_conflict",
            "client message conflicts with persisted input",
        )

    @app.exception_handler(PersistenceError)
    async def persistence_error(
        _: Request,
        __: PersistenceError,
    ) -> JSONResponse:
        return _error_response(
            503,
            "persistence_unavailable",
            "persistence operation failed",
        )

    @app.exception_handler(CursorAheadError)
    async def cursor_ahead(
        _: Request,
        error: CursorAheadError,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=409,
            content={
                "error": {
                    "code": "cursor_ahead",
                    "message": "replay cursor exceeds server state",
                    "server_last_conversation_seq": (
                        error.server_last_conversation_seq
                    ),
                }
            },
        )


def _error_response(
    status_code: int,
    code: str,
    message: str,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": message}},
    )
