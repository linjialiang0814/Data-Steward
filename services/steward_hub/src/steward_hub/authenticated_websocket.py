"""Authenticated WebSocket handshake orchestration with no business access."""

from __future__ import annotations

import asyncio
import hmac
from dataclasses import dataclass

from fastapi import WebSocket
from starlette.websockets import WebSocketDisconnect

from .device_auth import (
    SESSION_SYNC_CAPABILITY,
    AuthenticatedDevice,
    DeviceAuthError,
    authenticate_device_digest,
)
from .device_connection_registry import (
    DeviceConnectionLease,
    DeviceConnectionRegistry,
    DeviceConnectionRegistryCapacityError,
    DeviceConnectionRegistryClosedError,
    DeviceConnectionRegistryError,
    DeviceConnectionRegistryPolicyError,
    HandshakePermit,
)
from .pairing_store import PairingStore
from .pairing_store_executor import PairingStoreExecutor
from .subscriptions import cancel_and_drain_tasks
from .websocket_auth import (
    WebSocketAuthFrameError,
    auth_failed_frame,
    auth_ok_frame,
    decode_websocket_auth_message,
    websocket_error_from_device,
)


class WebSocketAuthenticationTerminated(Exception):
    """The accepted transport was rejected or disconnected before business use."""


@dataclass(frozen=True, slots=True)
class AuthenticatedWebSocketContext:
    device: AuthenticatedDevice
    lease: DeviceConnectionLease
    authorization_changed_task: asyncio.Task[None]

    async def send_json(self, websocket: WebSocket, payload: object) -> None:
        await self.lease.send_if_authorized(
            lambda: websocket.send_json(payload)
        )


async def cleanup_authenticated_websocket(
    context: AuthenticatedWebSocketContext,
) -> None:
    """Finish route-owned cleanup even under repeated parent cancellation."""

    async def cleanup() -> None:
        await cancel_and_drain_tasks(context.authorization_changed_task)
        await context.lease.unregister()

    cleanup_task = asyncio.create_task(cleanup())
    while not cleanup_task.done():
        try:
            await asyncio.shield(cleanup_task)
        except asyncio.CancelledError:
            continue
    if not cleanup_task.cancelled():
        cleanup_task.result()


async def _cleanup_incomplete_authentication(
    *,
    permit: HandshakePermit | None,
    lease: DeviceConnectionLease | None,
    authorization_changed_task: asyncio.Task[None] | None,
) -> None:
    async def cleanup() -> None:
        if authorization_changed_task is not None:
            await cancel_and_drain_tasks(authorization_changed_task)
        if lease is not None:
            await lease.unregister()
        if permit is not None:
            await permit.release()

    cleanup_task = asyncio.create_task(cleanup())
    while not cleanup_task.done():
        try:
            await asyncio.shield(cleanup_task)
        except asyncio.CancelledError:
            continue
    if not cleanup_task.cancelled():
        cleanup_task.result()


def _validate_upgrade_channel(websocket: WebSocket, after_seq: int) -> None:
    if isinstance(after_seq, bool) or not isinstance(after_seq, int) or after_seq < 0:
        raise WebSocketAuthFrameError("policy_violation", 1008)
    headers = websocket.scope.get("headers", ())
    if any(
        isinstance(name, bytes) and name.lower() == b"authorization"
        for name, _value in headers
    ):
        raise WebSocketAuthFrameError("policy_violation", 1008)
    raw_query = websocket.scope.get("query_string", b"")
    expected_query = f"after_seq={after_seq}".encode("ascii")
    if not isinstance(raw_query, bytes) or not hmac.compare_digest(
        raw_query,
        expected_query,
    ):
        raise WebSocketAuthFrameError("policy_violation", 1008)


async def _close_callback(
    websocket: WebSocket,
    code: int,
    reason: str,
) -> None:
    await websocket.close(code=code, reason=reason)


async def _report_auth_failure(
    websocket: WebSocket,
    error: WebSocketAuthFrameError,
) -> None:
    try:
        await websocket.send_json(auth_failed_frame(error.error_code))
    except Exception:  # noqa: BLE001 - disconnect is an expected terminal state
        pass
    try:
        await websocket.close(code=error.close_code, reason=error.error_code)
    except Exception:  # noqa: BLE001 - cleanup must remain idempotent
        pass


def _registry_error(error: DeviceConnectionRegistryError) -> WebSocketAuthFrameError:
    if isinstance(error, DeviceConnectionRegistryPolicyError):
        return WebSocketAuthFrameError("policy_violation", 1008)
    if isinstance(
        error,
        (
            DeviceConnectionRegistryClosedError,
            DeviceConnectionRegistryCapacityError,
        ),
    ):
        return WebSocketAuthFrameError("auth_unavailable", 1013)
    return WebSocketAuthFrameError("auth_unavailable", 1013)


async def authenticate_websocket(
    websocket: WebSocket,
    *,
    after_seq: int,
    pairing_store: PairingStore,
    store_executor: PairingStoreExecutor,
    registry: DeviceConnectionRegistry,
    auth_timeout_s: float,
) -> AuthenticatedWebSocketContext:
    """Accept and authenticate one socket without touching conversation state."""
    permit: HandshakePermit | None = None
    lease: DeviceConnectionLease | None = None
    authorization_changed_task: asyncio.Task[None] | None = None
    succeeded = False
    await websocket.accept()
    try:
        async def close_callback(code: int, reason: str) -> None:
            await _close_callback(websocket, code, reason)

        permit = await registry.acquire_handshake(close_callback)
        _validate_upgrade_channel(websocket, after_seq)
        message: dict[str, object] | None = None
        try:
            try:
                message = await asyncio.wait_for(
                    websocket.receive(),
                    timeout=auth_timeout_s,
                )
            except TimeoutError:
                raise WebSocketAuthFrameError("auth_invalid", 1008) from None
            if message.get("type") == "websocket.disconnect":
                raise WebSocketDisconnect(code=int(message.get("code") or 1000))
            credentials = decode_websocket_auth_message(message)
        finally:
            if isinstance(message, dict):
                message.clear()

        async def verifier() -> AuthenticatedDevice:
            return await authenticate_device_digest(
                pairing_store=pairing_store,
                store_executor=store_executor,
                device_id=credentials.device_id,
                credential_digest=credentials.credential_digest,
                capability_epoch=credentials.capability_epoch,
                required_capability=SESSION_SYNC_CAPABILITY,
                timeout_s=auth_timeout_s,
            )

        try:
            authenticated, lease = await registry.authenticate_and_register(
                device_id=credentials.device_id,
                verifier=verifier,
                close_callback=close_callback,
            )
        except DeviceAuthError as error:
            raise websocket_error_from_device(error) from None
        except DeviceConnectionRegistryError as error:
            raise _registry_error(error) from None

        await permit.release()
        permit = None
        authorization_changed_task = asyncio.create_task(
            lease.wait_authorization_changed()
        )
        await asyncio.sleep(0)
        if authorization_changed_task.done():
            raise WebSocketAuthenticationTerminated()
        try:
            await lease.send_if_authorized(
                lambda: websocket.send_json(auth_ok_frame(authenticated))
            )
        except DeviceConnectionRegistryError:
            raise WebSocketAuthenticationTerminated() from None
        succeeded = True
        return AuthenticatedWebSocketContext(
            device=authenticated,
            lease=lease,
            authorization_changed_task=authorization_changed_task,
        )
    except WebSocketAuthenticationTerminated:
        raise
    except WebSocketDisconnect:
        raise WebSocketAuthenticationTerminated() from None
    except WebSocketAuthFrameError as error:
        await _report_auth_failure(websocket, error)
        raise WebSocketAuthenticationTerminated() from None
    except asyncio.CancelledError:
        raise
    except Exception:
        await _report_auth_failure(
            websocket,
            WebSocketAuthFrameError("auth_unavailable", 1013),
        )
        raise WebSocketAuthenticationTerminated() from None
    finally:
        if not succeeded:
            await _cleanup_incomplete_authentication(
                permit=permit,
                lease=lease,
                authorization_changed_task=authorization_changed_task,
            )
