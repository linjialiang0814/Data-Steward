"""Bounded authenticated WebSocket connection ownership."""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Generic, TypeVar

from .device_auth import AuthenticatedDevice
from .pairing_codec import require_ulid
from .pairing_errors import PairingValidationError

DEFAULT_MAX_HANDSHAKES = 16
DEFAULT_MAX_CONNECTIONS = 32
DEFAULT_MAX_PER_DEVICE = 4
DEFAULT_MAX_OPERATIONS = 64
DEFAULT_MAX_OPERATIONS_PER_DEVICE = 8
LOCK_STRIPE_COUNT = 32
DEFAULT_CLOSE_TIMEOUT_S = 5.0
DEFAULT_SEND_TIMEOUT_S = 5.0
MAX_CLOSE_TIMEOUT_S = 30.0
MAX_SEND_TIMEOUT_S = 30.0

CloseCallback = Callable[[int, str], Awaitable[None]]
Verifier = Callable[[], Awaitable[AuthenticatedDevice]]
T = TypeVar("T")
CompletionCertainTransition = Callable[[], Awaitable[T]]
SendOperation = Callable[[], Awaitable[None]]

_STANDARD_SENDABLE_CLOSE_CODES = frozenset(
    {
        1000,
        1001,
        1002,
        1003,
        1007,
        1008,
        1009,
        1010,
        1011,
        1012,
        1013,
        1014,
    }
)


class DeviceConnectionRegistryError(Exception):
    """Base class with no device or socket detail."""


class DeviceConnectionRegistryClosedError(DeviceConnectionRegistryError):
    pass


class DeviceConnectionRegistryCapacityError(DeviceConnectionRegistryError):
    pass


class DeviceConnectionRegistryCloseTimeout(DeviceConnectionRegistryError):
    pass


class DeviceConnectionRegistryPolicyError(DeviceConnectionRegistryError):
    pass


class DeviceConnectionAuthorizationChangedError(DeviceConnectionRegistryError):
    pass


class DeviceConnectionSendTimeout(DeviceConnectionRegistryError):
    pass


@dataclass(frozen=True, slots=True)
class RegistrySnapshot:
    accepting: bool
    handshake_count: int
    connection_count: int
    closing_connection_count: int
    device_count: int
    stripe_count: int
    operation_count: int


@dataclass(eq=False, slots=True)
class HandshakePermit:
    _registry: DeviceConnectionRegistry
    _close_callback: CloseCallback
    _released: asyncio.Event = field(default_factory=asyncio.Event)
    _close_task: asyncio.Task[None] | None = None

    async def release(self) -> None:
        await self._registry.release_handshake(self)


@dataclass(eq=False, slots=True)
class DeviceConnectionLease:
    device_id: str
    capability_epoch: int
    _registry: DeviceConnectionRegistry
    _close_callback: CloseCallback
    _closed: asyncio.Event = field(default_factory=asyncio.Event)
    _authorization_changed: asyncio.Event = field(default_factory=asyncio.Event)
    _closing: bool = False
    _close_task: asyncio.Task[None] | None = None
    _send_gate: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def unregister(self) -> None:
        await self._registry.unregister(self)

    async def wait_authorization_changed(self) -> None:
        await self._authorization_changed.wait()

    async def send_if_authorized(self, operation: SendOperation) -> None:
        await self._registry.send_if_authorized(self, operation)


@dataclass(eq=False, slots=True)
class DeviceOperationLease:
    device_id: str
    capability_epoch: int
    _registry: DeviceConnectionRegistry
    _released: asyncio.Event = field(default_factory=asyncio.Event)

    async def release(self) -> None:
        await self._registry.release_operation(self)


@dataclass(frozen=True, slots=True)
class AuthorizationTransition(Generic[T]):
    value: T
    authorization_changed: bool


@dataclass(frozen=True, slots=True)
class TransitionResult(Generic[T]):
    value: T
    closed_connection_count: int


def _positive_int(name: str, value: object, *, upper: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be a positive int")
    if value < 1 or value > upper:
        raise ValueError(f"{name} is outside the allowed range")
    return value


def _positive_float(name: str, value: object, *, upper: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a positive number")
    number = float(value)
    if (
        number <= 0.0
        or number > upper
        or number != number
        or number in (float("inf"), float("-inf"))
    ):
        raise ValueError(f"{name} is outside the allowed range")
    return number


def _safe_close(code: object, reason: object) -> tuple[int, str]:
    if (
        isinstance(code, bool)
        or not isinstance(code, int)
        or (
            code not in _STANDARD_SENDABLE_CLOSE_CODES
            and not 3000 <= code <= 4999
        )
    ):
        raise ValueError("close code is invalid")
    if (
        not isinstance(reason, str)
        or len(reason.encode("utf-8")) > 123
        or any(ord(character) < 32 or ord(character) == 127 for character in reason)
    ):
        raise ValueError("close reason is invalid")
    return code, reason


class DeviceConnectionRegistry:
    def __init__(
        self,
        *,
        max_handshakes: int = DEFAULT_MAX_HANDSHAKES,
        max_connections: int = DEFAULT_MAX_CONNECTIONS,
        max_per_device: int = DEFAULT_MAX_PER_DEVICE,
        close_timeout_s: float = DEFAULT_CLOSE_TIMEOUT_S,
        send_timeout_s: float = DEFAULT_SEND_TIMEOUT_S,
        max_operations: int = DEFAULT_MAX_OPERATIONS,
        max_operations_per_device: int = DEFAULT_MAX_OPERATIONS_PER_DEVICE,
    ) -> None:
        self._max_handshakes = _positive_int(
            "max_handshakes", max_handshakes, upper=256
        )
        self._max_connections = _positive_int(
            "max_connections", max_connections, upper=1024
        )
        self._max_per_device = _positive_int(
            "max_per_device", max_per_device, upper=64
        )
        if self._max_per_device > self._max_connections:
            raise ValueError("max_per_device exceeds max_connections")
        self._close_timeout_s = _positive_float(
            "close_timeout_s", close_timeout_s, upper=MAX_CLOSE_TIMEOUT_S
        )
        self._send_timeout_s = _positive_float(
            "send_timeout_s", send_timeout_s, upper=MAX_SEND_TIMEOUT_S
        )
        self._max_operations = _positive_int(
            "max_operations", max_operations, upper=4096
        )
        self._max_operations_per_device = _positive_int(
            "max_operations_per_device",
            max_operations_per_device,
            upper=256,
        )
        if self._max_operations_per_device > self._max_operations:
            raise ValueError("max_operations_per_device exceeds max_operations")
        self._state_lock = asyncio.Lock()
        self._stripes = tuple(asyncio.Lock() for _ in range(LOCK_STRIPE_COUNT))
        self._handshakes: set[HandshakePermit] = set()
        self._connections: dict[str, set[DeviceConnectionLease]] = {}
        self._closing_connections: set[DeviceConnectionLease] = set()
        self._operations: dict[str, set[DeviceOperationLease]] = {}
        self._accepting = True

    def _stripe(self, device_id: str) -> asyncio.Lock:
        digest = hashlib.sha256(device_id.encode("ascii")).digest()
        index = int.from_bytes(digest[:4], "big") % len(self._stripes)
        return self._stripes[index]

    async def snapshot(self) -> RegistrySnapshot:
        async with self._state_lock:
            return RegistrySnapshot(
                accepting=self._accepting,
                handshake_count=len(self._handshakes),
                connection_count=sum(
                    len(items) for items in self._connections.values()
                )
                + len(self._closing_connections),
                closing_connection_count=len(self._closing_connections),
                device_count=len(
                    set(self._connections)
                    | {
                        lease.device_id
                        for lease in self._closing_connections
                    }
                ),
                stripe_count=len(self._stripes),
                operation_count=sum(
                    len(items) for items in self._operations.values()
                ),
            )

    async def acquire_handshake(
        self,
        close_callback: CloseCallback,
    ) -> HandshakePermit:
        if not callable(close_callback):
            raise ValueError("close_callback must be callable")
        async with self._state_lock:
            if not self._accepting:
                raise DeviceConnectionRegistryClosedError()
            if len(self._handshakes) >= self._max_handshakes:
                raise DeviceConnectionRegistryCapacityError()
            permit = HandshakePermit(self, close_callback)
            self._handshakes.add(permit)
            return permit

    async def release_handshake(self, permit: HandshakePermit) -> None:
        if not isinstance(permit, HandshakePermit) or permit._registry is not self:
            raise DeviceConnectionRegistryPolicyError()
        async with self._state_lock:
            self._handshakes.discard(permit)
            permit._released.set()

    async def authenticate_and_register(
        self,
        *,
        device_id: str,
        verifier: Verifier,
        close_callback: CloseCallback,
    ) -> tuple[AuthenticatedDevice, DeviceConnectionLease]:
        try:
            validated_device_id = require_ulid("device_id", device_id)
        except PairingValidationError:
            raise DeviceConnectionRegistryPolicyError() from None
        if not callable(verifier) or not callable(close_callback):
            raise ValueError("registry callbacks must be callable")
        async with self._stripe(validated_device_id):
            authenticated = await verifier()
            if (
                not isinstance(authenticated, AuthenticatedDevice)
                or authenticated.device_id != validated_device_id
                or isinstance(authenticated.capability_epoch, bool)
                or not isinstance(authenticated.capability_epoch, int)
                or authenticated.capability_epoch < 1
            ):
                raise DeviceConnectionRegistryPolicyError()
            async with self._state_lock:
                if not self._accepting:
                    raise DeviceConnectionRegistryClosedError()
                connection_count = sum(
                    len(items) for items in self._connections.values()
                ) + len(self._closing_connections)
                device_connections = self._connections.get(
                    validated_device_id, set()
                )
                closing_for_device = sum(
                    lease.device_id == validated_device_id
                    for lease in self._closing_connections
                )
                if (
                    connection_count >= self._max_connections
                    or len(device_connections) + closing_for_device
                    >= self._max_per_device
                ):
                    raise DeviceConnectionRegistryCapacityError()
                lease = DeviceConnectionLease(
                    device_id=validated_device_id,
                    capability_epoch=authenticated.capability_epoch,
                    _registry=self,
                    _close_callback=close_callback,
                )
                self._connections.setdefault(validated_device_id, set()).add(
                    lease
                )
                return authenticated, lease

    async def authenticate_and_acquire_operation(
        self,
        *,
        device_id: str,
        verifier: Verifier,
    ) -> tuple[AuthenticatedDevice, DeviceOperationLease]:
        try:
            validated_device_id = require_ulid("device_id", device_id)
        except PairingValidationError:
            raise DeviceConnectionRegistryPolicyError() from None
        if not callable(verifier):
            raise ValueError("verifier must be callable")
        async with self._stripe(validated_device_id):
            authenticated = await verifier()
            if (
                not isinstance(authenticated, AuthenticatedDevice)
                or authenticated.device_id != validated_device_id
                or isinstance(authenticated.capability_epoch, bool)
                or not isinstance(authenticated.capability_epoch, int)
                or authenticated.capability_epoch < 1
            ):
                raise DeviceConnectionRegistryPolicyError()
            async with self._state_lock:
                if not self._accepting:
                    raise DeviceConnectionRegistryClosedError()
                total = sum(len(items) for items in self._operations.values())
                device_operations = self._operations.get(
                    validated_device_id,
                    set(),
                )
                if (
                    total >= self._max_operations
                    or len(device_operations)
                    >= self._max_operations_per_device
                ):
                    raise DeviceConnectionRegistryCapacityError()
                lease = DeviceOperationLease(
                    device_id=validated_device_id,
                    capability_epoch=authenticated.capability_epoch,
                    _registry=self,
                )
                self._operations.setdefault(validated_device_id, set()).add(
                    lease
                )
                return authenticated, lease

    async def release_operation(self, lease: DeviceOperationLease) -> None:
        if not isinstance(lease, DeviceOperationLease) or lease._registry is not self:
            raise DeviceConnectionRegistryPolicyError()
        async with self._state_lock:
            items = self._operations.get(lease.device_id)
            if items is not None:
                items.discard(lease)
                if not items:
                    self._operations.pop(lease.device_id, None)
            lease._released.set()

    async def unregister(self, lease: DeviceConnectionLease) -> None:
        if not isinstance(lease, DeviceConnectionLease) or lease._registry is not self:
            raise DeviceConnectionRegistryPolicyError()
        async with self._state_lock:
            items = self._connections.get(lease.device_id)
            if items is not None:
                items.discard(lease)
                if not items:
                    self._connections.pop(lease.device_id, None)
            self._closing_connections.discard(lease)
            lease._closed.set()

    async def send_if_authorized(
        self,
        lease: DeviceConnectionLease,
        operation: SendOperation,
    ) -> None:
        if (
            not isinstance(lease, DeviceConnectionLease)
            or lease._registry is not self
        ):
            raise DeviceConnectionRegistryPolicyError()
        if not callable(operation):
            raise ValueError("send operation must be callable")
        async with lease._send_gate:
            async with self._state_lock:
                active = (
                    not lease._closing
                    and not lease._closed.is_set()
                    and lease in self._connections.get(lease.device_id, set())
                )
            if not active or lease._authorization_changed.is_set():
                raise DeviceConnectionAuthorizationChangedError()
            try:
                await asyncio.wait_for(
                    operation(),
                    timeout=self._send_timeout_s,
                )
            except TimeoutError:
                raise DeviceConnectionSendTimeout() from None

    async def transition_and_close(
        self,
        *,
        device_id: str,
        transition: CompletionCertainTransition[T],
        close_code: int = 1008,
        close_reason: str = "device authorization changed",
    ) -> TransitionResult[T]:
        """
        Run one completion-certain authorization transition and close leases.

        The callback must not raise while a durable side effect may still
        commit later. A caller using non-cancellable worker I/O must wait for
        its final result or reconcile persistent state before returning or
        raising; a generic executor timeout is not a valid transition result.
        """
        try:
            validated_device_id = require_ulid("device_id", device_id)
        except PairingValidationError:
            raise DeviceConnectionRegistryPolicyError() from None
        if not callable(transition):
            raise ValueError("transition must be callable")
        code, reason = _safe_close(close_code, close_reason)
        operation_task = asyncio.create_task(
            self._run_transition_and_close(
                device_id=validated_device_id,
                transition=transition,
                close_code=code,
                close_reason=reason,
            )
        )
        try:
            return await asyncio.shield(operation_task)
        except asyncio.CancelledError:
            # Once an authorization transition has started, caller
            # cancellation must not split a durable commit from registry
            # detachment and connection cleanup.
            await _drain_owned_task_after_cancellation(operation_task)
            raise

    async def _run_transition_and_close(
        self,
        *,
        device_id: str,
        transition: CompletionCertainTransition[T],
        close_code: int,
        close_reason: str,
    ) -> TransitionResult[T]:
        async with self._stripe(device_id):
            async with self._state_lock:
                active_operations = tuple(
                    self._operations.get(device_id, set())
                )
            if active_operations:
                await asyncio.gather(
                    *(lease._released.wait() for lease in active_operations)
                )
            async with self._state_lock:
                live_leases = tuple(
                    sorted(
                        self._connections.get(device_id, set()),
                        key=id,
                    )
                )
            acquired_gates: list[asyncio.Lock] = []
            try:
                for lease in live_leases:
                    await lease._send_gate.acquire()
                    acquired_gates.append(lease._send_gate)
                transition_value = await transition()
                if isinstance(transition_value, AuthorizationTransition):
                    value = transition_value.value
                    authorization_changed = (
                        transition_value.authorization_changed
                    )
                else:
                    value = transition_value
                    authorization_changed = True
                if not authorization_changed:
                    return TransitionResult(
                        value=value,
                        closed_connection_count=0,
                    )
                async with self._state_lock:
                    detached = set(self._connections.pop(device_id, set()))
                    leases = tuple(
                        detached
                        | {
                            lease
                            for lease in self._closing_connections
                            if lease.device_id == device_id
                        }
                    )
                    for lease in leases:
                        lease._closing = True
                        lease._authorization_changed.set()
                        self._closing_connections.add(lease)
                    self._claim_close_tasks_locked(
                        leases,
                        code=close_code,
                        reason=close_reason,
                    )
            finally:
                for gate in reversed(acquired_gates):
                    gate.release()
        await self._complete_close_despite_cancellation(
            leases,
            code=close_code,
            reason=close_reason,
        )
        return TransitionResult(
            value=value,
            closed_connection_count=len(detached),
        )

    async def stop_accepting_and_close_all(
        self,
        *,
        close_code: int = 1012,
        close_reason: str = "service restart",
    ) -> None:
        code, reason = _safe_close(close_code, close_reason)
        async with self._state_lock:
            self._accepting = False
            handshakes = tuple(self._handshakes)
            leases = tuple(
                {
                    lease
                    for items in self._connections.values()
                    for lease in items
                }
                | set(self._closing_connections)
            )
            self._connections.clear()
            for lease in leases:
                lease._closing = True
                lease._authorization_changed.set()
                self._closing_connections.add(lease)
            self._claim_close_tasks_locked(
                (*handshakes, *leases),
                code=code,
                reason=reason,
            )
        await self._complete_close_despite_cancellation(
            (*handshakes, *leases),
            code=code,
            reason=reason,
        )

    def _claim_close_tasks_locked(
        self,
        items: tuple[HandshakePermit | DeviceConnectionLease, ...],
        *,
        code: int,
        reason: str,
    ) -> None:
        for item in items:
            if item._close_task is None:
                item._close_task = asyncio.create_task(
                    _invoke_close_callback(item, code=code, reason=reason)
                )

    async def _complete_close_despite_cancellation(
        self,
        items: tuple[HandshakePermit | DeviceConnectionLease, ...],
        *,
        code: int,
        reason: str,
    ) -> None:
        if not items:
            return
        close_task = asyncio.create_task(
            self._close_and_wait(items, code=code, reason=reason)
        )
        try:
            await asyncio.shield(close_task)
        except asyncio.CancelledError:
            # A committed authorization transition must finish connection
            # cleanup before cancellation is allowed to escape.
            await close_task
            raise

    async def _close_and_wait(
        self,
        items: tuple[HandshakePermit | DeviceConnectionLease, ...],
        *,
        code: int,
        reason: str,
    ) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._close_timeout_s
        close_tasks: list[asyncio.Task[None]] = []
        for item in items:
            task = item._close_task
            if task is None:
                raise DeviceConnectionRegistryPolicyError()
            close_tasks.append(task)
        try:
            remaining = max(0.0, deadline - loop.time())
            await asyncio.wait_for(
                asyncio.gather(*close_tasks, return_exceptions=True),
                timeout=remaining,
            )
        except TimeoutError:
            raise DeviceConnectionRegistryCloseTimeout() from None
        finally:
            await _cancel_and_drain(close_tasks)

        wait_tasks = [
            asyncio.create_task(
                item._released.wait()
                if isinstance(item, HandshakePermit)
                else item._closed.wait()
            )
            for item in items
        ]
        try:
            remaining = max(0.0, deadline - loop.time())
            await asyncio.wait_for(
                asyncio.gather(*wait_tasks),
                timeout=remaining,
            )
        except TimeoutError:
            raise DeviceConnectionRegistryCloseTimeout() from None
        finally:
            await _cancel_and_drain(wait_tasks)


async def _cancel_and_drain(tasks: list[asyncio.Task[object]]) -> None:
    for task in tasks:
        if not task.done():
            task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


async def _invoke_close_callback(
    item: HandshakePermit | DeviceConnectionLease,
    *,
    code: int,
    reason: str,
) -> None:
    await item._close_callback(code, reason)


async def _drain_owned_task_after_cancellation(
    task: asyncio.Task[object],
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
