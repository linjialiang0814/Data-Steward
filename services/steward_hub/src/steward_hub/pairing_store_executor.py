"""App-scoped bounded PairingStore runner with fixed non-daemon workers."""

from __future__ import annotations

import asyncio
import queue
import secrets
import threading
import time
from collections.abc import Callable
from concurrent.futures import Future
from typing import Any, TypeVar

T = TypeVar("T")

DEFAULT_MAX_WORKERS = 4
DEFAULT_MAX_QUEUED = 16
DEFAULT_MAX_ERROR_KEYS = 32
DEFAULT_IDLE_TIMEOUT_S = 5.0
MAX_MAX_WORKERS = 32
MAX_MAX_QUEUED = 256
MAX_MAX_ERROR_KEYS = 64
MAX_IDLE_TIMEOUT_S = 60.0

_WORKER_NAME_ROOT = "pairing-store"


class PairingStoreSaturatedError(Exception):
    """In-flight + queue capacity exhausted."""

    error_code = "pairing_unavailable"


class PairingStoreExecutorClosedError(Exception):
    error_code = "pairing_unavailable"


def _require_positive_int(name: str, value: object, *, upper: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be a positive int")
    if value < 1 or value > upper:
        raise ValueError(f"{name} must be in 1..{upper}")
    return value


def _require_positive_float(name: str, value: object, *, upper: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a positive float")
    number = float(value)
    if number <= 0.0 or number > upper or number != number:  # NaN check
        raise ValueError(f"{name} must be in (0, {upper}]")
    return number


def list_alive_pairing_worker_threads() -> list[threading.Thread]:
    """Process-wide inventory of pairing store worker threads."""
    return [
        thread
        for thread in threading.enumerate()
        if thread.is_alive() and thread.name.startswith(_WORKER_NAME_ROOT)
    ]


class PairingStoreExecutor:
    """
    Bounded store execution with a project-owned worker pool:

    - fixed worker count; threads created with daemon=False
    - bounded in-flight + queue capacity (fail-closed on saturation)
    - shutdown: stop accept → cancel queued → wait active → sentinels → join
    - shutdown is idempotent; after success: active=queued=pending=workers=0
    - wait=False is rejected before any state mutation
    """

    def __init__(
        self,
        *,
        max_workers: int = DEFAULT_MAX_WORKERS,
        max_queued: int = DEFAULT_MAX_QUEUED,
        max_error_keys: int = DEFAULT_MAX_ERROR_KEYS,
        idle_timeout_s: float = DEFAULT_IDLE_TIMEOUT_S,
    ) -> None:
        self._max_workers = _require_positive_int(
            "max_workers", max_workers, upper=MAX_MAX_WORKERS
        )
        self._max_queued = _require_positive_int(
            "max_queued", max_queued, upper=MAX_MAX_QUEUED
        )
        self._max_error_keys = _require_positive_int(
            "max_error_keys", max_error_keys, upper=MAX_MAX_ERROR_KEYS
        )
        self._idle_timeout_s = _require_positive_float(
            "idle_timeout_s", idle_timeout_s, upper=MAX_IDLE_TIMEOUT_S
        )
        self._capacity = self._max_workers + self._max_queued
        self._slots = threading.BoundedSemaphore(self._capacity)
        self._lock = threading.Lock()
        self._shutdown_mutex = threading.Lock()
        self._accepting = True
        self._shutting_down = False
        self._shutdown_done = False
        self._stop_sent = False
        self._active = 0
        self._queued = 0
        self._error_counts: dict[str, int] = {}
        self._futures: set[Future[Any]] = set()
        # Unique, desensitized prefix for precise ownership audits.
        self._name_prefix = f"{_WORKER_NAME_ROOT}-{secrets.token_hex(4)}"
        self._tasks: queue.SimpleQueue[
            tuple[Future[Any], Callable[..., Any], tuple[Any, ...], dict[str, Any]]
            | None
        ] = queue.SimpleQueue()
        self._workers: list[threading.Thread] = []
        for index in range(self._max_workers):
            thread = threading.Thread(
                target=self._worker_main,
                name=f"{self._name_prefix}_{index}",
                daemon=False,
            )
            thread.start()
            self._workers.append(thread)

    @property
    def max_workers(self) -> int:
        return self._max_workers

    @property
    def max_queued(self) -> int:
        return self._max_queued

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def name_prefix(self) -> str:
        return self._name_prefix

    @property
    def active_count(self) -> int:
        with self._lock:
            return self._active

    @property
    def queued_count(self) -> int:
        with self._lock:
            return self._queued

    @property
    def pending_future_count(self) -> int:
        with self._lock:
            return sum(1 for fut in self._futures if not fut.done())

    @property
    def error_type_key_count(self) -> int:
        with self._lock:
            return len(self._error_counts)

    def error_counts_snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._error_counts)

    def workers_are_non_daemon(self) -> bool:
        return all(not thread.daemon for thread in self._workers)

    @property
    def is_shutdown(self) -> bool:
        with self._lock:
            return self._shutdown_done

    def _note_error_type(self, type_name: str) -> None:
        with self._lock:
            if type_name in self._error_counts:
                current = self._error_counts[type_name]
                self._error_counts[type_name] = min(current + 1, 1_000_000)
                return
            if len(self._error_counts) < self._max_error_keys:
                self._error_counts[type_name] = 1
                return
            overflow = self._error_counts.get("overflow", 0)
            self._error_counts["overflow"] = min(overflow + 1, 1_000_000)

    def _release_slot(self) -> None:
        self._slots.release()

    def _worker_main(self) -> None:
        while True:
            item = self._tasks.get()
            if item is None:
                return
            future, fn, args, kwargs = item
            with self._lock:
                self._queued = max(0, self._queued - 1)
            if not future.set_running_or_notify_cancel():
                # Cancelled before start — consume outcome and free capacity.
                self._finish_future(future)
                continue
            with self._lock:
                self._active += 1
            try:
                result = fn(*args, **kwargs)
            except BaseException as exc:  # noqa: BLE001
                self._note_error_type(type(exc).__name__)
                if not future.cancelled():
                    future.set_exception(exc)
            else:
                if not future.cancelled():
                    future.set_result(result)
            finally:
                with self._lock:
                    self._active -= 1
                self._finish_future(future)

    def _finish_future(self, future: Future[Any]) -> None:
        with self._lock:
            self._futures.discard(future)
        self._release_slot()
        # Consume every outcome so callbacks never leave unretrieved exceptions.
        try:
            if future.done():
                future.result()
        except BaseException:  # noqa: BLE001
            pass

    def submit(self, fn: Callable[..., T], /, *args: Any, **kwargs: Any) -> Future[T]:
        with self._lock:
            if not self._accepting or self._shutdown_done:
                raise PairingStoreExecutorClosedError()
        acquired = self._slots.acquire(blocking=False)
        if not acquired:
            raise PairingStoreSaturatedError()
        future: Future[T] = Future()
        try:
            with self._lock:
                if not self._accepting or self._shutdown_done:
                    raise PairingStoreExecutorClosedError()
                self._futures.add(future)
                self._queued += 1
            self._tasks.put((future, fn, args, kwargs))
        except Exception:
            with self._lock:
                self._futures.discard(future)
                self._queued = max(0, self._queued - 1)
            self._release_slot()
            raise

        def _done(done: Future[Any]) -> None:
            try:
                if done.done():
                    done.result()
            except BaseException:  # noqa: BLE001
                pass

        future.add_done_callback(_done)
        return future

    async def run(
        self,
        fn: Callable[..., T],
        /,
        *args: Any,
        timeout_s: float,
        **kwargs: Any,
    ) -> T:
        if timeout_s <= 0:
            raise TimeoutError("pairing store deadline exceeded")
        future = self.submit(fn, *args, **kwargs)
        try:
            return await asyncio.wait_for(
                asyncio.wrap_future(future),
                timeout=timeout_s,
            )
        except asyncio.TimeoutError as exc:
            # Started work continues; queued work may cancel via Future.cancel.
            future.cancel()
            raise TimeoutError("pairing store deadline exceeded") from exc

    async def run_completion_certain(
        self,
        fn: Callable[..., T],
        /,
        *args: Any,
        **kwargs: Any,
    ) -> T:
        """
        Run an admitted mutation until its worker outcome is final.

        Capacity rejection happens before admission. Once admitted, caller
        cancellation is deferred until the worker result or exception has
        been consumed, preventing a durable commit from becoming a late and
        ambiguous side effect.
        """
        future = self.submit(fn, *args, **kwargs)
        wrapped = asyncio.wrap_future(future)
        try:
            return await asyncio.shield(wrapped)
        except asyncio.CancelledError:
            while not wrapped.done():
                try:
                    await asyncio.shield(wrapped)
                except asyncio.CancelledError:
                    continue
                except BaseException:  # noqa: BLE001
                    break
            if wrapped.done() and not wrapped.cancelled():
                try:
                    wrapped.result()
                except BaseException:  # noqa: BLE001
                    pass
            raise

    def _shutdown_invariants_met(self) -> bool:
        return (
            self.active_count == 0
            and self.queued_count == 0
            and self.pending_future_count == 0
            and self.worker_thread_count() == 0
        )

    def _wait_until_idle(self, *, timeout_s: float) -> bool:
        """Return True when idle; False on timeout (never silently succeed)."""
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            with self._lock:
                if self._active == 0 and all(fut.done() for fut in self._futures):
                    return True
            time.sleep(0.01)
        return False

    def shutdown(self, *, wait: bool = True, cancel_queued: bool = True) -> None:
        # Fail-fast before any executor state mutation.
        if wait is not True:
            raise ValueError("wait must be True; non-waiting shutdown is not supported")

        with self._shutdown_mutex:
            with self._lock:
                if self._shutdown_done:
                    return
                self._accepting = False
                self._shutting_down = True

            if cancel_queued:
                with self._lock:
                    pending = [fut for fut in self._futures if not fut.done()]
                for fut in pending:
                    fut.cancel()

            if not self._wait_until_idle(timeout_s=self._idle_timeout_s):
                raise RuntimeError("pairing store executor idle wait timed out")

            if not self._stop_sent:
                for _ in self._workers:
                    self._tasks.put(None)
                self._stop_sent = True

            join_deadline = time.monotonic() + self._idle_timeout_s
            for thread in self._workers:
                remaining = max(0.0, join_deadline - time.monotonic())
                thread.join(timeout=remaining)

            if not self._shutdown_invariants_met():
                raise RuntimeError("pairing store executor shutdown incomplete")

            with self._lock:
                self._shutdown_done = True

    def worker_thread_count(self) -> int:
        """Alive threads owned by this executor instance."""
        return sum(1 for thread in self._workers if thread.is_alive())
