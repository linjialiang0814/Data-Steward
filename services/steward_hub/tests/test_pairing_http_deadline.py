"""Bounded store executor, deadline, and shutdown lifecycle tests."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import tempfile
import threading
import time
import unittest
from concurrent.futures import CancelledError
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from steward_hub.api import create_app
from steward_hub.pairing_api import shutdown_pairing_store_executor, validate_request_timeout_s
from steward_hub.pairing_store import PairingStore
from steward_hub.pairing_store_executor import (
    PairingStoreExecutor,
    PairingStoreExecutorClosedError,
    PairingStoreSaturatedError,
    list_alive_pairing_worker_threads,
)
from steward_hub.store import EventStore

HUB_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
ATTEMPT = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
PROTOCOL = "pairing_auth/1"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


class BlockingStore:
    """Blocks before touching SQLite so concurrent session creates remain possible."""

    def __init__(self, inner: PairingStore) -> None:
        self._inner = inner
        self.block = threading.Event()
        self.entered = threading.Event()
        self.calls = 0
        self.started_ids: list[str] = []
        self.lock = threading.Lock()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def register_client_hello_digest(self, **kwargs: Any) -> Any:
        with self.lock:
            self.calls += 1
            self.started_ids.append(str(kwargs.get("pairing_attempt_id")))
        self.entered.set()
        self.block.wait(timeout=30.0)
        return self._inner.register_client_hello_digest(**kwargs)


class PairingDeadlineTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "deadline.sqlite3"
        self.clock = lambda: datetime(2026, 7, 30, 5, 0, 0, tzinfo=timezone.utc)
        self.event_store = EventStore(self.db)
        self.pairing = PairingStore(
            self.db, clock=self.clock, auto_start_runtime=False
        )
        self.pairing.initialize_hub_identity(
            hub_id=HUB_ID,
            cert_fingerprint="a" * 64,
            tls_storage_kind="dpapi_encrypted_pkcs8",
            tls_key_ref_id="deadline-ref",
        )
        self.pairing.start_runtime()
        self.ott_raw = b"\x11" * 32
        self.session = self.pairing.create_pairing_session(
            pairing_token_digest=hashlib.sha256(self.ott_raw).hexdigest(),
            ttl_seconds=600,
        )

    def tearDown(self) -> None:
        self.pairing.close()
        self.event_store.close()
        self.tmp.cleanup()

    def _hello_body(self) -> dict[str, object]:
        return {
            "protocol_version": PROTOCOL,
            "pairing_attempt_id": ATTEMPT,
            "pairing_token": _b64url(self.ott_raw),
            "claim_secret": _b64url(b"\x22" * 32),
            "device_credential_digest": hashlib.sha256(b"\x33" * 32).hexdigest(),
            "client_nonce": "AAAAAAAAAAAAAAAAAAAAAA",
            "requested_capabilities": ["session.sync"],
            "platform": "android",
        }

    def test_timeout_config_fail_fast(self) -> None:
        for bad in (0, -1, float("nan"), float("inf"), True):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    validate_request_timeout_s(bad)

    def test_workers_are_non_daemon(self) -> None:
        ex = PairingStoreExecutor(max_workers=2, max_queued=2)
        try:
            self.assertTrue(ex.workers_are_non_daemon())
            for thread in ex._workers:
                self.assertFalse(thread.daemon)
                self.assertTrue(thread.name.startswith("pairing-store-"))
                self.assertTrue(thread.name.startswith(ex.name_prefix))
        finally:
            ex.shutdown(wait=True, cancel_queued=True)
            self.assertEqual(0, ex.worker_thread_count())

    def test_executor_config_and_error_bound(self) -> None:
        with self.assertRaises(ValueError):
            PairingStoreExecutor(max_workers=0)
        with self.assertRaises(ValueError):
            PairingStoreExecutor(max_queued=True)  # type: ignore[arg-type]
        ex = PairingStoreExecutor(max_workers=1, max_queued=1, max_error_keys=2)
        for i in range(5):
            ex._note_error_type(f"E{i}")
        self.assertLessEqual(ex.error_type_key_count, 3)
        self.assertIn("overflow", ex.error_counts_snapshot())
        ex.shutdown(wait=True)
        self.assertEqual(0, ex.worker_thread_count())
        self.assertEqual(0, ex.active_count)
        self.assertEqual(0, ex.queued_count)

    def test_shutdown_idempotent_and_submit_fail_closed(self) -> None:
        ex = PairingStoreExecutor(max_workers=1, max_queued=1)
        ex.shutdown(wait=True, cancel_queued=True)
        ex.shutdown(wait=True, cancel_queued=True)
        self.assertEqual(0, ex.worker_thread_count())
        with self.assertRaises(PairingStoreExecutorClosedError):
            ex.submit(lambda: 1)

    def test_wait_false_fail_fast_then_normal_shutdown(self) -> None:
        ex = PairingStoreExecutor(max_workers=1, max_queued=1)
        try:
            before_workers = ex.worker_thread_count()
            with self.assertRaises(ValueError):
                ex.shutdown(wait=False)
            self.assertFalse(ex.is_shutdown)
            self.assertEqual(before_workers, ex.worker_thread_count())
            # State unchanged: still accepting work.
            self.assertEqual(1, ex.submit(lambda: 1).result(timeout=2.0))
            ex.shutdown(wait=True, cancel_queued=True)
            self.assertTrue(ex.is_shutdown)
            self.assertEqual(0, ex.worker_thread_count())
        finally:
            if not ex.is_shutdown:
                ex.shutdown(wait=True, cancel_queued=True)

    def test_concurrent_shutdown_both_return_after_workers_zero(self) -> None:
        ex = PairingStoreExecutor(max_workers=1, max_queued=1)
        gate = threading.Event()

        def work() -> int:
            gate.wait(timeout=30.0)
            return 1

        future = ex.submit(work)
        deadline = time.monotonic() + 2.0
        while ex.active_count < 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertGreaterEqual(ex.active_count, 1)

        outcomes: list[tuple[int, bool]] = []
        errors: list[BaseException] = []

        def shut() -> None:
            try:
                ex.shutdown(wait=True, cancel_queued=True)
                outcomes.append((ex.worker_thread_count(), ex.is_shutdown))
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        t1 = threading.Thread(target=shut)
        t2 = threading.Thread(target=shut)
        t1.start()
        t2.start()
        time.sleep(0.1)
        gate.set()
        t1.join(timeout=5.0)
        t2.join(timeout=5.0)
        self.assertEqual([], errors)
        self.assertEqual(2, len(outcomes))
        for worker_count, done in outcomes:
            self.assertEqual(0, worker_count)
            self.assertTrue(done)
        self.assertEqual(1, future.result(timeout=2.0))

    def test_idle_timeout_keeps_store_open_then_retry(self) -> None:
        closed = {"value": False}
        original_close = self.pairing.close

        def guarded_close() -> None:
            closed["value"] = True
            original_close()

        self.pairing.close = guarded_close  # type: ignore[method-assign]
        blocking = BlockingStore(self.pairing)
        executor = PairingStoreExecutor(
            max_workers=1, max_queued=1, idle_timeout_s=0.08
        )
        app = create_app(
            event_store=self.event_store,
            pairing_store=blocking,  # type: ignore[arg-type]
            close_pairing_store=True,
            pairing_request_timeout_s=5.0,
            pairing_store_executor=executor,
            pairing_source_key_fn=lambda _r: "idle-to",
        )
        client_cm = TestClient(app)
        client = client_cm.__enter__()
        body = self._hello_body()

        def slow_call() -> None:
            client.post(
                f"/v1/pairing/sessions/{self.session.pairing_session_id}/client_hello",
                headers={"content-type": "application/json"},
                content=json.dumps(body).encode("utf-8"),
            )

        worker = threading.Thread(target=slow_call)
        worker.start()
        self.assertTrue(blocking.entered.wait(timeout=2.0))
        with self.assertRaises(RuntimeError):
            client_cm.__exit__(None, None, None)
        self.assertFalse(executor.is_shutdown)
        self.assertFalse(closed["value"])
        self.assertGreater(executor.worker_thread_count(), 0)

        blocking.block.set()
        worker.join(timeout=5.0)
        asyncio.run(shutdown_pairing_store_executor(app))
        self.assertTrue(executor.is_shutdown)
        self.assertEqual(0, executor.worker_thread_count())
        self.assertFalse(closed["value"])
        # Lifespan did not close store; recreate handle ownership for tearDown.
        self.pairing.close = original_close  # type: ignore[method-assign]

    def test_stalled_body_times_out(self) -> None:
        app = create_app(
            event_store=self.event_store,
            pairing_store=self.pairing,
            pairing_request_timeout_s=0.05,
            pairing_source_key_fn=lambda _r: "stall",
        )
        path = (
            f"/v1/pairing/sessions/{self.session.pairing_session_id}/client_hello"
        ).encode("ascii")
        scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": path.decode("ascii"),
            "raw_path": path,
            "query_string": b"",
            "headers": [(b"content-type", b"application/json")],
            "client": ("stall", 50000),
            "server": ("test", 80),
        }
        state = {"sent": False}

        async def receive() -> dict[str, object]:
            if not state["sent"]:
                state["sent"] = True
                return {
                    "type": "http.request",
                    "body": b'{"protocol_version":"',
                    "more_body": True,
                }
            await asyncio.sleep(3600)
            return {"type": "http.request", "body": b"", "more_body": False}

        messages: list[dict[str, object]] = []

        async def send(message: dict[str, object]) -> None:
            messages.append(message)

        started = time.monotonic()
        try:
            asyncio.run(app(scope, receive, send))
            self.assertLess(time.monotonic() - started, 1.0)
            start = next(m for m in messages if m["type"] == "http.response.start")
            self.assertEqual(503, start["status"])
        finally:
            # Raw ASGI call does not enter lifespan; shut down workers explicitly.
            app.state.pairing_store_executor.shutdown(wait=True, cancel_queued=True)
            self.assertEqual(0, app.state.pairing_store_executor.worker_thread_count())

    def test_store_deadline_and_idempotent_recovery(self) -> None:
        blocking = BlockingStore(self.pairing)
        app = create_app(
            event_store=self.event_store,
            pairing_store=blocking,  # type: ignore[arg-type]
            pairing_request_timeout_s=0.08,
            pairing_store_max_workers=2,
            pairing_store_max_queued=2,
            pairing_source_key_fn=lambda _r: "block",
        )
        with TestClient(app) as client:
            body = self._hello_body()
            started = time.monotonic()
            response = client.post(
                f"/v1/pairing/sessions/{self.session.pairing_session_id}/client_hello",
                headers={"content-type": "application/json"},
                content=json.dumps(body).encode("utf-8"),
            )
            self.assertLess(time.monotonic() - started, 1.0)
            self.assertEqual(503, response.status_code)
            self.assertEqual("pairing_unavailable", response.json()["error_code"])
            self.assertTrue(blocking.entered.wait(timeout=1.0))
            executor = app.state.pairing_store_executor
            blocking.block.set()
            deadline = time.monotonic() + 2.0
            while executor.active_count > 0 and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(0, executor.active_count)
        # Context exit runs lifespan shutdown for the first app.
        self.assertEqual(0, len(list_alive_pairing_worker_threads()))

        retry = create_app(
            event_store=self.event_store,
            pairing_store=self.pairing,
            pairing_source_key_fn=lambda _r: "recover",
        )
        with TestClient(retry) as retry_client:
            recovered = retry_client.post(
                f"/v1/pairing/sessions/{self.session.pairing_session_id}/client_hello",
                headers={"content-type": "application/json"},
                content=json.dumps(self._hello_body()).encode("utf-8"),
            )
            self.assertEqual(200, recovered.status_code)
        self.assertEqual(0, len(list_alive_pairing_worker_threads()))

    def test_saturation_fail_closed_and_thread_cap(self) -> None:
        blocking = BlockingStore(self.pairing)
        app = create_app(
            event_store=self.event_store,
            pairing_store=blocking,  # type: ignore[arg-type]
            pairing_request_timeout_s=3.0,
            pairing_store_max_workers=1,
            pairing_store_max_queued=1,
            pairing_source_key_fn=lambda _r: "sat",
        )
        with TestClient(app) as client:
            body = self._hello_body()
            url = f"/v1/pairing/sessions/{self.session.pairing_session_id}/client_hello"

            def post() -> None:
                client.post(
                    url,
                    headers={"content-type": "application/json"},
                    content=json.dumps(body).encode("utf-8"),
                )

            workers = [threading.Thread(target=post) for _ in range(2)]
            for thread in workers:
                thread.start()
            self.assertTrue(blocking.entered.wait(timeout=2.0))
            third = client.post(
                url,
                headers={"content-type": "application/json"},
                content=json.dumps(body).encode("utf-8"),
            )
            self.assertEqual(503, third.status_code)
            self.assertEqual("pairing_unavailable", third.json()["error_code"])
            executor = app.state.pairing_store_executor
            self.assertLessEqual(executor.active_count, 1)
            self.assertLessEqual(executor.worker_thread_count(), 1)
            blocking.block.set()
            for thread in workers:
                thread.join(timeout=5.0)
        self.assertEqual(0, len(list_alive_pairing_worker_threads()))

    def test_shutdown_waits_active_then_zero_workers(self) -> None:
        blocking = BlockingStore(self.pairing)
        app = create_app(
            event_store=self.event_store,
            pairing_store=blocking,  # type: ignore[arg-type]
            close_pairing_store=False,
            pairing_request_timeout_s=5.0,
            pairing_store_max_workers=1,
            pairing_store_max_queued=1,
            pairing_source_key_fn=lambda _r: "life",
        )
        with TestClient(app) as client:
            body = self._hello_body()
            executor = app.state.pairing_store_executor
            closed_with_active = {"value": False}
            original_close = self.pairing.close

            def guarded_close() -> None:
                closed_with_active["value"] = executor.active_count > 0
                original_close()

            self.pairing.close = guarded_close  # type: ignore[method-assign]

            def slow_call() -> None:
                client.post(
                    f"/v1/pairing/sessions/{self.session.pairing_session_id}/client_hello",
                    headers={"content-type": "application/json"},
                    content=json.dumps(body).encode("utf-8"),
                )

            worker = threading.Thread(target=slow_call)
            worker.start()
            self.assertTrue(blocking.entered.wait(timeout=2.0))
            self.assertGreaterEqual(executor.active_count, 1)

            shut_state = {"done": False}

            def ordered_shutdown() -> None:
                asyncio.run(shutdown_pairing_store_executor(app))
                self.assertEqual(0, executor.active_count)
                self.pairing.close()
                shut_state["done"] = True

            closer = threading.Thread(target=ordered_shutdown)
            closer.start()
            deadline = time.monotonic() + 1.0
            while time.monotonic() < deadline and not closer.is_alive():
                time.sleep(0.01)
            time.sleep(0.15)
            self.assertTrue(closer.is_alive(), "shutdown must block while store call active")
            self.assertFalse(shut_state["done"])
            self.assertFalse(closed_with_active["value"])
            blocking.block.set()
            worker.join(timeout=5.0)
            closer.join(timeout=5.0)
            self.assertTrue(shut_state["done"])
            self.assertFalse(closed_with_active["value"])
            self.assertEqual(0, executor.active_count)
            self.assertEqual(0, executor.worker_thread_count())
            self.pairing = PairingStore(
                self.db, clock=self.clock, auto_start_runtime=False
            )
        # Lifespan exit is idempotent after explicit shutdown.
        self.assertEqual(0, len(list_alive_pairing_worker_threads()))

    def test_close_without_context_is_not_lifespan_evidence(self) -> None:
        app = create_app(
            event_store=self.event_store,
            pairing_store=self.pairing,
            pairing_store_max_workers=1,
            pairing_store_max_queued=1,
            pairing_source_key_fn=lambda _r: "no-life",
        )
        # Intentionally avoid `with TestClient` so lifespan shutdown does not run.
        client = TestClient(app)
        executor = app.state.pairing_store_executor
        self.assertGreater(executor.worker_thread_count(), 0)
        client.close()
        # close() is not lifespan evidence — workers remain until explicit shutdown.
        self.assertGreater(executor.worker_thread_count(), 0)
        executor.shutdown(wait=True, cancel_queued=True)
        self.assertEqual(0, executor.worker_thread_count())
        owned = [
            t
            for t in list_alive_pairing_worker_threads()
            if t.name.startswith(executor.name_prefix)
        ]
        self.assertEqual([], owned)

    def test_multi_app_lifecycle_clears_process_workers(self) -> None:
        apps = []
        for index in range(3):
            apps.append(
                create_app(
                    event_store=self.event_store,
                    pairing_store=self.pairing,
                    pairing_store_max_workers=1,
                    pairing_store_max_queued=1,
                    pairing_source_key_fn=lambda _r, i=index: f"multi-{i}",
                )
            )
        try:
            for app in apps:
                with TestClient(app) as client:
                    response = client.get("/health")
                    self.assertEqual(200, response.status_code)
            self.assertEqual(0, len(list_alive_pairing_worker_threads()))
        finally:
            for app in apps:
                executor = getattr(app.state, "pairing_store_executor", None)
                if isinstance(executor, PairingStoreExecutor):
                    executor.shutdown(wait=True, cancel_queued=True)
            self.assertEqual(0, len(list_alive_pairing_worker_threads()))

    def test_queued_cancelled_on_shutdown_no_start(self) -> None:
        gate = threading.Event()
        started: list[str] = []
        ex = PairingStoreExecutor(max_workers=1, max_queued=2)

        def work(label: str) -> str:
            started.append(label)
            gate.wait(timeout=30.0)
            return label

        first = ex.submit(work, "active")
        deadline = time.monotonic() + 2.0
        while not started and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(["active"], started)
        queued = ex.submit(work, "queued")
        time.sleep(0.05)
        self.assertNotIn("queued", started)

        shut = threading.Thread(
            target=lambda: ex.shutdown(wait=True, cancel_queued=True)
        )
        shut.start()
        time.sleep(0.05)
        gate.set()
        shut.join(timeout=5.0)
        first.result(timeout=2.0)
        self.assertTrue(queued.cancelled() or queued.done())
        if queued.cancelled():
            with self.assertRaises(CancelledError):
                queued.result(timeout=0.1)
        self.assertNotIn("queued", started)
        self.assertEqual(0, ex.worker_thread_count())
        self.assertEqual(0, ex.active_count)
        self.assertEqual(0, ex.queued_count)

    def test_late_errors_consumed_and_bounded(self) -> None:
        ex = PairingStoreExecutor(max_workers=1, max_queued=1, max_error_keys=2)

        def boom() -> None:
            raise RuntimeError("secret-path-must-not-be-kept")

        fut = ex.submit(boom)
        with self.assertRaises(RuntimeError):
            fut.result(timeout=2.0)
        snap = ex.error_counts_snapshot()
        self.assertEqual(1, snap.get("RuntimeError", 0))
        self.assertNotIn("secret-path-must-not-be-kept", json.dumps(snap))
        for i in range(10):
            ex._note_error_type(f"T{i}")
        self.assertLessEqual(ex.error_type_key_count, 3)
        ex.shutdown(wait=True)
        self.assertEqual(0, ex.worker_thread_count())

    def test_direct_saturation_unit(self) -> None:
        gate = threading.Event()
        ex = PairingStoreExecutor(max_workers=1, max_queued=1)

        def block() -> int:
            gate.wait(timeout=30.0)
            return 1

        f1 = ex.submit(block)
        deadline = time.monotonic() + 2.0
        while ex.active_count < 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        f2 = ex.submit(block)
        with self.assertRaises(PairingStoreSaturatedError):
            ex.submit(block)
        gate.set()
        self.assertEqual(1, f1.result(timeout=2.0))
        self.assertEqual(1, f2.result(timeout=2.0))
        ex.shutdown(wait=True)
        self.assertEqual(0, len(list_alive_pairing_worker_threads()))

    def test_temp_dir_removed_after_cleanup(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="pairing-r3-"))
        try:
            db = root / "t.sqlite3"
            store = EventStore(db)
            pairing = PairingStore(db, clock=self.clock, auto_start_runtime=False)
            app = create_app(
                event_store=store,
                pairing_store=pairing,
                pairing_store_max_workers=1,
                pairing_store_max_queued=1,
            )
            with TestClient(app) as client:
                self.assertEqual(200, client.get("/health").status_code)
            pairing.close()
            store.close()
            self.assertEqual(0, len(list_alive_pairing_worker_threads()))
        finally:
            for _ in range(10):
                try:
                    import shutil

                    shutil.rmtree(root)
                    break
                except PermissionError:
                    time.sleep(0.05)
            self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main()
