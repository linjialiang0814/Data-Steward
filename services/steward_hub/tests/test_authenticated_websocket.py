from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from steward_hub.api import _serve_conversation_events, create_app
from steward_hub.authenticated_websocket import (
    WebSocketAuthenticationTerminated,
    authenticate_websocket,
    cleanup_authenticated_websocket,
)
from steward_hub.device_auth import AUTH_MODE_REQUIRED
from steward_hub.device_connection_registry import DeviceConnectionRegistry
from steward_hub.errors import ConversationNotFoundError
from steward_hub.models import Conversation
from steward_hub.pairing_models import AuthVerifyResult
from steward_hub.pairing_store import PairingStore
from steward_hub.pairing_store_executor import PairingStoreExecutor
from steward_hub.store import EventStore
from steward_hub.subscriptions import SubscriptionManager


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _secret(byte: int) -> tuple[str, str]:
    raw = bytes([byte]) * 32
    return (
        base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="),
        hashlib.sha256(raw).hexdigest(),
    )


class _RecordingWebSocket:
    def __init__(self, message: dict[str, object] | None = None) -> None:
        self.scope = {
            "headers": (),
            "query_string": b"after_seq=0",
        }
        self.message = message
        self.accept_count = 0
        self.sent: list[object] = []
        self.closes: list[tuple[int, str | None]] = []

    async def accept(self) -> None:
        self.accept_count += 1

    async def receive(self) -> dict[str, object]:
        if self.message is None:
            raise AssertionError("receive was not expected")
        return self.message

    async def send_json(self, value: object) -> None:
        self.sent.append(value)

    async def close(
        self,
        *,
        code: int = 1000,
        reason: str | None = None,
    ) -> None:
        self.closes.append((code, reason))


class AuthenticatedWebSocketRouteTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self._temporary_directory.name) / "wss.sqlite3"
        self.pairing_store = PairingStore(
            self.database_path,
            auto_start_runtime=False,
        )
        self.pairing_store.initialize_hub_identity(
            hub_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
            cert_fingerprint="a" * 64,
            tls_storage_kind="dpapi_encrypted_pkcs8",
            tls_key_ref_id="test-identity",
        )
        self.secret, credential_digest = _secret(17)
        session = self.pairing_store.create_pairing_session(
            pairing_token_digest=_digest("wss-ott"),
            ttl_seconds=300,
        )
        hello = self.pairing_store.register_client_hello_digest(
            pairing_session_id=session.pairing_session_id,
            pairing_attempt_id="01ARZ3NDEKTSV4RRFFQ69G5FAW",
            pairing_token_digest=_digest("wss-ott"),
            claim_secret_digest=_digest("wss-claim"),
            device_credential_digest=credential_digest,
            client_nonce="AAAAAAAAAAAAAAAAAAAAAA",
            requested_capabilities=["session.sync"],
            display_name="WSS fixture",
            platform="test",
        )
        self.pairing_store.record_hub_confirmation(
            pairing_session_id=session.pairing_session_id,
            pairing_attempt_id="01ARZ3NDEKTSV4RRFFQ69G5FAW",
            granted_capabilities=["session.sync"],
        )
        self.pairing_store.record_client_confirmation_digest(
            pairing_session_id=session.pairing_session_id,
            pairing_attempt_id="01ARZ3NDEKTSV4RRFFQ69G5FAW",
            claim_secret_digest=_digest("wss-claim"),
            short_verification_code=hello.short_verification_code,
        )
        self.device_id = hello.device_id
        self.event_store = EventStore(self.database_path)
        self.app = create_app(
            event_store=self.event_store,
            pairing_store=self.pairing_store,
            business_auth_mode=AUTH_MODE_REQUIRED,
        )
        self.client = TestClient(self.app, raise_server_exceptions=False)
        self.client.__enter__()

    def tearDown(self) -> None:
        self.client.__exit__(None, None, None)
        self.event_store.close()
        self.pairing_store.close()
        self._temporary_directory.cleanup()

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.secret}",
            "X-DataSteward-Protocol": "pairing_auth/1",
            "X-DataSteward-Device-Id": self.device_id,
            "X-DataSteward-Capability-Epoch": "1",
        }

    def _frame(
        self,
        *,
        device_id: str | None = None,
        secret: str | None = None,
    ) -> dict[str, object]:
        return {
            "kind": "auth",
            "protocol_version": "pairing_auth/1",
            "device_id": device_id or self.device_id,
            "capability_epoch": 1,
            "credential": secret or self.secret,
        }

    def _create_conversation(self, suffix: str) -> str:
        conversation_id = f"authenticated-wss-{suffix}"
        response = self.client.post(
            "/v1/conversations",
            headers=self._headers(),
            json={"title": "WSS", "conversation_id": conversation_id},
        )
        self.assertEqual(201, response.status_code, response.text)
        return conversation_id

    def _append(self, conversation_id: str, sequence: int) -> None:
        response = self.client.post(
            f"/v1/conversations/{conversation_id}/messages",
            headers=self._headers(),
            json={
                "client_message_id": f"wss-client-{sequence}",
                "actor_device_id": self.device_id,
                "role": "user",
                "content": f"wss-content-{sequence}",
            },
        )
        self.assertEqual(201, response.status_code, response.text)

    def _failure(
        self,
        *,
        path: str,
        frame: dict[str, object] | None,
        headers: dict[str, str] | None = None,
    ) -> tuple[dict[str, object], int]:
        with self.client.websocket_connect(path, headers=headers or {}) as websocket:
            if frame is not None:
                websocket.send_json(frame)
            failure = websocket.receive_json()
            with self.assertRaises(WebSocketDisconnect) as context:
                websocket.receive_json()
        return failure, context.exception.code

    def test_auth_ok_precedes_replay_ready_and_live(self) -> None:
        conversation_id = self._create_conversation("ordering")
        self._append(conversation_id, 1)
        path = f"/v1/conversations/{conversation_id}/events/ws?after_seq=0"
        with self.client.websocket_connect(path) as websocket:
            websocket.send_json(self._frame())
            auth_ok = websocket.receive_json()
            replay = websocket.receive_json()
            ready = websocket.receive_json()
            self._append(conversation_id, 2)
            live = websocket.receive_json()

            self.assertEqual("auth_ok", auth_ok["kind"])
            self.assertEqual(("event", "replay", 1), (
                replay["kind"],
                replay["delivery"],
                replay["event"]["conversation_seq"],
            ))
            self.assertEqual(
                {"kind": "ready", "last_conversation_seq": 1},
                ready,
            )
            self.assertEqual(("event", "live", 2), (
                live["kind"],
                live["delivery"],
                live["event"]["conversation_seq"],
            ))

    def test_invalid_auth_has_zero_business_access_and_redacts_input(self) -> None:
        wrong_secret, _ = _secret(18)
        with (
            patch.object(
                self.event_store,
                "get_conversation",
                wraps=self.event_store.get_conversation,
            ) as lookup,
            patch.object(
                self.app.state.subscriptions,
                "register",
                wraps=self.app.state.subscriptions.register,
            ) as register,
        ):
            failure, code = self._failure(
                path="/v1/conversations/private-name/events/ws?after_seq=0",
                frame=self._frame(secret=wrong_secret),
            )
        self.assertEqual(
            {
                "kind": "auth_failed",
                "error_code": "auth_invalid",
                "message_key": "auth.auth_invalid",
            },
            failure,
        )
        self.assertEqual(1008, code)
        self.assertEqual(0, lookup.call_count)
        self.assertEqual(0, register.call_count)
        self.assertNotIn(wrong_secret, str(failure))
        self.assertNotIn("private-name", str(failure))

    def test_wrong_and_unknown_credentials_are_indistinguishable(self) -> None:
        wrong_secret, _ = _secret(19)
        wrong = self._failure(
            path="/v1/conversations/hidden/events/ws?after_seq=0",
            frame=self._frame(secret=wrong_secret),
        )
        unknown = self._failure(
            path="/v1/conversations/hidden/events/ws?after_seq=0",
            frame=self._frame(
                device_id="01ARZ3NDEKTSV4RRFFQ69G5FAZ",
                secret=wrong_secret,
            ),
        )
        self.assertEqual(wrong, unknown)

    def test_upgrade_authorization_and_noncanonical_query_are_rejected(self) -> None:
        header_failure = self._failure(
            path="/v1/conversations/hidden/events/ws?after_seq=0",
            frame=None,
            headers={"Authorization": f"Bearer {self.secret}"},
        )
        query_failure = self._failure(
            path="/v1/conversations/hidden/events/ws?after_seq=00",
            frame=None,
        )
        extra_failure = self._failure(
            path="/v1/conversations/hidden/events/ws?after_seq=0&extra=x",
            frame=None,
        )
        expected = (
            {
                "kind": "auth_failed",
                "error_code": "policy_violation",
                "message_key": "auth.policy_violation",
            },
            1008,
        )
        self.assertEqual(expected, header_failure)
        self.assertEqual(expected, query_failure)
        self.assertEqual(expected, extra_failure)

    def test_stalled_first_frame_times_out_and_releases_handshake(self) -> None:
        self.app.state.websocket_auth_timeout_s = 0.02
        failure, code = self._failure(
            path="/v1/conversations/hidden/events/ws?after_seq=0",
            frame=None,
        )
        self.assertEqual("auth_invalid", failure["error_code"])
        self.assertEqual(1008, code)
        snapshot = self.client.portal.call(
            self.app.state.device_connection_registry.snapshot
        )
        self.assertEqual(0, snapshot.handshake_count)
        self.assertEqual(0, snapshot.connection_count)

    def test_post_auth_client_data_closes_policy_violation(self) -> None:
        conversation_id = self._create_conversation("post-auth")
        path = f"/v1/conversations/{conversation_id}/events/ws?after_seq=0"
        with self.client.websocket_connect(path) as websocket:
            websocket.send_json(self._frame())
            self.assertEqual("auth_ok", websocket.receive_json()["kind"])
            self.assertEqual("ready", websocket.receive_json()["kind"])
            websocket.send_json({"kind": "client-data-is-forbidden"})
            with self.assertRaises(WebSocketDisconnect) as context:
                websocket.receive_json()
        self.assertEqual(1008, context.exception.code)

    def test_synthetic_authorization_transition_closes_and_unregisters(self) -> None:
        conversation_id = self._create_conversation("transition")
        path = f"/v1/conversations/{conversation_id}/events/ws?after_seq=0"
        outcome: dict[str, object] = {}

        async def transition() -> str:
            return "transitioned"

        async def run_transition() -> None:
            outcome["result"] = await (
                self.app.state.device_connection_registry.transition_and_close(
                    device_id=self.device_id,
                    transition=transition,
                )
            )

        with self.client.websocket_connect(path) as websocket:
            websocket.send_json(self._frame())
            self.assertEqual("auth_ok", websocket.receive_json()["kind"])
            self.assertEqual("ready", websocket.receive_json()["kind"])
            worker = threading.Thread(
                target=lambda: self.client.portal.call(run_transition),
                daemon=False,
            )
            worker.start()
            with self.assertRaises(WebSocketDisconnect) as context:
                websocket.receive_json()
            worker.join(timeout=5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(1008, context.exception.code)
        result = outcome["result"]
        self.assertEqual(
            1,
            result.closed_connection_count,  # type: ignore[attr-defined]
        )
        snapshot = self.client.portal.call(
            self.app.state.device_connection_registry.snapshot
        )
        self.assertEqual(0, snapshot.connection_count)
        self.assertEqual(0, self.app.state.subscriptions.subscriber_count)

    def test_loopback_mode_rejects_registry_injection(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            "loopback registry requires operator transitions",
        ):
            create_app(
                event_store=self.event_store,
                device_connection_registry=DeviceConnectionRegistry(),
            )

    def test_authenticated_mode_rejects_invalid_registry_injection(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            "device_connection_registry is invalid",
        ):
            create_app(
                event_store=self.event_store,
                pairing_store=self.pairing_store,
                business_auth_mode=AUTH_MODE_REQUIRED,
                device_connection_registry=object(),  # type: ignore[arg-type]
            )


class AuthenticatedWebSocketCancellationTest(unittest.IsolatedAsyncioTestCase):
    async def test_cancellation_during_first_frame_wait_releases_permit(self) -> None:
        receive_started = asyncio.Event()

        class BlockingWebSocket:
            scope = {
                "headers": (),
                "query_string": b"after_seq=0",
            }

            async def accept(self) -> None:
                return None

            async def receive(self) -> dict[str, object]:
                receive_started.set()
                await asyncio.Future()
                raise AssertionError("unreachable")

            async def send_json(self, _value: object) -> None:
                return None

            async def close(self, **_kwargs: object) -> None:
                return None

        registry = DeviceConnectionRegistry()
        task = asyncio.create_task(
            authenticate_websocket(
                BlockingWebSocket(),  # type: ignore[arg-type]
                after_seq=0,
                pairing_store=object(),  # type: ignore[arg-type]
                store_executor=object(),  # type: ignore[arg-type]
                registry=registry,
                auth_timeout_s=10,
            )
        )
        await asyncio.wait_for(receive_started.wait(), timeout=1)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        snapshot = await registry.snapshot()
        self.assertEqual(0, snapshot.handshake_count)
        self.assertEqual(0, snapshot.connection_count)

    async def test_raw_first_frame_is_cleared_before_store_verification(self) -> None:
        secret, _digest_value = _secret(23)
        device_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
        message: dict[str, object] = {
            "type": "websocket.receive",
            "text": json.dumps(
                {
                    "kind": "auth",
                    "protocol_version": "pairing_auth/1",
                    "device_id": device_id,
                    "capability_epoch": 1,
                    "credential": secret,
                }
            ),
        }
        websocket = _RecordingWebSocket(message)
        verification_observed_cleared_message = False

        class StubStore:
            def verify_active_credential_digest(self, **_kwargs: object) -> None:
                raise AssertionError("executor must own the store call")

        class StubExecutor:
            async def run(
                self,
                _operation: object,
                **_kwargs: object,
            ) -> AuthVerifyResult:
                nonlocal verification_observed_cleared_message
                verification_observed_cleared_message = message == {}
                return AuthVerifyResult(
                    device_id=device_id,
                    hub_id="01ARZ3NDEKTSV4RRFFQ69G5FAW",
                    status="ACTIVE",
                    capability_epoch=1,
                    granted_capabilities=["session.sync"],
                    display_name=None,
                    platform="test",
                )

        registry = DeviceConnectionRegistry()
        context = await authenticate_websocket(
            websocket,  # type: ignore[arg-type]
            after_seq=0,
            pairing_store=StubStore(),  # type: ignore[arg-type]
            store_executor=StubExecutor(),  # type: ignore[arg-type]
            registry=registry,
            auth_timeout_s=1,
        )
        try:
            self.assertTrue(verification_observed_cleared_message)
            self.assertEqual({}, message)
            self.assertEqual(
                "auth_ok",
                websocket.sent[0]["kind"],  # type: ignore[index]
            )
        finally:
            await cleanup_authenticated_websocket(context)
        snapshot = await registry.snapshot()
        self.assertEqual(0, snapshot.handshake_count)
        self.assertEqual(0, snapshot.connection_count)

    async def test_raw_first_frame_is_cleared_on_decode_failure(self) -> None:
        message: dict[str, object] = {
            "type": "websocket.receive",
            "text": json.dumps(
                {
                    "kind": "auth",
                    "protocol_version": "pairing_auth/1",
                    "device_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
                    "capability_epoch": 1,
                    "credential": "SENSITIVE-RAW-MARKER",
                }
            ),
        }
        websocket = _RecordingWebSocket(message)
        registry = DeviceConnectionRegistry()
        with self.assertRaises(WebSocketAuthenticationTerminated):
            await authenticate_websocket(
                websocket,  # type: ignore[arg-type]
                after_seq=0,
                pairing_store=object(),  # type: ignore[arg-type]
                store_executor=object(),  # type: ignore[arg-type]
                registry=registry,
                auth_timeout_s=1,
            )
        self.assertEqual({}, message)
        self.assertEqual(
            "auth_failed",
            websocket.sent[0]["kind"],  # type: ignore[index]
        )
        snapshot = await registry.snapshot()
        self.assertEqual(0, snapshot.handshake_count)
        self.assertEqual(0, snapshot.connection_count)


class AuthenticatedStreamAuthorizationRaceTest(unittest.IsolatedAsyncioTestCase):
    async def test_auth_change_before_stream_skips_all_business_access(self) -> None:
        class NeverStore:
            def get_conversation(self, _conversation_id: str) -> Conversation:
                raise AssertionError("conversation lookup was not expected")

        websocket = _RecordingWebSocket()
        subscriptions = SubscriptionManager()
        authorization_changed = asyncio.create_task(asyncio.sleep(0))
        await authorization_changed
        await _serve_conversation_events(
            websocket,  # type: ignore[arg-type]
            store=NeverStore(),  # type: ignore[arg-type]
            subscriptions=subscriptions,
            conversation_id="private-conversation",
            after_seq=0,
            transport_accepted=True,
            authorization_changed_task=authorization_changed,
        )
        self.assertEqual([], websocket.sent)
        self.assertEqual([], websocket.closes)
        self.assertEqual(0, subscriptions.subscriber_count)

    async def test_auth_change_during_not_found_lookup_suppresses_4404(self) -> None:
        lookup_started = threading.Event()
        release_lookup = threading.Event()

        class BlockingNotFoundStore:
            def get_conversation(self, _conversation_id: str) -> Conversation:
                lookup_started.set()
                if not release_lookup.wait(timeout=2):
                    raise AssertionError("lookup release timed out")
                raise ConversationNotFoundError()

        websocket = _RecordingWebSocket()
        subscriptions = SubscriptionManager()
        authorization_signal = asyncio.Event()
        authorization_changed = asyncio.create_task(authorization_signal.wait())
        route = asyncio.create_task(
            _serve_conversation_events(
                websocket,  # type: ignore[arg-type]
                store=BlockingNotFoundStore(),  # type: ignore[arg-type]
                subscriptions=subscriptions,
                conversation_id="private-conversation",
                after_seq=0,
                transport_accepted=True,
                authorization_changed_task=authorization_changed,
            )
        )
        try:
            started = await asyncio.to_thread(lookup_started.wait, 1)
            self.assertTrue(started)
            authorization_signal.set()
            await authorization_changed
        finally:
            release_lookup.set()
        await route
        self.assertEqual([], websocket.sent)
        self.assertEqual([], websocket.closes)
        self.assertEqual(0, subscriptions.subscriber_count)

    async def test_auth_change_after_lookup_suppresses_cursor_error(self) -> None:
        loop = asyncio.get_running_loop()
        authorization_signal = asyncio.Event()
        authorization_observed = threading.Event()

        async def observe_authorization_change() -> None:
            await authorization_signal.wait()
            authorization_observed.set()

        authorization_changed = asyncio.create_task(observe_authorization_change())

        class TransitioningStore:
            def get_conversation(self, conversation_id: str) -> Conversation:
                loop.call_soon_threadsafe(authorization_signal.set)
                if not authorization_observed.wait(timeout=2):
                    raise AssertionError("authorization transition timed out")
                return Conversation(
                    conversation_id=conversation_id,
                    title="private",
                    next_seq=1,
                    created_at="2026-08-01T00:00:00Z",
                    updated_at="2026-08-01T00:00:00Z",
                )

        websocket = _RecordingWebSocket()
        subscriptions = SubscriptionManager()
        await _serve_conversation_events(
            websocket,  # type: ignore[arg-type]
            store=TransitioningStore(),  # type: ignore[arg-type]
            subscriptions=subscriptions,
            conversation_id="private-conversation",
            after_seq=1,
            transport_accepted=True,
            authorization_changed_task=authorization_changed,
        )
        self.assertEqual([], websocket.sent)
        self.assertEqual([], websocket.closes)
        self.assertEqual(0, subscriptions.subscriber_count)


class AuthenticatedWebSocketLifespanTest(unittest.IsolatedAsyncioTestCase):
    async def test_registry_shutdown_failure_still_closes_workers_and_stores(
        self,
    ) -> None:
        events: list[str] = []

        class FailingRegistry(DeviceConnectionRegistry):
            async def stop_accepting_and_close_all(self, **_kwargs: object) -> None:
                events.append("registry")
                raise RuntimeError("registry_shutdown_failed")

        class RecordingExecutor(PairingStoreExecutor):
            def shutdown(
                self,
                *,
                wait: bool = True,
                cancel_queued: bool = True,
            ) -> None:
                events.append("executor")
                super().shutdown(wait=wait, cancel_queued=cancel_queued)

        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            pairing_store = PairingStore(
                root_path / "pairing.sqlite3",
                auto_start_runtime=False,
            )
            executor = RecordingExecutor(max_workers=1, max_queued=1)
            app = create_app(
                database_path=root_path / "events.sqlite3",
                pairing_store=pairing_store,
                close_pairing_store=True,
                pairing_store_executor=executor,
                business_auth_mode=AUTH_MODE_REQUIRED,
                device_connection_registry=FailingRegistry(),
            )
            event_store = app.state.event_store
            original_pairing_close = pairing_store.close
            original_event_close = event_store.close

            def close_pairing_store() -> None:
                events.append("pairing_store")
                original_pairing_close()

            def close_event_store() -> None:
                events.append("event_store")
                original_event_close()

            with (
                patch.object(pairing_store, "close", side_effect=close_pairing_store),
                patch.object(event_store, "close", side_effect=close_event_store),
                self.assertRaisesRegex(RuntimeError, "registry_shutdown_failed"),
            ):
                async with app.router.lifespan_context(app):
                    pass

            self.assertEqual(
                ["registry", "executor", "pairing_store", "event_store"],
                events,
            )
            self.assertEqual(0, executor.worker_thread_count())


if __name__ == "__main__":
    unittest.main()
