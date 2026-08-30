from __future__ import annotations

import asyncio
import json
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from steward_hub.api import (
    AuthorizationChangedError,
    _next_event_or_disconnect,
    create_app,
)
from steward_hub.models import ConversationEvent
from steward_hub.store import EventStore
from steward_hub.subscriptions import (
    SubscriptionManager,
    SubscriptionOverflowError,
)


def sample_event(sequence: int) -> ConversationEvent:
    payload_json = json.dumps(
        {
            "accepted_seq": sequence,
            "client_message_id": f"client-{sequence}",
            "content": f"content-{sequence}",
            "message_id": f"message-{sequence}",
            "role": "user",
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    return ConversationEvent(
        event_id=f"event-{sequence}",
        protocol_version=1,
        event_type="conversation.message.accepted",
        conversation_id="conversation",
        conversation_seq=sequence,
        actor_device_id="windows",
        causation_id=f"client-{sequence}",
        correlation_id="conversation",
        occurred_at="2026-07-28T00:00:00.000Z",
        payload_json=payload_json,
        payload_sha256="0" * 64,
    )


class SubscriptionManagerTest(unittest.IsolatedAsyncioTestCase):
    async def test_two_subscribers_receive_the_same_committed_event(self) -> None:
        manager = SubscriptionManager(queue_size=4)
        first = await manager.register("conversation")
        second = await manager.register("conversation")
        event = sample_event(1)

        await manager.publish(event)

        self.assertEqual(event, await manager.next_event(first))
        self.assertEqual(event, await manager.next_event(second))
        await manager.unregister(first)
        await manager.unregister(second)
        self.assertEqual(0, manager.subscriber_count)

    async def test_bounded_queue_overflow_fails_closed(self) -> None:
        manager = SubscriptionManager(queue_size=1)
        subscription = await manager.register("conversation")

        await manager.publish(sample_event(1))
        await manager.publish(sample_event(2))

        self.assertTrue(subscription.overflowed.is_set())
        self.assertEqual(0, manager.subscriber_count)
        with self.assertRaises(SubscriptionOverflowError):
            await manager.next_event(subscription)

    async def test_unregister_is_idempotent(self) -> None:
        manager = SubscriptionManager(queue_size=1)
        subscription = await manager.register("conversation")

        await manager.unregister(subscription)
        await manager.unregister(subscription)

        self.assertEqual(0, manager.subscriber_count)

    async def test_parent_cancellation_drains_next_event_tasks(self) -> None:
        manager = SubscriptionManager(queue_size=1)
        subscription = await manager.register("conversation")
        created: list[asyncio.Task[object]] = []
        original_create_task = asyncio.create_task

        def track_task(coroutine):
            task = original_create_task(coroutine)
            created.append(task)
            return task

        waiter: asyncio.Task[ConversationEvent] | None = None
        try:
            with patch(
                "steward_hub.subscriptions.asyncio.create_task",
                side_effect=track_task,
            ):
                waiter = original_create_task(manager.next_event(subscription))
                await asyncio.sleep(0)
                self.assertEqual(2, len(created))
                waiter.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await waiter
                await asyncio.sleep(0)
                self.assertTrue(all(task.done() for task in created))
        finally:
            if waiter is not None and not waiter.done():
                waiter.cancel()
            for task in created:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*created, return_exceptions=True)
            await manager.unregister(subscription)

    async def test_parent_cancellation_drains_websocket_wait_tasks(self) -> None:
        manager = SubscriptionManager(queue_size=1)
        subscription = await manager.register("conversation")
        created: list[asyncio.Task[object]] = []
        original_create_task = asyncio.create_task

        class BlockingWebSocket:
            async def receive(self):
                await asyncio.Future()

        class BlockingSubscriptions:
            async def next_event(self, _: object):
                await asyncio.Future()

        def track_task(coroutine):
            task = original_create_task(coroutine)
            created.append(task)
            return task

        waiter: asyncio.Task[ConversationEvent] | None = None
        try:
            with patch(
                "steward_hub.api.asyncio.create_task",
                side_effect=track_task,
            ):
                waiter = original_create_task(
                    _next_event_or_disconnect(
                        BlockingWebSocket(),  # type: ignore[arg-type]
                        BlockingSubscriptions(),  # type: ignore[arg-type]
                        subscription,
                    )
                )
                await asyncio.sleep(0)
                self.assertEqual(2, len(created))
                waiter.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await waiter
                await asyncio.sleep(0)
                self.assertTrue(all(task.done() for task in created))
        finally:
            if waiter is not None and not waiter.done():
                waiter.cancel()
            for task in created:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*created, return_exceptions=True)
            await manager.unregister(subscription)

    async def test_authorization_change_wins_over_simultaneous_event(self) -> None:
        manager = SubscriptionManager(queue_size=1)
        subscription = await manager.register("conversation")

        class BlockingWebSocket:
            async def receive(self):
                await asyncio.Future()

        async def already_changed() -> None:
            return None

        authorization_task = asyncio.create_task(already_changed())
        await authorization_task
        await manager.publish(sample_event(1))
        try:
            with self.assertRaises(AuthorizationChangedError):
                await _next_event_or_disconnect(
                    BlockingWebSocket(),  # type: ignore[arg-type]
                    manager,
                    subscription,
                    authorization_changed_task=authorization_task,
                )
        finally:
            await manager.unregister(subscription)

    async def test_endpoint_cancellation_unregisters_subscription(self) -> None:
        manager = SubscriptionManager(queue_size=1)
        ready = asyncio.Event()

        class FakeConversation:
            next_seq = 1

        class FakeStore:
            def get_conversation(self, _: str) -> FakeConversation:
                return FakeConversation()

            def replay_events(self, **_: object) -> list[ConversationEvent]:
                return []

        class BlockingWebSocket:
            async def accept(self) -> None:
                return None

            async def send_json(self, message: dict[str, object]) -> None:
                if message.get("kind") == "ready":
                    ready.set()

            async def receive(self):
                await asyncio.Future()

            async def close(self, **_: object) -> None:
                return None

        app = create_app(
            event_store=FakeStore(),  # type: ignore[arg-type]
            subscription_manager=manager,
        )
        endpoint = next(
            route.endpoint
            for route in app.routes
            if getattr(route, "path", None)
            == "/v1/conversations/{conversation_id}/events/ws"
        )
        task = asyncio.create_task(
            endpoint(BlockingWebSocket(), "conversation", 0)
        )
        try:
            await asyncio.wait_for(ready.wait(), timeout=1)
            self.assertEqual(1, manager.subscriber_count)
            task.cancel()
            self.assertIsNone(await task)
            self.assertFalse(task.cancelled())
            self.assertEqual(0, manager.subscriber_count)
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)


class WebSocketTransportTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = (
            Path(self._temporary_directory.name) / "websocket.sqlite3"
        )
        self.store = EventStore(self.database_path)
        self.subscriptions = SubscriptionManager(queue_size=64)
        self.app = create_app(
            event_store=self.store,
            subscription_manager=self.subscriptions,
        )
        self.client = TestClient(self.app)
        self.client.__enter__()
        self.conversation_id = "websocket-conversation"
        response = self.client.post(
            "/v1/conversations",
            json={
                "title": "WebSocket shared session",
                "conversation_id": self.conversation_id,
            },
        )
        self.assertEqual(201, response.status_code)

    def tearDown(self) -> None:
        self.client.__exit__(None, None, None)
        self.store.close()
        self._temporary_directory.cleanup()

    def append(
        self,
        number: int,
        *,
        actor: str = "windows",
    ):
        return self.client.post(
            f"/v1/conversations/{self.conversation_id}/messages",
            json={
                "client_message_id": f"ws-client-{number}",
                "actor_device_id": actor,
                "role": "user",
                "content": f"ws-content-{number}",
            },
        )

    def test_websocket_sends_replay_then_ready_then_live(self) -> None:
        self.append(1)
        self.append(2, actor="phone")

        with self.client.websocket_connect(
            f"/v1/conversations/{self.conversation_id}/events/ws?after_seq=0"
        ) as websocket:
            replay_one = websocket.receive_json()
            replay_two = websocket.receive_json()
            ready = websocket.receive_json()
            self.append(3, actor="pad")
            live = websocket.receive_json()

        self.assertEqual(("event", "replay"), (
            replay_one["kind"],
            replay_one["delivery"],
        ))
        self.assertEqual(("event", "replay"), (
            replay_two["kind"],
            replay_two["delivery"],
        ))
        self.assertEqual(
            [1, 2],
            [
                replay_one["event"]["conversation_seq"],
                replay_two["event"]["conversation_seq"],
            ],
        )
        self.assertEqual(
            {"kind": "ready", "last_conversation_seq": 2},
            ready,
        )
        self.assertEqual("live", live["delivery"])
        self.assertEqual(3, live["event"]["conversation_seq"])

    def test_two_websocket_clients_receive_identical_live_event(self) -> None:
        path = (
            f"/v1/conversations/{self.conversation_id}/events/ws?after_seq=0"
        )
        with self.client.websocket_connect(path) as first:
            with self.client.websocket_connect(path) as second:
                self.assertEqual("ready", first.receive_json()["kind"])
                self.assertEqual("ready", second.receive_json()["kind"])
                response = self.append(1, actor="phone")
                first_event = first.receive_json()
                second_event = second.receive_json()

        self.assertEqual(201, response.status_code)
        self.assertEqual(first_event["event"], second_event["event"])

    def test_replay_live_boundary_has_no_gap_or_duplicate(self) -> None:
        replay_started = threading.Event()
        allow_replay = threading.Event()
        original_replay = self.store.replay_events
        first_call = True
        call_lock = threading.Lock()

        def blocking_replay(**arguments):
            nonlocal first_call
            with call_lock:
                should_block = first_call
                first_call = False
            if should_block:
                replay_started.set()
                if not allow_replay.wait(timeout=3):
                    raise RuntimeError("bounded replay wait expired")
            return original_replay(**arguments)

        self.store.replay_events = blocking_replay  # type: ignore[method-assign]
        path = (
            f"/v1/conversations/{self.conversation_id}/events/ws?after_seq=0"
        )
        with self.client.websocket_connect(path) as websocket:
            self.assertTrue(replay_started.wait(timeout=2))
            self.assertEqual(201, self.append(1).status_code)
            allow_replay.set()
            replay = websocket.receive_json()
            ready = websocket.receive_json()
            self.assertEqual(201, self.append(2).status_code)
            live = websocket.receive_json()

        self.assertEqual(1, replay["event"]["conversation_seq"])
        self.assertEqual(1, ready["last_conversation_seq"])
        self.assertEqual(2, live["event"]["conversation_seq"])

    def test_duplicate_rest_request_does_not_publish_second_live_event(
        self,
    ) -> None:
        path = (
            f"/v1/conversations/{self.conversation_id}/events/ws?after_seq=0"
        )
        with self.client.websocket_connect(path) as websocket:
            websocket.receive_json()
            first = self.append(1)
            live = websocket.receive_json()
            duplicate = self.append(1)

            self.assertEqual(1, self.subscriptions.published_count)
            self.assertEqual(0, self.subscriptions.queued_event_count)

        self.assertEqual(201, first.status_code)
        self.assertEqual(200, duplicate.status_code)
        self.assertEqual(1, live["event"]["conversation_seq"])
        replay = self.client.get(
            f"/v1/conversations/{self.conversation_id}/events",
            params={"after_seq": 0, "limit": 10},
        )
        self.assertEqual(1, len(replay.json()["events"]))

    def test_disconnect_removes_subscription(self) -> None:
        path = (
            f"/v1/conversations/{self.conversation_id}/events/ws?after_seq=0"
        )
        with self.client.websocket_connect(path) as websocket:
            websocket.receive_json()
            self.assertEqual(1, self.subscriptions.subscriber_count)

        deadline = time.monotonic() + 2
        while (
            self.subscriptions.subscriber_count != 0
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        self.assertEqual(0, self.subscriptions.subscriber_count)

    def test_websocket_rejects_cursor_ahead_without_subscription(self) -> None:
        self.append(1)
        path = (
            f"/v1/conversations/{self.conversation_id}/events/ws"
            "?after_seq=999"
        )

        with self.client.websocket_connect(path) as websocket:
            error = websocket.receive_json()
            with self.assertRaises(WebSocketDisconnect) as context:
                websocket.receive_json()

        self.assertEqual(
            {
                "kind": "error",
                "error": {
                    "code": "cursor_ahead",
                    "message": "replay cursor exceeds server state",
                    "server_last_conversation_seq": 1,
                },
            },
            error,
        )
        self.assertEqual(1008, context.exception.code)
        self.assertEqual(0, self.subscriptions.subscriber_count)

    def test_websocket_correct_cursor_recovers_after_rejection(self) -> None:
        self.append(1)
        ahead_path = (
            f"/v1/conversations/{self.conversation_id}/events/ws"
            "?after_seq=999"
        )
        with self.client.websocket_connect(ahead_path) as websocket:
            websocket.receive_json()
            with self.assertRaises(WebSocketDisconnect):
                websocket.receive_json()

        correct_path = (
            f"/v1/conversations/{self.conversation_id}/events/ws?after_seq=0"
        )
        with self.client.websocket_connect(correct_path) as websocket:
            replay = websocket.receive_json()
            ready = websocket.receive_json()
            self.append(2, actor="phone")
            live = websocket.receive_json()

        self.assertEqual(1, replay["event"]["conversation_seq"])
        self.assertEqual(
            {"kind": "ready", "last_conversation_seq": 1},
            ready,
        )
        self.assertEqual(2, live["event"]["conversation_seq"])
        self.assertEqual(0, self.subscriptions.subscriber_count)

    def test_websocket_corrupt_event_closes_1011_without_delivery(self) -> None:
        self.append(1)
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute(
                """
                UPDATE conversation_event
                SET payload_sha256 = ?
                WHERE conversation_id = ?
                """,
                ("0" * 64, self.conversation_id),
            )
            connection.commit()
        finally:
            connection.close()

        path = (
            f"/v1/conversations/{self.conversation_id}/events/ws?after_seq=0"
        )
        with self.client.websocket_connect(path) as websocket:
            with self.assertRaises(WebSocketDisconnect) as context:
                websocket.receive_json()

        self.assertEqual(1011, context.exception.code)
        self.assertEqual(0, self.subscriptions.subscriber_count)

    def test_overflow_closes_connection_with_replay_required(self) -> None:
        self.subscriptions = SubscriptionManager(queue_size=1)
        self.client.__exit__(None, None, None)
        self.app = create_app(
            event_store=self.store,
            subscription_manager=self.subscriptions,
        )
        self.client = TestClient(self.app)
        self.client.__enter__()

        replay_started = threading.Event()
        allow_replay = threading.Event()
        original_replay = self.store.replay_events

        def blocking_replay(**arguments):
            replay_started.set()
            if not allow_replay.wait(timeout=3):
                raise RuntimeError("bounded replay wait expired")
            return original_replay(**arguments)

        self.store.replay_events = blocking_replay  # type: ignore[method-assign]
        path = (
            f"/v1/conversations/{self.conversation_id}/events/ws?after_seq=0"
        )
        with self.client.websocket_connect(path) as websocket:
            self.assertTrue(replay_started.wait(timeout=2))
            self.append(1)
            self.append(2)
            allow_replay.set()
            websocket.receive_json()
            websocket.receive_json()
            with self.assertRaises(WebSocketDisconnect) as context:
                websocket.receive_json()

        self.assertEqual(1013, context.exception.code)
        self.assertEqual(0, self.subscriptions.subscriber_count)


if __name__ == "__main__":
    unittest.main()
