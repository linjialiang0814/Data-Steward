from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from fastapi.testclient import TestClient

from steward_hub.api import create_app, wire_event
from steward_hub.errors import PersistenceError
from steward_hub.store import EventStore
from steward_hub.subscriptions import SubscriptionManager


class ApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = (
            Path(self._temporary_directory.name) / "transport.sqlite3"
        )
        self.store = EventStore(self.database_path)
        self.subscriptions = SubscriptionManager(queue_size=32)
        self.app = create_app(
            event_store=self.store,
            subscription_manager=self.subscriptions,
        )
        self.client = TestClient(
            self.app,
            raise_server_exceptions=False,
        )
        self.client.__enter__()

    def tearDown(self) -> None:
        self.client.__exit__(None, None, None)
        self.store.close()
        self._temporary_directory.cleanup()

    def create_conversation(self, suffix: str = "primary") -> str:
        conversation_id = f"api-conversation-{suffix}"
        response = self.client.post(
            "/v1/conversations",
            json={
                "title": "API shared session",
                "conversation_id": conversation_id,
            },
        )
        self.assertEqual(201, response.status_code)
        return conversation_id

    def append_body(
        self,
        number: int,
        *,
        actor: str = "windows",
        content: str | None = None,
    ) -> dict[str, str]:
        return {
            "client_message_id": f"api-client-{number}",
            "actor_device_id": actor,
            "role": "user",
            "content": content or f"api-message-{number}",
        }

    def test_health_response_is_minimal_and_sanitized(self) -> None:
        response = self.client.get("/health")

        self.assertEqual(200, response.status_code)
        self.assertEqual(
            {
                "status": "ok",
                "protocol_version": 1,
                "database_ready": True,
                "transport_scope": "loopback_only",
            },
            response.json(),
        )
        self.assertNotIn(str(self.database_path), response.text)

    def test_create_conversation(self) -> None:
        conversation_id = self.create_conversation()

        response = self.client.post(
            "/v1/conversations",
            json={"title": "Generated identifier"},
        )

        self.assertEqual(conversation_id, "api-conversation-primary")
        self.assertEqual(201, response.status_code)
        self.assertTrue(response.json()["conversation_id"])
        self.assertEqual(1, response.json()["next_seq"])

    def test_new_message_returns_201_and_broadcasts_once(self) -> None:
        conversation_id = self.create_conversation()

        response = self.client.post(
            f"/v1/conversations/{conversation_id}/messages",
            json=self.append_body(1),
        )

        self.assertEqual(201, response.status_code)
        self.assertFalse(response.json()["deduplicated"])
        self.assertEqual(1, response.json()["event"]["conversation_seq"])
        self.assertEqual(1, self.subscriptions.published_count)

    def test_loopback_compat_preserves_internal_message_roles(self) -> None:
        conversation_id = self.create_conversation("trusted-roles")
        for number, role in enumerate(("assistant", "system", "tool"), start=1):
            body = self.append_body(number)
            body["role"] = role
            response = self.client.post(
                f"/v1/conversations/{conversation_id}/messages",
                json=body,
            )
            self.assertEqual(201, response.status_code, response.text)

        replay = self.client.get(
            f"/v1/conversations/{conversation_id}/events",
        )
        self.assertEqual(
            ["assistant", "system", "tool"],
            [event["payload"]["role"] for event in replay.json()["events"]],
        )

    def test_identical_retry_returns_200_without_second_broadcast(self) -> None:
        conversation_id = self.create_conversation()
        body = self.append_body(1)
        first = self.client.post(
            f"/v1/conversations/{conversation_id}/messages",
            json=body,
        )
        duplicate = self.client.post(
            f"/v1/conversations/{conversation_id}/messages",
            json=body,
        )

        self.assertEqual(201, first.status_code)
        self.assertEqual(200, duplicate.status_code)
        self.assertTrue(duplicate.json()["deduplicated"])
        self.assertEqual(first.json()["event"], duplicate.json()["event"])
        self.assertEqual(1, self.subscriptions.published_count)

    def test_conflicting_retry_returns_409(self) -> None:
        conversation_id = self.create_conversation()
        body = self.append_body(1)
        self.client.post(
            f"/v1/conversations/{conversation_id}/messages",
            json=body,
        )
        body["content"] = "different"

        response = self.client.post(
            f"/v1/conversations/{conversation_id}/messages",
            json=body,
        )

        self.assertEqual(409, response.status_code)
        self.assertEqual(
            "idempotency_conflict",
            response.json()["error"]["code"],
        )

    def test_missing_conversation_returns_404(self) -> None:
        response = self.client.post(
            "/v1/conversations/missing/messages",
            json=self.append_body(1),
        )

        self.assertEqual(404, response.status_code)
        self.assertEqual(
            "conversation_not_found",
            response.json()["error"]["code"],
        )

    def test_validation_errors_do_not_echo_input_or_database_path(self) -> None:
        conversation_id = self.create_conversation()
        sensitive_input = " private-credential-value "

        response = self.client.post(
            f"/v1/conversations/{conversation_id}/messages",
            json=self.append_body(1, actor=sensitive_input),
        )
        query_response = self.client.get(
            f"/v1/conversations/{conversation_id}/events?after_seq=0&limit=0"
        )

        self.assertEqual(400, response.status_code)
        self.assertEqual(422, query_response.status_code)
        self.assertNotIn(sensitive_input, response.text)
        self.assertNotIn(str(self.database_path), response.text)
        self.assertEqual(
            {"error": {
                "code": "validation_error",
                "message": "request validation failed",
            }},
            query_response.json(),
        )

    def test_rest_replay_uses_exclusive_cursor_and_pagination(self) -> None:
        conversation_id = self.create_conversation()
        for number in range(1, 6):
            self.client.post(
                f"/v1/conversations/{conversation_id}/messages",
                json=self.append_body(number),
            )

        response = self.client.get(
            f"/v1/conversations/{conversation_id}/events",
            params={"after_seq": 2, "limit": 2},
        )

        self.assertEqual(200, response.status_code)
        self.assertEqual(
            [3, 4],
            [
                event["conversation_seq"]
                for event in response.json()["events"]
            ],
        )
        self.assertEqual(4, response.json()["last_conversation_seq"])

    def test_rest_rejects_cursor_ahead_with_server_watermark(self) -> None:
        conversation_id = self.create_conversation()
        self.client.post(
            f"/v1/conversations/{conversation_id}/messages",
            json=self.append_body(1, content="private-message-body"),
        )

        response = self.client.get(
            f"/v1/conversations/{conversation_id}/events",
            params={"after_seq": 999, "limit": 10},
        )

        self.assertEqual(409, response.status_code)
        self.assertEqual(
            {
                "error": {
                    "code": "cursor_ahead",
                    "message": "replay cursor exceeds server state",
                    "server_last_conversation_seq": 1,
                }
            },
            response.json(),
        )
        self.assertNotIn(str(self.database_path), response.text)
        self.assertNotIn("private-message-body", response.text)

    def test_rest_accepts_cursor_equal_to_server_watermark(self) -> None:
        conversation_id = self.create_conversation()
        self.client.post(
            f"/v1/conversations/{conversation_id}/messages",
            json=self.append_body(1),
        )

        response = self.client.get(
            f"/v1/conversations/{conversation_id}/events",
            params={"after_seq": 1, "limit": 10},
        )

        self.assertEqual(200, response.status_code)
        self.assertEqual(
            {"events": [], "last_conversation_seq": 1},
            response.json(),
        )

    def test_correct_cursor_recovers_after_cursor_ahead_rejection(self) -> None:
        conversation_id = self.create_conversation()
        self.client.post(
            f"/v1/conversations/{conversation_id}/messages",
            json=self.append_body(1),
        )
        rejected = self.client.get(
            f"/v1/conversations/{conversation_id}/events",
            params={"after_seq": 999, "limit": 10},
        )
        self.client.post(
            f"/v1/conversations/{conversation_id}/messages",
            json=self.append_body(2),
        )

        recovered = self.client.get(
            f"/v1/conversations/{conversation_id}/events",
            params={"after_seq": 1, "limit": 10},
        )

        self.assertEqual(409, rejected.status_code)
        self.assertEqual(200, recovered.status_code)
        self.assertEqual(
            [2],
            [
                event["conversation_seq"]
                for event in recovered.json()["events"]
            ],
        )
        self.assertEqual(2, recovered.json()["last_conversation_seq"])

    def test_wire_event_payload_is_object_and_hash_is_unchanged(self) -> None:
        conversation_id = self.create_conversation()
        response = self.client.post(
            f"/v1/conversations/{conversation_id}/messages",
            json=self.append_body(1, content="wire-content"),
        )
        event = response.json()["event"]
        payload_json = json.dumps(
            event["payload"],
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )

        self.assertIsInstance(event["payload"], dict)
        self.assertNotIn("payload_json", event)
        self.assertEqual(
            event["payload_sha256"],
            hashlib.sha256(payload_json.encode("utf-8")).hexdigest(),
        )

    def test_wire_event_rejects_payload_hash_mismatch(self) -> None:
        conversation_id = self.create_conversation()
        self.client.post(
            f"/v1/conversations/{conversation_id}/messages",
            json=self.append_body(1),
        )
        event = self.store.replay_events(
            conversation_id=conversation_id,
            after_seq=0,
            limit=10,
        )[0]

        with self.assertRaises(PersistenceError):
            wire_event(replace(event, payload_sha256="0" * 64))

    def test_wire_event_rejects_accepted_seq_mismatch(self) -> None:
        conversation_id = self.create_conversation()
        self.client.post(
            f"/v1/conversations/{conversation_id}/messages",
            json=self.append_body(1),
        )
        event = self.store.replay_events(
            conversation_id=conversation_id,
            after_seq=0,
            limit=10,
        )[0]
        payload = json.loads(event.payload_json)
        payload["accepted_seq"] = 99
        payload_json = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )

        with self.assertRaises(PersistenceError):
            wire_event(
                replace(
                    event,
                    payload_json=payload_json,
                    payload_sha256=hashlib.sha256(
                        payload_json.encode("utf-8")
                    ).hexdigest(),
                )
            )

    def test_corrupt_wire_event_error_is_sanitized(self) -> None:
        conversation_id = self.create_conversation()
        response = self.client.post(
            f"/v1/conversations/{conversation_id}/messages",
            json=self.append_body(1, content="private-corrupt-content"),
        )
        message_id = response.json()["message_id"]
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute(
                """
                UPDATE conversation_event
                SET payload_sha256 = ?
                WHERE conversation_id = ?
                """,
                ("0" * 64, conversation_id),
            )
            connection.commit()
        finally:
            connection.close()

        corrupted = self.client.get(
            f"/v1/conversations/{conversation_id}/events",
            params={"after_seq": 0, "limit": 10},
        )

        self.assertEqual(503, corrupted.status_code)
        self.assertEqual(
            {
                "error": {
                    "code": "persistence_unavailable",
                    "message": "persistence operation failed",
                }
            },
            corrupted.json(),
        )
        for sensitive in (
            "private-corrupt-content",
            message_id,
            "0" * 64,
            str(self.database_path),
        ):
            self.assertNotIn(sensitive, corrupted.text)

    def test_openapi_contains_only_expected_rest_operations(self) -> None:
        paths = self.client.get("/openapi.json").json()["paths"]

        self.assertEqual(
            {
                "/health",
                "/v1/conversations",
                "/v1/conversations/{conversation_id}/messages",
                "/v1/conversations/{conversation_id}/events",
            },
            set(paths),
        )
        serialized = json.dumps(paths).lower()
        self.assertNotIn("file", serialized)
        self.assertNotIn("command", serialized)
        self.assertNotIn("eval", serialized)

    def test_persistence_failure_is_sanitized(self) -> None:
        self.store.close()

        response = self.client.get("/health")

        self.assertEqual(503, response.status_code)
        self.assertEqual(
            "persistence_unavailable",
            response.json()["error"]["code"],
        )
        self.assertNotIn(str(self.database_path), response.text)


if __name__ == "__main__":
    unittest.main()
