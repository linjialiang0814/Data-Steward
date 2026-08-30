from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from services.steward_hub.tool.smoke_shared_session import (
    semantic_projection_hash,
)
from steward_hub import (
    MESSAGE_ACCEPTED_EVENT,
    PROTOCOL_VERSION,
    ConversationNotFoundError,
    EventStore,
    IdempotencyConflictError,
    PersistenceError,
    ValidationError,
)


class EventStoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = (
            Path(self._temporary_directory.name) / "shared-session.sqlite3"
        )
        self.store = EventStore(self.database_path)

    def tearDown(self) -> None:
        self.store.close()
        self._temporary_directory.cleanup()

    def create_conversation(self, suffix: str = "primary") -> str:
        conversation_id = f"conversation-{suffix}"
        self.store.create_conversation(
            "Shared session",
            conversation_id=conversation_id,
        )
        return conversation_id

    def append(
        self,
        conversation_id: str,
        number: int,
        *,
        actor: str = "windows",
        client_message_id: str | None = None,
        content: str | None = None,
    ):
        return self.store.append_message(
            conversation_id=conversation_id,
            client_message_id=client_message_id or f"client-{number}",
            actor_device_id=actor,
            role="user",
            content=content or f"message-{number}",
        )

    def test_create_conversation(self) -> None:
        conversation = self.store.create_conversation(
            "Shared session",
            conversation_id="conversation-create",
        )

        self.assertEqual("conversation-create", conversation.conversation_id)
        self.assertEqual("Shared session", conversation.title)
        self.assertEqual(1, conversation.next_seq)
        self.assertRegex(
            conversation.created_at,
            r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$",
        )
        self.assertEqual(
            conversation,
            self.store.get_conversation("conversation-create"),
        )

    def test_three_devices_alternate_twenty_messages_in_exact_order(self) -> None:
        conversation_id = self.create_conversation()
        devices = ("windows", "phone", "pad")

        results = [
            self.append(
                conversation_id,
                number,
                actor=devices[(number - 1) % len(devices)],
            )
            for number in range(1, 21)
        ]

        self.assertEqual(
            list(range(1, 21)),
            [result.event.conversation_seq for result in results],
        )
        self.assertEqual((20, 20), self.store.count_records(conversation_id))
        self.assertEqual(
            21,
            self.store.get_conversation(conversation_id).next_seq,
        )

    def test_three_client_replays_from_different_cursors_converge(self) -> None:
        conversation_id = self.create_conversation()
        devices = ("windows", "phone", "pad")
        for number in range(1, 21):
            self.append(
                conversation_id,
                number,
                actor=devices[(number - 1) % len(devices)],
            )

        full_events = self.store.replay_events(
            conversation_id=conversation_id,
            after_seq=0,
            limit=100,
        )
        for prefix_length in (0, 6, 13):
            prefix = full_events[:prefix_length]
            cursor = (
                prefix[-1].conversation_seq
                if prefix
                else 0
            )
            replayed = self.store.replay_events(
                conversation_id=conversation_id,
                after_seq=cursor,
                limit=100,
            )
            self.assertEqual(
                full_events,
                prefix + replayed,
            )

    def test_same_sequences_with_changed_prefix_do_not_converge(self) -> None:
        conversation_id = self.create_conversation()
        for number in range(1, 6):
            self.append(conversation_id, number)
        full_events = self.store.replay_events(
            conversation_id=conversation_id,
            after_seq=0,
            limit=10,
        )
        replayed = self.store.replay_events(
            conversation_id=conversation_id,
            after_seq=2,
            limit=10,
        )

        changed_prefixes = (
            [replace(full_events[0], event_id="different-event-id")]
            + full_events[1:2],
            [replace(full_events[0], actor_device_id="phone")]
            + full_events[1:2],
        )
        for changed_prefix in changed_prefixes:
            with self.subTest(changed_event=changed_prefix[0]):
                merged = changed_prefix + replayed
                self.assertEqual(
                    [event.conversation_seq for event in full_events],
                    [event.conversation_seq for event in merged],
                )
                self.assertNotEqual(full_events, merged)

    def test_replay_paginates_without_gaps_or_duplicates(self) -> None:
        conversation_id = self.create_conversation()
        for number in range(1, 21):
            self.append(conversation_id, number)
        full_events = self.store.replay_events(
            conversation_id=conversation_id,
            after_seq=0,
            limit=100,
        )

        cursor = 0
        pages = []
        collected = []
        while True:
            page = self.store.replay_events(
                conversation_id=conversation_id,
                after_seq=cursor,
                limit=7,
            )
            if not page:
                break
            pages.append(page)
            collected.extend(page)
            cursor = page[-1].conversation_seq

        self.assertEqual([7, 7, 6], [len(page) for page in pages])
        self.assertEqual(8, pages[1][0].conversation_seq)
        self.assertEqual(full_events, collected)
        self.assertEqual(
            list(range(1, 21)),
            [event.conversation_seq for event in collected],
        )
        self.assertEqual(
            len(collected),
            len({event.event_id for event in collected}),
        )
        self.assertEqual(
            [],
            self.store.replay_events(
                conversation_id=conversation_id,
                after_seq=cursor,
                limit=7,
            ),
        )

    def test_identical_client_message_is_deduplicated(self) -> None:
        conversation_id = self.create_conversation()
        first = self.append(conversation_id, 1)
        duplicate = self.append(conversation_id, 1)

        self.assertFalse(first.deduplicated)
        self.assertTrue(duplicate.deduplicated)
        self.assertEqual(first.message, duplicate.message)
        self.assertEqual(first.event, duplicate.event)
        self.assertEqual((1, 1), self.store.count_records(conversation_id))
        self.assertEqual(
            2,
            self.store.get_conversation(conversation_id).next_seq,
        )

    def test_reused_client_message_with_changed_input_fails_closed(self) -> None:
        conversation_id = self.create_conversation()
        self.append(conversation_id, 1)

        with self.assertRaises(IdempotencyConflictError):
            self.append(conversation_id, 1, actor="phone")
        with self.assertRaises(IdempotencyConflictError):
            self.append(conversation_id, 1, content="changed")

        self.assertEqual((1, 1), self.store.count_records(conversation_id))
        self.assertEqual(
            2,
            self.store.get_conversation(conversation_id).next_seq,
        )

    def test_after_seq_is_exclusive_and_empty_replay_is_valid(self) -> None:
        conversation_id = self.create_conversation()
        for number in range(1, 4):
            self.append(conversation_id, number)

        events = self.store.replay_events(
            conversation_id=conversation_id,
            after_seq=1,
            limit=10,
        )
        empty = self.store.replay_events(
            conversation_id=conversation_id,
            after_seq=3,
            limit=10,
        )

        self.assertEqual([2, 3], [event.conversation_seq for event in events])
        self.assertEqual([], empty)

    def test_invalid_replay_cursor_limit_and_missing_conversation(self) -> None:
        conversation_id = self.create_conversation()

        for after_seq in (-1, True, 1.5):
            with self.subTest(after_seq=after_seq):
                with self.assertRaises(ValidationError):
                    self.store.replay_events(
                        conversation_id=conversation_id,
                        after_seq=after_seq,
                        limit=10,
                    )
        for limit in (0, 501, True, 1.5):
            with self.subTest(limit=limit):
                with self.assertRaises(ValidationError):
                    self.store.replay_events(
                        conversation_id=conversation_id,
                        after_seq=0,
                        limit=limit,
                    )
        with self.assertRaises(ConversationNotFoundError):
            self.store.replay_events(
                conversation_id="missing-conversation",
                after_seq=0,
                limit=10,
            )

    def test_database_reopen_restores_conversation_and_events(self) -> None:
        conversation_id = self.create_conversation()
        for number in range(1, 6):
            self.append(conversation_id, number)
        expected = self.store.replay_events(
            conversation_id=conversation_id,
            after_seq=0,
            limit=10,
        )
        self.store.close()

        self.store = EventStore(self.database_path)
        restored = self.store.replay_events(
            conversation_id=conversation_id,
            after_seq=0,
            limit=10,
        )

        self.assertEqual(expected, restored)
        self.assertEqual(
            6,
            self.store.get_conversation(conversation_id).next_seq,
        )

    def test_sqlite_safety_pragmas_are_enabled(self) -> None:
        settings = self.store.database_settings()

        self.assertEqual("wal", settings["journal_mode"].lower())
        self.assertEqual(1, settings["foreign_keys"])
        self.assertEqual(5_000, settings["busy_timeout"])

    def test_concurrent_unique_messages_have_contiguous_sequences(self) -> None:
        conversation_id = self.create_conversation()

        def submit(number: int):
            return self.append(
                conversation_id,
                number,
                actor=("windows", "phone", "pad")[number % 3],
            )

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(submit, range(1, 41)))

        sequences = sorted(
            result.event.conversation_seq for result in results
        )
        self.assertEqual(list(range(1, 41)), sequences)
        self.assertEqual((40, 40), self.store.count_records(conversation_id))
        replay = self.store.replay_events(
            conversation_id=conversation_id,
            after_seq=0,
            limit=100,
        )
        self.assertEqual(
            list(range(1, 41)),
            [event.conversation_seq for event in replay],
        )

    def test_concurrent_duplicate_submission_creates_one_event(self) -> None:
        conversation_id = self.create_conversation()

        def submit(_: int):
            return self.append(
                conversation_id,
                1,
                actor="phone",
                client_message_id="same-client-message",
                content="same-content",
            )

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(submit, range(16)))

        self.assertEqual(1, sum(not item.deduplicated for item in results))
        self.assertEqual(15, sum(item.deduplicated for item in results))
        self.assertEqual(
            1,
            len({item.event.event_id for item in results}),
        )
        self.assertEqual((1, 1), self.store.count_records(conversation_id))

    def test_fault_injection_rolls_back_message_event_and_sequence(self) -> None:
        conversation_id = self.create_conversation()

        def fail_after_message(stage: str) -> None:
            if stage == "after_message_insert":
                raise RuntimeError("injected")

        failing_store = EventStore(
            self.database_path,
            fault_injector=fail_after_message,
        )
        try:
            with self.assertRaises(PersistenceError):
                failing_store.append_message(
                    conversation_id=conversation_id,
                    client_message_id="faulted-message",
                    actor_device_id="windows",
                    role="user",
                    content="must roll back",
                )
        finally:
            failing_store.close()

        self.assertEqual((0, 0), self.store.count_records(conversation_id))
        self.assertEqual(
            1,
            self.store.get_conversation(conversation_id).next_seq,
        )
        accepted = self.append(conversation_id, 1)
        self.assertEqual(1, accepted.event.conversation_seq)

    def test_payload_hash_is_stable_and_matches_payload(self) -> None:
        conversation_id = self.create_conversation()
        result = self.append(
            conversation_id,
            1,
            content="稳定 JSON 内容",
        )

        recomputed = hashlib.sha256(
            result.event.payload_json.encode("utf-8")
        ).hexdigest()
        parsed = json.loads(result.event.payload_json)
        stable_again = json.dumps(
            parsed,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )

        self.assertEqual(PROTOCOL_VERSION, result.event.protocol_version)
        self.assertEqual(
            MESSAGE_ACCEPTED_EVENT,
            result.event.event_type,
        )
        self.assertEqual(result.event.payload_sha256, recomputed)
        self.assertEqual(result.event.payload_json, stable_again)

    def test_semantic_projection_hash_changes_with_stable_semantics(
        self,
    ) -> None:
        conversation_id = self.create_conversation()
        event = self.append(conversation_id, 1).event
        original_hash = semantic_projection_hash([event])

        changed_actor = replace(event, actor_device_id="phone")
        payload = json.loads(event.payload_json)
        payload["content"] = "changed-content"
        changed_payload = replace(
            event,
            payload_json=json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ),
        )

        self.assertNotEqual(
            original_hash,
            semantic_projection_hash([changed_actor]),
        )
        self.assertNotEqual(
            original_hash,
            semantic_projection_hash([changed_payload]),
        )

    def test_semantic_projection_hash_excludes_random_ids_and_time(
        self,
    ) -> None:
        conversation_id = self.create_conversation()
        event = self.append(conversation_id, 1).event
        original_hash = semantic_projection_hash([event])
        payload = json.loads(event.payload_json)
        payload["message_id"] = "different-random-message-id"
        changed_excluded_fields = replace(
            event,
            event_id="different-random-event-id",
            occurred_at="2099-01-01T00:00:00.000Z",
            payload_json=json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ),
            payload_sha256="0" * 64,
        )

        self.assertEqual(
            original_hash,
            semantic_projection_hash([changed_excluded_fields]),
        )

    def test_validation_and_persistence_errors_do_not_echo_sensitive_input(
        self,
    ) -> None:
        conversation_id = self.create_conversation()
        sensitive_value = " private-device-serial-ABC123456789 "

        with self.assertRaises(ValidationError) as validation_context:
            self.store.append_message(
                conversation_id=conversation_id,
                client_message_id="safe-client-id",
                actor_device_id=sensitive_value,
                role="user",
                content="safe",
            )
        self.assertNotIn(sensitive_value, str(validation_context.exception))

        sensitive_path = (
            Path(self._temporary_directory.name) / "private-user-path"
        )
        sensitive_path.mkdir()
        with self.assertRaises(PersistenceError) as persistence_context:
            EventStore(sensitive_path)
        self.assertNotIn(
            str(sensitive_path),
            str(persistence_context.exception),
        )

    def test_schema_has_no_network_token_or_device_serial_columns(self) -> None:
        connection = sqlite3.connect(self.database_path)
        try:
            columns: set[str] = set()
            for table in (
                "conversation",
                "conversation_message",
                "conversation_event",
            ):
                columns.update(
                    str(row[1]).lower()
                    for row in connection.execute(
                        f"PRAGMA table_info({table})"
                    )
                )
        finally:
            connection.close()

        forbidden = {"ip", "token", "device_serial", "serial_number"}
        self.assertTrue(columns.isdisjoint(forbidden))

    def test_nonempty_and_length_validation(self) -> None:
        with self.assertRaises(ValidationError):
            self.store.create_conversation("")
        with self.assertRaises(ValidationError):
            self.store.create_conversation("x" * 201)

        conversation_id = self.create_conversation()
        for field_override in (
            {"actor_device_id": ""},
            {"role": "unknown"},
            {"content": ""},
            {"content": "x" * 65_537},
        ):
            arguments = {
                "conversation_id": conversation_id,
                "client_message_id": "validation-message",
                "actor_device_id": "windows",
                "role": "user",
                "content": "valid",
            }
            arguments.update(field_override)
            with self.subTest(field_override=field_override):
                with self.assertRaises(ValidationError):
                    self.store.append_message(**arguments)


if __name__ == "__main__":
    unittest.main()
