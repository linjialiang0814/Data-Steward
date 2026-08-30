from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from steward_hub.archive_memory import ArchiveMemoryService, parse_archive_intent
from steward_hub.archive_memory_demo import (
    ARCHIVE_DEMO_RESET_CONFIRMATION,
    ArchiveDemoAdminError,
    inspect_archive_demo,
    reset_archive_demo,
)
from steward_hub.pc_file_scope import PcFileScopeService
from steward_hub.store import EventStore


class ArchiveMemoryDemoAdminTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        authorized = self.root / "Authorized"
        authorized.mkdir()
        (authorized / "fixture.png").write_bytes(b"fixture")
        self.database = self.root / "hub.sqlite3"
        self.event_store = EventStore(self.database)
        self.conversation = self.event_store.create_conversation("demo-conversation")
        scope = PcFileScopeService()
        scope.authorize(str(authorized))
        self.archive = ArchiveMemoryService(self.database, scope)
        suggestion = self.archive.execute(
            parse_archive_intent("智能整理电脑授权目录"),
            source_message_ref="suggestion-1",
        )
        self.archive.execute(
            parse_archive_intent(f"接受归档建议 {suggestion.suggestion_id}"),
            source_message_ref="accept-1",
        )

    def tearDown(self) -> None:
        self.archive.close()
        self.event_store.close()
        self.temporary.cleanup()

    def test_inspect_is_read_only(self) -> None:
        before = self.database.read_bytes()
        state = inspect_archive_demo(self.database)
        self.assertEqual((1, 1, 1), (
            state.suggestion_count,
            state.memory_count,
            state.evidence_count,
        ))
        self.assertEqual(before, self.database.read_bytes())

    def test_reset_requires_exact_confirmation(self) -> None:
        with self.assertRaisesRegex(
            ArchiveDemoAdminError, "archive_demo_confirmation_required"
        ):
            reset_archive_demo(self.database, confirmation="RESET")
        self.assertEqual(1, inspect_archive_demo(self.database).suggestion_count)

    def test_boolean_timeout_is_rejected_without_mutation(self) -> None:
        with self.assertRaisesRegex(
            ArchiveDemoAdminError, "archive_demo_timeout_invalid"
        ):
            reset_archive_demo(
                self.database,
                confirmation=ARCHIVE_DEMO_RESET_CONFIRMATION,
                busy_timeout_ms=True,
            )
        self.assertEqual(1, inspect_archive_demo(self.database).suggestion_count)

    def test_reset_only_clears_archive_memory_tables(self) -> None:
        result = reset_archive_demo(
            self.database,
            confirmation=ARCHIVE_DEMO_RESET_CONFIRMATION,
        )
        self.assertEqual((1, 1, 1), (
            result.before.suggestion_count,
            result.before.memory_count,
            result.before.evidence_count,
        ))
        self.assertEqual((0, 0, 0), (
            result.after.suggestion_count,
            result.after.memory_count,
            result.after.evidence_count,
        ))
        reopened = EventStore(self.database)
        try:
            self.assertEqual(self.conversation.conversation_id, reopened.get_conversation(
                self.conversation.conversation_id
            ).conversation_id)
        finally:
            reopened.close()

    def test_unknown_schema_fails_closed_without_mutation(self) -> None:
        self.archive.close()
        connection = sqlite3.connect(self.database)
        try:
            connection.execute("DROP TABLE archive_schema_meta")
            connection.execute(
                "CREATE TABLE archive_schema_meta(component TEXT PRIMARY KEY, schema_version INTEGER NOT NULL)"
            )
            connection.execute(
                "INSERT INTO archive_schema_meta(component, schema_version) VALUES ('archive_memory', 2)"
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(
            ArchiveDemoAdminError, "archive_demo_schema_unsupported"
        ):
            reset_archive_demo(
                self.database,
                confirmation=ARCHIVE_DEMO_RESET_CONFIRMATION,
            )
        connection = sqlite3.connect(self.database)
        count = connection.execute("SELECT count(*) FROM archive_suggestion").fetchone()[0]
        connection.close()
        self.assertEqual(1, count)

    def test_busy_database_fails_closed(self) -> None:
        blocker = sqlite3.connect(self.database, isolation_level=None)
        blocker.execute("BEGIN IMMEDIATE")
        try:
            with self.assertRaisesRegex(ArchiveDemoAdminError, "archive_demo_busy"):
                reset_archive_demo(
                    self.database,
                    confirmation=ARCHIVE_DEMO_RESET_CONFIRMATION,
                    busy_timeout_ms=10,
                )
        finally:
            blocker.execute("ROLLBACK")
            blocker.close()
        self.assertEqual(1, inspect_archive_demo(self.database).suggestion_count)


if __name__ == "__main__":
    unittest.main()
