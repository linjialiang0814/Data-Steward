from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from steward_hub.archive_memory import (
    ArchiveMemoryError,
    ArchiveMemoryService,
    parse_archive_intent,
)
from steward_hub.pc_file_scope import PcFileScopeService


class ArchiveMemoryServiceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "Authorized"
        self.root.mkdir()
        (self.root / "photo.png").write_bytes(b"image")
        (self.root / "brief.pdf").write_bytes(b"document")
        (self.root / "recording.mp4").write_bytes(b"media")
        (self.root / "bundle.zip").write_bytes(b"archive")
        (self.root / "fixture.bin").write_bytes(b"other")
        self.database = Path(self.temporary.name) / "hub.sqlite3"
        self.scope = PcFileScopeService()
        self.view = self.scope.authorize(str(self.root))
        self.service = ArchiveMemoryService(self.database, self.scope)

    def tearDown(self) -> None:
        self.service.close()
        self.temporary.cleanup()

    def _suggest_and_accept(self, index: int):
        suggestion = self.service.execute(
            parse_archive_intent("智能整理电脑授权目录"),
            source_message_ref=f"suggest-{index}",
        )
        accepted = self.service.execute(
            parse_archive_intent(f"接受归档建议 {suggestion.suggestion_id}"),
            source_message_ref=f"accept-{index}",
        )
        return suggestion, accepted

    def test_inventory_projection_and_suggestion_are_privacy_safe(self) -> None:
        inventory = self.scope.inventory()
        self.assertEqual(
            {"images": 1, "documents": 1, "media": 1, "archives": 1, "other": 1},
            inventory.category_counts,
        )
        suggestion = self.service.execute(
            parse_archive_intent("给出电脑授权目录的归档建议"),
            source_message_ref="privacy-safe",
        )
        text = suggestion.conversation_text()
        self.assertIn("尚未移动、重命名、修改或删除任何文件", text)
        self.assertNotIn("photo.png", text)
        self.assertNotIn(str(self.root), text)
        connection = sqlite3.connect(self.database)
        stored = "\n".join(
            str(value)
            for row in connection.execute("SELECT * FROM archive_suggestion")
            for value in row
            if value is not None
        )
        connection.close()
        self.assertNotIn("photo.png", stored)
        self.assertNotIn(str(self.root), stored)

    def test_three_distinct_acceptances_require_explicit_approval(self) -> None:
        receipts = [self._suggest_and_accept(index) for index in range(3)]
        memory_id = receipts[-1][1].memory_id
        self.assertEqual("candidate", receipts[-1][1].memory_status)
        approved = self.service.execute(
            parse_archive_intent(f"批准整理习惯 {memory_id}"),
            source_message_ref="approve",
        )
        self.assertEqual("active", approved.memory_status)
        recalled = self.service.execute(
            parse_archive_intent("按我的习惯整理电脑授权目录"),
            source_message_ref="new-conversation",
        )
        self.assertEqual(memory_id, recalled.memory_id)
        self.assertEqual(3, recalled.support_count)
        self.assertNotIn(memory_id, recalled.conversation_text())
        self.assertIn("已参考你批准的整理偏好", recalled.conversation_text())
        product_recall = self.service.execute(
            parse_archive_intent(
                "参考我的整理习惯，帮我整理当前资料"
            ),
            source_message_ref="product-memory-request",
        )
        self.assertEqual("recall", product_recall.operation)
        self.assertEqual(memory_id, product_recall.memory_id)

    def test_early_approval_fails_and_duplicate_accept_is_idempotent(self) -> None:
        suggestion, accepted = self._suggest_and_accept(1)
        duplicated = self.service.execute(
            parse_archive_intent(f"接受归档建议 {suggestion.suggestion_id}"),
            source_message_ref="accept-again",
        )
        self.assertEqual(1, duplicated.support_count)
        with self.assertRaisesRegex(
            ArchiveMemoryError, "archive_memory_insufficient_evidence"
        ):
            self.service.execute(
                parse_archive_intent(f"批准整理习惯 {accepted.memory_id}"),
                source_message_ref="approve-too-early",
            )

    def test_reject_and_pause_take_effect_and_paused_memory_can_reactivate(self) -> None:
        suggestion = self.service.execute(
            parse_archive_intent("智能整理电脑授权目录"),
            source_message_ref="reject-me",
        )
        self.service.execute(
            parse_archive_intent(f"拒绝归档建议 {suggestion.suggestion_id}"),
            source_message_ref="reject",
        )
        with self.assertRaisesRegex(ArchiveMemoryError, "archive_suggestion_closed"):
            self.service.execute(
                parse_archive_intent(f"接受归档建议 {suggestion.suggestion_id}"),
                source_message_ref="late-accept",
            )
        receipts = [self._suggest_and_accept(index + 10) for index in range(3)]
        memory_id = receipts[-1][1].memory_id
        self.service.execute(
            parse_archive_intent(f"批准整理习惯 {memory_id}"),
            source_message_ref="approve",
        )
        forgotten = self.service.execute(
            parse_archive_intent(f"忘记整理习惯 {memory_id}"),
            source_message_ref="forget",
        )
        self.assertEqual("forgotten", forgotten.memory_status)
        with self.assertRaisesRegex(ArchiveMemoryError, "archive_memory_not_active"):
            self.service.execute(
                parse_archive_intent("按我的习惯整理电脑授权目录"),
                source_message_ref="recall-after-forget",
            )
        reactivated = self.service.execute(
            parse_archive_intent(f"批准整理习惯 {memory_id}"),
            source_message_ref="reactivate",
        )
        self.assertEqual("active", reactivated.memory_status)
        self.assertEqual(3, reactivated.support_count)
        self.assertEqual(forgotten.memory_version + 1, reactivated.memory_version)
        recalled = self.service.execute(
            parse_archive_intent("按我的习惯整理电脑授权目录"),
            source_message_ref="recall-after-reactivate",
        )
        self.assertEqual(memory_id, recalled.memory_id)
        self.assertEqual(
            {"photo.png", "brief.pdf", "recording.mp4", "bundle.zip", "fixture.bin"},
            {item.name for item in self.root.iterdir()},
        )

    def test_only_explicit_action_can_start_fresh_learning_after_forget(self) -> None:
        receipts = [self._suggest_and_accept(index + 40) for index in range(3)]
        memory_id = receipts[-1][1].memory_id
        approved = self.service.execute(
            parse_archive_intent(f"批准整理习惯 {memory_id}"),
            source_message_ref="approve-before-relearn",
        )
        forgotten = self.service.execute(
            parse_archive_intent(f"忘记整理习惯 {memory_id}"),
            source_message_ref="forget-before-relearn",
        )
        suggestion = self.service.execute(
            parse_archive_intent("智能整理电脑授权目录"),
            source_message_ref="fresh-suggestion-after-forget",
        )

        with self.assertRaisesRegex(ArchiveMemoryError, "archive_memory_forgotten"):
            self.service.execute(
                parse_archive_intent(f"接受归档建议 {suggestion.suggestion_id}"),
                source_message_ref="legacy-accept-after-forget",
            )

        relearned = self.service.execute(
            parse_archive_intent(f"接受归档建议 {suggestion.suggestion_id}"),
            source_message_ref="explicit-action-after-forget",
            allow_explicit_relearn=True,
        )
        self.assertEqual("learning", relearned.memory_status)
        self.assertEqual(1, relearned.support_count)
        self.assertEqual(forgotten.memory_version + 1, relearned.memory_version)
        self.assertGreater(relearned.memory_version, approved.memory_version)

    def test_state_survives_reopen_and_unknown_schema_fails_closed(self) -> None:
        receipts = [self._suggest_and_accept(index + 20) for index in range(3)]
        memory_id = receipts[-1][1].memory_id
        self.service.execute(
            parse_archive_intent(f"批准整理习惯 {memory_id}"),
            source_message_ref="approve",
        )
        self.service.close()
        self.service = ArchiveMemoryService(self.database, self.scope)
        new_root = Path(self.temporary.name) / "Reauthorized"
        new_root.mkdir()
        (new_root / "fresh.docx").write_bytes(b"fresh")
        self.scope.authorize(str(new_root))
        recalled = self.service.execute(
            parse_archive_intent("按我的习惯整理电脑授权目录"),
            source_message_ref="reopened",
        )
        self.assertEqual(memory_id, recalled.memory_id)
        self.assertEqual(1, recalled.category_counts["documents"])
        self.service.close()
        connection = sqlite3.connect(self.database)
        connection.execute("DROP TABLE archive_schema_meta")
        connection.execute(
            "CREATE TABLE archive_schema_meta(component TEXT PRIMARY KEY, schema_version INTEGER NOT NULL)"
        )
        connection.execute(
            "INSERT INTO archive_schema_meta VALUES ('archive_memory', 999)"
        )
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(ArchiveMemoryError, "archive_schema_unsupported"):
            ArchiveMemoryService(self.database, self.scope)

    def test_parser_is_explicit_and_rejects_ambiguous_mutation(self) -> None:
        self.assertEqual(
            "suggest_or_recall",
            parse_archive_intent("智能整理电脑授权目录").operation,
        )
        for supported in (
            "再次给出电脑授权目录的归档建议",
            "请重新生成一下电脑授权目录的整理建议。",
            "提供电脑授权目录归档建议",
            "根据今天的资料给出归档建议，先不要移动文件。",
        ):
            self.assertEqual(
                "suggest_or_recall",
                parse_archive_intent(supported).operation,
            )
        self.assertEqual(
            "suggest_or_recall",
            parse_archive_intent(
                "根据今天的资料和我的整理习惯给出归档建议，先不要移动文件。"
            ).operation,
        )
        for supported in (
            "参考我的整理习惯，帮我整理当前资料",
            "按照我已批准的整理偏好归档这些文件。",
            "结合已启用的整理习惯生成今天资料的归档建议，先不要移动文件",
            "帮我整理一下今天的课程资料",
            "我想把这些课件和笔记分类一下",
            "如何归档当前工作材料？",
            "参考我的整理习惯，帮我整理当前资料并立即执行",
            "给出电脑授权目录归档建议并立即移动",
            "不要帮我移动文件，但可以给整理建议",
        ):
            self.assertEqual(
                "suggest_or_recall",
                parse_archive_intent(supported).operation,
            )
        self.assertEqual("recall", parse_archive_intent("按我的习惯整理电脑授权目录").operation)
        for unsupported in (
            "整理桌面",
            "移动所有图片",
            "不要整理这些资料",
            "我不想整理这些文件",
            "我不希望系统帮我归档当前资料",
            "暂时不分类这些课件",
            "先别帮我整理工作材料",
            "取消对这些文件的整理",
            "我喜欢按课程整理资料",
            "批准整理习惯 mem-bad",
        ):
            self.assertIsNone(parse_archive_intent(unsupported))


if __name__ == "__main__":
    unittest.main()
