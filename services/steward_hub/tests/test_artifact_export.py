from __future__ import annotations

import sqlite3
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from steward_hub.artifact_export import (
    ArtifactExportError,
    ArtifactExportService,
    ArtifactExportStore,
)
from steward_hub.knowledge_pack import KnowledgeCitation, KnowledgePack
from steward_hub.pc_file_scope import MARKDOWN_EXPORT_DIRECTORY, PcFileScopeService
from steward_hub.tls_identity.path_safety import is_reparse_point


def pack() -> KnowledgePack:
    return KnowledgePack(
        pack_id="kp-1234567890abcdef",
        kind="learning",
        snapshot_sha256="a" * 64,
        source_projection_sha256="b" * 64,
        title="学习资料包｜高等数学",
        summary="整理今天的课件、笔记和课堂图片。",
        topics=("limits", "continuity"),
        review_points=("核对定义", "完成作业"),
        citations=(
            KnowledgeCitation(
                "S1",
                "windows",
                "student-materials",
                "高等数学-课件.md",
                1_785_805_200_000,
                "1" * 64,
            ),
            KnowledgeCitation(
                "S2",
                "android",
                "手机资料",
                "课堂照片.png",
                1_785_805_200_000,
                "2" * 64,
            ),
        ),
        source="hermes",
        cross_device=True,
        created_at="2026-08-05T10:00:00.000Z",
        projection_sha256="c" * 64,
    )


class ArtifactExportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "student-materials"
        self.root.mkdir()
        self.scope = PcFileScopeService()
        self.scope.authorize(str(self.root))
        self.database = Path(self.temporary.name) / "hub.sqlite3"
        self.store = ArtifactExportStore(self.database)
        self.service = ArtifactExportService(store=self.store, file_scope=self.scope)

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def test_missing_export_target_is_not_a_reparse_point(self) -> None:
        self.assertFalse(is_reparse_point(self.root / "not-created.md"))

    def test_preview_execute_status_idempotency_and_undo(self) -> None:
        preview = self.service.preview(pack())
        self.assertEqual("student-materials", preview.target_display_name)
        self.assertEqual(MARKDOWN_EXPORT_DIRECTORY, preview.output_directory)
        self.assertLessEqual(preview.byte_count, 128 * 1024)

        receipt = self.service.execute(
            pack=pack(),
            preview_sha256=preview.preview_sha256,
            idempotency_key="export-" + "1" * 32,
        )
        repeated = self.service.execute(
            pack=pack(),
            preview_sha256=preview.preview_sha256,
            idempotency_key="export-" + "1" * 32,
        )
        target = self.root / MARKDOWN_EXPORT_DIRECTORY / preview.filename

        self.assertTrue(target.is_file())
        self.assertFalse(receipt.deduplicated)
        self.assertTrue(repeated.deduplicated)
        self.assertEqual("undo_available", self.service.status().state)
        undone = self.service.undo(undo_token=receipt.undo_token or "")
        self.assertEqual("undone", undone.state)
        self.assertFalse(target.exists())
        self.assertEqual("undone", self.service.status().state)

    def test_response_loss_after_write_converges_without_overwrite(self) -> None:
        preview = self.service.preview(pack())
        real_transition = self.store.transition
        calls = 0

        def fail_first_complete(export_id: str, *, expected: str, target: str):
            nonlocal calls
            if expected == "PREPARED" and target == "COMPLETED" and calls == 0:
                calls += 1
                raise ArtifactExportError("artifact_persistence_failed")
            return real_transition(export_id, expected=expected, target=target)

        with patch.object(self.store, "transition", side_effect=fail_first_complete):
            with self.assertRaisesRegex(ArtifactExportError, "artifact_persistence_failed"):
                self.service.execute(
                    pack=pack(),
                    preview_sha256=preview.preview_sha256,
                    idempotency_key="export-" + "2" * 32,
                )

        recovered = self.service.execute(
            pack=pack(),
            preview_sha256=preview.preview_sha256,
            idempotency_key="export-" + "2" * 32,
        )
        self.assertTrue(recovered.deduplicated)
        self.assertEqual(1, len(list((self.root / MARKDOWN_EXPORT_DIRECTORY).iterdir())))

    def test_external_modification_blocks_undo_and_preserves_file(self) -> None:
        preview = self.service.preview(pack())
        receipt = self.service.execute(
            pack=pack(),
            preview_sha256=preview.preview_sha256,
            idempotency_key="export-" + "3" * 32,
        )
        target = self.root / MARKDOWN_EXPORT_DIRECTORY / preview.filename
        target.write_text("user changed this file", encoding="utf-8")

        with self.assertRaisesRegex(ArtifactExportError, "artifact_modified"):
            self.service.undo(undo_token=receipt.undo_token or "")

        self.assertEqual("user changed this file", target.read_text(encoding="utf-8"))
        self.assertEqual("recovery_required", self.service.status().state)

    def test_preview_staleness_and_idempotency_conflict_fail_closed(self) -> None:
        preview = self.service.preview(pack())
        with self.assertRaisesRegex(ArtifactExportError, "artifact_preview_stale"):
            self.service.execute(
                pack=pack(),
                preview_sha256="f" * 64,
                idempotency_key="export-" + "4" * 32,
            )
        self.service.execute(
            pack=pack(),
            preview_sha256=preview.preview_sha256,
            idempotency_key="export-" + "4" * 32,
        )
        changed = replace(pack(), pack_id="kp-fedcba0987654321")
        with self.assertRaises(ArtifactExportError):
            self.service.execute(
                pack=changed,
                preview_sha256=self.service.preview(changed).preview_sha256,
                idempotency_key="export-" + "4" * 32,
            )

    def test_database_contains_no_markdown_or_absolute_path(self) -> None:
        preview = self.service.preview(pack())
        self.service.execute(
            pack=pack(),
            preview_sha256=preview.preview_sha256,
            idempotency_key="export-" + "5" * 32,
        )
        connection = sqlite3.connect(self.database)
        try:
            dump = "\n".join(connection.iterdump())
        finally:
            connection.close()
        self.assertNotIn("整理今天的课件", dump)
        self.assertNotIn(str(self.root), dump)


if __name__ == "__main__":
    unittest.main()
