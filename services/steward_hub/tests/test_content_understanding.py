from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from steward_hub.catalog_store import CatalogStore
from steward_hub.content_understanding import (
    ContentUnderstandingError,
    ContentUnderstandingService,
    ContentUnderstandingStore,
    build_study_pack,
)
from steward_hub.pc_file_scope import PcFileScopeError, PcFileScopeService

from services.steward_hub.tests.test_document_extraction import (
    build_docx,
    build_pptx,
    build_text_pdf,
)


WINDOWS_DEVICE_ID = "01J00000000000000000000001"


class ContentUnderstandingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "fixture"
        self.root.mkdir()
        (self.root / "高等数学课堂笔记.md").write_text(
            "极限与连续\n复习定义并完成课后习题。",
            encoding="utf-8",
        )
        (self.root / "课程安排.txt").write_text(
            "本周复习极限、导数和连续性。",
            encoding="utf-8",
        )
        (self.root / "课堂照片.jpg").write_bytes(b"not-image-content")
        (self.root / "课程讲义.docx").write_bytes(build_docx())
        (self.root / "复习课件.pptx").write_bytes(build_pptx())
        (self.root / "作业说明.pdf").write_bytes(build_text_pdf())
        self.database = Path(self.temp.name) / "hub.sqlite3"
        self.scope = PcFileScopeService()
        self.scope.authorize(str(self.root))
        self.catalog = CatalogStore(self.database)
        self.content_store = ContentUnderstandingStore(self.database)
        self.service = ContentUnderstandingService(
            store=self.content_store,
            catalog=self.catalog,
            file_scope=self.scope,
            windows_device_id=WINDOWS_DEVICE_ID,
        )
        batch = self.scope.catalog_snapshot(
            base_seq=0,
            idempotency_key="content-fixture-0001",
            generated_at_ms=1_800_000_000_000,
        )
        self.catalog.apply_snapshot(device_id=WINDOWS_DEVICE_ID, batch=batch)

    def tearDown(self) -> None:
        self.content_store.close()
        self.catalog.close()
        self.temp.cleanup()

    def test_default_off_and_opt_in_persists_without_reading(self) -> None:
        status = self.service.status()
        self.assertFalse(status.content_opt_in)
        self.assertEqual(5, status.supported_file_count)
        self.assertEqual(
            {"docx": 1, "md": 1, "pdf": 1, "pptx": 1, "txt": 1},
            status.supported_format_counts,
        )
        with self.assertRaisesRegex(
            ContentUnderstandingError, "content_opt_in_required"
        ):
            self.service.extract_assets(
                snapshot_sha256=self.catalog.projection_sha256()
            )
        enabled = self.service.set_opt_in(True)
        self.assertTrue(enabled.content_opt_in)
        reopened = ContentUnderstandingStore(self.database)
        try:
            self.assertTrue(
                reopened.is_opted_in(WINDOWS_DEVICE_ID, enabled.catalog_root_id or "")
            )
        finally:
            reopened.close()

    def test_extracts_current_multiformat_assets_with_budgets(self) -> None:
        self.service.set_opt_in(True)
        excerpts = self.service.extract_assets(
            snapshot_sha256=self.catalog.projection_sha256()
        )
        self.assertEqual(5, len(excerpts))
        self.assertEqual(
            {
                "作业说明.pdf",
                "复习课件.pptx",
                "课程安排.txt",
                "课程讲义.docx",
                "高等数学课堂笔记.md",
            },
            {item.display_name for item in excerpts},
        )
        self.assertTrue(all(len(item.excerpt) <= 4_000 for item in excerpts))
        self.assertNotIn(str(self.root), repr(excerpts))
        self.assertNotIn("极限与导数".encode(), self.database.read_bytes())

    def test_revision_change_and_binary_text_fail_closed(self) -> None:
        self.service.set_opt_in(True)
        snapshot = self.catalog.projection_sha256()
        assets = self.service.list_safe_assets(snapshot_sha256=snapshot)
        target = next(item for item in assets if item.extension == "md")
        (self.root / target.display_name).write_text("changed", encoding="utf-8")
        with self.assertRaisesRegex(
            ContentUnderstandingError, "content_revision_changed"
        ):
            self.service.extract_assets(
                snapshot_sha256=snapshot,
                requested_asset_ids=(target.asset_id,),
            )

        binary = next(item for item in assets if item.extension == "txt")
        path = self.root / binary.display_name
        original_stat = path.stat()
        path.write_bytes(b"hello\x00world")
        # The revision check executes before encoding checks for changed files.
        with self.assertRaises(PcFileScopeError):
            self.scope.read_safe_text(
                locator_token=binary.locator_token,
                expected_revision=binary.revision,
            )
        self.assertNotEqual(original_stat.st_mtime_ns, path.stat().st_mtime_ns)

    def test_study_pack_rejects_out_of_allowlist_and_persists_projection_only(self) -> None:
        self.service.set_opt_in(True)
        snapshot = self.catalog.projection_sha256()
        excerpts = self.service.extract_assets(snapshot_sha256=snapshot)
        allowed = tuple(item.asset_id for item in excerpts)
        pack = build_study_pack(
            snapshot_sha256=snapshot,
            title="高等数学复习包",
            summary="资料围绕极限、连续和导数，可按概念到习题的顺序复习。",
            topics=("极限", "连续", "导数"),
            review_points=("先复习定义", "再完成课后习题"),
            cited_asset_ids=allowed,
            source="deterministic_fallback",
        )
        saved = self.service.save_study_pack(
            pack.wire(include_internal=True), allowed_asset_ids=allowed
        )
        self.assertNotIn(pack.summary.encode("utf-8"), self.database.read_bytes())
        self.assertEqual(pack.projection_sha256, saved.projection_sha256)
        self.assertEqual(pack.projection_sha256, self.service.latest_study_pack().projection_sha256)  # type: ignore[union-attr]
        invalid = replace(pack, cited_asset_ids=("f" * 64,))
        with self.assertRaisesRegex(ContentUnderstandingError, "content_insight_invalid"):
            self.service.save_study_pack(
                invalid.wire(include_internal=True), allowed_asset_ids=allowed
            )


if __name__ == "__main__":
    unittest.main()
