from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from steward_hub.pc_file_scope import (
    PcFileScopeError,
    PcFileScopeService,
    parse_pc_file_query_intent,
)


class PcFileScopeServiceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "DataStewardPcDemo"
        self.root.mkdir()
        (self.root / "alpha.png").write_bytes(b"png-fixture")
        (self.root / "beta.JPG").write_bytes(b"jpg-fixture")
        (self.root / "training-plan.txt").write_text("fixture", encoding="utf-8")
        (self.root / "nested").mkdir()
        (self.root / "nested" / "ignored.png").write_bytes(b"ignored")
        self.service = PcFileScopeService()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_authorize_count_search_and_revoke(self) -> None:
        view = self.service.authorize(str(self.root))
        count = self.service.execute(
            parse_pc_file_query_intent("看下电脑授权目录有几个图片文件")
        )
        search = self.service.execute(
            parse_pc_file_query_intent("帮我找下电脑里有关training的文件")
        )

        self.assertTrue(view.configured)
        self.assertRegex(view.root_id or "", r"^pc-[0-9a-f]{12}$")
        self.assertEqual(4, count.scanned_entry_count)
        self.assertEqual(2, count.matched_count)
        self.assertEqual(1, search.matched_count)
        self.assertEqual(("training-plan.txt",), search.matched_names)
        self.assertNotIn(str(self.root), count.conversation_text())
        self.assertNotIn("result_sha256", count.conversation_text())
        self.assertNotIn("root=", count.conversation_text())
        self.assertEqual(count.result_sha256, self.service.execute(
            parse_pc_file_query_intent("电脑图片数量是多少")
        ).result_sha256)
        (self.root / "new-image.webp").write_bytes(b"fresh")
        refreshed = self.service.execute(
            parse_pc_file_query_intent("电脑图片数量是多少")
        )
        self.assertEqual(3, refreshed.matched_count)
        self.assertNotEqual(count.result_sha256, refreshed.result_sha256)

        self.service.revoke()
        with self.assertRaisesRegex(PcFileScopeError, "file_scope_unconfigured"):
            self.service.execute(
                parse_pc_file_query_intent("看下电脑有几个图片文件")
            )

    def test_intent_parser_is_narrow_and_rejects_paths(self) -> None:
        self.assertEqual(
            "count_images",
            parse_pc_file_query_intent("PC 有多少照片").operation,
        )
        self.assertEqual(
            "训练营",
            parse_pc_file_query_intent("搜索电脑里有关训练营的文件").query,
        )
        for unsupported in (
            "整理电脑桌面",
            "删除所有图片",
            "读取报告正文",
            "搜索电脑里有关../秘密的文件",
        ):
            self.assertIsNone(parse_pc_file_query_intent(unsupported))

    def test_scope_rejects_relative_root_drive_root_and_symlink(self) -> None:
        for invalid in ("relative", self.root.anchor):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(PcFileScopeError, "file_scope_invalid"):
                    self.service.authorize(invalid)
        link = Path(self.temporary.name) / "linked-root"
        try:
            link.symlink_to(self.root, target_is_directory=True)
        except OSError:
            self.skipTest("directory symlink creation is unavailable")
        with self.assertRaisesRegex(PcFileScopeError, "file_scope_invalid"):
            self.service.authorize(str(link))

    def test_catalog_snapshot_is_stable_and_metadata_only(self) -> None:
        view = self.service.authorize(str(self.root))
        first = self.service.catalog_snapshot(
            base_seq=0,
            idempotency_key="pc-catalog-fixture-0001",
            generated_at_ms=1_785_805_200_000,
        )
        second = self.service.catalog_snapshot(
            base_seq=0,
            idempotency_key="pc-catalog-fixture-0002",
            generated_at_ms=1_785_805_200_001,
        )
        self.assertEqual(view.root_id, first.catalog_root_id)
        self.assertEqual("windows", first.platform)
        self.assertEqual("windows.file-scope", first.provider)
        self.assertEqual(3, first.item_count)
        self.assertEqual(1, first.skipped_count)
        self.assertEqual(first.snapshot_sha256, second.snapshot_sha256)
        self.assertEqual(
            ["alpha.png", "beta.JPG", "training-plan.txt"],
            sorted(item.display_name for item in first.items),
        )
        self.assertNotIn(str(self.root), repr(first))


if __name__ == "__main__":
    unittest.main()
