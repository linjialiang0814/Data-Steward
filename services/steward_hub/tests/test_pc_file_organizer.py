from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from steward_hub.pc_file_organizer_journal import OrganizerJournalStore
from steward_hub.pc_file_scope import PcFileScopeError, PcFileScopeService


def _journal(path: Path) -> OrganizerJournalStore:
    return OrganizerJournalStore(
        path,
        protect=lambda value: b"sealed:" + value,
        unprotect=lambda value: bytearray(value.removeprefix(b"sealed:")),
        apply_root_security=lambda _path: None,
        verify_root_security=lambda _path: None,
        verify_file_security=lambda _path: None,
    )


class PcFileOrganizerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.root = self.base / "Authorized"
        self.root.mkdir()
        (self.root / "photo.png").write_bytes(b"image")
        (self.root / "brief.pdf").write_bytes(b"document")
        self.journal_path = self.base / "journal-root" / "journal.dpapi"
        self.store = _journal(self.journal_path)
        self.scope = PcFileScopeService(organizer_journal=self.store)
        self.view = self.scope.authorize(str(self.root))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_organize_and_undo_are_bounded_and_reversible(self) -> None:
        inventory = self.scope.inventory()
        receipt = self.scope.organize(
            expected_root_id=self.view.root_id or "",
            expected_evidence_sha256=inventory.evidence_sha256,
        )
        self.assertEqual(2, receipt.moved_count)
        self.assertFalse((self.root / "photo.png").exists())
        self.assertTrue(
            (self.root / "Data Steward 归档" / "图片" / "photo.png").is_file()
        )
        self.assertTrue(
            (self.root / "Data Steward 归档" / "文档" / "brief.pdf").is_file()
        )
        self.assertIsNotNone(self.store.load())

        undone = self.scope.undo_organization(receipt.journal_id)
        self.assertEqual(2, undone.moved_count)
        self.assertTrue((self.root / "photo.png").is_file())
        self.assertTrue((self.root / "brief.pdf").is_file())
        self.assertFalse((self.root / "Data Steward 归档").exists())
        self.assertIsNone(self.store.load())

    def test_stale_preview_fails_before_writing_journal(self) -> None:
        inventory = self.scope.inventory()
        (self.root / "later.txt").write_bytes(b"changed")
        with self.assertRaisesRegex(PcFileScopeError, "organizer_preview_stale"):
            self.scope.organize(
                expected_root_id=self.view.root_id or "",
                expected_evidence_sha256=inventory.evidence_sha256,
            )
        self.assertIsNone(self.store.load())
        self.assertTrue((self.root / "photo.png").is_file())

    def test_destination_conflict_rolls_back_without_overwrite(self) -> None:
        inventory = self.scope.inventory()
        target = self.root / "Data Steward 归档" / "图片"
        target.mkdir(parents=True)
        (target / "photo.png").write_bytes(b"keep")
        with self.assertRaisesRegex(PcFileScopeError, "organizer_destination_conflict"):
            self.scope.organize(
                expected_root_id=self.view.root_id or "",
                expected_evidence_sha256=inventory.evidence_sha256,
            )
        self.assertEqual(b"keep", (target / "photo.png").read_bytes())
        self.assertTrue((self.root / "photo.png").is_file())
        self.assertTrue((self.root / "brief.pdf").is_file())
        self.assertIsNone(self.store.load())

    def test_selected_organization_moves_only_requested_files_and_is_idempotent(
        self,
    ) -> None:
        snapshot = self.scope.catalog_snapshot(
            base_seq=0,
            idempotency_key="organizer-subset-0001",
            generated_at_ms=1,
        )
        photo = next(item for item in snapshot.items if item.display_name == "photo.png")
        locators = (photo.locator_token,)
        preview = self.scope.organization_preview(locator_tokens=locators)

        self.assertEqual(1, preview.selected_count)
        self.assertEqual(1, preview.category_counts["images"])
        receipt = self.scope.organize_selected(
            expected_root_id=self.view.root_id or "",
            expected_evidence_sha256=preview.evidence_sha256,
            locator_tokens=locators,
        )

        self.assertEqual(1, receipt.moved_count)
        self.assertTrue((self.root / "brief.pdf").is_file())
        self.assertFalse((self.root / "photo.png").exists())
        repeated = self.scope.organize_selected(
            expected_root_id=self.view.root_id or "",
            expected_evidence_sha256=preview.evidence_sha256,
            locator_tokens=locators,
        )
        self.assertEqual(receipt.journal_id, repeated.journal_id)
        self.assertEqual(1, repeated.moved_count)

        undone = self.scope.undo_organization(receipt.journal_id)
        self.assertEqual(1, undone.moved_count)
        self.assertTrue((self.root / "photo.png").is_file())
        self.assertTrue((self.root / "brief.pdf").is_file())

    def test_selected_organization_rejects_stale_or_unsorted_selection(self) -> None:
        snapshot = self.scope.catalog_snapshot(
            base_seq=0,
            idempotency_key="organizer-subset-0002",
            generated_at_ms=1,
        )
        locators = tuple(item.locator_token for item in snapshot.items)
        with self.assertRaisesRegex(PcFileScopeError, "organizer_selection_invalid"):
            self.scope.organization_preview(locator_tokens=tuple(reversed(locators)))

        selected = (locators[0],)
        preview = self.scope.organization_preview(locator_tokens=selected)
        selected_name = next(
            item.display_name
            for item in snapshot.items
            if item.locator_token == selected[0]
        )
        (self.root / selected_name).write_bytes(b"changed")
        with self.assertRaisesRegex(PcFileScopeError, "organizer_preview_stale"):
            self.scope.organize_selected(
                expected_root_id=self.view.root_id or "",
                expected_evidence_sha256=preview.evidence_sha256,
                locator_tokens=selected,
            )
        self.assertIsNone(self.store.load())

    def test_status_is_read_only_restart_safe_and_fails_closed_on_drift(self) -> None:
        idle = self.scope.organization_status()
        self.assertEqual("idle", idle.state)
        self.assertFalse(idle.can_undo)
        self.assertIsNone(idle.journal_id)

        snapshot = self.scope.catalog_snapshot(
            base_seq=0,
            idempotency_key="organizer-status-0001",
            generated_at_ms=1,
        )
        photo = next(item for item in snapshot.items if item.display_name == "photo.png")
        preview = self.scope.organization_preview(locator_tokens=(photo.locator_token,))
        receipt = self.scope.organize_selected(
            expected_root_id=self.view.root_id or "",
            expected_evidence_sha256=preview.evidence_sha256,
            locator_tokens=(photo.locator_token,),
        )

        available = self.scope.organization_status()
        self.assertEqual("undo_available", available.state)
        self.assertTrue(available.can_undo)
        self.assertEqual(receipt.journal_id, available.journal_id)
        self.assertEqual(1, available.moved_count)
        self.assertEqual(1, available.category_counts["images"])

        destination = self.root / "Data Steward 归档" / "图片" / "photo.png"
        destination.rename(self.root / "photo.png")
        blocked = self.scope.organization_status()
        self.assertEqual("recovery_required", blocked.state)
        self.assertFalse(blocked.can_undo)
        self.assertIsNone(blocked.journal_id)
        self.assertIsNotNone(self.store.load())

    def test_status_fails_closed_when_journal_is_damaged(self) -> None:
        inventory = self.scope.inventory()
        self.scope.organize(
            expected_root_id=self.view.root_id or "",
            expected_evidence_sha256=inventory.evidence_sha256,
        )
        self.journal_path.write_bytes(b"sealed:not-json")

        with self.assertRaisesRegex(
            PcFileScopeError,
            "organizer_journal_unavailable",
        ):
            self.scope.organization_status()


if __name__ == "__main__":
    unittest.main()
