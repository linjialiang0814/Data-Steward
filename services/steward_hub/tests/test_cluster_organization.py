from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from steward_hub.catalog_clustering import build_today_materials
from steward_hub.catalog_models import (
    CatalogItemInput,
    CatalogSnapshotBatch,
    catalog_snapshot_sha256,
)
from steward_hub.catalog_store import CatalogStore
from steward_hub.cluster_organization import (
    ClusterOrganizationError,
    ClusterOrganizationService,
)
from steward_hub.pc_file_organizer_journal import OrganizerJournalStore
from steward_hub.pc_file_scope import PcFileScopeService


WINDOWS_DEVICE = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
ANDROID_DEVICE = "01ARZ3NDEKTSV4RRFFQ69G5FAW"


def _journal(path: Path) -> OrganizerJournalStore:
    return OrganizerJournalStore(
        path,
        protect=lambda value: b"sealed:" + value,
        unprotect=lambda value: bytearray(value.removeprefix(b"sealed:")),
        apply_root_security=lambda _path: None,
        verify_root_security=lambda _path: None,
        verify_file_security=lambda _path: None,
    )


class ClusterOrganizationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.root = base / "Authorized"
        self.root.mkdir()
        (self.root / "project-slides.pdf").write_bytes(b"slides")
        (self.root / "english-homework.zip").write_bytes(b"archive")
        self.scope = PcFileScopeService(
            organizer_journal=_journal(base / "journal" / "journal.dpapi")
        )
        self.scope.authorize(str(self.root))
        self.catalog = CatalogStore(base / "catalog.sqlite3")
        self.now_ms = int(time.time() * 1000)
        pc_batch = self.scope.catalog_snapshot(
            base_seq=0,
            idempotency_key="cluster-pc-0001",
            generated_at_ms=self.now_ms,
        )
        self.catalog.apply_snapshot(
            device_id=WINDOWS_DEVICE,
            batch=pc_batch,
            replace_other_roots=True,
        )
        android_item = CatalogItemInput(
            locator_token="a" * 64,
            display_name="project-notes.md",
            extension="md",
            mime_family="text",
            size_bytes=20,
            modified_at_ms=self.now_ms,
            revision="b" * 64,
            content_eligible=True,
        )
        android_root = "c" * 64
        android_batch = CatalogSnapshotBatch(
            idempotency_key="cluster-android-0001",
            catalog_root_id=android_root,
            platform="android",
            provider="android.saf",
            display_name="Phone fixture",
            base_seq=0,
            snapshot_sha256=catalog_snapshot_sha256(
                android_root, (android_item,), 0
            ),
            generated_at_ms=self.now_ms,
            item_count=1,
            skipped_count=0,
            complete_snapshot=True,
            items=(android_item,),
        )
        self.catalog.apply_snapshot(device_id=ANDROID_DEVICE, batch=android_batch)
        self.service = ClusterOrganizationService(
            catalog=self.catalog,
            file_scope=self.scope,
            windows_device_id=WINDOWS_DEVICE,
            now_ms=lambda: self.now_ms,
        )

    def tearDown(self) -> None:
        self.catalog.close()
        self.temp.cleanup()

    def _today(self):
        roots, assets, source = self.catalog.current_view()
        return build_today_materials(
            roots=roots,
            assets=assets,
            source_projection_sha256=source,
            now_ms=self.now_ms,
        )

    def test_preview_execute_and_undo_move_only_cluster_pc_files(self) -> None:
        today = self._today()
        self.assertEqual(1, today.cluster_count)
        cluster = today.clusters[0]
        preview = self.service.preview(
            cluster_id=cluster.cluster_id,
            projection_sha256=today.projection_sha256,
        )
        self.assertEqual(1, preview.pc_file_count)
        self.assertEqual(1, preview.virtual_file_count)

        receipt = self.service.execute(
            cluster_id=cluster.cluster_id,
            projection_sha256=today.projection_sha256,
            preview_sha256=preview.preview_sha256,
        )
        self.assertEqual(1, receipt.moved_count)
        self.assertFalse((self.root / "project-slides.pdf").exists())
        self.assertTrue((self.root / "english-homework.zip").is_file())
        self.assertFalse(receipt.catalog_refresh_pending)

        restored_service = ClusterOrganizationService(
            catalog=self.catalog,
            file_scope=self.scope,
            windows_device_id=WINDOWS_DEVICE,
            now_ms=lambda: self.now_ms,
        )
        pending = restored_service.status()
        self.assertEqual("undo_available", pending.state)
        self.assertTrue(pending.can_undo)
        self.assertEqual(receipt.undo_token, pending.undo_token)
        self.assertEqual(1, pending.moved_count)

        undone = self.service.undo(undo_token=receipt.undo_token)
        self.assertEqual(1, undone.moved_count)
        self.assertTrue((self.root / "project-slides.pdf").is_file())
        self.assertTrue((self.root / "english-homework.zip").is_file())
        self.assertFalse(undone.catalog_refresh_pending)
        idle = restored_service.status()
        self.assertEqual("idle", idle.state)
        self.assertFalse(idle.can_undo)
        self.assertIsNone(idle.undo_token)

    def test_stale_projection_and_preview_fail_before_moving(self) -> None:
        today = self._today()
        cluster = today.clusters[0]
        preview = self.service.preview(
            cluster_id=cluster.cluster_id,
            projection_sha256=today.projection_sha256,
        )
        with self.assertRaisesRegex(
            ClusterOrganizationError, "organization_preview_stale"
        ):
            self.service.execute(
                cluster_id=cluster.cluster_id,
                projection_sha256=today.projection_sha256,
                preview_sha256="0" * 64,
            )
        with self.assertRaisesRegex(
            ClusterOrganizationError, "catalog_projection_stale"
        ):
            self.service.preview(
                cluster_id=cluster.cluster_id,
                projection_sha256="0" * 64,
            )
        self.assertTrue((self.root / "project-slides.pdf").is_file())


if __name__ == "__main__":
    unittest.main()
