from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from steward_hub.catalog_models import (
    CATALOG_SYNC_SCHEMA,
    CatalogItemInput,
    CatalogValidationError,
    catalog_batch_from_mapping,
    catalog_snapshot_sha256,
)
from steward_hub.catalog_store import (
    CatalogCursorConflict,
    CatalogStore,
    CatalogStoreError,
)


ANDROID_DEVICE = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
REPAIRED_ANDROID_DEVICE = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
WINDOWS_DEVICE = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
ANDROID_ROOT = "a" * 64
WINDOWS_ROOT = "pc-aabbccddeeff"


def item(token: str, name: str, *, size: int = 10) -> CatalogItemInput:
    return CatalogItemInput(
        locator_token=token * 64,
        display_name=name,
        extension=name.rsplit(".", 1)[-1].lower(),
        mime_family="text",
        size_bytes=size,
        modified_at_ms=1_785_805_200_000,
        revision=("f" if token != "f" else "e") * 64,
        content_eligible=True,
    )


def batch(
    *,
    root: str = ANDROID_ROOT,
    platform: str = "android",
    provider: str = "com.android.externalstorage.documents",
    label: str = "手机资料",
    base_seq: int = 0,
    key: str = "catalog-request-0001",
    items: tuple[CatalogItemInput, ...] = (),
    skipped: int = 0,
):
    ordered = tuple(sorted(items, key=lambda value: value.locator_token))
    value = {
        "schema_version": CATALOG_SYNC_SCHEMA,
        "idempotency_key": key,
        "catalog_root_id": root,
        "platform": platform,
        "provider": provider,
        "display_name": label,
        "base_seq": base_seq,
        "snapshot_sha256": catalog_snapshot_sha256(root, ordered, skipped),
        "generated_at_ms": 1_785_805_200_000,
        "item_count": len(ordered),
        "skipped_count": skipped,
        "complete_snapshot": True,
        "items": [value.wire() for value in ordered],
    }
    return catalog_batch_from_mapping(value)


class CatalogStoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "catalog.sqlite3"
        self.store = CatalogStore(self.path)

    def tearDown(self) -> None:
        if self.store is not None:
            self.store.close()
        self.temp.cleanup()

    def test_first_snapshot_idempotency_and_restart(self) -> None:
        original = batch(items=(item("a", "高等数学-课堂笔记.md"),), skipped=1)
        first = self.store.apply_snapshot(device_id=ANDROID_DEVICE, batch=original)
        replay = self.store.apply_snapshot(device_id=ANDROID_DEVICE, batch=original)

        self.assertEqual(1, first.accepted_seq)
        self.assertTrue(first.changed)
        self.assertFalse(first.deduplicated)
        self.assertTrue(replay.deduplicated)
        self.assertEqual(first.projection_sha256, replay.projection_sha256)
        self.store.close()
        self.store = None
        self.store = CatalogStore(self.path)
        self.assertEqual(1, self.store.current_seq(ANDROID_DEVICE, ANDROID_ROOT))
        self.assertEqual("高等数学-课堂笔记.md", self.store.list_assets()[0].display_name)

    def test_same_key_changed_request_conflicts_without_write(self) -> None:
        self.store.apply_snapshot(
            device_id=ANDROID_DEVICE,
            batch=batch(items=(item("a", "a.md"),)),
        )
        changed = batch(
            base_seq=1,
            key="catalog-request-0001",
            items=(item("b", "b.md"),),
        )
        with self.assertRaisesRegex(CatalogStoreError, "catalog_idempotency_conflict"):
            self.store.apply_snapshot(device_id=ANDROID_DEVICE, batch=changed)
        self.assertEqual(["a.md"], [asset.display_name for asset in self.store.list_assets()])

    def test_cursor_conflict_is_fail_closed(self) -> None:
        self.store.apply_snapshot(device_id=ANDROID_DEVICE, batch=batch())
        with self.assertRaises(CatalogCursorConflict) as caught:
            self.store.apply_snapshot(
                device_id=ANDROID_DEVICE,
                batch=batch(base_seq=0, key="catalog-request-0002", items=(item("a", "a.md"),)),
            )
        self.assertEqual(1, caught.exception.server_catalog_seq)
        self.assertEqual([], list(self.store.list_assets()))

    def test_complete_snapshot_tombstones_and_reappearance(self) -> None:
        first = batch(items=(item("a", "a.md"), item("b", "b.md")))
        self.store.apply_snapshot(device_id=ANDROID_DEVICE, batch=first)
        second = batch(
            base_seq=1,
            key="catalog-request-0002",
            items=(item("b", "b.md", size=11),),
        )
        result = self.store.apply_snapshot(device_id=ANDROID_DEVICE, batch=second)
        self.assertEqual(1, result.tombstone_count)
        self.assertEqual(["b.md"], [asset.display_name for asset in self.store.list_assets()])
        all_assets = self.store.list_assets(include_deleted=True)
        self.assertEqual(2, len(all_assets))
        self.assertIsNotNone(next(value for value in all_assets if value.display_name == "a.md").deleted_at)

        third = batch(
            base_seq=2,
            key="catalog-request-0003",
            items=(item("a", "a.md"), item("b", "b.md", size=11)),
        )
        self.store.apply_snapshot(device_id=ANDROID_DEVICE, batch=third)
        self.assertTrue(all(value.deleted_at is None for value in self.store.list_assets()))

    def test_two_devices_converge_in_one_projection(self) -> None:
        self.store.apply_snapshot(
            device_id=ANDROID_DEVICE,
            batch=batch(items=(item("a", "课堂照片.md"),)),
        )
        pc = batch(
            root=WINDOWS_ROOT,
            platform="windows",
            provider="windows.filesystem",
            label="课程资料",
            key="catalog-pc-request-01",
            items=(item("b", "高等数学课件.md"),),
        )
        self.store.apply_snapshot(device_id=WINDOWS_DEVICE, batch=pc)
        roots = self.store.list_roots()
        assets = self.store.list_assets()

        self.assertEqual({"android", "windows"}, {value.platform for value in roots})
        self.assertEqual(2, len(assets))
        self.assertEqual(2, len({value.asset_id for value in assets}))
        self.assertRegex(self.store.projection_sha256(), r"^[0-9a-f]{64}$")

    def test_repaired_device_supersedes_stale_snapshot_for_same_logical_root(
        self,
    ) -> None:
        self.store.apply_snapshot(
            device_id=ANDROID_DEVICE,
            batch=batch(
                items=(
                    item("a", "deleted-image.png"),
                    item("b", "duplicate-note.md"),
                ),
            ),
        )
        stale_projection = self.store.projection_sha256()

        self.store.apply_snapshot(
            device_id=REPAIRED_ANDROID_DEVICE,
            batch=batch(
                key="catalog-request-repaired-01",
                items=(
                    item("b", "duplicate-note.md"),
                    item("c", "current-note.md"),
                ),
            ),
        )

        roots, assets, projection = self.store.current_view()
        self.assertEqual(1, len(roots))
        self.assertEqual(REPAIRED_ANDROID_DEVICE, roots[0].device_id)
        self.assertEqual(
            ["current-note.md", "duplicate-note.md"],
            sorted(asset.display_name for asset in assets),
        )
        self.assertNotEqual(stale_projection, projection)
        self.assertEqual(2, len(self.store.list_assets(include_deleted=True)))

    def test_unknown_schema_fails_before_catalog_ddl(self) -> None:
        self.store.close()
        connection = sqlite3.connect(self.path)
        connection.execute("DROP TABLE catalog_schema_meta")
        connection.execute(
            "CREATE TABLE catalog_schema_meta(component TEXT, schema_version INTEGER)"
        )
        connection.execute("INSERT INTO catalog_schema_meta VALUES('unified_catalog', 999)")
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(CatalogStoreError, "catalog_schema_unsupported"):
            CatalogStore(self.path)

    def test_corrupt_persisted_digest_fails_closed(self) -> None:
        self.store.apply_snapshot(
            device_id=ANDROID_DEVICE,
            batch=batch(items=(item("a", "a.md"),)),
        )
        connection = sqlite3.connect(self.path)
        try:
            connection.execute(
                "UPDATE catalog_asset SET revision=?",
                ("A" * 64,),
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(CatalogStoreError, "catalog_integrity_error"):
            self.store.list_assets()
        with self.assertRaisesRegex(CatalogStoreError, "catalog_integrity_error"):
            self.store.projection_sha256()

    def test_mapping_rejects_hash_order_and_name_spoofing(self) -> None:
        valid = batch(items=(item("a", "a.md"), item("b", "b.md")))
        raw = {
            "schema_version": CATALOG_SYNC_SCHEMA,
            "idempotency_key": valid.idempotency_key,
            "catalog_root_id": valid.catalog_root_id,
            "platform": valid.platform,
            "provider": valid.provider,
            "display_name": valid.display_name,
            "base_seq": valid.base_seq,
            "snapshot_sha256": valid.snapshot_sha256,
            "generated_at_ms": valid.generated_at_ms,
            "item_count": valid.item_count,
            "skipped_count": valid.skipped_count,
            "complete_snapshot": True,
            "items": [value.wire() for value in reversed(valid.items)],
        }
        with self.assertRaises(CatalogValidationError):
            catalog_batch_from_mapping(raw)
        raw["items"] = [value.wire() for value in valid.items]
        raw["items"][0]["display_name"] = "safe\u202efdp.exe"
        with self.assertRaises(CatalogValidationError):
            catalog_batch_from_mapping(raw)


if __name__ == "__main__":
    unittest.main()
