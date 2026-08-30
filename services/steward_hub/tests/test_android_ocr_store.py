from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from steward_hub.android_ocr_store import (
    ANDROID_OCR_SYNC_SCHEMA,
    AndroidOcrStore,
    AndroidOcrStoreError,
    android_ocr_batch_from_mapping,
)
from steward_hub.catalog_models import CatalogItemInput, catalog_batch_from_mapping, catalog_snapshot_sha256
from steward_hub.catalog_store import CatalogStore
from steward_hub.content_understanding import ContentUnderstandingService, ContentUnderstandingStore
from steward_hub.pc_file_scope import PcFileScopeService

DEVICE = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
ROOT = "a" * 64
LOCATOR = "b" * 64
REVISION = "c" * 64
WINDOWS_DEVICE = "01ARZ3NDEKTSV4RRFFQ69G5FAW"


def _catalog_batch():
    item = CatalogItemInput(
        locator_token=LOCATOR,
        display_name="课堂板书.png",
        extension="png",
        mime_family="image",
        size_bytes=1024,
        modified_at_ms=1_800_000_000_000,
        revision=REVISION,
        content_eligible=True,
    )
    value = {
        "schema_version": "data-steward.catalog-sync/v1",
        "idempotency_key": "catalog-ocr-fixture-01",
        "catalog_root_id": ROOT,
        "platform": "android",
        "provider": "fixture.documents",
        "display_name": "手机课堂资料",
        "base_seq": 0,
        "snapshot_sha256": catalog_snapshot_sha256(ROOT, (item,), 0),
        "generated_at_ms": 1_800_000_000_000,
        "item_count": 1,
        "skipped_count": 0,
        "complete_snapshot": True,
        "items": [item.wire()],
    }
    return catalog_batch_from_mapping(value)


def _ocr_mapping(*, text: str = "高等数学 极限与连续", key: str = "ocr-1800000000000-aaaaaaaaaaaa"):
    catalog = _catalog_batch()
    return {
        "schema_version": ANDROID_OCR_SYNC_SCHEMA,
        "idempotency_key": key,
        "catalog_root_id": ROOT,
        "snapshot_sha256": catalog.snapshot_sha256,
        "generated_at_ms": 1_800_000_000_100,
        "items": [{
            "locator_token": LOCATOR,
            "revision": REVISION,
            "format": "png",
            "status": "recognized" if text else "no_text",
            "text": text,
            "text_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "char_count": len(text),
            "truncated": False,
            "confidence": 0.92,
            "language_hints": ["zh"],
            "extractor_id": "mlkit-chinese-bundled",
            "extractor_version": "16.0.1",
        }],
    }


class AndroidOcrStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.database = Path(self.temp.name) / "hub.sqlite3"
        self.catalog = CatalogStore(self.database)
        self.catalog.apply_snapshot(device_id=DEVICE, batch=_catalog_batch())
        self.store = AndroidOcrStore(
            self.database,
            catalog=self.catalog,
            protect=lambda raw: b"sealed:" + raw[::-1],
            unprotect=lambda raw: bytearray(raw.removeprefix(b"sealed:")[::-1]),
        )

    def tearDown(self) -> None:
        self.store.close()
        self.catalog.close()
        self.temp.cleanup()

    def test_apply_is_encrypted_and_idempotent(self) -> None:
        batch = android_ocr_batch_from_mapping(_ocr_mapping())
        first = self.store.apply(device_id=DEVICE, batch=batch)
        replay = self.store.apply(device_id=DEVICE, batch=batch)
        self.assertEqual(1, first.accepted_count)
        self.assertEqual(1, first.recognized_count)
        self.assertFalse(first.deduplicated)
        self.assertTrue(replay.deduplicated)
        self.assertEqual(first.projection_sha256, replay.projection_sha256)
        connection = sqlite3.connect(self.database)
        blob = bytes(connection.execute(
            "SELECT encrypted_projection FROM android_ocr_projection"
        ).fetchone()[0])
        request_row = connection.execute(
            "SELECT request_sha256,receipt_json FROM android_ocr_request"
        ).fetchone()
        connection.close()
        self.assertNotIn("高等数学".encode(), blob)
        self.assertNotIn("高等数学", str(request_row))
        projected = self.store.list_projected_assets()
        self.assertEqual(["课堂板书.png"], [asset.display_name for asset in projected])
        opened = self.store.load_text(
            asset_id=projected[0].asset_id,
            device_id=DEVICE,
            root_id=ROOT,
            revision=REVISION,
        )
        self.assertIsNotNone(opened)
        self.assertEqual("高等数学 极限与连续", opened.text)

    def test_changed_idempotency_key_payload_is_rejected_without_overwrite(self) -> None:
        self.store.apply(device_id=DEVICE, batch=android_ocr_batch_from_mapping(_ocr_mapping()))
        with self.assertRaisesRegex(AndroidOcrStoreError, "ocr_idempotency_conflict"):
            self.store.apply(
                device_id=DEVICE,
                batch=android_ocr_batch_from_mapping(_ocr_mapping(text="篡改正文")),
            )
        connection = sqlite3.connect(self.database)
        self.assertEqual(1, connection.execute("SELECT count(*) FROM android_ocr_projection").fetchone()[0])
        connection.close()

    def test_catalog_revision_and_snapshot_are_bound(self) -> None:
        stale = _ocr_mapping()
        stale["snapshot_sha256"] = "d" * 64
        with self.assertRaisesRegex(AndroidOcrStoreError, "ocr_snapshot_stale"):
            self.store.apply(device_id=DEVICE, batch=android_ocr_batch_from_mapping(stale))
        changed = _ocr_mapping()
        changed["items"][0]["revision"] = "e" * 64
        with self.assertRaisesRegex(AndroidOcrStoreError, "ocr_revision_changed"):
            self.store.apply(device_id=DEVICE, batch=android_ocr_batch_from_mapping(changed))

    def test_low_confidence_text_is_sealed_but_excluded_from_content_context(self) -> None:
        mapping = _ocr_mapping()
        mapping["items"][0]["confidence"] = 0.2
        receipt = self.store.apply(
            device_id=DEVICE,
            batch=android_ocr_batch_from_mapping(mapping),
        )
        self.assertEqual(1, receipt.low_confidence_count)
        self.assertEqual((), self.store.list_projected_assets())

    def test_strict_input_and_forget(self) -> None:
        invalid = _ocr_mapping()
        invalid["items"][0]["text_sha256"] = "f" * 64
        with self.assertRaisesRegex(AndroidOcrStoreError, "ocr_request_invalid"):
            android_ocr_batch_from_mapping(invalid)
        self.store.apply(device_id=DEVICE, batch=android_ocr_batch_from_mapping(_ocr_mapping()))
        self.assertEqual(1, self.store.forget_root(device_id=DEVICE, root_id=ROOT))
        self.assertEqual(0, self.store.forget_root(device_id=DEVICE, root_id=ROOT))

    def test_android_projection_participates_in_safe_content_context(self) -> None:
        self.store.apply(device_id=DEVICE, batch=android_ocr_batch_from_mapping(_ocr_mapping()))
        pc_root = Path(self.temp.name) / "pc"
        pc_root.mkdir()
        (pc_root / "课程安排.md").write_text("今天复习课程安排。", encoding="utf-8")
        scope = PcFileScopeService()
        scope.authorize(str(pc_root))
        self.catalog.apply_snapshot(
            device_id=WINDOWS_DEVICE,
            batch=scope.catalog_snapshot(
                base_seq=0,
                idempotency_key="ocr-content-context-01",
                generated_at_ms=1_800_000_000_000,
            ),
        )
        content_store = ContentUnderstandingStore(
            self.database,
            protect_projection=lambda raw: b"sealed:" + raw[::-1],
            unprotect_projection=lambda raw: bytearray(raw.removeprefix(b"sealed:")[::-1]),
        )
        try:
            content = ContentUnderstandingService(
                store=content_store,
                catalog=self.catalog,
                file_scope=scope,
                windows_device_id=WINDOWS_DEVICE,
                android_ocr_store=self.store,
            )
            content.set_opt_in(True)
            snapshot = content.current_snapshot()
            assets = content.list_safe_assets(snapshot_sha256=snapshot)
            self.assertEqual({"课程安排.md", "课堂板书.png"}, {asset.display_name for asset in assets})
            excerpts = content.extract_assets(snapshot_sha256=snapshot)
            self.assertIn("高等数学 极限与连续", {item.excerpt for item in excerpts})
        finally:
            content_store.close()


if __name__ == "__main__":
    unittest.main()
