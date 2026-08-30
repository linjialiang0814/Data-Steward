from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from steward_hub.content_projection import (
    ContentProjection,
    ContentProjectionError,
    open_content_projection,
    seal_content_projection,
)
from steward_hub.content_understanding import (
    ContentUnderstandingError,
    ContentUnderstandingStore,
)

ASSET_ID = "a" * 64
REVISION = "b" * 64
ROOT_ID = "pc-123456789abc"
DEVICE_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
MARKER = "S6B-PROJECTION-PLAINTEXT-MARKER"
KEY = b"s6b-hermetic-projection-key"


def protect(value: bytes) -> bytes:
    cipher = bytes(byte ^ KEY[index % len(KEY)] for index, byte in enumerate(value))
    return b"S6B1" + hashlib.sha256(KEY + value).digest() + cipher


def unprotect(value: bytes) -> bytearray:
    if not value.startswith(b"S6B1") or len(value) < 36:
        raise ValueError("sealed_invalid")
    digest = value[4:36]
    cipher = value[36:]
    plain = bytes(
        byte ^ KEY[index % len(KEY)] for index, byte in enumerate(cipher)
    )
    if hashlib.sha256(KEY + plain).digest() != digest:
        raise ValueError("sealed_invalid")
    return bytearray(plain)


def projection(*, revision: str = REVISION) -> ContentProjection:
    created = datetime(2026, 8, 5, 8, 0, tzinfo=UTC)
    return ContentProjection(
        asset_id=ASSET_ID,
        device_id=DEVICE_ID,
        catalog_root_id=ROOT_ID,
        revision=revision,
        format="docx",
        source_label="课程讲义.docx",
        text=MARKER,
        text_sha256=hashlib.sha256(MARKER.encode()).hexdigest(),
        char_count=len(MARKER),
        truncated=False,
        unit_count=2,
        created_at=created.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        expires_at=(created + timedelta(days=7))
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z"),
    )


class ContentProjectionTests(unittest.TestCase):
    def test_envelope_round_trip_and_binding(self) -> None:
        expected = projection()
        blob = seal_content_projection(expected, protect=protect)
        self.assertNotIn(MARKER.encode(), blob)
        actual = open_content_projection(
            blob,
            unprotect=unprotect,
            expected_asset_id=ASSET_ID,
            expected_device_id=DEVICE_ID,
            expected_root_id=ROOT_ID,
            expected_revision=REVISION,
        )
        self.assertEqual(actual, expected)
        with self.assertRaisesRegex(
            ContentProjectionError, "content_projection_integrity_error"
        ):
            open_content_projection(
                blob,
                unprotect=unprotect,
                expected_asset_id="c" * 64,
                expected_device_id=DEVICE_ID,
                expected_root_id=ROOT_ID,
                expected_revision=REVISION,
            )

    def test_tampered_blob_fails_closed(self) -> None:
        blob = bytearray(seal_content_projection(projection(), protect=protect))
        blob[-1] ^= 1
        with self.assertRaisesRegex(
            ContentProjectionError, "content_projection_integrity_error"
        ):
            open_content_projection(
                bytes(blob),
                unprotect=unprotect,
                expected_asset_id=ASSET_ID,
                expected_device_id=DEVICE_ID,
                expected_root_id=ROOT_ID,
                expected_revision=REVISION,
            )

    def test_store_migrates_v1_and_never_persists_plaintext(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "hub.sqlite3"
            connection = sqlite3.connect(database)
            connection.execute(
                "CREATE TABLE content_schema_meta(component TEXT PRIMARY KEY, schema_version INTEGER NOT NULL)"
            )
            connection.execute(
                "INSERT INTO content_schema_meta VALUES('content_understanding',1)"
            )
            connection.execute(
                """
                CREATE TABLE content_study_pack(
                  snapshot_sha256 TEXT PRIMARY KEY,
                  projection_sha256 TEXT NOT NULL,
                  payload_json TEXT NOT NULL,
                  source TEXT NOT NULL,
                  created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "INSERT INTO content_study_pack VALUES(?,?,?,?,?)",
                (
                    "d" * 64,
                    "e" * 64,
                    '{"marker":"S6B-LEGACY-STUDY-PACK-MARKER"}',
                    "deterministic_fallback",
                    "2026-08-05T08:00:00.000Z",
                ),
            )
            connection.commit()
            connection.close()
            clock = [datetime(2026, 8, 5, 9, 0, tzinfo=UTC)]
            store = ContentUnderstandingStore(
                database,
                protect_projection=protect,
                unprotect_projection=unprotect,
                now=lambda: clock[0],
            )
            try:
                store.set_opt_in(DEVICE_ID, ROOT_ID, True)
                store.save_projection(projection())
                loaded = store.load_projection(
                    asset_id=ASSET_ID,
                    device_id=DEVICE_ID,
                    root_id=ROOT_ID,
                    revision=REVISION,
                )
                self.assertEqual(loaded, projection())
            finally:
                store.close()
            residual = b"".join(
                path.read_bytes() for path in database.parent.glob("hub.sqlite3*")
            )
            self.assertNotIn(MARKER.encode(), residual)
            self.assertNotIn(b"S6B-LEGACY-STUDY-PACK-MARKER", residual)
            connection = sqlite3.connect(database)
            version = connection.execute(
                "SELECT schema_version FROM content_schema_meta"
            ).fetchone()
            legacy_count = connection.execute(
                "SELECT count(*) FROM content_study_pack"
            ).fetchone()
            connection.close()
            self.assertEqual(version, (2,))
            self.assertEqual(legacy_count, (0,))

    def test_expiration_revision_and_opt_out_forget_projection(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "hub.sqlite3"
            clock = [datetime(2026, 8, 5, 9, 0, tzinfo=UTC)]
            store = ContentUnderstandingStore(
                database,
                protect_projection=protect,
                unprotect_projection=unprotect,
                now=lambda: clock[0],
            )
            try:
                store.set_opt_in(DEVICE_ID, ROOT_ID, True)
                store.save_projection(projection())
                self.assertIsNone(
                    store.load_projection(
                        asset_id=ASSET_ID,
                        device_id=DEVICE_ID,
                        root_id=ROOT_ID,
                        revision="c" * 64,
                    )
                )
                clock[0] = datetime(2026, 8, 12, 9, 0, 1, tzinfo=UTC)
                self.assertIsNone(
                    store.load_projection(
                        asset_id=ASSET_ID,
                        device_id=DEVICE_ID,
                        root_id=ROOT_ID,
                        revision=REVISION,
                    )
                )
                clock[0] = datetime(2026, 8, 5, 9, 0, tzinfo=UTC)
                store.save_projection(projection())
                store.set_opt_in(DEVICE_ID, ROOT_ID, False)
                self.assertIsNone(
                    store.load_projection(
                        asset_id=ASSET_ID,
                        device_id=DEVICE_ID,
                        root_id=ROOT_ID,
                        revision=REVISION,
                    )
                )
            finally:
                store.close()

    def test_unknown_schema_still_fails_before_migration(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "hub.sqlite3"
            connection = sqlite3.connect(database)
            connection.execute(
                "CREATE TABLE content_schema_meta(component TEXT PRIMARY KEY, schema_version INTEGER NOT NULL)"
            )
            connection.execute(
                "INSERT INTO content_schema_meta VALUES('content_understanding',999)"
            )
            connection.commit()
            connection.close()
            with self.assertRaisesRegex(
                ContentUnderstandingError, "content_schema_unsupported"
            ):
                ContentUnderstandingStore(
                    database,
                    protect_projection=protect,
                    unprotect_projection=unprotect,
                )


if __name__ == "__main__":
    unittest.main()
