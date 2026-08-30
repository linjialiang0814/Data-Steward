from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from steward_hub.pc_file_scope import PcFileScopeService
from steward_hub.pc_file_scope_persistence import (
    FILE_SCOPE_RECORD_NAME,
    PcFileScopePersistence,
    PcFileScopePersistenceError,
    PersistedPcFileScope,
)


def _protect(raw: bytes) -> bytes:
    return b"sealed:" + raw


def _unprotect(raw: bytes) -> bytearray:
    if not raw.startswith(b"sealed:"):
        raise ValueError("invalid fixture")
    return bytearray(raw.removeprefix(b"sealed:"))


def _noop_security(_: Path) -> None:
    return None


class PcFileScopePersistenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.root = self.base / "DataStewardPcDemo"
        self.root.mkdir()
        (self.root / "fixture.png").write_bytes(b"fixture")
        self.record = self.base / "state" / FILE_SCOPE_RECORD_NAME

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def store(self) -> PcFileScopePersistence:
        return PcFileScopePersistence(
            self.record,
            protect=_protect,
            unprotect=_unprotect,
            apply_root_security=_noop_security,
            verify_root_security=_noop_security,
            verify_file_security=_noop_security,
        )

    def test_atomic_round_trip_and_idempotent_clear(self) -> None:
        value = PersistedPcFileScope(
            root_id="pc-aabbccddeeff",
            canonical_path=str(self.root.resolve()),
            authorized_at="2026-08-03T10:00:00.000Z",
            path_identity="a" * 64,
        )
        store = self.store()

        store.save(value)
        self.assertEqual(value, store.load())
        self.assertEqual([], list(self.record.parent.glob("*.tmp")))

        store.clear()
        store.clear()
        self.assertIsNone(store.load())

    def test_corrupt_record_fails_closed_and_is_not_deleted(self) -> None:
        store = self.store()
        self.record.parent.mkdir()
        self.record.write_bytes(b"not-dpapi")

        with self.assertRaisesRegex(
            PcFileScopePersistenceError,
            "file_scope_store_unavailable",
        ):
            store.load()
        self.assertEqual(b"not-dpapi", self.record.read_bytes())

    def test_service_restores_stable_root_and_forget_survives_restart(self) -> None:
        first = PcFileScopeService(self.store())
        authorized = first.authorize(str(self.root))

        restored_service = PcFileScopeService(self.store())
        restored = restored_service.status()
        self.assertTrue(restored.configured)
        self.assertTrue(restored.remembered)
        self.assertEqual("restored", restored.restore_status)
        self.assertEqual(authorized.root_id, restored.root_id)

        forgotten = restored_service.revoke()
        self.assertFalse(forgotten.configured)
        self.assertFalse(forgotten.remembered)
        self.assertIsNone(self.store().load())
        self.assertFalse(PcFileScopeService(self.store()).status().configured)

    def test_replaced_directory_identity_is_not_restored_or_overwritten(self) -> None:
        service = PcFileScopeService(self.store())
        service.authorize(str(self.root))
        sealed_before = self.record.read_bytes()
        old_root = self.base / "old-root"
        self.root.rename(old_root)
        self.root.mkdir()

        restored = PcFileScopeService(self.store()).status()

        self.assertFalse(restored.configured)
        self.assertTrue(restored.remembered)
        self.assertEqual("unavailable", restored.restore_status)
        self.assertEqual(sealed_before, self.record.read_bytes())


if __name__ == "__main__":
    unittest.main()
