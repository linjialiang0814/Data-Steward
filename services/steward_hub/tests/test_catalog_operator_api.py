from __future__ import annotations

import base64
import hashlib
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from steward_hub.api import create_app
from steward_hub.catalog_store import CatalogStore
from steward_hub.cluster_organization import ClusterOrganizationService
from steward_hub.device_connection_registry import DeviceConnectionRegistry
from steward_hub.pairing_store import PairingStore
from steward_hub.pc_file_organizer_journal import OrganizerJournalStore
from steward_hub.pc_file_scope import PcFileScopeService
from steward_hub.store import EventStore


class CatalogOperatorApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.database = root / "catalog.sqlite3"
        self.scope_root = root / "PcCatalogFixture"
        self.scope_root.mkdir()
        (self.scope_root / "project-courseware.pdf").write_bytes(b"pdf fixture")
        (self.scope_root / "project-notes.md").write_text("fixture", encoding="utf-8")
        self.secret = base64.urlsafe_b64encode(bytes([17]) * 32).decode().rstrip("=")
        self.digest = hashlib.sha256(bytes([17]) * 32).hexdigest()
        self.pairing = PairingStore(self.database, auto_start_runtime=False)
        self.pairing.initialize_hub_identity(
            hub_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
            cert_fingerprint="a" * 64,
            tls_storage_kind="dpapi_encrypted_pkcs8",
            tls_key_ref_id="fixture",
        )
        self.events = EventStore(self.database)
        self.catalog = CatalogStore(self.database)
        journal = OrganizerJournalStore(
            root / "journal" / "journal.dpapi",
            protect=lambda value: b"sealed:" + value,
            unprotect=lambda value: bytearray(value.removeprefix(b"sealed:")),
            apply_root_security=lambda _path: None,
            verify_root_security=lambda _path: None,
            verify_file_security=lambda _path: None,
        )
        self.scope = PcFileScopeService(organizer_journal=journal)
        self.scope.authorize(str(self.scope_root))
        self.organization = ClusterOrganizationService(
            catalog=self.catalog,
            file_scope=self.scope,
            windows_device_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
        )
        self.app = create_app(
            event_store=self.events,
            pairing_store=self.pairing,
            operator_token_digest=self.digest,
            pc_file_scope_service=self.scope,
            catalog_store=self.catalog,
            cluster_organization_service=self.organization,
            device_connection_registry=DeviceConnectionRegistry(),
            pairing_routes_enabled=False,
        )
        self.client = TestClient(self.app, raise_server_exceptions=False)
        self.client.__enter__()

    def tearDown(self) -> None:
        self.client.__exit__(None, None, None)
        self.catalog.close()
        self.events.close()
        self.pairing.close()
        self.temp.cleanup()

    def _headers(self) -> dict[str, str]:
        return {
            "authorization": f"DataSteward-Operator {self.secret}",
            "x-datasteward-protocol": "pairing_auth/1",
        }

    def test_pc_refresh_and_unified_summary(self) -> None:
        first = self.client.post(
            "/v1/operator/catalog/refresh-pc", headers=self._headers()
        )
        second = self.client.post(
            "/v1/operator/catalog/refresh-pc", headers=self._headers()
        )
        summary = self.client.get(
            "/v1/operator/catalog/summary", headers=self._headers()
        )
        today = self.client.get(
            "/v1/operator/catalog/today", headers=self._headers()
        )
        self.assertEqual(200, first.status_code)
        self.assertTrue(first.json()["changed"])
        self.assertEqual(1, first.json()["accepted_seq"])
        self.assertFalse(second.json()["changed"])
        self.assertEqual(1, second.json()["accepted_seq"])
        self.assertEqual(1, summary.json()["root_count"])
        self.assertEqual(2, summary.json()["asset_count"])
        self.assertEqual(
            ["project-courseware.pdf", "project-notes.md"],
            [item["display_name"] for item in summary.json()["assets"]],
        )
        self.assertNotIn(str(self.scope_root), summary.text)
        self.assertEqual(200, today.status_code)
        self.assertEqual("data-steward.today-materials/v1", today.json()["schema_version"])
        self.assertEqual(2, today.json()["asset_count"])
        self.assertNotIn(str(self.scope_root), today.text)

    def test_operator_auth_is_required(self) -> None:
        response = self.client.get("/v1/operator/catalog/summary")
        self.assertEqual(401, response.status_code)
        self.assertEqual("operator_invalid", response.json()["error_code"])

    def test_operator_cluster_organization_requires_preview_and_can_undo(self) -> None:
        refresh = self.client.post(
            "/v1/operator/catalog/refresh-pc", headers=self._headers()
        )
        self.assertEqual(200, refresh.status_code)
        today = self.client.get(
            "/v1/operator/catalog/today", headers=self._headers()
        ).json()
        self.assertEqual(1, today["cluster_count"])
        cluster = today["clusters"][0]
        request = {
            "schema_version": "data-steward.cluster-organization/v1",
            "cluster_id": cluster["cluster_id"],
            "projection_sha256": today["projection_sha256"],
        }
        preview = self.client.post(
            "/v1/operator/catalog/organization/preview",
            headers={**self._headers(), "content-type": "application/json"},
            json=request,
        )
        self.assertEqual(200, preview.status_code)
        self.assertEqual(2, preview.json()["pc_file_count"])
        execute = self.client.post(
            "/v1/operator/catalog/organization/execute",
            headers={**self._headers(), "content-type": "application/json"},
            json={**request, "preview_sha256": preview.json()["preview_sha256"]},
        )
        self.assertEqual(200, execute.status_code)
        self.assertEqual(2, execute.json()["moved_count"])
        self.assertFalse((self.scope_root / "project-notes.md").exists())
        status = self.client.get(
            "/v1/operator/catalog/organization/status",
            headers=self._headers(),
        )
        self.assertEqual(200, status.status_code)
        self.assertEqual("undo_available", status.json()["state"])
        self.assertTrue(status.json()["can_undo"])
        self.assertEqual(execute.json()["undo_token"], status.json()["undo_token"])
        self.assertNotIn(str(self.scope_root), status.text)
        undo = self.client.post(
            "/v1/operator/catalog/organization/undo",
            headers={**self._headers(), "content-type": "application/json"},
            json={
                "schema_version": "data-steward.cluster-organization/v1",
                "undo_token": execute.json()["undo_token"],
            },
        )
        self.assertEqual(200, undo.status_code)
        self.assertTrue((self.scope_root / "project-notes.md").is_file())
        idle = self.client.get(
            "/v1/operator/catalog/organization/status",
            headers=self._headers(),
        )
        self.assertEqual("idle", idle.json()["state"])
        self.assertFalse(idle.json()["can_undo"])
        self.assertIsNone(idle.json()["undo_token"])

    def test_operator_organization_status_requires_auth(self) -> None:
        response = self.client.get("/v1/operator/catalog/organization/status")
        self.assertEqual(401, response.status_code)
        self.assertEqual("operator_invalid", response.json()["error_code"])

    def test_replacing_pc_scope_removes_previous_windows_root(self) -> None:
        first = self.client.post(
            "/v1/operator/catalog/refresh-pc", headers=self._headers()
        )
        self.assertEqual(200, first.status_code)
        old_root_id = first.json()["catalog_root_id"]

        replacement = Path(self.temp.name) / "StableStudentFixture"
        replacement.mkdir()
        (replacement / "lesson.md").write_text("safe fixture", encoding="utf-8")
        self.scope.authorize(str(replacement))
        second = self.client.post(
            "/v1/operator/catalog/refresh-pc", headers=self._headers()
        )
        self.assertEqual(200, second.status_code)
        self.assertNotEqual(old_root_id, second.json()["catalog_root_id"])

        summary = self.client.get(
            "/v1/operator/catalog/summary", headers=self._headers()
        )
        self.assertEqual(200, summary.status_code)
        self.assertEqual(1, summary.json()["root_count"])
        self.assertEqual(1, summary.json()["asset_count"])
        self.assertEqual("lesson.md", summary.json()["assets"][0]["display_name"])
        self.assertNotIn(old_root_id, summary.text)


if __name__ == "__main__":
    unittest.main()
