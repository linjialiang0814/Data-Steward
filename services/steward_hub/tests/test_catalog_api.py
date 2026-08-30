from __future__ import annotations

import base64
import hashlib
import tempfile
import time
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from steward_hub.api import create_app
from steward_hub.catalog_api import CatalogRateLimiter
from steward_hub.catalog_models import (
    CATALOG_SYNC_SCHEMA,
    CatalogItemInput,
    catalog_snapshot_sha256,
)
from steward_hub.catalog_store import CatalogStore
from steward_hub.cluster_organization import ClusterOrganizationService
from steward_hub.device_auth import AUTH_MODE_REQUIRED, required_rest_capability
from steward_hub.pairing_store import PairingStore
from steward_hub.pc_file_scope import PcFileScopeService
from steward_hub.store import EventStore


TODAY_MS = int(time.time() * 1000)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _credential(byte: int) -> tuple[str, str]:
    raw = bytes([byte]) * 32
    return (
        base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="),
        hashlib.sha256(raw).hexdigest(),
    )


class CatalogApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "catalog-api.sqlite3"
        self.pairing = PairingStore(self.path, auto_start_runtime=False)
        self.pairing.initialize_hub_identity(
            hub_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
            cert_fingerprint="a" * 64,
            tls_storage_kind="dpapi_encrypted_pkcs8",
            tls_key_ref_id="fixture",
        )
        self.device_id, self.secret = self._activate(
            "01ARZ3NDEKTSV4RRFFQ69G5FAW",
            9,
            ["catalog.sync"],
            "android",
        )
        self.events = EventStore(self.path)
        self.catalog = CatalogStore(self.path)
        self.organization = ClusterOrganizationService(
            catalog=self.catalog,
            file_scope=PcFileScopeService(),
            windows_device_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
        )
        self.app = create_app(
            event_store=self.events,
            pairing_store=self.pairing,
            business_auth_mode=AUTH_MODE_REQUIRED,
            catalog_store=self.catalog,
            cluster_organization_service=self.organization,
        )
        self.client = TestClient(self.app, raise_server_exceptions=False)
        self.client.__enter__()

    def tearDown(self) -> None:
        self.client.__exit__(None, None, None)
        self.catalog.close()
        self.events.close()
        self.pairing.close()
        self.temp.cleanup()

    def _activate(
        self,
        attempt_id: str,
        byte: int,
        capabilities: list[str],
        platform: str,
    ) -> tuple[str, str]:
        secret, credential_digest = _credential(byte)
        session = self.pairing.create_pairing_session(
            pairing_token_digest=_digest("ott-" + attempt_id),
            ttl_seconds=300,
        )
        hello = self.pairing.register_client_hello_digest(
            pairing_session_id=session.pairing_session_id,
            pairing_attempt_id=attempt_id,
            pairing_token_digest=_digest("ott-" + attempt_id),
            claim_secret_digest=_digest("claim-" + attempt_id),
            device_credential_digest=credential_digest,
            client_nonce="AAAAAAAAAAAAAAAAAAAAAA",
            requested_capabilities=capabilities,
            display_name="Catalog fixture",
            platform=platform,
        )
        self.pairing.record_hub_confirmation(
            pairing_session_id=session.pairing_session_id,
            pairing_attempt_id=attempt_id,
            granted_capabilities=capabilities,
        )
        self.pairing.record_client_confirmation_digest(
            pairing_session_id=session.pairing_session_id,
            pairing_attempt_id=attempt_id,
            claim_secret_digest=_digest("claim-" + attempt_id),
            short_verification_code=hello.short_verification_code,
        )
        return hello.device_id, secret

    def _headers(self, device_id: str | None = None, secret: str | None = None):
        return {
            "Authorization": f"Bearer {secret or self.secret}",
            "X-DataSteward-Protocol": "pairing_auth/1",
            "X-DataSteward-Device-Id": device_id or self.device_id,
            "X-DataSteward-Capability-Epoch": "1",
        }

    def test_organization_requires_files_organize_in_addition_to_catalog(self) -> None:
        response = self.client.post(
            "/v1/catalog/organization/preview",
            headers={**self._headers(), "content-type": "application/json"},
            json={
                "schema_version": "data-steward.cluster-organization/v1",
                "cluster_id": "cl-0123456789abcdef",
                "projection_sha256": "a" * 64,
            },
        )
        self.assertEqual(403, response.status_code)
        self.assertEqual("capability_denied", response.json()["error_code"])
        status = self.client.get(
            "/v1/catalog/organization/status",
            headers=self._headers(),
        )
        self.assertEqual(403, status.status_code)
        self.assertEqual("capability_denied", status.json()["error_code"])

    @staticmethod
    def _payload(*, base_seq: int = 0, key: str = "catalog-http-0001"):
        item = CatalogItemInput(
            locator_token="b" * 64,
            display_name="lecture-notes.md",
            extension="md",
            mime_family="text",
            size_bytes=12,
            modified_at_ms=TODAY_MS,
            revision="c" * 64,
            content_eligible=True,
        )
        root = "d" * 64
        return {
            "schema_version": CATALOG_SYNC_SCHEMA,
            "idempotency_key": key,
            "catalog_root_id": root,
            "platform": "android",
            "provider": "com.android.externalstorage.documents",
            "display_name": "Mobile notes",
            "base_seq": base_seq,
            "snapshot_sha256": catalog_snapshot_sha256(root, [item], 0),
            "generated_at_ms": TODAY_MS,
            "item_count": 1,
            "skipped_count": 0,
            "complete_snapshot": True,
            "items": [item.wire()],
        }

    def test_snapshot_is_authenticated_idempotent_and_queryable(self) -> None:
        first = self.client.post(
            "/v1/catalog/snapshots", json=self._payload(), headers=self._headers()
        )
        replay = self.client.post(
            "/v1/catalog/snapshots", json=self._payload(), headers=self._headers()
        )
        roots = self.client.get("/v1/catalog/roots", headers=self._headers())
        assets = self.client.get("/v1/catalog/assets", headers=self._headers())
        today = self.client.get("/v1/catalog/today", headers=self._headers())
        self.assertEqual(200, first.status_code)
        self.assertEqual(1, first.json()["accepted_seq"])
        self.assertFalse(first.json()["deduplicated"])
        self.assertTrue(replay.json()["deduplicated"])
        self.assertEqual(1, len(roots.json()["roots"]))
        self.assertEqual("lecture-notes.md", assets.json()["assets"][0]["display_name"])
        self.assertEqual(200, today.status_code)
        self.assertEqual("data-steward.today-materials/v1", today.json()["schema_version"])
        self.assertEqual(1, today.json()["asset_count"])
        self.assertEqual(1, today.json()["unassigned_count"])

    def test_cursor_conflict_and_duplicate_json_fail_closed(self) -> None:
        self.client.post(
            "/v1/catalog/snapshots", json=self._payload(), headers=self._headers()
        )
        conflict = self.client.post(
            "/v1/catalog/snapshots",
            json=self._payload(key="catalog-http-0002"),
            headers=self._headers(),
        )
        duplicate = self.client.post(
            "/v1/catalog/snapshots",
            content=b'{"schema_version":"a","schema_version":"b"}',
            headers={**self._headers(), "content-type": "application/json"},
        )
        self.assertEqual(409, conflict.status_code)
        self.assertEqual(1, conflict.json()["server_catalog_seq"])
        self.assertEqual(400, duplicate.status_code)
        self.assertEqual(1, self.catalog.current_seq(self.device_id, "d" * 64))

    def test_capability_platform_and_missing_auth_are_rejected(self) -> None:
        denied_id, denied_secret = self._activate(
            "01ARZ3NDEKTSV4RRFFQ69G5FAX", 10, ["session.sync"], "android"
        )
        denied = self.client.post(
            "/v1/catalog/snapshots",
            json=self._payload(),
            headers=self._headers(denied_id, denied_secret),
        )
        missing = self.client.post("/v1/catalog/snapshots", json=self._payload())
        mismatched = self._payload()
        mismatched["platform"] = "windows"
        wrong_platform = self.client.post(
            "/v1/catalog/snapshots", json=mismatched, headers=self._headers()
        )
        self.assertEqual(403, denied.status_code)
        self.assertEqual(400, missing.status_code)
        self.assertEqual("protocol_version_rejected", missing.json()["error_code"])
        self.assertEqual(400, wrong_platform.status_code)
        self.assertEqual((), self.catalog.list_assets())

    def test_rate_limit_and_namespace_policy(self) -> None:
        limited_app = create_app(
            event_store=self.events,
            pairing_store=self.pairing,
            business_auth_mode=AUTH_MODE_REQUIRED,
            catalog_store=self.catalog,
            catalog_rate_limiter=CatalogRateLimiter(write_limit=1),
        )
        with TestClient(limited_app, raise_server_exceptions=False) as client:
            first = client.post(
                "/v1/catalog/snapshots", json=self._payload(), headers=self._headers()
            )
            second = client.post(
                "/v1/catalog/snapshots", json=self._payload(), headers=self._headers()
            )
        self.assertEqual(200, first.status_code)
        self.assertEqual(429, second.status_code)
        self.assertGreaterEqual(int(second.headers["Retry-After"]), 1)
        self.assertEqual("catalog.sync", required_rest_capability("/v1/catalog/assets"))
        self.assertEqual("catalog.sync", required_rest_capability("/v1/catalog/today"))

    def test_catalog_cannot_mount_on_unauthenticated_surface(self) -> None:
        with self.assertRaisesRegex(ValueError, "operator file scope"):
            create_app(
                event_store=self.events,
                pairing_store=self.pairing,
                catalog_store=self.catalog,
            )


if __name__ == "__main__":
    unittest.main()
