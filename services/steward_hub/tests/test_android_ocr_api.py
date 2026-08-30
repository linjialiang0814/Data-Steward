from __future__ import annotations

import base64
import hashlib
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from steward_hub.android_ocr_store import AndroidOcrStore
from steward_hub.api import create_app
from steward_hub.catalog_models import CatalogItemInput, catalog_batch_from_mapping, catalog_snapshot_sha256
from steward_hub.catalog_store import CatalogStore
from steward_hub.device_auth import AUTH_MODE_REQUIRED, required_rest_capability
from steward_hub.pairing_store import PairingStore
from steward_hub.store import EventStore

DEVICE = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
ROOT = "a" * 64
LOCATOR = "b" * 64
REVISION = "c" * 64


class AndroidOcrApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.database = Path(self.temp.name) / "ocr-api.sqlite3"
        self.pairing = PairingStore(self.database, auto_start_runtime=False)
        self.pairing.initialize_hub_identity(
            hub_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
            cert_fingerprint="a" * 64,
            tls_storage_kind="dpapi_encrypted_pkcs8",
            tls_key_ref_id="fixture",
        )
        self.secret = base64.urlsafe_b64encode(bytes([21]) * 32).decode().rstrip("=")
        self.device_id = self._activate()
        self.events = EventStore(self.database)
        self.catalog = CatalogStore(self.database)
        item = CatalogItemInput(
            locator_token=LOCATOR,
            display_name="课堂板书.jpg",
            extension="jpg",
            mime_family="image",
            size_bytes=1000,
            modified_at_ms=1_800_000_000_000,
            revision=REVISION,
            content_eligible=True,
        )
        self.snapshot = catalog_snapshot_sha256(ROOT, (item,), 0)
        self.catalog.apply_snapshot(
            device_id=self.device_id,
            batch=catalog_batch_from_mapping({
                "schema_version": "data-steward.catalog-sync/v1",
                "idempotency_key": "catalog-ocr-api-fixture",
                "catalog_root_id": ROOT,
                "platform": "android",
                "provider": "fixture.documents",
                "display_name": "手机资料",
                "base_seq": 0,
                "snapshot_sha256": self.snapshot,
                "generated_at_ms": 1_800_000_000_000,
                "item_count": 1,
                "skipped_count": 0,
                "complete_snapshot": True,
                "items": [item.wire()],
            }),
        )
        self.ocr = AndroidOcrStore(
            self.database,
            catalog=self.catalog,
            protect=lambda raw: b"sealed:" + raw[::-1],
            unprotect=lambda raw: bytearray(raw.removeprefix(b"sealed:")[::-1]),
        )
        self.app = create_app(
            event_store=self.events,
            pairing_store=self.pairing,
            business_auth_mode=AUTH_MODE_REQUIRED,
            catalog_store=self.catalog,
            android_ocr_store=self.ocr,
        )
        self.client = TestClient(self.app, raise_server_exceptions=False)
        self.client.__enter__()

    def tearDown(self) -> None:
        self.client.__exit__(None, None, None)
        self.ocr.close()
        self.catalog.close()
        self.events.close()
        self.pairing.close()
        self.temp.cleanup()

    def _activate(self) -> str:
        raw = bytes([21]) * 32
        session = self.pairing.create_pairing_session(
            pairing_token_digest=hashlib.sha256(b"ocr-ott").hexdigest(), ttl_seconds=300,
        )
        hello = self.pairing.register_client_hello_digest(
            pairing_session_id=session.pairing_session_id,
            pairing_attempt_id="01ARZ3NDEKTSV4RRFFQ69G5FAW",
            pairing_token_digest=hashlib.sha256(b"ocr-ott").hexdigest(),
            claim_secret_digest=hashlib.sha256(b"ocr-claim").hexdigest(),
            device_credential_digest=hashlib.sha256(raw).hexdigest(),
            client_nonce="AAAAAAAAAAAAAAAAAAAAAA",
            requested_capabilities=["catalog.sync", "content.analyze"],
            display_name="OCR fixture",
            platform="android",
        )
        self.pairing.record_hub_confirmation(
            pairing_session_id=session.pairing_session_id,
            pairing_attempt_id="01ARZ3NDEKTSV4RRFFQ69G5FAW",
            granted_capabilities=["catalog.sync", "content.analyze"],
        )
        self.pairing.record_client_confirmation_digest(
            pairing_session_id=session.pairing_session_id,
            pairing_attempt_id="01ARZ3NDEKTSV4RRFFQ69G5FAW",
            claim_secret_digest=hashlib.sha256(b"ocr-claim").hexdigest(),
            short_verification_code=hello.short_verification_code,
        )
        return hello.device_id

    def _headers(self):
        return {
            "Authorization": f"Bearer {self.secret}",
            "X-DataSteward-Protocol": "pairing_auth/1",
            "X-DataSteward-Device-Id": self.device_id,
            "X-DataSteward-Capability-Epoch": "1",
            "content-type": "application/json",
        }

    def _body(self):
        text = "高等数学 极限与连续"
        return {
            "schema_version": "data-steward.android-ocr-sync/v1",
            "idempotency_key": "ocr-1800000000000-aaaaaaaaaaaa",
            "catalog_root_id": ROOT,
            "snapshot_sha256": self.snapshot,
            "generated_at_ms": 1_800_000_000_100,
            "items": [{
                "locator_token": LOCATOR,
                "revision": REVISION,
                "format": "jpg",
                "status": "recognized",
                "text": text,
                "text_sha256": hashlib.sha256(text.encode()).hexdigest(),
                "char_count": len(text),
                "truncated": False,
                "confidence": 0.9,
                "language_hints": ["zh"],
                "extractor_id": "mlkit-chinese-bundled",
                "extractor_version": "16.0.1",
            }],
        }

    def test_authenticated_upload_replay_and_forget(self) -> None:
        first = self.client.post("/v1/content/android-ocr", headers=self._headers(), json=self._body())
        replay = self.client.post("/v1/content/android-ocr", headers=self._headers(), json=self._body())
        self.assertEqual(200, first.status_code, first.text)
        self.assertEqual(200, replay.status_code, replay.text)
        self.assertFalse(first.json()["deduplicated"])
        self.assertTrue(replay.json()["deduplicated"])
        forgotten = self.client.delete(
            f"/v1/content/android-ocr/{ROOT}",
            headers={key: value for key, value in self._headers().items() if key != "content-type"},
        )
        self.assertEqual({"status": "forgotten", "deleted_count": 1}, forgotten.json())

    def test_route_requires_content_capability(self) -> None:
        self.assertEqual("content.analyze", required_rest_capability("/v1/content/android-ocr"))
        response = self.client.post("/v1/content/android-ocr", json=self._body())
        self.assertEqual(400, response.status_code)


if __name__ == "__main__":
    unittest.main()
