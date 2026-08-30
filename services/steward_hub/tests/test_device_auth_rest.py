from __future__ import annotations

import base64
import hashlib
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from steward_hub.api import create_app
from steward_hub.agent_planning import AgentPlanningError, ReadOnlyPlan
from steward_hub.archive_memory import ArchiveMemoryService
from steward_hub.device_auth import (
    AUTH_MODE_REQUIRED,
    required_rest_capability,
    validate_auth_mode,
    validate_device_auth_timeout_s,
)
from steward_hub.pairing_store import PairingStore
from steward_hub.pairing_errors import PairingPersistenceError
from steward_hub.pairing_store_executor import (
    PairingStoreExecutor,
    PairingStoreSaturatedError,
)
from steward_hub.store import EventStore
from steward_hub.pc_file_scope import PcFileScopeService


class _PlannerFixture:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls = 0

    def plan(self, *, user_text: str, scope: object) -> ReadOnlyPlan:
        self.calls += 1
        if self.fail:
            raise AgentPlanningError("planner_unavailable")
        return ReadOnlyPlan(
            intent="count_images",
            query=None,
            scope_ref=f"scope:{getattr(scope, 'root_id')}",
            citations=(
                f"scope:{getattr(scope, 'root_id')}",
                "capability:files.read",
            ),
            plan_sha256="a" * 64,
        )


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _secret(byte: int) -> tuple[str, str]:
    raw = bytes([byte]) * 32
    encoded = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return encoded, hashlib.sha256(raw).hexdigest()


class DeviceAuthRestTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self._temporary_directory.name) / "auth.sqlite3"
        self.pairing_store = PairingStore(
            self.database_path,
            auto_start_runtime=False,
        )
        self.pairing_store.initialize_hub_identity(
            hub_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
            cert_fingerprint="a" * 64,
            tls_storage_kind="dpapi_encrypted_pkcs8",
            tls_key_ref_id="test-identity",
        )
        self.device_id, self.secret = self._activate_device(
            attempt_id="01ARZ3NDEKTSV4RRFFQ69G5FAW",
            secret_byte=7,
            capabilities=["session.sync"],
        )
        self.event_store = EventStore(self.database_path)
        self.file_scope = PcFileScopeService()
        self.archive_memory = ArchiveMemoryService(
            self.database_path,
            self.file_scope,
        )
        self.app = create_app(
            event_store=self.event_store,
            pairing_store=self.pairing_store,
            business_auth_mode=AUTH_MODE_REQUIRED,
            pc_file_scope_service=self.file_scope,
            archive_memory_service=self.archive_memory,
        )
        self.client = TestClient(self.app, raise_server_exceptions=False)
        self.client.__enter__()

    def tearDown(self) -> None:
        self.client.__exit__(None, None, None)
        self.archive_memory.close()
        self.event_store.close()
        self.pairing_store.close()
        self._temporary_directory.cleanup()

    def _activate_device(
        self,
        *,
        attempt_id: str,
        secret_byte: int,
        capabilities: list[str],
    ) -> tuple[str, str]:
        secret, credential_digest = _secret(secret_byte)
        session = self.pairing_store.create_pairing_session(
            pairing_token_digest=_digest(f"ott-{attempt_id}"),
            ttl_seconds=300,
        )
        hello = self.pairing_store.register_client_hello_digest(
            pairing_session_id=session.pairing_session_id,
            pairing_attempt_id=attempt_id,
            pairing_token_digest=_digest(f"ott-{attempt_id}"),
            claim_secret_digest=_digest(f"claim-{attempt_id}"),
            device_credential_digest=credential_digest,
            client_nonce="AAAAAAAAAAAAAAAAAAAAAA",
            requested_capabilities=capabilities,
            display_name="Test device",
            platform="test",
        )
        self.pairing_store.record_hub_confirmation(
            pairing_session_id=session.pairing_session_id,
            pairing_attempt_id=attempt_id,
            granted_capabilities=capabilities,
        )
        self.pairing_store.record_client_confirmation_digest(
            pairing_session_id=session.pairing_session_id,
            pairing_attempt_id=attempt_id,
            claim_secret_digest=_digest(f"claim-{attempt_id}"),
            short_verification_code=hello.short_verification_code,
        )
        return hello.device_id, secret

    def _headers(
        self,
        *,
        device_id: str | None = None,
        secret: str | None = None,
        epoch: str = "1",
    ) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {secret or self.secret}",
            "X-DataSteward-Protocol": "pairing_auth/1",
            "X-DataSteward-Device-Id": device_id or self.device_id,
            "X-DataSteward-Capability-Epoch": epoch,
        }

    def _pending_device(self, *, secret_byte: int) -> tuple[str, str]:
        secret, credential_digest = _secret(secret_byte)
        attempt_id = "01ARZ3NDEKTSV4RRFFQ69G5FB1"
        session = self.pairing_store.create_pairing_session(
            pairing_token_digest=_digest("ott-pending-auth"),
            ttl_seconds=300,
        )
        hello = self.pairing_store.register_client_hello_digest(
            pairing_session_id=session.pairing_session_id,
            pairing_attempt_id=attempt_id,
            pairing_token_digest=_digest("ott-pending-auth"),
            claim_secret_digest=_digest("claim-pending-auth"),
            device_credential_digest=credential_digest,
            client_nonce="BBBBBBBBBBBBBBBBBBBBBB",
            requested_capabilities=["session.sync"],
            platform="test",
        )
        return hello.device_id, secret

    def _create_conversation(self, suffix: str = "main") -> str:
        conversation_id = f"auth-conversation-{suffix}"
        response = self.client.post(
            "/v1/conversations",
            headers=self._headers(),
            json={"title": "Authenticated", "conversation_id": conversation_id},
        )
        self.assertEqual(201, response.status_code, response.text)
        return conversation_id

    def test_device_self_refreshes_current_epoch_without_trusting_cached_epoch(
        self,
    ) -> None:
        device_id, secret = self._activate_device(
            attempt_id="01ARZ3NDEKTSV4RRFFQ69G5FB6",
            secret_byte=16,
            capabilities=["files.read", "session.sync"],
        )
        # Deliberately omit the cached epoch: this endpoint authenticates the
        # credential first, then returns the server's current authorization.
        headers = self._headers(device_id=device_id, secret=secret)
        headers.pop("X-DataSteward-Capability-Epoch")
        initial = self.client.get("/v1/device/self", headers=headers)

        changed = self.pairing_store.update_device_capabilities(
            device_id,
            expected_capability_epoch=1,
            granted_capabilities=["session.sync"],
        )
        refreshed = self.client.get("/v1/device/self", headers=headers)

        self.assertTrue(changed.changed)
        self.assertEqual(200, initial.status_code, initial.text)
        self.assertEqual(200, refreshed.status_code, refreshed.text)
        self.assertEqual(
            {
                "protocol_version": "pairing_auth/1",
                "hub_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
                "device_id": device_id,
                "status": "ACTIVE",
                "capability_epoch": 2,
                "granted_capabilities": ["session.sync"],
                "display_name": "Test device",
                "platform": "test",
            },
            refreshed.json(),
        )

    def test_device_self_hides_lifecycle_until_secret_is_verified(self) -> None:
        headers = self._headers()
        headers.pop("X-DataSteward-Capability-Epoch")
        self.pairing_store.revoke_device_credential(
            self.device_id,
            expected_capability_epoch=1,
        )
        wrong_secret, _ = _secret(11)
        wrong_headers = self._headers(secret=wrong_secret)
        wrong_headers.pop("X-DataSteward-Capability-Epoch")

        revoked = self.client.get("/v1/device/self", headers=headers)
        hidden = self.client.get("/v1/device/self", headers=wrong_headers)

        self.assertEqual(
            (401, "auth_revoked"),
            (revoked.status_code, revoked.json()["error_code"]),
        )
        self.assertEqual(
            (401, "auth_invalid"),
            (hidden.status_code, hidden.json()["error_code"]),
        )

    def test_valid_device_can_create_append_and_replay(self) -> None:
        conversation_id = self._create_conversation()
        appended = self.client.post(
            f"/v1/conversations/{conversation_id}/messages",
            headers=self._headers(),
            json={
                "client_message_id": "auth-message-1",
                "actor_device_id": self.device_id,
                "role": "user",
                "content": "contract message",
            },
        )
        replay = self.client.get(
            f"/v1/conversations/{conversation_id}/events",
            headers=self._headers(),
        )

        self.assertEqual(201, appended.status_code, appended.text)
        self.assertEqual(200, replay.status_code, replay.text)
        self.assertEqual(
            [1],
            [item["conversation_seq"] for item in replay.json()["events"]],
        )

    def test_file_query_requires_grant_and_appends_one_idempotent_receipt(self) -> None:
        demo_root = Path(self._temporary_directory.name) / "pc-demo"
        demo_root.mkdir()
        (demo_root / "one.png").write_bytes(b"one")
        (demo_root / "training-note.txt").write_text("fixture", encoding="utf-8")
        self.file_scope.authorize(str(demo_root))

        denied_conversation = self._create_conversation("file-denied")
        denied = self.client.post(
            f"/v1/conversations/{denied_conversation}/messages",
            headers=self._headers(),
            json={
                "client_message_id": "file-query-denied",
                "actor_device_id": self.device_id,
                "role": "user",
                "content": "看下电脑授权目录有几个图片文件",
            },
        )
        self.assertEqual((403, "capability_denied"), (
            denied.status_code,
            denied.json()["error_code"],
        ))

        file_device, file_secret = self._activate_device(
            attempt_id="01ARZ3NDEKTSV4RRFFQ69G5FB2",
            secret_byte=12,
            capabilities=["files.read", "session.sync"],
        )
        headers = self._headers(device_id=file_device, secret=file_secret)
        conversation_id = "auth-conversation-file-query"
        created = self.client.post(
            "/v1/conversations",
            headers=headers,
            json={"title": "File query", "conversation_id": conversation_id},
        )
        self.assertEqual(201, created.status_code, created.text)
        payload = {
            "client_message_id": "file-query-count-1",
            "actor_device_id": file_device,
            "role": "user",
            "content": "看下电脑授权目录有几个图片文件",
        }
        first = self.client.post(
            f"/v1/conversations/{conversation_id}/messages",
            headers=headers,
            json=payload,
        )
        duplicate = self.client.post(
            f"/v1/conversations/{conversation_id}/messages",
            headers=headers,
            json=payload,
        )
        replay = self.client.get(
            f"/v1/conversations/{conversation_id}/events",
            headers=headers,
        )

        self.assertEqual(201, first.status_code, first.text)
        self.assertEqual(200, duplicate.status_code, duplicate.text)
        events = replay.json()["events"]
        self.assertEqual([1, 2], [item["conversation_seq"] for item in events])
        self.assertEqual("user", events[0]["payload"]["role"])
        self.assertEqual("assistant", events[1]["payload"]["role"])
        receipt = events[1]["payload"]["content"]
        self.assertIn("共 1 个图片文件", receipt)
        self.assertIn("查询校验信息已保留在本地", receipt)
        self.assertNotIn("result_sha256=", receipt)
        self.assertNotIn("root=", receipt)
        self.assertNotIn(str(demo_root), receipt)

    def test_archive_suggestion_requires_files_read_and_syncs_one_receipt(self) -> None:
        demo_root = Path(self._temporary_directory.name) / "archive-demo"
        demo_root.mkdir()
        (demo_root / "one.png").write_bytes(b"one")
        (demo_root / "plan.pdf").write_bytes(b"two")
        self.file_scope.authorize(str(demo_root))

        denied_conversation = self._create_conversation("archive-denied")
        denied = self.client.post(
            f"/v1/conversations/{denied_conversation}/messages",
            headers=self._headers(),
            json={
                "client_message_id": "archive-denied-1",
                "actor_device_id": self.device_id,
                "role": "user",
                "content": "智能整理电脑授权目录",
            },
        )
        self.assertEqual((403, "capability_denied"), (
            denied.status_code,
            denied.json()["error_code"],
        ))

        file_device, file_secret = self._activate_device(
            attempt_id="01ARZ3NDEKTSV4RRFFQ69G5FB5",
            secret_byte=15,
            capabilities=["files.read", "session.sync"],
        )
        headers = self._headers(device_id=file_device, secret=file_secret)
        planner = _PlannerFixture()
        self.app.state.read_only_intent_planner = planner
        conversation_id = "auth-conversation-archive"
        created = self.client.post(
            "/v1/conversations",
            headers=headers,
            json={"title": "Archive", "conversation_id": conversation_id},
        )
        self.assertEqual(201, created.status_code, created.text)
        payload = {
            "client_message_id": "archive-suggest-1",
            "actor_device_id": file_device,
            "role": "user",
            "content": "智能整理电脑授权目录",
        }
        first = self.client.post(
            f"/v1/conversations/{conversation_id}/messages",
            headers=headers,
            json=payload,
        )
        duplicate = self.client.post(
            f"/v1/conversations/{conversation_id}/messages",
            headers=headers,
            json=payload,
        )
        replay = self.client.get(
            f"/v1/conversations/{conversation_id}/events",
            headers=headers,
        )
        self.assertEqual(201, first.status_code, first.text)
        self.assertEqual(200, duplicate.status_code, duplicate.text)
        self.assertEqual(0, planner.calls)
        events = replay.json()["events"]
        self.assertEqual([1, 2], [item["conversation_seq"] for item in events])
        receipt = events[1]["payload"]["content"]
        self.assertIn("智能归档建议", receipt)
        self.assertIn("图片 1", receipt)
        self.assertIn("文档 1", receipt)
        self.assertIn("未移动、重命名、修改或删除任何文件", receipt)
        self.assertNotIn("one.png", receipt)
        self.assertNotIn(str(demo_root), receipt)
        connection = sqlite3.connect(self.database_path)
        stored_source = connection.execute(
            "SELECT source_message_ref FROM archive_suggestion"
        ).fetchone()[0]
        connection.close()
        self.assertRegex(stored_source, r"^msg-[0-9a-f]{64}$")
        self.assertNotEqual("archive-suggest-1", stored_source)

    def test_valid_agent_plan_drives_existing_executor_and_visible_receipt(self) -> None:
        demo_root = Path(self._temporary_directory.name) / "agent-demo"
        demo_root.mkdir()
        (demo_root / "one.png").write_bytes(b"one")
        self.file_scope.authorize(str(demo_root))
        planner = _PlannerFixture()
        self.app.state.read_only_intent_planner = planner
        file_device, file_secret = self._activate_device(
            attempt_id="01ARZ3NDEKTSV4RRFFQ69G5FB3",
            secret_byte=13,
            capabilities=["files.read", "session.sync"],
        )
        headers = self._headers(device_id=file_device, secret=file_secret)
        conversation_id = "auth-conversation-agent-plan"
        created = self.client.post(
            "/v1/conversations",
            headers=headers,
            json={"title": "Agent plan", "conversation_id": conversation_id},
        )
        self.assertEqual(201, created.status_code, created.text)

        appended = self.client.post(
            f"/v1/conversations/{conversation_id}/messages",
            headers=headers,
            json={
                "client_message_id": "agent-plan-1",
                "actor_device_id": file_device,
                "role": "user",
                "content": "请替我盘点授权区里的照片资产",
            },
        )
        self.assertEqual(201, appended.status_code, appended.text)
        deadline = time.monotonic() + 2
        events = []
        while time.monotonic() < deadline:
            events = self.client.get(
                f"/v1/conversations/{conversation_id}/events", headers=headers
            ).json()["events"]
            if len(events) >= 2:
                break
            time.sleep(0.01)
        self.assertEqual(1, planner.calls)
        self.assertEqual([1, 2], [item["conversation_seq"] for item in events])
        receipt = events[1]["payload"]["content"]
        self.assertIn("我已理解你的目标", receipt)
        self.assertIn("共 1 个图片文件", receipt)
        self.assertNotIn("planner=", receipt)
        self.assertNotIn("result_sha256=", receipt)
        self.assertNotIn("root=", receipt)
        self.assertNotIn(str(demo_root), receipt)

    def test_known_query_bypasses_failing_planner_and_uses_host_executor(self) -> None:
        demo_root = Path(self._temporary_directory.name) / "fallback-demo"
        demo_root.mkdir()
        (demo_root / "one.png").write_bytes(b"one")
        self.file_scope.authorize(str(demo_root))
        planner = _PlannerFixture(fail=True)
        self.app.state.read_only_intent_planner = planner
        file_device, file_secret = self._activate_device(
            attempt_id="01ARZ3NDEKTSV4RRFFQ69G5FB4",
            secret_byte=14,
            capabilities=["files.read", "session.sync"],
        )
        headers = self._headers(device_id=file_device, secret=file_secret)
        conversation_id = "auth-conversation-agent-fallback"
        self.client.post(
            "/v1/conversations",
            headers=headers,
            json={"title": "Fallback", "conversation_id": conversation_id},
        )

        appended = self.client.post(
            f"/v1/conversations/{conversation_id}/messages",
            headers=headers,
            json={
                "client_message_id": "agent-fallback-1",
                "actor_device_id": file_device,
                "role": "user",
                "content": "看下电脑授权目录有几个图片文件",
            },
        )
        self.assertEqual(201, appended.status_code, appended.text)
        deadline = time.monotonic() + 2
        events = []
        while time.monotonic() < deadline:
            events = self.client.get(
                f"/v1/conversations/{conversation_id}/events", headers=headers
            ).json()["events"]
            if len(events) >= 2:
                break
            time.sleep(0.01)
        self.assertEqual(0, planner.calls)
        receipt = events[1]["payload"]["content"]
        self.assertIn("共 1 个图片文件", receipt)
        self.assertNotIn("planner=hermes", receipt)

    def test_unauthorized_known_query_does_not_call_planner(self) -> None:
        planner = _PlannerFixture()
        self.app.state.read_only_intent_planner = planner
        conversation_id = self._create_conversation("agent-denied")
        denied = self.client.post(
            f"/v1/conversations/{conversation_id}/messages",
            headers=self._headers(),
            json={
                "client_message_id": "agent-denied-1",
                "actor_device_id": self.device_id,
                "role": "user",
                "content": "看下电脑授权目录有几个图片文件",
            },
        )
        self.assertEqual((403, "capability_denied"), (
            denied.status_code,
            denied.json()["error_code"],
        ))
        self.assertEqual(0, planner.calls)

    def test_missing_and_malformed_authorization_fail_closed(self) -> None:
        missing = self._headers()
        missing.pop("Authorization")
        malformed = self._headers()
        malformed["Authorization"] = f"bearer {self.secret}"

        for headers in (missing, malformed):
            with self.subTest(headers=headers):
                response = self.client.post(
                    "/v1/conversations",
                    headers=headers,
                    json={"title": "Denied"},
                )
                self.assertEqual(401, response.status_code)
                self.assertEqual("auth_invalid", response.json()["error_code"])

    def test_duplicate_authentication_headers_fail_closed(self) -> None:
        cases = (
            (
                "Authorization",
                f"Bearer {self.secret}",
                401,
                "auth_invalid",
            ),
            (
                "X-DataSteward-Protocol",
                "pairing_auth/1",
                400,
                "protocol_version_rejected",
            ),
            (
                "X-DataSteward-Device-Id",
                self.device_id,
                401,
                "auth_invalid",
            ),
            (
                "X-DataSteward-Capability-Epoch",
                "1",
                401,
                "auth_invalid",
            ),
        )
        for name, value, status, code in cases:
            with self.subTest(name=name):
                headers = list(self._headers().items())
                headers.append((name, value))
                response = self.client.post(
                    "/v1/conversations",
                    headers=headers,
                    json={"title": "Denied"},
                )
                self.assertEqual(status, response.status_code)
                self.assertEqual(code, response.json()["error_code"])

    def test_protocol_device_and_epoch_headers_are_strict(self) -> None:
        cases = (
            (
                "X-DataSteward-Protocol",
                "pairing_auth/2",
                400,
                "protocol_version_rejected",
            ),
            ("X-DataSteward-Device-Id", "not-a-device", 401, "auth_invalid"),
            ("X-DataSteward-Capability-Epoch", "01", 401, "auth_invalid"),
            ("X-DataSteward-Capability-Epoch", "+1", 401, "auth_invalid"),
            ("X-DataSteward-Capability-Epoch", str(1 << 63), 401, "auth_invalid"),
        )
        for header, value, status, code in cases:
            with self.subTest(header=header, value=value):
                headers = self._headers()
                headers[header] = value
                response = self.client.post(
                    "/v1/conversations",
                    headers=headers,
                    json={"title": "Denied"},
                )
                self.assertEqual(status, response.status_code)
                self.assertEqual(code, response.json()["error_code"])

    def test_unknown_device_and_wrong_secret_share_auth_invalid(self) -> None:
        wrong_secret, _ = _secret(8)
        cases = (
            self._headers(secret=wrong_secret),
            self._headers(device_id="01ARZ3NDEKTSV4RRFFQ69G5FAX"),
        )
        for headers in cases:
            response = self.client.post(
                "/v1/conversations",
                headers=headers,
                json={"title": "Denied"},
            )
            self.assertEqual(401, response.status_code)
            self.assertEqual("auth_invalid", response.json()["error_code"])

    def test_pending_and_expired_are_indistinguishable_from_invalid(self) -> None:
        pending_device, pending_secret = self._pending_device(secret_byte=10)
        pending = self.client.post(
            "/v1/conversations",
            headers=self._headers(
                device_id=pending_device,
                secret=pending_secret,
                epoch="1",
            ),
            json={"title": "Pending"},
        )
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute(
                "UPDATE device_credential SET status = 'EXPIRED' WHERE device_id = ?",
                (pending_device,),
            )
            connection.commit()
        finally:
            connection.close()
        expired = self.client.post(
            "/v1/conversations",
            headers=self._headers(
                device_id=pending_device,
                secret=pending_secret,
                epoch="1",
            ),
            json={"title": "Expired"},
        )

        for response in (pending, expired):
            self.assertEqual(401, response.status_code)
            self.assertEqual("auth_invalid", response.json()["error_code"])

    def test_revoked_stale_epoch_and_missing_capability_are_classified(self) -> None:
        denied_device, denied_secret = self._activate_device(
            attempt_id="01ARZ3NDEKTSV4RRFFQ69G5FAY",
            secret_byte=9,
            capabilities=["fs.read"],
        )
        denied = self.client.post(
            "/v1/conversations",
            headers=self._headers(device_id=denied_device, secret=denied_secret),
            json={"title": "Denied"},
        )
        stale = self.client.post(
            "/v1/conversations",
            headers=self._headers(epoch="2"),
            json={"title": "Stale"},
        )
        self.pairing_store.revoke_device_credential(
            self.device_id,
            expected_capability_epoch=1,
        )
        wrong_secret, _ = _secret(11)
        revoked_with_wrong_secret = self.client.post(
            "/v1/conversations",
            headers=self._headers(secret=wrong_secret),
            json={"title": "Revoked oracle"},
        )
        revoked = self.client.post(
            "/v1/conversations",
            headers=self._headers(),
            json={"title": "Revoked"},
        )

        self.assertEqual(
            (403, "capability_denied"),
            (denied.status_code, denied.json()["error_code"]),
        )
        self.assertEqual(
            (409, "capability_epoch_stale"),
            (stale.status_code, stale.json()["error_code"]),
        )
        self.assertEqual(
            (401, "auth_revoked"),
            (revoked.status_code, revoked.json()["error_code"]),
        )
        self.assertEqual(
            (401, "auth_invalid"),
            (
                revoked_with_wrong_secret.status_code,
                revoked_with_wrong_secret.json()["error_code"],
            ),
        )

    def test_actor_device_id_mismatch_writes_nothing(self) -> None:
        conversation_id = self._create_conversation("actor")
        response = self.client.post(
            f"/v1/conversations/{conversation_id}/messages",
            headers=self._headers(),
            json={
                "client_message_id": "actor-mismatch",
                "actor_device_id": "01ARZ3NDEKTSV4RRFFQ69G5FAX",
                "role": "user",
                "content": "must not persist",
            },
        )
        replay = self.client.get(
            f"/v1/conversations/{conversation_id}/events",
            headers=self._headers(),
        )

        self.assertEqual(400, response.status_code)
        self.assertEqual("policy_violation", response.json()["error_code"])
        self.assertEqual([], replay.json()["events"])

    def test_authenticated_device_cannot_forge_privileged_message_roles(self) -> None:
        conversation_id = self._create_conversation("roles")
        for role in ("assistant", "system", "tool"):
            with self.subTest(role=role):
                response = self.client.post(
                    f"/v1/conversations/{conversation_id}/messages",
                    headers=self._headers(),
                    json={
                        "client_message_id": f"forged-{role}",
                        "actor_device_id": self.device_id,
                        "role": role,
                        "content": "must not persist",
                    },
                )
                self.assertEqual(400, response.status_code)
                self.assertEqual(
                    "policy_violation",
                    response.json()["error_code"],
                )
        replay = self.client.get(
            f"/v1/conversations/{conversation_id}/events",
            headers=self._headers(),
        )
        self.assertEqual([], replay.json()["events"])

    def test_health_and_pairing_routes_are_not_bearer_gated(self) -> None:
        health = self.client.get("/health")
        pairing = self.client.get(
            "/v1/pairing/sessions/01ARZ3NDEKTSV4RRFFQ69G5FAZ/status",
            params={"pairing_attempt_id": "01ARZ3NDEKTSV4RRFFQ69G5FB0"},
            headers={"X-DataSteward-Protocol": "pairing_auth/1"},
        )

        self.assertEqual(200, health.status_code)
        self.assertEqual(401, pairing.status_code)
        self.assertEqual("claim_missing", pairing.json()["error_code"])

    def test_unknown_conversation_namespace_route_is_still_gated(self) -> None:
        unauthenticated = self.client.get("/v1/conversations/future-route")
        authenticated = self.client.get(
            "/v1/conversations/future-route",
            headers=self._headers(),
        )

        self.assertEqual(400, unauthenticated.status_code)
        self.assertEqual(
            "protocol_version_rejected",
            unauthenticated.json()["error_code"],
        )
        self.assertEqual(404, authenticated.status_code)

    def test_websocket_requires_first_frame_auth_before_ready(self) -> None:
        conversation_id = self._create_conversation("ws")
        with self.client.websocket_connect(
            f"/v1/conversations/{conversation_id}/events/ws?after_seq=0"
        ) as websocket:
            websocket.send_json(
                {
                    "kind": "auth",
                    "protocol_version": "pairing_auth/1",
                    "device_id": self.device_id,
                    "capability_epoch": 1,
                    "credential": self.secret,
                }
            )
            self.assertEqual("auth_ok", websocket.receive_json()["kind"])
            self.assertEqual("ready", websocket.receive_json()["kind"])

    def test_closed_executor_returns_sanitized_auth_unavailable(self) -> None:
        executor = self.app.state.pairing_store_executor
        executor.shutdown(wait=True, cancel_queued=True)
        response = self.client.post(
            "/v1/conversations",
            headers=self._headers(),
            json={"title": "Unavailable"},
        )

        self.assertEqual(503, response.status_code)
        self.assertEqual(
            {"error_code": "auth_unavailable", "message_key": "auth.auth_unavailable"},
            response.json(),
        )

    def test_executor_and_store_failures_are_sanitized(self) -> None:
        class FailingExecutor:
            def __init__(self, failure: BaseException) -> None:
                self.failure = failure

            async def run(self, *_args: object, **_kwargs: object) -> object:
                raise self.failure

        original = self.app.state.pairing_store_executor
        failures: tuple[BaseException, ...] = (
            PairingStoreSaturatedError("private saturation detail"),
            TimeoutError("private timeout detail"),
            PairingPersistenceError("private database detail"),
        )
        try:
            for failure in failures:
                with self.subTest(failure=type(failure).__name__):
                    self.app.state.pairing_store_executor = FailingExecutor(failure)
                    response = self.client.post(
                        "/v1/conversations",
                        headers=self._headers(),
                        json={"title": "Unavailable"},
                    )
                    self.assertEqual(503, response.status_code)
                    self.assertEqual(
                        "auth_unavailable",
                        response.json()["error_code"],
                    )
                    self.assertNotIn(str(failure), response.text)
        finally:
            self.app.state.pairing_store_executor = original

    def test_error_responses_never_echo_auth_material_or_path(self) -> None:
        wrong_secret, _ = _secret(6)
        response = self.client.post(
            "/v1/conversations",
            headers=self._headers(secret=wrong_secret),
            json={"title": "Private title"},
        )
        for sensitive in (
            wrong_secret,
            self.device_id,
            str(self.database_path),
            "Private title",
            "Authorization",
        ):
            self.assertNotIn(sensitive, response.text)

    def test_auth_configuration_is_explicit_and_bounded(self) -> None:
        self.assertEqual(
            "session.sync",
            required_rest_capability("/v1/conversations"),
        )
        self.assertEqual(
            "session.sync",
            required_rest_capability("/v1/conversations/x/events"),
        )
        self.assertEqual(
            "session.sync",
            required_rest_capability("/v1/suggestions/observe"),
        )
        self.assertIsNone(required_rest_capability("/health"))
        for invalid in (None, "", "optional", True):
            with self.assertRaises(ValueError):
                validate_auth_mode(invalid)
        for invalid in (0, -1, float("inf"), float("nan"), True, 31):
            with self.assertRaises(ValueError):
                validate_device_auth_timeout_s(invalid)

    def test_authenticated_openapi_declares_security_and_capability(self) -> None:
        schema = self.client.get("/openapi.json").json()
        self.assertEqual(
            "bearer",
            schema["components"]["securitySchemes"]["DeviceBearer"]["scheme"],
        )
        operations = (
            schema["paths"]["/v1/conversations"]["post"],
            schema["paths"]["/v1/conversations/{conversation_id}/messages"]["post"],
            schema["paths"]["/v1/conversations/{conversation_id}/events"]["get"],
        )
        for operation in operations:
            self.assertEqual([{"DeviceBearer": []}], operation["security"])
            self.assertEqual(
                "session.sync",
                operation["x-datasteward-required-capability"],
            )
            header_names = {
                item["name"]
                for item in operation["parameters"]
                if item["in"] == "header"
            }
            self.assertEqual(
                {
                    "X-DataSteward-Protocol",
                    "X-DataSteward-Device-Id",
                    "X-DataSteward-Capability-Epoch",
                },
                header_names,
            )
            for status in ("401", "403", "503"):
                schema_ref = operation["responses"][status]["content"][
                    "application/json"
                ]["schema"]["$ref"]
                self.assertTrue(schema_ref.endswith("/PairingErrorBody"))
        create_operation = operations[0]
        create_400_refs = {
            item["$ref"].rsplit("/", 1)[-1]
            for item in create_operation["responses"]["400"]["content"][
                "application/json"
            ]["schema"]["anyOf"]
        }
        replay_409_refs = {
            item["$ref"].rsplit("/", 1)[-1]
            for item in operations[2]["responses"]["409"]["content"][
                "application/json"
            ]["schema"]["anyOf"]
        }
        self.assertEqual(
            {"ErrorResponse", "PairingErrorBody"},
            create_400_refs,
        )
        self.assertEqual(
            {"CursorAheadErrorResponse", "PairingErrorBody"},
            replay_409_refs,
        )
        self_operation = schema["paths"]["/v1/device/self"]["get"]
        self.assertEqual([{"DeviceBearer": []}], self_operation["security"])
        self.assertNotIn(
            "x-datasteward-required-capability",
            self_operation,
        )
        self.assertEqual(
            {"X-DataSteward-Protocol", "X-DataSteward-Device-Id"},
            {
                item["name"]
                for item in self_operation["parameters"]
                if item["in"] == "header"
            },
        )

    def test_required_mode_rejects_missing_pairing_store(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = EventStore(Path(directory) / "missing-pairing.sqlite3")
            try:
                with self.assertRaisesRegex(ValueError, "requires pairing_store"):
                    create_app(
                        event_store=store,
                        business_auth_mode=AUTH_MODE_REQUIRED,
                    )
            finally:
                store.close()


class DeviceAuthExecutorOwnershipTest(unittest.TestCase):
    def test_injected_executor_can_be_constructed_for_auth(self) -> None:
        executor = PairingStoreExecutor(max_workers=1, max_queued=1)
        try:
            self.assertFalse(executor.is_shutdown)
        finally:
            executor.shutdown(wait=True, cancel_queued=True)
        self.assertTrue(executor.is_shutdown)


if __name__ == "__main__":
    unittest.main()
