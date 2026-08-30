from __future__ import annotations

import base64
import concurrent.futures
import hashlib
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from steward_hub.api import create_app
from steward_hub.autonomy_job import AutonomyJobStore
from steward_hub.catalog_store import CatalogStore
from steward_hub.content_api import ContentInsightCoordinator
from steward_hub.content_understanding import (
    ContentUnderstandingService,
    ContentUnderstandingStore,
    build_study_pack,
)
from steward_hub.device_auth import AUTH_MODE_REQUIRED, required_rest_capability
from steward_hub.device_connection_registry import DeviceConnectionRegistry
from steward_hub.pairing_store import PairingStore
from steward_hub.pc_file_scope import PcFileScopeService
from steward_hub.store import EventStore


class ContentOperatorApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        scope_root = root / "fixture"
        scope_root.mkdir()
        (scope_root / "课程复习.md").write_text(
            "今天复习极限和连续。", encoding="utf-8"
        )
        self.database = root / "hub.sqlite3"
        self.secret = base64.urlsafe_b64encode(bytes([33]) * 32).decode().rstrip("=")
        self.digest = hashlib.sha256(bytes([33]) * 32).hexdigest()
        self.pairing = PairingStore(self.database, auto_start_runtime=False)
        self.pairing.initialize_hub_identity(
            hub_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
            cert_fingerprint="a" * 64,
            tls_storage_kind="dpapi_encrypted_pkcs8",
            tls_key_ref_id="fixture",
        )
        self.events = EventStore(self.database)
        self.catalog = CatalogStore(self.database)
        self.scope = PcFileScopeService()
        self.scope.authorize(str(scope_root))
        batch = self.scope.catalog_snapshot(
            base_seq=0,
            idempotency_key="content-api-fixture-1",
            generated_at_ms=1_800_000_000_000,
        )
        self.catalog.apply_snapshot(
            device_id="01ARZ3NDEKTSV4RRFFQ69G5FAV", batch=batch
        )
        self.content_store = ContentUnderstandingStore(self.database)
        self.autonomy_store = AutonomyJobStore(self.database)
        content = ContentUnderstandingService(
            store=self.content_store,
            catalog=self.catalog,
            file_scope=self.scope,
            windows_device_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
        )
        self.content = content
        self.coordinator = ContentInsightCoordinator(
            content=content,
            planner=None,
            job_store=self.autonomy_store,
        )
        self.app = create_app(
            event_store=self.events,
            pairing_store=self.pairing,
            operator_token_digest=self.digest,
            pc_file_scope_service=self.scope,
            catalog_store=self.catalog,
            content_insight_coordinator=self.coordinator,
            device_connection_registry=DeviceConnectionRegistry(),
            pairing_routes_enabled=False,
        )
        self.client = TestClient(self.app, raise_server_exceptions=False)
        self.client.__enter__()

    def tearDown(self) -> None:
        self.client.__exit__(None, None, None)
        self.autonomy_store.close()
        self.content_store.close()
        self.catalog.close()
        self.events.close()
        self.pairing.close()
        self.temp.cleanup()

    def _headers(self) -> dict[str, str]:
        return {
            "authorization": f"DataSteward-Operator {self.secret}",
            "x-datasteward-protocol": "pairing_auth/1",
        }

    def _conversation(self, suffix: str) -> str:
        conversation_id = f"content-gateway-{suffix}"
        response = self.client.post(
            "/v1/conversations",
            json={"title": "Unified gateway", "conversation_id": conversation_id},
        )
        self.assertEqual(201, response.status_code, response.text)
        return conversation_id

    def _wait_for_events(
        self, conversation_id: str, expected: int, timeout_s: float = 3.0
    ) -> list[dict[str, object]]:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            response = self.client.get(
                f"/v1/conversations/{conversation_id}/events"
            )
            self.assertEqual(200, response.status_code, response.text)
            events = response.json()["events"]
            if len(events) >= expected:
                return events
            time.sleep(0.01)
        self.fail(f"timed out waiting for {expected} conversation events")

    def _activate_device(
        self, *, attempt_id: str, secret_byte: int, capabilities: list[str]
    ) -> tuple[str, str]:
        raw_secret = bytes([secret_byte]) * 32
        secret = base64.urlsafe_b64encode(raw_secret).decode("ascii").rstrip("=")
        session = self.pairing.create_pairing_session(
            pairing_token_digest=hashlib.sha256(attempt_id.encode()).hexdigest(),
            ttl_seconds=300,
        )
        hello = self.pairing.register_client_hello_digest(
            pairing_session_id=session.pairing_session_id,
            pairing_attempt_id=attempt_id,
            pairing_token_digest=hashlib.sha256(attempt_id.encode()).hexdigest(),
            claim_secret_digest=hashlib.sha256(("claim-" + attempt_id).encode()).hexdigest(),
            device_credential_digest=hashlib.sha256(raw_secret).hexdigest(),
            client_nonce="AAAAAAAAAAAAAAAAAAAAAA",
            requested_capabilities=capabilities,
            display_name="Content fixture",
            platform="android",
        )
        self.pairing.record_hub_confirmation(
            pairing_session_id=session.pairing_session_id,
            pairing_attempt_id=attempt_id,
            granted_capabilities=capabilities,
        )
        self.pairing.record_client_confirmation_digest(
            pairing_session_id=session.pairing_session_id,
            pairing_attempt_id=attempt_id,
            claim_secret_digest=hashlib.sha256(("claim-" + attempt_id).encode()).hexdigest(),
            short_verification_code=hello.short_verification_code,
        )
        return hello.device_id, secret

    @staticmethod
    def _device_headers(device_id: str, secret: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {secret}",
            "X-DataSteward-Protocol": "pairing_auth/1",
            "X-DataSteward-Device-Id": device_id,
            "X-DataSteward-Capability-Epoch": "1",
        }

    def test_opt_in_and_deterministic_study_pack(self) -> None:
        status = self.client.get(
            "/v1/operator/content/status", headers=self._headers()
        )
        self.assertEqual(200, status.status_code)
        self.assertFalse(status.json()["content_opt_in"])
        blocked = self.client.post(
            "/v1/operator/content/study-pack",
            headers=self._headers(),
            json={"request": "生成今天的复习要点"},
        )
        self.assertEqual(409, blocked.status_code)
        enabled = self.client.post(
            "/v1/operator/content/opt-in",
            headers=self._headers(),
            json={"enabled": True},
        )
        self.assertEqual(200, enabled.status_code)
        generated = self.client.post(
            "/v1/operator/content/study-pack",
            headers=self._headers(),
            json={"request": "生成今天的复习要点"},
        )
        self.assertEqual(200, generated.status_code)
        self.assertEqual("data-steward.study-pack/v1", generated.json()["schema_version"])
        self.assertEqual("deterministic_fallback", generated.json()["source"])
        self.assertNotIn(str(self.database.parent), generated.text)
        latest = self.client.get(
            "/v1/operator/content/study-pack", headers=self._headers()
        )
        self.assertEqual(generated.json(), latest.json())
        disabled = self.client.post(
            "/v1/operator/content/opt-in",
            headers=self._headers(),
            json={"enabled": False},
        )
        hidden = self.client.get(
            "/v1/operator/content/study-pack", headers=self._headers()
        )
        self.assertEqual(200, disabled.status_code)
        self.assertEqual(404, hidden.status_code)

    def test_conversation_gateway_generates_one_safe_material_brief(self) -> None:
        enabled = self.client.post(
            "/v1/operator/content/opt-in",
            headers=self._headers(),
            json={"enabled": True},
        )
        self.assertEqual(200, enabled.status_code)
        conversation_id = self._conversation("brief")
        body = {
            "client_message_id": "gateway-brief-1",
            "actor_device_id": "windows-ui",
            "role": "user",
            "content": "请综合今天的课程文档，提炼主要内容和下一步复习顺序。",
        }

        first = self.client.post(
            f"/v1/conversations/{conversation_id}/messages", json=body
        )
        events = self._wait_for_events(conversation_id, 2)
        repeated = self.client.post(
            f"/v1/conversations/{conversation_id}/messages", json=body
        )
        replay_after_repeat = self._wait_for_events(conversation_id, 2)

        self.assertEqual(201, first.status_code, first.text)
        self.assertEqual(200, repeated.status_code, repeated.text)
        self.assertEqual(2, len(events))
        self.assertEqual(events, replay_after_repeat)
        assistant = events[1]["payload"]["content"]
        self.assertIn("今日学习资料要点", assistant)
        self.assertIn("本机安全摘要", assistant)
        self.assertIn("未修改任何文件", assistant)
        self.assertNotIn(str(self.database.parent), assistant)
        self.assertNotIn("asset-", assistant)

    def test_conversation_gateway_returns_capability_guidance_for_unsupported(self) -> None:
        conversation_id = self._conversation("unsupported")
        response = self.client.post(
            f"/v1/conversations/{conversation_id}/messages",
            json={
                "client_message_id": "gateway-unsupported-1",
                "actor_device_id": "windows-ui",
                "role": "user",
                "content": "你好，你能做什么？",
            },
        )
        events = self._wait_for_events(conversation_id, 2)

        self.assertEqual(201, response.status_code, response.text)
        self.assertEqual(2, len(events))
        self.assertIn("汇总跨设备资料", events[1]["payload"]["content"])
        self.assertIn("等待你确认", events[1]["payload"]["content"])

    def test_concurrent_idempotent_gateway_request_generates_once(self) -> None:
        enabled = self.client.post(
            "/v1/operator/content/opt-in",
            headers=self._headers(),
            json={"enabled": True},
        )
        self.assertEqual(200, enabled.status_code)
        conversation_id = self._conversation("concurrent")
        body = {
            "client_message_id": "gateway-concurrent-1",
            "actor_device_id": "windows-ui",
            "role": "user",
            "content": "结合当前手机图片和电脑课件，为我设计三个复习检查问题，并说明依据的资料主题。",
        }
        original_generate = self.coordinator.generate
        calls = 0
        calls_lock = threading.Lock()
        start = threading.Barrier(2)

        def delayed_generate(value: str):
            nonlocal calls
            with calls_lock:
                calls += 1
            time.sleep(0.1)
            return original_generate(value)

        def submit():
            start.wait(timeout=2)
            return self.client.post(
                f"/v1/conversations/{conversation_id}/messages", json=body
            )

        self.coordinator.generate = delayed_generate  # type: ignore[method-assign]
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                responses = list(executor.map(lambda _: submit(), range(2)))
            events = self._wait_for_events(conversation_id, 2)
        finally:
            self.coordinator.generate = original_generate  # type: ignore[method-assign]

        self.assertEqual([200, 201], sorted(item.status_code for item in responses))
        self.assertEqual(1, calls)
        self.assertEqual(2, len(events))

    def test_user_message_is_acknowledged_before_agent_generation_finishes(self) -> None:
        enabled = self.client.post(
            "/v1/operator/content/opt-in",
            headers=self._headers(),
            json={"enabled": True},
        )
        self.assertEqual(200, enabled.status_code)
        conversation_id = self._conversation("early-ack")
        original_generate = self.coordinator.generate
        entered = threading.Event()
        release = threading.Event()

        class UnexpectedLegacyPlanner:
            calls = 0

            def plan(self, **_kwargs):
                self.calls += 1
                raise AssertionError("material request reached legacy planner")

        original_planner = self.app.state.read_only_intent_planner
        legacy_planner = UnexpectedLegacyPlanner()
        self.app.state.read_only_intent_planner = legacy_planner

        def blocked_generate(value: str):
            entered.set()
            release.wait(timeout=2)
            return original_generate(value)

        self.coordinator.generate = blocked_generate  # type: ignore[method-assign]
        try:
            started = time.monotonic()
            response = self.client.post(
                f"/v1/conversations/{conversation_id}/messages",
                json={
                    "client_message_id": "gateway-early-ack-1",
                    "actor_device_id": "windows-ui",
                    "role": "user",
                    "content": "分析今天的学习资料并给出复习计划。",
                },
            )
            elapsed = time.monotonic() - started
            self.assertEqual(201, response.status_code, response.text)
            self.assertLess(elapsed, 0.75)
            self.assertTrue(entered.wait(timeout=1))
            self.assertEqual(0, legacy_planner.calls)
        finally:
            release.set()
            self.coordinator.generate = original_generate  # type: ignore[method-assign]
            self.app.state.read_only_intent_planner = original_planner
        self.assertEqual(2, len(self._wait_for_events(conversation_id, 2)))

    def test_legacy_planner_runs_only_after_user_message_acknowledgement(self) -> None:
        conversation_id = self._conversation("planner-early-ack")
        entered = threading.Event()
        release = threading.Event()
        original_planner = self.app.state.read_only_intent_planner

        class BlockingPlanner:
            def plan(self, **_kwargs):
                entered.set()
                release.wait(timeout=2)
                return None

        self.app.state.read_only_intent_planner = BlockingPlanner()
        try:
            started = time.monotonic()
            response = self.client.post(
                f"/v1/conversations/{conversation_id}/messages",
                json={
                    "client_message_id": "gateway-planner-early-ack-1",
                    "actor_device_id": "windows-ui",
                    "role": "user",
                    "content": "你能帮我处理哪些事情？",
                },
            )
            elapsed = time.monotonic() - started
            self.assertEqual(201, response.status_code, response.text)
            self.assertLess(elapsed, 0.75)
            self.assertTrue(entered.wait(timeout=1))
        finally:
            release.set()
            self.app.state.read_only_intent_planner = original_planner
        events = self._wait_for_events(conversation_id, 2)
        self.assertIn("汇总跨设备资料", events[1]["payload"]["content"])

    def test_gateway_saturation_is_visible_and_never_auto_retries(self) -> None:
        enabled = self.client.post(
            "/v1/operator/content/opt-in",
            headers=self._headers(),
            json={"enabled": True},
        )
        self.assertEqual(200, enabled.status_code)
        first_conversation = self._conversation("saturation-first")
        second_conversation = self._conversation("saturation-second")
        original_generate = self.coordinator.generate
        entered = threading.Event()
        release = threading.Event()

        def blocked_generate(value: str):
            entered.set()
            release.wait(timeout=2)
            return original_generate(value)

        self.coordinator.generate = blocked_generate  # type: ignore[method-assign]
        try:
            first = self.client.post(
                f"/v1/conversations/{first_conversation}/messages",
                json={
                    "client_message_id": "gateway-saturation-1",
                    "actor_device_id": "windows-ui",
                    "role": "user",
                    "content": "分析今天的课程资料并给出复习顺序。",
                },
            )
            self.assertEqual(201, first.status_code, first.text)
            self.assertTrue(entered.wait(timeout=1))
            second = self.client.post(
                f"/v1/conversations/{second_conversation}/messages",
                json={
                    "client_message_id": "gateway-saturation-2",
                    "actor_device_id": "windows-ui",
                    "role": "user",
                    "content": "汇总今天的学习资料并说明重点。",
                },
            )
            self.assertEqual(201, second.status_code, second.text)
            events = self._wait_for_events(second_conversation, 2)
            self.assertIn("已有一项智能任务", events[1]["payload"]["content"])
            self.assertIn("不会自动重试", events[1]["payload"]["content"])
        finally:
            release.set()
            self.coordinator.generate = original_generate  # type: ignore[method-assign]
        self.assertEqual(2, len(self._wait_for_events(first_conversation, 2)))

    def test_auth_shape_and_capability_namespace(self) -> None:
        denied = self.client.get("/v1/operator/content/status")
        self.assertEqual(401, denied.status_code)
        malformed = self.client.post(
            "/v1/operator/content/opt-in",
            headers=self._headers(),
            json={"enabled": True, "extra": False},
        )
        self.assertEqual(400, malformed.status_code)
        self.assertEqual(
            "content.analyze", required_rest_capability("/v1/content/study-pack")
        )

    def test_file_scope_revoke_forgets_encrypted_content_projection_first(self) -> None:
        enabled = self.client.post(
            "/v1/operator/content/opt-in",
            headers=self._headers(),
            json={"enabled": True},
        )
        self.assertEqual(200, enabled.status_code)
        excerpts = self.content.extract_assets(
            snapshot_sha256=self.catalog.projection_sha256()
        )
        self.assertEqual(1, len(excerpts))
        connection = sqlite3.connect(self.database)
        try:
            before = connection.execute(
                "SELECT count(*) FROM content_projection_v2"
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual((1,), before)
        revoked = self.client.delete(
            "/v1/operator/file-scope", headers=self._headers()
        )
        self.assertEqual(200, revoked.status_code)
        self.assertFalse(revoked.json()["configured"])
        connection = sqlite3.connect(self.database)
        try:
            after = connection.execute(
                "SELECT count(*) FROM content_projection_v2"
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual((0,), after)

    def test_file_scope_reauthorization_forgets_previous_content_first(self) -> None:
        enabled = self.client.post(
            "/v1/operator/content/opt-in",
            headers=self._headers(),
            json={"enabled": True},
        )
        self.assertEqual(200, enabled.status_code)
        self.assertEqual(
            1,
            len(
                self.content.extract_assets(
                    snapshot_sha256=self.catalog.projection_sha256()
                )
            ),
        )
        replacement = Path(self.temp.name) / "replacement"
        replacement.mkdir()
        (replacement / "encrypted.pdf").write_bytes(b"fixture")

        authorized = self.client.put(
            "/v1/operator/file-scope",
            headers=self._headers(),
            json={"path": str(replacement), "remember": True},
        )

        self.assertEqual(200, authorized.status_code)
        self.assertTrue(authorized.json()["configured"])
        connection = sqlite3.connect(self.database)
        try:
            projections = connection.execute(
                "SELECT count(*) FROM content_projection_v2"
            ).fetchone()
            study_packs = connection.execute(
                "SELECT count(*) FROM content_study_pack"
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual((0,), projections)
        self.assertEqual((0,), study_packs)

    def test_device_route_requires_explicit_content_capability(self) -> None:
        allowed_id, allowed_secret = self._activate_device(
            attempt_id="01ARZ3NDEKTSV4RRFFQ69G5FAX",
            secret_byte=41,
            capabilities=["content.analyze"],
        )
        denied_id, denied_secret = self._activate_device(
            attempt_id="01ARZ3NDEKTSV4RRFFQ69G5FAY",
            secret_byte=42,
            capabilities=["session.sync"],
        )
        protected_app = create_app(
            event_store=self.events,
            pairing_store=self.pairing,
            business_auth_mode=AUTH_MODE_REQUIRED,
            pc_file_scope_service=self.scope,
            catalog_store=self.catalog,
            content_insight_coordinator=self.coordinator,
            operator_token_digest=self.digest,
            device_connection_registry=DeviceConnectionRegistry(),
            pairing_routes_enabled=False,
        )
        with TestClient(protected_app, raise_server_exceptions=False) as client:
            denied = client.get(
                "/v1/content/study-pack",
                headers=self._device_headers(denied_id, denied_secret),
            )
            opt_in_required = client.post(
                "/v1/content/study-pack",
                headers=self._device_headers(allowed_id, allowed_secret),
                json={"request": "Generate a study pack"},
            )
            self.content.set_opt_in(True)
            generated = client.post(
                "/v1/content/study-pack",
                headers=self._device_headers(allowed_id, allowed_secret),
                json={"request": "Generate a study pack"},
            )
        self.assertEqual(403, denied.status_code)
        self.assertEqual(409, opt_in_required.status_code)
        self.assertEqual(200, generated.status_code)
        self.assertEqual("data-steward.study-pack/v1", generated.json()["schema_version"])

    def test_identical_request_reuses_terminal_job_without_second_planner_call(self) -> None:
        class Planner:
            def __init__(self, content: ContentUnderstandingService) -> None:
                self.content = content
                self.calls = 0

            def analyze_study_pack(self, *, user_text: str, snapshot_sha256: str):
                self.calls += 1
                asset = self.content.list_safe_assets(
                    snapshot_sha256=snapshot_sha256
                )[0]
                return build_study_pack(
                    snapshot_sha256=snapshot_sha256,
                    title="复习路线",
                    summary="先核对课程主题，再完成练习。",
                    topics=["课程主题"],
                    review_points=["完成练习"],
                    cited_asset_ids=[asset.asset_id],
                    source="hermes",
                )

        self.content.set_opt_in(True)
        planner = Planner(self.content)
        coordinator = ContentInsightCoordinator(
            content=self.content,
            planner=planner,
            job_store=self.autonomy_store,
        )
        first = coordinator.generate("请生成我的复习路线")
        replay = coordinator.generate("  请生成我的复习路线\n")
        self.assertEqual(1, planner.calls)
        self.assertEqual(first.projection_sha256, replay.projection_sha256)


if __name__ == "__main__":
    unittest.main()
