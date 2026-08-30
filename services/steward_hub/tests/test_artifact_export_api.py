from __future__ import annotations

import base64
import hashlib
import unittest

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from steward_hub.artifact_export import (
    ArtifactExportPreview,
    ArtifactExportReceipt,
    ArtifactExportStatus,
)
from steward_hub.artifact_export_api import (
    create_artifact_device_router,
    create_artifact_operator_router,
)
from steward_hub.device_auth import AuthenticatedDevice, required_rest_capability
from steward_hub.knowledge_pack import KnowledgeCitation, KnowledgePack


def _pack() -> KnowledgePack:
    return KnowledgePack(
        pack_id="kp-1234567890abcdef",
        kind="learning",
        snapshot_sha256="a" * 64,
        source_projection_sha256="b" * 64,
        title="学习资料包｜高等数学",
        summary="结合电脑课件与手机课堂图片生成。",
        topics=("极限",),
        review_points=("复习定义",),
        citations=(
            KnowledgeCitation("S1", "windows", "课程资料", "课堂笔记.md", 1, "c" * 64),
            KnowledgeCitation("S2", "android", "手机资料", "课堂图片.png", 2, "d" * 64),
        ),
        source="hermes",
        cross_device=True,
        created_at="2026-08-05T10:00:00.000Z",
        projection_sha256="e" * 64,
    )


class _Coordinator:
    def __init__(self) -> None:
        self.prepare_calls = 0

    def prepare(self, *, kind: str, request: str) -> ArtifactExportPreview:
        self.prepare_calls += 1
        return ArtifactExportPreview(
            _pack(), "student-materials", "Data Steward 输出",
            "2026-08-05-learning.md", 512, "f" * 64, "1" * 64,
        )

    def execute(self, **_: object) -> ArtifactExportReceipt:
        return ArtifactExportReceipt(
            "artifact-1234567890abcdef", "kp-1234567890abcdef", "completed",
            "2026-08-05-learning.md", 512, "artifact-1234567890abcdef", False,
        )

    def status(self) -> ArtifactExportStatus:
        return ArtifactExportStatus("idle", None, None, None, 0, False, None)

    def undo(self, *, undo_token: str) -> ArtifactExportReceipt:
        return ArtifactExportReceipt(
            undo_token, "kp-1234567890abcdef", "undone",
            "2026-08-05-learning.md", 512, None, False,
        )


class ArtifactExportApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.secret = base64.urlsafe_b64encode(bytes([47]) * 32).decode().rstrip("=")
        digest = hashlib.sha256(bytes([47]) * 32).hexdigest()
        self.coordinator = _Coordinator()
        app = FastAPI()
        app.include_router(
            create_artifact_operator_router(
                coordinator=self.coordinator,
                operator_token_digest=digest,
            )
        )
        self.client = TestClient(app, raise_server_exceptions=False)

    def _headers(self) -> dict[str, str]:
        return {
            "authorization": f"DataSteward-Operator {self.secret}",
            "x-datasteward-protocol": "pairing_auth/1",
        }

    def test_operator_prepare_is_strict_and_redacted(self) -> None:
        response = self.client.post(
            "/v1/operator/artifacts/prepare",
            headers=self._headers(),
            json={"kind": "learning", "request": "生成学习资料包"},
        )
        self.assertEqual(200, response.status_code)
        body = response.json()
        self.assertTrue(body["requires_confirmation"])
        self.assertTrue(body["pack"]["cross_device"])
        self.assertEqual(
            ["content_projection", "content_projection"],
            [item["basis"] for item in body["pack"]["citations"]],
        )
        self.assertNotIn("asset_id", repr(body))
        self.assertNotIn("snapshot_sha256", repr(body))

        invalid = self.client.post(
            "/v1/operator/artifacts/prepare",
            headers=self._headers(),
            json={"kind": "learning", "request": "x", "extra": True},
        )
        self.assertEqual(400, invalid.status_code)
        self.assertEqual(1, self.coordinator.prepare_calls)

    def test_operator_auth_and_device_prepare_capability_fail_closed(self) -> None:
        denied = self.client.get("/v1/operator/artifacts/status")
        self.assertEqual(401, denied.status_code)

        coordinator = _Coordinator()
        app = FastAPI()

        @app.middleware("http")
        async def inject_auth(request: Request, call_next):
            request.state.authenticated_device = AuthenticatedDevice(
                device_id="01J00000000000000000000001",
                hub_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
                capability_epoch=1,
                granted_capabilities=("artifact.export",),
                display_name="fixture",
                platform="android",
            )
            return await call_next(request)

        app.include_router(create_artifact_device_router(coordinator=coordinator))
        device = TestClient(app, raise_server_exceptions=False)
        response = device.post(
            "/v1/artifacts/prepare",
            json={"kind": "learning", "request": "生成学习资料包"},
        )
        self.assertEqual(403, response.status_code)
        self.assertEqual("capability_denied", response.json()["error_code"])
        self.assertEqual(0, coordinator.prepare_calls)

    def test_capability_routing_requires_artifact_export(self) -> None:
        self.assertEqual(
            "artifact.export", required_rest_capability("/v1/artifacts/status")
        )


if __name__ == "__main__":
    unittest.main()
