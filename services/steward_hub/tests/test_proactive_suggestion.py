from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from steward_hub.agent_planning import TypedActionProposal
from steward_hub.autonomy_job import AutonomyJobStore
from steward_hub.catalog_models import (
    CatalogItemInput,
    CatalogSnapshotBatch,
    catalog_snapshot_sha256,
)
from steward_hub.catalog_store import CatalogStore
from steward_hub.cluster_organization import ClusterOrganizationService
from steward_hub.device_auth import AuthenticatedDevice
from steward_hub.pc_file_organizer_journal import OrganizerJournalStore
from steward_hub.pc_file_scope import PcFileScopeService
from steward_hub.proactive_suggestion import (
    ProactiveSuggestionService,
    ProactiveSuggestionStore,
)
from steward_hub.proactive_suggestion_api import create_suggestion_device_router

WINDOWS_DEVICE = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
ANDROID_DEVICE = "01ARZ3NDEKTSV4RRFFQ69G5FAW"


class _Planner:
    def __init__(self) -> None:
        self.calls = 0

    def propose_typed_action(self, *, snapshot_sha256, candidates):
        self.calls += 1
        selected = candidates[0]
        return TypedActionProposal(
            action_type=str(selected["action_type"]),
            category=str(selected["category"]),
            target_ref=str(selected["target_ref"]),
            title="整理今日高等数学资料",
            reason="这些资料在相近时间出现，并包含相同课程关键词。",
            request=str(selected["request"]),
            cited_asset_ids=tuple(selected["cited_asset_ids"]),
        )


class _Knowledge:
    def __init__(self, catalog: CatalogStore) -> None:
        self.catalog = catalog

    def build(self, kind: str):
        _, assets, _ = self.catalog.current_view()
        return SimpleNamespace(
            citations=tuple(SimpleNamespace(asset_id=item.asset_id) for item in assets[:2])
        )


def _journal(path: Path) -> OrganizerJournalStore:
    return OrganizerJournalStore(
        path,
        protect=lambda value: b"sealed:" + value,
        unprotect=lambda value: bytearray(value.removeprefix(b"sealed:")),
        apply_root_security=lambda _path: None,
        verify_root_security=lambda _path: None,
        verify_file_security=lambda _path: None,
    )


class ProactiveSuggestionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.database = base / "hub.sqlite3"
        self.root = base / "Authorized"
        self.root.mkdir()
        (self.root / "高等数学-课件.txt").write_text("fixture", encoding="utf-8")
        self.scope = PcFileScopeService(
            organizer_journal=_journal(base / "journal" / "journal.dpapi")
        )
        self.scope.authorize(str(self.root))
        self.catalog = CatalogStore(self.database)
        self.now_ms = 1_786_000_000_000
        batch = self.scope.catalog_snapshot(
            base_seq=0,
            idempotency_key="suggestion-pc-0001",
            generated_at_ms=self.now_ms,
        )
        self.catalog.apply_snapshot(
            device_id=WINDOWS_DEVICE,
            batch=batch,
            replace_other_roots=True,
        )
        item = CatalogItemInput(
            locator_token="a" * 64,
            display_name="高等数学-课堂笔记.png",
            extension="png",
            mime_family="image",
            size_bytes=10,
            modified_at_ms=self.now_ms,
            revision="b" * 64,
            content_eligible=True,
        )
        root_id = "c" * 64
        mobile = CatalogSnapshotBatch(
            idempotency_key="suggestion-android-0001",
            catalog_root_id=root_id,
            platform="android",
            provider="android.saf",
            display_name="手机课堂资料",
            base_seq=0,
            snapshot_sha256=catalog_snapshot_sha256(root_id, (item,), 0),
            generated_at_ms=self.now_ms,
            item_count=1,
            skipped_count=0,
            complete_snapshot=True,
            items=(item,),
        )
        self.catalog.apply_snapshot(device_id=ANDROID_DEVICE, batch=mobile)
        self.organizer = ClusterOrganizationService(
            catalog=self.catalog,
            file_scope=self.scope,
            windows_device_id=WINDOWS_DEVICE,
            now_ms=lambda: self.now_ms,
        )
        self.store = ProactiveSuggestionStore(self.database)
        self.autonomy = AutonomyJobStore(self.database)
        self.planner = _Planner()
        self.service = ProactiveSuggestionService(
            store=self.store,
            autonomy=self.autonomy,
            catalog=self.catalog,
            organization=self.organizer,
            knowledge=_Knowledge(self.catalog),
            planner=self.planner,
            now_ms=lambda: self.now_ms,
        )

    def tearDown(self) -> None:
        self.autonomy.close()
        self.store.close()
        self.catalog.close()
        self.temp.cleanup()

    def _device_api(self, capabilities: tuple[str, ...]) -> FastAPI:
        app = FastAPI()

        @app.middleware("http")
        async def inject_device(request: Request, call_next):
            request.state.authenticated_device = AuthenticatedDevice(
                device_id=ANDROID_DEVICE,
                hub_id="01ARZ3NDEKTSV4RRFFQ69G5FAX",
                capability_epoch=1,
                granted_capabilities=capabilities,
                display_name="Test phone",
                platform="android",
            )
            return await call_next(request)

        app.include_router(create_suggestion_device_router(service=self.service))
        return app

    def _create_organization_card(self):
        return self.store.create(
            snapshot_sha256="d" * 64,
            candidate_digest="e" * 64,
            proposal=TypedActionProposal(
                action_type="organize_selected",
                category="organization",
                target_ref="cl-" + "1" * 16,
                title="Organize today's course files",
                reason="Related files are ready for a reviewable preview.",
                request="Preview organization for 2 PC files",
                cited_asset_ids=("a" * 64,),
            ),
            now_ms=self.now_ms,
        )

    def test_opt_in_stability_gate_and_exactly_one_hermes_card(self) -> None:
        disabled = self.service.observe()
        self.assertEqual("disabled", disabled.state)
        self.assertEqual(0, self.planner.calls)
        self.store.update_settings(enabled=True, disabled_categories=())

        first = self.service.observe()
        self.assertEqual("stabilizing", first.state)
        self.assertEqual(0, self.planner.calls)
        self.now_ms += 9_999
        self.assertEqual("stabilizing", self.service.observe().state)
        self.now_ms += 1
        ready = self.service.observe()
        self.assertEqual("ready", ready.state)
        self.assertEqual(1, self.planner.calls)
        self.assertEqual(1, len(ready.suggestions))
        card = ready.suggestions[0]
        self.assertEqual("hermes", card.source)
        self.assertNotIn("action_target", card.wire())
        self.assertFalse((self.root / "Data Steward 归档").exists())

        replay = self.service.observe()
        self.assertEqual("ready", replay.state)
        self.assertEqual(1, self.planner.calls)
        self.assertEqual(card.suggestion_id, replay.suggestions[0].suggestion_id)

        accepted = self.service.accept(card.suggestion_id)
        self.assertEqual("accepted", accepted.status)
        self.assertEqual(card.target_ref, accepted.accepted_wire()["action_target"])
        self.assertEqual((), self.store.inbox())
        self.assertFalse((self.root / "Data Steward 归档").exists())

    def test_two_dismissals_pause_category_for_the_day(self) -> None:
        self.store.update_settings(enabled=True, disabled_categories=())
        proposal = TypedActionProposal(
            action_type="organize_selected",
            category="organization",
            target_ref="cl-" + "1" * 16,
            title="整理课程资料",
            reason="资料集中出现，建议先查看整理预览。",
            request="预览整理 2 个电脑文件",
            cited_asset_ids=("a" * 64,),
        )
        for index in range(2):
            now = self.now_ms + index * 31 * 60 * 1000
            digest = f"{index + 1:064x}"
            snapshot = f"{index + 10:064x}"
            self.assertEqual(
                "stabilizing",
                self.store.gate(
                    snapshot_sha256=snapshot,
                    candidate_digest=digest,
                    candidate_categories=("organization",),
                    now_ms=now,
                ),
            )
            self.assertEqual(
                "eligible",
                self.store.gate(
                    snapshot_sha256=snapshot,
                    candidate_digest=digest,
                    candidate_categories=("organization",),
                    now_ms=now + 10_000,
                ),
            )
            card = self.store.create(
                snapshot_sha256=snapshot,
                candidate_digest=digest,
                proposal=proposal,
                now_ms=now + 10_000,
            )
            self.store.transition(
                card.suggestion_id,
                target="dismissed",
                now_ms=now + 11_000,
            )
        later = self.now_ms + 2 * 31 * 60 * 1000
        self.assertEqual(
            "stabilizing",
            self.store.gate(
                snapshot_sha256="f" * 64,
                candidate_digest="e" * 64,
                candidate_categories=("organization",),
                now_ms=later,
            ),
        )
        self.assertEqual(
            "category_paused",
            self.store.gate(
                snapshot_sha256="f" * 64,
                candidate_digest="e" * 64,
                candidate_categories=("organization",),
                now_ms=later + 10_000,
            ),
        )

    def test_agent_unavailable_never_creates_fallback_card(self) -> None:
        self.service._planner = None
        self.store.update_settings(enabled=True, disabled_categories=())
        self.assertEqual("stabilizing", self.service.observe().state)
        self.now_ms += 10_000
        result = self.service.observe()
        self.assertEqual("unavailable", result.state)
        self.assertEqual("suggestion_agent_unavailable", result.message_key)
        self.assertEqual((), self.store.inbox())

    def test_device_api_hides_target_and_requires_action_capabilities(self) -> None:
        card = self._create_organization_card()
        with TestClient(
            self._device_api(("session.sync",)),
            raise_server_exceptions=False,
        ) as client:
            inbox = client.get("/v1/suggestions/inbox")
            denied = client.post(
                f"/v1/suggestions/{card.suggestion_id}/accept",
                json={},
            )
        self.assertEqual(200, inbox.status_code, inbox.text)
        self.assertNotIn("action_target", inbox.json()["suggestions"][0])
        self.assertEqual(
            (403, "capability_denied"),
            (denied.status_code, denied.json()["error_code"]),
        )
        self.assertEqual("available", self.store.inbox()[0].status)

        with TestClient(
            self._device_api(
                ("session.sync", "catalog.sync", "files.organize")
            ),
            raise_server_exceptions=False,
        ) as client:
            accepted = client.post(
                f"/v1/suggestions/{card.suggestion_id}/accept",
                json={},
            )
        self.assertEqual(200, accepted.status_code, accepted.text)
        self.assertEqual(card.target_ref, accepted.json()["action_target"])

    def test_device_observe_requires_content_permission(self) -> None:
        self.store.update_settings(enabled=True, disabled_categories=())
        with TestClient(
            self._device_api(("session.sync",)),
            raise_server_exceptions=False,
        ) as client:
            denied = client.post("/v1/suggestions/observe", json={})
        self.assertEqual(
            (403, "capability_denied"),
            (denied.status_code, denied.json()["error_code"]),
        )
        self.assertEqual(0, self.planner.calls)


if __name__ == "__main__":
    unittest.main()
