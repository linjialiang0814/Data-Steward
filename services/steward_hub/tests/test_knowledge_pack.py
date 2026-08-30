from __future__ import annotations

import unittest

from steward_hub.catalog_models import CatalogAssetView
from steward_hub.content_understanding import StudyPack
from steward_hub.knowledge_pack import (
    KnowledgeContextBuilder,
    KnowledgePackError,
    render_knowledge_markdown,
)

SNAPSHOT = "a" * 64
STUDY_PROJECTION = "b" * 64


def asset(asset_id: str, platform: str, name: str) -> CatalogAssetView:
    return CatalogAssetView(
        asset_id=asset_id,
        device_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
        catalog_root_id="c" * 64 if platform == "android" else "pc-aabbccddeeff",
        platform=platform,
        source_display_name="手机资料" if platform == "android" else "课程资料",
        locator_token="d" * 64,
        display_name=name,
        extension="md" if platform == "windows" else "png",
        mime_family="text" if platform == "windows" else "image",
        size_bytes=10,
        modified_at_ms=1_785_805_200_000,
        observed_at="2026-08-05T00:00:00.000Z",
        revision="e" * 64,
        content_eligible=True,
        catalog_seq=1,
        deleted_at=None,
    )


class FakeCatalog:
    def __init__(self, assets: tuple[CatalogAssetView, ...]) -> None:
        self.assets = assets

    def current_view(self):
        return (), self.assets, SNAPSHOT


class FakeContent:
    def __init__(self, pack: StudyPack | None) -> None:
        self.pack = pack

    def latest_study_pack(self) -> StudyPack | None:
        return self.pack


def study_pack(citations: tuple[str, ...]) -> StudyPack:
    return StudyPack(
        snapshot_sha256=SNAPSHOT,
        title="今日资料 `要点`",
        summary="结合电脑课件与手机课堂图片复习。",
        topics=("limits", "continuity"),
        review_points=("核对 [课堂] 笔记", "完成作业"),
        cited_asset_ids=citations,
        source="hermes",
        projection_sha256=STUDY_PROJECTION,
        created_at="2026-08-05T10:00:00.000Z",
    )


class KnowledgePackTest(unittest.TestCase):
    def test_builds_cross_device_pack_and_redacts_internal_ids(self) -> None:
        values = (
            asset("1" * 64, "windows", "高等数学-课件.md"),
            asset("2" * 64, "android", "课堂照片.png"),
        )
        builder = KnowledgeContextBuilder(
            catalog=FakeCatalog(values),  # type: ignore[arg-type]
            content=FakeContent(study_pack(("1" * 64, "2" * 64))),  # type: ignore[arg-type]
        )

        pack = builder.build("learning")
        public = pack.wire()

        self.assertTrue(pack.cross_device)
        self.assertEqual(["windows", "android"], [x.platform for x in pack.citations])
        self.assertNotIn("asset_id", str(public))
        self.assertNotIn("device_id", str(public))
        self.assertNotIn("catalog_root_id", str(public))
        self.assertRegex(pack.pack_id, r"^kp-[0-9a-f]{16}$")

    def test_markdown_is_deterministic_and_escapes_control_syntax(self) -> None:
        values = (asset("1" * 64, "windows", "[作业]*最终*.md"),)
        builder = KnowledgeContextBuilder(
            catalog=FakeCatalog(values),  # type: ignore[arg-type]
            content=FakeContent(study_pack(("1" * 64,))),  # type: ignore[arg-type]
        )
        pack = builder.build("general")

        first = render_knowledge_markdown(pack)
        second = render_knowledge_markdown(pack)

        self.assertEqual(first, second)
        text = first.decode("utf-8")
        self.assertIn(r"\[作业\]\*最终\*.md", text)
        self.assertIn("[S1] Windows", text)
        self.assertNotIn("content://", text)

    def test_adds_transparent_metadata_citation_for_missing_device(self) -> None:
        values = (
            asset("1" * 64, "windows", "高等数学-课件.md"),
            asset("2" * 64, "android", "课堂照片.png"),
        )
        builder = KnowledgeContextBuilder(
            catalog=FakeCatalog(values),  # type: ignore[arg-type]
            content=FakeContent(study_pack(("1" * 64,))),  # type: ignore[arg-type]
        )

        pack = builder.build("learning")

        self.assertTrue(pack.cross_device)
        self.assertEqual(
            [("windows", "content_projection"), ("android", "catalog_metadata")],
            [(item.platform, item.basis) for item in pack.citations],
        )
        self.assertIn("目录元数据", render_knowledge_markdown(pack).decode("utf-8"))

    def test_missing_or_stale_citation_fails_closed(self) -> None:
        builder = KnowledgeContextBuilder(
            catalog=FakeCatalog(()),  # type: ignore[arg-type]
            content=FakeContent(study_pack(("1" * 64,))),  # type: ignore[arg-type]
        )
        with self.assertRaisesRegex(KnowledgePackError, "knowledge_pack_citation_invalid"):
            builder.build("learning")

    def test_unknown_kind_and_missing_pack_are_rejected(self) -> None:
        builder = KnowledgeContextBuilder(
            catalog=FakeCatalog(()),  # type: ignore[arg-type]
            content=FakeContent(None),  # type: ignore[arg-type]
        )
        with self.assertRaisesRegex(KnowledgePackError, "knowledge_pack_kind_invalid"):
            builder.build("custom")
        with self.assertRaisesRegex(KnowledgePackError, "knowledge_pack_unavailable"):
            builder.build("meeting")


if __name__ == "__main__":
    unittest.main()
