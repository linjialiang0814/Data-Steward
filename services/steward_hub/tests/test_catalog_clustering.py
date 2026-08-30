from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import UTC, datetime

from steward_hub.catalog_clustering import build_today_materials
from steward_hub.catalog_models import CatalogAssetView, CatalogRootView


NOW_MS = int(datetime(2026, 8, 4, 8, 0, tzinfo=UTC).timestamp() * 1000)


def _root(platform: str) -> CatalogRootView:
    return CatalogRootView(
        device_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
        catalog_root_id=("a" if platform == "android" else "b") * 64,
        platform=platform,
        provider="fixture",
        display_name="手机资料" if platform == "android" else "电脑资料",
        catalog_seq=1,
        snapshot_sha256="c" * 64,
        item_count=1,
        skipped_count=0,
        last_synced_at="2026-08-04T08:00:00+00:00",
    )


def _asset(
    suffix: str,
    name: str,
    platform: str,
    minute: int,
    family: str = "document",
) -> CatalogAssetView:
    at = NOW_MS + minute * 60_000
    return CatalogAssetView(
        asset_id=(suffix * 64)[:64],
        device_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
        catalog_root_id=("a" if platform == "android" else "b") * 64,
        platform=platform,
        source_display_name="手机资料" if platform == "android" else "电脑资料",
        locator_token=(suffix[::-1] * 64)[:64],
        display_name=name,
        extension=name.rsplit(".", 1)[-1].lower(),
        mime_family=family,
        size_bytes=10,
        modified_at_ms=at,
        observed_at=datetime.fromtimestamp(at / 1000, tz=UTC).isoformat(),
        revision="d" * 64,
        content_eligible=True,
        catalog_seq=1,
        deleted_at=None,
    )


class CatalogClusteringTest(unittest.TestCase):
    def _build(self, assets: list[CatalogAssetView]):
        return build_today_materials(
            roots=[_root("android"), _root("windows")],
            assets=assets,
            source_projection_sha256="e" * 64,
            now_ms=NOW_MS,
        )

    def test_chinese_and_english_course_names_cluster_across_devices(self) -> None:
        result = self._build(
            [
                _asset("1", "高等数学课堂笔记.md", "android", 0, "text"),
                _asset("2", "calculus-lecture-slides.pdf", "windows", 25),
            ]
        )
        self.assertEqual(1, result.cluster_count)
        self.assertEqual("高等数学资料", result.clusters[0].title)
        self.assertEqual(("android", "windows"), result.clusters[0].source_platforms)
        self.assertEqual(0, result.unassigned_count)

    def test_input_order_does_not_change_projection_or_cluster_id(self) -> None:
        assets = [
            _asset("1", "meeting-notes.md", "android", 0, "text"),
            _asset("2", "meeting-slides.pdf", "windows", 20),
            _asset("3", "unrelated.zip", "windows", 360, "archive"),
        ]
        first = self._build(assets)
        second = self._build(list(reversed(assets)))
        self.assertEqual(first, second)
        self.assertEqual(first.projection_sha256, second.projection_sha256)

    def test_low_confidence_asset_is_not_forced_into_cluster(self) -> None:
        result = self._build([_asset("1", "receipt-9284.pdf", "android", 0)])
        self.assertEqual(0, result.cluster_count)
        self.assertEqual(1, result.unassigned_count)

    def test_same_name_on_two_devices_has_distinct_assets_and_one_cluster(self) -> None:
        result = self._build(
            [
                _asset("1", "project-plan-final.docx", "android", 0),
                _asset("2", "project-plan-final.docx", "windows", 10),
            ]
        )
        self.assertEqual(1, result.cluster_count)
        self.assertEqual(2, len({item.asset_id for item in result.clusters[0].assets}))

    def test_explicitly_different_topics_do_not_merge_only_by_time(self) -> None:
        result = self._build(
            [
                _asset("1", "english-notes.md", "android", 0, "text"),
                _asset("2", "math-slides.pdf", "windows", 5),
            ]
        )
        self.assertEqual(0, result.cluster_count)
        self.assertEqual(2, result.unassigned_count)

    def test_implausible_device_time_falls_back_to_observed_time(self) -> None:
        item = _asset("1", "english-notes.md", "android", 0, "text")
        item = replace(item, modified_at_ms=NOW_MS + 90 * 24 * 60 * 60 * 1000)
        result = self._build([item])
        self.assertEqual("observed", result.unassigned[0].time_source)
        self.assertEqual(NOW_MS, result.unassigned[0].effective_at_ms)

    def test_deleted_or_added_asset_changes_projection_without_stale_members(self) -> None:
        first_assets = [
            _asset("1", "meeting-notes.md", "android", 0, "text"),
            _asset("2", "meeting-slides.pdf", "windows", 10),
        ]
        first = self._build(first_assets)
        second = self._build([first_assets[0]])
        third = self._build([*first_assets, _asset("3", "meeting-photo.jpg", "android", 20, "image")])
        self.assertNotEqual(first.projection_sha256, second.projection_sha256)
        self.assertNotEqual(first.projection_sha256, third.projection_sha256)
        self.assertEqual(1, second.unassigned_count)
        self.assertEqual(3, third.clusters[0].asset_count)


if __name__ == "__main__":
    unittest.main()
