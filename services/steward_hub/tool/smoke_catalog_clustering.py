"""Cross-restart deterministic Catalog clustering smoke."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from steward_hub.catalog_clustering import build_today_materials
from steward_hub.catalog_models import (
    CatalogItemInput,
    CatalogSnapshotBatch,
    catalog_snapshot_sha256,
)
from steward_hub.catalog_store import CatalogStore

NOW_MS = 1_785_801_600_000


def _batch(
    *,
    root_id: str,
    platform: str,
    name: str,
    item: CatalogItemInput,
    key: str,
) -> CatalogSnapshotBatch:
    return CatalogSnapshotBatch(
        idempotency_key=key,
        catalog_root_id=root_id,
        platform=platform,
        provider="fixture",
        display_name=name,
        base_seq=0,
        snapshot_sha256=catalog_snapshot_sha256(root_id, [item], 0),
        generated_at_ms=NOW_MS,
        item_count=1,
        skipped_count=0,
        complete_snapshot=True,
        items=(item,),
    )


def _projection(store: CatalogStore):
    roots, assets, source_hash = store.current_view()
    return build_today_materials(
        roots=roots,
        assets=assets,
        source_projection_sha256=source_hash,
        now_ms=NOW_MS,
    )


def main() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        database = Path(temporary) / "catalog.sqlite3"
        phone = CatalogItemInput(
            locator_token="a" * 64,
            display_name="高等数学课堂笔记.md",
            extension="md",
            mime_family="text",
            size_bytes=10,
            modified_at_ms=NOW_MS,
            revision="b" * 64,
            content_eligible=True,
        )
        pc = CatalogItemInput(
            locator_token="c" * 64,
            display_name="calculus-lecture-slides.pdf",
            extension="pdf",
            mime_family="document",
            size_bytes=20,
            modified_at_ms=NOW_MS + 20 * 60_000,
            revision="d" * 64,
            content_eligible=True,
        )
        store = CatalogStore(database)
        store.apply_snapshot(
            device_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
            batch=_batch(
                root_id="e" * 64,
                platform="android",
                name="手机资料",
                item=phone,
                key="smoke-phone-0001",
            ),
        )
        store.apply_snapshot(
            device_id="01ARZ3NDEKTSV4RRFFQ69G5FAW",
            batch=_batch(
                root_id="f" * 64,
                platform="windows",
                name="电脑资料",
                item=pc,
                key="smoke-pc-0000001",
            ),
        )
        before = _projection(store)
        store.close()
        reopened = CatalogStore(database)
        after = _projection(reopened)
        reopened.close()
        payload = {
            "asset_count": after.asset_count,
            "cluster_count": after.cluster_count,
            "cross_device": after.clusters[0].source_platforms
            == ("android", "windows"),
            "projection_sha256": after.projection_sha256,
            "reopened_equal": before == after,
            "status": "PASS" if before == after else "FAIL",
        }
        encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        print(encoded)
        if payload["status"] != "PASS" or not payload["cross_device"]:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
