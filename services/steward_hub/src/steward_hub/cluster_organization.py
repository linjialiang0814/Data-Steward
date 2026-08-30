"""Bound a Today-materials cluster to reversible PC file organization."""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import asdict, dataclass
from typing import Callable

from .catalog_clustering import TodayClusterView, build_today_materials
from .catalog_models import CatalogAssetView
from .catalog_store import CatalogStore, CatalogStoreError
from .pc_file_scope import PcFileScopeError, PcFileScopeService


class ClusterOrganizationError(RuntimeError):
    """Stable, path-free error code."""


@dataclass(frozen=True, slots=True)
class ClusterOrganizationPreview:
    schema_version: str
    cluster_id: str
    cluster_title: str
    projection_sha256: str
    preview_sha256: str
    pc_file_count: int
    virtual_file_count: int
    category_counts: dict[str, int]
    can_execute: bool

    def wire(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ClusterOrganizationReceipt:
    schema_version: str
    operation: str
    cluster_id: str
    moved_count: int
    category_counts: dict[str, int]
    undo_token: str
    catalog_refresh_pending: bool

    def wire(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ClusterOrganizationStatus:
    schema_version: str
    state: str
    moved_count: int
    category_counts: dict[str, int]
    undo_token: str | None
    can_undo: bool

    def wire(self) -> dict[str, object]:
        return asdict(self)


class ClusterOrganizationService:
    """Revalidates a cluster before allowing a selected PC-file move."""

    SCHEMA = "data-steward.cluster-organization/v1"

    def __init__(
        self,
        *,
        catalog: CatalogStore,
        file_scope: PcFileScopeService,
        windows_device_id: str,
        now_ms: Callable[[], int] | None = None,
    ) -> None:
        self._catalog = catalog
        self._file_scope = file_scope
        self._windows_device_id = windows_device_id
        self._now_ms = now_ms or (lambda: int(time.time() * 1000))

    def preview(
        self, *, cluster_id: str, projection_sha256: str
    ) -> ClusterOrganizationPreview:
        cluster, assets = self._current_cluster(cluster_id, projection_sha256)
        root = self._file_scope.status()
        if not root.configured or root.root_id is None:
            raise ClusterOrganizationError("file_scope_unconfigured")
        cluster_asset_ids = {item.asset_id for item in cluster.assets}
        selected = tuple(
            sorted(
                item.locator_token
                for item in assets
                if item.asset_id in cluster_asset_ids
                and item.platform == "windows"
                and item.device_id == self._windows_device_id
                and item.catalog_root_id == root.root_id
            )
        )
        if not selected:
            raise ClusterOrganizationError("cluster_has_no_pc_files")
        try:
            file_preview = self._file_scope.organization_preview(
                locator_tokens=selected
            )
        except PcFileScopeError as exc:
            raise ClusterOrganizationError(exc.code) from None
        virtual_count = cluster.asset_count - len(selected)
        canonical = json.dumps(
            {
                "cluster_id": cluster.cluster_id,
                "file_evidence_sha256": file_preview.evidence_sha256,
                "projection_sha256": projection_sha256,
                "selected_locators": selected,
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return ClusterOrganizationPreview(
            schema_version=self.SCHEMA,
            cluster_id=cluster.cluster_id,
            cluster_title=cluster.title,
            projection_sha256=projection_sha256,
            preview_sha256=hashlib.sha256(canonical).hexdigest(),
            pc_file_count=len(selected),
            virtual_file_count=virtual_count,
            category_counts=file_preview.category_counts,
            can_execute=True,
        )

    def execute(
        self,
        *,
        cluster_id: str,
        projection_sha256: str,
        preview_sha256: str,
    ) -> ClusterOrganizationReceipt:
        preview = self.preview(
            cluster_id=cluster_id,
            projection_sha256=projection_sha256,
        )
        if preview.preview_sha256 != preview_sha256:
            raise ClusterOrganizationError("organization_preview_stale")
        cluster, assets = self._current_cluster(cluster_id, projection_sha256)
        root = self._file_scope.status()
        assert root.root_id is not None
        cluster_asset_ids = {item.asset_id for item in cluster.assets}
        selected = tuple(
            sorted(
                item.locator_token
                for item in assets
                if item.asset_id in cluster_asset_ids
                and item.platform == "windows"
                and item.device_id == self._windows_device_id
                and item.catalog_root_id == root.root_id
            )
        )
        try:
            file_preview = self._file_scope.organization_preview(
                locator_tokens=selected
            )
            receipt = self._file_scope.organize_selected(
                expected_root_id=root.root_id,
                expected_evidence_sha256=file_preview.evidence_sha256,
                locator_tokens=selected,
            )
        except PcFileScopeError as exc:
            raise ClusterOrganizationError(exc.code) from None
        return ClusterOrganizationReceipt(
            schema_version=self.SCHEMA,
            operation="organize",
            cluster_id=cluster_id,
            moved_count=receipt.moved_count,
            category_counts=receipt.category_counts,
            undo_token=receipt.journal_id,
            catalog_refresh_pending=not self._refresh_pc_catalog(),
        )

    def undo(self, *, undo_token: str) -> ClusterOrganizationReceipt:
        try:
            receipt = self._file_scope.undo_organization(undo_token)
        except PcFileScopeError as exc:
            raise ClusterOrganizationError(exc.code) from None
        return ClusterOrganizationReceipt(
            schema_version=self.SCHEMA,
            operation="undo",
            cluster_id="",
            moved_count=receipt.moved_count,
            category_counts=receipt.category_counts,
            undo_token=receipt.journal_id,
            catalog_refresh_pending=not self._refresh_pc_catalog(),
        )

    def status(self) -> ClusterOrganizationStatus:
        try:
            value = self._file_scope.organization_status()
        except PcFileScopeError as exc:
            raise ClusterOrganizationError(exc.code) from None
        return ClusterOrganizationStatus(
            schema_version=self.SCHEMA,
            state=value.state,
            moved_count=value.moved_count,
            category_counts=value.category_counts,
            undo_token=value.journal_id,
            can_undo=value.can_undo,
        )

    def _current_cluster(
        self, cluster_id: str, projection_sha256: str
    ) -> tuple[TodayClusterView, tuple[CatalogAssetView, ...]]:
        if not cluster_id or len(cluster_id) > 128:
            raise ClusterOrganizationError("cluster_request_invalid")
        if len(projection_sha256) != 64 or any(
            char not in "0123456789abcdef" for char in projection_sha256
        ):
            raise ClusterOrganizationError("cluster_request_invalid")
        try:
            roots, assets, source_projection = self._catalog.current_view()
            current = build_today_materials(
                roots=roots,
                assets=assets,
                source_projection_sha256=source_projection,
                now_ms=self._now_ms(),
            )
        except (CatalogStoreError, ValueError):
            raise ClusterOrganizationError("catalog_persistence_unavailable") from None
        if current.projection_sha256 != projection_sha256:
            raise ClusterOrganizationError("catalog_projection_stale")
        cluster = next(
            (item for item in current.clusters if item.cluster_id == cluster_id),
            None,
        )
        if cluster is None:
            raise ClusterOrganizationError("cluster_not_found")
        return cluster, assets

    def _refresh_pc_catalog(self) -> bool:
        root = self._file_scope.status()
        if not root.configured or root.root_id is None:
            return False
        try:
            base_seq = self._catalog.current_seq(
                self._windows_device_id,
                root.root_id,
            )
            batch = self._file_scope.catalog_snapshot(
                base_seq=base_seq,
                idempotency_key="cluster-organize-" + secrets.token_hex(12),
                generated_at_ms=self._now_ms(),
            )
            self._catalog.apply_snapshot(
                device_id=self._windows_device_id,
                batch=batch,
                replace_other_roots=True,
            )
            return True
        except (CatalogStoreError, PcFileScopeError):
            return False
