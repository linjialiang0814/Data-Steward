"""Durable unified metadata Catalog with full-snapshot convergence."""

from __future__ import annotations

import re
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .catalog_models import (
    CatalogAssetView,
    CatalogRootView,
    CatalogSnapshotBatch,
    CatalogSyncResult,
    catalog_projection_sha256,
    stable_asset_id,
)
from .pairing_codec import require_ulid
from .pairing_errors import PairingValidationError

CATALOG_SCHEMA_VERSION = 1
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_ROOT_ID_RE = re.compile(r"^(?:[0-9a-f]{64}|pc-[0-9a-f]{12})$")

_VISIBLE_ROOTS_CTE = """
WITH ranked_catalog_roots AS (
    SELECT catalog_root.*,
           ROW_NUMBER() OVER (
               PARTITION BY platform, provider, catalog_root_id
               ORDER BY last_synced_at DESC, catalog_seq DESC, device_id DESC
           ) AS visibility_rank
    FROM catalog_root
),
visible_catalog_roots AS (
    SELECT * FROM ranked_catalog_roots WHERE visibility_rank = 1
)
"""


class CatalogStoreError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class CatalogCursorConflict(CatalogStoreError):
    def __init__(self, server_catalog_seq: int) -> None:
        self.server_catalog_seq = server_catalog_seq
        super().__init__("catalog_cursor_conflict")


class CatalogStore:
    def __init__(self, database_path: str | Path) -> None:
        self._lock = threading.RLock()
        self._closed = False
        self._connection: sqlite3.Connection | None = None
        try:
            self._connection = sqlite3.connect(
                str(database_path),
                isolation_level=None,
                check_same_thread=False,
                timeout=5.0,
            )
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA busy_timeout = 5000")
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._initialize_schema()
        except CatalogStoreError:
            if self._connection is not None:
                self._connection.close()
                self._connection = None
            raise
        except Exception as exc:  # noqa: BLE001
            if self._connection is not None:
                self._connection.close()
                self._connection = None
            raise CatalogStoreError("catalog_persistence_unavailable") from exc

    def _initialize_schema(self) -> None:
        with self._lock:
            assert self._connection is not None
            tables = {
                str(row[0])
                for row in self._connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'catalog_%'"
                )
            }
            if "catalog_schema_meta" in tables:
                rows = list(
                    self._connection.execute(
                        "SELECT component, schema_version FROM catalog_schema_meta"
                    )
                )
                if len(rows) != 1 or tuple(rows[0]) != (
                    "unified_catalog",
                    CATALOG_SCHEMA_VERSION,
                ):
                    raise CatalogStoreError("catalog_schema_unsupported")
            elif tables:
                raise CatalogStoreError("catalog_schema_unsupported")
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS catalog_schema_meta (
                    component TEXT PRIMARY KEY,
                    schema_version INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS catalog_root (
                    device_id TEXT NOT NULL,
                    catalog_root_id TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    catalog_seq INTEGER NOT NULL CHECK(catalog_seq >= 1),
                    snapshot_sha256 TEXT NOT NULL CHECK(length(snapshot_sha256) = 64),
                    generated_at_ms INTEGER NOT NULL CHECK(generated_at_ms >= 0),
                    item_count INTEGER NOT NULL CHECK(item_count >= 0),
                    skipped_count INTEGER NOT NULL CHECK(skipped_count >= 0),
                    last_synced_at TEXT NOT NULL,
                    PRIMARY KEY(device_id, catalog_root_id)
                );
                CREATE TABLE IF NOT EXISTS catalog_asset (
                    asset_id TEXT PRIMARY KEY CHECK(length(asset_id) = 64),
                    device_id TEXT NOT NULL,
                    catalog_root_id TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    source_display_name TEXT NOT NULL,
                    locator_token TEXT NOT NULL CHECK(length(locator_token) = 64),
                    display_name TEXT NOT NULL,
                    extension TEXT NOT NULL,
                    mime_family TEXT NOT NULL,
                    size_bytes INTEGER,
                    modified_at_ms INTEGER,
                    observed_at TEXT NOT NULL,
                    revision TEXT NOT NULL CHECK(length(revision) = 64),
                    content_eligible INTEGER NOT NULL CHECK(content_eligible IN (0, 1)),
                    catalog_seq INTEGER NOT NULL CHECK(catalog_seq >= 1),
                    deleted_at TEXT,
                    UNIQUE(device_id, catalog_root_id, locator_token),
                    FOREIGN KEY(device_id, catalog_root_id)
                        REFERENCES catalog_root(device_id, catalog_root_id)
                        ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS catalog_asset_active_order
                    ON catalog_asset(deleted_at, platform, display_name, asset_id);
                CREATE TABLE IF NOT EXISTS catalog_sync_request (
                    device_id TEXT NOT NULL,
                    catalog_root_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL CHECK(length(request_sha256) = 64),
                    accepted_seq INTEGER NOT NULL CHECK(accepted_seq >= 0),
                    snapshot_sha256 TEXT NOT NULL CHECK(length(snapshot_sha256) = 64),
                    item_count INTEGER NOT NULL CHECK(item_count >= 0),
                    tombstone_count INTEGER NOT NULL CHECK(tombstone_count >= 0),
                    changed INTEGER NOT NULL CHECK(changed IN (0, 1)),
                    projection_sha256 TEXT NOT NULL CHECK(length(projection_sha256) = 64),
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(device_id, catalog_root_id, idempotency_key)
                );
                """
            )
            self._connection.execute(
                "INSERT OR IGNORE INTO catalog_schema_meta(component, schema_version) VALUES(?, ?)",
                ("unified_catalog", CATALOG_SCHEMA_VERSION),
            )

    def current_seq(self, device_id: str, catalog_root_id: str) -> int:
        self._validate_device(device_id)
        with self._lock:
            self._ensure_open()
            assert self._connection is not None
            row = self._connection.execute(
                "SELECT catalog_seq FROM catalog_root WHERE device_id=? AND catalog_root_id=?",
                (device_id, catalog_root_id),
            ).fetchone()
            return 0 if row is None else int(row[0])

    def apply_snapshot(
        self,
        *,
        device_id: str,
        batch: CatalogSnapshotBatch,
        replace_other_roots: bool = False,
    ) -> CatalogSyncResult:
        self._validate_device(device_id)
        if not isinstance(replace_other_roots, bool):
            raise CatalogStoreError("catalog_replace_mode_invalid")
        request_hash = batch.request_sha256()
        with self._lock:
            self._ensure_open()
            assert self._connection is not None
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                existing_request = self._connection.execute(
                    """
                    SELECT * FROM catalog_sync_request
                    WHERE device_id=? AND catalog_root_id=? AND idempotency_key=?
                    """,
                    (device_id, batch.catalog_root_id, batch.idempotency_key),
                ).fetchone()
                if existing_request is not None:
                    if str(existing_request["request_sha256"]) != request_hash:
                        raise CatalogStoreError("catalog_idempotency_conflict")
                    if replace_other_roots:
                        retired = self._retire_other_roots_locked(
                            device_id,
                            batch.catalog_root_id,
                        )
                        if retired:
                            projection_hash = catalog_projection_sha256(
                                self._active_projection_locked()
                            )
                            self._connection.execute(
                                """
                                UPDATE catalog_sync_request SET projection_sha256=?
                                WHERE device_id=? AND catalog_root_id=? AND idempotency_key=?
                                """,
                                (
                                    projection_hash,
                                    device_id,
                                    batch.catalog_root_id,
                                    batch.idempotency_key,
                                ),
                            )
                            existing_request = self._connection.execute(
                                """
                                SELECT * FROM catalog_sync_request
                                WHERE device_id=? AND catalog_root_id=? AND idempotency_key=?
                                """,
                                (
                                    device_id,
                                    batch.catalog_root_id,
                                    batch.idempotency_key,
                                ),
                            ).fetchone()
                            assert existing_request is not None
                    result = _result_from_request(existing_request, deduplicated=True)
                    self._connection.execute("COMMIT")
                    return result

                root = self._connection.execute(
                    "SELECT * FROM catalog_root WHERE device_id=? AND catalog_root_id=?",
                    (device_id, batch.catalog_root_id),
                ).fetchone()
                current_seq = 0 if root is None else int(root["catalog_seq"])
                if batch.base_seq != current_seq:
                    raise CatalogCursorConflict(current_seq)
                if root is not None and (
                    str(root["platform"]) != batch.platform
                    or str(root["provider"]) != batch.provider
                ):
                    raise CatalogStoreError("catalog_root_binding_conflict")

                now = _utc_now()
                changed = root is None or str(root["snapshot_sha256"]) != batch.snapshot_sha256
                accepted_seq = current_seq + 1 if changed else current_seq
                tombstone_count = 0
                if changed:
                    self._connection.execute(
                        """
                        INSERT INTO catalog_root(
                            device_id, catalog_root_id, platform, provider, display_name,
                            catalog_seq, snapshot_sha256, generated_at_ms, item_count,
                            skipped_count, last_synced_at
                        ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                        ON CONFLICT(device_id, catalog_root_id) DO UPDATE SET
                            display_name=excluded.display_name,
                            catalog_seq=excluded.catalog_seq,
                            snapshot_sha256=excluded.snapshot_sha256,
                            generated_at_ms=excluded.generated_at_ms,
                            item_count=excluded.item_count,
                            skipped_count=excluded.skipped_count,
                            last_synced_at=excluded.last_synced_at
                        """,
                        (
                            device_id,
                            batch.catalog_root_id,
                            batch.platform,
                            batch.provider,
                            batch.display_name,
                            accepted_seq,
                            batch.snapshot_sha256,
                            batch.generated_at_ms,
                            batch.item_count,
                            batch.skipped_count,
                            now,
                        ),
                    )
                    previous_active_tokens = {
                        str(row[0])
                        for row in self._connection.execute(
                            """
                            SELECT locator_token FROM catalog_asset
                            WHERE device_id=? AND catalog_root_id=? AND deleted_at IS NULL
                            """,
                            (device_id, batch.catalog_root_id),
                        )
                    }
                    self._connection.execute(
                        """
                        UPDATE catalog_asset SET deleted_at=?, catalog_seq=?
                        WHERE device_id=? AND catalog_root_id=? AND deleted_at IS NULL
                        """,
                        (now, accepted_seq, device_id, batch.catalog_root_id),
                    )
                    for item in batch.items:
                        self._connection.execute(
                            """
                            INSERT INTO catalog_asset(
                                asset_id, device_id, catalog_root_id, platform,
                                source_display_name, locator_token, display_name,
                                extension, mime_family, size_bytes, modified_at_ms,
                                observed_at, revision, content_eligible, catalog_seq, deleted_at
                            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)
                            ON CONFLICT(device_id, catalog_root_id, locator_token) DO UPDATE SET
                                platform=excluded.platform,
                                source_display_name=excluded.source_display_name,
                                display_name=excluded.display_name,
                                extension=excluded.extension,
                                mime_family=excluded.mime_family,
                                size_bytes=excluded.size_bytes,
                                modified_at_ms=excluded.modified_at_ms,
                                observed_at=excluded.observed_at,
                                revision=excluded.revision,
                                content_eligible=excluded.content_eligible,
                                catalog_seq=excluded.catalog_seq,
                                deleted_at=NULL
                            """,
                            (
                                stable_asset_id(
                                    device_id,
                                    batch.catalog_root_id,
                                    item.locator_token,
                                ),
                                device_id,
                                batch.catalog_root_id,
                                batch.platform,
                                batch.display_name,
                                item.locator_token,
                                item.display_name,
                                item.extension,
                                item.mime_family,
                                item.size_bytes,
                                item.modified_at_ms,
                                now,
                                item.revision,
                                int(item.content_eligible),
                                accepted_seq,
                            ),
                        )
                    tombstone_count = len(
                        previous_active_tokens
                        - {item.locator_token for item in batch.items}
                    )
                else:
                    self._connection.execute(
                        """
                        UPDATE catalog_root SET display_name=?, generated_at_ms=?,
                            skipped_count=?, last_synced_at=?
                        WHERE device_id=? AND catalog_root_id=?
                        """,
                        (
                            batch.display_name,
                            batch.generated_at_ms,
                            batch.skipped_count,
                            now,
                            device_id,
                            batch.catalog_root_id,
                        ),
                    )
                    self._connection.execute(
                        """
                        UPDATE catalog_asset SET source_display_name=?
                        WHERE device_id=? AND catalog_root_id=? AND deleted_at IS NULL
                        """,
                        (batch.display_name, device_id, batch.catalog_root_id),
                    )

                if replace_other_roots:
                    self._retire_other_roots_locked(
                        device_id,
                        batch.catalog_root_id,
                    )
                projection = self._active_projection_locked()
                projection_hash = catalog_projection_sha256(projection)
                self._connection.execute(
                    """
                    INSERT INTO catalog_sync_request(
                        device_id, catalog_root_id, idempotency_key, request_sha256,
                        accepted_seq, snapshot_sha256, item_count, tombstone_count,
                        changed, projection_sha256, created_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        device_id,
                        batch.catalog_root_id,
                        batch.idempotency_key,
                        request_hash,
                        accepted_seq,
                        batch.snapshot_sha256,
                        batch.item_count,
                        tombstone_count,
                        int(changed),
                        projection_hash,
                        now,
                    ),
                )
                self._connection.execute("COMMIT")
                return CatalogSyncResult(
                    device_id=device_id,
                    catalog_root_id=batch.catalog_root_id,
                    accepted_seq=accepted_seq,
                    snapshot_sha256=batch.snapshot_sha256,
                    item_count=batch.item_count,
                    tombstone_count=tombstone_count,
                    changed=changed,
                    deduplicated=False,
                    projection_sha256=projection_hash,
                )
            except (CatalogCursorConflict, CatalogStoreError):
                self._connection.execute("ROLLBACK")
                raise
            except Exception as exc:  # noqa: BLE001
                self._connection.execute("ROLLBACK")
                raise CatalogStoreError("catalog_persistence_unavailable") from exc

    def _retire_other_roots_locked(
        self,
        device_id: str,
        keep_root_id: str,
    ) -> int:
        assert self._connection is not None
        rows = self._connection.execute(
            """
            SELECT catalog_root_id FROM catalog_root
            WHERE device_id=? AND catalog_root_id<>?
            """,
            (device_id, keep_root_id),
        ).fetchall()
        if not rows:
            return 0
        retired = tuple(str(row[0]) for row in rows)
        self._connection.executemany(
            "DELETE FROM catalog_sync_request WHERE device_id=? AND catalog_root_id=?",
            ((device_id, root_id) for root_id in retired),
        )
        self._connection.executemany(
            "DELETE FROM catalog_root WHERE device_id=? AND catalog_root_id=?",
            ((device_id, root_id) for root_id in retired),
        )
        return len(retired)

    def list_roots(self) -> tuple[CatalogRootView, ...]:
        with self._lock:
            self._ensure_open()
            assert self._connection is not None
            rows = self._connection.execute(
                _VISIBLE_ROOTS_CTE
                + """
                SELECT * FROM visible_catalog_roots
                ORDER BY platform, display_name, device_id, catalog_root_id
                """
            ).fetchall()
            for row in rows:
                self._validate_device(str(row["device_id"]))
                _validate_root_id(str(row["catalog_root_id"]))
                _validate_digest(str(row["snapshot_sha256"]))
            return tuple(
                CatalogRootView(
                    device_id=str(row["device_id"]),
                    catalog_root_id=str(row["catalog_root_id"]),
                    platform=str(row["platform"]),
                    provider=str(row["provider"]),
                    display_name=str(row["display_name"]),
                    catalog_seq=int(row["catalog_seq"]),
                    snapshot_sha256=str(row["snapshot_sha256"]),
                    item_count=int(row["item_count"]),
                    skipped_count=int(row["skipped_count"]),
                    last_synced_at=str(row["last_synced_at"]),
                )
                for row in rows
            )

    def list_assets(self, *, include_deleted: bool = False) -> tuple[CatalogAssetView, ...]:
        with self._lock:
            self._ensure_open()
            assert self._connection is not None
            deleted_filter = "" if include_deleted else "AND asset.deleted_at IS NULL"
            rows = self._connection.execute(
                _VISIBLE_ROOTS_CTE
                + f"""
                SELECT asset.* FROM catalog_asset AS asset
                JOIN visible_catalog_roots AS root
                  ON root.device_id = asset.device_id
                 AND root.catalog_root_id = asset.catalog_root_id
                WHERE 1 = 1 {deleted_filter}
                ORDER BY asset.platform, asset.source_display_name,
                         asset.display_name, asset.asset_id
                LIMIT 512
                """
            ).fetchall()
            return tuple(_asset_from_row(row) for row in rows)

    def projection_sha256(self) -> str:
        with self._lock:
            self._ensure_open()
            assert self._connection is not None
            return catalog_projection_sha256(self._active_projection_locked())

    def current_view(
        self,
    ) -> tuple[
        tuple[CatalogRootView, ...],
        tuple[CatalogAssetView, ...],
        str,
    ]:
        """Return one lock-consistent roots/assets/projection snapshot."""
        with self._lock:
            self._ensure_open()
            roots = self.list_roots()
            assets = self.list_assets()
            projection = self.projection_sha256()
            return roots, assets, projection

    def _active_projection_locked(self) -> list[dict[str, Any]]:
        rows = self._connection.execute(
            _VISIBLE_ROOTS_CTE
            + """
            SELECT asset.asset_id, asset.device_id, asset.catalog_root_id,
                   asset.platform, asset.source_display_name,
                   asset.locator_token, asset.display_name, asset.extension,
                   asset.mime_family, asset.size_bytes, asset.modified_at_ms,
                   asset.revision, asset.content_eligible, asset.catalog_seq
            FROM catalog_asset AS asset
            JOIN visible_catalog_roots AS root
              ON root.device_id = asset.device_id
             AND root.catalog_root_id = asset.catalog_root_id
            WHERE asset.deleted_at IS NULL
            ORDER BY asset.platform, asset.source_display_name,
                     asset.display_name, asset.asset_id
            """
        ).fetchall()
        for row in rows:
            self._validate_device(str(row["device_id"]))
            _validate_root_id(str(row["catalog_root_id"]))
            for name in ("asset_id", "locator_token", "revision"):
                _validate_digest(str(row[name]))
        return [dict(row) for row in rows]

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            if self._connection is not None:
                self._connection.close()
                self._connection = None

    def _ensure_open(self) -> None:
        if self._closed or self._connection is None:
            raise CatalogStoreError("catalog_store_closed")

    @staticmethod
    def _validate_device(device_id: str) -> None:
        try:
            require_ulid("device_id", device_id)
        except PairingValidationError:
            raise CatalogStoreError("catalog_device_invalid") from None


def _result_from_request(row: sqlite3.Row, *, deduplicated: bool) -> CatalogSyncResult:
    return CatalogSyncResult(
        device_id=str(row["device_id"]),
        catalog_root_id=str(row["catalog_root_id"]),
        accepted_seq=int(row["accepted_seq"]),
        snapshot_sha256=str(row["snapshot_sha256"]),
        item_count=int(row["item_count"]),
        tombstone_count=int(row["tombstone_count"]),
        changed=bool(row["changed"]),
        deduplicated=deduplicated,
        projection_sha256=str(row["projection_sha256"]),
    )


def _asset_from_row(row: sqlite3.Row) -> CatalogAssetView:
    CatalogStore._validate_device(str(row["device_id"]))
    _validate_root_id(str(row["catalog_root_id"]))
    for name in ("asset_id", "locator_token", "revision"):
        _validate_digest(str(row[name]))
    return CatalogAssetView(
        asset_id=str(row["asset_id"]),
        device_id=str(row["device_id"]),
        catalog_root_id=str(row["catalog_root_id"]),
        platform=str(row["platform"]),
        source_display_name=str(row["source_display_name"]),
        locator_token=str(row["locator_token"]),
        display_name=str(row["display_name"]),
        extension=str(row["extension"]),
        mime_family=str(row["mime_family"]),
        size_bytes=None if row["size_bytes"] is None else int(row["size_bytes"]),
        modified_at_ms=(
            None if row["modified_at_ms"] is None else int(row["modified_at_ms"])
        ),
        observed_at=str(row["observed_at"]),
        revision=str(row["revision"]),
        content_eligible=bool(row["content_eligible"]),
        catalog_seq=int(row["catalog_seq"]),
        deleted_at=None if row["deleted_at"] is None else str(row["deleted_at"]),
    )


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _validate_digest(value: str) -> None:
    if _DIGEST_RE.fullmatch(value) is None:
        raise CatalogStoreError("catalog_integrity_error")


def _validate_root_id(value: str) -> None:
    if _ROOT_ID_RE.fullmatch(value) is None:
        raise CatalogStoreError("catalog_integrity_error")
