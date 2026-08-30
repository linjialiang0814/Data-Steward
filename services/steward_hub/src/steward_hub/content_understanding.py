"""Per-root content consent, bounded excerpts and validated study insights."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sqlite3
import threading
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterable

from .catalog_models import CatalogAssetView
from .android_ocr_store import AndroidOcrStore, AndroidOcrStoreError
from .catalog_store import CatalogStore
from .content_projection import (
    ContentProjection,
    ContentProjectionError,
    open_content_projection,
    seal_content_projection,
)
from .document_extraction import (
    DocumentExtractionError,
    DocumentExtractorSupervisor,
)
from .pairing_codec import require_ulid
from .pairing_errors import PairingValidationError
from .pc_file_scope import PcFileScopeError, PcFileScopeService
from .tls_identity.dpapi import (
    dpapi_protect_current_user,
    dpapi_unprotect_current_user,
)

CONTENT_SCHEMA_VERSION = 2
CONTENT_INSIGHT_SCHEMA = "data-steward.study-pack/v1"
MAX_ANALYSIS_FILES = 8
MAX_EXCERPT_CHARS = 4_000
MAX_TOTAL_EXCERPT_CHARS = 24_000
MAX_SUMMARY_CHARS = 600
MAX_TOPICS = 5
MAX_TOPIC_CHARS = 40
MAX_REVIEW_POINTS = 6
MAX_REVIEW_POINT_CHARS = 160
CONTENT_PROJECTION_RETENTION_DAYS = 7
SUPPORTED_CONTENT_EXTENSIONS = frozenset({"txt", "md", "docx", "pptx", "pdf"})
CONTENT_STUDY_PACK_SEALED_PREFIX = "sealed-v2:"
MAX_SEALED_STUDY_PACK_BYTES = 64 * 1024

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_ROOT_ID_RE = re.compile(r"^(?:[0-9a-f]{64}|pc-[0-9a-f]{12})$")
_PATH_RE = re.compile(r"(?i)(?:[a-z]:\\|\\\\|/users/|/home/)")


class ContentUnderstandingError(RuntimeError):
    """Stable, content-free failure code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ContentPolicyView:
    configured: bool
    catalog_root_id: str | None
    display_name: str | None
    content_opt_in: bool
    eligible_file_count: int
    supported_file_count: int
    supported_format_counts: dict[str, int]


@dataclass(frozen=True, slots=True)
class SafeAnalysisAsset:
    asset_id: str
    display_name: str
    mime_family: str
    modified_at_ms: int | None
    excerpt: str
    excerpt_sha256: str
    truncated: bool

    def tool_wire(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class StudyPack:
    snapshot_sha256: str
    title: str
    summary: str
    topics: tuple[str, ...]
    review_points: tuple[str, ...]
    cited_asset_ids: tuple[str, ...]
    source: str
    projection_sha256: str
    created_at: str

    def wire(self, *, include_internal: bool = False) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema_version": CONTENT_INSIGHT_SCHEMA,
            "title": self.title,
            "summary": self.summary,
            "topics": list(self.topics),
            "review_points": list(self.review_points),
            "source": self.source,
            "created_at": self.created_at,
        }
        if include_internal:
            value.update(
                {
                    "snapshot_sha256": self.snapshot_sha256,
                    "cited_asset_ids": list(self.cited_asset_ids),
                    "projection_sha256": self.projection_sha256,
                }
            )
        return value


class ContentUnderstandingStore:
    """Independent schema; derived text is persisted only as sealed blobs."""

    def __init__(
        self,
        database_path: str | Path,
        *,
        protect_projection: Callable[[bytes], bytes] = dpapi_protect_current_user,
        unprotect_projection: Callable[[bytes], bytearray] = dpapi_unprotect_current_user,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._closed = False
        self._protect_projection = protect_projection
        self._unprotect_projection = unprotect_projection
        self._now = now or (lambda: datetime.now(UTC))
        try:
            self._connection = sqlite3.connect(
                str(database_path),
                isolation_level=None,
                check_same_thread=False,
                timeout=5.0,
            )
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA busy_timeout = 5000")
            self._connection.execute("PRAGMA secure_delete = ON")
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._initialize_schema()
        except ContentUnderstandingError:
            connection = getattr(self, "_connection", None)
            if connection is not None:
                connection.close()
            raise
        except Exception as exc:  # noqa: BLE001
            connection = getattr(self, "_connection", None)
            if connection is not None:
                connection.close()
            raise ContentUnderstandingError("content_persistence_unavailable") from exc

    def _initialize_schema(self) -> None:
        with self._lock:
            tables = {
                str(row[0])
                for row in self._connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'content_%'"
                )
            }
            existing_version: int | None = None
            if "content_schema_meta" in tables:
                rows = list(
                    self._connection.execute(
                        "SELECT component, schema_version FROM content_schema_meta"
                    )
                )
                if (
                    len(rows) != 1
                    or str(rows[0][0]) != "content_understanding"
                    or isinstance(rows[0][1], bool)
                    or not isinstance(rows[0][1], int)
                    or int(rows[0][1]) not in {1, CONTENT_SCHEMA_VERSION}
                ):
                    raise ContentUnderstandingError("content_schema_unsupported")
                existing_version = int(rows[0][1])
            elif tables:
                raise ContentUnderstandingError("content_schema_unsupported")
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS content_schema_meta (
                    component TEXT PRIMARY KEY,
                    schema_version INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS content_root_policy (
                    device_id TEXT NOT NULL,
                    catalog_root_id TEXT NOT NULL,
                    content_opt_in INTEGER NOT NULL CHECK(content_opt_in IN (0,1)),
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(device_id, catalog_root_id)
                );
                CREATE TABLE IF NOT EXISTS content_study_pack (
                    snapshot_sha256 TEXT PRIMARY KEY CHECK(length(snapshot_sha256)=64),
                    projection_sha256 TEXT NOT NULL CHECK(length(projection_sha256)=64),
                    payload_json TEXT NOT NULL,
                    source TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS content_projection_v2 (
                    asset_id TEXT NOT NULL CHECK(length(asset_id)=64 AND asset_id NOT GLOB '*[^0-9a-f]*'),
                    device_id TEXT NOT NULL CHECK(length(device_id)=26),
                    catalog_root_id TEXT NOT NULL,
                    revision TEXT NOT NULL CHECK(length(revision)=64 AND revision NOT GLOB '*[^0-9a-f]*'),
                    format TEXT NOT NULL CHECK(format IN ('txt','md','docx','pptx','pdf')),
                    source_label TEXT NOT NULL,
                    text_sha256 TEXT NOT NULL CHECK(length(text_sha256)=64 AND text_sha256 NOT GLOB '*[^0-9a-f]*'),
                    char_count INTEGER NOT NULL CHECK(char_count BETWEEN 1 AND 20000),
                    truncated INTEGER NOT NULL CHECK(truncated IN (0,1)),
                    unit_count INTEGER NOT NULL CHECK(unit_count BETWEEN 1 AND 2000),
                    encrypted_text_blob BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    PRIMARY KEY(asset_id, revision)
                );
                CREATE INDEX IF NOT EXISTS content_projection_root_idx
                  ON content_projection_v2(device_id,catalog_root_id,expires_at);
                """
            )
            if existing_version is None:
                self._connection.execute(
                    "INSERT INTO content_schema_meta(component,schema_version) VALUES(?,?)",
                    ("content_understanding", CONTENT_SCHEMA_VERSION),
                )
            elif existing_version == 1:
                try:
                    self._connection.execute("BEGIN IMMEDIATE")
                    self._connection.execute("DELETE FROM content_study_pack")
                    self._connection.execute("COMMIT")
                    checkpoint = self._connection.execute(
                        "PRAGMA wal_checkpoint(TRUNCATE)"
                    ).fetchone()
                    if checkpoint is None or int(checkpoint[0]) != 0:
                        raise sqlite3.OperationalError("checkpoint_busy")
                    self._connection.execute("VACUUM")
                    self._connection.execute("BEGIN IMMEDIATE")
                    self._connection.execute(
                        "UPDATE content_schema_meta SET schema_version=? WHERE component=? AND schema_version=1",
                        (CONTENT_SCHEMA_VERSION, "content_understanding"),
                    )
                    self._connection.execute("COMMIT")
                except Exception:
                    if self._connection.in_transaction:
                        self._connection.execute("ROLLBACK")
                    raise ContentUnderstandingError(
                        "content_persistence_unavailable"
                    ) from None

    def set_opt_in(self, device_id: str, root_id: str, enabled: bool) -> None:
        _validate_binding(device_id, root_id)
        if not isinstance(enabled, bool):
            raise ContentUnderstandingError("content_policy_invalid")
        with self._lock:
            self._ensure_open()
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                self._connection.execute(
                    """
                    INSERT INTO content_root_policy(device_id,catalog_root_id,content_opt_in,updated_at)
                    VALUES(?,?,?,?)
                    ON CONFLICT(device_id,catalog_root_id) DO UPDATE SET
                      content_opt_in=excluded.content_opt_in,
                      updated_at=excluded.updated_at
                    """,
                    (device_id, root_id, int(enabled), _utc_now()),
                )
                if not enabled:
                    self._connection.execute(
                        "DELETE FROM content_projection_v2 WHERE device_id=? AND catalog_root_id=?",
                        (device_id, root_id),
                    )
                    self._connection.execute("DELETE FROM content_study_pack")
                self._connection.execute("COMMIT")
            except sqlite3.Error:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise ContentUnderstandingError("content_persistence_unavailable") from None

    def is_opted_in(self, device_id: str, root_id: str) -> bool:
        _validate_binding(device_id, root_id)
        with self._lock:
            self._ensure_open()
            row = self._connection.execute(
                "SELECT content_opt_in FROM content_root_policy WHERE device_id=? AND catalog_root_id=?",
                (device_id, root_id),
            ).fetchone()
            return row is not None and bool(row[0])

    def save_projection(self, projection: ContentProjection) -> None:
        try:
            sealed = seal_content_projection(
                projection, protect=self._protect_projection
            )
        except ContentProjectionError as exc:
            raise ContentUnderstandingError(exc.code) from None
        with self._lock:
            self._ensure_open()
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                self._connection.execute(
                    "DELETE FROM content_projection_v2 WHERE asset_id=? AND revision<>?",
                    (projection.asset_id, projection.revision),
                )
                self._connection.execute(
                    """
                    INSERT INTO content_projection_v2(
                      asset_id,device_id,catalog_root_id,revision,format,source_label,
                      text_sha256,char_count,truncated,unit_count,encrypted_text_blob,
                      created_at,expires_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(asset_id,revision) DO UPDATE SET
                      device_id=excluded.device_id,
                      catalog_root_id=excluded.catalog_root_id,
                      format=excluded.format,
                      source_label=excluded.source_label,
                      text_sha256=excluded.text_sha256,
                      char_count=excluded.char_count,
                      truncated=excluded.truncated,
                      unit_count=excluded.unit_count,
                      encrypted_text_blob=excluded.encrypted_text_blob,
                      created_at=excluded.created_at,
                      expires_at=excluded.expires_at
                    """,
                    (
                        projection.asset_id,
                        projection.device_id,
                        projection.catalog_root_id,
                        projection.revision,
                        projection.format,
                        projection.source_label,
                        projection.text_sha256,
                        projection.char_count,
                        int(projection.truncated),
                        projection.unit_count,
                        sealed,
                        projection.created_at,
                        projection.expires_at,
                    ),
                )
                self._connection.execute("COMMIT")
            except sqlite3.Error:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise ContentUnderstandingError("content_persistence_unavailable") from None

    def load_projection(
        self,
        *,
        asset_id: str,
        device_id: str,
        root_id: str,
        revision: str,
    ) -> ContentProjection | None:
        with self._lock:
            self._ensure_open()
            now = _format_utc(self._now())
            try:
                self._connection.execute(
                    "DELETE FROM content_projection_v2 WHERE expires_at<=?",
                    (now,),
                )
                row = self._connection.execute(
                    """
                    SELECT encrypted_text_blob FROM content_projection_v2
                    WHERE asset_id=? AND device_id=? AND catalog_root_id=? AND revision=?
                    """,
                    (asset_id, device_id, root_id, revision),
                ).fetchone()
            except sqlite3.Error:
                raise ContentUnderstandingError("content_persistence_unavailable") from None
        if row is None:
            return None
        try:
            return open_content_projection(
                bytes(row[0]),
                unprotect=self._unprotect_projection,
                expected_asset_id=asset_id,
                expected_device_id=device_id,
                expected_root_id=root_id,
                expected_revision=revision,
            )
        except ContentProjectionError as exc:
            raise ContentUnderstandingError(exc.code) from None

    def forget_root(self, device_id: str, root_id: str) -> None:
        _validate_binding(device_id, root_id)
        with self._lock:
            self._ensure_open()
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                self._connection.execute(
                    "DELETE FROM content_projection_v2 WHERE device_id=? AND catalog_root_id=?",
                    (device_id, root_id),
                )
                self._connection.execute("DELETE FROM content_study_pack")
                self._connection.execute("COMMIT")
            except sqlite3.Error:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise ContentUnderstandingError("content_persistence_unavailable") from None

    def save_study_pack(self, pack: StudyPack) -> None:
        payload = json.dumps(
            pack.wire(include_internal=True),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        sealed_payload = self._seal_study_pack_payload(payload)
        with self._lock:
            self._ensure_open()
            try:
                self._connection.execute(
                    """
                    INSERT INTO content_study_pack(snapshot_sha256,projection_sha256,payload_json,source,created_at)
                    VALUES(?,?,?,?,?)
                    ON CONFLICT(snapshot_sha256) DO UPDATE SET
                      projection_sha256=excluded.projection_sha256,
                      payload_json=excluded.payload_json,
                      source=excluded.source,
                      created_at=excluded.created_at
                    """,
                    (
                        pack.snapshot_sha256,
                        pack.projection_sha256,
                        sealed_payload,
                        pack.source,
                        pack.created_at,
                    ),
                )
            except sqlite3.Error:
                raise ContentUnderstandingError("content_persistence_unavailable") from None

    def latest_study_pack(self) -> StudyPack | None:
        with self._lock:
            self._ensure_open()
            row = self._connection.execute(
                "SELECT payload_json FROM content_study_pack ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
        if row is None:
            return None
        try:
            value = _strict_json_loads(
                self._open_study_pack_payload(str(row[0]))
            )
            citations = value.get("cited_asset_ids") if isinstance(value, dict) else None
            if not isinstance(citations, list):
                raise ValueError("citations_invalid")
            return study_pack_from_mapping(value, tuple(citations))
        except (ValueError, TypeError, json.JSONDecodeError):
            raise ContentUnderstandingError("content_integrity_error") from None

    def _seal_study_pack_payload(self, payload: str) -> str:
        try:
            raw = payload.encode("utf-8")
            sealed = self._protect_projection(raw)
            if (
                not isinstance(sealed, bytes)
                or not sealed
                or len(sealed) > MAX_SEALED_STUDY_PACK_BYTES
            ):
                raise ValueError("sealed_invalid")
            return CONTENT_STUDY_PACK_SEALED_PREFIX + base64.urlsafe_b64encode(
                sealed
            ).decode("ascii")
        except Exception:
            raise ContentUnderstandingError("content_projection_unavailable") from None

    def _open_study_pack_payload(self, payload: str) -> str:
        plaintext: bytearray | None = None
        try:
            if not payload.startswith(CONTENT_STUDY_PACK_SEALED_PREFIX):
                raise ValueError("sealed_prefix_invalid")
            encoded = payload[len(CONTENT_STUDY_PACK_SEALED_PREFIX) :]
            sealed = base64.b64decode(encoded, altchars=b"-_", validate=True)
            if not sealed or len(sealed) > MAX_SEALED_STUDY_PACK_BYTES:
                raise ValueError("sealed_invalid")
            plaintext = self._unprotect_projection(sealed)
            if not isinstance(plaintext, bytearray) or not plaintext:
                raise ValueError("plaintext_invalid")
            return bytes(plaintext).decode("utf-8")
        except Exception:
            raise ContentUnderstandingError("content_integrity_error") from None
        finally:
            if plaintext is not None:
                for index in range(len(plaintext)):
                    plaintext[index] = 0
                plaintext.clear()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._connection.close()

    def _ensure_open(self) -> None:
        if self._closed:
            raise ContentUnderstandingError("content_store_closed")


class ContentUnderstandingService:
    def __init__(
        self,
        *,
        store: ContentUnderstandingStore,
        catalog: CatalogStore,
        file_scope: PcFileScopeService,
        windows_device_id: str,
        document_extractor: DocumentExtractorSupervisor | None = None,
        android_ocr_store: AndroidOcrStore | None = None,
    ) -> None:
        _validate_device(windows_device_id)
        self._store = store
        self._catalog = catalog
        self._file_scope = file_scope
        self._windows_device_id = windows_device_id
        self._document_extractor = document_extractor or DocumentExtractorSupervisor()
        self._android_ocr_store = android_ocr_store

    def status(self) -> ContentPolicyView:
        scope = self._file_scope.status()
        if not scope.configured or scope.root_id is None:
            return ContentPolicyView(False, None, None, False, 0, 0, {})
        _, assets, _ = self._catalog.current_view()
        current = tuple(
            asset
            for asset in assets
            if asset.device_id == self._windows_device_id
            and asset.catalog_root_id == scope.root_id
        )
        format_counts = {
            extension: sum(
                asset.content_eligible and asset.extension == extension
                for asset in current
            )
            for extension in sorted(SUPPORTED_CONTENT_EXTENSIONS)
        }
        return ContentPolicyView(
            configured=True,
            catalog_root_id=scope.root_id,
            display_name=scope.display_name,
            content_opt_in=self._store.is_opted_in(
                self._windows_device_id, scope.root_id
            ),
            eligible_file_count=sum(asset.content_eligible for asset in current),
            supported_file_count=sum(
                asset.content_eligible
                and asset.extension in SUPPORTED_CONTENT_EXTENSIONS
                for asset in current
            ),
            supported_format_counts={
                key: value for key, value in format_counts.items() if value > 0
            },
        )

    def set_opt_in(self, enabled: bool) -> ContentPolicyView:
        scope = self._file_scope.status()
        if not scope.configured or scope.root_id is None:
            raise ContentUnderstandingError("content_scope_unconfigured")
        self._store.set_opt_in(self._windows_device_id, scope.root_id, enabled)
        return self.status()

    def current_snapshot(self) -> str:
        return self._catalog.projection_sha256()

    def list_safe_assets(self, *, snapshot_sha256: str) -> tuple[CatalogAssetView, ...]:
        _require_digest(snapshot_sha256)
        scope = self._file_scope.status()
        if not scope.configured or scope.root_id is None:
            raise ContentUnderstandingError("content_scope_unconfigured")
        if not self._store.is_opted_in(self._windows_device_id, scope.root_id):
            raise ContentUnderstandingError("content_opt_in_required")
        _, assets, actual_snapshot = self._catalog.current_view()
        if actual_snapshot != snapshot_sha256:
            raise ContentUnderstandingError("content_snapshot_stale")
        windows_assets = tuple(
            asset
            for asset in assets
            if asset.device_id == self._windows_device_id
            and asset.catalog_root_id == scope.root_id
            and asset.content_eligible
            and asset.extension in SUPPORTED_CONTENT_EXTENSIONS
        )
        ocr_store = self._android_ocr_store
        if ocr_store is None:
            return windows_assets
        try:
            android_assets = ocr_store.list_projected_assets()
        except AndroidOcrStoreError as exc:
            raise ContentUnderstandingError(exc.code) from None
        combined = {asset.asset_id: asset for asset in (*windows_assets, *android_assets)}
        return tuple(combined[key] for key in sorted(combined))

    def extract_assets(
        self,
        *,
        snapshot_sha256: str,
        requested_asset_ids: Iterable[str] | None = None,
    ) -> tuple[SafeAnalysisAsset, ...]:
        safe_assets = self.list_safe_assets(snapshot_sha256=snapshot_sha256)
        by_id = {asset.asset_id: asset for asset in safe_assets}
        if requested_asset_ids is None:
            selected_ids = tuple(sorted(by_id))[:MAX_ANALYSIS_FILES]
        else:
            selected_ids = tuple(requested_asset_ids)
            if (
                not selected_ids
                or len(selected_ids) > MAX_ANALYSIS_FILES
                or len(set(selected_ids)) != len(selected_ids)
                or any(_DIGEST_RE.fullmatch(item) is None for item in selected_ids)
                or any(item not in by_id for item in selected_ids)
            ):
                raise ContentUnderstandingError("content_asset_not_allowed")
        result: list[SafeAnalysisAsset] = []
        remaining = MAX_TOTAL_EXCERPT_CHARS
        scope = self._file_scope.status()
        if not scope.configured or scope.root_id is None:
            raise ContentUnderstandingError("content_scope_unconfigured")
        for asset_id in selected_ids:
            asset = by_id[asset_id]
            allowance = min(MAX_EXCERPT_CHARS, remaining)
            if allowance <= 0:
                break
            if asset.platform == "android":
                ocr_store = self._android_ocr_store
                if ocr_store is None:
                    raise ContentUnderstandingError("content_projection_unavailable")
                try:
                    ocr = ocr_store.load_text(
                        asset_id=asset.asset_id,
                        device_id=asset.device_id,
                        root_id=asset.catalog_root_id,
                        revision=asset.revision,
                    )
                except AndroidOcrStoreError as exc:
                    raise ContentUnderstandingError(exc.code) from None
                if ocr is None or not ocr.text:
                    raise ContentUnderstandingError("content_revision_changed")
                text = ocr.text[:allowance]
                truncated = ocr.truncated or len(ocr.text) > allowance
                unit_count = 1
            else:
                cached = self._store.load_projection(
                    asset_id=asset.asset_id,
                    device_id=self._windows_device_id,
                    root_id=scope.root_id,
                    revision=asset.revision,
                )
                if cached is not None:
                    text = cached.text[:allowance]
                    truncated = cached.truncated or len(cached.text) > allowance
                    unit_count = cached.unit_count
                else:
                    text, truncated, unit_count = self._extract_current_asset(
                        asset=asset,
                        allowance=allowance,
                    )
                    created = datetime.now(UTC)
                    projection = ContentProjection(
                        asset_id=asset.asset_id,
                        device_id=self._windows_device_id,
                        catalog_root_id=scope.root_id,
                        revision=asset.revision,
                        format=asset.extension,
                        source_label=asset.display_name,
                        text=text,
                        text_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
                        char_count=len(text),
                        truncated=truncated,
                        unit_count=unit_count,
                        created_at=_format_utc(created),
                        expires_at=_format_utc(
                            created + timedelta(days=CONTENT_PROJECTION_RETENTION_DAYS)
                        ),
                    )
                    self._store.save_projection(projection)
            result.append(
                SafeAnalysisAsset(
                    asset_id=asset.asset_id,
                    display_name=asset.display_name,
                    mime_family=asset.mime_family,
                    modified_at_ms=asset.modified_at_ms,
                    excerpt=text,
                    excerpt_sha256=hashlib.sha256(
                        text.encode("utf-8")
                    ).hexdigest(),
                    truncated=truncated,
                )
            )
            remaining -= len(text)
        if not result:
            raise ContentUnderstandingError("content_no_supported_files")
        return tuple(result)

    def _extract_current_asset(
        self, *, asset: CatalogAssetView, allowance: int
    ) -> tuple[str, bool, int]:
        try:
            if asset.extension in {"txt", "md"}:
                excerpt = self._file_scope.read_safe_text(
                    locator_token=asset.locator_token,
                    expected_revision=asset.revision,
                    max_chars=allowance,
                )
                return excerpt.text, excerpt.truncated, 1
            document = self._file_scope.read_safe_document(
                locator_token=asset.locator_token,
                expected_revision=asset.revision,
            )
            extracted = self._document_extractor.extract(
                extension=document.extension,
                payload=document.payload,
                max_chars=allowance,
            )
            return extracted.text, extracted.truncated, extracted.unit_count
        except PcFileScopeError as exc:
            raise ContentUnderstandingError(exc.code) from None
        except DocumentExtractionError as exc:
            raise ContentUnderstandingError(exc.code) from None

    def forget_current_root(self) -> ContentPolicyView:
        scope = self._file_scope.status()
        if not scope.configured or scope.root_id is None:
            raise ContentUnderstandingError("content_scope_unconfigured")
        self._store.forget_root(self._windows_device_id, scope.root_id)
        return self.status()

    def forget_current_root_if_configured(self) -> None:
        scope = self._file_scope.status()
        if not scope.configured or scope.root_id is None:
            return
        self._store.forget_root(self._windows_device_id, scope.root_id)

    def save_study_pack(
        self, value: Any, *, allowed_asset_ids: Iterable[str]
    ) -> StudyPack:
        pack = study_pack_from_mapping(value, tuple(allowed_asset_ids))
        if pack.snapshot_sha256 != self.current_snapshot():
            raise ContentUnderstandingError("content_snapshot_stale")
        self._store.save_study_pack(pack)
        return pack

    def latest_study_pack(self) -> StudyPack | None:
        pack = self._store.latest_study_pack()
        if pack is None:
            return None
        current_snapshot = self.current_snapshot()
        if pack.snapshot_sha256 != current_snapshot:
            return None
        try:
            allowed = {
                asset.asset_id
                for asset in self.list_safe_assets(
                    snapshot_sha256=current_snapshot
                )
            }
        except ContentUnderstandingError as exc:
            if exc.code in {
                "content_scope_unconfigured",
                "content_opt_in_required",
                "content_snapshot_stale",
            }:
                return None
            raise
        if not set(pack.cited_asset_ids).issubset(allowed):
            return None
        return pack


def study_pack_from_mapping(value: Any, allowed_asset_ids: Iterable[str]) -> StudyPack:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "snapshot_sha256",
        "title",
        "summary",
        "topics",
        "review_points",
        "cited_asset_ids",
        "source",
        "projection_sha256",
        "created_at",
    }:
        raise ContentUnderstandingError("content_insight_invalid")
    if value["schema_version"] != CONTENT_INSIGHT_SCHEMA:
        raise ContentUnderstandingError("content_insight_invalid")
    snapshot = value["snapshot_sha256"]
    title = _safe_text(value["title"], 80)
    summary = _safe_text(value["summary"], MAX_SUMMARY_CHARS)
    topics = _safe_text_list(value["topics"], MAX_TOPICS, MAX_TOPIC_CHARS)
    points = _safe_text_list(
        value["review_points"], MAX_REVIEW_POINTS, MAX_REVIEW_POINT_CHARS
    )
    citations = value["cited_asset_ids"]
    source = value["source"]
    created_at = value["created_at"]
    allowed = set(allowed_asset_ids)
    if (
        not isinstance(snapshot, str)
        or _DIGEST_RE.fullmatch(snapshot) is None
        or not isinstance(citations, list)
        or not citations
        or len(citations) > MAX_ANALYSIS_FILES
        or len(set(citations)) != len(citations)
        or not all(isinstance(item, str) and item in allowed for item in citations)
        or source not in {"hermes", "deterministic_fallback"}
        or not isinstance(created_at, str)
        or not created_at.endswith("Z")
    ):
        raise ContentUnderstandingError("content_insight_invalid")
    canonical = {
        "schema_version": CONTENT_INSIGHT_SCHEMA,
        "snapshot_sha256": snapshot,
        "title": title,
        "summary": summary,
        "topics": list(topics),
        "review_points": list(points),
        "cited_asset_ids": citations,
        "source": source,
        "created_at": created_at,
    }
    digest = hashlib.sha256(
        json.dumps(
            canonical,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    if value["projection_sha256"] != digest:
        raise ContentUnderstandingError("content_insight_invalid")
    return StudyPack(
        snapshot_sha256=snapshot,
        title=title,
        summary=summary,
        topics=topics,
        review_points=points,
        cited_asset_ids=tuple(citations),
        source=source,
        projection_sha256=digest,
        created_at=created_at,
    )


def build_study_pack(
    *,
    snapshot_sha256: str,
    title: str,
    summary: str,
    topics: Iterable[str],
    review_points: Iterable[str],
    cited_asset_ids: Iterable[str],
    source: str,
) -> StudyPack:
    created_at = _utc_now()
    base = {
        "schema_version": CONTENT_INSIGHT_SCHEMA,
        "snapshot_sha256": snapshot_sha256,
        "title": title,
        "summary": summary,
        "topics": list(topics),
        "review_points": list(review_points),
        "cited_asset_ids": list(cited_asset_ids),
        "source": source,
        "created_at": created_at,
    }
    digest = hashlib.sha256(
        json.dumps(
            base,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    return study_pack_from_mapping(
        {**base, "projection_sha256": digest}, base["cited_asset_ids"]
    )


def _safe_text(value: Any, limit: int) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > limit
        or any(ord(char) < 32 and char not in {"\n", "\t"} for char in value)
        or "content://" in value.casefold()
        or _PATH_RE.search(value)
    ):
        raise ContentUnderstandingError("content_insight_invalid")
    return value.strip()


def _safe_text_list(value: Any, max_items: int, max_chars: int) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or len(value) > max_items:
        raise ContentUnderstandingError("content_insight_invalid")
    result = tuple(_safe_text(item, max_chars) for item in value)
    if len(set(result)) != len(result):
        raise ContentUnderstandingError("content_insight_invalid")
    return result


def _validate_device(device_id: str) -> None:
    try:
        require_ulid("device_id", device_id)
    except PairingValidationError:
        raise ContentUnderstandingError("content_binding_invalid") from None


def _validate_binding(device_id: str, root_id: str) -> None:
    _validate_device(device_id)
    if not isinstance(root_id, str) or _ROOT_ID_RE.fullmatch(root_id) is None:
        raise ContentUnderstandingError("content_binding_invalid")


def _require_digest(value: str) -> None:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise ContentUnderstandingError("content_request_invalid")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate_key")
        value[key] = item
    return value


def _strict_json_loads(raw: str) -> Any:
    def reject_constant(_: str) -> None:
        raise ValueError("non_finite")

    return json.loads(
        raw,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=reject_constant,
    )


def _utc_now() -> str:
    return _format_utc(datetime.now(UTC))


def _format_utc(value: datetime) -> str:
    if value.tzinfo != UTC:
        raise ContentUnderstandingError("content_projection_invalid")
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")
