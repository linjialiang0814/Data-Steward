"""Persistent, read-only Windows file scope and deterministic query fallback."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import threading
import unicodedata
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .pc_file_scope_persistence import (
    PcFileScopePersistence,
    PcFileScopePersistenceError,
    PersistedPcFileScope,
)
from .pc_file_organizer_journal import (
    OrganizerJournal,
    OrganizerJournalError,
    OrganizerJournalStore,
    OrganizerMove,
)
from .tls_identity.path_safety import is_reparse_point
from .catalog_models import (
    MAX_CATALOG_ITEMS,
    CatalogItemInput,
    CatalogSnapshotBatch,
    catalog_snapshot_sha256,
)

MAX_SCOPE_PATH_CHARS = 1_024
MAX_SCAN_ENTRIES = 2_000
MAX_SEARCH_RESULTS = 10
MAX_QUERY_CHARS = 64
MAX_SAFE_TEXT_BYTES = 128 * 1024
MAX_SAFE_TEXT_CHARS = 20_000
MAX_SAFE_DOCUMENT_BYTES = 5 * 1024 * 1024
MAX_MARKDOWN_EXPORT_BYTES = 128 * 1024
MARKDOWN_EXPORT_DIRECTORY = "Data Steward 输出"
SAFE_DOCUMENT_EXTENSIONS = frozenset({".docx", ".pptx", ".pdf"})
IMAGE_EXTENSIONS = frozenset(
    {".bmp", ".gif", ".heic", ".jpeg", ".jpg", ".png", ".webp"}
)
DOCUMENT_EXTENSIONS = frozenset(
    {".csv", ".doc", ".docx", ".md", ".pdf", ".ppt", ".pptx", ".txt", ".xls", ".xlsx"}
)
MEDIA_EXTENSIONS = frozenset(
    {".aac", ".avi", ".flac", ".m4a", ".mkv", ".mov", ".mp3", ".mp4", ".wav", ".webm"}
)
ARCHIVE_EXTENSIONS = frozenset({".7z", ".gz", ".rar", ".tar", ".zip"})

_COUNT_TARGETS = ("电脑", "PC", "pc", "授权目录", "桌面")
_COUNT_SUBJECTS = ("图片", "图像", "照片")
_COUNT_WORDS = ("几个", "多少", "数量")
_SEARCH_RE = re.compile(
    r"(?:帮我)?(?:找下|找一下|查找|搜索)(?:电脑|PC|pc|授权目录|桌面)?"
    r"(?:里|中)?(?:有关|关于)?(?P<query>.+?)的文件(?:名)?[？?。.]?$"
)


class PcFileScopeError(Exception):
    """Stable error code which never contains a local path."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class PcFileScopeView:
    configured: bool
    root_id: str | None
    display_name: str | None
    authorized_at: str | None
    remembered: bool = False
    restore_status: str = "not_configured"


@dataclass(frozen=True, slots=True)
class PcFileQueryIntent:
    operation: str
    query: str | None = None


@dataclass(frozen=True, slots=True)
class PcFileQueryReceipt:
    operation: str
    root_id: str
    scanned_entry_count: int
    matched_count: int
    matched_names: tuple[str, ...]
    scanned_at: str
    result_sha256: str

    def conversation_text(self) -> str:
        if self.operation == "count_images":
            result = f"共 {self.matched_count} 个图片文件"
        else:
            names = "、".join(self.matched_names) if self.matched_names else "无"
            result = f"找到 {self.matched_count} 个文件：{names}"
        return (
            f"PC 已完成真实文件查询：{result}。"
            "范围为已授权目录的直接子文件。"
            "查询校验信息已保留在本地，不会显示目录路径或技术回执。"
        )


@dataclass(frozen=True, slots=True)
class PcFileInventory:
    """Privacy-safe metadata projection used by archive recommendations."""

    root_id: str
    scanned_entry_count: int
    category_counts: dict[str, int]
    category_bytes: dict[str, int]
    observed_at: str
    evidence_sha256: str


@dataclass(frozen=True, slots=True)
class PcFileOrganizationPreview:
    root_id: str
    selected_count: int
    category_counts: dict[str, int]
    evidence_sha256: str


@dataclass(frozen=True, slots=True)
class PcFileOrganizationReceipt:
    operation: str
    journal_id: str
    moved_count: int
    category_counts: dict[str, int]

    def conversation_text(self) -> str:
        if self.operation == "organize":
            return (
                f"整理完成：已将 {self.moved_count} 个直接子文件移动到 “Data Steward 归档”"
                "的分类目录中。没有覆盖或删除文件；如需恢复，可使用下方的撤销按钮。"
            )
        if self.operation == "undo":
            return (
                f"已撤销上次整理，{self.moved_count} 个文件已回到授权目录。"
                "没有覆盖或删除文件。"
            )
        raise PcFileScopeError("organizer_receipt_invalid")


@dataclass(frozen=True, slots=True)
class PcFileOrganizationStatus:
    state: str
    journal_id: str | None
    moved_count: int
    category_counts: dict[str, int]
    can_undo: bool


@dataclass(frozen=True, slots=True)
class PcSafeTextExcerpt:
    """A bounded text projection which never contains a filesystem path."""

    locator_token: str
    revision: str
    display_name: str
    text: str
    text_sha256: str
    truncated: bool


@dataclass(frozen=True, slots=True)
class PcSafeDocumentPayload:
    """Revision-bound document bytes for the isolated parser worker."""

    locator_token: str
    revision: str
    display_name: str
    extension: str
    payload_sha256: str
    payload: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class PcMarkdownArtifactInspection:
    state: str
    byte_count: int | None
    content_sha256: str | None


@dataclass(frozen=True, slots=True)
class _AuthorizedScope:
    path: Path
    view: PcFileScopeView


@dataclass(frozen=True, slots=True)
class _ScannedFile:
    name: str
    size: int
    modified_ns: int


def parse_pc_file_query_intent(content: str) -> PcFileQueryIntent | None:
    text = content.strip()
    if not text or len(text) > 2_000 or any(ord(char) < 32 for char in text):
        return None
    if (
        any(value in text for value in _COUNT_TARGETS)
        and any(value in text for value in _COUNT_SUBJECTS)
        and any(value in text for value in _COUNT_WORDS)
    ):
        return PcFileQueryIntent("count_images")
    match = _SEARCH_RE.search(text)
    if match is None:
        return None
    query = match.group("query").strip(" \t\"'“”‘’")
    if (
        not query
        or len(query) > MAX_QUERY_CHARS
        or any(ord(char) < 32 for char in query)
        or any(char in query for char in ("/", "\\", ":"))
    ):
        return None
    return PcFileQueryIntent("search_names", query=query)


class PcFileScopeService:
    """Owns one validated authorization and never opens file content."""

    def __init__(
        self,
        persistence: PcFileScopePersistence | None = None,
        organizer_journal: OrganizerJournalStore | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._scope: _AuthorizedScope | None = None
        self._persistence = persistence
        self._organizer_journal = organizer_journal
        self._empty_view = PcFileScopeView(False, None, None, None)
        if persistence is not None:
            self._restore_once()

    def status(self) -> PcFileScopeView:
        with self._lock:
            if self._scope is None:
                return self._empty_view
            return self._scope.view

    def authorize(self, path_text: str) -> PcFileScopeView:
        path = _validate_root(path_text)
        identity = _path_identity(path)
        display_name = path.name.strip()
        if not display_name or len(display_name) > 80:
            display_name = "已授权目录"
        authorized_at = _utc_now()
        with self._lock:
            existing = self._scope
            root_id = (
                existing.view.root_id
                if existing is not None and existing.path == path
                else f"pc-{secrets.token_hex(6)}"
            )
        assert root_id is not None
        if self._persistence is not None:
            try:
                self._persistence.save(
                    PersistedPcFileScope(
                        root_id=root_id,
                        canonical_path=str(path),
                        authorized_at=authorized_at,
                        path_identity=identity,
                    )
                )
            except PcFileScopePersistenceError:
                raise PcFileScopeError("file_scope_persistence_failed") from None
        view = PcFileScopeView(
            configured=True,
            root_id=root_id,
            display_name=display_name,
            authorized_at=authorized_at,
            remembered=self._persistence is not None,
            restore_status="active",
        )
        with self._lock:
            self._scope = _AuthorizedScope(path=path, view=view)
            self._empty_view = PcFileScopeView(False, None, None, None)
        return view

    def revoke(self) -> PcFileScopeView:
        if self._persistence is not None:
            try:
                self._persistence.clear()
            except PcFileScopePersistenceError:
                raise PcFileScopeError("file_scope_persistence_failed") from None
        with self._lock:
            self._scope = None
            self._empty_view = PcFileScopeView(False, None, None, None)
            return self._empty_view

    def _restore_once(self) -> None:
        assert self._persistence is not None
        try:
            record = self._persistence.load()
            if record is None:
                return
            path = _validate_root(record.canonical_path)
            if _path_identity(path) != record.path_identity:
                raise PcFileScopeError("file_scope_identity_changed")
            display_name = path.name.strip()
            if not display_name or len(display_name) > 80:
                display_name = "已授权目录"
            view = PcFileScopeView(
                configured=True,
                root_id=record.root_id,
                display_name=display_name,
                authorized_at=record.authorized_at,
                remembered=True,
                restore_status="restored",
            )
            self._scope = _AuthorizedScope(path=path, view=view)
        except (PcFileScopeError, PcFileScopePersistenceError):
            self._scope = None
            self._empty_view = PcFileScopeView(
                False,
                None,
                None,
                None,
                remembered=True,
                restore_status="unavailable",
            )

    def execute(self, intent: PcFileQueryIntent) -> PcFileQueryReceipt:
        if intent.operation not in {"count_images", "search_names"}:
            raise PcFileScopeError("file_query_invalid")
        with self._lock:
            scope = self._scope
            if scope is None:
                raise PcFileScopeError("file_scope_unconfigured")
            files, scanned_count = _scan_direct_files(scope.path)
            if intent.operation == "count_images":
                matched = [
                    item
                    for item in files
                    if Path(item.name).suffix.casefold() in IMAGE_EXTENSIONS
                ]
                visible_names: tuple[str, ...] = ()
            else:
                assert intent.query is not None
                needle = intent.query.casefold()
                matched = [item for item in files if needle in item.name.casefold()]
                visible_names = tuple(item.name for item in matched[:MAX_SEARCH_RESULTS])
            canonical = json.dumps(
                [
                    {"modified_ns": item.modified_ns, "name": item.name, "size": item.size}
                    for item in matched
                ],
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            return PcFileQueryReceipt(
                operation=intent.operation,
                root_id=scope.view.root_id or "pc-unknown",
                scanned_entry_count=scanned_count,
                matched_count=len(matched),
                matched_names=visible_names,
                scanned_at=_utc_now(),
                result_sha256=hashlib.sha256(canonical).hexdigest(),
            )

    def inventory(self) -> PcFileInventory:
        """Return counts and sizes only; names and paths never leave this boundary."""

        with self._lock:
            scope = self._scope
            if scope is None:
                raise PcFileScopeError("file_scope_unconfigured")
            files, scanned_count = _scan_direct_files(scope.path)
            counts = {name: 0 for name in _ARCHIVE_CATEGORIES}
            sizes = {name: 0 for name in _ARCHIVE_CATEGORIES}
            evidence_rows: list[dict[str, int | str]] = []
            for item in files:
                category = _archive_category(item.name)
                counts[category] += 1
                sizes[category] += item.size
                evidence_rows.append(
                    {
                        "modified_ns": item.modified_ns,
                        "name": item.name,
                        "size": item.size,
                    }
                )
            canonical = json.dumps(
                evidence_rows,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            return PcFileInventory(
                root_id=scope.view.root_id or "pc-unknown",
                scanned_entry_count=scanned_count,
                category_counts=counts,
                category_bytes=sizes,
                observed_at=_utc_now(),
                evidence_sha256=hashlib.sha256(canonical).hexdigest(),
            )

    def read_safe_text(
        self,
        *,
        locator_token: str,
        expected_revision: str,
        max_chars: int = MAX_SAFE_TEXT_CHARS,
    ) -> PcSafeTextExcerpt:
        """Read one current direct-child UTF-8 txt/md file, fail-closed."""

        if (
            re.fullmatch(r"[0-9a-f]{64}", locator_token) is None
            or re.fullmatch(r"[0-9a-f]{64}", expected_revision) is None
            or isinstance(max_chars, bool)
            or not isinstance(max_chars, int)
            or not 1 <= max_chars <= MAX_SAFE_TEXT_CHARS
        ):
            raise PcFileScopeError("content_request_invalid")
        with self._lock:
            scope = self._scope
            if scope is None or scope.view.root_id is None:
                raise PcFileScopeError("file_scope_unconfigured")
            files, _ = _scan_direct_files(scope.path)
            selected: _ScannedFile | None = None
            for item in files:
                projected = _catalog_item(scope.view.root_id, item)
                if projected.locator_token == locator_token:
                    selected = item
                    if projected.revision != expected_revision:
                        raise PcFileScopeError("content_revision_changed")
                    break
            if selected is None:
                raise PcFileScopeError("content_asset_unavailable")
            suffix = Path(selected.name).suffix.casefold()
            if suffix not in {".txt", ".md"} or selected.size > MAX_SAFE_TEXT_BYTES:
                raise PcFileScopeError("content_format_unsupported")
            source = scope.path / selected.name
            try:
                if source.is_symlink() or is_reparse_point(source):
                    raise PcFileScopeError("content_source_unsafe")
                before = source.stat(follow_symlinks=False)
                if (
                    not source.is_file()
                    or int(before.st_size) != selected.size
                    or int(before.st_mtime_ns) != selected.modified_ns
                ):
                    raise PcFileScopeError("content_revision_changed")
                with source.open("rb") as handle:
                    opened = os.fstat(handle.fileno())
                    if (
                        int(opened.st_size) != selected.size
                        or int(opened.st_mtime_ns) != selected.modified_ns
                    ):
                        raise PcFileScopeError("content_revision_changed")
                    raw = handle.read(MAX_SAFE_TEXT_BYTES + 1)
                    after_open = os.fstat(handle.fileno())
                after = source.stat(follow_symlinks=False)
            except PcFileScopeError:
                raise
            except OSError:
                raise PcFileScopeError("content_read_unavailable") from None
            if (
                len(raw) > MAX_SAFE_TEXT_BYTES
                or int(after_open.st_size) != selected.size
                or int(after_open.st_mtime_ns) != selected.modified_ns
                or int(after.st_size) != selected.size
                or int(after.st_mtime_ns) != selected.modified_ns
                or source.is_symlink()
                or is_reparse_point(source)
            ):
                raise PcFileScopeError("content_revision_changed")
            try:
                text = raw.decode("utf-8-sig")
            except UnicodeDecodeError:
                raise PcFileScopeError("content_encoding_unsupported") from None
            if "\x00" in text or any(
                unicodedata.category(char) in {"Cc", "Cs"}
                and char not in {"\n", "\r", "\t"}
                for char in text
            ):
                raise PcFileScopeError("content_encoding_unsupported")
            text = text.replace("\r\n", "\n").replace("\r", "\n")
            truncated = len(text) > max_chars
            safe_text = text[:max_chars]
            return PcSafeTextExcerpt(
                locator_token=locator_token,
                revision=expected_revision,
                display_name=selected.name,
                text=safe_text,
                text_sha256=hashlib.sha256(raw).hexdigest(),
                truncated=truncated,
            )

    def read_safe_document(
        self,
        *,
        locator_token: str,
        expected_revision: str,
    ) -> PcSafeDocumentPayload:
        """Read one current direct-child DOCX/PPTX/PDF into a bounded buffer."""

        if (
            re.fullmatch(r"[0-9a-f]{64}", locator_token) is None
            or re.fullmatch(r"[0-9a-f]{64}", expected_revision) is None
        ):
            raise PcFileScopeError("content_request_invalid")
        with self._lock:
            scope = self._scope
            if scope is None or scope.view.root_id is None:
                raise PcFileScopeError("file_scope_unconfigured")
            files, _ = _scan_direct_files(scope.path)
            selected: _ScannedFile | None = None
            for item in files:
                projected = _catalog_item(scope.view.root_id, item)
                if projected.locator_token == locator_token:
                    selected = item
                    if projected.revision != expected_revision:
                        raise PcFileScopeError("content_revision_changed")
                    break
            if selected is None:
                raise PcFileScopeError("content_asset_unavailable")
            suffix = Path(selected.name).suffix.casefold()
            if (
                suffix not in SAFE_DOCUMENT_EXTENSIONS
                or selected.size > MAX_SAFE_DOCUMENT_BYTES
            ):
                raise PcFileScopeError("content_format_unsupported")
            source = scope.path / selected.name
            try:
                if source.is_symlink() or is_reparse_point(source):
                    raise PcFileScopeError("content_source_unsafe")
                before = source.stat(follow_symlinks=False)
                if (
                    not source.is_file()
                    or int(before.st_size) != selected.size
                    or int(before.st_mtime_ns) != selected.modified_ns
                ):
                    raise PcFileScopeError("content_revision_changed")
                with source.open("rb") as handle:
                    opened = os.fstat(handle.fileno())
                    if (
                        int(opened.st_size) != selected.size
                        or int(opened.st_mtime_ns) != selected.modified_ns
                    ):
                        raise PcFileScopeError("content_revision_changed")
                    raw = handle.read(MAX_SAFE_DOCUMENT_BYTES + 1)
                    after_open = os.fstat(handle.fileno())
                after = source.stat(follow_symlinks=False)
            except PcFileScopeError:
                raise
            except OSError:
                raise PcFileScopeError("content_read_unavailable") from None
            if (
                not raw
                or len(raw) > MAX_SAFE_DOCUMENT_BYTES
                or int(after_open.st_size) != selected.size
                or int(after_open.st_mtime_ns) != selected.modified_ns
                or int(after.st_size) != selected.size
                or int(after.st_mtime_ns) != selected.modified_ns
                or source.is_symlink()
                or is_reparse_point(source)
            ):
                raise PcFileScopeError("content_revision_changed")
            return PcSafeDocumentPayload(
                locator_token=locator_token,
                revision=expected_revision,
                display_name=selected.name,
                extension=suffix[1:],
                payload_sha256=hashlib.sha256(raw).hexdigest(),
                payload=raw,
            )

    def catalog_snapshot(
        self,
        *,
        base_seq: int,
        idempotency_key: str,
        generated_at_ms: int,
    ) -> CatalogSnapshotBatch:
        """Build the shared metadata projection without exposing the root path."""

        with self._lock:
            scope = self._scope
            if scope is None or scope.view.root_id is None:
                raise PcFileScopeError("file_scope_unconfigured")
            files, scanned_count = _scan_direct_files(scope.path)
            if scanned_count > MAX_CATALOG_ITEMS:
                raise PcFileScopeError("file_scope_too_large")
            root_id = scope.view.root_id
            items = tuple(
                sorted(
                    (_catalog_item(root_id, item) for item in files),
                    key=lambda item: item.locator_token,
                )
            )
            skipped_count = scanned_count - len(files)
            return CatalogSnapshotBatch(
                idempotency_key=idempotency_key,
                catalog_root_id=root_id,
                platform="windows",
                provider="windows.file-scope",
                display_name=scope.view.display_name or "PC workspace",
                base_seq=base_seq,
                snapshot_sha256=catalog_snapshot_sha256(
                    root_id,
                    items,
                    skipped_count,
                ),
                generated_at_ms=generated_at_ms,
                item_count=len(items),
                skipped_count=skipped_count,
                complete_snapshot=True,
                items=items,
            )

    def organize(
        self, *, expected_root_id: str, expected_evidence_sha256: str
    ) -> PcFileOrganizationReceipt:
        journal_store = self._organizer_journal
        if journal_store is None:
            raise PcFileScopeError("organizer_unavailable")
        with self._lock:
            scope = self._scope
            if scope is None or scope.view.root_id != expected_root_id:
                raise PcFileScopeError("organizer_scope_changed")
            try:
                existing_journal = journal_store.load()
                if (
                    existing_journal is not None
                    and existing_journal.state == "completed"
                    and existing_journal.root_id == expected_root_id
                    and existing_journal.evidence_sha256 == expected_evidence_sha256
                    and _organization_state_is_complete(
                        scope.path, existing_journal.moves
                    )
                ):
                    counts = {name: 0 for name in _ARCHIVE_CATEGORIES}
                    for move in existing_journal.moves:
                        counts[move.category] += 1
                    return PcFileOrganizationReceipt(
                        operation="organize",
                        journal_id=existing_journal.journal_id,
                        moved_count=len(existing_journal.moves),
                        category_counts=counts,
                    )
                if (
                    existing_journal is not None
                    and existing_journal.state == "prepared"
                    and existing_journal.root_id == expected_root_id
                    and existing_journal.evidence_sha256 == expected_evidence_sha256
                    and _rollback_moves(scope.path, existing_journal.moves)
                ):
                    journal_store.clear()
                    existing_journal = None
                if existing_journal is not None:
                    raise PcFileScopeError("organizer_undo_required")
            except OrganizerJournalError:
                raise PcFileScopeError("organizer_journal_unavailable") from None
            inventory = self.inventory()
            if inventory.evidence_sha256 != expected_evidence_sha256:
                raise PcFileScopeError("organizer_preview_stale")
            files, _ = _scan_direct_files(scope.path)
            if not files:
                raise PcFileScopeError("organizer_nothing_to_do")
            _preflight_organization(scope.path, files)
            moves = tuple(
                OrganizerMove(item.name, _archive_category(item.name)) for item in files
            )
            journal = OrganizerJournal(
                journal_id="org-" + secrets.token_hex(8),
                root_id=expected_root_id,
                evidence_sha256=expected_evidence_sha256,
                state="prepared",
                moves=moves,
            )
            try:
                journal_store.save(journal)
                moved = _apply_organization(scope.path, files)
                completed = OrganizerJournal(
                    journal_id=journal.journal_id,
                    root_id=journal.root_id,
                    evidence_sha256=journal.evidence_sha256,
                    state="completed",
                    moves=journal.moves,
                )
                journal_store.save(completed)
            except (OrganizerJournalError, OSError, PcFileScopeError):
                if _rollback_moves(scope.path, moves):
                    try:
                        journal_store.clear()
                    except OrganizerJournalError:
                        pass
                raise PcFileScopeError("organizer_execution_failed") from None
            counts = {name: 0 for name in _ARCHIVE_CATEGORIES}
            for move in moves:
                counts[move.category] += 1
            return PcFileOrganizationReceipt(
                operation="organize",
                journal_id=journal.journal_id,
                moved_count=moved,
                category_counts=counts,
            )

    def organization_preview(
        self, *, locator_tokens: tuple[str, ...]
    ) -> PcFileOrganizationPreview:
        clean_tokens = _validate_organization_selection(locator_tokens)
        with self._lock:
            scope = self._scope
            if scope is None or scope.view.root_id is None:
                raise PcFileScopeError("file_scope_unconfigured")
            files, _ = _scan_direct_files(scope.path)
            selected = _select_catalog_files(
                root_id=scope.view.root_id,
                files=files,
                locator_tokens=clean_tokens,
            )
            _preflight_organization(scope.path, selected)
            counts = {name: 0 for name in _ARCHIVE_CATEGORIES}
            evidence_rows: list[dict[str, int | str]] = []
            for item in selected:
                projected = _catalog_item(scope.view.root_id, item)
                category = _archive_category(item.name)
                counts[category] += 1
                evidence_rows.append(
                    {
                        "category": category,
                        "locator_token": projected.locator_token,
                        "modified_ns": item.modified_ns,
                        "name": item.name,
                        "revision": projected.revision,
                        "size": item.size,
                    }
                )
            canonical = json.dumps(
                {
                    "files": evidence_rows,
                    "root_id": scope.view.root_id,
                },
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            return PcFileOrganizationPreview(
                root_id=scope.view.root_id,
                selected_count=len(selected),
                category_counts=counts,
                evidence_sha256=hashlib.sha256(canonical).hexdigest(),
            )

    def organize_selected(
        self,
        *,
        expected_root_id: str,
        expected_evidence_sha256: str,
        locator_tokens: tuple[str, ...],
    ) -> PcFileOrganizationReceipt:
        clean_tokens = _validate_organization_selection(locator_tokens)
        if re.fullmatch(r"[0-9a-f]{64}", expected_evidence_sha256) is None:
            raise PcFileScopeError("organizer_preview_invalid")
        journal_store = self._organizer_journal
        if journal_store is None:
            raise PcFileScopeError("organizer_unavailable")
        with self._lock:
            scope = self._scope
            if scope is None or scope.view.root_id != expected_root_id:
                raise PcFileScopeError("organizer_scope_changed")
            try:
                existing_journal = journal_store.load()
                if (
                    existing_journal is not None
                    and existing_journal.state == "completed"
                    and existing_journal.root_id == expected_root_id
                    and existing_journal.evidence_sha256 == expected_evidence_sha256
                    and _journal_locator_tokens(
                        expected_root_id, existing_journal.moves
                    )
                    == clean_tokens
                    and _organization_state_is_complete(
                        scope.path, existing_journal.moves
                    )
                ):
                    counts = {name: 0 for name in _ARCHIVE_CATEGORIES}
                    for move in existing_journal.moves:
                        counts[move.category] += 1
                    return PcFileOrganizationReceipt(
                        operation="organize",
                        journal_id=existing_journal.journal_id,
                        moved_count=len(existing_journal.moves),
                        category_counts=counts,
                    )
                if (
                    existing_journal is not None
                    and existing_journal.state == "prepared"
                    and existing_journal.root_id == expected_root_id
                    and existing_journal.evidence_sha256 == expected_evidence_sha256
                    and _rollback_moves(scope.path, existing_journal.moves)
                ):
                    journal_store.clear()
                    existing_journal = None
                if existing_journal is not None:
                    raise PcFileScopeError("organizer_undo_required")
            except OrganizerJournalError:
                raise PcFileScopeError("organizer_journal_unavailable") from None
            preview = self.organization_preview(locator_tokens=clean_tokens)
            if preview.evidence_sha256 != expected_evidence_sha256:
                raise PcFileScopeError("organizer_preview_stale")
            files, _ = _scan_direct_files(scope.path)
            selected = _select_catalog_files(
                root_id=expected_root_id,
                files=files,
                locator_tokens=clean_tokens,
            )
            _preflight_organization(scope.path, selected)
            moves = tuple(
                OrganizerMove(item.name, _archive_category(item.name))
                for item in selected
            )
            journal = OrganizerJournal(
                journal_id="org-" + secrets.token_hex(8),
                root_id=expected_root_id,
                evidence_sha256=expected_evidence_sha256,
                state="prepared",
                moves=moves,
            )
            try:
                journal_store.save(journal)
                moved = _apply_organization(scope.path, selected)
                journal_store.save(
                    OrganizerJournal(
                        journal_id=journal.journal_id,
                        root_id=journal.root_id,
                        evidence_sha256=journal.evidence_sha256,
                        state="completed",
                        moves=journal.moves,
                    )
                )
            except (OrganizerJournalError, OSError, PcFileScopeError):
                if _rollback_moves(scope.path, moves):
                    try:
                        journal_store.clear()
                    except OrganizerJournalError:
                        pass
                raise PcFileScopeError("organizer_execution_failed") from None
            counts = {name: 0 for name in _ARCHIVE_CATEGORIES}
            for move in moves:
                counts[move.category] += 1
            return PcFileOrganizationReceipt(
                operation="organize",
                journal_id=journal.journal_id,
                moved_count=moved,
                category_counts=counts,
            )

    def undo_organization(self, journal_id: str) -> PcFileOrganizationReceipt:
        journal_store = self._organizer_journal
        if journal_store is None:
            raise PcFileScopeError("organizer_unavailable")
        with self._lock:
            scope = self._scope
            if scope is None:
                raise PcFileScopeError("file_scope_unconfigured")
            try:
                journal = journal_store.load()
            except OrganizerJournalError:
                raise PcFileScopeError("organizer_journal_unavailable") from None
            if (
                journal is None
                or journal.journal_id != journal_id
                or journal.root_id != scope.view.root_id
            ):
                raise PcFileScopeError("organizer_undo_unavailable")
            if not _rollback_moves(scope.path, journal.moves):
                raise PcFileScopeError("organizer_undo_failed")
            try:
                journal_store.clear()
            except OrganizerJournalError:
                raise PcFileScopeError("organizer_journal_unavailable") from None
            counts = {name: 0 for name in _ARCHIVE_CATEGORIES}
            for move in journal.moves:
                counts[move.category] += 1
            return PcFileOrganizationReceipt(
                operation="undo",
                journal_id=journal.journal_id,
                moved_count=len(journal.moves),
                category_counts=counts,
            )

    def organization_status(self) -> PcFileOrganizationStatus:
        """Project the sealed journal without exposing paths or filenames."""
        journal_store = self._organizer_journal
        if journal_store is None:
            raise PcFileScopeError("organizer_unavailable")
        empty_counts = {name: 0 for name in _ARCHIVE_CATEGORIES}
        with self._lock:
            try:
                journal = journal_store.load()
            except OrganizerJournalError:
                raise PcFileScopeError("organizer_journal_unavailable") from None
            if journal is None:
                return PcFileOrganizationStatus(
                    state="idle",
                    journal_id=None,
                    moved_count=0,
                    category_counts=empty_counts,
                    can_undo=False,
                )
            counts = {name: 0 for name in _ARCHIVE_CATEGORIES}
            for move in journal.moves:
                counts[move.category] += 1
            scope = self._scope
            if (
                scope is not None
                and scope.view.root_id == journal.root_id
                and journal.state == "completed"
                and _organization_state_is_complete(scope.path, journal.moves)
            ):
                return PcFileOrganizationStatus(
                    state="undo_available",
                    journal_id=journal.journal_id,
                    moved_count=len(journal.moves),
                    category_counts=counts,
                    can_undo=True,
                )
            return PcFileOrganizationStatus(
                state="recovery_required",
                journal_id=None,
                moved_count=len(journal.moves),
                category_counts=counts,
                can_undo=False,
            )

    def write_markdown_export(
        self,
        *,
        expected_root_id: str,
        filename: str,
        content: bytes,
    ) -> None:
        """Exclusive-create one bounded Markdown artifact in the fixed output folder."""
        clean_name = _validate_markdown_export(filename, content)
        with self._lock:
            scope = self._scope
            if scope is None or scope.view.root_id != expected_root_id:
                raise PcFileScopeError("artifact_scope_changed")
            output = scope.path / MARKDOWN_EXPORT_DIRECTORY
            _ensure_artifact_directory(output, create=True)
            target = output / clean_name
            if target.exists() or target.is_symlink() or is_reparse_point(target):
                raise PcFileScopeError("artifact_target_exists")
            try:
                with target.open("xb") as handle:
                    handle.write(content)
                    handle.flush()
                    os.fsync(handle.fileno())
                _assert_safe_artifact_file(target)
            except FileExistsError:
                raise PcFileScopeError("artifact_target_exists") from None
            except PcFileScopeError:
                _remove_partial_artifact(target)
                raise
            except OSError:
                _remove_partial_artifact(target)
                raise PcFileScopeError("artifact_write_failed") from None

    def inspect_markdown_export(
        self,
        *,
        expected_root_id: str,
        filename: str,
        expected_byte_count: int,
        expected_content_sha256: str,
    ) -> PcMarkdownArtifactInspection:
        clean_name = _validate_markdown_export_name(filename)
        if (
            isinstance(expected_byte_count, bool)
            or not isinstance(expected_byte_count, int)
            or not 1 <= expected_byte_count <= MAX_MARKDOWN_EXPORT_BYTES
            or re.fullmatch(r"[0-9a-f]{64}", expected_content_sha256) is None
        ):
            raise PcFileScopeError("artifact_evidence_invalid")
        with self._lock:
            scope = self._scope
            if scope is None or scope.view.root_id != expected_root_id:
                raise PcFileScopeError("artifact_scope_changed")
            output = scope.path / MARKDOWN_EXPORT_DIRECTORY
            if not output.exists():
                return PcMarkdownArtifactInspection("missing", None, None)
            _ensure_artifact_directory(output, create=False)
            target = output / clean_name
            if not target.exists():
                return PcMarkdownArtifactInspection("missing", None, None)
            _assert_safe_artifact_file(target)
            try:
                size = target.stat(follow_symlinks=False).st_size
                if size <= 0 or size > MAX_MARKDOWN_EXPORT_BYTES:
                    return PcMarkdownArtifactInspection("changed", size, None)
                digest = hashlib.sha256()
                with target.open("rb") as handle:
                    while chunk := handle.read(32 * 1024):
                        digest.update(chunk)
                actual = digest.hexdigest()
            except OSError:
                raise PcFileScopeError("artifact_inspection_failed") from None
            state = (
                "exact"
                if size == expected_byte_count and actual == expected_content_sha256
                else "changed"
            )
            return PcMarkdownArtifactInspection(state, size, actual)

    def delete_markdown_export_unchanged(
        self,
        *,
        expected_root_id: str,
        filename: str,
        expected_byte_count: int,
        expected_content_sha256: str,
    ) -> None:
        with self._lock:
            inspection = self.inspect_markdown_export(
                expected_root_id=expected_root_id,
                filename=filename,
                expected_byte_count=expected_byte_count,
                expected_content_sha256=expected_content_sha256,
            )
            if inspection.state != "exact":
                raise PcFileScopeError("artifact_modified")
            scope = self._scope
            if scope is None or scope.view.root_id != expected_root_id:
                raise PcFileScopeError("artifact_scope_changed")
            output = scope.path / MARKDOWN_EXPORT_DIRECTORY
            _ensure_artifact_directory(output, create=False)
            target = output / _validate_markdown_export_name(filename)
            _assert_safe_artifact_file(target)
            try:
                target.unlink()
                if not any(output.iterdir()):
                    output.rmdir()
            except OSError:
                raise PcFileScopeError("artifact_delete_failed") from None


_ARCHIVE_CATEGORIES = ("images", "documents", "media", "archives", "other")
_ARCHIVE_ROOT_NAME = "Data Steward 归档"
_CATEGORY_DIRECTORIES = {
    "images": "图片",
    "documents": "文档",
    "media": "音视频",
    "archives": "压缩包",
    "other": "其他",
}

_WINDOWS_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
)


def _validate_markdown_export(filename: str, content: bytes) -> str:
    clean_name = _validate_markdown_export_name(filename)
    if (
        not isinstance(content, bytes)
        or not 1 <= len(content) <= MAX_MARKDOWN_EXPORT_BYTES
        or content.startswith(b"\xef\xbb\xbf")
    ):
        raise PcFileScopeError("artifact_content_invalid")
    try:
        text = content.decode("utf-8")
    except UnicodeError:
        raise PcFileScopeError("artifact_content_invalid") from None
    if not text.strip() or "\x00" in text:
        raise PcFileScopeError("artifact_content_invalid")
    return clean_name


def _validate_markdown_export_name(filename: str) -> str:
    if (
        not isinstance(filename, str)
        or not 4 <= len(filename) <= 120
        or Path(filename).name != filename
        or not filename.casefold().endswith(".md")
        or filename[-1] in {" ", "."}
        or any(unicodedata.category(char).startswith("C") for char in filename)
        or any(char in filename for char in '<>:"/\\|?*')
        or Path(filename).stem.upper() in _WINDOWS_RESERVED_NAMES
    ):
        raise PcFileScopeError("artifact_filename_invalid")
    return filename


def _ensure_artifact_directory(path: Path, *, create: bool) -> None:
    if not path.exists():
        if not create:
            raise PcFileScopeError("artifact_missing")
        try:
            path.mkdir()
        except OSError:
            raise PcFileScopeError("artifact_directory_unsafe") from None
    if path.is_symlink() or not path.is_dir() or is_reparse_point(path):
        raise PcFileScopeError("artifact_directory_unsafe")


def _assert_safe_artifact_file(path: Path) -> None:
    if path.is_symlink() or is_reparse_point(path) or not path.is_file():
        raise PcFileScopeError("artifact_file_unsafe")


def _remove_partial_artifact(path: Path) -> None:
    try:
        if path.exists() and path.is_file() and not path.is_symlink() and not is_reparse_point(path):
            path.unlink()
    except OSError:
        pass


def _validate_organization_selection(
    locator_tokens: tuple[str, ...],
) -> tuple[str, ...]:
    if (
        not isinstance(locator_tokens, tuple)
        or not 1 <= len(locator_tokens) <= MAX_CATALOG_ITEMS
        or tuple(sorted(locator_tokens)) != locator_tokens
        or len(set(locator_tokens)) != len(locator_tokens)
        or any(re.fullmatch(r"[0-9a-f]{64}", token) is None for token in locator_tokens)
    ):
        raise PcFileScopeError("organizer_selection_invalid")
    return locator_tokens


def _select_catalog_files(
    *,
    root_id: str,
    files: list[_ScannedFile],
    locator_tokens: tuple[str, ...],
) -> list[_ScannedFile]:
    by_locator = {
        _catalog_item(root_id, item).locator_token: item
        for item in files
    }
    try:
        selected = [by_locator[token] for token in locator_tokens]
    except KeyError:
        raise PcFileScopeError("organizer_selection_stale") from None
    return sorted(selected, key=lambda item: item.name)


def _journal_locator_tokens(
    root_id: str, moves: tuple[OrganizerMove, ...]
) -> tuple[str, ...]:
    return tuple(
        sorted(
            hashlib.sha256(f"{root_id}\0{move.source_name}".encode("utf-8")).hexdigest()
            for move in moves
        )
    )


def _apply_organization(root: Path, files: list[_ScannedFile]) -> int:
    archive_root = root / _ARCHIVE_ROOT_NAME
    _ensure_safe_directory(archive_root)
    moved: list[OrganizerMove] = []
    try:
        for item in files:
            category = _archive_category(item.name)
            category_root = archive_root / _CATEGORY_DIRECTORIES[category]
            _ensure_safe_directory(category_root)
            source = root / item.name
            destination = category_root / item.name
            if destination.exists() or destination.is_symlink():
                raise PcFileScopeError("organizer_destination_conflict")
            stat = source.stat(follow_symlinks=False)
            if (
                source.is_symlink()
                or not source.is_file()
                or int(stat.st_size) != item.size
                or int(stat.st_mtime_ns) != item.modified_ns
                or is_reparse_point(source)
            ):
                raise PcFileScopeError("organizer_source_changed")
            os.rename(source, destination)
            moved.append(OrganizerMove(item.name, category))
        return len(moved)
    except (OSError, PcFileScopeError):
        _rollback_moves(root, tuple(moved))
        raise


def _preflight_organization(root: Path, files: list[_ScannedFile]) -> None:
    archive_root = root / _ARCHIVE_ROOT_NAME
    if archive_root.exists():
        _ensure_safe_directory(archive_root)
    for item in files:
        category_root = archive_root / _CATEGORY_DIRECTORIES[_archive_category(item.name)]
        if category_root.exists():
            _ensure_safe_directory(category_root)
        destination = category_root / item.name
        if destination.exists() or destination.is_symlink():
            raise PcFileScopeError("organizer_destination_conflict")


def _rollback_moves(root: Path, moves: tuple[OrganizerMove, ...]) -> bool:
    archive_root = root / _ARCHIVE_ROOT_NAME
    states: list[tuple[Path, Path, bool]] = []
    try:
        for move in moves:
            source = root / move.source_name
            destination = (
                archive_root / _CATEGORY_DIRECTORIES[move.category] / move.source_name
            )
            source_exists = source.exists() and source.is_file() and not source.is_symlink()
            destination_exists = (
                destination.exists()
                and destination.is_file()
                and not destination.is_symlink()
            )
            if source_exists == destination_exists:
                return False
            states.append((source, destination, destination_exists))
        for source, destination, was_moved in reversed(states):
            if was_moved:
                os.rename(destination, source)
        for directory in _CATEGORY_DIRECTORIES.values():
            path = archive_root / directory
            if path.exists() and path.is_dir() and not any(path.iterdir()):
                path.rmdir()
        if archive_root.exists() and archive_root.is_dir() and not any(archive_root.iterdir()):
            archive_root.rmdir()
        return True
    except OSError:
        return False


def _organization_state_is_complete(
    root: Path, moves: tuple[OrganizerMove, ...]
) -> bool:
    archive_root = root / _ARCHIVE_ROOT_NAME
    try:
        for move in moves:
            source = root / move.source_name
            destination = (
                archive_root / _CATEGORY_DIRECTORIES[move.category] / move.source_name
            )
            if source.exists() or source.is_symlink():
                return False
            if (
                not destination.exists()
                or not destination.is_file()
                or destination.is_symlink()
                or is_reparse_point(destination)
            ):
                return False
        return True
    except OSError:
        return False


def _ensure_safe_directory(path: Path) -> None:
    if path.exists():
        if path.is_symlink() or not path.is_dir() or is_reparse_point(path):
            raise PcFileScopeError("organizer_directory_unsafe")
        return
    path.mkdir()
    if path.is_symlink() or is_reparse_point(path):
        raise PcFileScopeError("organizer_directory_unsafe")


def _archive_category(name: str) -> str:
    suffix = Path(name).suffix.casefold()
    if suffix in IMAGE_EXTENSIONS:
        return "images"
    if suffix in DOCUMENT_EXTENSIONS:
        return "documents"
    if suffix in MEDIA_EXTENSIONS:
        return "media"
    if suffix in ARCHIVE_EXTENSIONS:
        return "archives"
    return "other"


def _validate_root(path_text: str) -> Path:
    if (
        not isinstance(path_text, str)
        or not path_text
        or len(path_text) > MAX_SCOPE_PATH_CHARS
        or any(ord(char) < 32 for char in path_text)
        or path_text.startswith(("\\\\", "//"))
    ):
        raise PcFileScopeError("file_scope_invalid")
    candidate = Path(path_text)
    if not candidate.is_absolute():
        raise PcFileScopeError("file_scope_invalid")
    try:
        if candidate.is_symlink() or (
            hasattr(os.path, "isjunction") and os.path.isjunction(candidate)
        ):
            raise PcFileScopeError("file_scope_invalid")
        _reject_reparse_ancestors(candidate)
        resolved = candidate.resolve(strict=True)
        if not resolved.is_dir() or resolved.is_symlink():
            raise PcFileScopeError("file_scope_invalid")
        _reject_reparse_ancestors(resolved)
        if hasattr(os.path, "isjunction") and os.path.isjunction(resolved):
            raise PcFileScopeError("file_scope_invalid")
        if resolved == Path(resolved.anchor):
            raise PcFileScopeError("file_scope_invalid")
        if os.name == "nt" and not _is_fixed_windows_drive(resolved):
            raise PcFileScopeError("file_scope_invalid")
    except PcFileScopeError:
        raise
    except OSError:
        raise PcFileScopeError("file_scope_invalid") from None
    return resolved


def _reject_reparse_ancestors(path: Path) -> None:
    current = path
    while True:
        if is_reparse_point(current):
            raise PcFileScopeError("file_scope_invalid")
        parent = current.parent
        if parent == current:
            return
        current = parent


def _path_identity(path: Path) -> str:
    try:
        stat = path.stat(follow_symlinks=False)
        canonical = f"{int(stat.st_dev)}:{int(stat.st_ino)}".encode("ascii")
    except (OSError, ValueError):
        raise PcFileScopeError("file_scope_unavailable") from None
    return hashlib.sha256(canonical).hexdigest()


def _catalog_item(root_id: str, item: _ScannedFile) -> CatalogItemInput:
    extension = Path(item.name).suffix.casefold().removeprefix(".")
    if not re.fullmatch(r"[a-z0-9]{0,16}", extension):
        extension = ""
    suffix = f".{extension}" if extension else ""
    if suffix in IMAGE_EXTENSIONS:
        family = "image"
    elif suffix in MEDIA_EXTENSIONS:
        family = "audio" if suffix in {".aac", ".flac", ".m4a", ".mp3", ".wav"} else "video"
    elif suffix in ARCHIVE_EXTENSIONS:
        family = "archive"
    elif suffix in {".md", ".txt", ".csv"}:
        family = "text"
    elif suffix in DOCUMENT_EXTENSIONS:
        family = "document"
    else:
        family = "other"
    locator = hashlib.sha256(f"{root_id}\0{item.name}".encode("utf-8")).hexdigest()
    revision = hashlib.sha256(
        f"{item.name}\0{item.size}\0{item.modified_ns}".encode("utf-8")
    ).hexdigest()
    return CatalogItemInput(
        locator_token=locator,
        display_name=item.name,
        extension=extension,
        mime_family=family,
        size_bytes=item.size,
        modified_at_ms=item.modified_ns // 1_000_000,
        revision=revision,
        content_eligible=family in {"text", "document"} and item.size <= 5 * 1024 * 1024,
    )


def _scan_direct_files(root: Path) -> tuple[list[_ScannedFile], int]:
    files: list[_ScannedFile] = []
    scanned = 0
    try:
        with os.scandir(root) as entries:
            for entry in entries:
                scanned += 1
                if scanned > MAX_SCAN_ENTRIES:
                    raise PcFileScopeError("file_scope_too_large")
                if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                    continue
                if len(entry.name) > 255 or any(
                    unicodedata.category(char).startswith("C") for char in entry.name
                ):
                    continue
                stat = entry.stat(follow_symlinks=False)
                attributes = getattr(stat, "st_file_attributes", 0)
                reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                if attributes & reparse:
                    continue
                files.append(
                    _ScannedFile(
                        name=entry.name,
                        size=stat.st_size,
                        modified_ns=stat.st_mtime_ns,
                    )
                )
    except PcFileScopeError:
        raise
    except OSError:
        raise PcFileScopeError("file_scope_unavailable") from None
    files.sort(key=lambda item: (item.name.casefold(), item.name))
    return files, scanned


def _is_fixed_windows_drive(path: Path) -> bool:
    try:
        import ctypes

        drive_type = ctypes.windll.kernel32.GetDriveTypeW(str(path.anchor))
    except (AttributeError, OSError):
        return False
    return drive_type == 3


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
