"""Durable, confirmation-bound Markdown export with unchanged-only undo."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
import threading
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .knowledge_pack import (
    KnowledgeContextBuilder,
    KnowledgePack,
    KnowledgePackError,
    render_knowledge_markdown,
)
from .pc_file_scope import (
    MARKDOWN_EXPORT_DIRECTORY,
    PcFileScopeError,
    PcFileScopeService,
)

ARTIFACT_EXPORT_SCHEMA = "data-steward.artifact-export/v1"
ARTIFACT_EXPORT_SCHEMA_VERSION = 1
_EXPORT_STATES = frozenset({"PREPARED", "COMPLETED", "UNDOING", "UNDONE"})
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_PACK_ID_RE = re.compile(r"^kp-[0-9a-f]{16}$")
_EXPORT_ID_RE = re.compile(r"^artifact-[0-9a-f]{16}$")
_IDEMPOTENCY_RE = re.compile(r"^export-[0-9a-f]{32}$")


class ArtifactExportError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class StudyPackCoordinator(Protocol):
    def generate(self, user_text: str) -> object: ...


@dataclass(frozen=True, slots=True)
class ArtifactExportPreview:
    pack: KnowledgePack
    target_display_name: str
    output_directory: str
    filename: str
    byte_count: int
    content_sha256: str
    preview_sha256: str

    def wire(self) -> dict[str, Any]:
        return {
            "schema_version": ARTIFACT_EXPORT_SCHEMA,
            "pack": self.pack.wire(),
            "target_display_name": self.target_display_name,
            "output_directory": self.output_directory,
            "filename": self.filename,
            "byte_count": self.byte_count,
            "preview_sha256": self.preview_sha256,
            "requires_confirmation": True,
        }


@dataclass(frozen=True, slots=True)
class ArtifactExportReceipt:
    export_id: str
    pack_id: str
    state: str
    filename: str
    byte_count: int
    undo_token: str | None
    deduplicated: bool

    def wire(self) -> dict[str, Any]:
        return {
            "schema_version": ARTIFACT_EXPORT_SCHEMA,
            "export_id": self.export_id,
            "pack_id": self.pack_id,
            "state": self.state,
            "filename": self.filename,
            "byte_count": self.byte_count,
            "undo_token": self.undo_token,
            "deduplicated": self.deduplicated,
        }


@dataclass(frozen=True, slots=True)
class ArtifactExportStatus:
    state: str
    export_id: str | None
    pack_id: str | None
    filename: str | None
    byte_count: int
    can_undo: bool
    undo_token: str | None

    def wire(self) -> dict[str, Any]:
        return {
            "schema_version": ARTIFACT_EXPORT_SCHEMA,
            "state": self.state,
            "export_id": self.export_id,
            "pack_id": self.pack_id,
            "filename": self.filename,
            "byte_count": self.byte_count,
            "can_undo": self.can_undo,
            "undo_token": self.undo_token,
        }


@dataclass(frozen=True, slots=True)
class _ExportRecord:
    export_id: str
    idempotency_key: str
    pack_id: str
    kind: str
    root_id: str
    preview_sha256: str
    filename: str
    byte_count: int
    content_sha256: str
    state: str


class ArtifactExportStore:
    def __init__(self, database_path: str | Path) -> None:
        self._path = str(database_path)
        self._lock = threading.RLock()
        self._closed = False
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        if self._closed:
            raise ArtifactExportError("artifact_store_closed")
        try:
            connection = sqlite3.connect(self._path, timeout=5.0)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute("PRAGMA journal_mode = WAL")
            return connection
        except sqlite3.Error:
            raise ArtifactExportError("artifact_persistence_failed") from None

    def _initialize(self) -> None:
        with self._lock:
            connection = self._connect()
            try:
                tables = {
                    str(row[0])
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' "
                        "AND name LIKE 'artifact_export%'"
                    )
                }
                if "artifact_export_schema_meta" in tables:
                    rows = connection.execute(
                        "SELECT component, schema_version "
                        "FROM artifact_export_schema_meta"
                    ).fetchall()
                    if len(rows) != 1 or tuple(rows[0]) != (
                        "artifact_export",
                        ARTIFACT_EXPORT_SCHEMA_VERSION,
                    ):
                        raise ArtifactExportError("artifact_schema_unsupported")
                elif tables:
                    raise ArtifactExportError("artifact_schema_unsupported")
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS artifact_export_schema_meta(
                        component TEXT PRIMARY KEY,
                        schema_version INTEGER NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS artifact_export_journal(
                        export_id TEXT PRIMARY KEY,
                        idempotency_key TEXT NOT NULL UNIQUE,
                        pack_id TEXT NOT NULL,
                        kind TEXT NOT NULL,
                        root_id TEXT NOT NULL,
                        preview_sha256 TEXT NOT NULL,
                        filename TEXT NOT NULL,
                        byte_count INTEGER NOT NULL,
                        content_sha256 TEXT NOT NULL,
                        state TEXT NOT NULL,
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    """
                )
                connection.execute(
                    "INSERT OR IGNORE INTO artifact_export_schema_meta "
                    "VALUES('artifact_export', ?)",
                    (ARTIFACT_EXPORT_SCHEMA_VERSION,),
                )
                connection.commit()
            except ArtifactExportError:
                raise
            except sqlite3.Error:
                raise ArtifactExportError("artifact_persistence_failed") from None
            finally:
                connection.close()

    def prepare(self, record: _ExportRecord) -> tuple[_ExportRecord, bool]:
        _validate_record(record)
        with self._lock:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    "SELECT * FROM artifact_export_journal WHERE idempotency_key=?",
                    (record.idempotency_key,),
                ).fetchone()
                if existing is not None:
                    value = _record_from_row(existing)
                    if value != record:
                        comparable = (
                            value.export_id,
                            value.idempotency_key,
                            value.pack_id,
                            value.kind,
                            value.root_id,
                            value.preview_sha256,
                            value.filename,
                            value.byte_count,
                            value.content_sha256,
                        )
                        expected = (
                            record.export_id,
                            record.idempotency_key,
                            record.pack_id,
                            record.kind,
                            record.root_id,
                            record.preview_sha256,
                            record.filename,
                            record.byte_count,
                            record.content_sha256,
                        )
                        if comparable != expected:
                            raise ArtifactExportError("artifact_idempotency_conflict")
                    connection.commit()
                    return value, True
                connection.execute(
                    """
                    INSERT INTO artifact_export_journal(
                        export_id,idempotency_key,pack_id,kind,root_id,
                        preview_sha256,filename,byte_count,content_sha256,state
                    ) VALUES(?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        record.export_id,
                        record.idempotency_key,
                        record.pack_id,
                        record.kind,
                        record.root_id,
                        record.preview_sha256,
                        record.filename,
                        record.byte_count,
                        record.content_sha256,
                        record.state,
                    ),
                )
                connection.commit()
                return record, False
            except ArtifactExportError:
                connection.rollback()
                raise
            except sqlite3.Error:
                connection.rollback()
                raise ArtifactExportError("artifact_persistence_failed") from None
            finally:
                connection.close()

    def transition(self, export_id: str, *, expected: str, target: str) -> _ExportRecord:
        if (
            not _EXPORT_ID_RE.fullmatch(export_id)
            or expected not in _EXPORT_STATES
            or target not in _EXPORT_STATES
        ):
            raise ArtifactExportError("artifact_state_invalid")
        with self._lock:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                changed = connection.execute(
                    "UPDATE artifact_export_journal SET state=?, "
                    "updated_at=CURRENT_TIMESTAMP WHERE export_id=? AND state=?",
                    (target, export_id, expected),
                ).rowcount
                row = connection.execute(
                    "SELECT * FROM artifact_export_journal WHERE export_id=?",
                    (export_id,),
                ).fetchone()
                if changed != 1 or row is None:
                    raise ArtifactExportError("artifact_state_conflict")
                connection.commit()
                return _record_from_row(row)
            except ArtifactExportError:
                connection.rollback()
                raise
            except sqlite3.Error:
                connection.rollback()
                raise ArtifactExportError("artifact_persistence_failed") from None
            finally:
                connection.close()

    def by_export_id(self, export_id: str) -> _ExportRecord | None:
        if not _EXPORT_ID_RE.fullmatch(export_id):
            raise ArtifactExportError("artifact_undo_invalid")
        return self._one("export_id", export_id)

    def latest(self) -> _ExportRecord | None:
        with self._lock:
            connection = self._connect()
            try:
                row = connection.execute(
                    "SELECT * FROM artifact_export_journal "
                    "ORDER BY rowid DESC LIMIT 1"
                ).fetchone()
                return None if row is None else _record_from_row(row)
            except sqlite3.Error:
                raise ArtifactExportError("artifact_persistence_failed") from None
            finally:
                connection.close()

    def _one(self, field: str, value: str) -> _ExportRecord | None:
        if field not in {"export_id", "idempotency_key"}:
            raise AssertionError("unsafe field")
        with self._lock:
            connection = self._connect()
            try:
                row = connection.execute(
                    f"SELECT * FROM artifact_export_journal WHERE {field}=?",
                    (value,),
                ).fetchone()
                return None if row is None else _record_from_row(row)
            except sqlite3.Error:
                raise ArtifactExportError("artifact_persistence_failed") from None
            finally:
                connection.close()

    def close(self) -> None:
        with self._lock:
            self._closed = True


class ArtifactExportService:
    def __init__(
        self,
        *,
        store: ArtifactExportStore,
        file_scope: PcFileScopeService,
    ) -> None:
        self._store = store
        self._file_scope = file_scope
        self._lock = threading.RLock()

    def preview(self, pack: KnowledgePack) -> ArtifactExportPreview:
        scope = self._file_scope.status()
        if not scope.configured or scope.root_id is None or scope.display_name is None:
            raise ArtifactExportError("artifact_scope_unconfigured")
        content = render_knowledge_markdown(pack)
        filename = _export_filename(pack)
        digest = hashlib.sha256(content).hexdigest()
        evidence = hashlib.sha256(
            _canonical_json(
                {
                    "byte_count": len(content),
                    "content_sha256": digest,
                    "filename": filename,
                    "pack_id": pack.pack_id,
                    "root_id": scope.root_id,
                    "snapshot_sha256": pack.snapshot_sha256,
                }
            )
        ).hexdigest()
        return ArtifactExportPreview(
            pack=pack,
            target_display_name=scope.display_name,
            output_directory=MARKDOWN_EXPORT_DIRECTORY,
            filename=filename,
            byte_count=len(content),
            content_sha256=digest,
            preview_sha256=evidence,
        )

    def execute(
        self,
        *,
        pack: KnowledgePack,
        preview_sha256: str,
        idempotency_key: str,
    ) -> ArtifactExportReceipt:
        if not _IDEMPOTENCY_RE.fullmatch(idempotency_key):
            raise ArtifactExportError("artifact_request_invalid")
        with self._lock:
            preview = self.preview(pack)
            if preview.preview_sha256 != preview_sha256:
                raise ArtifactExportError("artifact_preview_stale")
            scope = self._file_scope.status()
            assert scope.root_id is not None
            export_id = "artifact-" + hashlib.sha256(
                idempotency_key.encode("ascii")
            ).hexdigest()[:16]
            candidate = _ExportRecord(
                export_id=export_id,
                idempotency_key=idempotency_key,
                pack_id=pack.pack_id,
                kind=pack.kind,
                root_id=scope.root_id,
                preview_sha256=preview.preview_sha256,
                filename=preview.filename,
                byte_count=preview.byte_count,
                content_sha256=preview.content_sha256,
                state="PREPARED",
            )
            record, existed = self._store.prepare(candidate)
            if record.state == "UNDONE":
                raise ArtifactExportError("artifact_already_undone")
            if record.state == "UNDOING":
                raise ArtifactExportError("artifact_recovery_required")
            inspection = self._inspect(record)
            if record.state == "COMPLETED":
                if inspection != "exact":
                    raise ArtifactExportError("artifact_recovery_required")
                return _receipt(record, deduplicated=True)
            if inspection == "changed":
                raise ArtifactExportError("artifact_recovery_required")
            if inspection == "missing":
                content = render_knowledge_markdown(pack)
                try:
                    self._file_scope.write_markdown_export(
                        expected_root_id=record.root_id,
                        filename=record.filename,
                        content=content,
                    )
                except PcFileScopeError as exc:
                    raise ArtifactExportError(exc.code) from None
            record = self._store.transition(
                record.export_id, expected="PREPARED", target="COMPLETED"
            )
            return _receipt(record, deduplicated=existed)

    def status(self) -> ArtifactExportStatus:
        with self._lock:
            record = self._store.latest()
            if record is None:
                return _empty_status()
            inspection = self._inspect(record)
            if record.state == "PREPARED" and inspection == "exact":
                record = self._store.transition(
                    record.export_id, expected="PREPARED", target="COMPLETED"
                )
            elif record.state == "UNDOING" and inspection == "missing":
                record = self._store.transition(
                    record.export_id, expected="UNDOING", target="UNDONE"
                )
            if record.state == "UNDONE":
                return ArtifactExportStatus(
                    "undone",
                    record.export_id,
                    record.pack_id,
                    record.filename,
                    record.byte_count,
                    False,
                    None,
                )
            if record.state == "COMPLETED" and inspection == "exact":
                return ArtifactExportStatus(
                    "undo_available",
                    record.export_id,
                    record.pack_id,
                    record.filename,
                    record.byte_count,
                    True,
                    record.export_id,
                )
            if record.state == "UNDOING" and inspection == "exact":
                return ArtifactExportStatus(
                    "undo_pending",
                    record.export_id,
                    record.pack_id,
                    record.filename,
                    record.byte_count,
                    True,
                    record.export_id,
                )
            return ArtifactExportStatus(
                "recovery_required",
                record.export_id,
                record.pack_id,
                record.filename,
                record.byte_count,
                False,
                None,
            )

    def undo(self, *, undo_token: str) -> ArtifactExportReceipt:
        with self._lock:
            record = self._store.by_export_id(undo_token)
            if record is None:
                raise ArtifactExportError("artifact_undo_unavailable")
            inspection = self._inspect(record)
            if record.state == "UNDONE":
                return _receipt(record, deduplicated=True)
            if record.state not in {"COMPLETED", "UNDOING"}:
                raise ArtifactExportError("artifact_undo_unavailable")
            if record.state == "UNDOING" and inspection == "missing":
                record = self._store.transition(
                    record.export_id, expected="UNDOING", target="UNDONE"
                )
                return _receipt(record, deduplicated=True)
            if inspection != "exact":
                raise ArtifactExportError("artifact_modified")
            if record.state == "COMPLETED":
                record = self._store.transition(
                    record.export_id, expected="COMPLETED", target="UNDOING"
                )
            try:
                self._file_scope.delete_markdown_export_unchanged(
                    expected_root_id=record.root_id,
                    filename=record.filename,
                    expected_byte_count=record.byte_count,
                    expected_content_sha256=record.content_sha256,
                )
            except PcFileScopeError as exc:
                raise ArtifactExportError(exc.code) from None
            record = self._store.transition(
                record.export_id, expected="UNDOING", target="UNDONE"
            )
            return _receipt(record, deduplicated=False)

    def _inspect(self, record: _ExportRecord) -> str:
        try:
            value = self._file_scope.inspect_markdown_export(
                expected_root_id=record.root_id,
                filename=record.filename,
                expected_byte_count=record.byte_count,
                expected_content_sha256=record.content_sha256,
            )
            return value.state
        except PcFileScopeError as exc:
            if exc.code == "artifact_scope_changed":
                return "changed"
            raise ArtifactExportError(exc.code) from None


class KnowledgeArtifactCoordinator:
    def __init__(
        self,
        *,
        content_coordinator: StudyPackCoordinator,
        builder: KnowledgeContextBuilder,
        export: ArtifactExportService,
    ) -> None:
        self._content = content_coordinator
        self._builder = builder
        self._export = export

    def prepare(self, *, kind: str, request: str) -> ArtifactExportPreview:
        self._content.generate(request)
        return self._export.preview(self._builder.build(kind))

    def execute(
        self,
        *,
        kind: str,
        pack_id: str,
        preview_sha256: str,
        idempotency_key: str,
    ) -> ArtifactExportReceipt:
        pack = self._builder.build(kind)
        if pack.pack_id != pack_id:
            raise ArtifactExportError("artifact_preview_stale")
        return self._export.execute(
            pack=pack,
            preview_sha256=preview_sha256,
            idempotency_key=idempotency_key,
        )

    def status(self) -> ArtifactExportStatus:
        return self._export.status()

    def undo(self, *, undo_token: str) -> ArtifactExportReceipt:
        return self._export.undo(undo_token=undo_token)


def _export_filename(pack: KnowledgePack) -> str:
    safe = []
    for char in pack.title:
        if char in '<>:"/\\|?*' or unicodedata.category(char).startswith("C"):
            safe.append("-")
        elif char.isspace():
            safe.append("-")
        else:
            safe.append(char)
    stem = re.sub(r"-+", "-", "".join(safe)).strip(" .-")[:64]
    if not stem:
        stem = "Data-Steward-资料包"
    date = pack.created_at[:10] if re.fullmatch(r"\d{4}-\d{2}-\d{2}.*", pack.created_at) else "资料"
    return f"{date}-{stem}-{pack.pack_id[-8:]}.md"


def _validate_record(record: _ExportRecord) -> None:
    if (
        not _EXPORT_ID_RE.fullmatch(record.export_id)
        or not _IDEMPOTENCY_RE.fullmatch(record.idempotency_key)
        or not _PACK_ID_RE.fullmatch(record.pack_id)
        or record.kind not in {"learning", "meeting", "project", "general"}
        or re.fullmatch(r"^pc-[0-9a-f]{12}$", record.root_id) is None
        or not _DIGEST_RE.fullmatch(record.preview_sha256)
        or not _DIGEST_RE.fullmatch(record.content_sha256)
        or not 1 <= record.byte_count <= 128 * 1024
        or not record.filename.casefold().endswith(".md")
        or len(record.filename) > 120
        or record.state not in _EXPORT_STATES
    ):
        raise ArtifactExportError("artifact_record_invalid")


def _record_from_row(row: sqlite3.Row) -> _ExportRecord:
    record = _ExportRecord(
        export_id=str(row["export_id"]),
        idempotency_key=str(row["idempotency_key"]),
        pack_id=str(row["pack_id"]),
        kind=str(row["kind"]),
        root_id=str(row["root_id"]),
        preview_sha256=str(row["preview_sha256"]),
        filename=str(row["filename"]),
        byte_count=int(row["byte_count"]),
        content_sha256=str(row["content_sha256"]),
        state=str(row["state"]),
    )
    _validate_record(record)
    return record


def _receipt(record: _ExportRecord, *, deduplicated: bool) -> ArtifactExportReceipt:
    return ArtifactExportReceipt(
        export_id=record.export_id,
        pack_id=record.pack_id,
        state="undone" if record.state == "UNDONE" else "completed",
        filename=record.filename,
        byte_count=record.byte_count,
        undo_token=None if record.state == "UNDONE" else record.export_id,
        deduplicated=deduplicated,
    )


def _empty_status() -> ArtifactExportStatus:
    return ArtifactExportStatus("idle", None, None, None, 0, False, None)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
