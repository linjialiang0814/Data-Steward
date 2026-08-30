"""Opaque product actions projected from auditable archive-memory receipts."""

from __future__ import annotations

import secrets
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .archive_memory import (
    ArchiveIntent,
    ArchiveMemoryService,
    ArchiveMemoryView,
    ArchiveReceipt,
)
from .pc_file_scope import PcFileOrganizationReceipt, PcFileScopeService


class ActionProjectionError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ProductAction:
    action_id: str
    assistant_message_id: str
    kind: str
    label: str
    description: str
    risk: str
    requires_confirmation: bool
    required_capability: str
    status: str


_ACTION_PRESENTATION = {
    "archive_accept": ("接受建议", "记录这次选择，不会移动文件", "preference", False),
    "archive_reject": ("暂不采用", "关闭本次建议，不形成习惯", "none", False),
    "memory_approve": ("启用这个习惯", "以后可主动引用这项整理偏好", "memory", True),
    "memory_forget": ("停用这个习惯", "停止在后续会话中使用，可随时重新启用", "memory", True),
    "organize_execute": ("确认整理", "按预览移动直接子文件，可撤销", "file_move", True),
    "organize_undo": ("撤销整理", "将上次整理的文件移回授权目录", "file_move", True),
}

ActionProjectionSpec = tuple[str, str, str | None, str | None]
PreparedActionProjection = tuple[ActionProjectionSpec, ...]


class ActionProjectionService:
    def __init__(self, database_path: str | Path) -> None:
        self._database_path = str(database_path)
        if not self._database_path or self._database_path == ":memory:":
            raise ActionProjectionError("action_database_invalid")
        self._lock = threading.RLock()
        self._closed = False
        self._initialize()

    def close(self) -> None:
        with self._lock:
            self._closed = True

    def register_receipt(
        self,
        *,
        conversation_id: str,
        assistant_message_id: str,
        receipt: ArchiveReceipt | PcFileOrganizationReceipt,
    ) -> tuple[ProductAction, ...]:
        specs = self.prepare_receipt_projection(receipt)
        with self._lock:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                _insert_specs(
                    connection,
                    conversation_id=conversation_id,
                    assistant_message_id=assistant_message_id,
                    specs=specs,
                )
                connection.commit()
            except sqlite3.Error:
                connection.rollback()
                raise ActionProjectionError("action_persistence_failed") from None
            finally:
                connection.close()
        return self.list_for_message(
            conversation_id=conversation_id,
            assistant_message_id=assistant_message_id,
        )

    def prepare_receipt_projection(
        self,
        receipt: ArchiveReceipt | PcFileOrganizationReceipt,
    ) -> PreparedActionProjection:
        """Validate service lifecycle and freeze receipt-derived action specs."""
        with self._lock:
            if self._closed:
                raise ActionProjectionError("action_service_closed")
            return tuple(_receipt_specs(receipt))

    def register_prepared_in_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        conversation_id: str,
        assistant_message_id: str,
        projection: PreparedActionProjection,
    ) -> None:
        """Write prepared specs without acquiring locks inside caller's transaction.

        Hub lifecycle drains derived tasks before closing this service. The
        lock-protected preparation step is therefore the lifecycle gate; this
        commit step must not reverse the global Action-lock -> SQLite order.
        """
        if self._closed:
            raise ActionProjectionError("action_service_closed")
        try:
            _insert_specs(
                connection,
                conversation_id=conversation_id,
                assistant_message_id=assistant_message_id,
                specs=projection,
            )
        except sqlite3.Error:
            raise ActionProjectionError("action_persistence_failed") from None

    def list_for_message(
        self, *, conversation_id: str, assistant_message_id: str
    ) -> tuple[ProductAction, ...]:
        connection = self._connect()
        try:
            rows = connection.execute(
                """
                SELECT * FROM product_action
                WHERE conversation_id=? AND assistant_message_id=?
                ORDER BY created_at, action_id
                """,
                (conversation_id, assistant_message_id),
            ).fetchall()
            return tuple(_public_action(row) for row in rows)
        except sqlite3.Error:
            raise ActionProjectionError("action_persistence_failed") from None
        finally:
            connection.close()

    def register_memory_view(
        self, *, conversation_id: str, view: ArchiveMemoryView
    ) -> tuple[str, tuple[ProductAction, ...]]:
        message_id = f"memory-center-v{view.version or 0}"
        if view.memory_id is None or view.status not in {"candidate", "active", "forgotten"}:
            return message_id, self.list_for_message(
                conversation_id=conversation_id,
                assistant_message_id=message_id,
            )
        kind = (
            "memory_approve"
            if view.status in {"candidate", "forgotten"}
            else "memory_forget"
        )
        with self._lock:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                if connection.execute(
                    """
                    SELECT 1 FROM product_action
                    WHERE conversation_id=? AND assistant_message_id=? AND kind=?
                    """,
                    (conversation_id, message_id, kind),
                ).fetchone() is None:
                    connection.execute(
                        """
                        INSERT INTO product_action(
                            action_id, conversation_id, assistant_message_id,
                            kind, reference_id, expected_root_id,
                            evidence_sha256, status, created_at
                        ) VALUES (?, ?, ?, ?, ?, NULL, NULL, 'available', ?)
                        """,
                        (
                            "act-" + secrets.token_hex(8),
                            conversation_id,
                            message_id,
                            kind,
                            view.memory_id,
                            _utc_now(),
                        ),
                    )
                connection.commit()
            except sqlite3.Error:
                connection.rollback()
                raise ActionProjectionError("action_persistence_failed") from None
            finally:
                connection.close()
        return message_id, self.list_for_message(
            conversation_id=conversation_id,
            assistant_message_id=message_id,
        )

    def execute_action(
        self,
        *,
        conversation_id: str,
        assistant_message_id: str,
        action_id: str,
        archive_memory: ArchiveMemoryService,
        file_scope: PcFileScopeService,
        source_message_ref: str,
    ) -> ArchiveReceipt | PcFileOrganizationReceipt:
        with self._lock:
            connection = self._connect()
            try:
                row = connection.execute(
                    """
                    SELECT * FROM product_action
                    WHERE action_id=? AND conversation_id=? AND assistant_message_id=?
                    """,
                    (action_id, conversation_id, assistant_message_id),
                ).fetchone()
            finally:
                connection.close()
            if row is None:
                raise ActionProjectionError("action_not_found")
            kind = str(row["kind"])
            operation = {
                "archive_accept": "accept",
                "archive_reject": "reject",
                "memory_approve": "approve",
                "memory_forget": "forget",
            }.get(kind)
            if operation is not None:
                receipt: ArchiveReceipt | PcFileOrganizationReceipt = archive_memory.execute(
                    ArchiveIntent(operation, str(row["reference_id"])),
                    source_message_ref=source_message_ref,
                    allow_explicit_relearn=kind == "archive_accept",
                )
            elif kind == "organize_execute":
                root_id = row["expected_root_id"]
                evidence = row["evidence_sha256"]
                if not isinstance(root_id, str) or not isinstance(evidence, str):
                    raise ActionProjectionError("action_record_invalid")
                receipt = file_scope.organize(
                    expected_root_id=root_id,
                    expected_evidence_sha256=evidence,
                )
            elif kind == "organize_undo":
                receipt = file_scope.undo_organization(str(row["reference_id"]))
            else:
                raise ActionProjectionError("action_not_supported")
            return receipt

    def mark_completed(self, action_id: str) -> None:
        """Mark an action complete only after its result event is durable.

        Executing the underlying archive/organize operation is deliberately
        separate from this transition. If the process exits after the operation
        but before the result event is appended, the action remains available;
        its stable source reference and result client-message ID make a retry
        converge without repeating a physical mutation.
        """
        with self._lock:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                cursor = connection.execute(
                    """
                    UPDATE product_action
                    SET status='completed', completed_at=COALESCE(completed_at, ?)
                    WHERE action_id=?
                    """,
                    (_utc_now(), action_id),
                )
                if cursor.rowcount != 1:
                    connection.rollback()
                    raise ActionProjectionError("action_not_found")
                connection.commit()
            except ActionProjectionError:
                raise
            except sqlite3.Error:
                connection.rollback()
                raise ActionProjectionError("action_persistence_failed") from None
            finally:
                connection.close()

    def _initialize(self) -> None:
        connection = self._connect(allow_closed=True)
        try:
            connection.executescript(_SCHEMA)
            row = connection.execute(
                "SELECT schema_version FROM action_projection_meta WHERE component='product_actions'"
            ).fetchone()
            if row is None or int(row[0]) != 1:
                raise ActionProjectionError("action_schema_unsupported")
            connection.commit()
        except ActionProjectionError:
            raise
        except sqlite3.Error:
            raise ActionProjectionError("action_persistence_failed") from None
        finally:
            connection.close()

    def _connect(self, *, allow_closed: bool = False) -> sqlite3.Connection:
        if self._closed and not allow_closed:
            raise ActionProjectionError("action_service_closed")
        connection = sqlite3.connect(self._database_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection


def _public_action(row: sqlite3.Row) -> ProductAction:
    kind = str(row["kind"])
    presentation = _ACTION_PRESENTATION.get(kind)
    if presentation is None:
        raise ActionProjectionError("action_record_invalid")
    label, description, risk, confirmation = presentation
    return ProductAction(
        action_id=str(row["action_id"]),
        assistant_message_id=str(row["assistant_message_id"]),
        kind=kind,
        label=label,
        description=description,
        risk=risk,
        requires_confirmation=confirmation,
        required_capability=(
            "files.organize" if kind in {"organize_execute", "organize_undo"} else "session.sync"
        ),
        status=str(row["status"]),
    )


def _receipt_specs(
    receipt: ArchiveReceipt | PcFileOrganizationReceipt,
) -> list[tuple[str, str, str | None, str | None]]:
    if (
        isinstance(receipt, ArchiveReceipt)
        and receipt.operation == "suggest"
        and receipt.suggestion_id
    ):
        return [
            ("archive_accept", receipt.suggestion_id, None, None),
            ("archive_reject", receipt.suggestion_id, None, None),
            (
                "organize_execute",
                receipt.suggestion_id,
                receipt.root_id,
                receipt.evidence_sha256,
            ),
        ]
    if (
        isinstance(receipt, ArchiveReceipt)
        and receipt.operation == "accept"
        and receipt.memory_status == "candidate"
        and receipt.memory_id
    ):
        return [("memory_approve", receipt.memory_id, None, None)]
    if (
        isinstance(receipt, ArchiveReceipt)
        and receipt.operation == "approve"
        and receipt.memory_id
    ):
        return [("memory_forget", receipt.memory_id, None, None)]
    if (
        isinstance(receipt, ArchiveReceipt)
        and receipt.operation == "forget"
        and receipt.memory_id
    ):
        return [("memory_approve", receipt.memory_id, None, None)]
    if (
        isinstance(receipt, ArchiveReceipt)
        and receipt.operation == "recall"
        and receipt.memory_id
    ):
        return [
            (
                "organize_execute",
                receipt.memory_id,
                receipt.root_id,
                receipt.evidence_sha256,
            )
        ]
    if (
        isinstance(receipt, PcFileOrganizationReceipt)
        and receipt.operation == "organize"
    ):
        return [("organize_undo", receipt.journal_id, None, None)]
    return []


def _insert_specs(
    connection: sqlite3.Connection,
    *,
    conversation_id: str,
    assistant_message_id: str,
    specs: tuple[ActionProjectionSpec, ...] | list[ActionProjectionSpec],
) -> None:
    for kind, reference_id, expected_root_id, evidence_sha256 in specs:
        if connection.execute(
            """
            SELECT 1 FROM product_action
            WHERE conversation_id=? AND assistant_message_id=? AND kind=?
            """,
            (conversation_id, assistant_message_id, kind),
        ).fetchone() is None:
            connection.execute(
                """
                INSERT INTO product_action(
                    action_id, conversation_id, assistant_message_id,
                    kind, reference_id, expected_root_id,
                    evidence_sha256, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'available', ?)
                """,
                (
                    "act-" + secrets.token_hex(8),
                    conversation_id,
                    assistant_message_id,
                    kind,
                    reference_id,
                    expected_root_id,
                    evidence_sha256,
                    _utc_now(),
                ),
            )


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


_SCHEMA = """
CREATE TABLE IF NOT EXISTS action_projection_meta(
    component TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL
);
INSERT OR IGNORE INTO action_projection_meta(component, schema_version)
VALUES ('product_actions', 1);
CREATE TABLE IF NOT EXISTS product_action(
    action_id TEXT PRIMARY KEY CHECK(
        length(action_id)=20 AND substr(action_id,1,4)='act-'
        AND substr(action_id,5) NOT GLOB '*[^0-9a-f]*'
    ),
    conversation_id TEXT NOT NULL,
    assistant_message_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN (
        'archive_accept','archive_reject','memory_approve','memory_forget',
        'organize_execute','organize_undo'
    )),
    reference_id TEXT NOT NULL,
    expected_root_id TEXT,
    evidence_sha256 TEXT,
    status TEXT NOT NULL CHECK(status IN ('available','completed')),
    created_at TEXT NOT NULL,
    completed_at TEXT,
    UNIQUE(conversation_id, assistant_message_id, kind)
);
"""
