"""Auditable archive suggestions and explicitly approved preference memory."""

from __future__ import annotations

import json
import re
import secrets
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .pc_file_scope import PcFileInventory, PcFileScopeError, PcFileScopeService

SCHEMA_VERSION = 1
MEMORY_ACTIVATION_THRESHOLD = 3
MEMORY_SCOPE = "pc-authorized-directory"
_ID_RE = r"[0-9a-f]{12}"
_REFERENCE_RE = re.compile(rf"^(?P<prefix>sg|mem)-(?P<value>{_ID_RE})$")
_SUGGEST_REQUEST_RE = re.compile(
    r"^(?:请)?(?:再次|重新)?(?:给出|生成|提供)(?:一下)?"
    r"电脑授权目录(?:的)?(?:归档|整理)建议[。！!]?$"
)
_PRODUCT_SUGGEST_REQUESTS = frozenset(
    {
        "根据今天的资料给出归档建议，先不要移动文件。",
    }
)
_PRODUCT_PREFER_MEMORY_REQUEST = (
    "根据今天的资料和我的整理习惯给出归档建议，先不要移动文件。"
)
_PRODUCT_PREFER_MEMORY_RE = re.compile(
    r"^(?:请)?(?:参考|根据|按照|按|结合)(?:一下)?"
    r"(?:我的|我已批准的|已批准的|我已启用的|已启用的)"
    r"(?:整理习惯|整理偏好)[，, ]*(?:帮我)?"
    r"(?:(?:整理|归档)(?:一下)?(?:当前|今天|这些)?"
    r"(?:资料|文件|电脑授权目录)|"
    r"(?:给出|生成)(?:当前|今天|这些)?"
    r"(?:资料|文件|电脑授权目录)?(?:的)?(?:整理|归档)建议)"
    r"(?:[，, ]*先不要移动文件)?[。！!]?$"
)
_ORGANIZE_ACTION_RE = re.compile(r"(?:整理|归档|分类)")
_ORGANIZE_TARGET_RE = re.compile(
    r"(?:资料|文件|目录|课件|笔记|图片|文档|学习材料|工作材料)"
)
_ORGANIZE_REQUEST_RE = re.compile(
    r"(?:^\s*(?:请)?(?:帮我|替我)?\s*(?:整理|归档|分类)|"
    r"(?:请|帮我|替我|想|需要|要|希望|建议|如何|怎么|能否|可以).{0,24}"
    r"(?:整理|归档|分类)|"
    r"(?:整理|归档|分类).{0,24}(?:建议|方案|预览|一下|帮我|可以吗|行吗))"
)
_ORGANIZE_NEGATION_RE = re.compile(
    r"(?:(?:不要|不用|不需要|无需|不想|不希望|不愿意|暂不|暂时不|先别|别|停止|取消)"
    r".{0,8}(?:整理|归档|分类)|"
    r"(?:整理|归档|分类).{0,8}"
    r"(?:不要|不用|不需要|无需|不想|不希望|不愿意|暂不|暂时不|先别|别|停止|取消))"
)
_CATEGORY_LABELS = {
    "images": "图片",
    "documents": "文档",
    "media": "音视频",
    "archives": "压缩包",
    "other": "其他",
}


class ArchiveMemoryError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ArchiveIntent:
    operation: str
    reference_id: str | None = None


@dataclass(frozen=True, slots=True)
class ArchiveReceipt:
    operation: str
    suggestion_id: str | None
    memory_id: str | None
    memory_status: str | None
    support_count: int
    memory_version: int | None
    root_id: str | None
    category_counts: dict[str, int]
    evidence_sha256: str | None

    def conversation_text(self) -> str:
        if self.operation in {"suggest", "recall"}:
            counts = "、".join(
                f"{_CATEGORY_LABELS[key]} {self.category_counts.get(key, 0)}"
                for key in _CATEGORY_LABELS
            )
            source = "已参考你批准的整理偏好" if self.operation == "recall" else "本次预览"
            return (
                f"智能归档建议（{source}）：按类型建立分类集合；{counts}。\n"
                "目前只是预览，尚未移动、重命名、修改或删除任何文件。"
                "你可以直接使用消息下方的操作按钮。"
            )
        if self.operation == "accept":
            confidence = min(
                100,
                round(100 * self.support_count / MEMORY_ACTIVATION_THRESHOLD),
            )
            next_step = (
                "候选习惯已形成，可在下方选择是否启用。"
                if self.memory_status == "candidate"
                else f"还需 {MEMORY_ACTIVATION_THRESHOLD - self.support_count} 次独立接受形成候选习惯。"
            )
            return (
                f"已记录这次选择，偏好学习进度 {self.support_count}/"
                f"{MEMORY_ACTIVATION_THRESHOLD}（{confidence}%）。{next_step}"
            )
        if self.operation == "reject":
            return "已关闭本次建议；这次反馈不会形成习惯记忆。"
        if self.operation == "approve":
            return (
                f"整理习惯已启用，依据 {self.support_count} 次明确选择；"
                "下次会话可以主动参考。"
            )
        if self.operation == "forget":
            return "已停用这项整理习惯；后续会话不再使用，可由你重新启用。"
        raise ArchiveMemoryError("archive_receipt_invalid")


@dataclass(frozen=True, slots=True)
class ArchiveMemoryView:
    memory_id: str | None
    status: str
    support_count: int
    version: int | None


def parse_archive_intent(content: str) -> ArchiveIntent | None:
    text = content.strip()
    if not text or len(text) > 256 or any(ord(char) < 32 for char in text):
        return None
    if (
        text == "智能整理电脑授权目录"
        or text in _PRODUCT_SUGGEST_REQUESTS
        or _SUGGEST_REQUEST_RE.fullmatch(text)
    ):
        return ArchiveIntent("suggest_or_recall")
    if (
        text == _PRODUCT_PREFER_MEMORY_REQUEST
        or _PRODUCT_PREFER_MEMORY_RE.fullmatch(text)
    ):
        return ArchiveIntent("suggest_or_recall")
    if text == "按我的习惯整理电脑授权目录":
        return ArchiveIntent("recall")
    commands = {
        "接受归档建议 ": ("accept", "sg"),
        "拒绝归档建议 ": ("reject", "sg"),
        "批准整理习惯 ": ("approve", "mem"),
        "忘记整理习惯 ": ("forget", "mem"),
    }
    for prefix, (operation, expected_kind) in commands.items():
        if text.startswith(prefix):
            reference = text.removeprefix(prefix).strip()
            match = _REFERENCE_RE.fullmatch(reference)
            if match is None or match.group("prefix") != expected_kind:
                return None
            return ArchiveIntent(operation, reference)
    if (
        _ORGANIZE_ACTION_RE.search(text)
        and _ORGANIZE_TARGET_RE.search(text)
        and _ORGANIZE_REQUEST_RE.search(text)
        and not _ORGANIZE_NEGATION_RE.search(text)
    ):
        # Product-level organization requests always consult an active memory
        # first. The resulting receipt remains preview-only and requires the
        # existing Action Card confirmation before any file mutation.
        return ArchiveIntent("suggest_or_recall")
    return None


class ArchiveMemoryService:
    """SQLite-backed memory; physical file mutations are intentionally absent."""

    def __init__(
        self,
        database_path: str | Path,
        file_scope: PcFileScopeService,
        *,
        busy_timeout_ms: int = 5_000,
    ) -> None:
        path_text = str(database_path)
        if not path_text or path_text == ":memory:":
            raise ArchiveMemoryError("archive_database_invalid")
        if (
            isinstance(busy_timeout_ms, bool)
            or not isinstance(busy_timeout_ms, int)
            or not 1 <= busy_timeout_ms <= 60_000
        ):
            raise ArchiveMemoryError("archive_busy_timeout_invalid")
        self._database_path = path_text
        self._file_scope = file_scope
        self._busy_timeout_ms = busy_timeout_ms
        self._state_lock = threading.Lock()
        self._closed = False
        self._initialize()

    def close(self) -> None:
        with self._state_lock:
            self._closed = True

    def execute(
        self,
        intent: ArchiveIntent,
        *,
        source_message_ref: str,
        allow_explicit_relearn: bool = False,
    ) -> ArchiveReceipt:
        if intent.operation == "suggest":
            return self._suggest(source_message_ref, self._file_scope.inventory())
        if intent.operation == "suggest_or_recall":
            inventory = self._file_scope.inventory()
            if self.status().status == "active":
                try:
                    return self._recall(inventory)
                except ArchiveMemoryError as error:
                    if error.code != "archive_memory_not_active":
                        raise
            return self._suggest(source_message_ref, inventory)
        if intent.operation == "recall":
            return self._recall(self._file_scope.inventory())
        if intent.operation == "accept":
            return self._accept(
                intent.reference_id,
                allow_explicit_relearn=allow_explicit_relearn,
            )
        if intent.operation == "reject":
            return self._reject(intent.reference_id)
        if intent.operation == "approve":
            return self._approve(intent.reference_id)
        if intent.operation == "forget":
            return self._forget(intent.reference_id)
        raise ArchiveMemoryError("archive_intent_invalid")

    def status(self) -> ArchiveMemoryView:
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT memory_id, status, support_count, version
                FROM archive_preference_memory
                WHERE root_id = ?
                ORDER BY updated_at DESC LIMIT 1
                """,
                (MEMORY_SCOPE,),
            ).fetchone()
            if row is None:
                return ArchiveMemoryView(None, "none", 0, None)
            return ArchiveMemoryView(
                memory_id=str(row["memory_id"]),
                status=str(row["status"]),
                support_count=int(row["support_count"]),
                version=int(row["version"]),
            )
        except sqlite3.Error:
            raise ArchiveMemoryError("archive_persistence_failed") from None
        finally:
            connection.close()

    def _suggest(self, source_ref: str, inventory: PcFileInventory) -> ArchiveReceipt:
        suggestion_id = f"sg-{secrets.token_hex(6)}"
        now = _utc_now()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM archive_suggestion WHERE source_message_ref = ?",
                (source_ref,),
            ).fetchone()
            if existing is None:
                connection.execute(
                    """
                    INSERT INTO archive_suggestion(
                        suggestion_id, source_message_ref, root_id,
                        inventory_sha256, category_counts_json, status, created_at
                    ) VALUES (?, ?, ?, ?, ?, 'pending', ?)
                    """,
                    (
                        suggestion_id,
                        source_ref,
                        inventory.root_id,
                        inventory.evidence_sha256,
                        _counts_json(inventory.category_counts),
                        now,
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM archive_suggestion WHERE suggestion_id = ?",
                    (suggestion_id,),
                ).fetchone()
            else:
                row = existing
            connection.commit()
            return _suggestion_receipt(row)
        except sqlite3.Error:
            connection.rollback()
            raise ArchiveMemoryError("archive_persistence_failed") from None
        finally:
            connection.close()

    def _accept(
        self,
        suggestion_id: str | None,
        *,
        allow_explicit_relearn: bool,
    ) -> ArchiveReceipt:
        clean_id = _require_id(suggestion_id, "sg")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            suggestion = connection.execute(
                "SELECT * FROM archive_suggestion WHERE suggestion_id = ?",
                (clean_id,),
            ).fetchone()
            if suggestion is None:
                raise ArchiveMemoryError("archive_suggestion_not_found")
            if suggestion["status"] == "rejected":
                raise ArchiveMemoryError("archive_suggestion_closed")
            memory = connection.execute(
                """
                SELECT * FROM archive_preference_memory
                WHERE root_id = ? AND rule_key = 'category-v1'
                """,
                (MEMORY_SCOPE,),
            ).fetchone()
            if memory is None:
                memory_id = f"mem-{secrets.token_hex(6)}"
                connection.execute(
                    """
                    INSERT INTO archive_preference_memory(
                        memory_id, root_id, rule_key, status, support_count,
                        version, created_at, updated_at
                    ) VALUES (?, ?, 'category-v1', 'learning', 0, 1, ?, ?)
                    """,
                    (memory_id, MEMORY_SCOPE, _utc_now(), _utc_now()),
                )
            else:
                memory_id = memory["memory_id"]
                if memory["status"] == "forgotten":
                    if (
                        not allow_explicit_relearn
                        or suggestion["status"] != "pending"
                        or suggestion["created_at"] <= memory["updated_at"]
                    ):
                        raise ArchiveMemoryError("archive_memory_forgotten")
                    connection.execute(
                        "DELETE FROM archive_memory_evidence WHERE memory_id = ?",
                        (memory_id,),
                    )
                    connection.execute(
                        """
                        UPDATE archive_preference_memory
                        SET status='learning', support_count=0, version=version+1,
                            updated_at=?
                        WHERE memory_id=? AND status='forgotten'
                        """,
                        (_utc_now(), memory_id),
                    )
            connection.execute(
                """
                INSERT OR IGNORE INTO archive_memory_evidence(memory_id, suggestion_id)
                VALUES (?, ?)
                """,
                (memory_id, clean_id),
            )
            support_count = connection.execute(
                "SELECT count(*) FROM archive_memory_evidence WHERE memory_id = ?",
                (memory_id,),
            ).fetchone()[0]
            status = (
                "candidate"
                if support_count >= MEMORY_ACTIVATION_THRESHOLD
                else "learning"
            )
            connection.execute(
                """
                UPDATE archive_preference_memory
                SET support_count = ?, status = CASE WHEN status = 'active' THEN status ELSE ? END,
                    updated_at = ?
                WHERE memory_id = ?
                """,
                (support_count, status, _utc_now(), memory_id),
            )
            connection.execute(
                "UPDATE archive_suggestion SET status = 'accepted', decided_at = ? WHERE suggestion_id = ?",
                (_utc_now(), clean_id),
            )
            memory = connection.execute(
                "SELECT * FROM archive_preference_memory WHERE memory_id = ?",
                (memory_id,),
            ).fetchone()
            connection.commit()
            return ArchiveReceipt(
                "accept",
                clean_id,
                memory_id,
                memory["status"],
                memory["support_count"],
                memory["version"],
                suggestion["root_id"],
                json.loads(suggestion["category_counts_json"]),
                suggestion["inventory_sha256"],
            )
        except ArchiveMemoryError:
            connection.rollback()
            raise
        except sqlite3.Error:
            connection.rollback()
            raise ArchiveMemoryError("archive_persistence_failed") from None
        finally:
            connection.close()

    def _reject(self, suggestion_id: str | None) -> ArchiveReceipt:
        clean_id = _require_id(suggestion_id, "sg")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM archive_suggestion WHERE suggestion_id = ?", (clean_id,)
            ).fetchone()
            if row is None:
                raise ArchiveMemoryError("archive_suggestion_not_found")
            if row["status"] == "accepted":
                raise ArchiveMemoryError("archive_suggestion_closed")
            connection.execute(
                "UPDATE archive_suggestion SET status = 'rejected', decided_at = ? WHERE suggestion_id = ?",
                (_utc_now(), clean_id),
            )
            connection.commit()
            return ArchiveReceipt(
                "reject",
                clean_id,
                None,
                None,
                0,
                None,
                row["root_id"],
                {},
                row["inventory_sha256"],
            )
        except ArchiveMemoryError:
            connection.rollback()
            raise
        except sqlite3.Error:
            connection.rollback()
            raise ArchiveMemoryError("archive_persistence_failed") from None
        finally:
            connection.close()

    def _approve(self, memory_id: str | None) -> ArchiveReceipt:
        return self._transition_memory(memory_id, "approve")

    def _forget(self, memory_id: str | None) -> ArchiveReceipt:
        return self._transition_memory(memory_id, "forget")

    def _transition_memory(
        self,
        memory_id: str | None,
        operation: str,
    ) -> ArchiveReceipt:
        clean_id = _require_id(memory_id, "mem")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM archive_preference_memory WHERE memory_id = ?", (clean_id,)
            ).fetchone()
            if row is None:
                raise ArchiveMemoryError("archive_memory_not_found")
            if operation == "approve":
                if row["support_count"] < MEMORY_ACTIVATION_THRESHOLD:
                    raise ArchiveMemoryError("archive_memory_insufficient_evidence")
                new_status = "active"
            else:
                new_status = "forgotten"
            version = (
                row["version"]
                if row["status"] == new_status
                else row["version"] + 1
            )
            connection.execute(
                "UPDATE archive_preference_memory SET status = ?, version = ?, updated_at = ? WHERE memory_id = ?",
                (new_status, version, _utc_now(), clean_id),
            )
            connection.commit()
            return ArchiveReceipt(
                operation,
                None,
                clean_id,
                new_status,
                row["support_count"],
                version,
                row["root_id"],
                {},
                None,
            )
        except ArchiveMemoryError:
            connection.rollback()
            raise
        except sqlite3.Error:
            connection.rollback()
            raise ArchiveMemoryError("archive_persistence_failed") from None
        finally:
            connection.close()

    def _recall(self, inventory: PcFileInventory) -> ArchiveReceipt:
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT * FROM archive_preference_memory
                WHERE root_id = ? AND status = 'active'
                ORDER BY updated_at DESC LIMIT 1
                """,
                (MEMORY_SCOPE,),
            ).fetchone()
            if row is None:
                raise ArchiveMemoryError("archive_memory_not_active")
            return ArchiveReceipt(
                "recall",
                None,
                row["memory_id"],
                row["status"],
                row["support_count"],
                row["version"],
                inventory.root_id,
                inventory.category_counts,
                inventory.evidence_sha256,
            )
        except sqlite3.Error:
            raise ArchiveMemoryError("archive_persistence_failed") from None
        finally:
            connection.close()

    def _initialize(self) -> None:
        connection = self._connect(allow_uninitialized=True)
        try:
            exists = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='archive_schema_meta'"
            ).fetchone()
            if exists is not None:
                row = connection.execute(
                    "SELECT schema_version FROM archive_schema_meta WHERE component='archive_memory'"
                ).fetchone()
                if row is None or row[0] != SCHEMA_VERSION:
                    raise ArchiveMemoryError("archive_schema_unsupported")
            connection.executescript(_SCHEMA)
            connection.execute(
                "INSERT OR IGNORE INTO archive_schema_meta(component, schema_version) VALUES ('archive_memory', ?)",
                (SCHEMA_VERSION,),
            )
            connection.commit()
        except ArchiveMemoryError:
            raise
        except sqlite3.Error:
            raise ArchiveMemoryError("archive_persistence_failed") from None
        finally:
            connection.close()

    def _connect(self, *, allow_uninitialized: bool = False) -> sqlite3.Connection:
        with self._state_lock:
            if self._closed and not allow_uninitialized:
                raise ArchiveMemoryError("archive_memory_closed")
        try:
            connection = sqlite3.connect(self._database_path, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA journal_mode = WAL")
            return connection
        except sqlite3.Error:
            raise ArchiveMemoryError("archive_persistence_failed") from None


def _require_id(value: str | None, prefix: str) -> str:
    if (
        value is None
        or _REFERENCE_RE.fullmatch(value) is None
        or not value.startswith(prefix + "-")
    ):
        raise ArchiveMemoryError("archive_reference_invalid")
    return value


def _counts_json(counts: dict[str, int]) -> str:
    clean = {key: int(counts.get(key, 0)) for key in _CATEGORY_LABELS}
    if any(value < 0 for value in clean.values()):
        raise ArchiveMemoryError("archive_inventory_invalid")
    return json.dumps(clean, sort_keys=True, separators=(",", ":"))


def _suggestion_receipt(row: sqlite3.Row) -> ArchiveReceipt:
    return ArchiveReceipt(
        "suggest", row["suggestion_id"], None, None, 0, None, row["root_id"],
        json.loads(row["category_counts_json"]), row["inventory_sha256"],
    )


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


_SCHEMA = """
CREATE TABLE IF NOT EXISTS archive_schema_meta(
    component TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL CHECK(schema_version = 1)
);
CREATE TABLE IF NOT EXISTS archive_suggestion(
    suggestion_id TEXT PRIMARY KEY CHECK(
        substr(suggestion_id, 1, 3) = 'sg-' AND length(suggestion_id)=15
        AND substr(suggestion_id, 4) NOT GLOB '*[^0-9a-f]*'
    ),
    source_message_ref TEXT NOT NULL UNIQUE CHECK(length(source_message_ref) BETWEEN 1 AND 128),
    root_id TEXT NOT NULL CHECK(length(root_id) BETWEEN 1 AND 64),
    inventory_sha256 TEXT NOT NULL CHECK(length(inventory_sha256)=64 AND inventory_sha256 NOT GLOB '*[^0-9a-f]*'),
    category_counts_json TEXT NOT NULL CHECK(length(category_counts_json) BETWEEN 2 AND 512),
    status TEXT NOT NULL CHECK(status IN ('pending','accepted','rejected')),
    created_at TEXT NOT NULL,
    decided_at TEXT
);
CREATE TABLE IF NOT EXISTS archive_preference_memory(
    memory_id TEXT PRIMARY KEY CHECK(
        substr(memory_id, 1, 4) = 'mem-' AND length(memory_id)=16
        AND substr(memory_id, 5) NOT GLOB '*[^0-9a-f]*'
    ),
    root_id TEXT NOT NULL,
    rule_key TEXT NOT NULL CHECK(rule_key='category-v1'),
    status TEXT NOT NULL CHECK(status IN ('learning','candidate','active','forgotten')),
    support_count INTEGER NOT NULL CHECK(support_count >= 0),
    version INTEGER NOT NULL CHECK(version >= 1),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(root_id, rule_key)
);
CREATE TABLE IF NOT EXISTS archive_memory_evidence(
    memory_id TEXT NOT NULL REFERENCES archive_preference_memory(memory_id),
    suggestion_id TEXT NOT NULL UNIQUE REFERENCES archive_suggestion(suggestion_id),
    PRIMARY KEY(memory_id, suggestion_id)
);
"""
