"""Transactional SQLite event store for the shared-session domain core."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from .errors import (
    ConversationAlreadyExistsError,
    ConversationNotFoundError,
    IdempotencyConflictError,
    PersistenceError,
    SharedSessionError,
    ValidationError,
)
from .models import (
    MESSAGE_ACCEPTED_EVENT,
    PROTOCOL_VERSION,
    AppendMessageResult,
    Conversation,
    ConversationEvent,
    ConversationMessage,
)

MAX_TITLE_LENGTH = 200
MAX_ID_LENGTH = 128
MAX_CONTENT_LENGTH = 65_536
MAX_REPLAY_LIMIT = 500
ALLOWED_ROLES = frozenset({"user", "assistant", "system", "tool"})

_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS conversation (
    conversation_id TEXT PRIMARY KEY,
    title TEXT NOT NULL CHECK (
        length(title) BETWEEN 1 AND {MAX_TITLE_LENGTH}
    ),
    next_seq INTEGER NOT NULL DEFAULT 1 CHECK (next_seq >= 1),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS conversation_message (
    message_id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL,
    client_message_id TEXT NOT NULL,
    actor_device_id TEXT NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    accepted_seq INTEGER NOT NULL CHECK (accepted_seq >= 1),
    occurred_at TEXT NOT NULL,
    FOREIGN KEY (conversation_id)
        REFERENCES conversation(conversation_id),
    UNIQUE (conversation_id, client_message_id),
    UNIQUE (conversation_id, accepted_seq)
);

CREATE TABLE IF NOT EXISTS conversation_event (
    event_id TEXT PRIMARY KEY,
    protocol_version INTEGER NOT NULL
        CHECK (protocol_version = {PROTOCOL_VERSION}),
    event_type TEXT NOT NULL
        CHECK (event_type = '{MESSAGE_ACCEPTED_EVENT}'),
    conversation_id TEXT NOT NULL,
    conversation_seq INTEGER NOT NULL CHECK (conversation_seq >= 1),
    actor_device_id TEXT NOT NULL,
    causation_id TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL
        CHECK (length(payload_sha256) = 64),
    FOREIGN KEY (conversation_id)
        REFERENCES conversation(conversation_id),
    UNIQUE (conversation_id, conversation_seq)
);

CREATE INDEX IF NOT EXISTS idx_conversation_event_replay
ON conversation_event(conversation_id, conversation_seq);
"""


class EventStore:
    """File-backed store with one short SQLite connection per operation."""

    def __init__(
        self,
        database_path: str | Path,
        *,
        busy_timeout_ms: int = 5_000,
        fault_injector: Callable[[str], None] | None = None,
    ) -> None:
        path_text = str(database_path)
        if not path_text or path_text == ":memory:":
            raise ValidationError("database_path must reference a file")
        if (
            isinstance(busy_timeout_ms, bool)
            or not isinstance(busy_timeout_ms, int)
            or not 1 <= busy_timeout_ms <= 60_000
        ):
            raise ValidationError("busy_timeout_ms is invalid")

        self._database_path = path_text
        self._busy_timeout_ms = busy_timeout_ms
        self._fault_injector = fault_injector
        self._state_lock = threading.Lock()
        self._closed = False
        self._initialize()

    def __enter__(self) -> EventStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        with self._state_lock:
            self._closed = True

    def create_conversation(
        self,
        title: str,
        *,
        conversation_id: str | None = None,
    ) -> Conversation:
        clean_title = _validated_text(
            "title",
            title,
            max_length=MAX_TITLE_LENGTH,
        )
        clean_id = (
            str(uuid.uuid4())
            if conversation_id is None
            else _validated_id("conversation_id", conversation_id)
        )
        now = _utc_now()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO conversation(
                    conversation_id, title, next_seq, created_at, updated_at
                ) VALUES (?, ?, 1, ?, ?)
                """,
                (clean_id, clean_title, now, now),
            )
            connection.commit()
            return Conversation(clean_id, clean_title, 1, now, now)
        except sqlite3.IntegrityError:
            connection.rollback()
            raise ConversationAlreadyExistsError(
                "conversation already exists"
            ) from None
        except sqlite3.Error:
            connection.rollback()
            raise PersistenceError("conversation creation failed") from None
        finally:
            connection.close()

    def get_conversation(self, conversation_id: str) -> Conversation:
        clean_id = _validated_id("conversation_id", conversation_id)
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT conversation_id, title, next_seq, created_at, updated_at
                FROM conversation
                WHERE conversation_id = ?
                """,
                (clean_id,),
            ).fetchone()
        except sqlite3.Error:
            raise PersistenceError("conversation lookup failed") from None
        finally:
            connection.close()
        if row is None:
            raise ConversationNotFoundError("conversation not found")
        return _conversation_from_row(row)

    def get_message_by_client_id(
        self,
        *,
        conversation_id: str,
        client_message_id: str,
    ) -> ConversationMessage | None:
        clean_conversation_id = _validated_id("conversation_id", conversation_id)
        clean_client_message_id = _validated_id(
            "client_message_id",
            client_message_id,
        )
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT
                    message_id, conversation_id, client_message_id,
                    actor_device_id, role, content, accepted_seq, occurred_at
                FROM conversation_message
                WHERE conversation_id = ? AND client_message_id = ?
                """,
                (clean_conversation_id, clean_client_message_id),
            ).fetchone()
        except sqlite3.Error:
            raise PersistenceError("message lookup failed") from None
        finally:
            connection.close()
        return None if row is None else _message_from_row(row)

    def append_message(
        self,
        *,
        conversation_id: str,
        client_message_id: str,
        actor_device_id: str,
        role: str,
        content: str,
        causation_id: str | None = None,
        correlation_id: str | None = None,
        transaction_hook: Callable[
            [sqlite3.Connection, ConversationMessage], None
        ]
        | None = None,
    ) -> AppendMessageResult:
        clean_conversation_id = _validated_id(
            "conversation_id",
            conversation_id,
        )
        clean_client_message_id = _validated_id(
            "client_message_id",
            client_message_id,
        )
        clean_actor_device_id = _validated_text(
            "actor_device_id",
            actor_device_id,
            max_length=MAX_ID_LENGTH,
        )
        clean_role = _validated_text("role", role, max_length=32)
        if clean_role not in ALLOWED_ROLES:
            raise ValidationError("role is invalid")
        clean_content = _validated_text(
            "content",
            content,
            max_length=MAX_CONTENT_LENGTH,
        )
        clean_causation_id = _validated_id(
            "causation_id",
            causation_id or clean_client_message_id,
        )
        clean_correlation_id = _validated_id(
            "correlation_id",
            correlation_id or clean_conversation_id,
        )

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            conversation_row = connection.execute(
                """
                SELECT conversation_id, next_seq
                FROM conversation
                WHERE conversation_id = ?
                """,
                (clean_conversation_id,),
            ).fetchone()
            if conversation_row is None:
                raise ConversationNotFoundError("conversation not found")

            existing_message_row = connection.execute(
                """
                SELECT
                    message_id, conversation_id, client_message_id,
                    actor_device_id, role, content, accepted_seq, occurred_at
                FROM conversation_message
                WHERE conversation_id = ? AND client_message_id = ?
                """,
                (clean_conversation_id, clean_client_message_id),
            ).fetchone()
            if existing_message_row is not None:
                result = self._deduplicated_result(
                    connection,
                    existing_message_row,
                    actor_device_id=clean_actor_device_id,
                    role=clean_role,
                    content=clean_content,
                    causation_id=clean_causation_id,
                    correlation_id=clean_correlation_id,
                )
                connection.commit()
                return result

            conversation_seq = int(conversation_row["next_seq"])
            message_id = str(uuid.uuid4())
            event_id = str(uuid.uuid4())
            occurred_at = _utc_now()
            payload_json = _stable_payload_json(
                message_id=message_id,
                client_message_id=clean_client_message_id,
                role=clean_role,
                content=clean_content,
                accepted_seq=conversation_seq,
            )
            payload_sha256 = hashlib.sha256(
                payload_json.encode("utf-8")
            ).hexdigest()

            updated = connection.execute(
                """
                UPDATE conversation
                SET next_seq = next_seq + 1, updated_at = ?
                WHERE conversation_id = ? AND next_seq = ?
                """,
                (occurred_at, clean_conversation_id, conversation_seq),
            )
            if updated.rowcount != 1:
                raise PersistenceError("sequence allocation failed")
            self._inject_fault("after_sequence_reserved")

            connection.execute(
                """
                INSERT INTO conversation_message(
                    message_id, conversation_id, client_message_id,
                    actor_device_id, role, content, accepted_seq, occurred_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    message_id,
                    clean_conversation_id,
                    clean_client_message_id,
                    clean_actor_device_id,
                    clean_role,
                    clean_content,
                    conversation_seq,
                    occurred_at,
                ),
            )
            self._inject_fault("after_message_insert")

            connection.execute(
                """
                INSERT INTO conversation_event(
                    event_id, protocol_version, event_type, conversation_id,
                    conversation_seq, actor_device_id, causation_id,
                    correlation_id, occurred_at, payload_json, payload_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    PROTOCOL_VERSION,
                    MESSAGE_ACCEPTED_EVENT,
                    clean_conversation_id,
                    conversation_seq,
                    clean_actor_device_id,
                    clean_causation_id,
                    clean_correlation_id,
                    occurred_at,
                    payload_json,
                    payload_sha256,
                ),
            )
            self._inject_fault("after_event_insert")
            message = ConversationMessage(
                message_id=message_id,
                conversation_id=clean_conversation_id,
                client_message_id=clean_client_message_id,
                actor_device_id=clean_actor_device_id,
                role=clean_role,
                content=clean_content,
                accepted_seq=conversation_seq,
                occurred_at=occurred_at,
            )
            if transaction_hook is not None:
                transaction_hook(connection, message)
            connection.commit()
            return AppendMessageResult(
                message=message,
                event=ConversationEvent(
                    event_id=event_id,
                    protocol_version=PROTOCOL_VERSION,
                    event_type=MESSAGE_ACCEPTED_EVENT,
                    conversation_id=clean_conversation_id,
                    conversation_seq=conversation_seq,
                    actor_device_id=clean_actor_device_id,
                    causation_id=clean_causation_id,
                    correlation_id=clean_correlation_id,
                    occurred_at=occurred_at,
                    payload_json=payload_json,
                    payload_sha256=payload_sha256,
                ),
                deduplicated=False,
            )
        except SharedSessionError:
            connection.rollback()
            raise
        except sqlite3.Error:
            connection.rollback()
            raise PersistenceError("message append failed") from None
        except Exception:
            connection.rollback()
            raise PersistenceError("message append failed") from None
        finally:
            connection.close()

    def replay_events(
        self,
        *,
        conversation_id: str,
        after_seq: int,
        limit: int,
    ) -> list[ConversationEvent]:
        clean_id = _validated_id("conversation_id", conversation_id)
        if (
            isinstance(after_seq, bool)
            or not isinstance(after_seq, int)
            or after_seq < 0
        ):
            raise ValidationError("after_seq is invalid")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_REPLAY_LIMIT
        ):
            raise ValidationError("limit is invalid")

        connection = self._connect()
        try:
            exists = connection.execute(
                """
                SELECT 1 FROM conversation WHERE conversation_id = ?
                """,
                (clean_id,),
            ).fetchone()
            if exists is None:
                raise ConversationNotFoundError("conversation not found")
            rows = connection.execute(
                """
                SELECT
                    event_id, protocol_version, event_type, conversation_id,
                    conversation_seq, actor_device_id, causation_id,
                    correlation_id, occurred_at, payload_json, payload_sha256
                FROM conversation_event
                WHERE conversation_id = ? AND conversation_seq > ?
                ORDER BY conversation_seq ASC
                LIMIT ?
                """,
                (clean_id, after_seq, limit),
            ).fetchall()
            return [_event_from_row(row) for row in rows]
        except SharedSessionError:
            raise
        except sqlite3.Error:
            raise PersistenceError("event replay failed") from None
        finally:
            connection.close()

    def count_records(self, conversation_id: str) -> tuple[int, int]:
        clean_id = _validated_id("conversation_id", conversation_id)
        connection = self._connect()
        try:
            exists = connection.execute(
                "SELECT 1 FROM conversation WHERE conversation_id = ?",
                (clean_id,),
            ).fetchone()
            if exists is None:
                raise ConversationNotFoundError("conversation not found")
            message_count = connection.execute(
                """
                SELECT count(*) FROM conversation_message
                WHERE conversation_id = ?
                """,
                (clean_id,),
            ).fetchone()[0]
            event_count = connection.execute(
                """
                SELECT count(*) FROM conversation_event
                WHERE conversation_id = ?
                """,
                (clean_id,),
            ).fetchone()[0]
            return int(message_count), int(event_count)
        except SharedSessionError:
            raise
        except sqlite3.Error:
            raise PersistenceError("record count failed") from None
        finally:
            connection.close()

    def database_settings(self) -> dict[str, int | str]:
        connection = self._connect()
        try:
            journal_mode = str(
                connection.execute("PRAGMA journal_mode").fetchone()[0]
            )
            foreign_keys = int(
                connection.execute("PRAGMA foreign_keys").fetchone()[0]
            )
            busy_timeout = int(
                connection.execute("PRAGMA busy_timeout").fetchone()[0]
            )
            return {
                "journal_mode": journal_mode,
                "foreign_keys": foreign_keys,
                "busy_timeout": busy_timeout,
            }
        except sqlite3.Error:
            raise PersistenceError("database settings lookup failed") from None
        finally:
            connection.close()

    def _initialize(self) -> None:
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                self._database_path,
                timeout=self._busy_timeout_ms / 1_000,
                isolation_level=None,
            )
            journal_mode = connection.execute(
                "PRAGMA journal_mode=WAL"
            ).fetchone()[0]
            if str(journal_mode).lower() != "wal":
                raise PersistenceError("WAL mode could not be enabled")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                f"PRAGMA busy_timeout={self._busy_timeout_ms}"
            )
            connection.executescript(_SCHEMA)
        except SharedSessionError:
            raise
        except sqlite3.Error:
            raise PersistenceError("database initialization failed") from None
        finally:
            if connection is not None:
                connection.close()

    def _connect(self) -> sqlite3.Connection:
        with self._state_lock:
            if self._closed:
                raise PersistenceError("event store is closed")
        try:
            connection = sqlite3.connect(
                self._database_path,
                timeout=self._busy_timeout_ms / 1_000,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                f"PRAGMA busy_timeout={self._busy_timeout_ms}"
            )
            return connection
        except sqlite3.Error:
            raise PersistenceError("database connection failed") from None

    def _deduplicated_result(
        self,
        connection: sqlite3.Connection,
        message_row: sqlite3.Row,
        *,
        actor_device_id: str,
        role: str,
        content: str,
        causation_id: str,
        correlation_id: str,
    ) -> AppendMessageResult:
        message = _message_from_row(message_row)
        event_row = connection.execute(
            """
            SELECT
                event_id, protocol_version, event_type, conversation_id,
                conversation_seq, actor_device_id, causation_id,
                correlation_id, occurred_at, payload_json, payload_sha256
            FROM conversation_event
            WHERE conversation_id = ? AND conversation_seq = ?
            """,
            (message.conversation_id, message.accepted_seq),
        ).fetchone()
        if event_row is None:
            raise PersistenceError("idempotency record is incomplete")
        event = _event_from_row(event_row)
        if (
            message.actor_device_id != actor_device_id
            or message.role != role
            or message.content != content
            or event.causation_id != causation_id
            or event.correlation_id != correlation_id
        ):
            raise IdempotencyConflictError(
                "client_message_id conflicts with persisted input"
            )
        return AppendMessageResult(
            message=message,
            event=event,
            deduplicated=True,
        )

    def _inject_fault(self, stage: str) -> None:
        if self._fault_injector is not None:
            self._fault_injector(stage)


def _validated_id(field_name: str, value: object) -> str:
    return _validated_text(field_name, value, max_length=MAX_ID_LENGTH)


def _validated_text(
    field_name: str,
    value: object,
    *,
    max_length: int,
) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{field_name} is invalid")
    if value != value.strip() or not value or len(value) > max_length:
        raise ValidationError(f"{field_name} is invalid")
    return value


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _stable_payload_json(
    *,
    message_id: str,
    client_message_id: str,
    role: str,
    content: str,
    accepted_seq: int,
) -> str:
    return json.dumps(
        {
            "accepted_seq": accepted_seq,
            "client_message_id": client_message_id,
            "content": content,
            "message_id": message_id,
            "role": role,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _conversation_from_row(row: sqlite3.Row) -> Conversation:
    return Conversation(
        conversation_id=str(row["conversation_id"]),
        title=str(row["title"]),
        next_seq=int(row["next_seq"]),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
    )


def _message_from_row(row: sqlite3.Row) -> ConversationMessage:
    return ConversationMessage(
        message_id=str(row["message_id"]),
        conversation_id=str(row["conversation_id"]),
        client_message_id=str(row["client_message_id"]),
        actor_device_id=str(row["actor_device_id"]),
        role=str(row["role"]),
        content=str(row["content"]),
        accepted_seq=int(row["accepted_seq"]),
        occurred_at=str(row["occurred_at"]),
    )


def _event_from_row(row: sqlite3.Row) -> ConversationEvent:
    return ConversationEvent(
        event_id=str(row["event_id"]),
        protocol_version=int(row["protocol_version"]),
        event_type=str(row["event_type"]),
        conversation_id=str(row["conversation_id"]),
        conversation_seq=int(row["conversation_seq"]),
        actor_device_id=str(row["actor_device_id"]),
        causation_id=str(row["causation_id"]),
        correlation_id=str(row["correlation_id"]),
        occurred_at=str(row["occurred_at"]),
        payload_json=str(row["payload_json"]),
        payload_sha256=str(row["payload_sha256"]),
    )
