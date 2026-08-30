"""Fail-closed administration for resetting only Showcase archive-memory data."""

from __future__ import annotations

import os
import sqlite3
from dataclasses import asdict, dataclass
from pathlib import Path

ARCHIVE_DEMO_RESET_CONFIRMATION = "RESET_S3_ARCHIVE_MEMORY"
_SCHEMA_VERSION = 1
_EXPECTED_COLUMNS = {
    "archive_schema_meta": ("component", "schema_version"),
    "archive_suggestion": (
        "suggestion_id",
        "source_message_ref",
        "root_id",
        "inventory_sha256",
        "category_counts_json",
        "status",
        "created_at",
        "decided_at",
    ),
    "archive_preference_memory": (
        "memory_id",
        "root_id",
        "rule_key",
        "status",
        "support_count",
        "version",
        "created_at",
        "updated_at",
    ),
    "archive_memory_evidence": ("memory_id", "suggestion_id"),
}


class ArchiveDemoAdminError(Exception):
    """A redacted administration failure safe to surface to a local operator."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ArchiveDemoState:
    suggestion_count: int
    memory_count: int
    evidence_count: int

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ArchiveDemoResetResult:
    before: ArchiveDemoState
    after: ArchiveDemoState
    reset_performed: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "before": self.before.to_dict(),
            "after": self.after.to_dict(),
            "reset_performed": self.reset_performed,
        }


def inspect_archive_demo(database_path: str | Path) -> ArchiveDemoState:
    """Inspect archive-memory row counts without creating or mutating a database."""

    path = _validate_database_path(database_path)
    try:
        connection = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)
        connection.execute("PRAGMA query_only = ON")
        _validate_archive_schema(connection)
        return _read_state(connection)
    except ArchiveDemoAdminError:
        raise
    except sqlite3.Error:
        raise ArchiveDemoAdminError("archive_demo_inspection_failed") from None
    finally:
        if "connection" in locals():
            connection.close()


def reset_archive_demo(
    database_path: str | Path,
    *,
    confirmation: str,
    busy_timeout_ms: int = 1000,
) -> ArchiveDemoResetResult:
    """Delete only the three S3 archive-memory tables under an exclusive writer lock."""

    if confirmation != ARCHIVE_DEMO_RESET_CONFIRMATION:
        raise ArchiveDemoAdminError("archive_demo_confirmation_required")
    if (
        isinstance(busy_timeout_ms, bool)
        or not isinstance(busy_timeout_ms, int)
        or not 1 <= busy_timeout_ms <= 10_000
    ):
        raise ArchiveDemoAdminError("archive_demo_timeout_invalid")
    path = _validate_database_path(database_path)
    try:
        connection = sqlite3.connect(path, isolation_level=None, timeout=0)
        connection.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("BEGIN EXCLUSIVE")
        _validate_archive_schema(connection)
        before = _read_state(connection)
        connection.execute("DELETE FROM archive_memory_evidence")
        connection.execute("DELETE FROM archive_preference_memory")
        connection.execute("DELETE FROM archive_suggestion")
        after = _read_state(connection)
        connection.execute("COMMIT")
        return ArchiveDemoResetResult(before, after, True)
    except ArchiveDemoAdminError:
        if "connection" in locals() and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    except sqlite3.OperationalError as exc:
        if "connection" in locals() and connection.in_transaction:
            connection.execute("ROLLBACK")
        code = "archive_demo_busy" if "locked" in str(exc).lower() else "archive_demo_reset_failed"
        raise ArchiveDemoAdminError(code) from None
    except sqlite3.Error:
        if "connection" in locals() and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise ArchiveDemoAdminError("archive_demo_reset_failed") from None
    finally:
        if "connection" in locals():
            connection.close()


def _validate_database_path(database_path: str | Path) -> Path:
    path = Path(database_path)
    if not path.is_absolute():
        raise ArchiveDemoAdminError("archive_demo_database_absolute_required")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError):
        raise ArchiveDemoAdminError("archive_demo_database_missing") from None
    if (
        not resolved.is_file()
        or path.is_symlink()
        or _is_junction(path)
        or any(parent.is_symlink() or _is_junction(parent) for parent in path.parents)
    ):
        raise ArchiveDemoAdminError("archive_demo_database_unsafe")
    return resolved


def _is_junction(path: Path) -> bool:
    checker = getattr(os.path, "isjunction", None)
    return bool(checker(path)) if checker is not None else False


def _validate_archive_schema(connection: sqlite3.Connection) -> None:
    for table, expected in _EXPECTED_COLUMNS.items():
        actual = tuple(
            row[1] for row in connection.execute(f'PRAGMA table_info("{table}")')
        )
        if actual != expected:
            raise ArchiveDemoAdminError("archive_demo_schema_unsupported")
    row = connection.execute(
        "SELECT schema_version FROM archive_schema_meta WHERE component = 'archive_memory'"
    ).fetchone()
    if row is None or row[0] != _SCHEMA_VERSION:
        raise ArchiveDemoAdminError("archive_demo_schema_unsupported")


def _read_state(connection: sqlite3.Connection) -> ArchiveDemoState:
    return ArchiveDemoState(
        suggestion_count=_count(connection, "archive_suggestion"),
        memory_count=_count(connection, "archive_preference_memory"),
        evidence_count=_count(connection, "archive_memory_evidence"),
    )


def _count(connection: sqlite3.Connection, table: str) -> int:
    return int(connection.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0])
