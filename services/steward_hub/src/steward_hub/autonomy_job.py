"""Durable, content-free Agent Job idempotency ledger."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

AUTONOMY_SCHEMA_VERSION = 2
ACTIVE_STATES = frozenset({"QUEUED", "SNAPSHOT_BOUND", "RUNNING", "VALIDATING"})
TERMINAL_STATES = frozenset({"SUCCEEDED", "DEGRADED", "FAILED_SAFE"})
MAX_RESULT_BYTES = 32 * 1024

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_JOB_ID_RE = re.compile(r"^aj-[0-9a-f]{24}$")
_OUTCOME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


class AutonomyJobError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class AutonomyJobLease:
    job_id: str
    job_key: str
    attempt_count: int
    cached_result: dict[str, Any] | None
    cached_state: str | None


class AutonomyJobStore:
    """One row per snapshot/request digest; never stores the raw request."""

    def __init__(self, database_path: str | Path) -> None:
        self._lock = threading.RLock()
        self._closed = False
        try:
            self._connection = sqlite3.connect(
                str(database_path),
                isolation_level=None,
                check_same_thread=False,
                timeout=5.0,
            )
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA busy_timeout = 5000")
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._initialize()
        except AutonomyJobError:
            if hasattr(self, "_connection"):
                self._connection.close()
            raise
        except sqlite3.Error:
            if hasattr(self, "_connection"):
                self._connection.close()
            raise AutonomyJobError("autonomy_persistence_unavailable") from None

    def begin(self, *, snapshot_sha256: str, normalized_request: str) -> AutonomyJobLease:
        _require_digest(snapshot_sha256)
        if (
            not isinstance(normalized_request, str)
            or not normalized_request
            or len(normalized_request) > 500
            or any(ord(char) < 32 for char in normalized_request)
        ):
            raise AutonomyJobError("autonomy_request_invalid")
        intent_digest = hashlib.sha256(normalized_request.encode("utf-8")).hexdigest()
        job_key = hashlib.sha256(
            f"data-steward.autonomy-job/v1\n{snapshot_sha256}\n{intent_digest}".encode()
        ).hexdigest()
        with self._lock:
            self._ensure_open()
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                row = self._connection.execute(
                    "SELECT * FROM autonomy_job WHERE job_key=?", (job_key,)
                ).fetchone()
                if row is not None and row["state"] == "SUCCEEDED":
                    result = _strict_object(str(row["result_json"]))
                    self._connection.commit()
                    return AutonomyJobLease(
                        str(row["job_id"]),
                        job_key,
                        int(row["attempt_count"]),
                        result,
                        str(row["state"]),
                    )
                if row is not None and row["state"] in ACTIVE_STATES:
                    self._connection.rollback()
                    raise AutonomyJobError("autonomy_job_busy")
                now = _utc_now()
                if row is None:
                    job_id = "aj-" + secrets.token_hex(12)
                    self._connection.execute(
                        """
                        INSERT INTO autonomy_job(
                          job_key,job_id,snapshot_sha256,intent_digest,state,
                          attempt_count,result_json,created_at,updated_at
                        ) VALUES(?,?,?,?, 'QUEUED', 1, NULL, ?, ?)
                        """,
                        (job_key, job_id, snapshot_sha256, intent_digest, now, now),
                    )
                    attempt_count = 1
                else:
                    job_id = str(row["job_id"])
                    attempt_count = int(row["attempt_count"]) + 1
                    self._connection.execute(
                        """
                        UPDATE autonomy_job SET state='QUEUED',attempt_count=?,
                          result_json=NULL,outcome_code=NULL,updated_at=? WHERE job_key=?
                        """,
                        (attempt_count, now, job_key),
                    )
                self._connection.commit()
                return AutonomyJobLease(
                    job_id, job_key, attempt_count, None, None
                )
            except AutonomyJobError:
                raise
            except (sqlite3.Error, ValueError, json.JSONDecodeError):
                self._connection.rollback()
                raise AutonomyJobError("autonomy_persistence_unavailable") from None

    def transition(self, job_id: str, *, expected: str, target: str) -> None:
        _require_job_id(job_id)
        allowed = {
            ("QUEUED", "SNAPSHOT_BOUND"),
            ("SNAPSHOT_BOUND", "RUNNING"),
            ("RUNNING", "VALIDATING"),
        }
        if (expected, target) not in allowed:
            raise AutonomyJobError("autonomy_transition_invalid")
        with self._lock:
            self._ensure_open()
            try:
                cursor = self._connection.execute(
                    "UPDATE autonomy_job SET state=?,updated_at=? WHERE job_id=? AND state=?",
                    (target, _utc_now(), job_id, expected),
                )
                if cursor.rowcount != 1:
                    raise AutonomyJobError("autonomy_transition_conflict")
            except AutonomyJobError:
                raise
            except sqlite3.Error:
                raise AutonomyJobError("autonomy_persistence_unavailable") from None

    def complete(
        self,
        job_id: str,
        *,
        state: str,
        result: dict[str, Any],
        outcome_code: str | None = None,
    ) -> None:
        _require_job_id(job_id)
        if (
            state not in {"SUCCEEDED", "DEGRADED"}
            or not isinstance(result, dict)
            or (
                outcome_code is not None
                and (
                    not isinstance(outcome_code, str)
                    or _OUTCOME_RE.fullmatch(outcome_code) is None
                )
            )
        ):
            raise AutonomyJobError("autonomy_result_invalid")
        encoded = json.dumps(
            result, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        if len(encoded) > MAX_RESULT_BYTES:
            raise AutonomyJobError("autonomy_result_invalid")
        with self._lock:
            self._ensure_open()
            try:
                cursor = self._connection.execute(
                    """
                    UPDATE autonomy_job SET state=?,result_json=?,outcome_code=?,updated_at=?
                    WHERE job_id=? AND state='VALIDATING'
                    """,
                    (
                        state,
                        encoded.decode("utf-8"),
                        outcome_code,
                        _utc_now(),
                        job_id,
                    ),
                )
                if cursor.rowcount != 1:
                    raise AutonomyJobError("autonomy_transition_conflict")
            except AutonomyJobError:
                raise
            except sqlite3.Error:
                raise AutonomyJobError("autonomy_persistence_unavailable") from None

    def fail_safe(self, job_id: str) -> None:
        _require_job_id(job_id)
        with self._lock:
            self._ensure_open()
            try:
                self._connection.execute(
                    """
                    UPDATE autonomy_job SET state='FAILED_SAFE',result_json=NULL,updated_at=?
                    WHERE job_id=? AND state IN ('QUEUED','SNAPSHOT_BOUND','RUNNING','VALIDATING')
                    """,
                    (_utc_now(), job_id),
                )
            except sqlite3.Error:
                raise AutonomyJobError("autonomy_persistence_unavailable") from None

    def state(self, job_id: str) -> str:
        _require_job_id(job_id)
        with self._lock:
            self._ensure_open()
            row = self._connection.execute(
                "SELECT state FROM autonomy_job WHERE job_id=?", (job_id,)
            ).fetchone()
        if row is None:
            raise AutonomyJobError("autonomy_job_not_found")
        return str(row[0])

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._connection.close()

    def _initialize(self) -> None:
        tables = {
            str(row[0])
            for row in self._connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'autonomy_%'"
            )
        }
        if "autonomy_schema_meta" in tables:
            rows = list(
                self._connection.execute(
                    "SELECT component,schema_version FROM autonomy_schema_meta"
                )
            )
            if len(rows) != 1 or str(rows[0][0]) != "hermes_autonomy":
                raise AutonomyJobError("autonomy_schema_unsupported")
            version = int(rows[0][1])
            if version == 1:
                self._migrate_v1_to_v2()
            elif version != AUTONOMY_SCHEMA_VERSION:
                raise AutonomyJobError("autonomy_schema_unsupported")
        elif tables:
            raise AutonomyJobError("autonomy_schema_unsupported")
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS autonomy_schema_meta(
              component TEXT PRIMARY KEY,
              schema_version INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS autonomy_job(
              job_key TEXT PRIMARY KEY CHECK(
                length(job_key)=64 AND job_key NOT GLOB '*[^0-9a-f]*'
              ),
              job_id TEXT NOT NULL UNIQUE CHECK(
                length(job_id)=27 AND substr(job_id,1,3)='aj-' AND
                substr(job_id,4) NOT GLOB '*[^0-9a-f]*'
              ),
              snapshot_sha256 TEXT NOT NULL CHECK(
                length(snapshot_sha256)=64 AND
                snapshot_sha256 NOT GLOB '*[^0-9a-f]*'
              ),
              intent_digest TEXT NOT NULL CHECK(
                length(intent_digest)=64 AND
                intent_digest NOT GLOB '*[^0-9a-f]*'
              ),
              state TEXT NOT NULL CHECK(state IN (
                'QUEUED','SNAPSHOT_BOUND','RUNNING','VALIDATING',
                'SUCCEEDED','DEGRADED','FAILED_SAFE'
              )),
              attempt_count INTEGER NOT NULL CHECK(attempt_count>=1),
              result_json TEXT,
              outcome_code TEXT CHECK(
                outcome_code IS NULL OR (
                  length(outcome_code) BETWEEN 1 AND 64 AND
                  outcome_code NOT GLOB '*[^a-z0-9_]*'
                )
              ),
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              CHECK((state IN ('SUCCEEDED','DEGRADED')) = (result_json IS NOT NULL))
            );
            """
        )
        self._connection.execute(
            "INSERT OR IGNORE INTO autonomy_schema_meta VALUES('hermes_autonomy',?)",
            (AUTONOMY_SCHEMA_VERSION,),
        )
        self._connection.execute(
            """
            UPDATE autonomy_job SET state='FAILED_SAFE',result_json=NULL,updated_at=?
            WHERE state IN ('QUEUED','SNAPSHOT_BOUND','RUNNING','VALIDATING')
            """,
            (_utc_now(),),
        )

    def _migrate_v1_to_v2(self) -> None:
        columns = {
            str(row[1])
            for row in self._connection.execute("PRAGMA table_info(autonomy_job)")
        }
        if "outcome_code" in columns:
            raise AutonomyJobError("autonomy_schema_unsupported")
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            self._connection.execute(
                """
                ALTER TABLE autonomy_job ADD COLUMN outcome_code TEXT CHECK(
                  outcome_code IS NULL OR (
                    length(outcome_code) BETWEEN 1 AND 64 AND
                    outcome_code NOT GLOB '*[^a-z0-9_]*'
                  )
                )
                """
            )
            self._connection.execute(
                "UPDATE autonomy_schema_meta SET schema_version=2 "
                "WHERE component='hermes_autonomy' AND schema_version=1"
            )
            self._connection.commit()
        except sqlite3.Error:
            self._connection.rollback()
            raise AutonomyJobError("autonomy_schema_unsupported") from None

    def _ensure_open(self) -> None:
        if self._closed:
            raise AutonomyJobError("autonomy_store_closed")


def _require_digest(value: str) -> None:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise AutonomyJobError("autonomy_request_invalid")


def _require_job_id(value: str) -> None:
    if not isinstance(value, str) or _JOB_ID_RE.fullmatch(value) is None:
        raise AutonomyJobError("autonomy_job_invalid")


def _strict_object(raw: str) -> dict[str, Any]:
    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in rows:
            if key in value:
                raise ValueError("duplicate_key")
            value[key] = item
        return value

    value = json.loads(
        raw,
        object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")),
    )
    if not isinstance(value, dict):
        raise ValueError("result_not_object")
    return value


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
