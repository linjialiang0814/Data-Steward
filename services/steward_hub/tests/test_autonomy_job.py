from __future__ import annotations

import tempfile
import unittest
import sqlite3
from pathlib import Path

from steward_hub.autonomy_job import AutonomyJobError, AutonomyJobStore


class AutonomyJobStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "jobs.sqlite3"
        self.store = AutonomyJobStore(self.path)

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def test_terminal_result_is_reused_without_raw_request_persistence(self) -> None:
        marker = "RAW_USER_REQUEST_MUST_NOT_PERSIST"
        first = self.store.begin(snapshot_sha256="a" * 64, normalized_request=marker)
        self.store.transition(first.job_id, expected="QUEUED", target="SNAPSHOT_BOUND")
        self.store.transition(first.job_id, expected="SNAPSHOT_BOUND", target="RUNNING")
        self.store.transition(first.job_id, expected="RUNNING", target="VALIDATING")
        result = {"schema_version": "fixture", "value": "safe"}
        self.store.complete(first.job_id, state="SUCCEEDED", result=result)
        replay = self.store.begin(snapshot_sha256="a" * 64, normalized_request=marker)
        self.assertEqual(first.job_id, replay.job_id)
        self.assertEqual(result, replay.cached_result)
        self.assertNotIn(marker.encode(), self.path.read_bytes())

    def test_active_duplicate_is_busy(self) -> None:
        self.store.begin(snapshot_sha256="b" * 64, normalized_request="same")
        with self.assertRaisesRegex(AutonomyJobError, "autonomy_job_busy"):
            self.store.begin(snapshot_sha256="b" * 64, normalized_request="same")

    def test_restart_marks_incomplete_failed_safe_and_manual_begin_recovers(self) -> None:
        first = self.store.begin(snapshot_sha256="c" * 64, normalized_request="resume")
        self.store.transition(first.job_id, expected="QUEUED", target="SNAPSHOT_BOUND")
        self.store.close()
        self.store = AutonomyJobStore(self.path)
        self.assertEqual("FAILED_SAFE", self.store.state(first.job_id))
        retry = self.store.begin(snapshot_sha256="c" * 64, normalized_request="resume")
        self.assertEqual(first.job_id, retry.job_id)
        self.assertEqual(2, retry.attempt_count)
        self.assertIsNone(retry.cached_result)

    def test_snapshot_change_creates_distinct_job(self) -> None:
        one = self.store.begin(snapshot_sha256="d" * 64, normalized_request="question")
        two = self.store.begin(snapshot_sha256="e" * 64, normalized_request="question")
        self.assertNotEqual(one.job_id, two.job_id)

    def test_degraded_result_requires_an_explicit_new_attempt(self) -> None:
        first = self.store.begin(
            snapshot_sha256="1" * 64,
            normalized_request="retry after stable network",
        )
        self.store.transition(first.job_id, expected="QUEUED", target="SNAPSHOT_BOUND")
        self.store.transition(first.job_id, expected="SNAPSHOT_BOUND", target="RUNNING")
        self.store.transition(first.job_id, expected="RUNNING", target="VALIDATING")
        self.store.complete(first.job_id, state="DEGRADED", result={"safe": True})
        retry = self.store.begin(
            snapshot_sha256="1" * 64,
            normalized_request="retry after stable network",
        )
        self.assertEqual(first.job_id, retry.job_id)
        self.assertEqual(2, retry.attempt_count)
        self.assertIsNone(retry.cached_result)

    def test_corrupt_cached_result_is_rejected_without_reuse(self) -> None:
        lease = self.store.begin(
            snapshot_sha256="f" * 64,
            normalized_request="safe request",
        )
        self.store.transition(lease.job_id, expected="QUEUED", target="SNAPSHOT_BOUND")
        self.store.transition(lease.job_id, expected="SNAPSHOT_BOUND", target="RUNNING")
        self.store.transition(lease.job_id, expected="RUNNING", target="VALIDATING")
        self.store.complete(lease.job_id, state="SUCCEEDED", result={"safe": True})
        self.store.close()
        connection = sqlite3.connect(self.path)
        try:
            connection.execute(
                "UPDATE autonomy_job SET result_json=? WHERE job_id=?",
                ('{"safe":NaN}', lease.job_id),
            )
            connection.commit()
        finally:
            connection.close()
        self.store = AutonomyJobStore(self.path)
        with self.assertRaisesRegex(
            AutonomyJobError, "autonomy_persistence_unavailable"
        ):
            self.store.begin(
                snapshot_sha256="f" * 64,
                normalized_request="safe request",
            )

    def test_v1_schema_migrates_and_accepts_redacted_outcome(self) -> None:
        self.store.close()
        legacy = Path(self.temp.name) / "legacy.sqlite3"
        connection = sqlite3.connect(legacy)
        try:
            connection.executescript(
                """
                CREATE TABLE autonomy_schema_meta(
                  component TEXT PRIMARY KEY,
                  schema_version INTEGER NOT NULL
                );
                INSERT INTO autonomy_schema_meta VALUES('hermes_autonomy',1);
                CREATE TABLE autonomy_job(
                  job_key TEXT PRIMARY KEY,
                  job_id TEXT NOT NULL UNIQUE,
                  snapshot_sha256 TEXT NOT NULL,
                  intent_digest TEXT NOT NULL,
                  state TEXT NOT NULL,
                  attempt_count INTEGER NOT NULL,
                  result_json TEXT,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL
                );
                """
            )
            connection.commit()
        finally:
            connection.close()
        self.store = AutonomyJobStore(legacy)
        lease = self.store.begin(
            snapshot_sha256="2" * 64,
            normalized_request="migration request",
        )
        self.store.transition(lease.job_id, expected="QUEUED", target="SNAPSHOT_BOUND")
        self.store.transition(lease.job_id, expected="SNAPSHOT_BOUND", target="RUNNING")
        self.store.transition(lease.job_id, expected="RUNNING", target="VALIDATING")
        self.store.complete(
            lease.job_id,
            state="DEGRADED",
            result={"safe": True},
            outcome_code="planner_unavailable",
        )
        row = self.store._connection.execute(
            "SELECT outcome_code FROM autonomy_job WHERE job_id=?", (lease.job_id,)
        ).fetchone()
        version = self.store._connection.execute(
            "SELECT schema_version FROM autonomy_schema_meta"
        ).fetchone()
        self.assertEqual("planner_unavailable", row[0])
        self.assertEqual(2, version[0])


if __name__ == "__main__":
    unittest.main()
