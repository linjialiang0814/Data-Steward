"""Read-only, redacted audit for the S6-B persistent content projection gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
from pathlib import Path


EXPECTED_FORMATS = ("docx", "md", "pdf", "pptx", "txt")
PLAINTEXT_MARKERS = (
    "\u9ad8\u7b49\u6570\u5b66\u8bb2\u4e49".encode(),
    "\u8bfe\u5802\u91cd\u70b9".encode(),
    "\u8bfe\u540e\u5b8c\u6210\u4e09\u9053\u5bfc\u6570\u7ec3\u4e60".encode(),
    b"Review limits continuity and derivatives",
)


def _database_path() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        raise RuntimeError("local_app_data_unavailable")
    path = Path(local_app_data) / "DataSteward" / "hub" / "steward.sqlite3"
    if not path.is_file():
        raise RuntimeError("database_unavailable")
    return path


def _plaintext_hit_count(database: Path) -> int:
    hits = 0
    for path in (database, Path(f"{database}-wal"), Path(f"{database}-shm")):
        if not path.is_file():
            continue
        data = path.read_bytes()
        hits += sum(data.count(marker) for marker in PLAINTEXT_MARKERS)
    return hits


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--expected-state",
        choices=("positive", "cleared"),
        default="positive",
    )
    arguments = parser.parse_args()
    database = _database_path()
    connection = sqlite3.connect(
        f"file:{database.as_posix()}?mode=ro",
        uri=True,
        timeout=5.0,
    )
    try:
        schema_row = connection.execute(
            "SELECT schema_version FROM content_schema_meta WHERE component=?",
            ("content_understanding",),
        ).fetchone()
        if schema_row is None:
            raise RuntimeError("content_schema_unavailable")
        projection_rows = connection.execute(
            """
            SELECT asset_id,revision,format,encrypted_text_blob
            FROM content_projection_v2
            ORDER BY asset_id,revision
            """
        ).fetchall()
        format_rows = connection.execute(
            "SELECT format,count(*) FROM content_projection_v2 GROUP BY format ORDER BY format"
        ).fetchall()
        pack_rows = connection.execute(
            "SELECT payload_json FROM content_study_pack ORDER BY snapshot_sha256"
        ).fetchall()
    finally:
        connection.close()

    digest = hashlib.sha256()
    for asset_id, revision, file_format, encrypted_blob in projection_rows:
        for value in (
            str(asset_id).encode("ascii"),
            str(revision).encode("ascii"),
            str(file_format).encode("ascii"),
            bytes(encrypted_blob),
        ):
            digest.update(len(value).to_bytes(8, "big"))
            digest.update(value)

    format_counts = {str(name): int(count) for name, count in format_rows}
    plaintext_hit_count = _plaintext_hit_count(database)
    positive_state = (
        int(schema_row[0]) == 2
        and len(projection_rows) == len(EXPECTED_FORMATS)
        and format_counts == {name: 1 for name in EXPECTED_FORMATS}
        and len(pack_rows) == 1
        and all(str(row[0]).startswith("sealed-v2:") for row in pack_rows)
        and plaintext_hit_count == 0
    )
    cleared_state = (
        int(schema_row[0]) == 2
        and len(projection_rows) == 0
        and not format_counts
        and len(pack_rows) == 0
        and plaintext_hit_count == 0
    )
    expected_pass = (
        positive_state if arguments.expected_state == "positive" else cleared_state
    )
    result = {
        "expected_state": arguments.expected_state,
        "fixture_plaintext_hit_count": plaintext_hit_count,
        "pack_count": len(pack_rows),
        "projection_count": len(projection_rows),
        "projection_evidence_sha256": digest.hexdigest(),
        "projection_formats": format_counts,
        "schema_version": int(schema_row[0]),
        "sealed_pack_count": sum(
            str(row[0]).startswith("sealed-v2:") for row in pack_rows
        ),
        "status": "PASS" if expected_pass else "FAIL",
    }
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
