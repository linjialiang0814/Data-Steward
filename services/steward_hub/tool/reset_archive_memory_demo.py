from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from steward_hub.archive_memory_demo import (
    ArchiveDemoAdminError,
    inspect_archive_demo,
    reset_archive_demo,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inspect or explicitly reset only S3 archive-memory demo rows."
    )
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--reset", action="store_true")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    try:
        if args.reset:
            result = reset_archive_demo(args.database, confirmation=args.confirm)
            payload = {"status": "PASS", **result.to_dict()}
        else:
            payload = {
                "status": "READY",
                "state": inspect_archive_demo(args.database).to_dict(),
                "reset_performed": False,
            }
    except ArchiveDemoAdminError as exc:
        print(f"S3D_ARCHIVE_DEMO:{exc.code}", file=sys.stderr)
        return 2
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
