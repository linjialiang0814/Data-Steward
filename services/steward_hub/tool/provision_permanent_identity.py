"""Controlled permanent TLS identity provisioner (B2B-B2).

Creates Known Folder permanent identity once (or loads idempotently).
Emits redacted JSON evidence only — never paths, secrets, or full IDs.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_HUB = Path(__file__).resolve().parents[1]
_SRC = _HUB / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from steward_hub.tls_identity import (  # noqa: E402
    file_content_digests,
    file_mtimes_ns,
    provision_or_load_permanent_identity,
    redacted_bootstrap_evidence,
)


def main() -> int:
    first = provision_or_load_permanent_identity()
    digests_1 = file_content_digests()
    mtimes_1 = file_mtimes_ns()
    second = provision_or_load_permanent_identity()
    digests_2 = file_content_digests()
    mtimes_2 = file_mtimes_ns()

    report = {
        "status": "PASS",
        "first": redacted_bootstrap_evidence(first),
        "second": {
            "created": second.created,
            "idempotent": not second.created,
            "fingerprint_stable": (
                first.cert_fingerprint_sha256 == second.cert_fingerprint_sha256
            ),
            "hub_id_stable": first.hub_id == second.hub_id,
            "file_sha256_stable": digests_1 == digests_2,
            "file_mtime_stable": mtimes_1 == mtimes_2,
        },
    }
    ok = (
        first.created
        and (not second.created)
        and report["second"]["fingerprint_stable"]
        and report["second"]["hub_id_stable"]
        and report["second"]["file_sha256_stable"]
        and report["second"]["file_mtime_stable"]
    )
    if not ok:
        # Allow re-run when identity already existed before this tool invocation.
        if (not first.created) and (not second.created) and report["second"][
            "fingerprint_stable"
        ]:
            report["status"] = "PASS_IDEMPOTENT_ONLY"
            ok = True
        else:
            report["status"] = "FAIL"
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
