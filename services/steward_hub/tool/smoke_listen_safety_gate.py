"""B4 real-process loopback/default and unsafe pre-listen acceptance Smoke."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

_HUB = Path(__file__).resolve().parents[1]
_SRC = _HUB / "src"
_TESTS = _HUB / "tests"
_TOOL = _HUB / "tool"
for import_path in (_SRC, _TESTS, _TOOL):
    if str(import_path) not in sys.path:
        sys.path.insert(0, str(import_path))

from helpers_tls_fixture import create_temp_identity, require_openssl  # noqa: E402
from smoke_loopback_https_pinning import _start_hub, _stop_hub  # noqa: E402
from steward_hub.https_runtime import allocate_loopback_port  # noqa: E402
from steward_hub.listen_policy import (  # noqa: E402
    LISTEN_AUTHENTICATED_SERVICE,
    LISTEN_PAIRING_ONLY,
    resolve_listen_policy,
)
from steward_hub.pin_client import PinFirstHttpsClient  # noqa: E402

HUB_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"


def _run_cli(python: str, args: list[str]) -> subprocess.CompletedProcess[bytes]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(_SRC)
    return subprocess.run(
        [python, "-m", "steward_hub.https_runtime", *args],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
        check=False,
    )


def run() -> dict[str, object]:
    require_openssl()
    python = sys.executable
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        identity_root = root / "identity"
        _, fingerprint = create_temp_identity(identity_root, hub_id=HUB_ID)
        database = root / "hub.sqlite3"
        reply = root / "reply.json"
        port = allocate_loopback_port()

        hub = _start_hub(
            python=python,
            db=database,
            identity_root=identity_root,
            port=port,
            reply=reply,
        )
        try:
            with PinFirstHttpsClient(
                host="127.0.0.1",
                port=port,
                expected_fingerprint=fingerprint,
            ) as client:
                health = client.get("/health")
                loopback_health_ok = (
                    health.status_code == 200
                    and health.json().get("transport_scope") == "loopback_only"
                )
        finally:
            loopback_stopped = _stop_hub(hub, reply)

        common = [
            "--database",
            str(root / "must-not-exist.sqlite3"),
            "--identity-root",
            str(root / "must-not-exist-identity"),
            "--port",
            str(allocate_loopback_port()),
        ]
        disabled = _run_cli(
            python,
            [*common, "--listen-mode", "disabled"],
        )
        wildcard = _run_cli(
            python,
            [
                *common,
                "--listen-mode",
                "authenticated-service",
                "--host",
                "0.0.0.0",
                "--acknowledge-private-lan-risk",
            ],
        )
        missing_ack = _run_cli(
            python,
            [
                *common,
                "--listen-mode",
                "pairing-only",
                "--host",
                "192.168.1.8",
            ],
        )
        pairing_policy = resolve_listen_policy(
            mode=LISTEN_PAIRING_ONLY,
            host="192.168.1.8",
            private_lan_authorized=True,
        )
        authenticated_policy = resolve_listen_policy(
            mode=LISTEN_AUTHENTICATED_SERVICE,
            host="10.2.3.4",
            private_lan_authorized=True,
        )
        forbidden_side_effects_absent = not (root / "must-not-exist.sqlite3").exists()

        checks = {
            "default_loopback_health_ok": loopback_health_ok,
            "default_loopback_stopped": loopback_stopped,
            "disabled_zero_side_effect": disabled.returncode == 0,
            "wildcard_rejected_prelisten": wildcard.returncode == 2,
            "missing_ack_rejected_prelisten": missing_ack.returncode == 2,
            "unsafe_prelisten_zero_database": forbidden_side_effects_absent,
            "pairing_only_business_routes_disabled": not pairing_policy.business_routes_enabled,
            "authenticated_service_business_routes_enabled": authenticated_policy.business_routes_enabled,
            "child_processes_exited": hub.poll() is not None,
        }
        if not all(checks.values()):
            raise RuntimeError("listen_safety_smoke_failed")
        return {"status": "PASS", **checks}


if __name__ == "__main__":
    print(json.dumps(run(), sort_keys=True, separators=(",", ":")))
