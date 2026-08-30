"""Real-process Python Hub <-> pure Dart B3D secure-client contract Smoke."""

from __future__ import annotations

import base64
import gc
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

_HUB = Path(__file__).resolve().parents[1]
_REPO = _HUB.parents[1]
_APP = _REPO / "apps" / "steward_app"
_SRC = _HUB / "src"
_TESTS = _HUB / "tests"
_TOOL = _HUB / "tool"
for item in (_SRC, _TESTS, _TOOL):
    if str(item) not in sys.path:
        sys.path.insert(0, str(item))

from helpers_tls_fixture import create_temp_identity, require_openssl  # noqa: E402
from smoke_loopback_https_pinning import _control, _start_hub  # noqa: E402
from steward_hub.https_runtime import allocate_loopback_port  # noqa: E402

HUB_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _read_json_line(process: subprocess.Popen[str], timeout: float = 30.0) -> dict[str, Any]:
    if process.stdout is None:
        raise RuntimeError("dart_stdout_missing")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        line = process.stdout.readline()
        if line:
            value = json.loads(line)
            if not isinstance(value, dict):
                raise RuntimeError("dart_output_invalid")
            return value
        if process.poll() is not None:
            raise RuntimeError("dart_exited_early")
        time.sleep(0.02)
    raise RuntimeError("dart_output_timeout")


def _stop_hub(process: subprocess.Popen[bytes], reply: Path) -> tuple[bool, dict[str, Any]]:
    if process.poll() is not None or process.stdin is None:
        return False, {}
    reply.unlink(missing_ok=True)
    process.stdin.write(b"shutdown\n")
    process.stdin.flush()
    try:
        code = process.wait(timeout=20)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
        return False, {}
    try:
        value = json.loads(reply.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False, {}
    return code == 0, value if isinstance(value, dict) else {}


def _run() -> dict[str, Any]:
    require_openssl()
    root = Path(tempfile.mkdtemp(prefix="data-steward-b3d-"))
    identity = root / "identity"
    database = root / "hub.sqlite3"
    reply = root / "control.json"
    hub: subprocess.Popen[bytes] | None = None
    dart: subprocess.Popen[str] | None = None
    ott = _b64url(os.urandom(32))
    try:
        _, fingerprint = create_temp_identity(identity, hub_id=HUB_ID)
        port = allocate_loopback_port()
        hub = _start_hub(
            python=sys.executable,
            db=database,
            identity_root=identity,
            port=port,
            reply=reply,
        )
        ott_digest = hashlib.sha256(base64.urlsafe_b64decode(ott + "=")).hexdigest()
        created = _control(
            hub,
            reply,
            f"CREATE_SESSION {ott_digest} 600",
            op="CREATE_SESSION",
        )
        qr = {
            "protocol_version": "pairing_auth/1",
            "hub_id": HUB_ID,
            "base_url": f"https://127.0.0.1:{port}",
            "cert_fingerprint": fingerprint,
            "pairing_session_id": created["pairing_session_id"],
            "pairing_token": ott,
            "expires_at": "2099-01-01T00:00:00Z",
        }
        configured = os.environ.get("DART_EXECUTABLE")
        candidate = configured or shutil.which("dart")
        if candidate is None:
            raise RuntimeError("dart_executable_missing")
        dart_exe = Path(candidate)
        if dart_exe.suffix.lower() != ".exe":
            direct = dart_exe.parent / "cache" / "dart-sdk" / "bin" / "dart.exe"
            if direct.exists():
                dart_exe = direct
        if not dart_exe.exists() or dart_exe.suffix.lower() != ".exe":
            raise RuntimeError("dart_executable_invalid")
        dart = subprocess.Popen(
            [
                str(dart_exe),
                "--packages=.dart_tool/package_config.json",
                "tool/smoke_secure_pairing_client.dart",
            ],
            cwd=_APP,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        if dart.stdin is None:
            raise RuntimeError("dart_stdin_missing")
        dart.stdin.write(json.dumps(qr, separators=(",", ":")) + "\n")
        dart.stdin.flush()
        stage = _read_json_line(dart)
        if stage.get("stage") != "awaiting_hub_confirm":
            raise RuntimeError("dart_stage_invalid")
        _control(
            hub,
            reply,
            f"HUB_CONFIRM {created['pairing_session_id']} {stage['pairing_attempt_id']}",
            op="HUB_CONFIRM",
        )
        dart.stdin.write("hub_confirmed\n")
        dart.stdin.flush()
        result = _read_json_line(dart)
        if result.get("status") != "PASS":
            raise RuntimeError(
                "dart_reported_"
                + str(result.get("stage", "unknown"))
                + "_"
                + str(result.get("error_code") or result.get("error_type", "unknown"))
            )
        try:
            return_code = dart.wait(timeout=30)
        except subprocess.TimeoutExpired:
            dart.kill()
            dart.wait(timeout=5)
            raise RuntimeError("dart_exit_timeout")
        stderr = dart.stderr.read() if dart.stderr is not None else ""
        if return_code != 0 or stderr.strip():
            raise RuntimeError("dart_process_failed")
        connection = sqlite3.connect(database)
        try:
            attempts_before_wrong_pin = connection.execute(
                "SELECT COUNT(*) FROM pairing_attempt"
            ).fetchone()[0]
        finally:
            connection.close()
        stopped, snapshot = _stop_hub(hub, reply)
        hub = None
        checks = {
            "status": result.get("status"),
            "client_language": result.get("client_language"),
            "hub_language": result.get("hub_language"),
            "human32_verified": result.get("human32_verified"),
            "pairing_active": result.get("pairing_active"),
            "authenticated_rest": result.get("authenticated_rest"),
            "authenticated_wss": result.get("authenticated_wss"),
            "wrong_pin_rejected": result.get("wrong_pin_rejected"),
            "permanent_auth_retry": result.get("permanent_auth_retry"),
            "secret_marker_count": result.get("secret_marker_count"),
            "attempt_count": int(attempts_before_wrong_pin),
            "hub_stopped": stopped,
            "shutdown_residual": sum(
                int(snapshot.get(key, -1))
                for key in (
                    "handshake_count",
                    "connection_count",
                    "operation_count",
                    "subscription_count",
                    "worker_count",
                )
            ),
            "loopback_only": True,
        }
        expected = {
            "status": "PASS",
            "client_language": "dart",
            "hub_language": "python",
            "human32_verified": True,
            "pairing_active": True,
            "authenticated_rest": True,
            "authenticated_wss": True,
            "wrong_pin_rejected": True,
            "permanent_auth_retry": False,
            "secret_marker_count": 0,
            "attempt_count": 1,
            "hub_stopped": True,
            "shutdown_residual": 0,
            "loopback_only": True,
        }
        if checks != expected:
            raise RuntimeError("b3d_checks_failed")
        return checks
    finally:
        if dart is not None and dart.poll() is None:
            dart.kill()
            dart.wait(timeout=5)
        if hub is not None:
            _stop_hub(hub, reply)
        gc.collect()
        shutil.rmtree(root, ignore_errors=False)


def main() -> int:
    try:
        checks = _run()
    except Exception as exc:  # noqa: BLE001
        print(
            json.dumps(
                {"status": "FAIL", "error_type": type(exc).__name__},
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(checks, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
