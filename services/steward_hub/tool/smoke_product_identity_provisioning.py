"""Temporary-directory product identity provisioning + HTTPS smoke (B2B-B1)."""

from __future__ import annotations

import base64
import gc
import hashlib
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

_HUB = Path(__file__).resolve().parents[1]
_SRC = _HUB / "src"
_TESTS = _HUB / "tests"
for path in (_SRC, _TESTS):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from steward_hub.https_runtime import allocate_loopback_port  # noqa: E402
from steward_hub.pairing_store_executor import (  # noqa: E402
    list_alive_pairing_worker_threads,
)
from steward_hub.pin_client import PinFirstHttpsClient  # noqa: E402
from steward_hub.tls_identity import (  # noqa: E402
    count_transient_siblings,
    create_rotation_candidate,
    discard_rotation_candidate,
    load_tls_identity,
    provision_or_load_identity,
)
from steward_hub.tls_identity.provisioner import (  # noqa: E402
    OWNER_FILENAME,
    set_provision_inject_hook,
)

PROTOCOL = "pairing_auth/1"
ATTEMPT = "01ARZ3NDEKTSV4RRFFQ69G5FAX"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _rmtree_strict(path: Path, *, attempts: int = 80, delay_s: float = 0.05) -> bool:
    gc.collect()
    for _ in range(attempts):
        if not path.exists():
            return True
        try:
            shutil.rmtree(path, ignore_errors=False)
        except OSError:
            time.sleep(delay_s)
            gc.collect()
            continue
        if not path.exists():
            return True
        time.sleep(delay_s)
    return not path.exists()


def _wait_port(port: int, proc: subprocess.Popen[bytes], timeout: float = 25.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            err = (proc.stderr.read() if proc.stderr else b"").decode(
                "utf-8", errors="replace"
            )
            raise RuntimeError(f"hub_exited:{err[:400]}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("hub_listen_timeout")


def _start_hub(
    *, db: Path, identity: Path, port: int, reply: Path
) -> subprocess.Popen[bytes]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(_SRC)
    reply.unlink(missing_ok=True)
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "steward_hub.https_runtime",
            "--database",
            str(db),
            "--identity-root",
            str(identity),
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--shutdown-stdin",
            "--control-reply",
            str(reply),
        ],
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
    )
    _wait_port(port, proc)
    return proc


def _stop(proc: subprocess.Popen[bytes]) -> bool:
    if proc.poll() is not None:
        return proc.returncode == 0
    if proc.stdin is None:
        return False
    try:
        proc.stdin.write(b"shutdown\n")
        proc.stdin.flush()
        return proc.wait(timeout=15) == 0
    except Exception:  # noqa: BLE001
        proc.kill()
        proc.wait(timeout=5)
        return False


def _wait_reply(path: Path, op: str, timeout: float = 10.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                time.sleep(0.05)
                continue
            if data.get("op") == op:
                path.unlink(missing_ok=True)
                return data
        time.sleep(0.05)
    raise RuntimeError(f"control_timeout:{op}")


def _control(proc: subprocess.Popen[bytes], reply: Path, command: str, op: str) -> dict:
    assert proc.stdin is not None
    reply.unlink(missing_ok=True)
    proc.stdin.write((command + "\n").encode("ascii"))
    proc.stdin.flush()
    data = _wait_reply(reply, op)
    if not data.get("ok"):
        raise RuntimeError(f"control_failed:{data}")
    return data


def run_smoke() -> dict[str, Any]:
    tmp = Path(tempfile.mkdtemp(prefix="b2b-b1-prov-smoke-"))
    identity = tmp / "identity"
    db = tmp / "hub.sqlite3"
    reply = tmp / "control-reply.json"
    report: dict[str, Any] = {"status": "FAIL"}
    try:
        first = provision_or_load_identity(identity)
        loaded = load_tls_identity(identity)
        second = provision_or_load_identity(identity)
        candidate = create_rotation_candidate(identity)
        candidate_diff = (
            candidate.cert_fingerprint_sha256 != first.cert_fingerprint_sha256
        )
        current_unchanged = (
            load_tls_identity(identity).cert_fingerprint_sha256
            == first.cert_fingerprint_sha256
        )
        discard_rotation_candidate(candidate)
        candidate_gone = not candidate.candidate_root.exists()

        # after_publish crash recovery (temp only; never permanent LocalAppData)
        crash_id = tmp / "identity-crash"
        set_provision_inject_hook(
            lambda p: (_ for _ in ()).throw(RuntimeError("smoke_after_rename"))
            if p == "immediately_after_rename"
            else None
        )
        try:
            provision_or_load_identity(crash_id)
            crash_raised = False
        except RuntimeError:
            crash_raised = True
        finally:
            set_provision_inject_hook(None)
        recovered = provision_or_load_identity(crash_id)
        crash_recovery_ok = (
            crash_raised
            and (not recovered.created)
            and (not (crash_id / OWNER_FILENAME).exists())
            and len(recovered.cert_fingerprint_sha256) == 64
        )

        port1 = allocate_loopback_port()
        hub1 = _start_hub(db=db, identity=identity, port=port1, reply=reply)
        wrong_http = -1
        try:
            bad = PinFirstHttpsClient(
                host="127.0.0.1",
                port=port1,
                expected_fingerprint="c" * 64,
            )
            try:
                bad.connect_and_pin()
            except Exception:
                pass
            finally:
                bad.close()
            wrong_http = bad.http_requests_sent
            wrong_attempts = 0
            if db.exists():
                conn = sqlite3.connect(db)
                try:
                    wrong_attempts = int(
                        conn.execute(
                            "SELECT COUNT(*) FROM pairing_attempt"
                        ).fetchone()[0]
                    )
                finally:
                    conn.close()

            with PinFirstHttpsClient(
                host="127.0.0.1",
                port=port1,
                expected_fingerprint=first.cert_fingerprint_sha256,
            ) as client:
                health = client.get("/health")
                ott_raw = b"\x51" * 32
                claim_raw = b"\x52" * 32
                cred_raw = b"\x53" * 32
                ott = _b64url(ott_raw)
                claim = _b64url(claim_raw)
                cred_digest = hashlib.sha256(cred_raw).hexdigest()
                ott_digest = hashlib.sha256(ott_raw).hexdigest()
                created = _control(
                    hub1,
                    reply,
                    f"CREATE_SESSION {ott_digest} 600",
                    "CREATE_SESSION",
                )
                session_id = created["pairing_session_id"]
                body = {
                    "protocol_version": PROTOCOL,
                    "pairing_attempt_id": ATTEMPT,
                    "pairing_token": ott,
                    "claim_secret": claim,
                    "device_credential_digest": cred_digest,
                    "client_nonce": "AAAAAAAAAAAAAAAAAAAAAA",
                    "requested_capabilities": ["session.sync"],
                    "platform": "android",
                    "display_name": "B2BB1Phone",
                }
                h1 = client.post(
                    f"/v1/pairing/sessions/{session_id}/client_hello",
                    headers={"content-type": "application/json"},
                    body=json.dumps(body, separators=(",", ":")).encode("utf-8"),
                )
                h2 = client.post(
                    f"/v1/pairing/sessions/{session_id}/client_hello",
                    headers={"content-type": "application/json"},
                    body=json.dumps(body, separators=(",", ":")).encode("utf-8"),
                )
                hello_ok = (
                    h1.status_code == 200
                    and h2.status_code == 200
                    and h1.json()["device_id"] == h2.json()["device_id"]
                )
                short_code = h1.json()["short_verification_code"]
                _control(
                    hub1,
                    reply,
                    f"HUB_CONFIRM {session_id} {ATTEMPT}",
                    "HUB_CONFIRM",
                )
                confirm = client.post(
                    f"/v1/pairing/sessions/{session_id}/client_confirm",
                    headers={
                        "content-type": "application/json",
                        "authorization": f"Pairing {claim}",
                        "X-DataSteward-Protocol": PROTOCOL,
                    },
                    body=json.dumps(
                        {
                            "protocol_version": PROTOCOL,
                            "pairing_attempt_id": ATTEMPT,
                            "short_verification_code": short_code,
                        },
                        separators=(",", ":"),
                    ).encode("utf-8"),
                )
                active = (
                    confirm.status_code == 200
                    and confirm.json().get("credential_status") == "ACTIVE"
                )
        finally:
            stopped1 = _stop(hub1)

        port2 = allocate_loopback_port()
        hub2 = _start_hub(db=db, identity=identity, port=port2, reply=reply)
        try:
            with PinFirstHttpsClient(
                host="127.0.0.1",
                port=port2,
                expected_fingerprint=first.cert_fingerprint_sha256,
            ) as client2:
                health2 = client2.get("/health")
                restart_health = health2.status_code == 200
        finally:
            stopped2 = _stop(hub2)

        residual_count = count_transient_siblings(tmp)
        marker_count = sum(1 for path in tmp.rglob(OWNER_FILENAME) if path.is_file())
        checks = {
            "first_created": first.created,
            "load_ok": loaded.cert_fingerprint_sha256
            == first.cert_fingerprint_sha256,
            "second_idempotent": (not second.created)
            and second.cert_fingerprint_sha256 == first.cert_fingerprint_sha256,
            "candidate_diff": candidate_diff,
            "current_unchanged_during_candidate": current_unchanged,
            "candidate_gone": candidate_gone,
            "crash_recovery_ok": crash_recovery_ok,
            "residual_count_zero": residual_count == 0,
            "steady_state_marker_zero": marker_count == 0,
            "wrong_pin_zero_http": wrong_http == 0,
            "wrong_pin_zero_attempts": wrong_attempts == 0,
            "hello_ok": hello_ok,
            "active": active,
            "health_ok": health.status_code == 200,
            "restart_health": restart_health,
            "fingerprint_stable": True,
            "hub1_stopped": stopped1,
            "hub2_stopped": stopped2,
            "workers_zero": len(list_alive_pairing_worker_threads()) == 0,
        }
        report = {
            "status": "PASS" if all(checks.values()) else "FAIL",
            "checks": checks,
            "residual_count": residual_count,
            "marker_count": marker_count,
            "fingerprint": first.cert_fingerprint_sha256,
            "hub_id": first.hub_id,
            "cryptography_version": __import__("cryptography").__version__,
        }
    except Exception as exc:  # noqa: BLE001
        report = {"status": "FAIL", "error_type": type(exc).__name__}
    finally:
        removed = _rmtree_strict(tmp)
        report["temp_root_removed"] = removed
        if report.get("status") == "PASS" and not removed:
            report["status"] = "FAIL"
    return report


def main() -> int:
    report = run_smoke()
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
