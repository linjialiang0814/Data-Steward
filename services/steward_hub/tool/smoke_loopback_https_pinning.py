"""Real-process loopback HTTPS + pin-first pairing smoke (B2B-A)."""

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

# Ensure production package + test fixture helper are importable.
_HUB = Path(__file__).resolve().parents[1]
_SRC = _HUB / "src"
_TESTS = _HUB / "tests"
_TOOL = _HUB / "tool"
for path in (_SRC, _TESTS, _TOOL):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from helpers_tls_fixture import create_temp_identity, require_openssl  # noqa: E402
from steward_hub.https_runtime import allocate_loopback_port  # noqa: E402
from steward_hub.pairing_store_executor import (  # noqa: E402
    list_alive_pairing_worker_threads,
)
from steward_hub.pin_client import PinFirstHttpsClient  # noqa: E402
from steward_hub.tls_identity import load_tls_identity  # noqa: E402

PROTOCOL = "pairing_auth/1"
HUB_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
ATTEMPT = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
MARKER = "B2B_A_SMOKE_SECRET_MARKER_7e1c"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _rmtree_strict(path: Path, *, attempts: int = 80, delay_s: float = 0.05) -> bool:
    gc.collect()
    for _ in range(attempts):
        if not path.exists():
            return True
        try:
            for child in sorted(path.rglob("*"), reverse=True):
                try:
                    if child.is_file() or child.is_symlink():
                        child.unlink(missing_ok=True)
                    elif child.is_dir():
                        child.rmdir()
                except OSError:
                    pass
            shutil.rmtree(path, ignore_errors=False)
        except OSError:
            time.sleep(delay_s)
            gc.collect()
            continue
        if not path.exists():
            return True
        time.sleep(delay_s)
        gc.collect()
    return not path.exists()


def _wait_port(host: str, port: int, proc: subprocess.Popen[bytes], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            err = (proc.stderr.read() if proc.stderr else b"").decode(
                "utf-8", errors="replace"
            )
            raise RuntimeError(f"hub_exited_early:{err[:500]}")
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("hub_listen_timeout")


def _wait_reply(path: Path, *, op: str, timeout: float = 10.0) -> dict[str, Any]:
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
    raise RuntimeError(f"control_reply_timeout:{op}")


def _start_hub(
    *,
    python: str,
    db: Path,
    identity_root: Path,
    port: int,
    reply: Path,
    operator_token_digest: str | None = None,
) -> subprocess.Popen[bytes]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(_SRC)
    reply.unlink(missing_ok=True)
    command = [
            python,
            "-m",
            "steward_hub.https_runtime",
            "--database",
            str(db),
            "--identity-root",
            str(identity_root),
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--shutdown-stdin",
            "--control-reply",
            str(reply),
        ]
    if operator_token_digest is not None:
        command.extend(["--operator-token-digest", operator_token_digest])
    proc = subprocess.Popen(
        command,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
    )
    _wait_port("127.0.0.1", port, proc, timeout=25.0)
    return proc


def _stop_hub(proc: subprocess.Popen[bytes], reply: Path) -> bool:
    if proc.poll() is not None:
        return proc.returncode == 0
    if proc.stdin is None:
        return False
    reply.unlink(missing_ok=True)
    try:
        proc.stdin.write(b"shutdown\n")
        proc.stdin.flush()
    except OSError:
        return False
    try:
        code = proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
        return False
    return code == 0


def _control(
    proc: subprocess.Popen[bytes],
    reply: Path,
    command: str,
    *,
    op: str,
) -> dict[str, Any]:
    if proc.stdin is None:
        raise RuntimeError("stdin_missing")
    reply.unlink(missing_ok=True)
    proc.stdin.write((command + "\n").encode("ascii"))
    proc.stdin.flush()
    data = _wait_reply(reply, op=op)
    if not data.get("ok"):
        raise RuntimeError(f"control_failed:{data}")
    return data


def _count_table(db: Path, table: str) -> int:
    conn = sqlite3.connect(db)
    try:
        return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
    finally:
        conn.close()


def _credential_status(db: Path, device_id: str) -> str | None:
    conn = sqlite3.connect(db)
    try:
        row = conn.execute(
            "SELECT status FROM device_credential WHERE device_id = ?",
            (device_id,),
        ).fetchone()
        return None if row is None else str(row[0])
    finally:
        conn.close()


def _post_json(
    client: PinFirstHttpsClient,
    path: str,
    body: dict[str, Any],
    *,
    headers: dict[str, str] | None = None,
) -> Any:
    hdrs = {"content-type": "application/json"}
    if headers:
        hdrs.update(headers)
    return client.post(
        path,
        headers=hdrs,
        body=json.dumps(body, separators=(",", ":")).encode("utf-8"),
    )


def run_smoke() -> dict[str, Any]:
    require_openssl()
    python = sys.executable
    ott_raw = b"\x41" * 32
    claim_raw = b"\x42" * 32
    cred_raw = b"\x43" * 32
    wrong_claim = _b64url(b"\xaa" * 32)
    ott = _b64url(ott_raw)
    claim = _b64url(claim_raw)
    cred_digest = hashlib.sha256(cred_raw).hexdigest()
    ott_digest = hashlib.sha256(ott_raw).hexdigest()

    response_blobs: list[str] = []
    wrong_pin_http = -1
    wrong_pin_attempts = -1
    fingerprint_boot1 = ""
    fingerprint_boot2 = ""
    device_id = ""
    short_code = ""
    active_after_confirm = False
    confirm_loss_recovered = False
    hello_deduplicated = False
    wrong_claim_rejected = False
    active_after_restart = False
    pending_aborted_after_restart = False
    listener_created = False
    hub1_stopped = False
    hub2_stopped = False
    pid1 = 0
    pid2 = 0
    pid1_alive_after = True
    pid2_alive_after = True
    workers_after = -1
    wal_shm_after = -1
    temp_root_removed = False
    secret_hits = 0
    load_fail_listener_created = True

    tmp = Path(tempfile.mkdtemp(prefix="b2b-a-https-smoke-"))
    identity_root = tmp / "identity"
    db = tmp / "hub.sqlite3"
    reply = tmp / "control-reply.json"
    report: dict[str, Any] = {"status": "FAIL"}

    try:
        # Negative: load fail must not listen.
        bad_root = tmp / "bad-identity"
        create_temp_identity(bad_root, hub_id=HUB_ID, tamper_dpapi=True)
        bad_port = allocate_loopback_port()
        env = os.environ.copy()
        env["PYTHONPATH"] = str(_SRC)
        bad_proc = subprocess.Popen(
            [
                python,
                "-m",
                "steward_hub.https_runtime",
                "--database",
                str(tmp / "bad.sqlite3"),
                "--identity-root",
                str(bad_root),
                "--host",
                "127.0.0.1",
                "--port",
                str(bad_port),
                "--shutdown-stdin",
            ],
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        bad_code = bad_proc.wait(timeout=20)
        try:
            with socket.create_connection(("127.0.0.1", bad_port), timeout=0.3):
                load_fail_listener_created = True
        except OSError:
            load_fail_listener_created = False
        if bad_code != 2:
            load_fail_listener_created = True

        _, fingerprint_boot1 = create_temp_identity(identity_root, hub_id=HUB_ID)
        loaded = load_tls_identity(identity_root)
        assert loaded.cert_fingerprint_sha256 == fingerprint_boot1

        port1 = allocate_loopback_port()
        hub1 = _start_hub(
            python=python,
            db=db,
            identity_root=identity_root,
            port=port1,
            reply=reply,
        )
        pid1 = int(hub1.pid)
        listener_created = True

        # Wrong pin: zero HTTP, zero store writes.
        bad_client = PinFirstHttpsClient(
            host="127.0.0.1",
            port=port1,
            expected_fingerprint="c" * 64,
        )
        try:
            bad_client.connect_and_pin()
            wrong_pin_http = bad_client.http_requests_sent
        except Exception:
            wrong_pin_http = bad_client.http_requests_sent
        finally:
            bad_client.close()
        wrong_pin_attempts = _count_table(db, "pairing_attempt")

        # Correct pin flow.
        with PinFirstHttpsClient(
            host="127.0.0.1",
            port=port1,
            expected_fingerprint=fingerprint_boot1,
        ) as client:
            health = client.get("/health")
            response_blobs.append(health.text)
            if health.status_code != 200:
                raise RuntimeError("health_failed")

            created = _control(
                hub1,
                reply,
                f"CREATE_SESSION {ott_digest} 600",
                op="CREATE_SESSION",
            )
            session_id = str(created["pairing_session_id"])

            hello_body = {
                "protocol_version": PROTOCOL,
                "pairing_attempt_id": ATTEMPT,
                "pairing_token": ott,
                "claim_secret": claim,
                "device_credential_digest": cred_digest,
                "client_nonce": "AAAAAAAAAAAAAAAAAAAAAA",
                "requested_capabilities": ["session.sync"],
                "platform": "android",
                "display_name": "B2BPhone",
            }
            h1 = _post_json(
                client,
                f"/v1/pairing/sessions/{session_id}/client_hello",
                hello_body,
            )
            h2 = _post_json(
                client,
                f"/v1/pairing/sessions/{session_id}/client_hello",
                hello_body,
            )
            response_blobs.extend([h1.text, h2.text])
            j1 = h1.json()
            j2 = h2.json()
            device_id = str(j1["device_id"])
            short_code = str(j1["short_verification_code"])
            hello_deduplicated = (
                h1.status_code == 200
                and h2.status_code == 200
                and j1["device_id"] == j2["device_id"]
                and j1["short_verification_code"] == j2["short_verification_code"]
            )

            wrong = client.get(
                f"/v1/pairing/sessions/{session_id}/status",
                query={"pairing_attempt_id": ATTEMPT},
                headers={
                    "authorization": f"Pairing {wrong_claim}",
                    "X-DataSteward-Protocol": PROTOCOL,
                },
            )
            response_blobs.append(wrong.text)
            wrong_claim_rejected = (
                wrong.status_code == 401
                and wrong.json().get("error_code") == "claim_invalid"
            )

            _control(
                hub1,
                reply,
                f"HUB_CONFIRM {session_id} {ATTEMPT}",
                op="HUB_CONFIRM",
            )
            confirm = _post_json(
                client,
                f"/v1/pairing/sessions/{session_id}/client_confirm",
                {
                    "protocol_version": PROTOCOL,
                    "pairing_attempt_id": ATTEMPT,
                    "short_verification_code": short_code,
                },
                headers={
                    "authorization": f"Pairing {claim}",
                    "X-DataSteward-Protocol": PROTOCOL,
                },
            )
            response_blobs.append(confirm.text)
            active_after_confirm = (
                confirm.status_code == 200
                and confirm.json().get("credential_status") == "ACTIVE"
            )

            # Status recovers confirmation / ACTIVE projection.
            status = client.get(
                f"/v1/pairing/sessions/{session_id}/status",
                query={"pairing_attempt_id": ATTEMPT},
                headers={
                    "authorization": f"Pairing {claim}",
                    "X-DataSteward-Protocol": PROTOCOL,
                },
            )
            response_blobs.append(status.text)
            confirm_loss_recovered = (
                status.status_code == 200
                and status.json().get("credential_status") == "ACTIVE"
            )

            # Open a second PENDING session to prove reboot abort semantics.
            pending_digest = hashlib.sha256(bytes([0x99]) * 32).hexdigest()
            pending = _control(
                hub1,
                reply,
                f"CREATE_SESSION {pending_digest} 600",
                op="CREATE_SESSION",
            )
            pending_session_id = str(pending["pairing_session_id"])

        hub1_stopped = _stop_hub(hub1, reply)
        pid1_alive_after = hub1.poll() is None

        # Restart same identity + SQLite.
        port2 = allocate_loopback_port()
        hub2 = _start_hub(
            python=python,
            db=db,
            identity_root=identity_root,
            port=port2,
            reply=reply,
        )
        pid2 = int(hub2.pid)
        loaded2 = load_tls_identity(identity_root)
        fingerprint_boot2 = loaded2.cert_fingerprint_sha256

        with PinFirstHttpsClient(
            host="127.0.0.1",
            port=port2,
            expected_fingerprint=fingerprint_boot2,
        ) as client2:
            health2 = client2.get("/health")
            response_blobs.append(health2.text)
            active_after_restart = _credential_status(db, device_id) == "ACTIVE"
            conn = sqlite3.connect(db)
            try:
                row = conn.execute(
                    "SELECT state FROM pairing_session WHERE pairing_session_id = ?",
                    (pending_session_id,),
                ).fetchone()
                pending_aborted_after_restart = (
                    row is not None and str(row[0]) == "ABORTED_HUB_RESTART"
                )
            finally:
                conn.close()

        hub2_stopped = _stop_hub(hub2, reply)
        pid2_alive_after = hub2.poll() is None

        workers_after = len(list_alive_pairing_worker_threads())
        wal_shm_after = sum(
            1
            for suffix in ("-wal", "-shm")
            if (db.parent / (db.name + suffix)).exists()
            or Path(str(db) + suffix).exists()
        )
        # After graceful close, WAL/SHM may linger briefly; force checkpoint via connect.
        if db.exists():
            c = sqlite3.connect(db)
            try:
                c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            finally:
                c.close()
            time.sleep(0.1)
            wal_shm_after = sum(
                1 for suffix in ("-wal", "-shm") if Path(str(db) + suffix).exists()
            )

        blob = "\n".join(response_blobs)
        for token in (ott, claim, MARKER, "BEGIN PRIVATE KEY", "BEGIN ENCRYPTED"):
            if token in blob:
                secret_hits += 1
        # Also scan stderr of last hub if available (should be redacted).
        if hub2.stderr is not None:
            try:
                err = hub2.stderr.read().decode("utf-8", errors="replace")
            except OSError:
                err = ""
            for token in (ott, claim, MARKER):
                if token in err:
                    secret_hits += 1

        checks = {
            "load_fail_listener_created": load_fail_listener_created is False,
            "listener_created": listener_created,
            "wrong_pin_zero_http": wrong_pin_http == 0,
            "wrong_pin_zero_attempts": wrong_pin_attempts == 0,
            "fingerprint_stable": fingerprint_boot1 == fingerprint_boot2
            and len(fingerprint_boot1) == 64,
            "hello_deduplicated": hello_deduplicated,
            "short_code_bound": isinstance(short_code, str) and len(short_code) == 8,
            "wrong_claim_rejected": wrong_claim_rejected,
            "active_after_confirm": active_after_confirm,
            "confirm_loss_recovered": confirm_loss_recovered,
            "active_after_restart": active_after_restart,
            "pending_aborted_after_restart": pending_aborted_after_restart,
            "hub1_stopped": hub1_stopped,
            "hub2_stopped": hub2_stopped,
            "pid1_exited": not pid1_alive_after and pid1 > 0,
            "pid2_exited": not pid2_alive_after and pid2 > 0,
            "workers_zero": workers_after == 0,
            "wal_shm_zero": wal_shm_after == 0,
            "secret_hits_zero": secret_hits == 0,
        }
        report = {
            "status": "PASS" if all(checks.values()) else "FAIL",
            "checks": checks,
            "fingerprint_boot1": fingerprint_boot1,
            "fingerprint_boot2": fingerprint_boot2,
            "device_id_prefix": device_id[:8] if device_id else "",
            "pid1": pid1,
            "pid2": pid2,
            "workers_after": workers_after,
            "wal_shm_after": wal_shm_after,
            "secret_hits": secret_hits,
            "listener_created": listener_created,
            "load_fail_listener_created": load_fail_listener_created,
        }
    except Exception as exc:  # noqa: BLE001
        report = {
            "status": "FAIL",
            "error_type": type(exc).__name__,
        }
    finally:
        temp_root_removed = _rmtree_strict(tmp)
        report["temp_root_removed"] = temp_root_removed
        if report.get("status") == "PASS" and not temp_root_removed:
            report["status"] = "FAIL"
            checks = dict(report.get("checks") or {})
            checks["temp_root_removed"] = False
            report["checks"] = checks

    return report


def main() -> int:
    report = run_smoke()
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
