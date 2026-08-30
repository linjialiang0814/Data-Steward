"""Real-process B3C capability epoch and connected revoke acceptance."""

from __future__ import annotations

import gc
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

_HUB = Path(__file__).resolve().parents[1]
_SRC = _HUB / "src"
_TESTS = _HUB / "tests"
_TOOL = _HUB / "tool"
for import_path in (_SRC, _TESTS, _TOOL):
    if str(import_path) not in sys.path:
        sys.path.insert(0, str(import_path))

from helpers_tls_fixture import create_temp_identity, require_openssl  # noqa: E402
from smoke_authenticated_wss import (  # noqa: E402
    ATTEMPT_ID,
    CONVERSATION_ID,
    HUB_ID,
    _activate_device,
    _auth_headers,
    _b64url,
    _force_stop_owned,
    _post_business_json,
    _stop_hub_with_snapshot,
)
from smoke_loopback_https_pinning import _post_json, _start_hub  # noqa: E402
from steward_hub.https_runtime import allocate_loopback_port  # noqa: E402
from steward_hub.pin_client import PinFirstHttpsClient  # noqa: E402
from steward_hub.pin_websocket_client import (  # noqa: E402
    PinFirstWebSocketClient,
    PinFirstWebSocketError,
)

PROTOCOL = "pairing_auth/1"


def _rmtree_strict(path: Path, *, attempts: int = 80) -> bool:
    gc.collect()
    for _ in range(attempts):
        if not path.exists():
            return True
        try:
            shutil.rmtree(path, ignore_errors=False)
        except OSError:
            time.sleep(0.05)
            gc.collect()
            continue
        if not path.exists():
            return True
    return not path.exists()


def _operator_request(
    client: PinFirstHttpsClient,
    *,
    method: str,
    path: str,
    operator_secret: str,
    body: dict[str, Any],
) -> tuple[int, dict[str, Any]]:
    payload = json.dumps(
        body,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    response = client.request(
        method,
        path,
        headers={
            "authorization": f"DataSteward-Operator {operator_secret}",
            "X-DataSteward-Protocol": PROTOCOL,
            "content-type": "application/json",
        },
        body=payload,
    )
    value = response.json()
    if not isinstance(value, dict):
        raise RuntimeError("operator_response_invalid")
    return response.status_code, value


def _open_ready_wss(
    *,
    port: int,
    fingerprint: str,
    device_id: str,
    credential: str,
    epoch: int,
) -> PinFirstWebSocketClient:
    client = PinFirstWebSocketClient(
        host="127.0.0.1",
        port=port,
        expected_fingerprint=fingerprint,
    )
    client.connect(
        f"/v1/conversations/{CONVERSATION_ID}/events/ws?after_seq=0"
    )
    client.send_auth(
        device_id=device_id,
        capability_epoch=epoch,
        credential=credential,
    )
    if client.receive_json().get("kind") != "auth_ok":
        raise RuntimeError("auth_ok_missing")
    ready = client.receive_json()
    if ready != {"kind": "ready", "last_conversation_seq": 0}:
        raise RuntimeError("ready_invalid")
    return client


def _closed_without_frame(client: PinFirstWebSocketClient) -> bool:
    try:
        client.receive_json(timeout_s=5)
    except PinFirstWebSocketError:
        return True
    return False


def _auth_failure_code(
    *,
    port: int,
    fingerprint: str,
    device_id: str,
    credential: str,
    epoch: int,
) -> str | None:
    client = PinFirstWebSocketClient(
        host="127.0.0.1",
        port=port,
        expected_fingerprint=fingerprint,
    )
    try:
        try:
            client.connect(
                f"/v1/conversations/{CONVERSATION_ID}/events/ws?after_seq=0"
            )
            client.send_auth(
                device_id=device_id,
                capability_epoch=epoch,
                credential=credential,
            )
            frame = client.receive_json()
        except PinFirstWebSocketError:
            return "transport_error"
        if frame.get("kind") != "auth_failed":
            return None
        return str(frame.get("error_code"))
    finally:
        client.close()


def run_smoke() -> dict[str, Any]:
    require_openssl()
    root = Path(tempfile.mkdtemp(prefix="b3c-live-transition-"))
    identity_root = root / "identity"
    database = root / "hub.sqlite3"
    reply = root / "control.json"
    hub1: subprocess.Popen[bytes] | None = None
    hub2: subprocess.Popen[bytes] | None = None
    sockets: list[PinFirstWebSocketClient] = []
    report: dict[str, Any] = {"status": "FAIL"}
    stage = "setup"
    stderr_blobs: list[str] = []
    secret_markers: list[str] = []
    try:
        stage = "identity"
        _, fingerprint = create_temp_identity(identity_root, hub_id=HUB_ID)
        ott = _b64url(b"\x81" * 32)
        claim = _b64url(b"\x82" * 32)
        credential = _b64url(b"\x83" * 32)
        operator_secret = _b64url(b"\x84" * 32)
        wrong_credential = _b64url(b"\x85" * 32)
        secret_markers.extend(
            (ott, claim, credential, operator_secret, wrong_credential)
        )
        operator_digest = hashlib.sha256(b"\x84" * 32).hexdigest()
        credential_digest = hashlib.sha256(b"\x83" * 32).hexdigest()

        stage = "hub1_start"
        port1 = allocate_loopback_port()
        hub1 = _start_hub(
            python=sys.executable,
            db=database,
            identity_root=identity_root,
            port=port1,
            reply=reply,
            operator_token_digest=operator_digest,
        )
        stage = "pairing"
        device_id = _activate_device(
            hub=hub1,
            reply=reply,
            port=port1,
            fingerprint=fingerprint,
            ott=ott,
            claim=claim,
            credential_digest=credential_digest,
            requested_capabilities=["profile.read", "session.sync"],
        )
        epoch1_headers = _auth_headers(credential, device_id)
        stage = "conversation_create"
        with PinFirstHttpsClient(
            host="127.0.0.1",
            port=port1,
            expected_fingerprint=fingerprint,
        ) as rest:
            _post_business_json(
                rest,
                "/v1/conversations",
                {
                    "title": "B3C live transition",
                    "conversation_id": CONVERSATION_ID,
                },
                headers=epoch1_headers,
            )

        stage = "epoch_wss_a"
        wss_a = _open_ready_wss(
            port=port1,
            fingerprint=fingerprint,
            device_id=device_id,
            credential=credential,
            epoch=1,
        )
        stage = "epoch_wss_b"
        wss_b = _open_ready_wss(
            port=port1,
            fingerprint=fingerprint,
            device_id=device_id,
            credential=credential,
            epoch=1,
        )
        sockets.extend((wss_a, wss_b))

        stage = "epoch_update"
        with PinFirstHttpsClient(
            host="127.0.0.1",
            port=port1,
            expected_fingerprint=fingerprint,
        ) as operator:
            epoch_status, epoch_body = _operator_request(
                operator,
                method="PUT",
                path=f"/v1/operator/devices/{device_id}/capabilities",
                operator_secret=operator_secret,
                body={
                    "expected_capability_epoch": 1,
                    "granted_capabilities": ["profile.read", "session.sync"],
                },
            )
        stage = "epoch_close_observe"
        epoch_sockets_closed = (
            _closed_without_frame(wss_a) and _closed_without_frame(wss_b)
        )
        stage = "old_epoch_wss"
        old_wss_error = _auth_failure_code(
            port=port1,
            fingerprint=fingerprint,
            device_id=device_id,
            credential=credential,
            epoch=1,
        )
        epoch2_headers = dict(epoch1_headers)
        epoch2_headers["X-DataSteward-Capability-Epoch"] = "2"
        stage = "epoch_rest_classification"
        with PinFirstHttpsClient(
            host="127.0.0.1",
            port=port1,
            expected_fingerprint=fingerprint,
        ) as rest:
            stale_rest = rest.get(
                f"/v1/conversations/{CONVERSATION_ID}/events",
                query={"after_seq": "0", "limit": "10"},
                headers=epoch1_headers,
            )
            new_epoch_rest = rest.get(
                f"/v1/conversations/{CONVERSATION_ID}/events",
                query={"after_seq": "0", "limit": "10"},
                headers=epoch2_headers,
            )

        stage = "epoch2_wss"
        wss_epoch2 = _open_ready_wss(
            port=port1,
            fingerprint=fingerprint,
            device_id=device_id,
            credential=credential,
            epoch=2,
        )
        sockets.append(wss_epoch2)
        stage = "revoke"
        with PinFirstHttpsClient(
            host="127.0.0.1",
            port=port1,
            expected_fingerprint=fingerprint,
        ) as operator:
            revoke_status, revoke_body = _operator_request(
                operator,
                method="POST",
                path=f"/v1/operator/devices/{device_id}/revoke",
                operator_secret=operator_secret,
                body={"expected_capability_epoch": 2},
            )
        stage = "revoke_close_observe"
        revoke_socket_closed = _closed_without_frame(wss_epoch2)

        stage = "revoke_rest_classification"
        with PinFirstHttpsClient(
            host="127.0.0.1",
            port=port1,
            expected_fingerprint=fingerprint,
        ) as rest:
            revoked_rest = rest.get(
                f"/v1/conversations/{CONVERSATION_ID}/events",
                query={"after_seq": "0", "limit": "10"},
                headers=epoch2_headers,
            )
            wrong_headers = _auth_headers(wrong_credential, device_id)
            wrong_headers["X-DataSteward-Capability-Epoch"] = "2"
            wrong_rest = rest.get(
                f"/v1/conversations/{CONVERSATION_ID}/events",
                query={"after_seq": "0", "limit": "10"},
                headers=wrong_headers,
            )

        stage = "hub1_stop"
        stopped1, shutdown1 = _stop_hub_with_snapshot(hub1, reply)
        if hub1.stderr is not None:
            stderr_blobs.append(
                hub1.stderr.read().decode("utf-8", errors="replace")
            )

        stage = "hub2_start"
        port2 = allocate_loopback_port()
        hub2 = _start_hub(
            python=sys.executable,
            db=database,
            identity_root=identity_root,
            port=port2,
            reply=reply,
            operator_token_digest=operator_digest,
        )
        stage = "restart_revoke_classification"
        restart_revoked = _auth_failure_code(
            port=port2,
            fingerprint=fingerprint,
            device_id=device_id,
            credential=credential,
            epoch=2,
        )
        stage = "hub2_stop"
        stopped2, shutdown2 = _stop_hub_with_snapshot(hub2, reply)
        if hub2.stderr is not None:
            stderr_blobs.append(
                hub2.stderr.read().decode("utf-8", errors="replace")
            )

        shutdowns = (shutdown1, shutdown2)
        shutdown_zero = all(
            item.get(key) == 0
            for item in shutdowns
            for key in (
                "handshake_count",
                "connection_count",
                "operation_count",
                "subscription_count",
                "worker_count",
            )
        )
        database_bytes = database.read_bytes()
        secret_hit_count = sum(
            marker in stderr
            for marker in secret_markers
            for stderr in stderr_blobs
        ) + sum(
            database_bytes.count(marker.encode("ascii"))
            for marker in secret_markers
        )
        checks = {
            "epoch_http_ok": epoch_status == 200,
            "epoch_incremented_once": (
                epoch_body.get("changed") is True
                and epoch_body.get("capability_epoch") == 2
                and epoch_body.get("closed_connection_count") == 2
            ),
            "epoch_sockets_closed": epoch_sockets_closed,
            "old_epoch_rest_stale": (
                stale_rest.status_code == 409
                and stale_rest.json().get("error_code")
                == "capability_epoch_stale"
            ),
            "old_epoch_wss_stale": old_wss_error == "capability_epoch_stale",
            "new_epoch_rest_ok": new_epoch_rest.status_code == 200,
            "revoke_http_ok": revoke_status == 200,
            "revoked_once": (
                revoke_body.get("changed") is True
                and revoke_body.get("status") == "REVOKED"
                and revoke_body.get("closed_connection_count") == 1
            ),
            "revoke_socket_closed": revoke_socket_closed,
            "correct_secret_revoked": (
                revoked_rest.status_code == 401
                and revoked_rest.json().get("error_code") == "auth_revoked"
            ),
            "wrong_secret_invalid": (
                wrong_rest.status_code == 401
                and wrong_rest.json().get("error_code") == "auth_invalid"
            ),
            "restart_revoked": restart_revoked == "auth_revoked",
            "shutdown_zero": shutdown_zero,
            "processes_stopped": stopped1 and stopped2,
            "secret_hits_zero": secret_hit_count == 0,
        }
        semantic = json.dumps(checks, separators=(",", ":"), sort_keys=True)
        report = {
            "status": "PASS" if all(checks.values()) else "FAIL",
            "process_start_count": 2,
            "graceful_stop_count": int(stopped1) + int(stopped2),
            "leaked_process_count": int(hub1.poll() is None)
            + int(hub2.poll() is None),
            "epoch_closed_connection_count": epoch_body.get(
                "closed_connection_count"
            ),
            "revoke_closed_connection_count": revoke_body.get(
                "closed_connection_count"
            ),
            "old_epoch_rest_code": stale_rest.json().get("error_code"),
            "old_epoch_wss_code": old_wss_error,
            "revoked_rest_code": revoked_rest.json().get("error_code"),
            "wrong_secret_code": wrong_rest.json().get("error_code"),
            "restart_wss_code": restart_revoked,
            "shutdown_residual_count": sum(
                int(item.get(key, -1))
                for item in shutdowns
                for key in (
                    "handshake_count",
                    "connection_count",
                    "operation_count",
                    "subscription_count",
                    "worker_count",
                )
            ),
            "secret_hit_count": secret_hit_count,
            "semantic_projection_hash": hashlib.sha256(
                semantic.encode("utf-8")
            ).hexdigest(),
            "loopback_only": True,
        }
    except Exception as exc:  # noqa: BLE001
        report = {
            "status": "FAIL",
            "error_type": type(exc).__name__,
            "failure_stage": stage,
        }
    finally:
        for client in sockets:
            client.close()
        _force_stop_owned(hub1)
        _force_stop_owned(hub2)
        removed = _rmtree_strict(root)
        report["temp_residual_count"] = int(not removed)
        if report.get("status") == "PASS" and not removed:
            report["status"] = "FAIL"
    return report


def main() -> int:
    report = run_smoke()
    print(json.dumps(report, separators=(",", ":"), sort_keys=True))
    return 0 if report.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
