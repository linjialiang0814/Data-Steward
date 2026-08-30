"""Real-process pin-first authenticated WSS convergence Smoke (B3B-B2)."""

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
_SRC = _HUB / "src"
_TESTS = _HUB / "tests"
_TOOL = _HUB / "tool"
for import_path in (_SRC, _TESTS, _TOOL):
    if str(import_path) not in sys.path:
        sys.path.insert(0, str(import_path))

from helpers_tls_fixture import create_temp_identity, require_openssl  # noqa: E402
from smoke_loopback_https_pinning import (  # noqa: E402
    _control,
    _post_json,
    _start_hub,
)
from steward_hub.api import wire_event  # noqa: E402
from steward_hub.https_runtime import allocate_loopback_port  # noqa: E402
from steward_hub.pin_client import PinFirstHttpsClient  # noqa: E402
from steward_hub.pin_websocket_client import PinFirstWebSocketClient  # noqa: E402
from steward_hub.store import EventStore  # noqa: E402
from steward_hub.tls_identity.errors import TlsPinError  # noqa: E402

PROTOCOL = "pairing_auth/1"
HUB_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
ATTEMPT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
CONVERSATION_ID = "b3b-authenticated-wss-smoke"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


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


def _auth_headers(credential: str, device_id: str) -> dict[str, str]:
    return {
        "authorization": f"Bearer {credential}",
        "X-DataSteward-Protocol": PROTOCOL,
        "X-DataSteward-Device-Id": device_id,
        "X-DataSteward-Capability-Epoch": "1",
    }


def _activate_device(
    *,
    hub: subprocess.Popen[bytes],
    reply: Path,
    port: int,
    fingerprint: str,
    ott: str,
    claim: str,
    credential_digest: str,
    requested_capabilities: list[str] | None = None,
) -> str:
    ott_digest = hashlib.sha256(
        base64.urlsafe_b64decode(ott + "=" * (-len(ott) % 4))
    ).hexdigest()
    with PinFirstHttpsClient(
        host="127.0.0.1",
        port=port,
        expected_fingerprint=fingerprint,
    ) as client:
        created = _control(
            hub,
            reply,
            f"CREATE_SESSION {ott_digest} 600",
            op="CREATE_SESSION",
        )
        session_id = str(created["pairing_session_id"])
        hello = _post_json(
            client,
            f"/v1/pairing/sessions/{session_id}/client_hello",
            {
                "protocol_version": PROTOCOL,
                "pairing_attempt_id": ATTEMPT_ID,
                "pairing_token": ott,
                "claim_secret": claim,
                "device_credential_digest": credential_digest,
                "client_nonce": "AAAAAAAAAAAAAAAAAAAAAA",
                "requested_capabilities": (
                    requested_capabilities or ["session.sync"]
                ),
                "platform": "android",
                "display_name": "B3B Smoke",
            },
        )
        if hello.status_code != 200:
            raise RuntimeError("pairing_hello_failed")
        body = hello.json()
        device_id = str(body["device_id"])
        short_code = str(body["short_verification_code"])
        _control(
            hub,
            reply,
            f"HUB_CONFIRM {session_id} {ATTEMPT_ID}",
            op="HUB_CONFIRM",
        )
        confirmed = _post_json(
            client,
            f"/v1/pairing/sessions/{session_id}/client_confirm",
            {
                "protocol_version": PROTOCOL,
                "pairing_attempt_id": ATTEMPT_ID,
                "short_verification_code": short_code,
            },
            headers={
                "authorization": f"Pairing {claim}",
                "X-DataSteward-Protocol": PROTOCOL,
            },
        )
        if (
            confirmed.status_code != 200
            or confirmed.json().get("credential_status") != "ACTIVE"
        ):
            raise RuntimeError("pairing_confirm_failed")
        return device_id


def _last_auth_at(database: Path, device_id: str) -> str | None:
    connection = sqlite3.connect(database)
    try:
        row = connection.execute(
            "SELECT last_auth_at FROM device_credential WHERE device_id = ?",
            (device_id,),
        ).fetchone()
        return None if row is None or row[0] is None else str(row[0])
    finally:
        connection.close()


def _post_business_json(
    client: PinFirstHttpsClient,
    path: str,
    body: dict[str, Any],
    *,
    headers: dict[str, str],
) -> dict[str, Any]:
    response = _post_json(client, path, body, headers=headers)
    if response.status_code not in {200, 201}:
        raise RuntimeError("business_post_failed")
    value = response.json()
    if not isinstance(value, dict):
        raise RuntimeError("business_response_invalid")
    return value


def _append_message(
    client: PinFirstHttpsClient,
    *,
    headers: dict[str, str],
    device_id: str,
    sequence: int,
) -> dict[str, Any]:
    return _post_business_json(
        client,
        f"/v1/conversations/{CONVERSATION_ID}/messages",
        {
            "client_message_id": f"b3b-client-{sequence}",
            "actor_device_id": device_id,
            "role": "user",
            "content": f"b3b-message-{sequence}",
        },
        headers=headers,
    )


def _event_from_frame(frame: dict[str, Any], delivery: str, seq: int) -> dict[str, Any]:
    if frame.get("kind") != "event" or frame.get("delivery") != delivery:
        raise RuntimeError("wss_event_order_invalid")
    event = frame.get("event")
    if not isinstance(event, dict) or event.get("conversation_seq") != seq:
        raise RuntimeError("wss_event_sequence_invalid")
    return event


def _semantic_projection_hash(events: list[dict[str, Any]]) -> str:
    by_sequence: dict[int, dict[str, Any]] = {}
    for event in events:
        sequence = event.get("conversation_seq")
        payload = event.get("payload")
        if not isinstance(sequence, int) or not isinstance(payload, dict):
            raise RuntimeError("event_projection_invalid")
        projection = {
            # The Hub issues a random device ULID on every hermetic run. This
            # one-device Smoke normalizes that identity while retaining all
            # stable message semantics, so independent runs have equal hashes.
            "actor_device_role": "paired-device",
            "causation_id": event.get("causation_id"),
            "correlation_id": event.get("correlation_id"),
            "conversation_seq": sequence,
            "event_type": event.get("event_type"),
            "payload": {
                field: payload.get(field)
                for field in ("accepted_seq", "client_message_id", "content", "role")
            },
            "protocol_version": event.get("protocol_version"),
        }
        existing = by_sequence.get(sequence)
        if existing is not None and existing != projection:
            raise RuntimeError("event_projection_conflict")
        by_sequence[sequence] = projection
    canonical = json.dumps(
        [by_sequence[key] for key in sorted(by_sequence)],
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _stop_hub_with_snapshot(
    process: subprocess.Popen[bytes],
    reply: Path,
) -> tuple[bool, dict[str, Any]]:
    if process.poll() is not None or process.stdin is None:
        return False, {}
    reply.unlink(missing_ok=True)
    try:
        process.stdin.write(b"shutdown\n")
        process.stdin.flush()
        return_code = process.wait(timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        process.kill()
        process.wait(timeout=5)
        return False, {}
    try:
        snapshot = json.loads(reply.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False, {}
    return return_code == 0 and snapshot.get("op") == "shutdown_complete", snapshot


def _force_stop_owned(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.kill()
    process.wait(timeout=5)


def run_smoke() -> dict[str, Any]:
    require_openssl()
    temporary_root = Path(tempfile.mkdtemp(prefix="b3b-auth-wss-"))
    identity_root = temporary_root / "identity"
    database = temporary_root / "hub.sqlite3"
    reply = temporary_root / "control.json"
    hub1: subprocess.Popen[bytes] | None = None
    hub2: subprocess.Popen[bytes] | None = None
    report: dict[str, Any] = {"status": "FAIL"}
    secret_markers: list[str] = []
    stderr_blobs: list[str] = []

    try:
        _, fingerprint = create_temp_identity(identity_root, hub_id=HUB_ID)
        ott = _b64url(b"\x71" * 32)
        claim = _b64url(b"\x72" * 32)
        credential = _b64url(b"\x73" * 32)
        secret_markers.extend((ott, claim, credential))
        credential_digest = hashlib.sha256(b"\x73" * 32).hexdigest()

        port1 = allocate_loopback_port()
        hub1 = _start_hub(
            python=sys.executable,
            db=database,
            identity_root=identity_root,
            port=port1,
            reply=reply,
        )
        device_id = _activate_device(
            hub=hub1,
            reply=reply,
            port=port1,
            fingerprint=fingerprint,
            ott=ott,
            claim=claim,
            credential_digest=credential_digest,
        )

        auth_before_wrong_pin = _last_auth_at(database, device_id)
        wrong_fingerprint = ("0" if fingerprint[0] != "0" else "1") + fingerprint[1:]
        wrong_pin = PinFirstWebSocketClient(
            host="127.0.0.1",
            port=port1,
            expected_fingerprint=wrong_fingerprint,
        )
        try:
            wrong_pin.connect(
                f"/v1/conversations/{CONVERSATION_ID}/events/ws?after_seq=0"
            )
            raise RuntimeError("wrong_pin_connected")
        except TlsPinError:
            pass
        finally:
            wrong_pin.close()
        auth_after_wrong_pin = _last_auth_at(database, device_id)

        auth_headers = _auth_headers(credential, device_id)
        submitted_count = 0
        deduplicated_count = 0
        with PinFirstHttpsClient(
            host="127.0.0.1",
            port=port1,
            expected_fingerprint=fingerprint,
        ) as rest1:
            _post_business_json(
                rest1,
                "/v1/conversations",
                {"title": "B3B Smoke", "conversation_id": CONVERSATION_ID},
                headers=auth_headers,
            )
            for sequence in (1, 2, 2):
                appended = _append_message(
                    rest1,
                    headers=auth_headers,
                    device_id=device_id,
                    sequence=sequence,
                )
                submitted_count += 1
                deduplicated_count += int(bool(appended.get("deduplicated")))

        boot1_events: list[dict[str, Any]] = []
        wss1 = PinFirstWebSocketClient(
            host="127.0.0.1",
            port=port1,
            expected_fingerprint=fingerprint,
        )
        try:
            wss1.connect(
                f"/v1/conversations/{CONVERSATION_ID}/events/ws?after_seq=0"
            )
            wss1.send_auth(
                device_id=device_id,
                capability_epoch=1,
                credential=credential,
            )
            if wss1.receive_json().get("kind") != "auth_ok":
                raise RuntimeError("auth_ok_not_first")
            boot1_events.append(_event_from_frame(wss1.receive_json(), "replay", 1))
            boot1_events.append(_event_from_frame(wss1.receive_json(), "replay", 2))
            ready1 = wss1.receive_json()
            if ready1 != {"kind": "ready", "last_conversation_seq": 2}:
                raise RuntimeError("ready1_invalid")
            with PinFirstHttpsClient(
                host="127.0.0.1",
                port=port1,
                expected_fingerprint=fingerprint,
            ) as rest_live1:
                _append_message(
                    rest_live1,
                    headers=auth_headers,
                    device_id=device_id,
                    sequence=3,
                )
                submitted_count += 1
            boot1_events.append(_event_from_frame(wss1.receive_json(), "live", 3))
        finally:
            wss1.close()

        stopped1, shutdown1 = _stop_hub_with_snapshot(hub1, reply)
        if hub1.stderr is not None:
            stderr_blobs.append(hub1.stderr.read().decode("utf-8", errors="replace"))

        port2 = allocate_loopback_port()
        hub2 = _start_hub(
            python=sys.executable,
            db=database,
            identity_root=identity_root,
            port=port2,
            reply=reply,
        )
        boot2_events: list[dict[str, Any]] = []
        wss2 = PinFirstWebSocketClient(
            host="127.0.0.1",
            port=port2,
            expected_fingerprint=fingerprint,
        )
        try:
            wss2.connect(
                f"/v1/conversations/{CONVERSATION_ID}/events/ws?after_seq=1"
            )
            wss2.send_auth(
                device_id=device_id,
                capability_epoch=1,
                credential=credential,
            )
            if wss2.receive_json().get("kind") != "auth_ok":
                raise RuntimeError("restart_auth_ok_not_first")
            boot2_events.append(_event_from_frame(wss2.receive_json(), "replay", 2))
            boot2_events.append(_event_from_frame(wss2.receive_json(), "replay", 3))
            ready2 = wss2.receive_json()
            if ready2 != {"kind": "ready", "last_conversation_seq": 3}:
                raise RuntimeError("ready2_invalid")
            with PinFirstHttpsClient(
                host="127.0.0.1",
                port=port2,
                expected_fingerprint=fingerprint,
            ) as rest2:
                _append_message(
                    rest2,
                    headers=auth_headers,
                    device_id=device_id,
                    sequence=4,
                )
                submitted_count += 1
            boot2_events.append(_event_from_frame(wss2.receive_json(), "live", 4))
        finally:
            wss2.close()

        with PinFirstHttpsClient(
            host="127.0.0.1",
            port=port2,
            expected_fingerprint=fingerprint,
        ) as rest_final:
            response = rest_final.get(
                f"/v1/conversations/{CONVERSATION_ID}/events",
                query={"after_seq": "0", "limit": "100"},
                headers=auth_headers,
            )
            if response.status_code != 200:
                raise RuntimeError("rest_replay_failed")
            rest_events = response.json().get("events")
            if not isinstance(rest_events, list):
                raise RuntimeError("rest_replay_invalid")

        stopped2, shutdown2 = _stop_hub_with_snapshot(hub2, reply)
        if hub2.stderr is not None:
            stderr_blobs.append(hub2.stderr.read().decode("utf-8", errors="replace"))

        reopened = EventStore(database)
        try:
            reopened_events = [
                wire_event(event).model_dump()
                for event in reopened.replay_events(
                    conversation_id=CONVERSATION_ID,
                    after_seq=0,
                    limit=100,
                )
            ]
            message_count, event_count = reopened.count_records(CONVERSATION_ID)
        finally:
            reopened.close()

        wss_projection = boot1_events + boot2_events
        rest_hash = _semantic_projection_hash(rest_events)
        wss_hash = _semantic_projection_hash(wss_projection)
        reopened_hash = _semantic_projection_hash(reopened_events)
        shutdown_snapshots = (shutdown1, shutdown2)
        shutdown_zero = all(
            snapshot.get(key) == 0
            for snapshot in shutdown_snapshots
            for key in (
                "handshake_count",
                "connection_count",
                "subscription_count",
                "worker_count",
            )
        )
        secret_hit_count = sum(
            marker in blob
            for marker in secret_markers
            for blob in stderr_blobs
        )
        database_bytes = database.read_bytes()
        secret_hit_count += sum(
            database_bytes.count(marker.encode("ascii"))
            for marker in secret_markers
        )
        checks = {
            "wrong_pin_zero_upgrade": wrong_pin.upgrade_attempt_count == 0,
            "wrong_pin_zero_auth_frame": wrong_pin.auth_frame_sent_count == 0,
            "wrong_pin_zero_auth_write": (
                auth_before_wrong_pin == auth_after_wrong_pin
            ),
            "boot1_ordered": [event["conversation_seq"] for event in boot1_events]
            == [1, 2, 3],
            "boot2_ordered": [event["conversation_seq"] for event in boot2_events]
            == [2, 3, 4],
            "stored_four": message_count == event_count == 4,
            "deduplicated_once": submitted_count == 5 and deduplicated_count == 1,
            "converged": rest_hash == wss_hash == reopened_hash,
            "shutdown_zero": shutdown_zero,
            "processes_stopped": stopped1 and stopped2,
            "secret_hits_zero": secret_hit_count == 0,
        }
        report = {
            "status": "PASS" if all(checks.values()) else "FAIL",
            "client_transport": "pin-first-prewrapped-tls-wss",
            "process_start_count": 2,
            "graceful_stop_count": int(stopped1) + int(stopped2),
            "leaked_process_count": int(hub1.poll() is None)
            + int(hub2.poll() is None),
            "wrong_pin_upgrade_attempt_count": wrong_pin.upgrade_attempt_count,
            "wrong_pin_auth_frame_sent_count": wrong_pin.auth_frame_sent_count,
            "wrong_pin_auth_write_count": int(
                auth_before_wrong_pin != auth_after_wrong_pin
            ),
            "submitted_count": submitted_count,
            "stored_count": event_count,
            "deduplicated_count": deduplicated_count,
            "boot1_replay_count": 2,
            "boot1_live_count": 1,
            "boot2_replay_count": 2,
            "boot2_live_count": 1,
            "rest_projection_hash": rest_hash,
            "wss_projection_hash": wss_hash,
            "reopened_projection_hash": reopened_hash,
            "converged": checks["converged"],
            "loopback_only": True,
            "shutdown_residual_count": sum(
                int(snapshot.get(key, -1))
                for snapshot in shutdown_snapshots
                for key in (
                    "handshake_count",
                    "connection_count",
                    "subscription_count",
                    "worker_count",
                )
            ),
            "secret_hit_count": secret_hit_count,
        }
    except Exception as exc:  # noqa: BLE001
        report = {"status": "FAIL", "error_type": type(exc).__name__}
    finally:
        _force_stop_owned(hub1)
        _force_stop_owned(hub2)
        removed = _rmtree_strict(temporary_root)
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
