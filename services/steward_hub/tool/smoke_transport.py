"""Independent-process loopback REST/WebSocket transport smoke."""

from __future__ import annotations

import hashlib
import json
import os
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path

import httpx
from websockets.exceptions import ConnectionClosed
from websockets.sync.client import connect

from steward_hub.api import wire_event
from steward_hub.store import EventStore


def projection_hash(events: list[dict[str, object]]) -> str:
    canonical = json.dumps(
        [
            {
                "actor_device_id": event["actor_device_id"],
                "causation_id": event["causation_id"],
                "correlation_id": event["correlation_id"],
                "conversation_seq": event["conversation_seq"],
                "event_type": event["event_type"],
                "payload": {
                    field: event["payload"][field]  # type: ignore[index]
                    for field in (
                        "accepted_seq",
                        "client_message_id",
                        "content",
                        "role",
                    )
                },
                "protocol_version": event["protocol_version"],
            }
            for event in events
        ],
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def available_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def start_hub(
    *,
    python: Path,
    source_root: Path,
    database_path: Path,
    port: int,
) -> subprocess.Popen[bytes]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(source_root)
    creation_flags = (
        subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    )
    return subprocess.Popen(
        [
            str(python),
            "-m",
            "steward_hub.server",
            "--database",
            str(database_path),
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--workers",
            "1",
            "--shutdown-stdin",
        ],
        env=environment,
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=creation_flags,
    )


def wait_for_health(base_url: str, process: subprocess.Popen[bytes]) -> dict:
    deadline = time.monotonic() + 10
    with httpx.Client(
        base_url=base_url,
        timeout=0.5,
        trust_env=False,
    ) as client:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("hub exited before health readiness")
            try:
                response = client.get("/health")
                if response.status_code == 200:
                    return response.json()
            except httpx.HTTPError:
                pass
            time.sleep(0.05)
    raise RuntimeError("hub health readiness timed out")


def stop_hub(process: subprocess.Popen[bytes]) -> bool:
    if process.poll() is not None:
        return False
    try:
        if process.stdin is None:
            raise OSError("shutdown pipe is unavailable")
        process.stdin.write(b"shutdown\n")
        process.stdin.flush()
        return process.wait(timeout=5) == 0
    except (OSError, subprocess.TimeoutExpired):
        try:
            if os.name == "nt":
                process.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                process.terminate()
        except OSError:
            pass
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
        return False


def message_body(number: int, actor: str) -> dict[str, str]:
    return {
        "client_message_id": f"transport-client-{number}",
        "actor_device_id": actor,
        "role": "user",
        "content": f"transport-content-{number}",
    }


def receive_json(websocket) -> dict:
    value = websocket.recv(timeout=3)
    if not isinstance(value, str):
        raise RuntimeError("unexpected binary websocket frame")
    return json.loads(value)


def main() -> None:
    hub_root = Path(__file__).resolve().parents[1]
    python = hub_root / ".venv" / "Scripts" / "python.exe"
    source_root = hub_root / "src"
    if not python.is_file():
        raise RuntimeError("local virtual environment is unavailable")

    processes: list[subprocess.Popen[bytes]] = []
    graceful_stop_count = 0
    with tempfile.TemporaryDirectory() as temporary_directory:
        database_path = Path(temporary_directory) / "transport-smoke.sqlite3"
        port = available_loopback_port()
        base_url = f"http://127.0.0.1:{port}"
        websocket_url = f"ws://127.0.0.1:{port}"
        conversation_id = "transport-smoke-conversation"
        first_session_events: list[dict[str, object]] = []
        gap_events: list[dict[str, object]] = []
        live_after_restart: dict[str, object] | None = None
        deduplicated_count = 0
        submitted_count = 0
        cursor_ahead_rejected_count = 0
        cursor_recovery_succeeded = False
        health_results: list[dict] = []

        try:
            first_process = start_hub(
                python=python,
                source_root=source_root,
                database_path=database_path,
                port=port,
            )
            processes.append(first_process)
            health_results.append(wait_for_health(base_url, first_process))

            with httpx.Client(
                base_url=base_url,
                timeout=3,
                trust_env=False,
            ) as client:
                created = client.post(
                    "/v1/conversations",
                    json={
                        "title": "Transport smoke",
                        "conversation_id": conversation_id,
                    },
                )
                created.raise_for_status()

                with connect(
                    f"{websocket_url}/v1/conversations/"
                    f"{conversation_id}/events/ws?after_seq=0",
                    open_timeout=3,
                    close_timeout=3,
                ) as websocket:
                    ready = receive_json(websocket)
                    if ready != {
                        "kind": "ready",
                        "last_conversation_seq": 0,
                    }:
                        raise RuntimeError("unexpected initial ready frame")
                    for number, actor in enumerate(
                        ("windows", "phone", "pad"),
                        start=1,
                    ):
                        response = client.post(
                            f"/v1/conversations/{conversation_id}/messages",
                            json=message_body(number, actor),
                        )
                        response.raise_for_status()
                        submitted_count += 1
                        frame = receive_json(websocket)
                        if frame.get("kind") != "event":
                            raise RuntimeError("expected live event frame")
                        first_session_events.append(frame["event"])

                rest_ahead = client.get(
                    f"/v1/conversations/{conversation_id}/events",
                    params={"after_seq": 999, "limit": 10},
                )
                if (
                    rest_ahead.status_code != 409
                    or rest_ahead.json().get("error", {}).get("code")
                    != "cursor_ahead"
                    or rest_ahead.json()["error"].get(
                        "server_last_conversation_seq"
                    )
                    != 3
                ):
                    raise RuntimeError("REST cursor-ahead rejection failed")
                cursor_ahead_rejected_count += 1

                with connect(
                    f"{websocket_url}/v1/conversations/"
                    f"{conversation_id}/events/ws?after_seq=999",
                    open_timeout=3,
                    close_timeout=3,
                ) as websocket:
                    error_frame = receive_json(websocket)
                    if (
                        error_frame.get("kind") != "error"
                        or error_frame.get("error", {}).get("code")
                        != "cursor_ahead"
                        or error_frame["error"].get(
                            "server_last_conversation_seq"
                        )
                        != 3
                    ):
                        raise RuntimeError(
                            "WebSocket cursor-ahead rejection failed"
                        )
                    try:
                        websocket.recv(timeout=3)
                    except ConnectionClosed as error:
                        if error.code != 1008:
                            raise RuntimeError(
                                "unexpected cursor-ahead close code"
                            ) from None
                    else:
                        raise RuntimeError(
                            "cursor-ahead WebSocket remained open"
                        )
                cursor_ahead_rejected_count += 1

                with connect(
                    f"{websocket_url}/v1/conversations/"
                    f"{conversation_id}/events/ws?after_seq=2",
                    open_timeout=3,
                    close_timeout=3,
                ) as websocket:
                    recovered_replay = receive_json(websocket)
                    recovered_ready = receive_json(websocket)
                    fourth = client.post(
                        f"/v1/conversations/{conversation_id}/messages",
                        json=message_body(4, "windows"),
                    )
                    fourth.raise_for_status()
                    submitted_count += 1
                    recovered_live = receive_json(websocket)
                    cursor_recovery_succeeded = (
                        recovered_replay.get("event", {}).get(
                            "conversation_seq"
                        )
                        == 3
                        and recovered_ready.get("last_conversation_seq") == 3
                        and recovered_live.get("event", {}).get(
                            "conversation_seq"
                        )
                        == 4
                    )
                    first_session_events.append(recovered_live["event"])

            graceful_stop_count += int(stop_hub(first_process))

            second_process = start_hub(
                python=python,
                source_root=source_root,
                database_path=database_path,
                port=port,
            )
            processes.append(second_process)
            health_results.append(wait_for_health(base_url, second_process))

            with httpx.Client(
                base_url=base_url,
                timeout=3,
                trust_env=False,
            ) as client:
                with connect(
                    f"{websocket_url}/v1/conversations/"
                    f"{conversation_id}/events/ws?after_seq=1",
                    open_timeout=3,
                    close_timeout=3,
                ) as websocket:
                    for _ in range(3):
                        frame = receive_json(websocket)
                        if frame.get("delivery") != "replay":
                            raise RuntimeError("expected replay frame")
                        gap_events.append(frame["event"])
                    ready = receive_json(websocket)
                    if ready.get("last_conversation_seq") != 4:
                        raise RuntimeError("unexpected resumed ready cursor")

                    duplicate = client.post(
                        f"/v1/conversations/{conversation_id}/messages",
                        json=message_body(4, "windows"),
                    )
                    duplicate.raise_for_status()
                    submitted_count += 1
                    deduplicated_count += int(
                        duplicate.json()["deduplicated"]
                    )
                    try:
                        websocket.recv(timeout=0.25)
                    except TimeoutError:
                        pass
                    else:
                        raise RuntimeError("duplicate produced a live frame")

                    fifth = client.post(
                        f"/v1/conversations/{conversation_id}/messages",
                        json=message_body(5, "phone"),
                    )
                    fifth.raise_for_status()
                    submitted_count += 1
                    live_frame = receive_json(websocket)
                    live_after_restart = live_frame["event"]

                replay = client.get(
                    f"/v1/conversations/{conversation_id}/events",
                    params={"after_seq": 0, "limit": 100},
                )
                replay.raise_for_status()
                rest_events = replay.json()["events"]

            graceful_stop_count += int(stop_hub(second_process))

            reopened_store = EventStore(database_path)
            try:
                reopened_events = [
                    wire_event(event).model_dump(mode="json")
                    for event in reopened_store.replay_events(
                        conversation_id=conversation_id,
                        after_seq=0,
                        limit=100,
                    )
                ]
            finally:
                reopened_store.close()

            websocket_events = (
                first_session_events[:1]
                + gap_events
                + [live_after_restart]
            )
            rest_hash = projection_hash(rest_events)
            websocket_hash = projection_hash(websocket_events)
            reopened_hash = projection_hash(reopened_events)
            loopback_only = all(
                item == {
                    "status": "ok",
                    "protocol_version": 1,
                    "database_ready": True,
                    "transport_scope": "loopback_only",
                }
                for item in health_results
            )
            leaked_process_count = sum(
                process.poll() is None for process in processes
            )
            converged = (
                rest_events == websocket_events == reopened_events
                and rest_hash == websocket_hash == reopened_hash
            )
            summary = {
                "converged": converged,
                "cursor_ahead_rejected_count": (
                    cursor_ahead_rejected_count
                ),
                "cursor_recovery_succeeded": cursor_recovery_succeeded,
                "deduplicated_count": deduplicated_count,
                "first_seq": rest_events[0]["conversation_seq"],
                "graceful_stop_count": graceful_stop_count,
                "last_seq": rest_events[-1]["conversation_seq"],
                "leaked_process_count": leaked_process_count,
                "loopback_only": loopback_only,
                "process_start_count": len(processes),
                "reopened_projection_hash": reopened_hash,
                "replay_gap_count": len(gap_events),
                "rest_projection_hash": rest_hash,
                "stored_count": len(rest_events),
                "submitted_count": submitted_count,
                "websocket_projection_hash": websocket_hash,
            }
            checks = {
                "converged": converged,
                "cursor_ahead_rejections": (
                    cursor_ahead_rejected_count == 2
                ),
                "cursor_recovery": cursor_recovery_succeeded,
                "deduplicated": deduplicated_count == 1,
                "graceful_stops": graceful_stop_count == 2,
                "loopback_only": loopback_only,
                "no_leaked_process": leaked_process_count == 0,
            }
            if not all(checks.values()):
                print(
                    "SMOKE_CHECKS="
                    + json.dumps(
                        checks,
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                )
                raise RuntimeError("transport smoke invariants failed")
            print(
                json.dumps(
                    summary,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
        finally:
            for process in processes:
                if process.poll() is None:
                    stop_hub(process)


if __name__ == "__main__":
    main()
