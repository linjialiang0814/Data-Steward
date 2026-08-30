"""Owned-process, loopback-only runtime probe for the S3-A Hermes gate."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

import psutil


MAX_BODY_BYTES = 64 * 1024


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _request_json(
    port: int,
    path: str,
    token: str | None,
    *,
    timeout_s: float = 1.0,
) -> dict[str, object]:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(f"http://127.0.0.1:{port}{path}", headers=headers)
    with build_opener(ProxyHandler({})).open(request, timeout=timeout_s) as response:
        body = response.read(MAX_BODY_BYTES + 1)
    if len(body) > MAX_BODY_BYTES:
        raise RuntimeError("response_too_large")
    value = json.loads(body.decode("utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("response_not_object")
    return value


def _owned_processes(root_pid: int) -> list[psutil.Process]:
    try:
        root = psutil.Process(root_pid)
    except psutil.Error:
        return []
    return [root, *root.children(recursive=True)]


def _listeners(processes: list[psutil.Process]) -> list[tuple[str, int]]:
    listeners: set[tuple[str, int]] = set()
    for process in processes:
        try:
            for connection in process.net_connections(kind="inet"):
                if connection.status != psutil.CONN_LISTEN or not connection.laddr:
                    continue
                listeners.add((str(connection.laddr.ip), int(connection.laddr.port)))
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
    return sorted(listeners)


def _stop_owned_process(proc: subprocess.Popen[str]) -> tuple[bool, int]:
    graceful = False
    owned = _owned_processes(proc.pid)
    if proc.poll() is None:
        try:
            proc.send_signal(signal.CTRL_BREAK_EVENT)
            proc.wait(timeout=8)
            graceful = True
        except (OSError, subprocess.TimeoutExpired):
            pass
    for child in reversed(owned[1:]):
        try:
            child.terminate()
        except psutil.Error:
            pass
    try:
        _, alive = psutil.wait_procs(owned[1:], timeout=3)
    except psutil.Error:
        alive = []
    for child in alive:
        try:
            child.kill()
        except psutil.Error:
            pass
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)
    residual_count = 0
    for process in owned:
        try:
            if process.is_running() and process.status() != psutil.STATUS_ZOMBIE:
                residual_count += 1
        except psutil.Error:
            continue
    return graceful, residual_count


def _drain(stream: object, sink: list[str]) -> None:
    readline = getattr(stream, "readline", None)
    if not callable(readline):
        return
    while sum(map(len, sink)) < MAX_BODY_BYTES:
        line = readline()
        if not line:
            return
        sink.append(str(line))


def _redact_diagnostic(text: str, secrets_to_remove: list[str]) -> str:
    redacted = text
    for secret in sorted(secrets_to_remove, key=len, reverse=True):
        if secret:
            redacted = redacted.replace(secret, "<redacted>")
    redacted = redacted.replace("\r", " ").replace("\n", " | ")
    return redacted[-2000:]


def run_probe(args: argparse.Namespace) -> dict[str, object]:
    hermes = Path(args.hermes).resolve(strict=True)
    home = Path(args.home).resolve(strict=True)
    config = Path(args.config).resolve(strict=True)
    mcp_python = Path(args.mcp_python).resolve(strict=True)
    mcp_server = Path(args.mcp_server).resolve(strict=True)
    hub_src = Path(args.hub_src).resolve(strict=True)
    if config.parent != home:
        raise ValueError("config_not_in_isolated_home")

    port = _free_loopback_port()
    token = secrets.token_urlsafe(32)
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    synthetic_profile = home / "os-profile"
    synthetic_local = synthetic_profile / "AppData" / "Local"
    synthetic_roaming = synthetic_profile / "AppData" / "Roaming"
    synthetic_local.mkdir(parents=True, exist_ok=True)
    synthetic_roaming.mkdir(parents=True, exist_ok=True)
    synthetic_temp = home / "temp"
    synthetic_temp.mkdir(parents=True, exist_ok=True)
    env = {
        "SystemRoot": system_root,
        "WINDIR": system_root,
        "COMSPEC": os.path.join(system_root, "System32", "cmd.exe"),
        "PATH": os.pathsep.join((str(hermes.parent), os.path.join(system_root, "System32"))),
        "TEMP": str(synthetic_temp),
        "TMP": str(synthetic_temp),
        "HOME": str(synthetic_profile),
        "USERPROFILE": str(synthetic_profile),
        "LOCALAPPDATA": str(synthetic_local),
        "APPDATA": str(synthetic_roaming),
        "PYTHONUTF8": "1",
        "NO_PROXY": "127.0.0.1",
        "HERMES_HOME": str(home),
        "HERMES_CONFIG": str(config),
        "DATA_STEWARD_HERMES_PYTHON": str(mcp_python),
        "DATA_STEWARD_GATE_MCP_SERVER": str(mcp_server),
        "API_SERVER_ENABLED": "true",
        "API_SERVER_HOST": "127.0.0.1",
        "API_SERVER_PORT": str(port),
        "API_SERVER_KEY": token,
        "API_SERVER_CORS_ORIGINS": "",
    }
    creation_flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    proc = subprocess.Popen(
        [str(hermes), "gateway", "run"],
        cwd=str(home),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=creation_flags,
    )
    stdout_lines: list[str] = []
    stderr_lines: list[str] = []
    drain_threads = [
        threading.Thread(target=_drain, args=(proc.stdout, stdout_lines), daemon=False),
        threading.Thread(target=_drain, args=(proc.stderr, stderr_lines), daemon=False),
    ]
    for thread in drain_threads:
        thread.start()
    started_at = time.monotonic()
    health: dict[str, object] | None = None
    last_error = "startup_timeout"
    try:
        deadline = started_at + 20.0
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError("gateway_exited_before_ready")
            try:
                health = _request_json(port, "/health", None)
                break
            except (HTTPError, URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
                last_error = "gateway_not_ready"
                time.sleep(0.2)
        if health is None:
            raise RuntimeError(last_error)
        if health.get("status") != "ok" or health.get("platform") != "hermes-agent":
            raise RuntimeError("health_contract_invalid")

        capabilities = _request_json(port, "/v1/capabilities", token)
        toolsets = _request_json(port, "/v1/toolsets", token)
        if capabilities.get("object") != "hermes.api_server.capabilities":
            raise RuntimeError("capabilities_contract_invalid")
        rows = toolsets.get("data")
        if not isinstance(rows, list) or not rows:
            raise RuntimeError("toolsets_missing")
        enabled_builtins = sorted(
            str(row.get("name"))
            for row in rows
            if isinstance(row, dict) and row.get("enabled") is True
        )
        if enabled_builtins:
            raise RuntimeError("builtin_toolset_enabled")

        listeners = _listeners(_owned_processes(proc.pid))
        if listeners != [("127.0.0.1", port)]:
            raise RuntimeError("listener_scope_invalid")
        sys.path.insert(0, str(hub_src))
        from steward_hub.agent_adapter import AgentRuntimeState, HermesAgentAdapter

        with HermesAgentAdapter(
            enabled=True,
            endpoint=f"http://127.0.0.1:{port}",
            bearer_token=token.encode("ascii"),
        ) as adapter:
            adapter_status = adapter.probe()
            adapter_request_count = adapter.request_count
        if adapter_status.state != AgentRuntimeState.READY:
            raise RuntimeError("product_adapter_not_ready")
        return {
            "status": "PASS",
            "runtime": "hermes-agent",
            "version": health.get("version"),
            "startup_ms": round((time.monotonic() - started_at) * 1000),
            "loopback_only": True,
            "bearer_required": capabilities.get("auth", {}).get("required") is True,
            "builtin_toolset_enabled_count": 0,
            "listener_count": 1,
            "provider_configured": False,
            "product_adapter_state": adapter_status.state,
            "product_adapter_request_count": adapter_request_count,
        }
    except Exception:
        diagnostic = _redact_diagnostic(
            "".join(stderr_lines + stdout_lines),
            [
                token,
                str(Path.cwd().resolve()),
                str(home),
                str(config),
                str(hermes),
                str(mcp_python),
                str(mcp_server),
                str(hub_src),
                str(port),
            ],
        )
        if diagnostic:
            print(f"HERMES_DIAGNOSTIC:{diagnostic}", file=sys.stderr)
        raise
    finally:
        graceful, residual_count = _stop_owned_process(proc)
        for thread in drain_threads:
            thread.join(timeout=2)
        # Never print endpoint, token, PID, or isolated local paths.
        if residual_count:
            print("GATEWAY_CLEANUP:RuntimeError", file=sys.stderr)
        elif not graceful:
            print("GATEWAY_STOP:TERMINATED", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hermes", required=True)
    parser.add_argument("--home", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--mcp-python", required=True)
    parser.add_argument("--mcp-server", required=True)
    parser.add_argument("--hub-src", required=True)
    args = parser.parse_args()
    try:
        result = run_probe(args)
    except Exception as exc:  # noqa: BLE001 - deliberately redacted gate output
        print(f"HERMES_GATE:{type(exc).__name__}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
