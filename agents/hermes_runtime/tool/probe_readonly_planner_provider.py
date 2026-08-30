"""Live, redacted S3-B provider gate over an owned Hermes process.

Run this manually from a PowerShell process that holds the selected provider
credential. The script uses synthetic intent/scope data only and cleans its
isolated Hermes home and owned process tree.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.error import HTTPError, URLError

from probe_hermes_gateway import (
    _drain,
    _free_loopback_port,
    _listeners,
    _owned_processes,
    _redact_diagnostic,
    _request_json,
    _stop_owned_process,
)
from validate_provider_environment import PROVIDER_SPECS, ProviderSpec, _MODEL_RE


MAX_DIAGNOSTIC_BYTES = 64 * 1024
CONTROL_REQUEST_TIMEOUT_S = 10.0
SAFE_PLANNING_ERROR_CODES = frozenset(
    {
        "planner_answer_invalid",
        "planner_auth_rejected",
        "planner_binding_invalid",
        "planner_busy",
        "planner_closed",
        "planner_hash_invalid",
        "planner_http_error",
        "planner_input_invalid",
        "planner_intent_invalid",
        "planner_output_invalid",
        "planner_policy_invalid",
        "planner_protocol_invalid",
        "planner_query_invalid",
        "planner_rate_limited",
        "planner_request_too_large",
        "planner_response_invalid",
        "planner_response_too_large",
        "planner_result_type_invalid",
        "planner_schema_invalid",
        "planner_unavailable",
        "planner_unsupported_shape_invalid",
    }
)
DISABLED_TOOLSETS = (
    "browser",
    "code_execution",
    "computer_use",
    "cronjob",
    "delegation",
    "file",
    "image_gen",
    "memory",
    "project",
    "session_search",
    "skills",
    "terminal",
    "todo",
    "tts",
    "video",
    "video_gen",
    "vision",
    "web",
    "x_search",
)


def _yaml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _profile_text(
    *, provider_spec: ProviderSpec, model: str, python: Path, mcp_server: Path
) -> str:
    disabled = "\n".join(f"    - {item}" for item in DISABLED_TOOLSETS)
    custom_provider = ""
    if provider_spec.base_url is not None:
        custom_provider = f"""providers:
  volcengine:
    name: Volcengine Ark
    api: {_yaml_string(provider_spec.base_url)}
    key_env: {_yaml_string(provider_spec.credential_env)}
    default_model: {_yaml_string(model)}
    transport: chat_completions
"""
    return f"""model:
  default: {_yaml_string(model)}
  provider: {_yaml_string(provider_spec.hermes_provider)}
{custom_provider}platform_toolsets:
  api_server:
    - data_steward
agent:
  max_turns: 4
  gateway_timeout: 30
  parallel_tool_call_guidance: false
  disabled_toolsets:
{disabled}
context:
  engine: compressor
mcp_servers:
  data_steward:
    enabled: true
    supports_parallel_tool_calls: false
    command: {_yaml_string(str(python))}
    args:
      - {_yaml_string(str(mcp_server))}
    connect_timeout: 5
    timeout: 10
    tools:
      include:
        - inspect_authorized_scope
        - search_authorized_assets
        - propose_archive_plan
        - recall_approved_preferences
      prompts: false
      resources: false
"""


def _read_provider() -> tuple[str, str, ProviderSpec, str]:
    provider = os.environ.get("DATA_STEWARD_HERMES_PROVIDER", "").strip().lower()
    model = os.environ.get("DATA_STEWARD_HERMES_MODEL", "").strip()
    provider_spec = PROVIDER_SPECS.get(provider)
    if provider_spec is None:
        raise RuntimeError("provider_required")
    key_env = provider_spec.credential_env
    secret = os.environ.get(key_env, "")
    if (
        not 16 <= len(secret) <= 512
        or any(ord(char) < 33 or ord(char) > 126 for char in secret)
        or not _MODEL_RE.fullmatch(model)
    ):
        raise RuntimeError("provider_required")
    return provider, model, provider_spec, secret


def _safe_remove_run_home(run_home: Path, runs_root: Path) -> None:
    resolved_root = runs_root.resolve(strict=True)
    resolved_home = run_home.resolve(strict=True)
    if resolved_home.parent != resolved_root or run_home.is_symlink():
        raise RuntimeError("run_home_cleanup_refused")
    shutil.rmtree(resolved_home)
    if any(resolved_root.iterdir()):
        raise RuntimeError("run_root_not_empty")
    resolved_root.rmdir()


def _request_control_json(
    port: int,
    path: str,
    api_token: str,
) -> dict[str, object]:
    try:
        return _request_json(
            port,
            path,
            api_token,
            timeout_s=CONTROL_REQUEST_TIMEOUT_S,
        )
    except TimeoutError:
        raise RuntimeError("gateway_control_timeout") from None


def _safe_gate_error(exc: Exception) -> str:
    error_type = type(exc).__name__
    code = getattr(exc, "code", None)
    if isinstance(code, str) and code in SAFE_PLANNING_ERROR_CODES:
        return f"{error_type}:{code}"
    return error_type


def run_gate() -> dict[str, object]:
    provider, model, provider_spec, provider_secret = _read_provider()
    key_env = provider_spec.credential_env
    repo = Path(__file__).resolve().parents[3]
    runtime_root = repo / "agents" / "hermes_runtime"
    hermes = (runtime_root / ".venv" / "Scripts" / "hermes.exe").resolve(strict=True)
    python = (runtime_root / ".venv" / "Scripts" / "python.exe").resolve(strict=True)
    mcp_server = (runtime_root / "tool" / "gate_mcp_server.py").resolve(strict=True)
    hub_src = (repo / "services" / "steward_hub" / "src").resolve(strict=True)
    runs_root = runtime_root / ".venv" / "s3b-provider-runs"
    runs_root.mkdir(parents=False, exist_ok=False)
    run_home = runs_root / ("run-" + secrets.token_hex(8))
    run_home.mkdir()
    config = run_home / "config.yaml"
    config.write_text(
        _profile_text(
            provider_spec=provider_spec,
            model=model,
            python=python,
            mcp_server=mcp_server,
        ),
        encoding="utf-8",
        newline="\n",
    )
    synthetic_profile = run_home / "os-profile"
    synthetic_local = synthetic_profile / "AppData" / "Local"
    synthetic_roaming = synthetic_profile / "AppData" / "Roaming"
    synthetic_temp = run_home / "temp"
    for directory in (synthetic_local, synthetic_roaming, synthetic_temp):
        directory.mkdir(parents=True, exist_ok=True)

    port = _free_loopback_port()
    api_token = secrets.token_urlsafe(32)
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
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
        "HERMES_HOME": str(run_home),
        "HERMES_CONFIG": str(config),
        "API_SERVER_ENABLED": "true",
        "API_SERVER_HOST": "127.0.0.1",
        "API_SERVER_PORT": str(port),
        "API_SERVER_KEY": api_token,
        "API_SERVER_CORS_ORIGINS": "",
        key_env: provider_secret,
    }
    creation_flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    try:
        proc = subprocess.Popen(
            [str(hermes), "gateway", "run"],
            cwd=str(run_home),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=creation_flags,
        )
    except Exception:
        _safe_remove_run_home(run_home, runs_root)
        raise
    stdout_lines: list[str] = []
    stderr_lines: list[str] = []
    drain_threads = [
        threading.Thread(target=_drain, args=(proc.stdout, stdout_lines), daemon=False),
        threading.Thread(target=_drain, args=(proc.stderr, stderr_lines), daemon=False),
    ]
    for thread in drain_threads:
        thread.start()
    started_at = time.monotonic()
    residual_count = -1
    graceful = False
    try:
        health = None
        deadline = started_at + 20
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError("gateway_exited_before_ready")
            try:
                health = _request_json(port, "/health", None)
                break
            except (HTTPError, URLError, TimeoutError, OSError, ValueError):
                time.sleep(0.2)
        if health is None or health.get("status") != "ok":
            raise RuntimeError("gateway_not_ready")
        capabilities = _request_control_json(
            port,
            "/v1/capabilities",
            api_token,
        )
        toolsets = _request_control_json(port, "/v1/toolsets", api_token)
        if (
            capabilities.get("object") != "hermes.api_server.capabilities"
            or capabilities.get("auth", {}).get("required") is not True
        ):
            raise RuntimeError("capability_contract_invalid")
        rows = toolsets.get("data")
        if not isinstance(rows, list) or not rows:
            raise RuntimeError("toolset_inventory_missing")
        if any(
            isinstance(row, dict) and row.get("enabled") is not False
            for row in rows
        ):
            raise RuntimeError("builtin_toolset_enabled")
        listeners = _listeners(_owned_processes(proc.pid))
        if listeners != [("127.0.0.1", port)]:
            raise RuntimeError("listener_scope_invalid")

        sys.path.insert(0, str(hub_src))
        from steward_hub.agent_planning import HermesReadOnlyPlanner
        from steward_hub.pc_file_scope import PcFileScopeView

        scope = PcFileScopeView(
            configured=True,
            root_id="pc-s3bsynthetic",
            display_name=None,
            authorized_at=None,
        )
        with HermesReadOnlyPlanner(
            endpoint=f"http://127.0.0.1:{port}",
            bearer_token=api_token.encode("ascii"),
            timeout_s=30,
        ) as planner:
            count_plan = planner.plan(
                user_text="请替我盘点电脑授权区里的照片资产",
                scope=scope,
            )
            search_plan = planner.plan(
                user_text="请帮我在电脑授权区定位训练营相关资料",
                scope=scope,
            )
            unsupported = planner.plan(user_text="今天天气怎么样", scope=scope)
            request_count = planner.request_count
        if (
            count_plan is None
            or count_plan.intent != "count_images"
            or search_plan is None
            or search_plan.intent != "search_names"
            or search_plan.query != "训练营"
            or unsupported is not None
            or request_count != 3
        ):
            raise RuntimeError("golden_intent_mismatch")
        return {
            "builtin_toolset_enabled_count": 0,
            "count_plan_sha256": count_plan.plan_sha256,
            "credential_echoed": False,
            "live_model_request_count": request_count,
            "listener_count": 1,
            "loopback_only": True,
            "model_sha256": hashlib.sha256(model.encode("utf-8")).hexdigest(),
            "provider": provider,
            "search_plan_sha256": search_plan.plan_sha256,
            "startup_ms": round((time.monotonic() - started_at) * 1000),
            "status": "PASS",
            "unsupported_rejected": True,
        }
    except Exception:
        diagnostic = _redact_diagnostic(
            "".join(stderr_lines + stdout_lines)[-MAX_DIAGNOSTIC_BYTES:],
            [
                provider_secret,
                api_token,
                model,
                str(repo),
                str(run_home),
                str(port),
            ],
        )
        if diagnostic:
            print(f"PROVIDER_DIAGNOSTIC:{diagnostic}", file=sys.stderr)
        raise
    finally:
        graceful, residual_count = _stop_owned_process(proc)
        for thread in drain_threads:
            thread.join(timeout=2)
        if residual_count:
            print("PROVIDER_CLEANUP:RuntimeError", file=sys.stderr)
        elif not graceful:
            print("PROVIDER_STOP:TERMINATED", file=sys.stderr)
        _safe_remove_run_home(run_home, runs_root)


def main() -> int:
    try:
        result = run_gate()
    except Exception as exc:  # noqa: BLE001 - deliberately redacted gate output
        print(f"S3B_PROVIDER_GATE:{_safe_gate_error(exc)}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
