"""Owned, loopback-only Hermes planner lifecycle for the product runtime.

The model is an untrusted planner.  This supervisor never grants filesystem
authority to Hermes and never retries a failed startup.  The Hub keeps its
deterministic parser/executor as the fail-safe path when configuration is
missing or the owned child cannot be proven ready.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

from .agent_planning import HermesReadOnlyPlanner
from .readonly_tool_bridge import ReadonlyToolBridge


_MODEL_RE = re.compile(r"^[A-Za-z0-9._:/-]{1,128}$")
_PROVIDERS = {
    "openrouter": ("OPENROUTER_API_KEY", "openrouter", None),
    "openai": ("OPENAI_API_KEY", "openai", None),
    "deepseek": ("DEEPSEEK_API_KEY", "deepseek", None),
    "dashscope": ("DASHSCOPE_API_KEY", "dashscope", None),
    "volcengine": (
        "ARK_API_KEY",
        "custom:volcengine",
        "https://ark.cn-beijing.volces.com/api/v3",
    ),
}
_DISABLED_TOOLSETS = (
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


@dataclass(frozen=True, slots=True)
class AgentRuntimeStatus:
    mode: str
    reason: str


@dataclass(frozen=True, slots=True)
class _ProviderConfig:
    provider: str
    model: str
    credential_env: str
    hermes_provider: str
    base_url: str | None
    secret: str


def _provider_config(environment: Mapping[str, str]) -> _ProviderConfig | None:
    provider = environment.get("DATA_STEWARD_HERMES_PROVIDER", "").strip().lower()
    model = environment.get("DATA_STEWARD_HERMES_MODEL", "").strip()
    if not provider and not model:
        return None
    spec = _PROVIDERS.get(provider)
    if spec is None or not _MODEL_RE.fullmatch(model):
        raise ValueError("agent_configuration_invalid")
    credential_env, hermes_provider, base_url = spec
    secret = environment.get(credential_env, "")
    if not 16 <= len(secret) <= 512 or any(
        ord(char) < 33 or ord(char) > 126 for char in secret
    ):
        raise ValueError("agent_configuration_invalid")
    return _ProviderConfig(
        provider=provider,
        model=model,
        credential_env=credential_env,
        hermes_provider=hermes_provider,
        base_url=base_url,
        secret=secret,
    )


def _yaml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _profile_text(
    *,
    config: _ProviderConfig,
    python: Path,
    mcp_server: Path,
    product_tools: bool = False,
) -> str:
    disabled = "\n".join(f"    - {item}" for item in _DISABLED_TOOLSETS)
    custom_provider = ""
    if config.base_url is not None:
        custom_provider = f"""providers:
  volcengine:
    name: Volcengine Ark
    api: {_yaml_string(config.base_url)}
    key_env: {_yaml_string(config.credential_env)}
    default_model: {_yaml_string(config.model)}
    transport: chat_completions
"""
    included_tools = (
        """        - catalog_list_recent_assets
        - catalog_search_assets
        - catalog_get_clusters
        - content_get_safe_excerpt
        - memory_get_active_preferences
        - insight_draft_study_pack"""
        if product_tools
        else """        - inspect_authorized_scope
        - search_authorized_assets
        - propose_archive_plan
        - recall_approved_preferences"""
    )
    return f"""model:
  default: {_yaml_string(config.model)}
  provider: {_yaml_string(config.hermes_provider)}
{custom_provider}platform_toolsets:
  api_server:
    - data_steward
agent:
  max_turns: 6
  gateway_timeout: 60
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
{included_tools}
      prompts: false
      resources: false
"""


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _request_json(port: int, path: str, token: str | None) -> dict[str, object]:
    headers = {"Accept": "application/json"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    request = Request(f"http://127.0.0.1:{port}{path}", headers=headers)
    opener = build_opener(ProxyHandler({}))
    with opener.open(request, timeout=5.0) as response:
        if response.status != 200:
            raise RuntimeError("agent_control_unavailable")
        raw = response.read(64 * 1024 + 1)
    if len(raw) > 64 * 1024:
        raise RuntimeError("agent_control_invalid")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("agent_control_invalid")
    return value


def _stop_owned_process_tree(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=8,
            check=False,
        )
    else:
        process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


class AgentPlannerSupervisor:
    """Own one Hermes gateway and expose only a validated planner client."""

    def __init__(
        self,
        *,
        repo_root: Path,
        environment: Mapping[str, str] | None = None,
        startup_timeout_s: float = 20.0,
        popen: Callable[..., subprocess.Popen[str]] = subprocess.Popen,
        request_json: Callable[[int, str, str | None], dict[str, object]] = _request_json,
        port_allocator: Callable[[], int] = _free_loopback_port,
        process_tree_stopper: Callable[[subprocess.Popen[str]], None] = (
            _stop_owned_process_tree
        ),
        tool_bridge: ReadonlyToolBridge | None = None,
        tool_bridge_endpoint: str | None = None,
        tool_bridge_token: str | None = None,
    ) -> None:
        self._repo_root = repo_root.resolve(strict=True)
        self._environment = dict(os.environ if environment is None else environment)
        self._startup_timeout_s = startup_timeout_s
        self._popen = popen
        self._request_json = request_json
        self._port_allocator = port_allocator
        self._process_tree_stopper = process_tree_stopper
        bridge_parts = (
            tool_bridge is not None,
            tool_bridge_endpoint is not None,
            tool_bridge_token is not None,
        )
        if any(bridge_parts) and not all(bridge_parts):
            raise ValueError("tool_bridge_configuration_invalid")
        self._tool_bridge = tool_bridge
        self._tool_bridge_endpoint = tool_bridge_endpoint
        self._tool_bridge_token = tool_bridge_token
        self._process: subprocess.Popen[str] | None = None
        self._planner: HermesReadOnlyPlanner | None = None
        self._run_home: Path | None = None
        self._runs_root: Path | None = None
        self._token = bytearray()
        self.status = AgentRuntimeStatus("fallback", "not_started")

    @property
    def planner(self) -> HermesReadOnlyPlanner | None:
        return self._planner

    def start_optional(self) -> HermesReadOnlyPlanner | None:
        if self._process is not None or self._planner is not None:
            raise RuntimeError("agent_supervisor_state_invalid")
        stage = "configuration"
        try:
            config = _provider_config(self._environment)
            if config is None:
                self.status = AgentRuntimeStatus("fallback", "not_configured")
                return None
            stage = "runtime_paths"
            runtime_root = self._repo_root / "agents" / "hermes_runtime"
            hermes = (runtime_root / ".venv" / "Scripts" / "hermes.exe").resolve(
                strict=True
            )
            python = (runtime_root / ".venv" / "Scripts" / "python.exe").resolve(
                strict=True
            )
            product_tools = self._tool_bridge is not None
            mcp_name = (
                "product_readonly_mcp_server.py" if product_tools else "gate_mcp_server.py"
            )
            mcp_server = (runtime_root / "tool" / mcp_name).resolve(strict=True)
            runs_root = runtime_root / ".venv" / "s4c-product-runs"
            stage = "run_home"
            runs_root.mkdir(exist_ok=True)
            if runs_root.is_symlink():
                raise RuntimeError("agent_run_root_invalid")
            run_home = runs_root / ("run-" + secrets.token_hex(12))
            run_home.mkdir(exist_ok=False)
            self._runs_root = runs_root
            self._run_home = run_home
            config_path = run_home / "config.yaml"
            config_path.write_text(
                _profile_text(
                    config=config,
                    python=python,
                    mcp_server=mcp_server,
                    product_tools=product_tools,
                ),
                encoding="utf-8",
                newline="\n",
            )
            for directory in (
                run_home / "profile" / "AppData" / "Local",
                run_home / "profile" / "AppData" / "Roaming",
                run_home / "temp",
            ):
                directory.mkdir(parents=True, exist_ok=False)
            port = self._port_allocator()
            token = secrets.token_urlsafe(32)
            self._token = bytearray(token.encode("ascii"))
            system_root = self._environment.get("SystemRoot", r"C:\Windows")
            child_env = {
                "SystemRoot": system_root,
                "WINDIR": system_root,
                "COMSPEC": str(Path(system_root) / "System32" / "cmd.exe"),
                "PATH": os.pathsep.join(
                    (str(hermes.parent), str(Path(system_root) / "System32"))
                ),
                "TEMP": str(run_home / "temp"),
                "TMP": str(run_home / "temp"),
                "HOME": str(run_home / "profile"),
                "USERPROFILE": str(run_home / "profile"),
                "LOCALAPPDATA": str(run_home / "profile" / "AppData" / "Local"),
                "APPDATA": str(run_home / "profile" / "AppData" / "Roaming"),
                "PYTHONUTF8": "1",
                "NO_PROXY": "127.0.0.1",
                "HERMES_HOME": str(run_home),
                "HERMES_CONFIG": str(config_path),
                "API_SERVER_ENABLED": "true",
                "API_SERVER_HOST": "127.0.0.1",
                "API_SERVER_PORT": str(port),
                "API_SERVER_KEY": token,
                "API_SERVER_CORS_ORIGINS": "",
                config.credential_env: config.secret,
            }
            if product_tools:
                assert self._tool_bridge_endpoint is not None
                assert self._tool_bridge_token is not None
                child_env["DATA_STEWARD_TOOL_BRIDGE_URL"] = self._tool_bridge_endpoint
                child_env["DATA_STEWARD_TOOL_BRIDGE_TOKEN"] = self._tool_bridge_token
            stage = "process_start"
            self._process = self._popen(
                [str(hermes), "gateway", "run"],
                cwd=str(run_home),
                env=child_env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
                creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
            )
            deadline = time.monotonic() + self._startup_timeout_s
            health: dict[str, object] | None = None
            stage = "health"
            while time.monotonic() < deadline:
                if self._process.poll() is not None:
                    raise RuntimeError("agent_exited_before_ready")
                try:
                    health = self._request_json(port, "/health", None)
                    if health.get("status") == "ok":
                        break
                except (HTTPError, URLError, TimeoutError, OSError, ValueError):
                    pass
                time.sleep(0.2)
            if health is None or health.get("status") != "ok":
                raise RuntimeError("agent_start_timeout")
            stage = "capabilities"
            capabilities = self._request_json(port, "/v1/capabilities", token)
            toolsets = self._request_json(port, "/v1/toolsets", token)
            rows = toolsets.get("data")
            if (
                capabilities.get("object") != "hermes.api_server.capabilities"
                or not isinstance(capabilities.get("auth"), dict)
                or capabilities["auth"].get("required") is not True  # type: ignore[union-attr]
                or not isinstance(rows, list)
                or not rows
                or any(
                    isinstance(row, dict) and row.get("enabled") is not False
                    for row in rows
                )
            ):
                raise RuntimeError("agent_capability_contract_invalid")
            stage = "planner_client"
            self._planner = HermesReadOnlyPlanner(
                endpoint=f"http://127.0.0.1:{port}",
                bearer_token=self._token,
                model=config.model,
                # S5-E may perform several bounded MCP calls in one inference.
                # The gateway has a bounded six-turn/60-second budget. Leave
                # five seconds for it to return a stable terminal envelope.
                timeout_s=65.0,
                tool_bridge=self._tool_bridge,
                # Ark currently completes normal chat requests but does not
                # emit Hermes-native function calls. Keep the choice with the
                # model while the Host executes the same read-only bridge.
                study_tool_mode=(
                    "host_assisted"
                    if config.provider == "volcengine" and product_tools
                    else "native"
                ),
            )
            self.status = AgentRuntimeStatus("hermes", "ready")
            return self._planner
        except Exception as exc:  # noqa: BLE001 - type only, no secret diagnostics
            self.close()
            self.status = AgentRuntimeStatus(
                "fallback",
                f"{stage}_{type(exc).__name__}",
            )
            return None

    def close(self) -> None:
        planner = self._planner
        self._planner = None
        if planner is not None:
            planner.close()
        process = self._process
        self._process = None
        if process is not None and process.poll() is None:
            self._process_tree_stopper(process)
        for index in range(len(self._token)):
            self._token[index] = 0
        self._token.clear()
        run_home = self._run_home
        runs_root = self._runs_root
        self._run_home = None
        self._runs_root = None
        if run_home is not None and runs_root is not None and run_home.exists():
            resolved_home = run_home.resolve(strict=True)
            resolved_root = runs_root.resolve(strict=True)
            if resolved_home.parent == resolved_root and not run_home.is_symlink():
                shutil.rmtree(resolved_home)
                if not any(resolved_root.iterdir()):
                    resolved_root.rmdir()


def find_repo_root(source: Path | None = None) -> Path:
    current = (source or Path(__file__)).resolve()
    for parent in (current.parent, *current.parents):
        if (parent / "agents" / "hermes_runtime").is_dir() and (
            parent / "services" / "steward_hub"
        ).is_dir():
            return parent
    raise RuntimeError("repo_root_not_found")
