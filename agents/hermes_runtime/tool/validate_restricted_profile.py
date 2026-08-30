"""Fail-closed validation for the committed Hermes profile template."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import yaml

from hermes_cli.tools_config import _get_platform_tools


EXPECTED_SERVER = "data_steward"
EXPECTED_TOOLS = (
    "inspect_authorized_scope",
    "propose_archive_plan",
    "recall_approved_preferences",
    "search_authorized_assets",
)
FORBIDDEN_TOOLSETS = frozenset(
    {
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
    }
)


def validate_profile(path: Path) -> dict[str, object]:
    raw = path.read_bytes()
    if len(raw) > 32 * 1024:
        raise ValueError("profile_too_large")
    config = yaml.safe_load(raw) or {}
    if not isinstance(config, dict):
        raise ValueError("profile_not_object")

    selected = config.get("platform_toolsets", {}).get("api_server")
    if selected != [EXPECTED_SERVER]:
        raise ValueError("api_server_toolset_not_exact")

    disabled = set(config.get("agent", {}).get("disabled_toolsets", []))
    if not FORBIDDEN_TOOLSETS.issubset(disabled):
        raise ValueError("built_in_toolset_not_disabled")
    if config.get("agent", {}).get("parallel_tool_call_guidance") is not False:
        raise ValueError("parallel_tool_guidance_enabled")

    server = config.get("mcp_servers", {}).get(EXPECTED_SERVER)
    if not isinstance(server, dict) or server.get("enabled") is not True:
        raise ValueError("mcp_server_not_enabled")
    if server.get("supports_parallel_tool_calls") is not False:
        raise ValueError("mcp_parallel_calls_enabled")
    if server.get("command") != "${DATA_STEWARD_HERMES_PYTHON}":
        raise ValueError("mcp_command_not_runtime_injected")
    if server.get("args") != ["${DATA_STEWARD_GATE_MCP_SERVER}"]:
        raise ValueError("mcp_args_not_runtime_injected")

    filters = server.get("tools")
    if not isinstance(filters, dict):
        raise ValueError("mcp_filter_missing")
    include = filters.get("include")
    if not isinstance(include, list) or tuple(sorted(include)) != EXPECTED_TOOLS:
        raise ValueError("mcp_allowlist_not_exact")
    if filters.get("prompts") is not False or filters.get("resources") is not False:
        raise ValueError("mcp_auxiliary_surface_enabled")

    tools_logger = logging.getLogger("hermes_cli.tools_config")
    logger_was_disabled = tools_logger.disabled
    tools_logger.disabled = True
    try:
        effective = sorted(_get_platform_tools(config, "api_server"))
    finally:
        tools_logger.disabled = logger_was_disabled
    if effective != [EXPECTED_SERVER]:
        raise ValueError("effective_toolsets_not_exact")

    return {
        "status": "PASS",
        "api_server_toolsets": effective,
        "allowed_tools": list(EXPECTED_TOOLS),
        "built_in_tools_enabled": False,
        "prompts_enabled": False,
        "resources_enabled": False,
        "parallel_tool_calls_enabled": False,
    }


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate_restricted_profile.py PROFILE", file=sys.stderr)
        return 2
    try:
        result = validate_profile(Path(sys.argv[1]).resolve(strict=True))
    except Exception as exc:  # noqa: BLE001 - stage-only, redacted CLI result
        print(f"PROFILE_GATE:{type(exc).__name__}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
