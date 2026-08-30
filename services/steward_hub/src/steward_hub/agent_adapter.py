"""Fail-closed health adapter for the optional local Hermes Agent runtime.

This module does not submit prompts or execute plans. S3-A only establishes a
bounded, loopback-only readiness contract and an explicit deterministic
fallback when the optional agent runtime is unavailable or incompatible.
"""

from __future__ import annotations

import json
import re
import socket
from dataclasses import dataclass
from enum import StrEnum
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener


MAX_AGENT_RESPONSE_BYTES = 64 * 1024
EXPECTED_HERMES_VERSION = "0.18.2"
_TOKEN_RE = re.compile(rb"^[\x21-\x7e]{32,128}$")


class AgentRuntimeState(StrEnum):
    DISABLED = "disabled"
    UNAVAILABLE = "unavailable"
    READY = "ready"
    DEGRADED = "degraded"


@dataclass(frozen=True)
class AgentRuntimeStatus:
    state: AgentRuntimeState
    runtime: str
    version: str | None
    fallback_reason: str | None
    deterministic_fallback: bool = True


class AgentAdapterConfigurationError(ValueError):
    """Raised before any network access when configuration is unsafe."""


class _ProtocolError(RuntimeError):
    pass


def validate_agent_endpoint(endpoint: str) -> str:
    parsed = urlsplit(endpoint)
    try:
        port = parsed.port
    except ValueError as exc:
        raise AgentAdapterConfigurationError("agent_port_invalid") from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or port is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise AgentAdapterConfigurationError("agent_endpoint_not_loopback")
    if not 1 <= port <= 65535:
        raise AgentAdapterConfigurationError("agent_port_invalid")
    return f"http://127.0.0.1:{port}"


class HermesAgentAdapter:
    """One-shot readiness probe with no proxies and no automatic retries."""

    def __init__(
        self,
        *,
        enabled: bool,
        endpoint: str | None = None,
        bearer_token: bytes | bytearray | None = None,
        timeout_s: float = 1.5,
        expected_version: str = EXPECTED_HERMES_VERSION,
    ) -> None:
        self._enabled = bool(enabled)
        self._endpoint: str | None = None
        self._token = bytearray()
        self._closed = False
        self._timeout_s = float(timeout_s)
        self._expected_version = expected_version
        self.request_count = 0

        if not self._enabled:
            return
        if not endpoint or bearer_token is None:
            raise AgentAdapterConfigurationError("agent_configuration_missing")
        if not 0.05 <= self._timeout_s <= 10.0:
            raise AgentAdapterConfigurationError("agent_timeout_invalid")
        self._endpoint = validate_agent_endpoint(endpoint)
        token = bytes(bearer_token)
        if not _TOKEN_RE.fullmatch(token):
            raise AgentAdapterConfigurationError("agent_token_invalid")
        self._token.extend(token)

    def __repr__(self) -> str:
        return (
            "HermesAgentAdapter("
            f"enabled={self._enabled!r}, endpoint={self._endpoint!r}, "
            "bearer_token=<redacted>)"
        )

    def close(self) -> None:
        for index in range(len(self._token)):
            self._token[index] = 0
        self._token.clear()
        self._closed = True

    def __enter__(self) -> "HermesAgentAdapter":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def probe(self) -> AgentRuntimeStatus:
        if not self._enabled:
            return AgentRuntimeStatus(
                state=AgentRuntimeState.DISABLED,
                runtime="hermes-agent",
                version=None,
                fallback_reason="agent_disabled",
            )
        if self._closed:
            return self._fallback(AgentRuntimeState.UNAVAILABLE, "adapter_closed")

        try:
            health = self._get_json("/health", authenticated=False)
            version = self._validate_health(health)
            capabilities = self._get_json("/v1/capabilities", authenticated=True)
            self._validate_capabilities(capabilities)
            toolsets = self._get_json("/v1/toolsets", authenticated=True)
            self._validate_no_builtin_toolsets(toolsets)
        except HTTPError as exc:
            if exc.code in {401, 403}:
                return self._fallback(AgentRuntimeState.DEGRADED, "agent_auth_rejected")
            return self._fallback(AgentRuntimeState.DEGRADED, "agent_http_incompatible")
        except (TimeoutError, socket.timeout, URLError, OSError):
            return self._fallback(AgentRuntimeState.UNAVAILABLE, "transient_network")
        except (_ProtocolError, UnicodeError, json.JSONDecodeError):
            return self._fallback(AgentRuntimeState.DEGRADED, "agent_protocol_incompatible")

        return AgentRuntimeStatus(
            state=AgentRuntimeState.READY,
            runtime="hermes-agent",
            version=version,
            fallback_reason=None,
        )

    def _fallback(self, state: AgentRuntimeState, reason: str) -> AgentRuntimeStatus:
        return AgentRuntimeStatus(
            state=state,
            runtime="hermes-agent",
            version=None,
            fallback_reason=reason,
        )

    def _get_json(self, path: str, *, authenticated: bool) -> Any:
        if self._endpoint is None:
            raise _ProtocolError("endpoint_missing")
        headers = {"Accept": "application/json"}
        if authenticated:
            try:
                token = bytes(self._token).decode("ascii")
            except UnicodeDecodeError as exc:
                raise _ProtocolError("token_encoding_invalid") from exc
            headers["Authorization"] = f"Bearer {token}"
        request = Request(f"{self._endpoint}{path}", headers=headers, method="GET")
        self.request_count += 1
        opener = build_opener(ProxyHandler({}))
        with opener.open(request, timeout=self._timeout_s) as response:
            if response.status != 200:
                raise _ProtocolError("status_invalid")
            declared = response.headers.get("Content-Length")
            if declared is not None:
                try:
                    if int(declared) > MAX_AGENT_RESPONSE_BYTES:
                        raise _ProtocolError("response_too_large")
                except ValueError as exc:
                    raise _ProtocolError("content_length_invalid") from exc
            body = response.read(MAX_AGENT_RESPONSE_BYTES + 1)
        if len(body) > MAX_AGENT_RESPONSE_BYTES:
            raise _ProtocolError("response_too_large")
        value = json.loads(body.decode("utf-8"))
        if not isinstance(value, dict):
            raise _ProtocolError("response_not_object")
        return value

    def _validate_health(self, body: dict[str, Any]) -> str:
        version = body.get("version")
        if (
            body.get("status") != "ok"
            or body.get("platform") != "hermes-agent"
            or version != self._expected_version
        ):
            raise _ProtocolError("health_contract_invalid")
        return version

    @staticmethod
    def _validate_capabilities(body: dict[str, Any]) -> None:
        auth = body.get("auth")
        runtime = body.get("runtime")
        features = body.get("features")
        if (
            body.get("object") != "hermes.api_server.capabilities"
            or body.get("platform") != "hermes-agent"
            or not isinstance(auth, dict)
            or auth.get("type") != "bearer"
            or auth.get("required") is not True
            or not isinstance(runtime, dict)
            or runtime.get("mode") != "server_agent"
            or runtime.get("tool_execution") != "server"
            or runtime.get("split_runtime") is not False
            or not isinstance(features, dict)
            or features.get("admin_config_rw") is not False
            or features.get("memory_write_api") is not False
        ):
            raise _ProtocolError("capability_contract_invalid")

    @staticmethod
    def _validate_no_builtin_toolsets(body: dict[str, Any]) -> None:
        if body.get("object") != "list" or body.get("platform") != "api_server":
            raise _ProtocolError("toolset_contract_invalid")
        rows = body.get("data")
        if not isinstance(rows, list) or not rows:
            raise _ProtocolError("toolset_inventory_missing")
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("name"), str):
                raise _ProtocolError("toolset_row_invalid")
            if row.get("enabled") is not False:
                raise _ProtocolError("builtin_toolset_enabled")
