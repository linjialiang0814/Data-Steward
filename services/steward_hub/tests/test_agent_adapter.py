from __future__ import annotations

import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from steward_hub.agent_adapter import (
    AgentAdapterConfigurationError,
    AgentRuntimeState,
    HermesAgentAdapter,
    MAX_AGENT_RESPONSE_BYTES,
)


TOKEN = b"s3a-framework-gate-token-00000001"


def _health() -> dict[str, object]:
    return {"status": "ok", "platform": "hermes-agent", "version": "0.18.2"}


def _capabilities() -> dict[str, object]:
    return {
        "object": "hermes.api_server.capabilities",
        "platform": "hermes-agent",
        "auth": {"type": "bearer", "required": True},
        "runtime": {
            "mode": "server_agent",
            "tool_execution": "server",
            "split_runtime": False,
        },
        "features": {"admin_config_rw": False, "memory_write_api": False},
    }


def _toolsets(*, enabled: bool = False) -> dict[str, object]:
    return {
        "object": "list",
        "platform": "api_server",
        "data": [{"name": "terminal", "enabled": enabled, "tools": ["terminal"]}],
    }


class _QuietServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):  # type: ignore[no-untyped-def]
        return


class _Fixture:
    def __init__(self) -> None:
        self.responses: dict[str, tuple[int, object, float]] = {
            "/health": (200, _health(), 0),
            "/v1/capabilities": (200, _capabilities(), 0),
            "/v1/toolsets": (200, _toolsets(), 0),
        }
        self.paths: list[str] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                outer.paths.append(self.path)
                status, body, delay = outer.responses[self.path]
                if delay:
                    time.sleep(delay)
                if isinstance(body, bytes):
                    encoded = body
                else:
                    encoded = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, *_: object) -> None:
                return

        self.server = _QuietServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=False)
        self.thread.start()

    @property
    def endpoint(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class HermesAgentAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = _Fixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def adapter(self, **kwargs: object) -> HermesAgentAdapter:
        return HermesAgentAdapter(
            enabled=True,
            endpoint=self.fixture.endpoint,
            bearer_token=TOKEN,
            **kwargs,
        )

    def test_ready_requires_health_capabilities_and_disabled_builtins(self) -> None:
        with self.adapter() as adapter:
            result = adapter.probe()
        self.assertEqual(result.state, AgentRuntimeState.READY)
        self.assertEqual(result.version, "0.18.2")
        self.assertEqual(adapter.request_count, 3)

    def test_disabled_makes_no_request(self) -> None:
        adapter = HermesAgentAdapter(enabled=False)
        result = adapter.probe()
        self.assertEqual(result.state, AgentRuntimeState.DISABLED)
        self.assertEqual(adapter.request_count, 0)

    def test_non_loopback_endpoint_is_rejected_before_network(self) -> None:
        with self.assertRaisesRegex(AgentAdapterConfigurationError, "not_loopback"):
            HermesAgentAdapter(
                enabled=True,
                endpoint="http://192.168.1.4:8642",
                bearer_token=TOKEN,
            )

    def test_auth_rejection_is_permanent_degraded_without_retry(self) -> None:
        self.fixture.responses["/v1/capabilities"] = (401, {"error": "no"}, 0)
        with self.adapter() as adapter:
            result = adapter.probe()
        self.assertEqual(result.state, AgentRuntimeState.DEGRADED)
        self.assertEqual(result.fallback_reason, "agent_auth_rejected")
        self.assertEqual(adapter.request_count, 2)

    def test_timeout_is_unavailable_and_not_retried(self) -> None:
        self.fixture.responses["/health"] = (200, _health(), 0.2)
        with self.adapter(timeout_s=0.05) as adapter:
            result = adapter.probe()
        self.assertEqual(result.state, AgentRuntimeState.UNAVAILABLE)
        self.assertEqual(result.fallback_reason, "transient_network")
        self.assertEqual(adapter.request_count, 1)

    def test_enabled_builtin_toolset_is_fail_closed(self) -> None:
        self.fixture.responses["/v1/toolsets"] = (200, _toolsets(enabled=True), 0)
        with self.adapter() as adapter:
            result = adapter.probe()
        self.assertEqual(result.state, AgentRuntimeState.DEGRADED)
        self.assertEqual(result.fallback_reason, "agent_protocol_incompatible")

    def test_missing_builtin_enablement_state_is_fail_closed(self) -> None:
        body = _toolsets()
        del body["data"][0]["enabled"]  # type: ignore[index]
        self.fixture.responses["/v1/toolsets"] = (200, body, 0)
        with self.adapter() as adapter:
            result = adapter.probe()
        self.assertEqual(result.state, AgentRuntimeState.DEGRADED)

    def test_oversized_response_is_fail_closed(self) -> None:
        self.fixture.responses["/health"] = (
            200,
            b"{" + (b"x" * MAX_AGENT_RESPONSE_BYTES) + b"}",
            0,
        )
        with self.adapter() as adapter:
            result = adapter.probe()
        self.assertEqual(result.state, AgentRuntimeState.DEGRADED)

    def test_secret_is_redacted_and_cleared(self) -> None:
        adapter = self.adapter()
        rendered = repr(adapter)
        adapter.close()
        self.assertNotIn(TOKEN.decode("ascii"), rendered)
        self.assertIn("<redacted>", rendered)
        self.assertEqual(adapter.probe().fallback_reason, "adapter_closed")


if __name__ == "__main__":
    unittest.main()
