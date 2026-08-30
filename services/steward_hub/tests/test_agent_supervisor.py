from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from steward_hub.agent_supervisor import (
    AgentPlannerSupervisor,
    _profile_text,
    _provider_config,
)
from steward_hub.supervised_shared_session_runtime import _agent_environment


class AgentSupervisorConfigurationTest(unittest.TestCase):
    def test_explicit_runtime_selection_preserves_secret_only_in_environment(self) -> None:
        with patch.dict(
            "os.environ",
            {"ARK_API_KEY": "secret-marker-0123456789abcdef"},
            clear=True,
        ):
            environment = _agent_environment(
                provider="volcengine",
                model="ep-test",
            )
        assert environment is not None
        self.assertEqual("volcengine", environment["DATA_STEWARD_HERMES_PROVIDER"])
        self.assertEqual("ep-test", environment["DATA_STEWARD_HERMES_MODEL"])
        self.assertEqual(
            "secret-marker-0123456789abcdef",
            environment["ARK_API_KEY"],
        )
        with self.assertRaisesRegex(ValueError, "agent_provider_model_pair_required"):
            _agent_environment(provider="volcengine", model=None)

    def test_absent_configuration_selects_deterministic_fallback(self) -> None:
        self.assertIsNone(_provider_config({}))

    def test_partial_or_unsupported_configuration_is_rejected(self) -> None:
        for environment in (
            {"DATA_STEWARD_HERMES_PROVIDER": "volcengine"},
            {
                "DATA_STEWARD_HERMES_PROVIDER": "unknown",
                "DATA_STEWARD_HERMES_MODEL": "model",
                "ARK_API_KEY": "x" * 32,
            },
        ):
            with self.subTest(environment=environment), self.assertRaisesRegex(
                ValueError, "agent_configuration_invalid"
            ):
                _provider_config(environment)

    def test_profile_disables_powerful_tools_and_contains_no_secret(self) -> None:
        config = _provider_config(
            {
                "DATA_STEWARD_HERMES_PROVIDER": "volcengine",
                "DATA_STEWARD_HERMES_MODEL": "ep-test",
                "ARK_API_KEY": "secret-marker-0123456789abcdef",
            }
        )
        assert config is not None
        profile = _profile_text(
            config=config,
            python=Path("python.exe"),
            mcp_server=Path("gate_mcp_server.py"),
        )
        self.assertIn("custom:volcengine", profile)
        self.assertIn("    - terminal", profile)
        self.assertIn("    - file", profile)
        self.assertNotIn(config.secret, profile)

        product_profile = _profile_text(
            config=config,
            python=Path("python.exe"),
            mcp_server=Path("product_readonly_mcp_server.py"),
            product_tools=True,
        )
        for tool in (
            "catalog_list_recent_assets",
            "catalog_search_assets",
            "catalog_get_clusters",
            "content_get_safe_excerpt",
            "memory_get_active_preferences",
            "insight_draft_study_pack",
        ):
            self.assertIn(f"        - {tool}", product_profile)
        for synthetic_tool in (
            "inspect_authorized_scope",
            "search_authorized_assets",
            "propose_archive_plan",
            "recall_approved_preferences",
        ):
            self.assertNotIn(synthetic_tool, product_profile)
        self.assertNotIn(config.secret, product_profile)


class AgentSupervisorLifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        runtime = self.repo / "agents" / "hermes_runtime"
        (runtime / ".venv" / "Scripts").mkdir(parents=True)
        (runtime / "tool").mkdir(parents=True)
        (self.repo / "services" / "steward_hub").mkdir(parents=True)
        for path in (
            runtime / ".venv" / "Scripts" / "hermes.exe",
            runtime / ".venv" / "Scripts" / "python.exe",
            runtime / "tool" / "gate_mcp_server.py",
            runtime / "tool" / "product_readonly_mcp_server.py",
        ):
            path.write_text("fixture", encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_missing_configuration_starts_no_process(self) -> None:
        popen = Mock()
        supervisor = AgentPlannerSupervisor(
            repo_root=self.repo,
            environment={},
            popen=popen,
        )
        self.assertIsNone(supervisor.start_optional())
        self.assertEqual("fallback", supervisor.status.mode)
        self.assertEqual("not_configured", supervisor.status.reason)
        popen.assert_not_called()

    def test_ready_gateway_is_owned_and_cleaned(self) -> None:
        process = Mock()
        process.poll.return_value = None
        process.pid = 4242
        process.wait.return_value = 0
        popen = Mock(return_value=process)

        def request(_port: int, path: str, _token: str | None) -> dict[str, object]:
            if path == "/health":
                return {"status": "ok"}
            if path == "/v1/capabilities":
                return {
                    "object": "hermes.api_server.capabilities",
                    "auth": {"required": True},
                }
            return {"data": [{"name": "terminal", "enabled": False}]}

        supervisor = AgentPlannerSupervisor(
            repo_root=self.repo,
            environment={
                "DATA_STEWARD_HERMES_PROVIDER": "volcengine",
                "DATA_STEWARD_HERMES_MODEL": "ep-test",
                "ARK_API_KEY": "secret-marker-0123456789abcdef",
                "SystemRoot": r"C:\Windows",
            },
            popen=popen,
            request_json=request,
            port_allocator=lambda: 43210,
            process_tree_stopper=lambda value: (
                value.terminate(),
                value.wait(timeout=1),
            ),
            tool_bridge=Mock(),
            tool_bridge_endpoint="http://127.0.0.1:43199",
            tool_bridge_token="t" * 43,
        )
        planner = supervisor.start_optional()
        self.assertIsNotNone(planner)
        assert planner is not None
        self.assertEqual("host_assisted", planner._study_tool_mode)
        self.assertEqual("hermes", supervisor.status.mode)
        kwargs = popen.call_args.kwargs
        self.assertEqual("127.0.0.1", kwargs["env"]["API_SERVER_HOST"])
        self.assertNotIn("secret-marker", repr(supervisor))
        run_home = Path(kwargs["cwd"])
        self.assertTrue(run_home.is_dir())
        profile = (run_home / "config.yaml").read_text(encoding="utf-8")
        self.assertIn("  max_turns: 6\n", profile)
        self.assertIn("  gateway_timeout: 60\n", profile)

        process.poll.return_value = None
        supervisor.close()
        process.terminate.assert_called_once()
        self.assertFalse(run_home.exists())

    def test_start_failure_degrades_once_and_cleans_run_home(self) -> None:
        process = Mock()
        process.poll.return_value = 1
        process.pid = 4243
        popen = Mock(return_value=process)
        supervisor = AgentPlannerSupervisor(
            repo_root=self.repo,
            environment={
                "DATA_STEWARD_HERMES_PROVIDER": "volcengine",
                "DATA_STEWARD_HERMES_MODEL": "ep-test",
                "ARK_API_KEY": "secret-marker-0123456789abcdef",
            },
            popen=popen,
            request_json=lambda *_: {"status": "ok"},
            port_allocator=lambda: 43211,
        )
        self.assertIsNone(supervisor.start_optional())
        self.assertEqual("health_RuntimeError", supervisor.status.reason)
        runs = self.repo / "agents" / "hermes_runtime" / ".venv" / "s4c-product-runs"
        self.assertFalse(runs.exists())


if __name__ == "__main__":
    unittest.main()
