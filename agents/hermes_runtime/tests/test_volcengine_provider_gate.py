from __future__ import annotations

import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import yaml


RUNTIME_ROOT = Path(__file__).resolve().parents[1]
TOOL_ROOT = RUNTIME_ROOT / "tool"
if str(TOOL_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOL_ROOT))

from probe_readonly_planner_provider import (
    CONTROL_REQUEST_TIMEOUT_S,
    _profile_text,
    _request_control_json,
    _safe_gate_error,
)
from validate_provider_environment import (
    PROVIDER_SPECS,
    VOLCENGINE_ARK_BASE_URL,
    main as validate_provider_environment,
)


class VolcengineProviderGateTests(unittest.TestCase):
    def test_environment_gate_accepts_ark_key_without_echoing_secret_or_model(self) -> None:
        secret = "unit-test-ark-credential-not-real"
        model = "ep-20260803-unit-test"
        stdout = io.StringIO()
        with patch.dict(
            os.environ,
            {
                "DATA_STEWARD_HERMES_PROVIDER": "volcengine",
                "DATA_STEWARD_HERMES_MODEL": model,
                "ARK_API_KEY": secret,
            },
            clear=True,
        ), redirect_stdout(stdout):
            exit_code = validate_provider_environment()

        output = stdout.getvalue()
        payload = json.loads(output)
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["status"], "READY_FOR_LIVE_PROVIDER_GATE")
        self.assertEqual(payload["credential_source"], "ARK_API_KEY")
        self.assertTrue(payload["endpoint_locked"])
        self.assertNotIn(secret, output)
        self.assertNotIn(model, output)

    def test_environment_gate_lists_volcengine_but_requires_ark_key(self) -> None:
        stdout = io.StringIO()
        with patch.dict(
            os.environ,
            {
                "DATA_STEWARD_HERMES_PROVIDER": "unsupported",
                "DATA_STEWARD_HERMES_MODEL": "model",
            },
            clear=True,
        ), redirect_stdout(stdout):
            exit_code = validate_provider_environment()

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 2)
        self.assertIn("volcengine", payload["allowed_providers"])

        stdout = io.StringIO()
        with patch.dict(
            os.environ,
            {
                "DATA_STEWARD_HERMES_PROVIDER": "volcengine",
                "DATA_STEWARD_HERMES_MODEL": "ep-unit-test",
            },
            clear=True,
        ), redirect_stdout(stdout):
            exit_code = validate_provider_environment()
        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 2)
        self.assertEqual(payload["credential_source"], "ARK_API_KEY")

    def test_profile_uses_named_custom_provider_and_fixed_ark_endpoint(self) -> None:
        secret = "unit-test-ark-credential-not-real"
        model = "ep-20260803-unit-test"
        spec = PROVIDER_SPECS["volcengine"]
        with patch.dict(
            os.environ,
            {
                "ARK_API_KEY": secret,
                "ARK_BASE_URL": "https://attacker.invalid/v1",
            },
            clear=True,
        ):
            profile_text = _profile_text(
                provider_spec=spec,
                model=model,
                python=Path("python.exe"),
                mcp_server=Path("gate_mcp_server.py"),
            )

        profile = yaml.safe_load(profile_text)
        self.assertEqual(profile["model"]["provider"], "custom:volcengine")
        self.assertEqual(profile["model"]["default"], model)
        self.assertEqual(
            profile["providers"]["volcengine"],
            {
                "name": "Volcengine Ark",
                "api": VOLCENGINE_ARK_BASE_URL,
                "key_env": "ARK_API_KEY",
                "default_model": model,
                "transport": "chat_completions",
            },
        )
        self.assertNotIn(secret, profile_text)
        self.assertNotIn("attacker.invalid", profile_text)

    def test_installed_hermes_resolves_named_provider_from_key_env(self) -> None:
        from hermes_cli import runtime_provider

        secret = "unit-test-ark-credential-not-real"
        model = "ep-20260803-unit-test"
        profile = yaml.safe_load(
            _profile_text(
                provider_spec=PROVIDER_SPECS["volcengine"],
                model=model,
                python=Path("python.exe"),
                mcp_server=Path("gate_mcp_server.py"),
            )
        )
        with patch.object(runtime_provider, "load_config", return_value=profile), patch.dict(
            os.environ,
            {"ARK_API_KEY": secret},
            clear=False,
        ):
            resolved = runtime_provider._get_named_custom_provider(
                "custom:volcengine"
            )

        self.assertIsNotNone(resolved)
        assert resolved is not None
        self.assertEqual(resolved["base_url"], VOLCENGINE_ARK_BASE_URL)
        self.assertEqual(resolved["api_key"], secret)
        self.assertEqual(resolved["model"], model)
        self.assertEqual(resolved["api_mode"], "chat_completions")

    def test_control_plane_has_bounded_warmup_timeout_and_classified_failure(self) -> None:
        with patch(
            "probe_readonly_planner_provider._request_json",
            return_value={"status": "ok"},
        ) as request_json:
            self.assertEqual(
                _request_control_json(43123, "/v1/toolsets", "runtime-token"),
                {"status": "ok"},
            )
        request_json.assert_called_once_with(
            43123,
            "/v1/toolsets",
            "runtime-token",
            timeout_s=CONTROL_REQUEST_TIMEOUT_S,
        )

        with patch(
            "probe_readonly_planner_provider._request_json",
            side_effect=TimeoutError,
        ):
            with self.assertRaisesRegex(RuntimeError, "gateway_control_timeout"):
                _request_control_json(43123, "/v1/toolsets", "runtime-token")

    def test_gate_exposes_only_allowlisted_planning_error_codes(self) -> None:
        class _PlanningFailure(RuntimeError):
            def __init__(self, code: str) -> None:
                self.code = code
                super().__init__(code)

        self.assertEqual(
            _safe_gate_error(_PlanningFailure("planner_response_invalid")),
            "_PlanningFailure:planner_response_invalid",
        )
        self.assertEqual(
            _safe_gate_error(_PlanningFailure("secret-provider-body")),
            "_PlanningFailure",
        )


if __name__ == "__main__":
    unittest.main()
