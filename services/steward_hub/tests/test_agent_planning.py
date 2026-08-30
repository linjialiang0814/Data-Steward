from __future__ import annotations

import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from steward_hub.agent_planning import (
    AgentPlanningError,
    HermesReadOnlyPlanner,
    MAX_PLANNING_RESPONSE_BYTES,
    PLANNING_PROTOCOL_VERSION,
    build_readonly_planning_messages,
    parse_readonly_plan,
    validate_readonly_plan_for_execution,
)
from steward_hub.pc_file_scope import PcFileScopeView


TOKEN = b"s3b-readonly-planner-token-00000001"


class _QuietServer(ThreadingHTTPServer):
    def handle_error(self, request: object, client_address: object) -> None:
        return


def _scope(*, configured: bool = True) -> PcFileScopeView:
    return PcFileScopeView(
        configured=configured,
        root_id="pc-abc123" if configured else None,
        display_name="Demo" if configured else None,
        authorized_at="2026-08-03T00:00:00.000Z" if configured else None,
    )


def _plan(
    *, intent: str = "count_images", query: str | None = None
) -> dict[str, object]:
    if intent in {"count_images", "search_names"}:
        steps = [
            {
                "step_id": "inspect-scope",
                "tool": "inspect_authorized_scope",
                "target_device": "windows_pc",
                "depends_on": [],
            },
            {
                "step_id": "query-assets",
                "tool": "search_authorized_assets",
                "target_device": "windows_pc",
                "depends_on": ["inspect-scope"],
            },
        ]
    elif intent == "propose_archive":
        steps = [
            {
                "step_id": "inspect-scope",
                "tool": "inspect_authorized_scope",
                "target_device": "windows_pc",
                "depends_on": [],
            },
            {
                "step_id": "propose-archive",
                "tool": "propose_archive_plan",
                "target_device": "windows_pc",
                "depends_on": ["inspect-scope"],
            },
        ]
    else:
        steps = [
            {
                "step_id": "recall-preference",
                "tool": "recall_approved_preferences",
                "target_device": "windows_pc",
                "depends_on": [],
            },
            {
                "step_id": "inspect-scope",
                "tool": "inspect_authorized_scope",
                "target_device": "windows_pc",
                "depends_on": ["recall-preference"],
            },
            {
                "step_id": "propose-archive",
                "tool": "propose_archive_plan",
                "target_device": "windows_pc",
                "depends_on": ["inspect-scope"],
            },
        ]
    return {
        "protocol_version": PLANNING_PROTOCOL_VERSION,
        "intent": intent,
        "target_device": "windows_pc",
        "scope_ref": "scope:pc-abc123",
        "query": query,
        "risk": "read_only",
        "requires_confirmation": False,
        "citations": ["scope:pc-abc123", "capability:files.read"],
        "steps": steps,
        "answer": "将检查授权范围并执行只读查询。",
    }


def _unsupported() -> dict[str, object]:
    return {
        "protocol_version": PLANNING_PROTOCOL_VERSION,
        "intent": "unsupported",
        "target_device": None,
        "scope_ref": None,
        "query": None,
        "risk": "none",
        "requires_confirmation": False,
        "citations": [],
        "steps": [],
        "answer": "当前只支持 PC 授权目录的图片计数或文件名搜索。",
    }


def _model_text(value: dict[str, object]) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _envelope(content: str) -> dict[str, object]:
    return {
        "id": "chatcmpl-fixture",
        "object": "chat.completion",
        "created": 1,
        "model": "data-steward-planner",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }


class _Fixture:
    def __init__(self) -> None:
        self.status = 200
        self.delay = 0.0
        self.body: object = _envelope(_model_text(_plan()))
        self.requests: list[dict[str, object]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length)
                outer.requests.append(
                    {
                        "path": self.path,
                        "authorization": self.headers.get("Authorization"),
                        "idempotency_key": self.headers.get("Idempotency-Key"),
                        "body": json.loads(raw.decode("utf-8")),
                    }
                )
                if outer.delay:
                    time.sleep(outer.delay)
                encoded = (
                    outer.body
                    if isinstance(outer.body, bytes)
                    else json.dumps(outer.body).encode("utf-8")
                )
                self.send_response(outer.status)
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


class ReadOnlyPlanContractTest(unittest.TestCase):
    def test_prompt_contains_only_sanitized_scope_metadata(self) -> None:
        system, user = build_readonly_planning_messages(
            user_text="盘点电脑照片", scope=_scope()
        )
        self.assertIn("inspect_authorized_scope", system)
        self.assertIn("scope:pc-abc123", user)
        self.assertNotIn("C:\\", user)
        self.assertNotIn("Demo", user)

    def test_count_plan_is_compiled_to_existing_executor_intent(self) -> None:
        plan = parse_readonly_plan(
            model_text=_model_text(_plan()),
            user_text="请盘点电脑授权区的图片数量",
            scope=_scope(),
        )
        self.assertIsNotNone(plan)
        assert plan is not None
        self.assertEqual("count_images", plan.to_executor_intent().operation)
        self.assertRegex(plan.plan_sha256, r"^[0-9a-f]{64}$")

    def test_search_query_must_be_present_in_user_text(self) -> None:
        with self.assertRaisesRegex(AgentPlanningError, "planner_query_invalid"):
            parse_readonly_plan(
                model_text=_model_text(_plan(intent="search_names", query="机密")),
                user_text="找一下训练营文件",
                scope=_scope(),
            )

    def test_search_query_is_bounded_and_compiled(self) -> None:
        plan = parse_readonly_plan(
            model_text=_model_text(_plan(intent="search_names", query="训练营")),
            user_text="请帮我在电脑授权区定位训练营相关资料",
            scope=_scope(),
        )
        assert plan is not None
        self.assertEqual("训练营", plan.query)

    def test_supported_plan_must_be_grounded_in_user_text(self) -> None:
        with self.assertRaisesRegex(AgentPlanningError, "planner_query_invalid"):
            parse_readonly_plan(
                model_text=_model_text(_plan()),
                user_text="今天天气怎么样",
                scope=_scope(),
            )

    def test_archive_plan_is_natural_language_grounded_but_not_executable(self) -> None:
        plan = parse_readonly_plan(
            model_text=_model_text(_plan(intent="propose_archive")),
            user_text="请帮我整理一下电脑授权目录里的资料",
            scope=_scope(),
        )
        assert plan is not None
        self.assertEqual("suggest", plan.archive_operation())
        with self.assertRaisesRegex(AgentPlanningError, "planner_executor_mismatch"):
            plan.to_executor_intent()
        self.assertNotIn("sha256", plan.conversation_prefix())

    def test_preference_recall_requires_explicit_preference_language(self) -> None:
        with self.assertRaisesRegex(AgentPlanningError, "planner_query_invalid"):
            parse_readonly_plan(
                model_text=_model_text(_plan(intent="recall_archive_preference")),
                user_text="请整理电脑授权目录",
                scope=_scope(),
            )
        plan = parse_readonly_plan(
            model_text=_model_text(_plan(intent="recall_archive_preference")),
            user_text="请按我之前的习惯整理电脑授权目录",
            scope=_scope(),
        )
        assert plan is not None
        self.assertEqual("recall", plan.archive_operation())

    def test_unsupported_is_not_an_executable_plan(self) -> None:
        self.assertIsNone(
            parse_readonly_plan(
                model_text=_model_text(_unsupported()),
                user_text="今天天气怎么样",
                scope=_scope(),
            )
        )

    def test_write_tool_or_wrong_citation_fails_closed(self) -> None:
        for mutation in ("tool", "citation"):
            value = _plan()
            if mutation == "tool":
                value["steps"][1]["tool"] = "move_asset"  # type: ignore[index]
            else:
                value["citations"] = ["scope:invented", "capability:files.read"]
            with self.subTest(mutation=mutation), self.assertRaisesRegex(
                AgentPlanningError, "planner_policy_invalid"
            ):
                parse_readonly_plan(
                    model_text=_model_text(value),
                    user_text="盘点电脑图片",
                    scope=_scope(),
                )

    def test_surrounding_markdown_and_duplicate_keys_are_rejected(self) -> None:
        valid = _model_text(_plan())
        cases = (
            f"```json\n{valid}\n```",
            valid[:-1] + ',"intent":"count_images"}',
        )
        for value in cases:
            with self.subTest(value=value[:10]), self.assertRaises(AgentPlanningError):
                parse_readonly_plan(
                    model_text=value,
                    user_text="盘点电脑图片",
                    scope=_scope(),
                )

    def test_unconfigured_scope_is_bound_not_invented(self) -> None:
        value = _plan()
        value["scope_ref"] = "scope:unconfigured"
        value["citations"] = ["scope:unconfigured", "capability:files.read"]
        plan = parse_readonly_plan(
            model_text=_model_text(value),
            user_text="盘点电脑图片",
            scope=_scope(configured=False),
        )
        assert plan is not None
        self.assertEqual("scope:unconfigured", plan.scope_ref)

    def test_hub_boundary_rejects_forged_compiled_plan(self) -> None:
        forged = _plan()
        compiled = parse_readonly_plan(
            model_text=_model_text(forged),
            user_text="盘点电脑图片",
            scope=_scope(),
        )
        assert compiled is not None
        object.__setattr__(compiled, "citations", ("scope:invented",))
        with self.assertRaisesRegex(AgentPlanningError, "planner_binding_invalid"):
            validate_readonly_plan_for_execution(
                plan=compiled,
                user_text="盘点电脑图片",
                scope=_scope(),
            )


class HermesReadOnlyPlannerClientTest(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = _Fixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def planner(self, **kwargs: object) -> HermesReadOnlyPlanner:
        return HermesReadOnlyPlanner(
            endpoint=self.fixture.endpoint,
            bearer_token=TOKEN,
            **kwargs,
        )

    def test_posts_one_stateless_bearer_authenticated_request(self) -> None:
        with self.planner() as planner:
            result = planner.plan(user_text="盘点电脑图片", scope=_scope())
        self.assertIsNotNone(result)
        self.assertEqual(1, planner.request_count)
        captured = self.fixture.requests[0]
        self.assertEqual("/v1/chat/completions", captured["path"])
        self.assertEqual(f"Bearer {TOKEN.decode('ascii')}", captured["authorization"])
        self.assertRegex(str(captured["idempotency_key"]), r"^s3b-[0-9a-f]{64}$")
        body = captured["body"]
        self.assertEqual(False, body["stream"])  # type: ignore[index]
        self.assertNotIn("X-Hermes-Session-Id", captured)

    def test_auth_and_rate_limit_fail_without_retry(self) -> None:
        for status, code in ((401, "planner_auth_rejected"), (429, "planner_rate_limited")):
            self.fixture.status = status
            with self.subTest(status=status), self.planner() as planner:
                with self.assertRaisesRegex(AgentPlanningError, code):
                    planner.plan(user_text="盘点电脑图片", scope=_scope())
                self.assertEqual(1, planner.request_count)
            self.fixture.requests.clear()

    def test_timeout_fails_without_retry(self) -> None:
        self.fixture.delay = 0.3
        with self.planner(timeout_s=0.1) as planner:
            with self.assertRaisesRegex(AgentPlanningError, "planner_timeout"):
                planner.plan(user_text="盘点电脑图片", scope=_scope())
            self.assertEqual(1, planner.request_count)

    def test_concurrent_call_is_rejected_without_queue_or_second_request(self) -> None:
        self.fixture.delay = 0.3
        planner = self.planner(timeout_s=1.0)
        first_errors: list[BaseException] = []

        def first_call() -> None:
            try:
                planner.plan(user_text="盘点电脑图片", scope=_scope())
            except BaseException as exc:  # noqa: BLE001 - test captures worker failure
                first_errors.append(exc)

        worker = threading.Thread(target=first_call, daemon=False)
        worker.start()
        deadline = time.monotonic() + 1
        while not self.fixture.requests and time.monotonic() < deadline:
            time.sleep(0.01)
        with self.assertRaisesRegex(AgentPlanningError, "planner_busy"):
            planner.plan(user_text="盘点电脑图片", scope=_scope())
        worker.join(timeout=2)
        planner.close()

        self.assertFalse(first_errors)
        self.assertFalse(worker.is_alive())
        self.assertEqual(1, planner.request_count)
        self.assertEqual(1, len(self.fixture.requests))

    def test_partial_or_oversized_response_is_rejected(self) -> None:
        partial = _envelope(_model_text(_plan()))
        partial["hermes"] = {"partial": True}
        self.fixture.body = partial
        with self.planner() as planner, self.assertRaisesRegex(
            AgentPlanningError, "planner_response_invalid"
        ):
            planner.plan(user_text="盘点电脑图片", scope=_scope())

        self.fixture.body = b"x" * (MAX_PLANNING_RESPONSE_BYTES + 1)
        with self.planner() as planner, self.assertRaisesRegex(
            AgentPlanningError, "planner_response_too_large"
        ):
            planner.plan(user_text="盘点电脑图片", scope=_scope())

    def test_secret_is_redacted_and_cleared(self) -> None:
        planner = self.planner()
        rendered = repr(planner)
        planner.close()
        self.assertNotIn(TOKEN.decode("ascii"), rendered)
        self.assertIn("<redacted>", rendered)
        with self.assertRaisesRegex(AgentPlanningError, "planner_closed"):
            planner.plan(user_text="盘点电脑图片", scope=_scope())


if __name__ == "__main__":
    unittest.main()
