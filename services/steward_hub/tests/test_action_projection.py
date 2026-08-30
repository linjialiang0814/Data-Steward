from __future__ import annotations

import sqlite3
import tempfile
import threading
import time
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from steward_hub.action_projection import ActionProjectionError, ActionProjectionService
from steward_hub.api import create_app
from steward_hub.archive_memory import ArchiveIntent, ArchiveMemoryService
from steward_hub.pc_file_scope import PcFileScopeService
from steward_hub.pc_file_organizer_journal import OrganizerJournalStore
from steward_hub.store import EventStore


class ProductActionFlowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "Authorized"
        self.root.mkdir()
        (self.root / "photo.png").write_bytes(b"image")
        self.database = Path(self.temporary.name) / "hub.sqlite3"
        journal = OrganizerJournalStore(
            Path(self.temporary.name) / "journal" / "journal.dpapi",
            protect=lambda value: b"sealed:" + value,
            unprotect=lambda value: bytearray(value.removeprefix(b"sealed:")),
            apply_root_security=lambda _path: None,
            verify_root_security=lambda _path: None,
            verify_file_security=lambda _path: None,
        )
        self.scope = PcFileScopeService(organizer_journal=journal)
        self.scope.authorize(str(self.root))
        self.memory = ArchiveMemoryService(self.database, self.scope)
        self.actions = ActionProjectionService(self.database)
        self.client = TestClient(
            create_app(
                database_path=self.database,
                pc_file_scope_service=self.scope,
                archive_memory_service=self.memory,
                action_projection_service=self.actions,
            )
        )
        self.client.__enter__()
        response = self.client.post(
            "/v1/conversations",
            json={"title": "actions", "conversation_id": "action-demo"},
        )
        self.assertEqual(201, response.status_code)

    def tearDown(self) -> None:
        self.client.__exit__(None, None, None)
        self.actions.close()
        self.memory.close()
        self.temporary.cleanup()

    def _append_suggestion(
        self,
        index: int,
        content: str = "智能整理电脑授权目录",
    ) -> tuple[str, list[dict[str, object]]]:
        idle_deadline = time.monotonic() + 2
        while (
            self.client.app.state.unified_gateway_tasks.pending_count
            and time.monotonic() < idle_deadline
        ):
            time.sleep(0.01)
        self.assertEqual(
            0,
            self.client.app.state.unified_gateway_tasks.pending_count,
            "previous derived task did not reach its terminal state",
        )
        before = self.client.get(
            "/v1/conversations/action-demo/events?after_seq=0&limit=100"
        ).json()["events"]
        before_count = sum(
            row["actor_device_id"] == "data-steward-memory" for row in before
        )
        response = self.client.post(
            "/v1/conversations/action-demo/messages",
            json={
                "client_message_id": f"suggest-{index}",
                "actor_device_id": "windows-demo",
                "role": "user",
                "content": content,
            },
        )
        self.assertEqual(201, response.status_code)
        deadline = time.monotonic() + 2
        replay: list[dict[str, object]] = []
        while time.monotonic() < deadline:
            replay = self.client.get(
                "/v1/conversations/action-demo/events?after_seq=0&limit=100"
            ).json()["events"]
            if (
                sum(
                    row["actor_device_id"] == "data-steward-memory"
                    for row in replay
                )
                > before_count
            ):
                break
            time.sleep(0.01)
        assistant = [
            row
            for row in replay
            if row["actor_device_id"] == "data-steward-memory"
        ][-1]
        message_id = assistant["payload"]["message_id"]
        content = assistant["payload"]["content"]
        self.assertNotIn("sg-", content)
        self.assertNotIn("mem-", content)
        self.assertNotIn("sha256", content)
        action_deadline = time.monotonic() + 2
        actions: list[dict[str, object]] = []
        while time.monotonic() < action_deadline:
            actions = self.client.get(
                f"/v1/conversations/action-demo/messages/{message_id}/actions"
            ).json()["actions"]
            if actions:
                break
            time.sleep(0.01)
        return message_id, actions

    def test_home_quick_start_creates_confirmation_actions(self) -> None:
        _message_id, actions = self._append_suggestion(
            99,
            "参考我的整理习惯，帮我整理当前资料",
        )
        self.assertEqual(
            {"archive_accept", "archive_reject", "organize_execute"},
            {action["kind"] for action in actions},
        )
        self.assertTrue((self.root / "photo.png").is_file())

    def test_projection_failure_rolls_back_assistant_and_actions_atomically(self) -> None:
        original = self.actions.register_prepared_in_transaction

        def fail_after_projection(*args: object, **kwargs: object) -> None:
            original(*args, **kwargs)
            raise ActionProjectionError("action_persistence_failed")

        body = {
            "client_message_id": "projection-failure-1",
            "actor_device_id": "windows-demo",
            "role": "user",
            "content": "智能整理电脑授权目录",
        }
        with mock.patch.object(
            self.actions,
            "register_prepared_in_transaction",
            side_effect=fail_after_projection,
        ):
            response = self.client.post(
                "/v1/conversations/action-demo/messages",
                json=body,
            )
            self.assertEqual(201, response.status_code, response.text)
            deadline = time.monotonic() + 2
            events: list[dict[str, object]] = []
            while time.monotonic() < deadline:
                events = self.client.get(
                    "/v1/conversations/action-demo/events?after_seq=0&limit=100"
                ).json()["events"]
                if len(events) >= 2:
                    break
                time.sleep(0.01)

        self.assertEqual(2, len(events))
        assistant = events[1]
        self.assertEqual("data-steward-agent", assistant["actor_device_id"])
        self.assertIn("本次智能处理已安全停止", assistant["payload"]["content"])
        self.assertNotIn("确认整理", assistant["payload"]["content"])
        with closing(sqlite3.connect(self.database)) as connection:
            action_count = connection.execute(
                "SELECT COUNT(*) FROM product_action"
            ).fetchone()[0]
            memory_assistant_count = connection.execute(
                """
                SELECT COUNT(*) FROM conversation_message
                WHERE actor_device_id='data-steward-memory'
                """
            ).fetchone()[0]
        self.assertEqual(0, action_count)
        self.assertEqual(0, memory_assistant_count)

        repeated = self.client.post(
            "/v1/conversations/action-demo/messages",
            json=body,
        )
        replay = self.client.get(
            "/v1/conversations/action-demo/events?after_seq=0&limit=100"
        ).json()["events"]
        self.assertEqual(200, repeated.status_code, repeated.text)
        self.assertEqual(events, replay)

    def test_prepared_projection_transaction_does_not_wait_for_action_lock(self) -> None:
        receipt = self.memory.execute(
            ArchiveIntent("suggest"),
            source_message_ref="r6-prepared-projection",
        )
        projection = self.actions.prepare_receipt_projection(receipt)
        store = EventStore(self.database)
        finished = threading.Event()
        errors: list[BaseException] = []
        results = []

        def append_projected_message() -> None:
            try:
                results.append(
                    store.append_message(
                        conversation_id="action-demo",
                        client_message_id="r6-concurrent-projection",
                        actor_device_id="data-steward-memory",
                        role="assistant",
                        content=receipt.conversation_text(),
                        transaction_hook=lambda connection, message: (
                            self.actions.register_prepared_in_transaction(
                                connection,
                                conversation_id="action-demo",
                                assistant_message_id=message.message_id,
                                projection=projection,
                            )
                        ),
                    )
                )
            except BaseException as error:  # noqa: BLE001
                errors.append(error)
            finally:
                finished.set()

        try:
            # execute_action holds this lock across its bounded operation. A
            # prepared projection must still commit without requesting it.
            with self.actions._lock:  # noqa: SLF001
                worker = threading.Thread(target=append_projected_message)
                worker.start()
                completed_without_lock_wait = finished.wait(3)
            worker.join(5)
        finally:
            store.close()

        self.assertTrue(
            completed_without_lock_wait,
            "prepared projection waited on the Action lock inside SQLite",
        )
        self.assertFalse(worker.is_alive())
        self.assertEqual([], errors)
        self.assertEqual(1, len(results))
        projected = self.actions.list_for_message(
            conversation_id="action-demo",
            assistant_message_id=results[0].message.message_id,
        )
        self.assertEqual(
            {"archive_accept", "archive_reject", "organize_execute"},
            {action.kind for action in projected},
        )

    def test_actions_hide_internal_references_and_execute_idempotently(self) -> None:
        message_id, actions = self._append_suggestion(1)
        self.assertEqual(
            {"archive_accept", "archive_reject", "organize_execute"},
            {a["kind"] for a in actions},
        )
        serialized = str(actions)
        self.assertNotIn("sg-", serialized)
        self.assertNotIn("mem-", serialized)
        accept = next(action for action in actions if action["kind"] == "archive_accept")
        path = (
            f"/v1/conversations/action-demo/messages/{message_id}/actions/"
            f"{accept['action_id']}"
        )
        first = self.client.post(path)
        second = self.client.post(path)
        self.assertEqual(200, first.status_code)
        self.assertEqual(200, second.status_code)
        self.assertEqual(
            first.json()["event"]["payload"]["message_id"],
            second.json()["event"]["payload"]["message_id"],
        )

    def test_action_stays_retryable_until_result_is_marked_durable(self) -> None:
        message_id, actions = self._append_suggestion(2)
        accept = next(action for action in actions if action["kind"] == "archive_accept")
        source_ref = "action-crash-window-fixture"

        first_receipt = self.actions.execute_action(
            conversation_id="action-demo",
            assistant_message_id=message_id,
            action_id=str(accept["action_id"]),
            archive_memory=self.memory,
            file_scope=self.scope,
            source_message_ref=source_ref,
        )
        still_available = self.actions.list_for_message(
            conversation_id="action-demo",
            assistant_message_id=message_id,
        )
        self.assertEqual("available", still_available[0].status)

        retried_receipt = self.actions.execute_action(
            conversation_id="action-demo",
            assistant_message_id=message_id,
            action_id=str(accept["action_id"]),
            archive_memory=self.memory,
            file_scope=self.scope,
            source_message_ref=source_ref,
        )
        self.assertEqual(first_receipt.suggestion_id, retried_receipt.suggestion_id)

        self.actions.mark_completed(str(accept["action_id"]))
        completed = self.actions.list_for_message(
            conversation_id="action-demo",
            assistant_message_id=message_id,
        )
        completed_action = next(
            item for item in completed if item.action_id == accept["action_id"]
        )
        self.assertEqual("completed", completed_action.status)

    def test_third_accept_projects_memory_approval_button(self) -> None:
        latest_actions: list[dict[str, object]] = []
        for index in range(3):
            message_id, actions = self._append_suggestion(index + 10)
            accept = next(action for action in actions if action["kind"] == "archive_accept")
            response = self.client.post(
                f"/v1/conversations/action-demo/messages/{message_id}/actions/{accept['action_id']}"
            )
            self.assertEqual(200, response.status_code)
            latest_actions = response.json()["actions"]
        self.assertEqual(["memory_approve"], [row["kind"] for row in latest_actions])
        self.assertNotIn("mem-", str(latest_actions))
        center = self.client.get("/v1/conversations/action-demo/memory")
        self.assertEqual(200, center.status_code)
        self.assertEqual("candidate", center.json()["status"])
        self.assertEqual(3, center.json()["support_count"])
        approve = center.json()["actions"][0]
        approved = self.client.post(
            "/v1/conversations/action-demo/messages/"
            f"{approve['assistant_message_id']}/actions/{approve['action_id']}"
        )
        self.assertEqual(200, approved.status_code)
        active = self.client.get("/v1/conversations/action-demo/memory").json()
        self.assertEqual("active", active["status"])
        self.assertEqual(["memory_forget"], [row["kind"] for row in active["actions"]])

    def test_accept_button_explicitly_relearns_after_forgotten_memory(self) -> None:
        latest_actions: list[dict[str, object]] = []
        for index in range(3):
            message_id, actions = self._append_suggestion(index + 60)
            accept = next(action for action in actions if action["kind"] == "archive_accept")
            response = self.client.post(
                f"/v1/conversations/action-demo/messages/{message_id}/actions/{accept['action_id']}"
            )
            self.assertEqual(200, response.status_code)
            latest_actions = response.json()["actions"]
        approve = next(action for action in latest_actions if action["kind"] == "memory_approve")
        approved = self.client.post(
            "/v1/conversations/action-demo/messages/"
            f"{approve['assistant_message_id']}/actions/{approve['action_id']}"
        )
        self.assertEqual(200, approved.status_code)
        active = self.client.get("/v1/conversations/action-demo/memory").json()
        forget = next(action for action in active["actions"] if action["kind"] == "memory_forget")
        forgotten = self.client.post(
            "/v1/conversations/action-demo/messages/"
            f"{forget['assistant_message_id']}/actions/{forget['action_id']}"
        )
        self.assertEqual(200, forgotten.status_code)

        message_id, actions = self._append_suggestion(70)
        accept = next(action for action in actions if action["kind"] == "archive_accept")
        relearned = self.client.post(
            f"/v1/conversations/action-demo/messages/{message_id}/actions/{accept['action_id']}"
        )
        self.assertEqual(200, relearned.status_code)
        memory = self.client.get("/v1/conversations/action-demo/memory").json()
        self.assertEqual("learning", memory["status"])
        self.assertEqual(1, memory["support_count"])

    def test_paused_memory_projects_explicit_reactivation_action(self) -> None:
        latest_actions: list[dict[str, object]] = []
        for index in range(3):
            message_id, actions = self._append_suggestion(index + 80)
            accept = next(action for action in actions if action["kind"] == "archive_accept")
            response = self.client.post(
                f"/v1/conversations/action-demo/messages/{message_id}/actions/{accept['action_id']}"
            )
            self.assertEqual(200, response.status_code)
            latest_actions = response.json()["actions"]
        approve = next(action for action in latest_actions if action["kind"] == "memory_approve")
        approved = self.client.post(
            "/v1/conversations/action-demo/messages/"
            f"{approve['assistant_message_id']}/actions/{approve['action_id']}"
        )
        self.assertEqual(200, approved.status_code)
        active = self.client.get("/v1/conversations/action-demo/memory").json()
        pause = next(action for action in active["actions"] if action["kind"] == "memory_forget")
        paused = self.client.post(
            "/v1/conversations/action-demo/messages/"
            f"{pause['assistant_message_id']}/actions/{pause['action_id']}"
        )
        self.assertEqual(200, paused.status_code)

        center = self.client.get("/v1/conversations/action-demo/memory").json()
        self.assertEqual("forgotten", center["status"])
        self.assertEqual(3, center["support_count"])
        self.assertEqual(["memory_approve"], [row["kind"] for row in center["actions"]])
        reactivate = center["actions"][0]
        result = self.client.post(
            "/v1/conversations/action-demo/messages/"
            f"{reactivate['assistant_message_id']}/actions/{reactivate['action_id']}"
        )
        self.assertEqual(200, result.status_code)
        restored = self.client.get("/v1/conversations/action-demo/memory").json()
        self.assertEqual("active", restored["status"])
        self.assertEqual(3, restored["support_count"])
        self.assertEqual(["memory_forget"], [row["kind"] for row in restored["actions"]])

    def test_confirmed_organization_projects_reversible_undo(self) -> None:
        message_id, actions = self._append_suggestion(30)
        organize = next(action for action in actions if action["kind"] == "organize_execute")
        response = self.client.post(
            f"/v1/conversations/action-demo/messages/{message_id}/actions/{organize['action_id']}"
        )
        self.assertEqual(200, response.status_code)
        self.assertFalse((self.root / "photo.png").exists())
        self.assertTrue(
            (self.root / "Data Steward 归档" / "图片" / "photo.png").is_file()
        )
        undo = response.json()["actions"]
        self.assertEqual(["organize_undo"], [row["kind"] for row in undo])
        undo_action = undo[0]
        undone = self.client.post(
            "/v1/conversations/action-demo/messages/"
            f"{undo_action['assistant_message_id']}/actions/{undo_action['action_id']}"
        )
        self.assertEqual(200, undone.status_code)
        self.assertTrue((self.root / "photo.png").is_file())
        self.assertFalse((self.root / "Data Steward 归档").exists())


if __name__ == "__main__":
    unittest.main()
