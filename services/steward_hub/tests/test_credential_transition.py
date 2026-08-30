from __future__ import annotations

import asyncio
import base64
import hashlib
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from steward_hub.api import create_app
from steward_hub.credential_transition import DeviceAuthorizationService
from steward_hub.device_auth import AUTH_MODE_REQUIRED, AuthenticatedDevice
from steward_hub.device_connection_registry import (
    AuthorizationTransition,
    DeviceConnectionAuthorizationChangedError,
    DeviceConnectionRegistry,
)
from steward_hub.pairing_errors import (
    PairingCapabilityEpochStaleError,
    PairingPersistenceError,
    PairingStateError,
    PairingValidationError,
)
from steward_hub.pairing_store import PairingStore
from steward_hub.pairing_store_executor import PairingStoreExecutor
from steward_hub.store import EventStore


HUB_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
ATTEMPT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
PAIRING_UI_ATTEMPT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAX"


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _secret(byte: int) -> tuple[str, str]:
    raw = bytes([byte]) * 32
    encoded = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return encoded, hashlib.sha256(raw).hexdigest()


def _activate(
    store: PairingStore,
    *,
    capabilities: list[str],
) -> tuple[str, str]:
    raw_secret, credential_digest = _secret(7)
    session = store.create_pairing_session(
        pairing_token_digest=_digest("transition-ott"),
        ttl_seconds=300,
    )
    hello = store.register_client_hello_digest(
        pairing_session_id=session.pairing_session_id,
        pairing_attempt_id=ATTEMPT_ID,
        pairing_token_digest=_digest("transition-ott"),
        claim_secret_digest=_digest("transition-claim"),
        device_credential_digest=credential_digest,
        client_nonce="AAAAAAAAAAAAAAAAAAAAAA",
        requested_capabilities=capabilities,
        display_name="Transition fixture",
        platform="test",
    )
    store.record_hub_confirmation(
        pairing_session_id=session.pairing_session_id,
        pairing_attempt_id=ATTEMPT_ID,
        granted_capabilities=capabilities,
    )
    store.record_client_confirmation_digest(
        pairing_session_id=session.pairing_session_id,
        pairing_attempt_id=ATTEMPT_ID,
        claim_secret_digest=_digest("transition-claim"),
        short_verification_code=hello.short_verification_code,
    )
    return hello.device_id, raw_secret


class CredentialTransitionStoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "transition.sqlite3"
        self.store = PairingStore(self.path, auto_start_runtime=False)
        self.store.initialize_hub_identity(
            hub_id=HUB_ID,
            cert_fingerprint="a" * 64,
            tls_storage_kind="dpapi_encrypted_pkcs8",
            tls_key_ref_id="transition-test",
        )
        self.device_id, _ = _activate(
            self.store,
            capabilities=["profile.read", "session.sync"],
        )

    def tearDown(self) -> None:
        self.store.close()
        self._tmp.cleanup()

    def test_capability_change_is_cas_idempotent_and_persistent(self) -> None:
        changed = self.store.update_device_capabilities(
            self.device_id,
            expected_capability_epoch=1,
            granted_capabilities=["session.sync"],
        )
        self.assertTrue(changed.changed)
        self.assertEqual(2, changed.credential.capability_epoch)
        self.assertEqual(
            ["session.sync"],
            changed.credential.granted_capabilities,
        )

        same = self.store.update_device_capabilities(
            self.device_id,
            expected_capability_epoch=2,
            granted_capabilities=["session.sync"],
        )
        self.assertFalse(same.changed)
        self.assertEqual(2, same.credential.capability_epoch)
        with self.assertRaises(PairingCapabilityEpochStaleError):
            self.store.update_device_capabilities(
                self.device_id,
                expected_capability_epoch=1,
                granted_capabilities=["session.sync"],
            )
        with self.assertRaises(PairingValidationError):
            self.store.update_device_capabilities(
                self.device_id,
                expected_capability_epoch=2,
                granted_capabilities=["fs.write"],
            )

        self.store.close()
        reopened = PairingStore(self.path, auto_start_runtime=False)
        try:
            view = reopened.get_device_credential(self.device_id)
            self.assertEqual(2, view.capability_epoch)
            self.assertEqual(["session.sync"], view.granted_capabilities)
        finally:
            reopened.close()
        self.store = PairingStore(self.path, auto_start_runtime=False)

    def test_revoke_requires_active_exact_epoch_and_is_idempotent(self) -> None:
        with self.assertRaises(PairingCapabilityEpochStaleError):
            self.store.revoke_device_credential(
                self.device_id,
                expected_capability_epoch=2,
            )
        revoked = self.store.revoke_device_credential(
            self.device_id,
            expected_capability_epoch=1,
        )
        self.assertTrue(revoked.changed)
        again = self.store.revoke_device_credential(
            self.device_id,
            expected_capability_epoch=1,
        )
        self.assertFalse(again.changed)
        with self.assertRaises(PairingStateError):
            self.store.update_device_capabilities(
                self.device_id,
                expected_capability_epoch=1,
                granted_capabilities=["session.sync"],
            )

    def test_concurrent_capability_cas_has_one_winner(self) -> None:
        barrier = threading.Barrier(2)
        outcomes: list[str] = []
        lock = threading.Lock()

        def update(grants: list[str]) -> None:
            barrier.wait(timeout=2)
            try:
                result = self.store.update_device_capabilities(
                    self.device_id,
                    expected_capability_epoch=1,
                    granted_capabilities=grants,
                )
                outcome = "changed" if result.changed else "noop"
            except PairingCapabilityEpochStaleError:
                outcome = "stale"
            with lock:
                outcomes.append(outcome)

        threads = (
            threading.Thread(target=update, args=(["session.sync"],)),
            threading.Thread(target=update, args=(["profile.read"],)),
        )
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(["changed", "stale"], sorted(outcomes))
        self.assertEqual(
            2,
            self.store.get_device_credential(
                self.device_id
            ).capability_epoch,
        )
    def test_capability_fault_rolls_back_epoch_grants_and_audit(self) -> None:
        self.store.close()
        armed = True

        def inject(stage: str) -> None:
            if armed and stage == "after_capability_change":
                raise sqlite3.OperationalError("synthetic secret-bearing fault")

        store = PairingStore(
            self.path,
            auto_start_runtime=False,
            fault_injector=inject,
        )
        try:
            with self.assertRaises(PairingPersistenceError):
                store.update_device_capabilities(
                    self.device_id,
                    expected_capability_epoch=1,
                    granted_capabilities=["session.sync"],
                )
            view = store.get_device_credential(self.device_id)
            self.assertEqual(1, view.capability_epoch)
            self.assertEqual(
                ["profile.read", "session.sync"],
                view.granted_capabilities,
            )
        finally:
            store.close()
        self.store = PairingStore(self.path, auto_start_runtime=False)


class CredentialTransitionCoordinationTest(unittest.IsolatedAsyncioTestCase):
    async def test_noop_transition_keeps_connection_authorized(self) -> None:
        registry = DeviceConnectionRegistry()
        closed = False

        async def close(_code: int, _reason: str) -> None:
            nonlocal closed
            closed = True

        async def verify() -> AuthenticatedDevice:
            return AuthenticatedDevice(
                device_id=HUB_ID,
                hub_id=ATTEMPT_ID,
                capability_epoch=1,
                granted_capabilities=("session.sync",),
                display_name=None,
                platform="test",
            )

        _, lease = await registry.authenticate_and_register(
            device_id=HUB_ID,
            verifier=verify,
            close_callback=close,
        )

        async def transition() -> AuthorizationTransition[str]:
            return AuthorizationTransition(
                value="unchanged",
                authorization_changed=False,
            )

        result = await registry.transition_and_close(
            device_id=HUB_ID,
            transition=transition,
        )
        self.assertEqual("unchanged", result.value)
        self.assertEqual(0, result.closed_connection_count)
        self.assertFalse(closed)
        sent = False

        async def send() -> None:
            nonlocal sent
            sent = True

        await lease.send_if_authorized(send)
        self.assertTrue(sent)
        await lease.unregister()

    async def test_rest_operation_finishes_before_transition_commit(self) -> None:
        registry = DeviceConnectionRegistry(
            max_operations=2,
            max_operations_per_device=1,
        )
        committed = asyncio.Event()

        async def verify() -> AuthenticatedDevice:
            return AuthenticatedDevice(
                device_id=HUB_ID,
                hub_id=ATTEMPT_ID,
                capability_epoch=1,
                granted_capabilities=("session.sync",),
                display_name=None,
                platform="test",
            )

        _, operation = await registry.authenticate_and_acquire_operation(
            device_id=HUB_ID,
            verifier=verify,
        )
        self.assertEqual(1, (await registry.snapshot()).operation_count)

        async def transition() -> None:
            committed.set()

        transition_task = asyncio.create_task(
            registry.transition_and_close(
                device_id=HUB_ID,
                transition=transition,
            )
        )
        await asyncio.sleep(0)
        self.assertFalse(committed.is_set())
        await operation.release()
        await transition_task
        self.assertTrue(committed.is_set())
        self.assertEqual(0, (await registry.snapshot()).operation_count)

    async def test_send_gate_finishes_before_transition_and_blocks_later_send(self) -> None:
        registry = DeviceConnectionRegistry(send_timeout_s=1, close_timeout_s=1)
        send_started = asyncio.Event()
        allow_send = asyncio.Event()
        transition_ran = asyncio.Event()
        holder: dict[str, object] = {}

        async def close(_code: int, _reason: str) -> None:
            await holder["lease"].unregister()  # type: ignore[union-attr]

        async def verify() -> AuthenticatedDevice:
            return AuthenticatedDevice(
                device_id=HUB_ID,
                hub_id=ATTEMPT_ID,
                capability_epoch=1,
                granted_capabilities=("session.sync",),
                display_name=None,
                platform="test",
            )

        _, lease = await registry.authenticate_and_register(
            device_id=HUB_ID,
            verifier=verify,
            close_callback=close,
        )
        holder["lease"] = lease

        async def send() -> None:
            send_started.set()
            await allow_send.wait()

        send_task = asyncio.create_task(lease.send_if_authorized(send))
        await send_started.wait()

        async def transition() -> None:
            transition_ran.set()

        transition_task = asyncio.create_task(
            registry.transition_and_close(
                device_id=HUB_ID,
                transition=transition,
            )
        )
        await asyncio.sleep(0)
        self.assertFalse(transition_ran.is_set())
        allow_send.set()
        await send_task
        await transition_task
        self.assertTrue(transition_ran.is_set())
        with self.assertRaises(DeviceConnectionAuthorizationChangedError):
            await lease.send_if_authorized(lambda: asyncio.sleep(0))

    async def test_completion_certain_executor_defers_cancellation(self) -> None:
        executor = PairingStoreExecutor(max_workers=1, max_queued=1)
        started = threading.Event()
        finish = threading.Event()
        completed = threading.Event()

        def mutation() -> str:
            started.set()
            finish.wait(timeout=2)
            completed.set()
            return "committed"

        task = asyncio.create_task(executor.run_completion_certain(mutation))
        await asyncio.to_thread(started.wait, 1)
        task.cancel()
        await asyncio.sleep(0.02)
        self.assertFalse(task.done())
        finish.set()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(completed.is_set())
        self.assertEqual(0, executor.pending_future_count)
        await asyncio.to_thread(executor.shutdown)


class CredentialTransitionApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "operator.sqlite3"
        self.pairing_store = PairingStore(self.path, auto_start_runtime=False)
        self.pairing_store.initialize_hub_identity(
            hub_id=HUB_ID,
            cert_fingerprint="b" * 64,
            tls_storage_kind="dpapi_encrypted_pkcs8",
            tls_key_ref_id="operator-test",
        )
        self.device_id, self.device_secret = _activate(
            self.pairing_store,
            capabilities=["profile.read", "session.sync"],
        )
        self.operator_secret, operator_digest = _secret(31)
        self.event_store = EventStore(self.path)
        self.registry = DeviceConnectionRegistry()
        self.app = create_app(
            event_store=self.event_store,
            pairing_store=self.pairing_store,
            business_auth_mode=AUTH_MODE_REQUIRED,
            operator_token_digest=operator_digest,
            device_connection_registry=self.registry,
        )
        self.client = TestClient(self.app, raise_server_exceptions=False)
        self.client.__enter__()

    def tearDown(self) -> None:
        self.client.__exit__(None, None, None)
        self.event_store.close()
        self.pairing_store.close()
        self._tmp.cleanup()

    def _headers(self, secret: str | None = None) -> dict[str, str]:
        return {
            "Authorization": (
                f"DataSteward-Operator {secret or self.operator_secret}"
            ),
            "X-DataSteward-Protocol": "pairing_auth/1",
            "Content-Type": "application/json",
        }

    def test_pairing_operator_create_inspect_confirm_and_activate(self) -> None:
        raw_ott, ott_digest = _secret(41)
        created = self.client.post(
            "/v1/operator/pairing/sessions",
            headers=self._headers(),
            json={"pairing_token_digest": ott_digest, "ttl_seconds": 300},
        )
        self.assertEqual(201, created.status_code)
        body = created.json()
        self.assertEqual(HUB_ID, body["hub_id"])
        self.assertEqual("b" * 64, body["cert_fingerprint"])
        self.assertEqual("PAIRING_ACTIVE", body["state"])
        session_id = body["pairing_session_id"]
        self.assertNotIn(raw_ott.encode("ascii"), self.path.read_bytes())

        before = self.client.get(
            f"/v1/operator/pairing/sessions/{session_id}",
            headers=self._headers(),
        )
        self.assertEqual(200, before.status_code)
        self.assertIsNone(before.json()["pairing_attempt_id"])
        self.assertIsNone(before.json()["short_verification_code"])

        hello = self.pairing_store.register_client_hello_digest(
            pairing_session_id=session_id,
            pairing_attempt_id=PAIRING_UI_ATTEMPT_ID,
            pairing_token_digest=ott_digest,
            claim_secret_digest=_digest("pairing-ui-claim"),
            device_credential_digest=_digest("pairing-ui-credential"),
            client_nonce="BBBBBBBBBBBBBBBBBBBBBB",
            requested_capabilities=["profile.read", "session.sync"],
            display_name="Huawei Phone",
            platform="android",
        )
        pending = self.client.get(
            f"/v1/operator/pairing/sessions/{session_id}",
            headers=self._headers(),
        )
        self.assertEqual(200, pending.status_code)
        pending_body = pending.json()
        self.assertEqual(hello.short_verification_code, pending_body["short_verification_code"])
        self.assertEqual(["profile.read", "session.sync"], pending_body["requested_capabilities"])
        self.assertFalse(pending_body["hub_confirmed"])

        confirmed = self.client.post(
            f"/v1/operator/pairing/sessions/{session_id}/attempts/"
            f"{PAIRING_UI_ATTEMPT_ID}/confirm",
            headers=self._headers(),
            json={"granted_capabilities": ["session.sync"]},
        )
        self.assertEqual(200, confirmed.status_code)
        self.assertTrue(confirmed.json()["hub_confirmed"])
        self.assertEqual("PENDING", confirmed.json()["credential_status"])

        client_result = self.pairing_store.record_client_confirmation_digest(
            pairing_session_id=session_id,
            pairing_attempt_id=PAIRING_UI_ATTEMPT_ID,
            claim_secret_digest=_digest("pairing-ui-claim"),
            short_verification_code=hello.short_verification_code,
        )
        self.assertEqual("ACTIVE", client_result.credential_status)
        active = self.client.get(
            f"/v1/operator/pairing/sessions/{session_id}",
            headers=self._headers(),
        ).json()
        self.assertEqual("ACTIVE_PAIR", active["state"])
        self.assertEqual(["session.sync"], active["granted_capabilities"])
        self.assertEqual(1, active["capability_epoch"])
        self.assertIsNone(active["short_verification_code"])

    def test_pairing_operator_wrong_auth_zero_write_and_cancel(self) -> None:
        before = sqlite3.connect(self.path)
        try:
            count_before = before.execute("SELECT COUNT(*) FROM pairing_session").fetchone()[0]
        finally:
            before.close()
        wrong, _ = _secret(42)
        denied = self.client.post(
            "/v1/operator/pairing/sessions",
            headers=self._headers(wrong),
            json={"pairing_token_digest": _digest("denied"), "ttl_seconds": 300},
        )
        self.assertEqual(401, denied.status_code)
        check = sqlite3.connect(self.path)
        try:
            self.assertEqual(
                count_before,
                check.execute("SELECT COUNT(*) FROM pairing_session").fetchone()[0],
            )
        finally:
            check.close()

        created = self.client.post(
            "/v1/operator/pairing/sessions",
            headers=self._headers(),
            json={"pairing_token_digest": _digest("cancel-ui"), "ttl_seconds": 300},
        ).json()
        cancelled = self.client.post(
            f"/v1/operator/pairing/sessions/{created['pairing_session_id']}/cancel",
            headers=self._headers(),
            json={},
        )
        self.assertEqual(200, cancelled.status_code)
        self.assertEqual("ABORTED_CANCEL", cancelled.json()["state"])

    def test_routes_are_feature_gated_and_operator_authenticated(self) -> None:
        enabled_schema = self.client.get("/openapi.json").json()
        self.assertIn(
            f"/v1/operator/devices/{{device_id}}",
            enabled_schema["paths"],
        )
        listed = self.client.get(
            "/v1/operator/devices",
            headers=self._headers(),
        )
        self.assertEqual(200, listed.status_code)
        self.assertEqual(1, len(listed.json()["devices"]))
        device = listed.json()["devices"][0]
        self.assertEqual(self.device_id, device["device_id"])
        self.assertNotIn("credential", device)
        self.assertIn(
            "DataStewardOperator",
            enabled_schema["components"]["securitySchemes"],
        )
        wrong, _ = _secret(30)
        denied = self.client.put(
            f"/v1/operator/devices/{self.device_id}/capabilities",
            headers=self._headers(wrong),
            json={
                "expected_capability_epoch": 1,
                "granted_capabilities": ["session.sync"],
            },
        )
        self.assertEqual(401, denied.status_code)
        self.assertEqual("operator_invalid", denied.json()["error_code"])
        duplicate_headers = [
            (
                "Authorization",
                f"DataSteward-Operator {self.operator_secret}",
            ),
            (
                "Authorization",
                f"DataSteward-Operator {self.operator_secret}",
            ),
            ("X-DataSteward-Protocol", "pairing_auth/1"),
            ("Content-Type", "application/json"),
        ]
        duplicate_auth = self.client.put(
            f"/v1/operator/devices/{self.device_id}/capabilities",
            headers=duplicate_headers,
            json={
                "expected_capability_epoch": 1,
                "granted_capabilities": ["session.sync"],
            },
        )
        self.assertEqual(401, duplicate_auth.status_code)

        disabled_event_store = EventStore(Path(self._tmp.name) / "disabled.sqlite3")
        disabled_pairing = PairingStore(
            Path(self._tmp.name) / "disabled.sqlite3",
            auto_start_runtime=False,
        )
        disabled_pairing.initialize_hub_identity(
            hub_id=ATTEMPT_ID,
            cert_fingerprint="c" * 64,
            tls_storage_kind="dpapi_encrypted_pkcs8",
            tls_key_ref_id="disabled-test",
        )
        disabled_app = create_app(
            event_store=disabled_event_store,
            pairing_store=disabled_pairing,
            business_auth_mode=AUTH_MODE_REQUIRED,
        )
        with TestClient(disabled_app) as disabled:
            disabled_schema = disabled.get("/openapi.json").json()
            self.assertFalse(
                any(
                    path.startswith("/v1/operator/")
                    for path in disabled_schema["paths"]
                )
            )
            response = disabled.post(
                f"/v1/operator/devices/{self.device_id}/revoke",
                headers=self._headers(),
                json={"expected_capability_epoch": 1},
            )
            self.assertEqual(404, response.status_code)
        disabled_event_store.close()
        disabled_pairing.close()

    def test_capability_change_noop_stale_and_revoke(self) -> None:
        changed = self.client.put(
            f"/v1/operator/devices/{self.device_id}/capabilities",
            headers=self._headers(),
            json={
                "expected_capability_epoch": 1,
                "granted_capabilities": ["session.sync"],
            },
        )
        self.assertEqual(200, changed.status_code, changed.text)
        self.assertTrue(changed.json()["changed"])
        self.assertEqual(2, changed.json()["capability_epoch"])
        status = self.client.get(
            f"/v1/operator/devices/{self.device_id}",
            headers={
                "Authorization": (
                    f"DataSteward-Operator {self.operator_secret}"
                ),
                "X-DataSteward-Protocol": "pairing_auth/1",
            },
        )
        self.assertEqual(200, status.status_code)
        self.assertEqual(2, status.json()["capability_epoch"])
        self.assertEqual(["session.sync"], status.json()["granted_capabilities"])

        same = self.client.put(
            f"/v1/operator/devices/{self.device_id}/capabilities",
            headers=self._headers(),
            json={
                "expected_capability_epoch": 2,
                "granted_capabilities": ["session.sync"],
            },
        )
        self.assertEqual(200, same.status_code)
        self.assertFalse(same.json()["changed"])

        stale = self.client.post(
            f"/v1/operator/devices/{self.device_id}/revoke",
            headers=self._headers(),
            json={"expected_capability_epoch": 1},
        )
        self.assertEqual(409, stale.status_code)
        self.assertEqual("capability_epoch_stale", stale.json()["error_code"])

        revoked = self.client.post(
            f"/v1/operator/devices/{self.device_id}/revoke",
            headers=self._headers(),
            json={"expected_capability_epoch": 2},
        )
        self.assertEqual(200, revoked.status_code)
        self.assertEqual("REVOKED", revoked.json()["status"])
        self.assertTrue(revoked.json()["changed"])

        again = self.client.post(
            f"/v1/operator/devices/{self.device_id}/revoke",
            headers=self._headers(),
            json={"expected_capability_epoch": 2},
        )
        self.assertEqual(200, again.status_code)
        self.assertFalse(again.json()["changed"])
        self.assertNotIn(self.operator_secret.encode("ascii"), self.path.read_bytes())

    def test_duplicate_json_and_grant_outside_request_fail_closed(self) -> None:
        duplicate = self.client.put(
            f"/v1/operator/devices/{self.device_id}/capabilities",
            headers=self._headers(),
            content=(
                b'{"expected_capability_epoch":1,'
                b'"expected_capability_epoch":1,'
                b'"granted_capabilities":["session.sync"]}'
            ),
        )
        self.assertEqual(400, duplicate.status_code)
        outside = self.client.put(
            f"/v1/operator/devices/{self.device_id}/capabilities",
            headers=self._headers(),
            json={
                "expected_capability_epoch": 1,
                "granted_capabilities": ["fs.write"],
            },
        )
        self.assertEqual(400, outside.status_code)
        self.assertEqual(
            1,
            self.pairing_store.get_device_credential(
                self.device_id
            ).capability_epoch,
        )


if __name__ == "__main__":
    unittest.main()
