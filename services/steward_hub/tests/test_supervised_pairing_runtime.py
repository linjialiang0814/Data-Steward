from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from steward_hub.pairing_store import PairingStore
from steward_hub.pairing_store_executor import PairingStoreExecutor
from steward_hub.supervised_pairing_runtime import (
    _serve_dual,
    create_local_pairing_control_app,
    serve_supervised_pairing,
)

HUB_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"


def _secret(byte: int) -> tuple[str, str]:
    raw = bytes([byte]) * 32
    encoded = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return encoded, hashlib.sha256(raw).hexdigest()


class _FakeServer:
    def __init__(self, *, fail: bool = False) -> None:
        self.started = False
        self.should_exit = False
        self.fail = fail
        self.exited = False

    async def serve(self) -> None:
        if self.fail:
            self.exited = True
            return
        self.started = True
        while not self.should_exit:
            await asyncio.sleep(0.001)
        self.exited = True


class SupervisedPairingRuntimeTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.database = self.root / "pairing.sqlite3"
        self.store = PairingStore(
            self.database,
            auto_start_runtime=False,
        )
        self.store.initialize_hub_identity(
            hub_id=HUB_ID,
            cert_fingerprint="a" * 64,
            tls_storage_kind="dpapi_encrypted_pkcs8",
            tls_key_ref_id="c2-test",
        )
        self.executor = PairingStoreExecutor(max_workers=1, max_queued=2)
        self.operator_secret, self.operator_digest = _secret(23)

    def tearDown(self) -> None:
        self.executor.shutdown(wait=True, cancel_queued=True)
        self.store.close()
        self._tmp.cleanup()

    def test_control_app_contains_pairing_operator_routes_only(self) -> None:
        app = create_local_pairing_control_app(
            pairing_store=self.store,
            store_executor=self.executor,
            operator_token_digest=self.operator_digest,
        )
        paths = set(app.openapi()["paths"])
        self.assertIn("/v1/operator/pairing/sessions", paths)
        self.assertFalse(any(path.startswith("/v1/operator/devices") for path in paths))
        self.assertFalse(any(path.startswith("/v1/pairing") for path in paths))
        self.assertFalse(any(path.startswith("/v1/conversations") for path in paths))

    def test_private_app_contains_public_pairing_routes_but_no_control(self) -> None:
        from steward_hub.api import create_app

        app = create_app(
            database_path=self.database,
            pairing_store=self.store,
            close_pairing_store=False,
            pairing_store_executor=self.executor,
            business_routes_enabled=False,
            transport_scope="private_lan_pairing_only",
        )
        paths = set(app.openapi()["paths"])
        self.assertIn(
            "/v1/pairing/sessions/{pairing_session_id}/client_hello",
            paths,
        )
        self.assertFalse(any(path.startswith("/v1/operator") for path in paths))
        self.assertFalse(any(path.startswith("/v1/conversations") for path in paths))

    def test_control_app_creates_digest_only_session(self) -> None:
        app = create_local_pairing_control_app(
            pairing_store=self.store,
            store_executor=self.executor,
            operator_token_digest=self.operator_digest,
        )
        _, ott_digest = _secret(29)
        headers = {
            "Authorization": f"DataSteward-Operator {self.operator_secret}",
            "X-DataSteward-Protocol": "pairing_auth/1",
        }
        with TestClient(app, raise_server_exceptions=False) as client:
            response = client.post(
                "/v1/operator/pairing/sessions",
                headers=headers,
                json={"pairing_token_digest": ott_digest, "ttl_seconds": 300},
            )
        self.assertEqual(201, response.status_code)
        self.assertNotIn(self.operator_secret, response.text)
        self.assertNotIn(ott_digest, response.text)
        self.assertNotIn(self.operator_secret.encode(), self.database.read_bytes())

    def test_dual_readiness_is_bounded_and_shutdown_is_coordinated(self) -> None:
        lan = _FakeServer()
        control = _FakeServer()
        payload = {
            "event": "c2_pairing_ready",
            "control_url": "https://127.0.0.1:41001",
            "pairing_url": "https://192.168.1.5:41002",
            "cert_fingerprint": "a" * 64,
        }
        stdout = io.StringIO()
        with patch("sys.stdin", io.StringIO("shutdown\n")), contextlib.redirect_stdout(
            stdout
        ):
            result = asyncio.run(
                _serve_dual(
                    lan_server=lan,  # type: ignore[arg-type]
                    control_server=control,  # type: ignore[arg-type]
                    ready_payload=payload,
                )
            )
        self.assertTrue(result)
        self.assertTrue(lan.exited)
        self.assertTrue(control.exited)
        self.assertEqual(payload, json.loads(stdout.getvalue()))

    def test_second_listener_failure_stops_the_first_without_readiness(self) -> None:
        lan = _FakeServer()
        control = _FakeServer(fail=True)
        stdout = io.StringIO()
        with patch("sys.stdin", io.StringIO("")), contextlib.redirect_stdout(stdout):
            result = asyncio.run(
                _serve_dual(
                    lan_server=lan,  # type: ignore[arg-type]
                    control_server=control,  # type: ignore[arg-type]
                    ready_payload={"event": "must_not_emit"},
                )
            )
        self.assertFalse(result)
        self.assertTrue(lan.exited)
        self.assertEqual("", stdout.getvalue())

    def test_public_host_fails_before_identity_or_database_access(self) -> None:
        database = self.root / "must-not-exist.sqlite3"
        identity = self.root / "must-not-read"
        with contextlib.redirect_stderr(io.StringIO()):
            result = serve_supervised_pairing(
                database_path=database,
                identity_root=identity,
                private_host="8.8.8.8",
                pairing_port=41002,
                control_port=41001,
                operator_token_digest=self.operator_digest,
                private_lan_authorized=True,
            )
        self.assertEqual(2, result)
        self.assertFalse(database.exists())
        self.assertFalse(identity.exists())


if __name__ == "__main__":
    unittest.main()
