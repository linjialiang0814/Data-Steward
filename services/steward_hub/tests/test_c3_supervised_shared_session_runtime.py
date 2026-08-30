from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from steward_hub.api import create_app
from steward_hub.device_auth import AUTH_MODE_REQUIRED
from steward_hub.device_connection_registry import DeviceConnectionRegistry
from steward_hub.listen_policy import TRANSPORT_SCOPE_PRIVATE_LAN_AUTHENTICATED
from steward_hub.pairing_store import PairingStore
from steward_hub.pairing_store_executor import PairingStoreExecutor
from steward_hub.store import EventStore
from steward_hub.pc_file_scope import PcFileScopeService
from steward_hub.subscriptions import SubscriptionManager


def _paths(app: object) -> set[str]:
    return {
        str(getattr(route, "path", ""))
        for route in getattr(app, "routes", ())
        if getattr(route, "path", None)
    }


class C3AuthenticatedSurfaceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.database = Path(self.tmp.name) / "c3.sqlite3"
        self.pairing = PairingStore(self.database, auto_start_runtime=False)
        self.pairing.initialize_hub_identity(
            hub_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
            cert_fingerprint="a" * 64,
            tls_storage_kind="dpapi_encrypted_pkcs8",
            tls_key_ref_id="test",
        )
        self.pairing.start_runtime()
        self.events = EventStore(self.database)
        self.executor = PairingStoreExecutor()

    def tearDown(self) -> None:
        self.executor.shutdown(wait=True, cancel_queued=True)
        self.events.close()
        self.pairing.close()
        self.tmp.cleanup()

    def test_authenticated_surface_has_business_and_ott_pairing_but_no_operator_routes(
        self,
    ) -> None:
        file_scope = PcFileScopeService()
        app = create_app(
            event_store=self.events,
            subscription_manager=SubscriptionManager(),
            pairing_store=self.pairing,
            pairing_store_executor=self.executor,
            pc_file_scope_service=file_scope,
            business_auth_mode=AUTH_MODE_REQUIRED,
            pairing_routes_enabled=True,
            transport_scope=TRANSPORT_SCOPE_PRIVATE_LAN_AUTHENTICATED,
        )
        paths = set(app.openapi()["paths"])
        runtime_paths = _paths(app)
        self.assertIn("/health", paths)
        self.assertIn("/v1/conversations", paths)
        self.assertIn(
            "/v1/conversations/{conversation_id}/events/ws",
            runtime_paths,
        )
        self.assertIn(
            "/v1/pairing/sessions/{pairing_session_id}/client_hello",
            paths,
        )
        self.assertIn(
            "/v1/pairing/sessions/{pairing_session_id}/client_confirm",
            paths,
        )
        self.assertIn(
            "/v1/pairing/sessions/{pairing_session_id}/status",
            paths,
        )
        self.assertFalse(any(path.startswith("/v1/operator/") for path in paths))

    def test_pairing_route_policy_requires_pairing_store(self) -> None:
        with self.assertRaisesRegex(ValueError, "pairing route policy"):
            create_app(
                event_store=self.events,
                pairing_routes_enabled=False,
            )

    def test_loopback_admin_surface_has_operator_but_no_public_pairing(self) -> None:
        registry = DeviceConnectionRegistry()
        file_scope = PcFileScopeService()
        app = create_app(
            event_store=self.events,
            subscription_manager=SubscriptionManager(),
            pairing_store=self.pairing,
            pairing_store_executor=self.executor,
            device_connection_registry=registry,
            operator_token_digest="b" * 64,
            pc_file_scope_service=file_scope,
            pairing_routes_enabled=False,
        )
        paths = set(app.openapi()["paths"])
        self.assertIn("/v1/operator/devices", paths)
        self.assertIn("/v1/operator/devices/{device_id}/revoke", paths)
        self.assertIn("/v1/operator/file-scope", paths)
        self.assertFalse(any(path.startswith("/v1/pairing/") for path in paths))
