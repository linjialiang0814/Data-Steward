"""B4 listener policy, route-surface, and pre-listen safety tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from steward_hub.api import create_app
from steward_hub.device_auth import AUTH_MODE_REQUIRED
from steward_hub.https_runtime import (
    EXIT_OK,
    EXIT_PRE_LISTEN,
    build_https_config,
    serve_https_hub,
)
from steward_hub.listen_policy import (
    LISTEN_AUTHENTICATED_SERVICE,
    LISTEN_DISABLED,
    LISTEN_LOOPBACK_ONLY,
    LISTEN_PAIRING_ONLY,
    ListenPolicyError,
    resolve_listen_policy,
)
from steward_hub.pairing_store import PairingStore
from steward_hub.pairing_store_executor import PairingStoreExecutor


class ListenPolicyTest(unittest.TestCase):
    def test_default_loopback_and_disabled_are_exact(self) -> None:
        loopback = resolve_listen_policy(
            mode=LISTEN_LOOPBACK_ONLY,
            host="127.0.0.1",
        )
        self.assertTrue(loopback.listener_enabled)
        self.assertFalse(loopback.private_lan)
        self.assertTrue(loopback.business_routes_enabled)
        self.assertEqual("loopback_only", loopback.transport_scope)

        disabled = resolve_listen_policy(
            mode=LISTEN_DISABLED,
            host="127.0.0.1",
        )
        self.assertFalse(disabled.listener_enabled)
        self.assertFalse(disabled.private_lan)

    def test_loopback_modes_reject_host_or_unexpected_acknowledgement(self) -> None:
        for mode, host, acknowledgement in (
            (LISTEN_LOOPBACK_ONLY, "0.0.0.0", False),
            (LISTEN_LOOPBACK_ONLY, "localhost", False),
            (LISTEN_DISABLED, "192.168.1.8", False),
            (LISTEN_LOOPBACK_ONLY, "127.0.0.1", True),
        ):
            with self.subTest(mode=mode, host=host):
                with self.assertRaises(ListenPolicyError):
                    resolve_listen_policy(
                        mode=mode,
                        host=host,
                        private_lan_authorized=acknowledgement,
                    )

    def test_private_lan_modes_require_ack_and_rfc1918_literal(self) -> None:
        for mode in (LISTEN_PAIRING_ONLY, LISTEN_AUTHENTICATED_SERVICE):
            with self.subTest(mode=mode):
                with self.assertRaises(ListenPolicyError):
                    resolve_listen_policy(
                        mode=mode,
                        host="192.168.1.8",
                    )
        for host in (
            "0.0.0.0",
            "127.0.0.1",
            "localhost",
            "::1",
            "169.254.1.1",
            "224.0.0.1",
            "8.8.8.8",
            "192.0.2.1",
        ):
            with self.subTest(host=host):
                with self.assertRaises(ListenPolicyError):
                    resolve_listen_policy(
                        mode=LISTEN_PAIRING_ONLY,
                        host=host,
                        private_lan_authorized=True,
                    )

    def test_private_lan_modes_project_distinct_surfaces(self) -> None:
        pairing = resolve_listen_policy(
            mode=LISTEN_PAIRING_ONLY,
            host="192.168.10.20",
            private_lan_authorized=True,
        )
        self.assertFalse(pairing.business_routes_enabled)
        self.assertEqual("private_lan_pairing_only", pairing.transport_scope)

        authenticated = resolve_listen_policy(
            mode=LISTEN_AUTHENTICATED_SERVICE,
            host="10.1.2.3",
            private_lan_authorized=True,
        )
        self.assertTrue(authenticated.business_routes_enabled)
        self.assertEqual(
            "private_lan_authenticated_service",
            authenticated.transport_scope,
        )

    def test_config_requires_the_same_resolved_policy(self) -> None:
        policy = resolve_listen_policy(
            mode=LISTEN_PAIRING_ONLY,
            host="172.16.4.5",
            private_lan_authorized=True,
        )
        identity = mock.Mock(
            cert_path=Path("fixture-cert.pem"),
            key_path=Path("fixture-key.pem"),
        )
        config = build_https_config(
            app=mock.Mock(),
            host=policy.host,
            port=43123,
            identity=identity,
            ssl_context_factory=mock.Mock(),
            listen_policy=policy,
        )
        self.assertEqual("172.16.4.5", config.host)
        with self.assertRaises(ValueError):
            build_https_config(
                app=mock.Mock(),
                host="172.16.4.6",
                port=43123,
                identity=identity,
                ssl_context_factory=mock.Mock(),
                listen_policy=policy,
            )


class PairingOnlySurfaceTest(unittest.TestCase):
    def test_pairing_only_removes_business_rest_ws_and_openapi(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "hub.sqlite3"
            pairing = PairingStore(database, auto_start_runtime=False)
            executor = PairingStoreExecutor(max_workers=1, max_queued=1)
            app = None
            try:
                app = create_app(
                    database_path=database,
                    pairing_store=pairing,
                    pairing_store_executor=executor,
                    close_pairing_store=False,
                    business_auth_mode=AUTH_MODE_REQUIRED,
                    business_routes_enabled=False,
                    transport_scope="private_lan_pairing_only",
                )
                self.assertEqual(
                    "private_lan_pairing_only",
                    app.state.transport_scope,
                )
                paths = app.openapi()["paths"]
                schemes = app.openapi().get("components", {}).get(
                    "securitySchemes", {}
                )
                self.assertFalse(
                    any(path.startswith("/v1/conversations") for path in paths)
                )
                self.assertTrue(
                    any(path.startswith("/v1/pairing/") for path in paths)
                )
                self.assertNotIn("DeviceBearer", schemes)
                self.assertNotIn("DataStewardOperator", schemes)
                self.assertFalse(
                    any(
                        str(getattr(route, "path", "")) not in {"", "/health"}
                        for route in app.router.routes
                    )
                )
            finally:
                executor.shutdown(wait=True, cancel_queued=True)
                pairing.close()
                if app is not None:
                    app.state.event_store.close()

    def test_surface_and_transport_scope_mismatches_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "hub.sqlite3"
            pairing = PairingStore(database, auto_start_runtime=False)
            try:
                with self.assertRaises(ValueError):
                    create_app(
                        database_path=database,
                        pairing_store=pairing,
                        business_auth_mode=AUTH_MODE_REQUIRED,
                        business_routes_enabled=True,
                        transport_scope="private_lan_pairing_only",
                    )
                with self.assertRaises(ValueError):
                    create_app(
                        database_path=database,
                        pairing_store=pairing,
                        business_auth_mode=AUTH_MODE_REQUIRED,
                        business_routes_enabled=False,
                        transport_scope="private_lan_authenticated_service",
                    )
                with self.assertRaises(ValueError):
                    create_app(
                        database_path=database,
                        pairing_store=pairing,
                        business_auth_mode=AUTH_MODE_REQUIRED,
                        transport_scope="private_lan_authenticated_service",
                        operator_token_digest="a" * 64,
                    )
            finally:
                pairing.close()


class DisabledAndUnsafeStartupTest(unittest.TestCase):
    def test_disabled_returns_without_identity_database_or_socket_work(self) -> None:
        with mock.patch(
            "steward_hub.https_runtime.load_tls_identity"
        ) as load_identity:
            code = serve_https_hub(
                database_path="must-not-exist.sqlite3",
                identity_root="must-not-exist-identity",
                host="127.0.0.1",
                port=43123,
                listen_mode=LISTEN_DISABLED,
            )
        self.assertEqual(EXIT_OK, code)
        load_identity.assert_not_called()

    def test_unsafe_policy_fails_before_identity_load(self) -> None:
        for mode, host, acknowledged in (
            (LISTEN_AUTHENTICATED_SERVICE, "0.0.0.0", True),
            (LISTEN_PAIRING_ONLY, "192.168.1.8", False),
            (LISTEN_LOOPBACK_ONLY, "192.168.1.8", False),
        ):
            with self.subTest(mode=mode, host=host):
                with mock.patch(
                    "steward_hub.https_runtime.load_tls_identity"
                ) as load_identity:
                    code = serve_https_hub(
                        database_path="must-not-exist.sqlite3",
                        identity_root="must-not-exist-identity",
                        host=host,
                        port=43123,
                        listen_mode=mode,
                        private_lan_authorized=acknowledged,
                    )
                self.assertEqual(EXIT_PRE_LISTEN, code)
                load_identity.assert_not_called()


if __name__ == "__main__":
    unittest.main()
