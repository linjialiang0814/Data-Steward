from __future__ import annotations

import json
import socket
import ssl
import unittest
from unittest.mock import MagicMock, patch

from steward_hub.pin_client import PinFirstHttpsClient
from steward_hub.pin_websocket_client import (
    PinFirstWebSocketClient,
    PinFirstWebSocketError,
    validate_authenticated_wss_path,
)
from steward_hub.tls_identity.errors import TlsPinError


DEVICE_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
CREDENTIAL = "ERERERERERERERERERERERERERERERERERERERERERE"


class PinFirstHttpsSocketTransferTest(unittest.TestCase):
    def test_detach_transfers_only_verified_ssl_socket_once(self) -> None:
        client = PinFirstHttpsClient(
            host="127.0.0.1",
            port=443,
            expected_fingerprint="a" * 64,
        )
        sock = MagicMock(spec=ssl.SSLSocket)
        client._sock = sock  # type: ignore[assignment]
        client.pin_verified = True
        self.assertIs(sock, client.detach_verified_socket())
        self.assertFalse(client.pin_verified)
        self.assertIsNone(client._sock)
        with self.assertRaises(TlsPinError):
            client.detach_verified_socket()


class PinFirstWebSocketClientTest(unittest.TestCase):
    def test_path_is_exact_and_canonical(self) -> None:
        valid = "/v1/conversations/demo-1/events/ws?after_seq=0"
        self.assertEqual(valid, validate_authenticated_wss_path(valid))
        for invalid in (
            "/v1/conversations/demo/events/ws?after_seq=00",
            "/v1/conversations/demo/events/ws?after_seq=-1",
            "/v1/conversations/demo/events/ws?after_seq=0&extra=x",
            "/v1/conversations/a%2Fb/events/ws?after_seq=0",
            "wss://127.0.0.1/v1/conversations/demo/events/ws?after_seq=0",
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(ValueError, "wss_path_invalid"):
                    validate_authenticated_wss_path(invalid)

    def test_constructor_rejects_non_loopback_and_non_finite_timeout(self) -> None:
        with self.assertRaises(ValueError):
            PinFirstWebSocketClient(
                host="localhost",
                port=9443,
                expected_fingerprint="a" * 64,
            )
        with self.assertRaisesRegex(ValueError, "timeout_invalid"):
            PinFirstWebSocketClient(
                host="127.0.0.1",
                port=9443,
                expected_fingerprint="a" * 64,
                timeout_s=float("nan"),
            )

    @patch("steward_hub.pin_websocket_client.websocket_connect")
    @patch("steward_hub.pin_websocket_client.PinFirstHttpsClient")
    def test_wrong_pin_performs_zero_upgrade_and_auth(
        self,
        https_factory: MagicMock,
        websocket_connect: MagicMock,
    ) -> None:
        https_factory.return_value.connect_and_pin.side_effect = TlsPinError(
            "fingerprint_mismatch"
        )
        client = PinFirstWebSocketClient(
            host="127.0.0.1",
            port=9443,
            expected_fingerprint="b" * 64,
        )
        with self.assertRaises(TlsPinError):
            client.connect("/v1/conversations/demo/events/ws?after_seq=0")
        self.assertEqual(0, client.upgrade_attempt_count)
        self.assertEqual(0, client.auth_frame_sent_count)
        websocket_connect.assert_not_called()

    @patch("steward_hub.pin_websocket_client.websocket_connect")
    @patch("steward_hub.pin_websocket_client.PinFirstHttpsClient")
    def test_plain_socket_never_reaches_websocket_upgrade(
        self,
        https_factory: MagicMock,
        websocket_connect: MagicMock,
    ) -> None:
        plain_socket = MagicMock(spec=socket.socket)
        https_factory.return_value.detach_verified_socket.return_value = plain_socket
        client = PinFirstWebSocketClient(
            host="127.0.0.1",
            port=9443,
            expected_fingerprint="b" * 64,
        )
        with self.assertRaises(TlsPinError):
            client.connect("/v1/conversations/demo/events/ws?after_seq=0")
        plain_socket.close.assert_called_once_with()
        websocket_connect.assert_not_called()

    @patch("steward_hub.pin_websocket_client.websocket_connect")
    @patch("steward_hub.pin_websocket_client.PinFirstHttpsClient")
    def test_upgrade_failure_is_sanitized(
        self,
        https_factory: MagicMock,
        websocket_connect: MagicMock,
    ) -> None:
        https_factory.return_value.detach_verified_socket.return_value = MagicMock(
            spec=ssl.SSLSocket
        )
        websocket_connect.side_effect = OSError("private/path/and/port")
        client = PinFirstWebSocketClient(
            host="127.0.0.1",
            port=9443,
            expected_fingerprint="b" * 64,
        )
        with self.assertRaisesRegex(PinFirstWebSocketError, "connect_failed") as caught:
            client.connect("/v1/conversations/demo/events/ws?after_seq=0")
        self.assertNotIn("private", str(caught.exception))
        self.assertEqual(1, client.upgrade_attempt_count)
        self.assertEqual(0, client.auth_frame_sent_count)

    @patch("steward_hub.pin_websocket_client.websocket_connect")
    @patch("steward_hub.pin_websocket_client.PinFirstHttpsClient")
    def test_verified_ssl_socket_is_prewrapped_without_proxy_or_second_tls(
        self,
        https_factory: MagicMock,
        websocket_connect: MagicMock,
    ) -> None:
        sock = MagicMock(spec=ssl.SSLSocket)
        connection = MagicMock()
        https_factory.return_value.detach_verified_socket.return_value = sock
        websocket_connect.return_value = connection
        client = PinFirstWebSocketClient(
            host="127.0.0.1",
            port=9443,
            expected_fingerprint="c" * 64,
        )
        path = "/v1/conversations/demo/events/ws?after_seq=7"
        client.connect(path)
        args, kwargs = websocket_connect.call_args
        self.assertEqual(f"ws://127.0.0.1:9443{path}", args[0])
        self.assertIs(sock, kwargs["sock"])
        self.assertIsNone(kwargs["proxy"])
        self.assertNotIn("ssl", kwargs)
        self.assertIsNone(kwargs["compression"])
        self.assertIsNone(kwargs["user_agent_header"])
        self.assertTrue(client.pin_verified)
        self.assertEqual(1, client.upgrade_attempt_count)
        client.close()
        connection.close.assert_called_once_with()

    @patch("steward_hub.pin_websocket_client.websocket_connect")
    @patch("steward_hub.pin_websocket_client.PinFirstHttpsClient")
    def test_auth_send_and_strict_receive(
        self,
        https_factory: MagicMock,
        websocket_connect: MagicMock,
    ) -> None:
        https_factory.return_value.detach_verified_socket.return_value = MagicMock(
            spec=ssl.SSLSocket
        )
        connection = MagicMock()
        connection.recv.return_value = '{"kind":"ready","last_conversation_seq":0}'
        websocket_connect.return_value = connection
        client = PinFirstWebSocketClient(
            host="127.0.0.1",
            port=9443,
            expected_fingerprint="d" * 64,
        )
        client.connect("/v1/conversations/demo/events/ws?after_seq=0")
        client.send_auth(
            device_id=DEVICE_ID,
            capability_epoch=1,
            credential=CREDENTIAL,
        )
        sent = json.loads(connection.send.call_args.args[0])
        self.assertEqual("auth", sent["kind"])
        self.assertEqual(CREDENTIAL, sent["credential"])
        self.assertEqual(1, client.auth_frame_sent_count)
        with self.assertRaisesRegex(PinFirstWebSocketError, "auth_already_sent"):
            client.send_auth(
                device_id=DEVICE_ID,
                capability_epoch=1,
                credential=CREDENTIAL,
            )
        self.assertEqual(
            {"kind": "ready", "last_conversation_seq": 0},
            client.receive_json(),
        )
        client.close()

    @patch("steward_hub.pin_websocket_client.PinFirstHttpsClient")
    def test_connection_object_does_not_retry_after_pin_failure(
        self,
        https_factory: MagicMock,
    ) -> None:
        https_factory.return_value.connect_and_pin.side_effect = TlsPinError(
            "fingerprint_mismatch"
        )
        client = PinFirstWebSocketClient(
            host="127.0.0.1",
            port=9443,
            expected_fingerprint="f" * 64,
        )
        path = "/v1/conversations/demo/events/ws?after_seq=0"
        with self.assertRaises(TlsPinError):
            client.connect(path)
        with self.assertRaisesRegex(PinFirstWebSocketError, "already_connected"):
            client.connect(path)
        self.assertEqual(1, https_factory.call_count)

    @patch("steward_hub.pin_websocket_client.websocket_connect")
    @patch("steward_hub.pin_websocket_client.PinFirstHttpsClient")
    def test_invalid_auth_or_server_message_fails_closed(
        self,
        https_factory: MagicMock,
        websocket_connect: MagicMock,
    ) -> None:
        https_factory.return_value.detach_verified_socket.return_value = MagicMock(
            spec=ssl.SSLSocket
        )
        connection = MagicMock()
        websocket_connect.return_value = connection
        client = PinFirstWebSocketClient(
            host="127.0.0.1",
            port=9443,
            expected_fingerprint="e" * 64,
        )
        client.connect("/v1/conversations/demo/events/ws?after_seq=0")
        with self.assertRaisesRegex(ValueError, "auth_frame_invalid"):
            client.send_auth(
                device_id=DEVICE_ID,
                capability_epoch=1,
                credential="raw-secret-invalid",
            )
        self.assertEqual(0, client.auth_frame_sent_count)
        connection.send.assert_not_called()

        connection.recv.side_effect = [b"binary", '{"kind":1,"kind":2}']
        with self.assertRaisesRegex(
            PinFirstWebSocketError,
            "binary_message_rejected",
        ):
            client.receive_json()
        with self.assertRaisesRegex(PinFirstWebSocketError, "message_invalid"):
            client.receive_json()
        client.close()


if __name__ == "__main__":
    unittest.main()
