"""Pin-first loopback WSS client for tests and process Smoke only.

The helper performs TCP/TLS and certificate pinning before handing the
verified ``ssl.SSLSocket`` to ``websockets``. The WebSocket library receives a
``ws://`` URI solely to prevent a second TLS wrap; a plain socket is rejected.
There are no proxies, redirects, cookies, caller headers, or automatic retries.
"""

from __future__ import annotations

import json
import re
import ssl
from typing import Any, NoReturn

from websockets.sync.client import ClientConnection, connect as websocket_connect

from .pairing_codec import PROTOCOL_VERSION, require_ulid
from .pairing_errors import PairingValidationError
from .pairing_http_codec import PairingHttpCodecError, digest_secret_b64url
from .pin_client import LOOPBACK_HOST, PinFirstHttpsClient
from .tls_identity.errors import TlsPinError
from .websocket_auth import MAX_AUTH_FRAME_BYTES

MAX_INBOUND_MESSAGE_BYTES = 1 * 1024 * 1024
MAX_AFTER_SEQ = (1 << 63) - 1
_ROUTE_RE = re.compile(
    r"^/v1/conversations/([A-Za-z0-9][A-Za-z0-9._-]{0,127})/events/ws"
    r"\?after_seq=(0|[1-9][0-9]{0,18})$"
)


class PinFirstWebSocketError(RuntimeError):
    """Stable harness failure without URI, credential, or peer detail."""


def _reject_constant(_value: str) -> NoReturn:
    raise ValueError("non_finite_number")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate_key")
        value[key] = item
    return value


def validate_authenticated_wss_path(path: object) -> str:
    if not isinstance(path, str):
        raise ValueError("wss_path_invalid")
    match = _ROUTE_RE.fullmatch(path)
    if match is None or int(match.group(2)) > MAX_AFTER_SEQ:
        raise ValueError("wss_path_invalid")
    return path


class PinFirstWebSocketClient:
    """One-shot pinned loopback WSS connection with observable safety counters."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        expected_fingerprint: str,
        timeout_s: float = 5.0,
    ) -> None:
        if host != LOOPBACK_HOST:
            raise ValueError("only 127.0.0.1 is allowed")
        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65535
        ):
            raise ValueError("port_invalid")
        timeout = float(timeout_s) if isinstance(timeout_s, (int, float)) else 0.0
        if (
            isinstance(timeout_s, bool)
            or not isinstance(timeout_s, (int, float))
            or timeout != timeout
            or timeout <= 0
            or timeout > 30
        ):
            raise ValueError("timeout_invalid")
        self._host = host
        self._port = port
        self._expected_fingerprint = expected_fingerprint
        self._timeout_s = timeout
        self._connection: ClientConnection | None = None
        self._connect_attempted = False
        self.pin_verified = False
        self.upgrade_attempt_count = 0
        self.auth_frame_sent_count = 0

    def connect(self, path: str) -> None:
        if self._connect_attempted:
            raise PinFirstWebSocketError("already_connected")
        self._connect_attempted = True
        safe_path = validate_authenticated_wss_path(path)
        pin_client = PinFirstHttpsClient(
            host=self._host,
            port=self._port,
            expected_fingerprint=self._expected_fingerprint,
            timeout_s=self._timeout_s,
        )
        sock: ssl.SSLSocket | None = None
        try:
            pin_client.connect_and_pin()
            sock = pin_client.detach_verified_socket()
            if not isinstance(sock, ssl.SSLSocket):
                sock.close()
                sock = None
                raise TlsPinError("verified_socket_invalid")
            self.pin_verified = True
            self.upgrade_attempt_count += 1
            self._connection = websocket_connect(
                f"ws://{self._host}:{self._port}{safe_path}",
                sock=sock,
                proxy=None,
                compression=None,
                user_agent_header=None,
                open_timeout=self._timeout_s,
                ping_interval=None,
                close_timeout=self._timeout_s,
                max_size=MAX_INBOUND_MESSAGE_BYTES,
                max_queue=16,
            )
            sock = None
        except TlsPinError:
            self.pin_verified = False
            if sock is not None:
                sock.close()
            raise
        except Exception:
            self.pin_verified = False
            if sock is not None:
                sock.close()
            raise PinFirstWebSocketError("connect_failed") from None
        finally:
            pin_client.close()

    def send_auth(
        self,
        *,
        device_id: str,
        capability_epoch: int,
        credential: str,
    ) -> None:
        connection = self._require_connection()
        if self.auth_frame_sent_count != 0:
            raise PinFirstWebSocketError("auth_already_sent")
        try:
            safe_device_id = require_ulid("device_id", device_id)
        except PairingValidationError:
            raise ValueError("auth_frame_invalid") from None
        if (
            isinstance(capability_epoch, bool)
            or not isinstance(capability_epoch, int)
            or not 1 <= capability_epoch <= MAX_AFTER_SEQ
        ):
            raise ValueError("auth_frame_invalid")
        try:
            digest_secret_b64url(credential)
        except PairingHttpCodecError:
            raise ValueError("auth_frame_invalid") from None
        frame: dict[str, object] = {
            "kind": "auth",
            "protocol_version": PROTOCOL_VERSION,
            "device_id": safe_device_id,
            "capability_epoch": capability_epoch,
            "credential": credential,
        }
        encoded = ""
        try:
            encoded = json.dumps(frame, separators=(",", ":"), ensure_ascii=True)
            if len(encoded.encode("utf-8")) > MAX_AUTH_FRAME_BYTES:
                raise ValueError("auth_frame_invalid")
            try:
                connection.send(encoded)
            except Exception:
                self.close()
                raise PinFirstWebSocketError("auth_send_failed") from None
            self.auth_frame_sent_count += 1
        finally:
            frame.clear()
            encoded = ""

    def receive_json(self, *, timeout_s: float = 5.0) -> dict[str, Any]:
        connection = self._require_connection()
        try:
            message = connection.recv(timeout=timeout_s)
        except Exception:
            self.close()
            raise PinFirstWebSocketError("receive_failed") from None
        if not isinstance(message, str):
            raise PinFirstWebSocketError("binary_message_rejected")
        if len(message.encode("utf-8")) > MAX_INBOUND_MESSAGE_BYTES:
            raise PinFirstWebSocketError("message_too_large")
        try:
            value = json.loads(
                message,
                object_pairs_hook=_strict_object,
                parse_constant=_reject_constant,
            )
        except (TypeError, ValueError, json.JSONDecodeError):
            raise PinFirstWebSocketError("message_invalid") from None
        if not isinstance(value, dict):
            raise PinFirstWebSocketError("message_invalid")
        return value

    def close(self) -> None:
        connection = self._connection
        self._connection = None
        self.pin_verified = False
        if connection is not None:
            try:
                connection.close()
            except Exception:  # noqa: BLE001 - close is idempotent cleanup
                pass

    def _require_connection(self) -> ClientConnection:
        if self._connection is None or not self.pin_verified:
            raise PinFirstWebSocketError("not_connected")
        return self._connection

    def __enter__(self) -> PinFirstWebSocketClient:
        if self._connection is None:
            raise PinFirstWebSocketError("not_connected")
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()
