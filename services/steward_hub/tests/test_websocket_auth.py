from __future__ import annotations

import base64
import json
import unittest

from steward_hub.device_auth import (
    AuthenticatedDevice,
    DeviceAuthError,
    authenticate_device_digest,
)
from steward_hub.pairing_models import AuthVerifyResult
from steward_hub.pairing_store_executor import PairingStoreSaturatedError
from steward_hub.websocket_auth import (
    MAX_AUTH_FRAME_BYTES,
    WebSocketAuthFrameError,
    auth_failed_frame,
    auth_ok_frame,
    decode_websocket_auth_message,
    validate_auth_frame_timeout_s,
    websocket_error_from_device,
)

DEVICE_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"


def _secret(byte: int) -> str:
    return base64.urlsafe_b64encode(bytes([byte]) * 32).decode("ascii").rstrip("=")


def _message(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "kind": "auth",
        "protocol_version": "pairing_auth/1",
        "device_id": DEVICE_ID,
        "capability_epoch": 1,
        "credential": _secret(7),
    }
    payload.update(overrides)
    return {"type": "websocket.receive", "text": json.dumps(payload)}


class WebSocketAuthCodecTest(unittest.TestCase):
    def test_valid_frame_returns_digest_only_credentials(self) -> None:
        raw_secret = _secret(7)
        result = decode_websocket_auth_message(_message(credential=raw_secret))

        self.assertEqual(DEVICE_ID, result.device_id)
        self.assertEqual(1, result.capability_epoch)
        self.assertEqual(64, len(result.credential_digest))
        self.assertNotIn(raw_secret, repr(result))

    def test_duplicate_keys_and_non_finite_numbers_fail_closed(self) -> None:
        duplicate = (
            '{"kind":"auth","kind":"auth",'
            '"protocol_version":"pairing_auth/1",'
            f'"device_id":"{DEVICE_ID}","capability_epoch":1,'
            f'"credential":"{_secret(7)}"}}'
        )
        non_finite = json.dumps(
            {
                "kind": "auth",
                "protocol_version": "pairing_auth/1",
                "device_id": DEVICE_ID,
                "capability_epoch": 1,
                "credential": _secret(7),
            }
        ).replace('"capability_epoch": 1', '"capability_epoch": NaN')

        for text in (duplicate, non_finite):
            with self.subTest(text=text[:20]):
                with self.assertRaises(WebSocketAuthFrameError) as context:
                    decode_websocket_auth_message(
                        {"type": "websocket.receive", "text": text}
                    )
                self.assertEqual("auth_invalid", context.exception.error_code)
                self.assertEqual(1008, context.exception.close_code)

    def test_strict_shape_and_field_boundaries(self) -> None:
        cases = (
            _message(extra="forbidden"),
            _message(kind="ready"),
            _message(device_id="not-a-device"),
            _message(capability_epoch=True),
            _message(capability_epoch=0),
            _message(capability_epoch=1 << 63),
            _message(credential="short"),
            {"type": "websocket.receive", "text": "[]"},
            {"type": "websocket.receive", "text": "{"},
            {"type": "websocket.receive", "bytes": b"{}"},
            {"type": "websocket.disconnect", "code": 1000},
        )
        for message in cases:
            with self.subTest(message=message):
                with self.assertRaises(WebSocketAuthFrameError) as context:
                    decode_websocket_auth_message(message)
                self.assertEqual("auth_invalid", context.exception.error_code)
                self.assertEqual(1008, context.exception.close_code)

    def test_protocol_mismatch_has_stable_error(self) -> None:
        with self.assertRaises(WebSocketAuthFrameError) as context:
            decode_websocket_auth_message(_message(protocol_version="pairing_auth/2"))
        self.assertEqual("protocol_version_rejected", context.exception.error_code)
        self.assertEqual(1008, context.exception.close_code)

    def test_oversized_frame_closes_1009(self) -> None:
        message = _message(extra="x" * MAX_AUTH_FRAME_BYTES)
        with self.assertRaises(WebSocketAuthFrameError) as context:
            decode_websocket_auth_message(message)
        self.assertEqual("payload_too_large", context.exception.error_code)
        self.assertEqual(1009, context.exception.close_code)

    def test_error_never_echoes_raw_frame_or_secret(self) -> None:
        raw_secret = _secret(5)
        with self.assertRaises(WebSocketAuthFrameError) as context:
            decode_websocket_auth_message(_message(credential=raw_secret, extra="x"))
        rendered = f"{context.exception!s}|{context.exception!r}"
        self.assertNotIn(raw_secret, rendered)
        self.assertNotIn(DEVICE_ID, rendered)

    def test_frame_builders_are_minimal_and_redacted(self) -> None:
        device = AuthenticatedDevice(
            device_id=DEVICE_ID,
            hub_id="01ARZ3NDEKTSV4RRFFQ69G5FAW",
            capability_epoch=3,
            granted_capabilities=("session.sync",),
            display_name="Phone",
            platform="android",
        )
        self.assertEqual(
            {
                "kind": "auth_ok",
                "protocol_version": "pairing_auth/1",
                "capability_epoch": 3,
            },
            auth_ok_frame(device),
        )
        self.assertEqual(
            {
                "kind": "auth_failed",
                "error_code": "auth_invalid",
                "message_key": "auth.auth_invalid",
            },
            auth_failed_frame("auth_invalid"),
        )
        with self.assertRaises(ValueError):
            auth_failed_frame(_secret(9))

    def test_timeout_validation_and_device_error_close_mapping(self) -> None:
        self.assertEqual(10.0, validate_auth_frame_timeout_s(10))
        for invalid in (0, -1, 31, True, float("nan"), float("inf")):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    validate_auth_frame_timeout_s(invalid)
        unavailable = websocket_error_from_device(
            DeviceAuthError("auth_unavailable", 503)
        )
        invalid = websocket_error_from_device(DeviceAuthError("auth_invalid", 401))
        self.assertEqual(("auth_unavailable", 1013), (
            unavailable.error_code,
            unavailable.close_code,
        ))
        self.assertEqual(("auth_invalid", 1008), (
            invalid.error_code,
            invalid.close_code,
        ))
        unknown = websocket_error_from_device(
            DeviceAuthError(_secret(9), 500)
        )
        self.assertEqual(("auth_unavailable", 1013), (
            unknown.error_code,
            unknown.close_code,
        ))


class SharedDigestAuthenticatorTest(unittest.IsolatedAsyncioTestCase):
    async def test_common_authenticator_forwards_digest_without_raw_secret(
        self,
    ) -> None:
        class Store:
            def verify_active_credential_digest(self, **_: object) -> None:
                raise AssertionError("executor owns invocation")

        class Executor:
            async def run(self, fn, /, *args, timeout_s, **kwargs):
                self.fn = fn
                self.args = args
                self.timeout_s = timeout_s
                self.kwargs = kwargs
                return AuthVerifyResult(
                    device_id=DEVICE_ID,
                    hub_id="01ARZ3NDEKTSV4RRFFQ69G5FAW",
                    status="ACTIVE",
                    capability_epoch=1,
                    granted_capabilities=["session.sync"],
                    display_name=None,
                    platform="android",
                )

        store = Store()
        executor = Executor()
        result = await authenticate_device_digest(
            pairing_store=store,  # type: ignore[arg-type]
            store_executor=executor,  # type: ignore[arg-type]
            device_id=DEVICE_ID,
            credential_digest="a" * 64,
            capability_epoch=1,
            required_capability="session.sync",
            timeout_s=4,
        )

        self.assertEqual(DEVICE_ID, result.device_id)
        self.assertIs(executor.fn.__self__, store)
        self.assertIs(
            executor.fn.__func__,
            store.verify_active_credential_digest.__func__,
        )
        self.assertEqual(4, executor.timeout_s)
        self.assertEqual("a" * 64, executor.kwargs["credential_digest"])
        self.assertNotIn("credential", executor.kwargs)

    async def test_common_authenticator_preserves_sanitized_failure_mapping(
        self,
    ) -> None:
        class Store:
            def verify_active_credential_digest(self, **_: object) -> None:
                raise AssertionError

        class Executor:
            async def run(self, *_args, **_kwargs):
                raise PairingStoreSaturatedError("private detail")

        with self.assertRaises(DeviceAuthError) as context:
            await authenticate_device_digest(
                pairing_store=Store(),  # type: ignore[arg-type]
                store_executor=Executor(),  # type: ignore[arg-type]
                device_id=DEVICE_ID,
                credential_digest="a" * 64,
                capability_epoch=1,
                required_capability="session.sync",
                timeout_s=4,
            )
        self.assertEqual("auth_unavailable", context.exception.error_code)
        self.assertNotIn("private detail", str(context.exception))


if __name__ == "__main__":
    unittest.main()
