"""Integration tests for pairing HTTP contract (TestClient, no listener)."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Request
from fastapi.testclient import TestClient

from steward_hub.api import create_app
from steward_hub.pairing_api import MAX_PAIRING_BODY_BYTES
from steward_hub.pairing_codec import (
    canonicalize_capabilities,
    compute_short_verification_code,
)
from steward_hub.pairing_errors import PairingClosedError
from steward_hub.pairing_rate_limit import PairingRateLimiter
from steward_hub.pairing_store import PairingStore
from steward_hub.store import EventStore

PROTOCOL = "pairing_auth/1"
HUB_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
ATTEMPT_A = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
ATTEMPT_B = "01ARZ3NDEKTSV4RRFFQ69G5FB0"
MARKER_OTT = "R1_MARKER_PAIRING_TOKEN_7f3a9c"
MARKER_CLAIM = "R1_MARKER_CLAIM_SECRET_2b8e1d"
MARKER_AUTH = "R1_MARKER_AUTHORIZATION_VALUE_9c4"
MARKER_CRED = "R1_MARKER_DEVICE_CRED_SECRET_5a1"
MARKER_PATH = "R1_MARKER_DB_PATH_SHOULD_NOT_LEAK"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _digest_b64(token: str) -> str:
    pad = (-len(token)) % 4
    raw = base64.urlsafe_b64decode(token + ("=" * pad))
    return hashlib.sha256(raw).hexdigest()


class FakeClock:
    def __init__(self) -> None:
        self._now = datetime(2026, 7, 30, 3, 0, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self._now


class PairingApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = self.root / f"{MARKER_PATH}.sqlite3"
        self.clock = FakeClock()
        self.event_store = EventStore(self.db)
        self.pairing = PairingStore(
            self.db, clock=self.clock, auto_start_runtime=False
        )
        self.pairing.initialize_hub_identity(
            hub_id=HUB_ID,
            cert_fingerprint="a" * 64,
            tls_storage_kind="dpapi_encrypted_pkcs8",
            tls_key_ref_id="b2a-ref",
        )
        self.pairing.start_runtime()
        self.source = {"key": "src-a"}

        def source_fn(_: Request) -> str:
            return self.source["key"]

        self.limiter = PairingRateLimiter(
            limits={
                "client_hello": 10,
                "client_confirm": 20,
                "status": 30,
            },
            window_seconds=60.0,
        )
        self.app = create_app(
            event_store=self.event_store,
            pairing_store=self.pairing,
            pairing_rate_limiter=self.limiter,
            pairing_source_key_fn=source_fn,
            close_pairing_store=False,
        )
        self._client_cm = TestClient(self.app)
        self.client = self._client_cm.__enter__()
        self.ott_raw = b"\x11" * 32
        self.claim_raw = b"\x22" * 32
        self.cred_raw = b"\x33" * 32
        self.ott = _b64url(self.ott_raw)
        self.claim = _b64url(self.claim_raw)
        self.cred_digest = hashlib.sha256(self.cred_raw).hexdigest()
        self.session = self.pairing.create_pairing_session(
            pairing_token_digest=hashlib.sha256(self.ott_raw).hexdigest(),
            ttl_seconds=600,
        )

    def tearDown(self) -> None:
        self._client_cm.__exit__(None, None, None)
        self.pairing.close()
        self.event_store.close()
        self.tmp.cleanup()

    def _hello_body(self, **overrides: object) -> dict[str, object]:
        body: dict[str, object] = {
            "protocol_version": PROTOCOL,
            "pairing_attempt_id": ATTEMPT_A,
            "pairing_token": self.ott,
            "claim_secret": self.claim,
            "device_credential_digest": self.cred_digest,
            "client_nonce": "AAAAAAAAAAAAAAAAAAAAAA",
            "requested_capabilities": ["session.sync"],
            "platform": "android",
            "display_name": "PhoneA",
        }
        body.update(overrides)
        return body

    def _hello(self, **overrides: object):
        return self.client.post(
            f"/v1/pairing/sessions/{self.session.pairing_session_id}/client_hello",
            headers={"content-type": "application/json"},
            content=json.dumps(self._hello_body(**overrides)).encode("utf-8"),
        )

    def _confirm_headers(self, claim: str | None = None) -> dict[str, str]:
        token = self.claim if claim is None else claim
        return {
            "content-type": "application/json",
            "authorization": f"Pairing {token}",
            "X-DataSteward-Protocol": PROTOCOL,
        }

    def _confirm(self, short_code: str, *, claim: str | None = None, **overrides):
        body = {
            "protocol_version": PROTOCOL,
            "pairing_attempt_id": ATTEMPT_A,
            "short_verification_code": short_code,
        }
        body.update(overrides)
        return self.client.post(
            f"/v1/pairing/sessions/{self.session.pairing_session_id}/client_confirm",
            headers=self._confirm_headers(claim),
            content=json.dumps(body).encode("utf-8"),
        )

    def _status(self, *, claim: str | None = None, attempt: str = ATTEMPT_A):
        headers = {"X-DataSteward-Protocol": PROTOCOL}
        token = self.claim if claim is None else claim
        if token is not None:
            headers["authorization"] = f"Pairing {token}"
        return self.client.get(
            f"/v1/pairing/sessions/{self.session.pairing_session_id}/status",
            params={"pairing_attempt_id": attempt},
            headers=headers,
        )

    def _attempt_count(self) -> int:
        conn = sqlite3.connect(self.db)
        try:
            return int(
                conn.execute("SELECT COUNT(*) FROM pairing_attempt").fetchone()[0]
            )
        finally:
            conn.close()

    def test_client_hello_happy_retry_conflict_wrong_ott(self) -> None:
        first = self._hello()
        self.assertEqual(200, first.status_code, first.text)
        data = first.json()
        self.assertEqual("PENDING", data["credential_status"])
        device_id = data["device_id"]
        code = data["short_verification_code"]
        retry = self._hello()
        self.assertEqual(200, retry.status_code)
        self.assertEqual(device_id, retry.json()["device_id"])
        self.assertEqual(code, retry.json()["short_verification_code"])
        conflict = self._hello(platform="windows")
        self.assertEqual(409, conflict.status_code)
        self.assertEqual("pairing_attempt_conflict", conflict.json()["error_code"])

        self.pairing.abort_pairing_session(
            pairing_session_id=self.session.pairing_session_id, reason="cancel"
        )
        other = self.pairing.create_pairing_session(
            pairing_token_digest=hashlib.sha256(b"\x44" * 32).hexdigest(),
            ttl_seconds=600,
        )
        bad = self.client.post(
            f"/v1/pairing/sessions/{other.pairing_session_id}/client_hello",
            headers={"content-type": "application/json"},
            content=json.dumps(
                self._hello_body(pairing_attempt_id=ATTEMPT_B)
            ).encode(),
        )
        self.assertEqual(409, bad.status_code)
        self.assertEqual("pairing_rejected", bad.json()["error_code"])

    def test_same_qr_short_codes_diverge_and_second_attempt_busy(self) -> None:
        ott_digest = hashlib.sha256(self.ott_raw).hexdigest()
        caps, _, caps_digest = canonicalize_capabilities(["session.sync"])
        code_a = compute_short_verification_code(
            hub_id=HUB_ID,
            cert_fingerprint="a" * 64,
            pairing_session_id=self.session.pairing_session_id,
            pairing_attempt_id=ATTEMPT_A,
            ott_digest=ott_digest,
            device_credential_digest=hashlib.sha256(b"\x33" * 32).hexdigest(),
            claim_secret_digest=hashlib.sha256(b"\x22" * 32).hexdigest(),
            client_nonce="AAAAAAAAAAAAAAAAAAAAAA",
            requested_capabilities_digest=caps_digest,
        )
        code_b = compute_short_verification_code(
            hub_id=HUB_ID,
            cert_fingerprint="a" * 64,
            pairing_session_id=self.session.pairing_session_id,
            pairing_attempt_id=ATTEMPT_B,
            ott_digest=ott_digest,
            device_credential_digest=hashlib.sha256(b"\x77" * 32).hexdigest(),
            claim_secret_digest=hashlib.sha256(b"\x66" * 32).hexdigest(),
            client_nonce="BBBBBBBBBBBBBBBBBBBBBB",
            requested_capabilities_digest=caps_digest,
        )
        self.assertNotEqual(code_a, code_b)
        # Changing one client-bound field changes code_a.
        code_a2 = compute_short_verification_code(
            hub_id=HUB_ID,
            cert_fingerprint="a" * 64,
            pairing_session_id=self.session.pairing_session_id,
            pairing_attempt_id=ATTEMPT_A,
            ott_digest=ott_digest,
            device_credential_digest=hashlib.sha256(b"\x33" * 32).hexdigest(),
            claim_secret_digest=hashlib.sha256(b"\x22" * 32).hexdigest(),
            client_nonce="CCCCCCCCCCCCCCCCCCCCCC",
            requested_capabilities_digest=caps_digest,
        )
        self.assertNotEqual(code_a, code_a2)
        _ = caps

        first = self._hello()
        self.assertEqual(200, first.status_code)
        first_device = first.json()["device_id"]
        first_code = first.json()["short_verification_code"]
        second = self.client.post(
            f"/v1/pairing/sessions/{self.session.pairing_session_id}/client_hello",
            headers={"content-type": "application/json"},
            content=json.dumps(
                self._hello_body(
                    pairing_attempt_id=ATTEMPT_B,
                    claim_secret=_b64url(b"\x66" * 32),
                    device_credential_digest=hashlib.sha256(b"\x77" * 32).hexdigest(),
                    client_nonce="BBBBBBBBBBBBBBBBBBBBBB",
                )
            ).encode(),
        )
        self.assertEqual(409, second.status_code)
        self.assertEqual("pairing_busy", second.json()["error_code"])
        status = self._status()
        self.assertEqual(200, status.status_code)
        self.assertEqual(first_device, status.json()["device_id"])
        # First attempt short code unchanged in store via confirm path material.
        self.assertEqual(first_code, first.json()["short_verification_code"])

    def test_hello_validation_exact_negatives(self) -> None:
        cases = [
            ({"protocol_version": "nope"}, 400, "protocol_version_rejected"),
            (
                {"pairing_attempt_id": "not-a-ulid-value-xxxxxx"},
                400,
                "pairing_validation_error",
            ),
            (
                {"device_credential_digest": "G" * 64},
                400,
                "pairing_validation_error",
            ),
            ({"pairing_token": self.ott + "="}, 400, "pairing_validation_error"),
        ]
        before = self._attempt_count()
        for overrides, status, code in cases:
            with self.subTest(overrides=overrides):
                body = self._hello_body()
                body.update(overrides)
                response = self.client.post(
                    f"/v1/pairing/sessions/{self.session.pairing_session_id}/client_hello",
                    headers={"content-type": "application/json"},
                    content=json.dumps(body).encode("utf-8"),
                )
                self.assertEqual(status, response.status_code, response.text)
                self.assertEqual(code, response.json()["error_code"])
                self.assertEqual(
                    {"error_code", "message_key"}, set(response.json())
                )
        extra = self._hello_body()
        extra["extra"] = "field"
        response = self.client.post(
            f"/v1/pairing/sessions/{self.session.pairing_session_id}/client_hello",
            headers={"content-type": "application/json"},
            content=json.dumps(extra).encode("utf-8"),
        )
        self.assertEqual(400, response.status_code)
        self.assertEqual("pairing_validation_error", response.json()["error_code"])
        self.assertEqual(before, self._attempt_count())

    def test_duplicate_json_keys_rejected(self) -> None:
        before = self._attempt_count()
        base = self._hello_body()
        for field in ("pairing_token", "claim_secret", "pairing_attempt_id"):
            with self.subTest(field=field):
                parts = [f"{json.dumps(field)}: {json.dumps(base[field])}"]
                for key, value in base.items():
                    if key == field:
                        continue
                    parts.append(f"{json.dumps(key)}: {json.dumps(value)}")
                parts.append(f"{json.dumps(field)}: {json.dumps('DUPLICATE_VALUE')}")
                injected = "{" + ",".join(parts) + "}"
                self.assertEqual(2, injected.count(f'"{field}"'))
                response = self.client.post(
                    f"/v1/pairing/sessions/{self.session.pairing_session_id}/client_hello",
                    headers={"content-type": "application/json"},
                    content=injected.encode("utf-8"),
                )
                self.assertEqual(400, response.status_code, response.text)
                self.assertEqual(
                    "pairing_validation_error", response.json()["error_code"]
                )
        self.assertEqual(before, self._attempt_count())

    def test_dual_confirm_orders_and_status_recovery(self) -> None:
        hello = self._hello()
        code = hello.json()["short_verification_code"]
        device_id = hello.json()["device_id"]
        self.pairing.record_hub_confirmation(
            pairing_session_id=self.session.pairing_session_id,
            pairing_attempt_id=ATTEMPT_A,
            granted_capabilities=["session.sync"],
        )
        confirm = self._confirm(code)
        self.assertEqual(200, confirm.status_code)
        self.assertEqual("ACTIVE", confirm.json()["credential_status"])
        self.assertEqual(1, confirm.json()["capability_epoch"])
        again = self._confirm(code)
        self.assertEqual(200, again.status_code)
        status = self._status()
        self.assertEqual(200, status.status_code)
        self.assertEqual("ACTIVE", status.json()["credential_status"])
        self.assertEqual(device_id, status.json()["device_id"])

    def test_client_first_then_hub(self) -> None:
        hello = self._hello()
        code = hello.json()["short_verification_code"]
        pending = self._confirm(code)
        self.assertEqual(200, pending.status_code)
        self.assertEqual("PENDING", pending.json()["credential_status"])
        self.pairing.record_hub_confirmation(
            pairing_session_id=self.session.pairing_session_id,
            pairing_attempt_id=ATTEMPT_A,
            granted_capabilities=["session.sync"],
        )
        status = self._status()
        self.assertEqual("ACTIVE", status.json()["credential_status"])

    def test_confirm_auth_and_short_code(self) -> None:
        hello = self._hello()
        code = hello.json()["short_verification_code"]
        missing = self.client.post(
            f"/v1/pairing/sessions/{self.session.pairing_session_id}/client_confirm",
            headers={
                "content-type": "application/json",
                "X-DataSteward-Protocol": PROTOCOL,
            },
            content=json.dumps(
                {
                    "protocol_version": PROTOCOL,
                    "pairing_attempt_id": ATTEMPT_A,
                    "short_verification_code": code,
                }
            ).encode(),
        )
        self.assertEqual(401, missing.status_code)
        self.assertEqual("claim_missing", missing.json()["error_code"])
        wrong = self._confirm(code, claim=_b64url(b"\x99" * 32))
        self.assertEqual(401, wrong.status_code)
        self.assertEqual("claim_invalid", wrong.json()["error_code"])
        body_claim = self.client.post(
            f"/v1/pairing/sessions/{self.session.pairing_session_id}/client_confirm",
            headers=self._confirm_headers(),
            content=json.dumps(
                {
                    "protocol_version": PROTOCOL,
                    "pairing_attempt_id": ATTEMPT_A,
                    "short_verification_code": code,
                    "claim_secret": self.claim,
                }
            ).encode(),
        )
        self.assertEqual(400, body_claim.status_code)
        for _ in range(4):
            mismatch = self._confirm("2EJ9Y5EW")
            self.assertEqual(401, mismatch.status_code)
            self.assertEqual("short_code_mismatch", mismatch.json()["error_code"])
        fifth = self._confirm("2EJ9Y5EW")
        self.assertEqual(401, fifth.status_code)

    def test_status_claim_rules_and_confirm_loss(self) -> None:
        hello = self._hello()
        code = hello.json()["short_verification_code"]
        anon = self.client.get(
            f"/v1/pairing/sessions/{self.session.pairing_session_id}/status",
            params={"pairing_attempt_id": ATTEMPT_A},
            headers={"X-DataSteward-Protocol": PROTOCOL},
        )
        self.assertEqual(401, anon.status_code)
        self.assertEqual("claim_missing", anon.json()["error_code"])
        cross = self._status(claim=_b64url(b"\x88" * 32))
        self.assertEqual(401, cross.status_code)
        self.assertEqual("claim_invalid", cross.json()["error_code"])
        self.pairing.record_hub_confirmation(
            pairing_session_id=self.session.pairing_session_id,
            pairing_attempt_id=ATTEMPT_A,
            granted_capabilities=["session.sync"],
        )
        confirm = self._confirm(code)
        self.assertEqual(200, confirm.status_code)
        recovered = self._status()
        self.assertEqual(200, recovered.status_code)
        self.assertEqual("ACTIVE", recovered.json()["credential_status"])

    def test_protocol_header_required_on_confirm_status(self) -> None:
        hello = self._hello()
        code = hello.json()["short_verification_code"]
        no_header = self.client.post(
            f"/v1/pairing/sessions/{self.session.pairing_session_id}/client_confirm",
            headers={
                "content-type": "application/json",
                "authorization": f"Pairing {self.claim}",
            },
            content=json.dumps(
                {
                    "protocol_version": PROTOCOL,
                    "pairing_attempt_id": ATTEMPT_A,
                    "short_verification_code": code,
                }
            ).encode(),
        )
        self.assertEqual(400, no_header.status_code)
        self.assertEqual("protocol_version_rejected", no_header.json()["error_code"])

    def test_payload_too_large_content_length_and_stream(self) -> None:
        huge = b'{"protocol_version":"pairing_auth/1","pad":"' + (
            b"x" * (MAX_PAIRING_BODY_BYTES + 100)
        ) + b'"}'
        cl = self.client.post(
            f"/v1/pairing/sessions/{self.session.pairing_session_id}/client_hello",
            headers={
                "content-type": "application/json",
                "content-length": str(len(huge)),
            },
            content=huge,
        )
        self.assertEqual(413, cl.status_code)
        self.assertEqual("payload_too_large", cl.json()["error_code"])

        path = (
            f"/v1/pairing/sessions/{self.session.pairing_session_id}/client_hello"
        ).encode("ascii")
        scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": path.decode("ascii"),
            "raw_path": path,
            "query_string": b"",
            "headers": [(b"content-type", b"application/json")],
            "client": ("stream-src", 50000),
            "server": ("test", 80),
        }
        chunks = [huge[i : i + 1024] for i in range(0, len(huge), 1024)]
        state = {"i": 0}

        async def receive() -> dict[str, object]:
            idx = state["i"]
            if idx >= len(chunks):
                return {"type": "http.request", "body": b"", "more_body": False}
            body = chunks[idx]
            state["i"] = idx + 1
            return {
                "type": "http.request",
                "body": body,
                "more_body": idx + 1 < len(chunks),
            }

        messages: list[dict[str, object]] = []

        async def send(message: dict[str, object]) -> None:
            messages.append(message)

        import asyncio

        asyncio.run(self.app(scope, receive, send))
        start = next(m for m in messages if m["type"] == "http.response.start")
        self.assertEqual(413, start["status"])

    def test_http_rate_limits_three_endpoints(self) -> None:
        clock = {"t": 0.0}

        def mono() -> float:
            return clock["t"]

        limited = PairingRateLimiter(
            limits={"client_hello": 2, "client_confirm": 2, "status": 2},
            window_seconds=60.0,
            clock=mono,
        )
        self._client_cm.__exit__(None, None, None)
        self.app = create_app(
            event_store=self.event_store,
            pairing_store=self.pairing,
            pairing_rate_limiter=limited,
            pairing_source_key_fn=lambda _: self.source["key"],
        )
        self._client_cm = TestClient(self.app)
        self.client = self._client_cm.__enter__()

        self.assertEqual(200, self._hello().status_code)
        self.assertEqual(200, self._hello().status_code)
        third = self._hello()
        self.assertEqual(429, third.status_code)
        self.assertEqual("rate_limited", third.json()["error_code"])
        self.assertEqual("60", third.headers.get("Retry-After"))

        self.source["key"] = "src-confirm"
        hello = self._hello()
        self.assertEqual(200, hello.status_code)
        for _ in range(2):
            resp = self._confirm("2EJ9Y5EW", claim=_b64url(b"\xaa" * 32))
            self.assertEqual(401, resp.status_code)
        blocked = self._confirm("2EJ9Y5EW", claim=_b64url(b"\xaa" * 32))
        self.assertEqual(429, blocked.status_code)

        self.source["key"] = "src-status"
        self.assertEqual(200, self._hello().status_code)
        for _ in range(2):
            bad = self._status(claim=_b64url(b"\xbb" * 32))
            self.assertEqual(401, bad.status_code)
        status_blocked = self._status(claim=_b64url(b"\xbb" * 32))
        self.assertEqual(429, status_blocked.status_code)

        clock["t"] = 60.0
        self.source["key"] = "src-confirm"
        recovered = self._confirm("2EJ9Y5EW", claim=_b64url(b"\xaa" * 32))
        self.assertEqual(401, recovered.status_code)

    def test_openapi_pairing_schemas(self) -> None:
        openapi = self.client.get("/openapi.json").json()
        paths = openapi["paths"]
        hello = paths["/v1/pairing/sessions/{pairing_session_id}/client_hello"]["post"]
        confirm = paths[
            "/v1/pairing/sessions/{pairing_session_id}/client_confirm"
        ]["post"]
        status = paths["/v1/pairing/sessions/{pairing_session_id}/status"]["get"]
        self.assertIn("requestBody", hello)
        self.assertIn("requestBody", confirm)
        confirm_schema = json.dumps(confirm["requestBody"]).lower()
        self.assertNotIn("claim_secret", confirm_schema)
        status_schema = json.dumps(status).lower()
        self.assertNotIn("digest", status_schema)
        self.assertNotIn("pairing_token", status_schema)
        for path_item in (hello, confirm, status):
            for code in ("400", "401", "409", "410", "413", "429", "503"):
                self.assertIn(code, path_item.get("responses", {}))

    def test_secret_markers_never_leak(self) -> None:
        # Unique markers embedded into fixtures (base64url-safe alphabet only for secrets).
        ott = _b64url(hashlib.sha256(MARKER_OTT.encode()).digest())
        claim = _b64url(hashlib.sha256(MARKER_CLAIM.encode()).digest())
        cred_digest = hashlib.sha256(MARKER_CRED.encode()).hexdigest()
        self.pairing.abort_pairing_session(
            pairing_session_id=self.session.pairing_session_id, reason="cancel"
        )
        session = self.pairing.create_pairing_session(
            pairing_token_digest=_digest_b64(ott),
            ttl_seconds=600,
        )
        markers = [
            MARKER_OTT,
            MARKER_CLAIM,
            MARKER_AUTH,
            MARKER_CRED,
            MARKER_PATH,
            ott,
            claim,
            f"Pairing {claim}",
        ]
        records: list[str] = []

        class Handler(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record.getMessage())

        handler = Handler()
        root = logging.getLogger()
        root.addHandler(handler)
        try:
            body = self._hello_body(
                pairing_token=ott,
                claim_secret=claim,
                device_credential_digest=cred_digest,
            )
            wrong = self.client.post(
                f"/v1/pairing/sessions/{session.pairing_session_id}/client_hello",
                headers={"content-type": "application/json"},
                content=json.dumps(
                    {**body, "pairing_token": _b64url(b"\xee" * 32)}
                ).encode(),
            )
            self.assertEqual(409, wrong.status_code)
            good = self.client.post(
                f"/v1/pairing/sessions/{session.pairing_session_id}/client_hello",
                headers={"content-type": "application/json"},
                content=json.dumps(body).encode(),
            )
            self.assertEqual(200, good.status_code)
            bad_auth = self.client.get(
                f"/v1/pairing/sessions/{session.pairing_session_id}/status",
                params={"pairing_attempt_id": ATTEMPT_A},
                headers={
                    "X-DataSteward-Protocol": PROTOCOL,
                    "authorization": f"Pairing {MARKER_AUTH}xxxxxxxxxxxxxxxxxxxxxxx",
                },
            )
            self.assertEqual(401, bad_auth.status_code)
            surfaces = [
                wrong.text,
                good.text,
                bad_auth.text,
                json.dumps(dict(wrong.headers)),
                json.dumps(dict(good.headers)),
                "\n".join(records),
                str(wrong.json()),
                str(good.json()),
            ]
            db_bytes = self.db.read_bytes()
            for marker in markers:
                for surface in surfaces:
                    self.assertNotIn(marker, surface)
                self.assertEqual(0, db_bytes.count(marker.encode("utf-8")))
        finally:
            root.removeHandler(handler)

    def test_lifespan_close_pairing_store_flags(self) -> None:
        # close=false keeps external store usable after TestClient exit.
        app_keep = create_app(
            event_store=self.event_store,
            pairing_store=self.pairing,
            close_pairing_store=False,
            pairing_source_key_fn=lambda _: "life-keep",
        )
        with TestClient(app_keep) as client:
            self.assertEqual(200, client.get("/health").status_code)
        # External store still works.
        self.pairing.expire_due_sessions()

        owned = PairingStore(
            self.root / "owned.sqlite3",
            clock=self.clock,
            auto_start_runtime=False,
        )
        owned.initialize_hub_identity(
            hub_id="01ARZ3NDEKTSV4RRFFQ69G5FAW",
            cert_fingerprint="b" * 64,
            tls_storage_kind="dpapi_encrypted_pkcs8",
            tls_key_ref_id="owned",
        )
        owned.start_runtime()
        es2 = EventStore(self.root / "owned-events.sqlite3")
        app_close = create_app(
            event_store=es2,
            pairing_store=owned,
            close_pairing_store=True,
            pairing_source_key_fn=lambda _: "life-close",
        )
        with TestClient(app_close) as client:
            self.assertEqual(200, client.get("/health").status_code)
        with self.assertRaises(PairingClosedError):
            owned.expire_due_sessions()
        es2.close()

    def test_error_body_is_flat(self) -> None:
        response = self.client.post(
            f"/v1/pairing/sessions/{self.session.pairing_session_id}/client_hello",
            headers={"content-type": "application/json"},
            content=b"{}",
        )
        self.assertEqual({"error_code", "message_key"}, set(response.json()))


if __name__ == "__main__":
    unittest.main()
