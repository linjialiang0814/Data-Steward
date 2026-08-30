"""Unit tests for digest-only PairingStore (B1B + R1 contract fixes)."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from steward_hub import EventStore, PairingStore
from steward_hub.pairing_codec import (
    MAX_CAPABILITIES,
    MAX_CAPABILITY_ITEM_LEN,
    MAX_CAPABILITY_JSON,
    canonicalize_capabilities,
    compute_short_verification_code,
    generate_ulid,
    hello_payload_hash,
    max_capabilities_json_utf8_len,
    require_digest,
    require_optional_display_name,
)
from steward_hub.pairing_errors import (
    PairingAttemptConflictError,
    PairingAuthInvalidError,
    PairingAuthRevokedError,
    PairingBusyError,
    PairingCapabilityDeniedError,
    PairingCapabilityEpochStaleError,
    PairingClaimInvalidError,
    PairingClosedError,
    PairingExpiredError,
    PairingIdentityCasError,
    PairingIdentityConflictError,
    PairingRejectedError,
    PairingSchemaError,
    PairingShortCodeMismatchError,
    PairingValidationError,
)
from steward_hub.pairing_models import CREDENTIAL_ACTIVE, SESSION_ACTIVE_PAIR
from steward_hub.pairing_store import SCHEMA_COMPONENT, SCHEMA_VERSION


class FakeClock:
    def __init__(self, start: datetime | None = None) -> None:
        self._now = start or datetime(2026, 7, 30, 1, 0, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self._now

    def advance(self, seconds: int) -> None:
        self._now = self._now + timedelta(seconds=seconds)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _fixed_rand(seed: int = 1):
    state = {"n": seed}

    def randbytes(n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            state["n"] = (state["n"] * 1103515245 + 12345) & 0x7FFFFFFF
            out.append(state["n"] & 0xFF)
        return bytes(out[:n])

    return randbytes


class CodecTest(unittest.TestCase):
    def test_human32_golden_vectors(self) -> None:
        cases = [
            (
                "2EJ9Y5EW",
                dict(
                    hub_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
                    cert_fingerprint="a" * 64,
                    pairing_session_id="01ARZ3NDEKTSV4RRFFQ69G5FAW",
                    pairing_attempt_id="01ARZ3NDEKTSV4RRFFQ69G5FAX",
                    ott_digest="b" * 64,
                    device_credential_digest="c" * 64,
                    claim_secret_digest="d" * 64,
                    client_nonce="AAAAAAAAAAAAAAAAAAAAAA",
                    requested_capabilities_digest="e" * 64,
                ),
            ),
            (
                "J5PLXKDR",
                dict(
                    hub_id="01BX5ZZKBKACTAV9WEVGEMMVRZ",
                    cert_fingerprint="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    pairing_session_id="01BX5ZZKBKACTAV9WEVGEMMVS0",
                    pairing_attempt_id="01BX5ZZKBKACTAV9WEVGEMMVS1",
                    ott_digest="0" * 64,
                    device_credential_digest="f" * 64,
                    claim_secret_digest="1" * 64,
                    client_nonce="BBBBBBBBBBBBBBBBBBBBBB",
                    requested_capabilities_digest="2" * 64,
                ),
            ),
            (
                "ZHSEF84R",
                dict(
                    hub_id="01HXYZEXAMPLE000000000001",
                    cert_fingerprint="deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    pairing_session_id="01HXYZEXAMPLE000000000002",
                    pairing_attempt_id="01HXYZEXAMPLE000000000003",
                    ott_digest="a" * 64,
                    device_credential_digest="b" * 64,
                    claim_secret_digest="c" * 64,
                    client_nonce="CCCCCCCCCCCCCCCCCCCCCC",
                    requested_capabilities_digest="d" * 64,
                ),
            ),
        ]
        for expected, kwargs in cases:
            with self.subTest(expected=expected):
                self.assertEqual(expected, compute_short_verification_code(**kwargs))

    def test_ulid_format_and_injection(self) -> None:
        clock = FakeClock(datetime(2026, 1, 1, tzinfo=timezone.utc))
        ulid = generate_ulid(clock=clock, randbytes=_fixed_rand(9))
        self.assertEqual(26, len(ulid))
        self.assertRegex(ulid, r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$")

    def test_capabilities_strict_and_bounds(self) -> None:
        caps, _payload, digest = canonicalize_capabilities(["a.sync", "b.read"])
        self.assertEqual(["a.sync", "b.read"], caps)
        self.assertEqual(digest, require_digest("x", digest))
        with self.assertRaises(PairingValidationError):
            canonicalize_capabilities(["b", "a"])
        with self.assertRaises(PairingValidationError):
            canonicalize_capabilities(["a", "a"])
        with self.assertRaises(PairingValidationError):
            canonicalize_capabilities(["bad token"])
        with self.assertRaises(PairingValidationError):
            canonicalize_capabilities(["a" + "x" * 64])
        with self.assertRaises(PairingValidationError):
            canonicalize_capabilities([f"c{i:02d}" for i in range(33)])


class PairingStoreCoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "pairing.sqlite3"
        self.clock = FakeClock()
        self.store = PairingStore(
            self.path,
            clock=self.clock,
            randbytes=_fixed_rand(1),
            auto_start_runtime=False,
        )
        self.hub = self.store.initialize_hub_identity(
            hub_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
            cert_fingerprint="a" * 64,
            tls_storage_kind="dpapi_encrypted_pkcs8",
            tls_key_ref_id="tls-ref-1",
        )

    def tearDown(self) -> None:
        self.store.close()
        self._tmp.cleanup()

    def _hello(
        self,
        session_id: str,
        *,
        attempt: str,
        ott_label: str,
        claim_label: str,
        cred_label: str,
        caps: list[str] | None = None,
        nonce: str = "AAAAAAAAAAAAAAAAAAAAAA",
        display_name: str | None = "Phone",
        platform: str = "android",
        ott_digest: str | None = None,
    ):
        return self.store.register_client_hello_digest(
            pairing_session_id=session_id,
            pairing_attempt_id=attempt,
            pairing_token_digest=ott_digest or _digest(ott_label),
            claim_secret_digest=_digest(claim_label),
            device_credential_digest=_digest(cred_label),
            client_nonce=nonce,
            requested_capabilities=caps or ["session.sync"],
            display_name=display_name,
            platform=platform,
        )

    def test_schema_version(self) -> None:
        conn = sqlite3.connect(self.path)
        try:
            row = conn.execute(
                "SELECT schema_version FROM pairing_schema_meta WHERE component=?",
                (SCHEMA_COMPONENT,),
            ).fetchone()
            self.assertEqual(SCHEMA_VERSION, int(row[0]))
        finally:
            conn.close()

    def test_unknown_schema_zero_ddl(self) -> None:
        path = Path(self._tmp.name) / "unknown-schema.sqlite3"
        conn = sqlite3.connect(path)
        try:
            conn.execute(
                """
                CREATE TABLE pairing_schema_meta (
                    component TEXT PRIMARY KEY,
                    schema_version INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                "INSERT INTO pairing_schema_meta(component, schema_version) VALUES (?, ?)",
                (SCHEMA_COMPONENT, 999),
            )
            conn.execute(
                "CREATE TABLE sentinel_probe(id INTEGER PRIMARY KEY, v TEXT NOT NULL)"
            )
            conn.execute("INSERT INTO sentinel_probe(id, v) VALUES (1, 'keep')")
            conn.commit()
            before = {
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
        finally:
            conn.close()
        with self.assertRaises(PairingSchemaError) as ctx:
            PairingStore(path, auto_start_runtime=False)
        self.assertEqual("pairing_schema_unsupported", ctx.exception.error_code)
        conn = sqlite3.connect(path)
        try:
            after = {
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            self.assertEqual(before, after)
            self.assertNotIn("hub_identity", after)
            self.assertNotIn("pairing_session", after)
            v = conn.execute("SELECT v FROM sentinel_probe WHERE id=1").fetchone()[0]
            self.assertEqual("keep", v)
            ver = conn.execute(
                "SELECT schema_version FROM pairing_schema_meta WHERE component=?",
                (SCHEMA_COMPONENT,),
            ).fetchone()[0]
            self.assertEqual(999, int(ver))
        finally:
            conn.close()

    def test_event_store_coexistence(self) -> None:
        events = EventStore(self.path)
        conv = events.create_conversation("coexist", conversation_id="c1")
        self.assertEqual("c1", conv.conversation_id)
        session = self.store.create_pairing_session(
            pairing_token_digest=_digest("ott-1"), ttl_seconds=120
        )
        self.assertTrue(session.pairing_session_id)
        again = events.get_conversation("c1")
        self.assertEqual("coexist", again.title)
        events.close()

    def test_identity_idempotent_and_conflict(self) -> None:
        again = self.store.initialize_hub_identity(
            hub_id=self.hub.hub_id,
            cert_fingerprint="a" * 64,
            tls_storage_kind="dpapi_encrypted_pkcs8",
            tls_key_ref_id="tls-ref-1",
        )
        self.assertEqual(self.hub.hub_id, again.hub_id)
        with self.assertRaises(PairingIdentityConflictError):
            self.store.initialize_hub_identity(
                hub_id=self.hub.hub_id,
                cert_fingerprint="b" * 64,
                tls_storage_kind="dpapi_encrypted_pkcs8",
                tls_key_ref_id="tls-ref-1",
            )

    def test_fingerprint_format_and_rotation_cas(self) -> None:
        with self.assertRaises(PairingValidationError):
            self.store.initialize_hub_identity(
                hub_id=self.hub.hub_id,
                cert_fingerprint="ZZ",
                tls_storage_kind="dpapi_encrypted_pkcs8",
                tls_key_ref_id="tls-ref-1",
            )
        with self.assertRaises(PairingIdentityCasError):
            self.store.rotate_hub_identity_reference(
                expected_current_fingerprint="b" * 64,
                new_cert_fingerprint="c" * 64,
                tls_storage_kind="dpapi_encrypted_pkcs8",
                tls_key_ref_id="tls-ref-2",
            )
        rotated = self.store.rotate_hub_identity_reference(
            expected_current_fingerprint="a" * 64,
            new_cert_fingerprint="c" * 64,
            tls_storage_kind="dpapi_encrypted_pkcs8",
            tls_key_ref_id="tls-ref-2",
        )
        self.assertEqual("c" * 64, rotated.cert_fingerprint)

    def test_ott_atomic_verify_wrong_zero_write(self) -> None:
        session = self.store.create_pairing_session(
            pairing_token_digest=_digest("ott-good"), ttl_seconds=300
        )
        before = self.path.read_bytes()
        with self.assertRaises(PairingRejectedError):
            self._hello(
                session.pairing_session_id,
                attempt="01ARZ3NDEKTSV4RRFFQ69G5FAX",
                ott_label="ott-bad",
                claim_label="claim",
                cred_label="cred",
            )
        conn = sqlite3.connect(self.path)
        try:
            attempts = conn.execute("SELECT COUNT(*) FROM pairing_attempt").fetchone()[0]
            creds = conn.execute("SELECT COUNT(*) FROM device_credential").fetchone()[0]
            state = conn.execute(
                "SELECT state FROM pairing_session WHERE pairing_session_id=?",
                (session.pairing_session_id,),
            ).fetchone()[0]
            self.assertEqual(0, attempts)
            self.assertEqual(0, creds)
            self.assertEqual("PAIRING_ACTIVE", state)
        finally:
            conn.close()
        # Correct OTT still works on same session
        hello = self._hello(
            session.pairing_session_id,
            attempt="01ARZ3NDEKTSV4RRFFQ69G5FAX",
            ott_label="ott-good",
            claim_label="claim",
            cred_label="cred",
        )
        self.assertFalse(hello.deduplicated)
        self.assertTrue(hello.device_id)
        _ = before  # silence lint; wrong OTT path asserted via SQL counts

    def test_hub_issues_device_id_and_retry_stable(self) -> None:
        session = self.store.create_pairing_session(
            pairing_token_digest=_digest("ott-h"), ttl_seconds=300
        )
        attempt = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
        first = self._hello(
            session.pairing_session_id,
            attempt=attempt,
            ott_label="ott-h",
            claim_label="claim",
            cred_label="cred",
        )
        again = self._hello(
            session.pairing_session_id,
            attempt=attempt,
            ott_label="ott-h",
            claim_label="claim",
            cred_label="cred",
        )
        self.assertTrue(again.deduplicated)
        self.assertEqual(first.device_id, again.device_id)
        self.assertEqual(first.short_verification_code, again.short_verification_code)
        # Caller must not supply device_id
        import inspect

        params = inspect.signature(
            self.store.register_client_hello_digest
        ).parameters
        self.assertNotIn("device_id", params)

    def test_hello_input_conflicts(self) -> None:
        session = self.store.create_pairing_session(
            pairing_token_digest=_digest("ott-c"), ttl_seconds=300
        )
        attempt = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
        self._hello(
            session.pairing_session_id,
            attempt=attempt,
            ott_label="ott-c",
            claim_label="claim",
            cred_label="cred",
        )
        conflict_cases = [
            dict(claim_label="claim2", cred_label="cred"),
            dict(claim_label="claim", cred_label="cred2"),
            dict(claim_label="claim", cred_label="cred", nonce="BBBBBBBBBBBBBBBBBBBBBB"),
            dict(claim_label="claim", cred_label="cred", caps=["session.sync", "z.cap"]),
            dict(claim_label="claim", cred_label="cred", display_name="Other"),
            dict(claim_label="claim", cred_label="cred", platform="windows"),
        ]
        for kwargs in conflict_cases:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(PairingAttemptConflictError):
                    self._hello(
                        session.pairing_session_id,
                        attempt=attempt,
                        ott_label="ott-c",
                        **kwargs,
                    )
        with self.assertRaises(PairingBusyError):
            self._hello(
                session.pairing_session_id,
                attempt="01ARZ3NDEKTSV4RRFFQ69G5FB0",
                ott_label="ott-c",
                claim_label="claim-x",
                cred_label="cred-x",
            )

    def test_claim_invalid_does_not_abort(self) -> None:
        session = self.store.create_pairing_session(
            pairing_token_digest=_digest("ott-cl"), ttl_seconds=300
        )
        attempt = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
        hello = self._hello(
            session.pairing_session_id,
            attempt=attempt,
            ott_label="ott-cl",
            claim_label="claim",
            cred_label="cred",
        )
        with self.assertRaises(PairingClaimInvalidError):
            self.store.record_client_confirmation_digest(
                pairing_session_id=session.pairing_session_id,
                pairing_attempt_id=attempt,
                claim_secret_digest=_digest("wrong"),
                short_verification_code=hello.short_verification_code,
            )
        conn = sqlite3.connect(self.path)
        try:
            state = conn.execute(
                "SELECT state FROM pairing_session WHERE pairing_session_id=?",
                (session.pairing_session_id,),
            ).fetchone()[0]
            status = conn.execute(
                "SELECT status FROM device_credential WHERE pairing_attempt_id=?",
                (attempt,),
            ).fetchone()[0]
            self.assertEqual("AWAITING_CONFIRM", state)
            self.assertEqual("PENDING", status)
        finally:
            conn.close()

    def test_short_code_threshold_and_recover(self) -> None:
        session = self.store.create_pairing_session(
            pairing_token_digest=_digest("ott-sc"), ttl_seconds=300
        )
        attempt = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
        hello = self._hello(
            session.pairing_session_id,
            attempt=attempt,
            ott_label="ott-sc",
            claim_label="claim",
            cred_label="cred",
        )
        for i in range(4):
            with self.assertRaises(PairingShortCodeMismatchError):
                self.store.record_client_confirmation_digest(
                    pairing_session_id=session.pairing_session_id,
                    pairing_attempt_id=attempt,
                    claim_secret_digest=_digest("claim"),
                    short_verification_code="2EJ9Y5EW",
                )
            conn = sqlite3.connect(self.path)
            try:
                state = conn.execute(
                    "SELECT state FROM pairing_session WHERE pairing_session_id=?",
                    (session.pairing_session_id,),
                ).fetchone()[0]
                count = conn.execute(
                    "SELECT short_code_mismatch_count FROM pairing_attempt WHERE pairing_attempt_id=?",
                    (attempt,),
                ).fetchone()[0]
                self.assertEqual("AWAITING_CONFIRM", state)
                self.assertEqual(i + 1, int(count))
            finally:
                conn.close()
        # After 4 wrongs, correct code still activates with hub confirm
        self.store.record_hub_confirmation(
            pairing_session_id=session.pairing_session_id,
            pairing_attempt_id=attempt,
            granted_capabilities=["session.sync"],
        )
        result = self.store.record_client_confirmation_digest(
            pairing_session_id=session.pairing_session_id,
            pairing_attempt_id=attempt,
            claim_secret_digest=_digest("claim"),
            short_verification_code=hello.short_verification_code,
        )
        self.assertTrue(result.activated)

    def test_short_code_fifth_aborts(self) -> None:
        session = self.store.create_pairing_session(
            pairing_token_digest=_digest("ott-sc5"), ttl_seconds=300
        )
        attempt = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
        hello = self._hello(
            session.pairing_session_id,
            attempt=attempt,
            ott_label="ott-sc5",
            claim_label="claim",
            cred_label="cred",
        )
        for _ in range(5):
            with self.assertRaises(PairingShortCodeMismatchError):
                self.store.record_client_confirmation_digest(
                    pairing_session_id=session.pairing_session_id,
                    pairing_attempt_id=attempt,
                    claim_secret_digest=_digest("claim"),
                    short_verification_code="2EJ9Y5EW",
                )
        conn = sqlite3.connect(self.path)
        try:
            state = conn.execute(
                "SELECT state FROM pairing_session WHERE pairing_session_id=?",
                (session.pairing_session_id,),
            ).fetchone()[0]
            status = conn.execute(
                "SELECT status FROM device_credential WHERE pairing_attempt_id=?",
                (attempt,),
            ).fetchone()[0]
            count = conn.execute(
                "SELECT short_code_mismatch_count FROM pairing_attempt WHERE pairing_attempt_id=?",
                (attempt,),
            ).fetchone()[0]
            self.assertEqual("ABORTED_MISMATCH", state)
            self.assertEqual("EXPIRED", status)
            self.assertEqual(5, int(count))
        finally:
            conn.close()
        _ = hello

    def test_concurrent_short_code_mismatch_count(self) -> None:
        session = self.store.create_pairing_session(
            pairing_token_digest=_digest("ott-conc"), ttl_seconds=300
        )
        attempt = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
        self._hello(
            session.pairing_session_id,
            attempt=attempt,
            ott_label="ott-conc",
            claim_label="claim",
            cred_label="cred",
        )
        barrier = threading.Barrier(4)
        errors: list[BaseException] = []

        def worker() -> None:
            barrier.wait(timeout=5)
            try:
                self.store.record_client_confirmation_digest(
                    pairing_session_id=session.pairing_session_id,
                    pairing_attempt_id=attempt,
                    claim_secret_digest=_digest("claim"),
                    short_verification_code="2EJ9Y5EW",
                )
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
        self.assertEqual(4, len(errors))
        self.assertTrue(all(isinstance(e, PairingShortCodeMismatchError) for e in errors))
        conn = sqlite3.connect(self.path)
        try:
            count = conn.execute(
                "SELECT short_code_mismatch_count FROM pairing_attempt WHERE pairing_attempt_id=?",
                (attempt,),
            ).fetchone()[0]
            self.assertEqual(4, int(count))
            state = conn.execute(
                "SELECT state FROM pairing_session WHERE pairing_session_id=?",
                (session.pairing_session_id,),
            ).fetchone()[0]
            self.assertEqual("AWAITING_CONFIRM", state)
        finally:
            conn.close()

    def test_status_attempt_binding(self) -> None:
        session = self.store.create_pairing_session(
            pairing_token_digest=_digest("ott-st"), ttl_seconds=300
        )
        attempt = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
        hello = self._hello(
            session.pairing_session_id,
            attempt=attempt,
            ott_label="ott-st",
            claim_label="claim",
            cred_label="cred",
        )
        status = self.store.get_redacted_pairing_status(
            pairing_session_id=session.pairing_session_id,
            pairing_attempt_id=attempt,
            claim_secret_digest=_digest("claim"),
        )
        self.assertEqual(attempt, status.pairing_attempt_id)
        self.assertEqual(hello.device_id, status.device_id)
        with self.assertRaises(PairingClaimInvalidError):
            self.store.get_redacted_pairing_status(
                pairing_session_id=session.pairing_session_id,
                pairing_attempt_id="01ARZ3NDEKTSV4RRFFQ69G5FB0",
                claim_secret_digest=_digest("claim"),
            )
        with self.assertRaises(PairingClaimInvalidError):
            self.store.get_redacted_pairing_status(
                pairing_session_id=session.pairing_session_id,
                pairing_attempt_id=attempt,
                claim_secret_digest=_digest("other"),
            )
        conn = sqlite3.connect(self.path)
        try:
            state = conn.execute(
                "SELECT state FROM pairing_session WHERE pairing_session_id=?",
                (session.pairing_session_id,),
            ).fetchone()[0]
            self.assertEqual("AWAITING_CONFIRM", state)
        finally:
            conn.close()

    def test_input_boundary_negatives(self) -> None:
        session = self.store.create_pairing_session(
            pairing_token_digest=_digest("ott-b"), ttl_seconds=300
        )
        attempt = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
        with self.assertRaises(PairingValidationError):
            self._hello(
                session.pairing_session_id,
                attempt=attempt,
                ott_label="ott-b",
                claim_label="claim",
                cred_label="cred",
                nonce="short",
            )
        with self.assertRaises(PairingValidationError):
            self._hello(
                session.pairing_session_id,
                attempt=attempt,
                ott_label="ott-b",
                claim_label="claim",
                cred_label="cred",
                display_name="bad\nname",
            )
        with self.assertRaises(PairingValidationError):
            self._hello(
                session.pairing_session_id,
                attempt=attempt,
                ott_label="ott-b",
                claim_label="claim",
                cred_label="cred",
                caps=["not valid"],
            )

    def test_single_open_session_and_concurrent(self) -> None:
        s1 = self.store.create_pairing_session(
            pairing_token_digest=_digest("ott-a"), ttl_seconds=60
        )
        with self.assertRaises(PairingBusyError):
            self.store.create_pairing_session(
                pairing_token_digest=_digest("ott-b"), ttl_seconds=60
            )
        self.store.abort_pairing_session(
            pairing_session_id=s1.pairing_session_id, reason="cancel"
        )
        outcomes: list[str] = []
        barrier = threading.Barrier(4)

        def worker(label: str) -> None:
            barrier.wait(timeout=5)
            try:
                self.store.create_pairing_session(
                    pairing_token_digest=_digest(label), ttl_seconds=60
                )
                outcomes.append("ok")
            except PairingBusyError:
                outcomes.append("busy")

        threads = [
            threading.Thread(target=worker, args=(f"conc-{i}",)) for i in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
        self.assertEqual(1, outcomes.count("ok"))
        self.assertEqual(3, outcomes.count("busy"))

    def test_server_ttl(self) -> None:
        session = self.store.create_pairing_session(
            pairing_token_digest=_digest("ott-ttl"), ttl_seconds=30
        )
        self.clock.advance(31)
        self.assertEqual(1, self.store.expire_due_sessions())
        with self.assertRaises(PairingExpiredError):
            self._hello(
                session.pairing_session_id,
                attempt="01ARZ3NDEKTSV4RRFFQ69G5FAX",
                ott_label="ott-ttl",
                claim_label="claim",
                cred_label="cred",
            )

    def test_dual_confirm_orders_and_activation(self) -> None:
        for order in ("client_first", "hub_first"):
            with self.subTest(order=order):
                self.clock.advance(1)
                session = self.store.create_pairing_session(
                    pairing_token_digest=_digest(f"ott-{order}"), ttl_seconds=300
                )
                attempt = generate_ulid(clock=self.clock, randbytes=_fixed_rand(3))
                hello = self._hello(
                    session.pairing_session_id,
                    attempt=attempt,
                    ott_label=f"ott-{order}",
                    claim_label=f"claim-{order}",
                    cred_label=f"cred-{order}",
                    caps=["fs.read", "session.sync"],
                )
                if order == "client_first":
                    c1 = self.store.record_client_confirmation_digest(
                        pairing_session_id=session.pairing_session_id,
                        pairing_attempt_id=attempt,
                        claim_secret_digest=_digest(f"claim-{order}"),
                        short_verification_code=hello.short_verification_code,
                    )
                    self.assertFalse(c1.activated)
                    c2 = self.store.record_hub_confirmation(
                        pairing_session_id=session.pairing_session_id,
                        pairing_attempt_id=attempt,
                        granted_capabilities=["session.sync"],
                    )
                    self.assertTrue(c2.activated)
                else:
                    h1 = self.store.record_hub_confirmation(
                        pairing_session_id=session.pairing_session_id,
                        pairing_attempt_id=attempt,
                        granted_capabilities=["session.sync"],
                    )
                    self.assertFalse(h1.activated)
                    h2 = self.store.record_client_confirmation_digest(
                        pairing_session_id=session.pairing_session_id,
                        pairing_attempt_id=attempt,
                        claim_secret_digest=_digest(f"claim-{order}"),
                        short_verification_code=hello.short_verification_code,
                    )
                    self.assertTrue(h2.activated)
                cred = self.store.get_device_credential(hello.device_id)
                self.assertEqual(CREDENTIAL_ACTIVE, cred.status)
                self.assertEqual(1, cred.capability_epoch)

    def test_grant_subset(self) -> None:
        session = self.store.create_pairing_session(
            pairing_token_digest=_digest("ott-g"), ttl_seconds=300
        )
        attempt = "01ARZ3NDEKTSV4RRFFQ69G5FC0"
        self._hello(
            session.pairing_session_id,
            attempt=attempt,
            ott_label="ott-g",
            claim_label="claim-g",
            cred_label="cred-g",
            caps=["session.sync"],
        )
        with self.assertRaises(PairingValidationError):
            self.store.record_hub_confirmation(
                pairing_session_id=session.pairing_session_id,
                pairing_attempt_id=attempt,
                granted_capabilities=["fs.write"],
            )

    def test_restart_keeps_active_expires_pending(self) -> None:
        s_active = self.store.create_pairing_session(
            pairing_token_digest=_digest("ott-act"), ttl_seconds=300
        )
        attempt_a = "01ARZ3NDEKTSV4RRFFQ69G5FD0"
        hello = self._hello(
            s_active.pairing_session_id,
            attempt=attempt_a,
            ott_label="ott-act",
            claim_label="claim-a",
            cred_label="cred-a",
        )
        self.store.record_client_confirmation_digest(
            pairing_session_id=s_active.pairing_session_id,
            pairing_attempt_id=attempt_a,
            claim_secret_digest=_digest("claim-a"),
            short_verification_code=hello.short_verification_code,
        )
        self.store.record_hub_confirmation(
            pairing_session_id=s_active.pairing_session_id,
            pairing_attempt_id=attempt_a,
            granted_capabilities=["session.sync"],
        )
        s_pending = self.store.create_pairing_session(
            pairing_token_digest=_digest("ott-pend"), ttl_seconds=300
        )
        hello_p = self._hello(
            s_pending.pairing_session_id,
            attempt="01ARZ3NDEKTSV4RRFFQ69G5FD2",
            ott_label="ott-pend",
            claim_label="claim-p",
            cred_label="cred-p",
        )
        boot1 = self.store.current_boot_id()
        # same instance restart is noop
        again = self.store.start_runtime()
        self.assertEqual(boot1, again.boot_id)
        self.store.close()
        store2 = PairingStore(
            self.path, clock=self.clock, randbytes=_fixed_rand(2), auto_start_runtime=True
        )
        self.assertNotEqual(boot1, store2.current_boot_id())
        cred_a = store2.get_device_credential(hello.device_id)
        self.assertEqual(CREDENTIAL_ACTIVE, cred_a.status)
        cred_p = store2.get_device_credential(hello_p.device_id)
        self.assertEqual("EXPIRED", cred_p.status)
        conn = sqlite3.connect(self.path)
        try:
            stopped = conn.execute(
                "SELECT COUNT(*) FROM hub_runtime WHERE stopped_at IS NOT NULL"
            ).fetchone()[0]
            self.assertGreaterEqual(int(stopped), 1)
            state_a = conn.execute(
                "SELECT state FROM pairing_session WHERE pairing_session_id=?",
                (s_active.pairing_session_id,),
            ).fetchone()[0]
            self.assertEqual(SESSION_ACTIVE_PAIR, state_a)
        finally:
            conn.close()
        store2.close()
        self.store = PairingStore(
            self.path, clock=self.clock, randbytes=_fixed_rand(5), auto_start_runtime=True
        )

    def test_verify_revoke_epoch_capability_status(self) -> None:
        session = self.store.create_pairing_session(
            pairing_token_digest=_digest("ott-v"), ttl_seconds=300
        )
        attempt = "01ARZ3NDEKTSV4RRFFQ69G5FE0"
        hello = self._hello(
            session.pairing_session_id,
            attempt=attempt,
            ott_label="ott-v",
            claim_label="claim-v",
            cred_label="cred-v",
        )
        self.store.record_hub_confirmation(
            pairing_session_id=session.pairing_session_id,
            pairing_attempt_id=attempt,
            granted_capabilities=["session.sync"],
        )
        self.store.record_client_confirmation_digest(
            pairing_session_id=session.pairing_session_id,
            pairing_attempt_id=attempt,
            claim_secret_digest=_digest("claim-v"),
            short_verification_code=hello.short_verification_code,
        )
        device = hello.device_id
        ok = self.store.verify_active_credential_digest(
            device_id=device,
            credential_digest=_digest("cred-v"),
            capability_epoch=1,
            required_capability="session.sync",
        )
        self.assertEqual(device, ok.device_id)
        with self.assertRaises(PairingCapabilityDeniedError):
            self.store.verify_active_credential_digest(
                device_id=device,
                credential_digest=_digest("cred-v"),
                capability_epoch=1,
                required_capability="fs.write",
            )
        with self.assertRaises(PairingCapabilityEpochStaleError):
            self.store.verify_active_credential_digest(
                device_id=device,
                credential_digest=_digest("cred-v"),
                capability_epoch=2,
            )
        with self.assertRaises(PairingAuthInvalidError):
            self.store.verify_active_credential_digest(
                device_id=device,
                credential_digest=_digest("wrong"),
                capability_epoch=1,
            )
        status = self.store.get_redacted_pairing_status(
            pairing_session_id=session.pairing_session_id,
            pairing_attempt_id=attempt,
            claim_secret_digest=_digest("claim-v"),
        )
        blob = json.dumps(status.__dict__)
        self.assertNotIn(_digest("ott-v"), blob)
        self.assertNotIn(_digest("cred-v"), blob)
        revoked = self.store.revoke_device_credential(
            device,
            expected_capability_epoch=1,
        )
        self.assertTrue(revoked.changed)
        self.assertEqual("REVOKED", revoked.credential.status)
        again = self.store.revoke_device_credential(
            device,
            expected_capability_epoch=1,
        )
        self.assertFalse(again.changed)
        self.assertEqual("REVOKED", again.credential.status)
        with self.assertRaises(PairingAuthInvalidError):
            self.store.verify_active_credential_digest(
                device_id=device,
                credential_digest=_digest("wrong-after-revoke"),
                capability_epoch=1,
            )
        with self.assertRaises(PairingAuthRevokedError):
            self.store.verify_active_credential_digest(
                device_id=device,
                credential_digest=_digest("cred-v"),
                capability_epoch=1,
            )

    def test_fault_injection_rollback(self) -> None:
        path = Path(self._tmp.name) / "fault-hello.sqlite3"

        def boom(name: str) -> None:
            if name == "after_hello_insert":
                raise RuntimeError("fault")

        store = PairingStore(
            path,
            clock=self.clock,
            randbytes=_fixed_rand(7),
            fault_injector=boom,
            auto_start_runtime=False,
        )
        store.initialize_hub_identity(
            hub_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
            cert_fingerprint="a" * 64,
            tls_storage_kind="dpapi_encrypted_pkcs8",
            tls_key_ref_id="tls-ref-1",
        )
        store._fault_injector = None
        session = store.create_pairing_session(
            pairing_token_digest=_digest("ott-f"), ttl_seconds=300
        )
        store._fault_injector = boom
        with self.assertRaises(RuntimeError):
            store.register_client_hello_digest(
                pairing_session_id=session.pairing_session_id,
                pairing_attempt_id="01ARZ3NDEKTSV4RRFFQ69G5FAX",
                pairing_token_digest=_digest("ott-f"),
                claim_secret_digest=_digest("c"),
                device_credential_digest=_digest("d"),
                client_nonce="AAAAAAAAAAAAAAAAAAAAAA",
                requested_capabilities=["session.sync"],
                display_name="Phone",
                platform="android",
            )
        store.close()
        conn = sqlite3.connect(path)
        try:
            n = conn.execute("SELECT COUNT(*) FROM pairing_attempt").fetchone()[0]
            self.assertEqual(0, n)
        finally:
            conn.close()

    def test_db_bytes_have_no_raw_secret_markers(self) -> None:
        raw_ott = "RAW_OTT_SECRET_MARKER_ZZZ"
        raw_claim = "RAW_CLAIM_SECRET_MARKER_YYY"
        raw_cred = "RAW_CRED_SECRET_MARKER_XXX"
        session = self.store.create_pairing_session(
            pairing_token_digest=hashlib.sha256(raw_ott.encode()).hexdigest(),
            ttl_seconds=300,
        )
        attempt = "01ARZ3NDEKTSV4RRFFQ69G5FF0"
        hello = self.store.register_client_hello_digest(
            pairing_session_id=session.pairing_session_id,
            pairing_attempt_id=attempt,
            pairing_token_digest=hashlib.sha256(raw_ott.encode()).hexdigest(),
            claim_secret_digest=hashlib.sha256(raw_claim.encode()).hexdigest(),
            device_credential_digest=hashlib.sha256(raw_cred.encode()).hexdigest(),
            client_nonce="AAAAAAAAAAAAAAAAAAAAAA",
            requested_capabilities=["session.sync"],
            display_name="Phone",
            platform="android",
        )
        self.store.record_hub_confirmation(
            pairing_session_id=session.pairing_session_id,
            pairing_attempt_id=attempt,
            granted_capabilities=["session.sync"],
        )
        self.store.record_client_confirmation_digest(
            pairing_session_id=session.pairing_session_id,
            pairing_attempt_id=attempt,
            claim_secret_digest=hashlib.sha256(raw_claim.encode()).hexdigest(),
            short_verification_code=hello.short_verification_code,
        )
        data = self.path.read_bytes()
        for marker in (raw_ott, raw_claim, raw_cred):
            self.assertEqual(-1, data.find(marker.encode("utf-8")))

    def test_reopen_and_close(self) -> None:
        session = self.store.create_pairing_session(
            pairing_token_digest=_digest("ott-close"), ttl_seconds=60
        )
        self.store.close()
        with self.assertRaises(PairingClosedError):
            self.store.create_pairing_session(
                pairing_token_digest=_digest("x"), ttl_seconds=60
            )
        store2 = PairingStore(
            self.path, clock=self.clock, randbytes=_fixed_rand(11), auto_start_runtime=True
        )
        conn = sqlite3.connect(self.path)
        try:
            state = conn.execute(
                "SELECT state FROM pairing_session WHERE pairing_session_id=?",
                (session.pairing_session_id,),
            ).fetchone()[0]
            self.assertEqual("ABORTED_HUB_RESTART", state)
        finally:
            conn.close()
        store2.close()
        self.store = PairingStore(
            self.path, clock=self.clock, randbytes=_fixed_rand(12), auto_start_runtime=True
        )

    def test_no_http_imports_in_pairing_modules(self) -> None:
        root = Path(__file__).resolve().parents[1] / "src" / "steward_hub"
        for name in (
            "pairing_store.py",
            "pairing_codec.py",
            "pairing_models.py",
            "pairing_errors.py",
        ):
            text = (root / name).read_text(encoding="utf-8")
            self.assertNotIn("fastapi", text.lower())
            self.assertNotIn("uvicorn", text.lower())
            self.assertNotIn("websocket", text.lower())
            self.assertNotIn("0.0.0.0", text)

    def test_client_confirm_no_existence_leak(self) -> None:
        s_a = self.store.create_pairing_session(
            pairing_token_digest=_digest("ott-a2"), ttl_seconds=300
        )
        attempt_a = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
        hello_a = self._hello(
            s_a.pairing_session_id,
            attempt=attempt_a,
            ott_label="ott-a2",
            claim_label="claim-a2",
            cred_label="cred-a2",
        )
        conn = sqlite3.connect(self.path)
        try:
            before_a = conn.execute(
                "SELECT s.state, a.short_code_mismatch_count FROM pairing_session s "
                "JOIN pairing_attempt a ON a.pairing_session_id=s.pairing_session_id "
                "WHERE s.pairing_session_id=?",
                (s_a.pairing_session_id,),
            ).fetchone()
            before_status = conn.execute(
                "SELECT status FROM device_credential WHERE pairing_attempt_id=?",
                (attempt_a,),
            ).fetchone()[0]
        finally:
            conn.close()

        # missing attempt on correct session
        with self.assertRaises(PairingClaimInvalidError):
            self.store.record_client_confirmation_digest(
                pairing_session_id=s_a.pairing_session_id,
                pairing_attempt_id="01ARZ3NDEKTSV4RRFFQ69G5FB9",
                claim_secret_digest=_digest("claim-a2"),
                short_verification_code=hello_a.short_verification_code,
            )
        # abort A so a second open session can be created
        self.store.abort_pairing_session(
            pairing_session_id=s_a.pairing_session_id, reason="cancel"
        )
        s_b = self.store.create_pairing_session(
            pairing_token_digest=_digest("ott-b2"), ttl_seconds=300
        )
        attempt_b = "01ARZ3NDEKTSV4RRFFQ69G5FB0"
        hello_b = self._hello(
            s_b.pairing_session_id,
            attempt=attempt_b,
            ott_label="ott-b2",
            claim_label="claim-b2",
            cred_label="cred-b2",
        )
        # attempt A claim used for attempt B
        with self.assertRaises(PairingClaimInvalidError):
            self.store.record_client_confirmation_digest(
                pairing_session_id=s_b.pairing_session_id,
                pairing_attempt_id=attempt_b,
                claim_secret_digest=_digest("claim-a2"),
                short_verification_code=hello_b.short_verification_code,
            )
        # attempt A paired with session B
        with self.assertRaises(PairingClaimInvalidError):
            self.store.record_client_confirmation_digest(
                pairing_session_id=s_b.pairing_session_id,
                pairing_attempt_id=attempt_a,
                claim_secret_digest=_digest("claim-a2"),
                short_verification_code=hello_a.short_verification_code,
            )
        conn = sqlite3.connect(self.path)
        try:
            # session A remains cancelled; mismatch count untouched from pre-abort snapshot
            count_a = conn.execute(
                "SELECT short_code_mismatch_count FROM pairing_attempt "
                "WHERE pairing_attempt_id=?",
                (attempt_a,),
            ).fetchone()[0]
            status_a = conn.execute(
                "SELECT status FROM device_credential WHERE pairing_attempt_id=?",
                (attempt_a,),
            ).fetchone()[0]
            state_b = conn.execute(
                "SELECT state FROM pairing_session WHERE pairing_session_id=?",
                (s_b.pairing_session_id,),
            ).fetchone()[0]
            count_b = conn.execute(
                "SELECT short_code_mismatch_count FROM pairing_attempt "
                "WHERE pairing_attempt_id=?",
                (attempt_b,),
            ).fetchone()[0]
            status_b = conn.execute(
                "SELECT status FROM device_credential WHERE pairing_attempt_id=?",
                (attempt_b,),
            ).fetchone()[0]
            self.assertEqual(int(before_a[1]), int(count_a))
            self.assertEqual("EXPIRED", status_a)  # abort expires PENDING
            self.assertEqual("AWAITING_CONFIRM", state_b)
            self.assertEqual(0, int(count_b))
            self.assertEqual("PENDING", status_b)
            self.assertEqual(before_status, "PENDING")
        finally:
            conn.close()

    def test_sql_digest_check_rejects_invalid_hex(self) -> None:
        # Ensure schema applied, then probe CHECK via raw SQL.
        conn = sqlite3.connect(self.path)
        try:
            bad_values = [
                ("A" * 64, "uppercase"),
                ("g" + "a" * 63, "nonhex"),
                ("a" * 63, "too_short"),
                ("a" * 65, "too_long"),
            ]
            for value, label in bad_values:
                with self.subTest(label=label, table="hub_identity"):
                    with self.assertRaises(sqlite3.IntegrityError):
                        conn.execute(
                            """
                            UPDATE hub_identity
                            SET cert_fingerprint = ?
                            WHERE hub_id = ?
                            """,
                            (value, self.hub.hub_id),
                        )
                with self.subTest(label=label, table="pairing_session"):
                    with self.assertRaises(sqlite3.IntegrityError):
                        conn.execute(
                            """
                            INSERT INTO pairing_session(
                                pairing_session_id, hub_id, boot_id,
                                pairing_token_digest, state, expires_at_server,
                                terminal_reason, created_at, consumed_at
                            ) VALUES (?, ?, ?, ?, 'PAIRING_ACTIVE', ?, NULL, ?, NULL)
                            """,
                            (
                                generate_ulid(
                                    clock=self.clock, randbytes=_fixed_rand(20)
                                ),
                                self.hub.hub_id,
                                self.store.current_boot_id(),
                                value,
                                "2099-01-01T00:00:00.000Z",
                                "2099-01-01T00:00:00.000Z",
                            ),
                        )
            # Positive control: lowercase 64 hex accepted by CHECK
            conn.execute(
                """
                UPDATE hub_identity SET cert_fingerprint = ? WHERE hub_id = ?
                """,
                ("b" * 64, self.hub.hub_id),
            )
            conn.rollback()
        finally:
            conn.close()

    def test_optional_display_name(self) -> None:
        self.assertIsNone(require_optional_display_name(None))
        with self.assertRaises(PairingValidationError):
            require_optional_display_name(" ")
        with self.assertRaises(PairingValidationError):
            require_optional_display_name("x" * 65)
        with self.assertRaises(PairingValidationError):
            require_optional_display_name("bad\nname")
        session = self.store.create_pairing_session(
            pairing_token_digest=_digest("ott-dn"), ttl_seconds=300
        )
        attempt = "01ARZ3NDEKTSV4RRFFQ69G5FC8"
        hello = self._hello(
            session.pairing_session_id,
            attempt=attempt,
            ott_label="ott-dn",
            claim_label="claim-dn",
            cred_label="cred-dn",
            display_name=None,
        )
        cred = self.store.get_device_credential(hello.device_id)
        self.assertIsNone(cred.display_name)
        caps, caps_json, caps_digest = canonicalize_capabilities(["session.sync"])
        h_missing = hello_payload_hash(
            pairing_session_id=session.pairing_session_id,
            pairing_attempt_id=attempt,
            claim_secret_digest=_digest("claim-dn"),
            device_credential_digest=_digest("cred-dn"),
            client_nonce="AAAAAAAAAAAAAAAAAAAAAA",
            requested_capabilities_json=caps_json,
            requested_capabilities_digest=caps_digest,
            display_name=None,
            platform="android",
        )
        h_present = hello_payload_hash(
            pairing_session_id=session.pairing_session_id,
            pairing_attempt_id=attempt,
            claim_secret_digest=_digest("claim-dn"),
            device_credential_digest=_digest("cred-dn"),
            client_nonce="AAAAAAAAAAAAAAAAAAAAAA",
            requested_capabilities_json=caps_json,
            requested_capabilities_digest=caps_digest,
            display_name="Phone",
            platform="android",
        )
        self.assertNotEqual(h_missing, h_present)
        _ = caps

    def test_input_boundary_matrix(self) -> None:
        session = self.store.create_pairing_session(
            pairing_token_digest=_digest("ott-bound"), ttl_seconds=300
        )
        attempt = "01ARZ3NDEKTSV4RRFFQ69G5FC9"
        # nonce
        for nonce in ("A" * 21, "A" * 23, "AAAAAAAAAAAAAAAAAAAAA*"):
            with self.subTest(nonce=nonce):
                with self.assertRaises(PairingValidationError):
                    self._hello(
                        session.pairing_session_id,
                        attempt=attempt,
                        ott_label="ott-bound",
                        claim_label="c",
                        cred_label="d",
                        nonce=nonce,
                    )
        # capabilities
        with self.assertRaises(PairingValidationError):
            canonicalize_capabilities([])
        with self.assertRaises(PairingValidationError):
            canonicalize_capabilities([f"c{i:02d}" for i in range(MAX_CAPABILITIES + 1)])
        with self.assertRaises(PairingValidationError):
            canonicalize_capabilities(["a", "a"])
        with self.assertRaises(PairingValidationError):
            canonicalize_capabilities(["b", "a"])
        with self.assertRaises(PairingValidationError):
            canonicalize_capabilities(["x" * (MAX_CAPABILITY_ITEM_LEN + 1)])
        with self.assertRaises(PairingValidationError):
            canonicalize_capabilities(["bad token"])
        # platform / display
        with self.assertRaises(PairingValidationError):
            self._hello(
                session.pairing_session_id,
                attempt=attempt,
                ott_label="ott-bound",
                claim_label="c",
                cred_label="d",
                platform="win\tdows",
            )
        with self.assertRaises(PairingValidationError):
            self._hello(
                session.pairing_session_id,
                attempt=attempt,
                ott_label="ott-bound",
                claim_label="c",
                cred_label="d",
                platform="p" * 33,
            )
        # Max legal capability JSON is under 4096 (secondary defense)
        max_len = max_capabilities_json_utf8_len()
        self.assertLessEqual(max_len, MAX_CAPABILITY_JSON)
        items = [
            f"c{i:02d}{'x' * (MAX_CAPABILITY_ITEM_LEN - 3)}"
            for i in range(MAX_CAPABILITIES)
        ]
        caps, payload, _digest_hex = canonicalize_capabilities(sorted(items))
        self.assertEqual(MAX_CAPABILITIES, len(caps))
        self.assertEqual(max_len, len(payload.encode("utf-8")))


if __name__ == "__main__":
    unittest.main()
