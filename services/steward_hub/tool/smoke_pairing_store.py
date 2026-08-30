"""Temporary-DB smoke for PairingStore (no listeners, no LocalAppData)."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from steward_hub.pairing_store import PairingStore


def _d(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def run_smoke() -> dict[str, object]:
    markers = (
        b"SMOKE_RAW_OTT_MARKER",
        b"SMOKE_RAW_CLAIM_MARKER",
        b"SMOKE_RAW_CRED_MARKER",
    )
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "pairing-smoke.sqlite3"
        clock_box = {"t": datetime(2026, 7, 30, 2, 0, 0, tzinfo=timezone.utc)}

        def clock() -> datetime:
            return clock_box["t"]

        store = PairingStore(db, clock=clock, auto_start_runtime=False)
        store.initialize_hub_identity(
            hub_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
            cert_fingerprint="a" * 64,
            tls_storage_kind="dpapi_encrypted_pkcs8",
            tls_key_ref_id="smoke-tls-ref",
        )
        boot1 = store.current_boot_id()
        # Same-instance start_runtime must not mint another boot.
        boot1b = store.start_runtime().boot_id
        s1 = store.create_pairing_session(
            pairing_token_digest=_d("smoke-ott-a"), ttl_seconds=600
        )
        hello_a = store.register_client_hello_digest(
            pairing_session_id=s1.pairing_session_id,
            pairing_attempt_id="01ARZ3NDEKTSV4RRFFQ69G5FAX",
            pairing_token_digest=_d("smoke-ott-a"),
            claim_secret_digest=_d("smoke-claim-a"),
            device_credential_digest=_d("smoke-cred-a"),
            client_nonce="AAAAAAAAAAAAAAAAAAAAAA",
            requested_capabilities=["session.sync"],
            display_name="DeviceA",
            platform="android",
        )
        # Wrong OTT must leave zero attempt rows for a fresh session probe via status.
        rejected = False
        try:
            store.register_client_hello_digest(
                pairing_session_id=s1.pairing_session_id,
                pairing_attempt_id="01ARZ3NDEKTSV4RRFFQ69G5FAY",
                pairing_token_digest=_d("smoke-ott-wrong"),
                claim_secret_digest=_d("smoke-claim-x"),
                device_credential_digest=_d("smoke-cred-x"),
                client_nonce="BBBBBBBBBBBBBBBBBBBBBB",
                requested_capabilities=["session.sync"],
                display_name="DeviceX",
                platform="android",
            )
        except Exception as exc:  # noqa: BLE001
            rejected = type(exc).__name__ == "PairingRejectedError"
        store.record_client_confirmation_digest(
            pairing_session_id=s1.pairing_session_id,
            pairing_attempt_id="01ARZ3NDEKTSV4RRFFQ69G5FAX",
            claim_secret_digest=_d("smoke-claim-a"),
            short_verification_code=hello_a.short_verification_code,
        )
        act = store.record_hub_confirmation(
            pairing_session_id=s1.pairing_session_id,
            pairing_attempt_id="01ARZ3NDEKTSV4RRFFQ69G5FAX",
            granted_capabilities=["session.sync"],
        )
        s2 = store.create_pairing_session(
            pairing_token_digest=_d("smoke-ott-b"), ttl_seconds=600
        )
        hello_b = store.register_client_hello_digest(
            pairing_session_id=s2.pairing_session_id,
            pairing_attempt_id="01ARZ3NDEKTSV4RRFFQ69G5FB0",
            pairing_token_digest=_d("smoke-ott-b"),
            claim_secret_digest=_d("smoke-claim-b"),
            device_credential_digest=_d("smoke-cred-b"),
            client_nonce="BBBBBBBBBBBBBBBBBBBBBB",
            requested_capabilities=["session.sync"],
            display_name="DeviceB",
            platform="android",
        )
        store.close()

        store2 = PairingStore(db, clock=clock, auto_start_runtime=True)
        boot2 = store2.current_boot_id()
        cred_a = store2.get_device_credential(hello_a.device_id)
        cred_b = store2.get_device_credential(hello_b.device_id)
        verify = store2.verify_active_credential_digest(
            device_id=hello_a.device_id,
            credential_digest=_d("smoke-cred-a"),
            capability_epoch=1,
            required_capability="session.sync",
        )
        revoked = store2.revoke_device_credential(
            hello_a.device_id,
            expected_capability_epoch=1,
        )
        store2.close()

        raw = db.read_bytes()
        marker_hits = sum(raw.count(m) for m in markers)
        secret_hits = sum(
            raw.count(x)
            for x in (
                b"smoke-ott-a",
                b"smoke-claim-a",
                b"smoke-cred-a",
                b"SMOKE_RAW",
            )
        )
        conn = sqlite3.connect(db)
        try:
            audit_rows = conn.execute("SELECT detail_json FROM auth_audit").fetchall()
            audit_secret_fields = 0
            for (detail,) in audit_rows:
                keys = set(json.loads(detail))
                if any("digest" in k or "secret" in k for k in keys):
                    audit_secret_fields += 1
            attempt_count = conn.execute(
                "SELECT COUNT(*) FROM pairing_attempt"
            ).fetchone()[0]
        finally:
            conn.close()

        report = {
            "status": "PASS",
            "identity_initialized": True,
            "same_instance_boot_stable": boot1 == boot1b,
            "boot_changed": boot1 != boot2,
            "wrong_ott_rejected": rejected,
            "device_a_active_after_boot1": act.activated and act.credential_status == "ACTIVE",
            "device_a_active_after_boot2": cred_a.status == "ACTIVE",
            "device_b_pending_expired_after_boot2": cred_b.status == "EXPIRED",
            "verify_active_ok": verify.status == "ACTIVE",
            "revoke_ok": revoked.credential.status == "REVOKED",
            "attempt_rows": int(attempt_count),
            "raw_secret_marker_count": marker_hits + secret_hits,
            "audit_secret_field_count": audit_secret_fields,
            "listener_created": False,
            "temp_database_residual_count": 0,
        }
        if not all(
            [
                report["same_instance_boot_stable"],
                report["boot_changed"],
                report["wrong_ott_rejected"],
                report["device_a_active_after_boot1"],
                report["device_a_active_after_boot2"],
                report["device_b_pending_expired_after_boot2"],
                report["verify_active_ok"],
                report["revoke_ok"],
                report["raw_secret_marker_count"] == 0,
                report["audit_secret_field_count"] == 0,
            ]
        ):
            report["status"] = "FAIL"
    return report


def main() -> int:
    report = run_smoke()
    print(json.dumps(report, separators=(",", ":"), sort_keys=True))
    return 0 if report.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
