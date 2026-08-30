"""Digest-only pairing storage core (no network, no raw secrets)."""

from __future__ import annotations

import hmac
import json
import sqlite3
import threading
from collections.abc import Callable, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .pairing_codec import (
    ALLOWED_TLS_STORAGE_KINDS,
    SHORT_CODE_MISMATCH_LIMIT,
    canonicalize_capabilities,
    compute_short_verification_code,
    generate_ulid,
    hello_payload_hash,
    parse_utc_iso,
    require_client_nonce,
    require_digest,
    require_optional_display_name,
    require_platform,
    require_ulid,
    utc_now_iso,
)
from .pairing_errors import (
    PairingAttemptConflictError,
    PairingAuthExpiredError,
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
    PairingNotFoundError,
    PairingPersistenceError,
    PairingRejectedError,
    PairingSchemaError,
    PairingShortCodeMismatchError,
    PairingStateError,
    PairingValidationError,
)
from .pairing_models import (
    CREDENTIAL_ACTIVE,
    CREDENTIAL_EXPIRED,
    CREDENTIAL_PENDING,
    CREDENTIAL_REVOKED,
    OPEN_SESSION_STATES,
    SESSION_ABORTED_CANCEL,
    SESSION_ABORTED_HUB_RESTART,
    SESSION_ABORTED_MISMATCH,
    SESSION_ABORTED_PROTOCOL,
    SESSION_ABORTED_TIMEOUT,
    SESSION_ACTIVE_PAIR,
    SESSION_AWAITING_CONFIRM,
    SESSION_PAIRING_ACTIVE,
    TERMINAL_SESSION_STATES,
    AuthVerifyResult,
    ConfirmResult,
    CredentialTransitionResult,
    DeviceCredentialView,
    HelloResult,
    HubIdentity,
    HubRuntime,
    PairingSessionView,
    OperatorPairingView,
    RedactedPairingStatus,
    audit_detail,
)

SCHEMA_COMPONENT = "pairing_auth"
SCHEMA_VERSION = 1
MAX_SQLITE_INTEGER = 9_223_372_036_854_775_807
DEFAULT_PENDING_TTL_SECONDS = 300
AUDIT_DETAIL_ALLOWLIST = frozenset(
    {
        "reason",
        "from_state",
        "to_state",
        "from_status",
        "to_status",
        "hub_id_prefix",
        "session_id_prefix",
        "attempt_id_prefix",
        "device_id_prefix",
        "boot_id_prefix",
        "capability_epoch",
        "granted_count",
        "requested_count",
        "tls_storage_kind",
        "mismatch_count",
    }
)

_OPEN_STATES = f"'{SESSION_PAIRING_ACTIVE}', '{SESSION_AWAITING_CONFIRM}'"
_ALL_SESSION_STATES = (
    f"'{SESSION_PAIRING_ACTIVE}', '{SESSION_AWAITING_CONFIRM}', "
    f"'{SESSION_ACTIVE_PAIR}', '{SESSION_ABORTED_TIMEOUT}', "
    f"'{SESSION_ABORTED_CANCEL}', '{SESSION_ABORTED_MISMATCH}', "
    f"'{SESSION_ABORTED_HUB_RESTART}', '{SESSION_ABORTED_PROTOCOL}'"
)
_CRED_STATES = (
    f"'{CREDENTIAL_PENDING}', '{CREDENTIAL_ACTIVE}', "
    f"'{CREDENTIAL_REVOKED}', '{CREDENTIAL_EXPIRED}'"
)

_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS pairing_schema_meta (
    component TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS hub_identity (
    hub_id TEXT PRIMARY KEY,
    cert_fingerprint TEXT NOT NULL
        CHECK (
            length(cert_fingerprint) = 64
            AND cert_fingerprint NOT GLOB '*[^0-9a-f]*'
        ),
    tls_storage_kind TEXT NOT NULL
        CHECK (tls_storage_kind = 'dpapi_encrypted_pkcs8'),
    tls_key_ref_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    rotated_at TEXT
);

CREATE TABLE IF NOT EXISTS hub_runtime (
    boot_id TEXT PRIMARY KEY,
    hub_id TEXT NOT NULL,
    started_at TEXT NOT NULL,
    stopped_at TEXT,
    FOREIGN KEY (hub_id) REFERENCES hub_identity(hub_id)
);

CREATE TABLE IF NOT EXISTS pairing_session (
    pairing_session_id TEXT PRIMARY KEY,
    hub_id TEXT NOT NULL,
    boot_id TEXT NOT NULL,
    pairing_token_digest TEXT NOT NULL UNIQUE
        CHECK (
            length(pairing_token_digest) = 64
            AND pairing_token_digest NOT GLOB '*[^0-9a-f]*'
        ),
    state TEXT NOT NULL CHECK (state IN ({_ALL_SESSION_STATES})),
    expires_at_server TEXT NOT NULL,
    terminal_reason TEXT,
    created_at TEXT NOT NULL,
    consumed_at TEXT,
    FOREIGN KEY (hub_id) REFERENCES hub_identity(hub_id),
    FOREIGN KEY (boot_id) REFERENCES hub_runtime(boot_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_pairing_session_one_open
ON pairing_session(hub_id)
WHERE state IN ({_OPEN_STATES});

CREATE TABLE IF NOT EXISTS pairing_attempt (
    pairing_attempt_id TEXT PRIMARY KEY,
    pairing_session_id TEXT NOT NULL UNIQUE,
    device_id TEXT NOT NULL,
    claim_secret_digest TEXT NOT NULL
        CHECK (
            length(claim_secret_digest) = 64
            AND claim_secret_digest NOT GLOB '*[^0-9a-f]*'
        ),
    device_credential_digest TEXT NOT NULL
        CHECK (
            length(device_credential_digest) = 64
            AND device_credential_digest NOT GLOB '*[^0-9a-f]*'
        ),
    client_nonce TEXT NOT NULL
        CHECK (length(client_nonce) = 22),
    requested_capabilities_json TEXT NOT NULL
        CHECK (length(requested_capabilities_json) <= 4096),
    requested_capabilities_digest TEXT NOT NULL
        CHECK (
            length(requested_capabilities_digest) = 64
            AND requested_capabilities_digest NOT GLOB '*[^0-9a-f]*'
        ),
    short_verification_code TEXT NOT NULL
        CHECK (length(short_verification_code) = 8),
    hello_payload_hash TEXT NOT NULL
        CHECK (
            length(hello_payload_hash) = 64
            AND hello_payload_hash NOT GLOB '*[^0-9a-f]*'
        ),
    short_code_mismatch_count INTEGER NOT NULL DEFAULT 0
        CHECK (
            short_code_mismatch_count >= 0
            AND short_code_mismatch_count <= {SHORT_CODE_MISMATCH_LIMIT}
        ),
    client_confirmed_at TEXT,
    hub_confirmed_at TEXT,
    pending_expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (pairing_session_id)
        REFERENCES pairing_session(pairing_session_id)
);

CREATE TABLE IF NOT EXISTS device_credential (
    device_id TEXT PRIMARY KEY,
    hub_id TEXT NOT NULL,
    pairing_attempt_id TEXT NOT NULL UNIQUE,
    credential_digest TEXT NOT NULL
        CHECK (
            length(credential_digest) = 64
            AND credential_digest NOT GLOB '*[^0-9a-f]*'
        ),
    status TEXT NOT NULL CHECK (status IN ({_CRED_STATES})),
    requested_capabilities_json TEXT NOT NULL
        CHECK (length(requested_capabilities_json) <= 4096),
    granted_capabilities_json TEXT NOT NULL
        CHECK (length(granted_capabilities_json) <= 4096),
    capability_epoch INTEGER NOT NULL CHECK (capability_epoch >= 0),
    display_name TEXT,
    platform TEXT NOT NULL,
    paired_at TEXT,
    revoked_at TEXT,
    last_auth_at TEXT,
    FOREIGN KEY (hub_id) REFERENCES hub_identity(hub_id),
    FOREIGN KEY (pairing_attempt_id)
        REFERENCES pairing_attempt(pairing_attempt_id)
);

CREATE TABLE IF NOT EXISTS auth_audit (
    id TEXT PRIMARY KEY,
    device_id TEXT,
    pairing_session_id TEXT,
    event_type TEXT NOT NULL,
    error_code TEXT,
    detail_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


class PairingStore:
    """File-backed pairing store; digests only; one boot per instance."""

    def __init__(
        self,
        database_path: str | Path,
        *,
        busy_timeout_ms: int = 5_000,
        clock: Callable[[], datetime] | None = None,
        randbytes: Callable[[int], bytes] | None = None,
        fault_injector: Callable[[str], None] | None = None,
        auto_start_runtime: bool = True,
    ) -> None:
        path_text = str(database_path)
        if not path_text or path_text == ":memory:":
            raise PairingValidationError("database_path_invalid")
        if (
            isinstance(busy_timeout_ms, bool)
            or not isinstance(busy_timeout_ms, int)
            or not 1 <= busy_timeout_ms <= 60_000
        ):
            raise PairingValidationError("busy_timeout_invalid")
        self._database_path = path_text
        self._busy_timeout_ms = busy_timeout_ms
        self._clock = clock
        self._randbytes = randbytes
        self._fault_injector = fault_injector
        self._state_lock = threading.Lock()
        self._closed = False
        self._boot_id: str | None = None
        self._hub_id: str | None = None
        self._initialize()
        if auto_start_runtime:
            # Runtime start requires identity; deferred until initialize_hub_identity
            # when identity missing. If identity already present, start now.
            connection = self._connect()
            try:
                row = connection.execute(
                    "SELECT hub_id FROM hub_identity LIMIT 1"
                ).fetchone()
            finally:
                connection.close()
            if row is not None:
                self.start_runtime()

    def close(self) -> None:
        with self._state_lock:
            self._closed = True
            self._boot_id = None

    def initialize_hub_identity(
        self,
        *,
        hub_id: str | None = None,
        cert_fingerprint: str,
        tls_storage_kind: str,
        tls_key_ref_id: str,
    ) -> HubIdentity:
        self._ensure_open()
        clean_fp = require_digest("cert_fingerprint", cert_fingerprint)
        if tls_storage_kind not in ALLOWED_TLS_STORAGE_KINDS:
            raise PairingValidationError("tls_storage_kind_invalid")
        clean_ref = _validated_text("tls_key_ref_id", tls_key_ref_id, max_length=128)
        clean_hub = (
            generate_ulid(clock=self._clock, randbytes=self._randbytes)
            if hub_id is None
            else require_ulid("hub_id", hub_id)
        )
        now = utc_now_iso(self._clock)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM hub_identity LIMIT 1"
            ).fetchone()
            if existing is None:
                connection.execute(
                    """
                    INSERT INTO hub_identity(
                        hub_id, cert_fingerprint, tls_storage_kind,
                        tls_key_ref_id, created_at, rotated_at
                    ) VALUES (?, ?, ?, ?, ?, NULL)
                    """,
                    (clean_hub, clean_fp, tls_storage_kind, clean_ref, now),
                )
                self._inject("after_identity_insert")
                connection.commit()
                identity = HubIdentity(
                    hub_id=clean_hub,
                    cert_fingerprint=clean_fp,
                    tls_storage_kind=tls_storage_kind,
                    tls_key_ref_id=clean_ref,
                    created_at=now,
                    rotated_at=None,
                )
            else:
                if (
                    str(existing["hub_id"]) != clean_hub
                    or str(existing["cert_fingerprint"]) != clean_fp
                    or str(existing["tls_storage_kind"]) != tls_storage_kind
                    or str(existing["tls_key_ref_id"]) != clean_ref
                ):
                    connection.rollback()
                    raise PairingIdentityConflictError()
                connection.commit()
                identity = _identity_from_row(existing)
            self._hub_id = identity.hub_id
        except (
            PairingIdentityConflictError,
            PairingValidationError,
            PairingPersistenceError,
        ):
            raise
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        if self._boot_id is None:
            self.start_runtime()
        return identity

    def rotate_hub_identity_reference(
        self,
        *,
        expected_current_fingerprint: str,
        new_cert_fingerprint: str,
        tls_storage_kind: str,
        tls_key_ref_id: str,
    ) -> HubIdentity:
        self._ensure_open()
        expected = require_digest("cert_fingerprint", expected_current_fingerprint)
        new_fp = require_digest("cert_fingerprint", new_cert_fingerprint)
        if tls_storage_kind not in ALLOWED_TLS_STORAGE_KINDS:
            raise PairingValidationError("tls_storage_kind_invalid")
        clean_ref = _validated_text("tls_key_ref_id", tls_key_ref_id, max_length=128)
        now = utc_now_iso(self._clock)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM hub_identity LIMIT 1").fetchone()
            if row is None:
                connection.rollback()
                raise PairingNotFoundError()
            if str(row["cert_fingerprint"]) != expected:
                connection.rollback()
                raise PairingIdentityCasError()
            connection.execute(
                """
                UPDATE hub_identity
                SET cert_fingerprint = ?, tls_storage_kind = ?,
                    tls_key_ref_id = ?, rotated_at = ?
                WHERE hub_id = ?
                """,
                (
                    new_fp,
                    tls_storage_kind,
                    clean_ref,
                    now,
                    str(row["hub_id"]),
                ),
            )
            self._inject("after_identity_rotate")
            connection.commit()
            updated = connection.execute(
                "SELECT * FROM hub_identity WHERE hub_id = ?",
                (str(row["hub_id"]),),
            ).fetchone()
            assert updated is not None
            return _identity_from_row(updated)
        except (
            PairingNotFoundError,
            PairingIdentityCasError,
            PairingValidationError,
        ):
            raise
        except sqlite3.Error:
            connection.rollback()
            raise PairingPersistenceError() from None
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def get_hub_identity(self) -> HubIdentity:
        self._ensure_open()
        connection = self._connect()
        try:
            row = connection.execute("SELECT * FROM hub_identity LIMIT 1").fetchone()
        except sqlite3.Error:
            raise PairingPersistenceError() from None
        finally:
            connection.close()
        if row is None:
            raise PairingNotFoundError()
        return _identity_from_row(row)

    def start_runtime(self) -> HubRuntime:
        self._ensure_open()
        # Same instance: never mint a second boot or abort own sessions.
        if self._boot_id is not None and self._hub_id is not None:
            connection = self._connect()
            try:
                row = connection.execute(
                    "SELECT * FROM hub_runtime WHERE boot_id = ?",
                    (self._boot_id,),
                ).fetchone()
            finally:
                connection.close()
            if row is None:
                raise PairingStateError()
            return HubRuntime(
                boot_id=str(row["boot_id"]),
                hub_id=str(row["hub_id"]),
                started_at=str(row["started_at"]),
                stopped_at=(
                    str(row["stopped_at"])
                    if row["stopped_at"] is not None
                    else None
                ),
            )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            identity = connection.execute(
                "SELECT hub_id FROM hub_identity LIMIT 1"
            ).fetchone()
            if identity is None:
                connection.rollback()
                raise PairingNotFoundError()
            hub_id = str(identity["hub_id"])
            now = utc_now_iso(self._clock)
            boot_id = generate_ulid(clock=self._clock, randbytes=self._randbytes)
            # Close prior open runtime rows before aborting leftover sessions.
            connection.execute(
                """
                UPDATE hub_runtime
                SET stopped_at = ?
                WHERE stopped_at IS NULL
                """,
                (now,),
            )
            # Abort open sessions from previous boots
            open_rows = connection.execute(
                """
                SELECT pairing_session_id, state, boot_id
                FROM pairing_session
                WHERE state IN (?, ?)
                """,
                (SESSION_PAIRING_ACTIVE, SESSION_AWAITING_CONFIRM),
            ).fetchall()
            for row in open_rows:
                sid = str(row["pairing_session_id"])
                connection.execute(
                    """
                    UPDATE pairing_session
                    SET state = ?, terminal_reason = ?
                    WHERE pairing_session_id = ?
                    """,
                    (
                        SESSION_ABORTED_HUB_RESTART,
                        "hub_restart",
                        sid,
                    ),
                )
                connection.execute(
                    """
                    UPDATE device_credential
                    SET status = ?
                    WHERE pairing_attempt_id IN (
                        SELECT pairing_attempt_id FROM pairing_attempt
                        WHERE pairing_session_id = ?
                    ) AND status = ?
                    """,
                    (CREDENTIAL_EXPIRED, sid, CREDENTIAL_PENDING),
                )
                self._write_audit(
                    connection,
                    event_type="session_aborted_hub_restart",
                    pairing_session_id=sid,
                    detail={
                        "reason": "hub_restart",
                        "from_state": str(row["state"]),
                        "to_state": SESSION_ABORTED_HUB_RESTART,
                        "boot_id_prefix": str(row["boot_id"])[:4],
                    },
                )
            connection.execute(
                """
                INSERT INTO hub_runtime(boot_id, hub_id, started_at, stopped_at)
                VALUES (?, ?, ?, NULL)
                """,
                (boot_id, hub_id, now),
            )
            self._inject("after_runtime_start")
            connection.commit()
            self._boot_id = boot_id
            self._hub_id = hub_id
            return HubRuntime(
                boot_id=boot_id,
                hub_id=hub_id,
                started_at=now,
                stopped_at=None,
            )
        except (PairingNotFoundError, PairingValidationError):
            raise
        except sqlite3.Error:
            connection.rollback()
            raise PairingPersistenceError() from None
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def current_boot_id(self) -> str:
        self._ensure_open()
        if self._boot_id is None:
            raise PairingStateError()
        return self._boot_id

    def create_pairing_session(
        self,
        *,
        pairing_token_digest: str,
        ttl_seconds: int,
    ) -> PairingSessionView:
        self._ensure_open()
        digest = require_digest("pairing_token_digest", pairing_token_digest)
        if (
            isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, int)
            or ttl_seconds < 1
            or ttl_seconds > 86_400
        ):
            raise PairingValidationError("ttl_invalid")
        boot_id = self.current_boot_id()
        hub_id = self._require_hub_id()
        now_dt = self._now()
        now = utc_now_iso(lambda: now_dt)
        expires = utc_now_iso(lambda: now_dt + timedelta(seconds=ttl_seconds))
        session_id = generate_ulid(clock=self._clock, randbytes=self._randbytes)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._expire_due_locked(connection, now_dt)
            connection.execute(
                """
                INSERT INTO pairing_session(
                    pairing_session_id, hub_id, boot_id, pairing_token_digest,
                    state, expires_at_server, terminal_reason, created_at, consumed_at
                ) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, NULL)
                """,
                (
                    session_id,
                    hub_id,
                    boot_id,
                    digest,
                    SESSION_PAIRING_ACTIVE,
                    expires,
                    now,
                ),
            )
            self._inject("after_session_insert")
            self._write_audit(
                connection,
                event_type="pairing_session_created",
                pairing_session_id=session_id,
                detail={
                    "to_state": SESSION_PAIRING_ACTIVE,
                    "hub_id_prefix": hub_id[:4],
                    "boot_id_prefix": boot_id[:4],
                },
            )
            connection.commit()
            return PairingSessionView(
                pairing_session_id=session_id,
                hub_id=hub_id,
                boot_id=boot_id,
                state=SESSION_PAIRING_ACTIVE,
                expires_at_server=expires,
                terminal_reason=None,
                created_at=now,
                consumed_at=None,
            )
        except sqlite3.IntegrityError:
            connection.rollback()
            raise PairingBusyError() from None
        except (PairingValidationError, PairingBusyError, PairingStateError):
            raise
        except sqlite3.Error:
            connection.rollback()
            raise PairingPersistenceError() from None
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def register_client_hello_digest(
        self,
        *,
        pairing_session_id: str,
        pairing_attempt_id: str,
        pairing_token_digest: str,
        claim_secret_digest: str,
        device_credential_digest: str,
        client_nonce: str,
        requested_capabilities: Sequence[str],
        display_name: str | None = None,
        platform: str = "android",
    ) -> HelloResult:
        self._ensure_open()
        sid = require_ulid("pairing_session_id", pairing_session_id)
        aid = require_ulid("pairing_attempt_id", pairing_attempt_id)
        provided_ott = require_digest("pairing_token_digest", pairing_token_digest)
        claim = require_digest("claim_secret_digest", claim_secret_digest)
        cred = require_digest("device_credential_digest", device_credential_digest)
        nonce = require_client_nonce(client_nonce)
        name = require_optional_display_name(display_name)
        plat = require_platform(platform)
        caps, caps_json, caps_digest = canonicalize_capabilities(requested_capabilities)
        payload_hash = hello_payload_hash(
            pairing_session_id=sid,
            pairing_attempt_id=aid,
            claim_secret_digest=claim,
            device_credential_digest=cred,
            client_nonce=nonce,
            requested_capabilities_json=caps_json,
            requested_capabilities_digest=caps_digest,
            display_name=name,
            platform=plat,
        )
        boot_id = self.current_boot_id()
        hub_id = self._require_hub_id()
        now_dt = self._now()
        now = utc_now_iso(lambda: now_dt)
        pending_exp = utc_now_iso(
            lambda: now_dt + timedelta(seconds=DEFAULT_PENDING_TTL_SECONDS)
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._expire_due_locked(connection, now_dt)
            session = connection.execute(
                "SELECT * FROM pairing_session WHERE pairing_session_id = ?",
                (sid,),
            ).fetchone()
            if session is None:
                connection.rollback()
                raise PairingNotFoundError()
            if str(session["boot_id"]) != boot_id:
                connection.rollback()
                raise PairingExpiredError()
            state = str(session["state"])
            if state in TERMINAL_SESSION_STATES:
                connection.rollback()
                raise PairingExpiredError()
            if parse_utc_iso(str(session["expires_at_server"])) <= now_dt:
                self._abort_session_locked(
                    connection,
                    sid,
                    SESSION_ABORTED_TIMEOUT,
                    "ttl",
                    expire_pending=True,
                )
                connection.commit()
                raise PairingExpiredError()
            if state not in {SESSION_PAIRING_ACTIVE, SESSION_AWAITING_CONFIRM}:
                connection.rollback()
                raise PairingStateError()
            # Atomic OTT verify before any attempt/credential write.
            if not hmac.compare_digest(
                str(session["pairing_token_digest"]), provided_ott
            ):
                connection.rollback()
                raise PairingRejectedError()

            existing = connection.execute(
                "SELECT * FROM pairing_attempt WHERE pairing_session_id = ?",
                (sid,),
            ).fetchone()
            if existing is not None:
                if str(existing["pairing_attempt_id"]) != aid:
                    connection.rollback()
                    raise PairingBusyError()
                if str(existing["hello_payload_hash"]) != payload_hash:
                    connection.rollback()
                    raise PairingAttemptConflictError()
                connection.commit()
                return HelloResult(
                    pairing_session_id=sid,
                    pairing_attempt_id=aid,
                    device_id=str(existing["device_id"]),
                    short_verification_code=str(existing["short_verification_code"]),
                    pending_expires_at=str(existing["pending_expires_at"]),
                    state=SESSION_AWAITING_CONFIRM,
                    deduplicated=True,
                )

            # Hub-issued device_id (not a client hello input).
            did = generate_ulid(clock=self._clock, randbytes=self._randbytes)
            identity = connection.execute(
                "SELECT cert_fingerprint FROM hub_identity WHERE hub_id = ?",
                (hub_id,),
            ).fetchone()
            assert identity is not None
            short = compute_short_verification_code(
                hub_id=hub_id,
                cert_fingerprint=str(identity["cert_fingerprint"]),
                pairing_session_id=sid,
                pairing_attempt_id=aid,
                ott_digest=str(session["pairing_token_digest"]),
                device_credential_digest=cred,
                claim_secret_digest=claim,
                client_nonce=nonce,
                requested_capabilities_digest=caps_digest,
            )
            connection.execute(
                """
                INSERT INTO pairing_attempt(
                    pairing_attempt_id, pairing_session_id, device_id,
                    claim_secret_digest, device_credential_digest, client_nonce,
                    requested_capabilities_json, requested_capabilities_digest,
                    short_verification_code, hello_payload_hash,
                    short_code_mismatch_count,
                    client_confirmed_at, hub_confirmed_at, pending_expires_at,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, NULL, ?, ?)
                """,
                (
                    aid,
                    sid,
                    did,
                    claim,
                    cred,
                    nonce,
                    caps_json,
                    caps_digest,
                    short,
                    payload_hash,
                    pending_exp,
                    now,
                ),
            )
            connection.execute(
                """
                INSERT INTO device_credential(
                    device_id, hub_id, pairing_attempt_id, credential_digest,
                    status, requested_capabilities_json, granted_capabilities_json,
                    capability_epoch, display_name, platform,
                    paired_at, revoked_at, last_auth_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, NULL, NULL, NULL)
                """,
                (
                    did,
                    hub_id,
                    aid,
                    cred,
                    CREDENTIAL_PENDING,
                    caps_json,
                    "[]",
                    name,
                    plat,
                ),
            )
            connection.execute(
                """
                UPDATE pairing_session SET state = ? WHERE pairing_session_id = ?
                """,
                (SESSION_AWAITING_CONFIRM, sid),
            )
            self._inject("after_hello_insert")
            self._write_audit(
                connection,
                event_type="client_hello_registered",
                pairing_session_id=sid,
                device_id=did,
                detail={
                    "to_state": SESSION_AWAITING_CONFIRM,
                    "to_status": CREDENTIAL_PENDING,
                    "attempt_id_prefix": aid[:4],
                    "device_id_prefix": did[:4],
                    "requested_count": len(caps),
                },
            )
            connection.commit()
            return HelloResult(
                pairing_session_id=sid,
                pairing_attempt_id=aid,
                device_id=did,
                short_verification_code=short,
                pending_expires_at=pending_exp,
                state=SESSION_AWAITING_CONFIRM,
                deduplicated=False,
            )
        except (
            PairingBusyError,
            PairingAttemptConflictError,
            PairingExpiredError,
            PairingNotFoundError,
            PairingStateError,
            PairingValidationError,
            PairingRejectedError,
        ):
            raise
        except sqlite3.IntegrityError:
            connection.rollback()
            raise PairingBusyError() from None
        except sqlite3.Error:
            connection.rollback()
            raise PairingPersistenceError() from None
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def record_client_confirmation_digest(
        self,
        *,
        pairing_session_id: str,
        pairing_attempt_id: str,
        claim_secret_digest: str,
        short_verification_code: str,
    ) -> ConfirmResult:
        self._ensure_open()
        sid = require_ulid("pairing_session_id", pairing_session_id)
        aid = require_ulid("pairing_attempt_id", pairing_attempt_id)
        claim = require_digest("claim_secret_digest", claim_secret_digest)
        code = _validated_text(
            "short_verification_code", short_verification_code, max_length=8
        )
        if len(code) != 8:
            raise PairingValidationError("short_code_invalid")
        return self._record_confirmation(
            pairing_session_id=sid,
            pairing_attempt_id=aid,
            side="client",
            claim_secret_digest=claim,
            short_verification_code=code,
            granted_capabilities=None,
        )

    def record_hub_confirmation(
        self,
        *,
        pairing_session_id: str,
        pairing_attempt_id: str,
        granted_capabilities: Sequence[str],
    ) -> ConfirmResult:
        self._ensure_open()
        sid = require_ulid("pairing_session_id", pairing_session_id)
        aid = require_ulid("pairing_attempt_id", pairing_attempt_id)
        caps, _, _ = canonicalize_capabilities(granted_capabilities)
        return self._record_confirmation(
            pairing_session_id=sid,
            pairing_attempt_id=aid,
            side="hub",
            claim_secret_digest=None,
            short_verification_code=None,
            granted_capabilities=caps,
        )

    def get_redacted_pairing_status(
        self,
        *,
        pairing_session_id: str,
        pairing_attempt_id: str,
        claim_secret_digest: str,
    ) -> RedactedPairingStatus:
        self._ensure_open()
        sid = require_ulid("pairing_session_id", pairing_session_id)
        aid = require_ulid("pairing_attempt_id", pairing_attempt_id)
        claim = require_digest("claim_secret_digest", claim_secret_digest)
        now_dt = self._now()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._expire_due_locked(connection, now_dt)
            session = connection.execute(
                "SELECT * FROM pairing_session WHERE pairing_session_id = ?",
                (sid,),
            ).fetchone()
            attempt = connection.execute(
                """
                SELECT * FROM pairing_attempt
                WHERE pairing_session_id = ? AND pairing_attempt_id = ?
                """,
                (sid, aid),
            ).fetchone()
            # Unified claim_invalid: no existence leak; no state mutation on failure.
            if (
                session is None
                or attempt is None
                or not hmac.compare_digest(
                    str(attempt["claim_secret_digest"]), claim
                )
            ):
                connection.rollback()
                raise PairingClaimInvalidError()
            cred = connection.execute(
                "SELECT * FROM device_credential WHERE pairing_attempt_id = ?",
                (aid,),
            ).fetchone()
            connection.commit()
            granted = (
                json.loads(str(cred["granted_capabilities_json"]))
                if cred is not None
                else None
            )
            return RedactedPairingStatus(
                pairing_session_id=sid,
                pairing_attempt_id=aid,
                state=str(session["state"]),
                credential_status=str(cred["status"]) if cred else None,
                device_id=str(attempt["device_id"]),
                capability_epoch=int(cred["capability_epoch"]) if cred else None,
                granted_capabilities=granted,
                pending_expires_at=str(attempt["pending_expires_at"]),
                expires_at_server=str(session["expires_at_server"]),
                terminal_reason=(
                    str(session["terminal_reason"])
                    if session["terminal_reason"] is not None
                    else None
                ),
            )
        except (PairingClaimInvalidError, PairingValidationError):
            raise
        except sqlite3.Error:
            connection.rollback()
            raise PairingPersistenceError() from None
        finally:
            connection.close()

    def get_operator_pairing_view(
        self,
        *,
        pairing_session_id: str,
    ) -> OperatorPairingView:
        """Trusted local status without claim auth; never returns stored digests."""
        self._ensure_open()
        sid = require_ulid("pairing_session_id", pairing_session_id)
        now_dt = self._now()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._expire_due_locked(connection, now_dt)
            row = connection.execute(
                """
                SELECT
                    s.pairing_session_id, s.hub_id, s.state,
                    s.expires_at_server, s.terminal_reason,
                    a.pairing_attempt_id, a.device_id,
                    a.short_verification_code,
                    a.requested_capabilities_json,
                    c.display_name, c.platform,
                    a.client_confirmed_at, a.hub_confirmed_at,
                    c.status AS credential_status,
                    c.granted_capabilities_json,
                    c.capability_epoch
                FROM pairing_session AS s
                LEFT JOIN pairing_attempt AS a
                    ON a.pairing_session_id = s.pairing_session_id
                LEFT JOIN device_credential AS c
                    ON c.pairing_attempt_id = a.pairing_attempt_id
                WHERE s.pairing_session_id = ?
                """,
                (sid,),
            ).fetchone()
            if row is None:
                connection.rollback()
                raise PairingNotFoundError()
            connection.commit()
            requested = (
                []
                if row["requested_capabilities_json"] is None
                else json.loads(str(row["requested_capabilities_json"]))
            )
            granted = (
                []
                if row["granted_capabilities_json"] is None
                else json.loads(str(row["granted_capabilities_json"]))
            )
            return OperatorPairingView(
                pairing_session_id=str(row["pairing_session_id"]),
                hub_id=str(row["hub_id"]),
                state=str(row["state"]),
                expires_at_server=str(row["expires_at_server"]),
                terminal_reason=(
                    None
                    if row["terminal_reason"] is None
                    else str(row["terminal_reason"])
                ),
                pairing_attempt_id=(
                    None
                    if row["pairing_attempt_id"] is None
                    else str(row["pairing_attempt_id"])
                ),
                device_id=(
                    None if row["device_id"] is None else str(row["device_id"])
                ),
                short_verification_code=(
                    None
                    if row["short_verification_code"] is None
                    or row["credential_status"] == "ACTIVE"
                    else str(row["short_verification_code"])
                ),
                requested_capabilities=list(requested),
                granted_capabilities=list(granted),
                display_name=(
                    None if row["display_name"] is None else str(row["display_name"])
                ),
                platform=(
                    None if row["platform"] is None else str(row["platform"])
                ),
                client_confirmed=row["client_confirmed_at"] is not None,
                hub_confirmed=row["hub_confirmed_at"] is not None,
                credential_status=(
                    None
                    if row["credential_status"] is None
                    else str(row["credential_status"])
                ),
                capability_epoch=(
                    0 if row["capability_epoch"] is None else int(row["capability_epoch"])
                ),
            )
        except (PairingNotFoundError, PairingValidationError):
            raise
        except sqlite3.Error:
            connection.rollback()
            raise PairingPersistenceError() from None
        finally:
            connection.close()

    def abort_pairing_session(
        self,
        *,
        pairing_session_id: str,
        reason: str = "cancel",
    ) -> PairingSessionView:
        self._ensure_open()
        sid = require_ulid("pairing_session_id", pairing_session_id)
        reason_key = _validated_text("reason", reason, max_length=64)
        state_map = {
            "cancel": SESSION_ABORTED_CANCEL,
            "mismatch": SESSION_ABORTED_MISMATCH,
            "protocol": SESSION_ABORTED_PROTOCOL,
            "timeout": SESSION_ABORTED_TIMEOUT,
        }
        target = state_map.get(reason_key, SESSION_ABORTED_CANCEL)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            session = connection.execute(
                "SELECT * FROM pairing_session WHERE pairing_session_id = ?",
                (sid,),
            ).fetchone()
            if session is None:
                connection.rollback()
                raise PairingNotFoundError()
            if str(session["state"]) in TERMINAL_SESSION_STATES:
                connection.commit()
                return _session_from_row(session)
            self._abort_session_locked(
                connection,
                sid,
                target,
                reason_key,
                expire_pending=True,
            )
            connection.commit()
            row = connection.execute(
                "SELECT * FROM pairing_session WHERE pairing_session_id = ?",
                (sid,),
            ).fetchone()
            assert row is not None
            return _session_from_row(row)
        except (PairingNotFoundError, PairingValidationError):
            raise
        except sqlite3.Error:
            connection.rollback()
            raise PairingPersistenceError() from None
        finally:
            connection.close()

    def expire_due_sessions(self) -> int:
        self._ensure_open()
        now_dt = self._now()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            count = self._expire_due_locked(connection, now_dt)
            connection.commit()
            return count
        except sqlite3.Error:
            connection.rollback()
            raise PairingPersistenceError() from None
        finally:
            connection.close()

    def get_device_credential(self, device_id: str) -> DeviceCredentialView:
        self._ensure_open()
        did = require_ulid("device_id", device_id)
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM device_credential WHERE device_id = ?",
                (did,),
            ).fetchone()
        except sqlite3.Error:
            raise PairingPersistenceError() from None
        finally:
            connection.close()
        if row is None:
            raise PairingNotFoundError()
        return _credential_view_from_row(row)

    def list_device_credentials(
        self,
        *,
        limit: int = 32,
    ) -> list[DeviceCredentialView]:
        self._ensure_open()
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise PairingValidationError("credential_limit_invalid")
        connection = self._connect()
        try:
            rows = connection.execute(
                """
                SELECT * FROM device_credential
                ORDER BY paired_at IS NULL, paired_at DESC, device_id ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        except sqlite3.Error:
            raise PairingPersistenceError() from None
        finally:
            connection.close()
        return [_credential_view_from_row(row) for row in rows]

    def verify_active_credential_digest(
        self,
        *,
        device_id: str,
        credential_digest: str,
        capability_epoch: int,
        required_capability: str | None = None,
    ) -> AuthVerifyResult:
        self._ensure_open()
        did = require_ulid("device_id", device_id)
        digest = require_digest("credential_digest", credential_digest)
        if (
            isinstance(capability_epoch, bool)
            or not isinstance(capability_epoch, int)
            or capability_epoch < 1
        ):
            raise PairingValidationError("capability_epoch_invalid")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM device_credential WHERE device_id = ?",
                (did,),
            ).fetchone()
            if row is None:
                connection.rollback()
                raise PairingAuthInvalidError()
            # Authenticate possession before exposing credential lifecycle state.
            # A caller with only a device_id must not distinguish revoked,
            # expired, or pending rows from an invalid credential.
            if not hmac.compare_digest(str(row["credential_digest"]), digest):
                connection.rollback()
                raise PairingAuthInvalidError()
            status = str(row["status"])
            if status == CREDENTIAL_REVOKED:
                connection.rollback()
                raise PairingAuthRevokedError()
            if status == CREDENTIAL_EXPIRED or status == CREDENTIAL_PENDING:
                connection.rollback()
                raise PairingAuthExpiredError()
            if status != CREDENTIAL_ACTIVE:
                connection.rollback()
                raise PairingAuthInvalidError()
            if int(row["capability_epoch"]) != capability_epoch:
                connection.rollback()
                raise PairingCapabilityEpochStaleError()
            granted = json.loads(str(row["granted_capabilities_json"]))
            if required_capability is not None:
                if (
                    not isinstance(required_capability, str)
                    or required_capability != required_capability.strip()
                    or not required_capability
                ):
                    connection.rollback()
                    raise PairingValidationError("capability_invalid")
                if required_capability not in granted:
                    connection.rollback()
                    raise PairingCapabilityDeniedError()
            now = utc_now_iso(self._clock)
            connection.execute(
                "UPDATE device_credential SET last_auth_at = ? WHERE device_id = ?",
                (now, did),
            )
            connection.commit()
            return AuthVerifyResult(
                device_id=did,
                hub_id=str(row["hub_id"]),
                status=CREDENTIAL_ACTIVE,
                capability_epoch=int(row["capability_epoch"]),
                granted_capabilities=list(granted),
                display_name=(
                    None
                    if row["display_name"] is None
                    else str(row["display_name"])
                ),
                platform=str(row["platform"]),
            )
        except (
            PairingAuthInvalidError,
            PairingAuthRevokedError,
            PairingAuthExpiredError,
            PairingCapabilityDeniedError,
            PairingCapabilityEpochStaleError,
            PairingValidationError,
        ):
            raise
        except sqlite3.Error:
            connection.rollback()
            raise PairingPersistenceError() from None
        finally:
            connection.close()

    def refresh_active_credential_digest(
        self,
        *,
        device_id: str,
        credential_digest: str,
    ) -> AuthVerifyResult:
        """Refresh current grants after authenticating credential possession.

        The caller intentionally supplies no capability epoch: this method is
        the recovery path used when a previously valid client cache is stale.
        Lifecycle state is exposed only after the secret digest matches.
        """
        self._ensure_open()
        did = require_ulid("device_id", device_id)
        digest = require_digest("credential_digest", credential_digest)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM device_credential WHERE device_id = ?",
                (did,),
            ).fetchone()
            if row is None or not hmac.compare_digest(
                str(row["credential_digest"]), digest
            ):
                connection.rollback()
                raise PairingAuthInvalidError()
            status = str(row["status"])
            if status == CREDENTIAL_REVOKED:
                connection.rollback()
                raise PairingAuthRevokedError()
            if status in {CREDENTIAL_EXPIRED, CREDENTIAL_PENDING}:
                connection.rollback()
                raise PairingAuthExpiredError()
            if status != CREDENTIAL_ACTIVE:
                connection.rollback()
                raise PairingAuthInvalidError()
            granted = json.loads(str(row["granted_capabilities_json"]))
            now = utc_now_iso(self._clock)
            connection.execute(
                "UPDATE device_credential SET last_auth_at = ? WHERE device_id = ?",
                (now, did),
            )
            connection.commit()
            return AuthVerifyResult(
                device_id=did,
                hub_id=str(row["hub_id"]),
                status=CREDENTIAL_ACTIVE,
                capability_epoch=int(row["capability_epoch"]),
                granted_capabilities=list(granted),
                display_name=(
                    None if row["display_name"] is None else str(row["display_name"])
                ),
                platform=str(row["platform"]),
            )
        except (
            PairingAuthInvalidError,
            PairingAuthRevokedError,
            PairingAuthExpiredError,
            PairingValidationError,
        ):
            raise
        except sqlite3.Error:
            connection.rollback()
            raise PairingPersistenceError() from None
        finally:
            connection.close()

    def revoke_device_credential(
        self,
        device_id: str,
        *,
        expected_capability_epoch: int,
    ) -> CredentialTransitionResult:
        self._ensure_open()
        did = require_ulid("device_id", device_id)
        expected_epoch = _require_capability_epoch(expected_capability_epoch)
        now = utc_now_iso(self._clock)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM device_credential WHERE device_id = ?",
                (did,),
            ).fetchone()
            if row is None:
                connection.rollback()
                raise PairingNotFoundError()
            current_epoch = int(row["capability_epoch"])
            if current_epoch != expected_epoch:
                connection.rollback()
                raise PairingCapabilityEpochStaleError()
            status = str(row["status"])
            if status == CREDENTIAL_REVOKED:
                connection.commit()
                return CredentialTransitionResult(
                    credential=_credential_view_from_row(row),
                    changed=False,
                )
            if status != CREDENTIAL_ACTIVE:
                connection.rollback()
                raise PairingStateError()
            connection.execute(
                """
                UPDATE device_credential
                SET status = ?, revoked_at = ?
                WHERE device_id = ?
                """,
                (CREDENTIAL_REVOKED, now, did),
            )
            self._inject("after_revoke")
            self._write_audit(
                connection,
                event_type="credential_revoked",
                device_id=did,
                detail={
                    "from_status": str(row["status"]),
                    "to_status": CREDENTIAL_REVOKED,
                    "device_id_prefix": did[:4],
                },
            )
            connection.commit()
            updated = connection.execute(
                "SELECT * FROM device_credential WHERE device_id = ?",
                (did,),
            ).fetchone()
            assert updated is not None
            return CredentialTransitionResult(
                credential=_credential_view_from_row(updated),
                changed=True,
            )
        except (
            PairingCapabilityEpochStaleError,
            PairingNotFoundError,
            PairingStateError,
            PairingValidationError,
        ):
            connection.rollback()
            raise
        except sqlite3.Error:
            connection.rollback()
            raise PairingPersistenceError() from None
        finally:
            connection.close()

    def update_device_capabilities(
        self,
        device_id: str,
        *,
        expected_capability_epoch: int,
        granted_capabilities: Sequence[str],
    ) -> CredentialTransitionResult:
        self._ensure_open()
        did = require_ulid("device_id", device_id)
        expected_epoch = _require_capability_epoch(expected_capability_epoch)
        granted, granted_json, _ = canonicalize_capabilities(granted_capabilities)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM device_credential WHERE device_id = ?",
                (did,),
            ).fetchone()
            if row is None:
                connection.rollback()
                raise PairingNotFoundError()
            if str(row["status"]) != CREDENTIAL_ACTIVE:
                connection.rollback()
                raise PairingStateError()
            current_epoch = int(row["capability_epoch"])
            if current_epoch != expected_epoch:
                connection.rollback()
                raise PairingCapabilityEpochStaleError()
            requested = json.loads(str(row["requested_capabilities_json"]))
            if not set(granted).issubset(set(requested)):
                connection.rollback()
                raise PairingValidationError("grants_exceed_request")
            current_granted = json.loads(str(row["granted_capabilities_json"]))
            if current_granted == granted:
                connection.commit()
                return CredentialTransitionResult(
                    credential=_credential_view_from_row(row),
                    changed=False,
                )
            if current_epoch >= MAX_SQLITE_INTEGER:
                connection.rollback()
                raise PairingStateError("capability_epoch_exhausted")
            new_epoch = current_epoch + 1
            updated_count = connection.execute(
                """
                UPDATE device_credential
                SET granted_capabilities_json = ?, capability_epoch = ?
                WHERE device_id = ? AND status = ? AND capability_epoch = ?
                """,
                (
                    granted_json,
                    new_epoch,
                    did,
                    CREDENTIAL_ACTIVE,
                    expected_epoch,
                ),
            ).rowcount
            if updated_count != 1:
                connection.rollback()
                raise PairingCapabilityEpochStaleError()
            self._inject("after_capability_change")
            self._write_audit(
                connection,
                event_type="credential_capabilities_changed",
                device_id=did,
                detail={
                    "device_id_prefix": did[:4],
                    "capability_epoch": new_epoch,
                    "granted_count": len(granted),
                },
            )
            connection.commit()
            updated = connection.execute(
                "SELECT * FROM device_credential WHERE device_id = ?",
                (did,),
            ).fetchone()
            assert updated is not None
            return CredentialTransitionResult(
                credential=_credential_view_from_row(updated),
                changed=True,
            )
        except (
            PairingCapabilityEpochStaleError,
            PairingNotFoundError,
            PairingStateError,
            PairingValidationError,
        ):
            connection.rollback()
            raise
        except sqlite3.Error:
            connection.rollback()
            raise PairingPersistenceError() from None
        finally:
            connection.close()

    # --- internals ---

    def _record_confirmation(
        self,
        *,
        pairing_session_id: str,
        pairing_attempt_id: str,
        side: str,
        claim_secret_digest: str | None,
        short_verification_code: str | None,
        granted_capabilities: list[str] | None,
    ) -> ConfirmResult:
        boot_id = self.current_boot_id()
        now_dt = self._now()
        now = utc_now_iso(lambda: now_dt)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._expire_due_locked(connection, now_dt)
            session = connection.execute(
                "SELECT * FROM pairing_session WHERE pairing_session_id = ?",
                (pairing_session_id,),
            ).fetchone()
            attempt = connection.execute(
                """
                SELECT * FROM pairing_attempt
                WHERE pairing_session_id = ? AND pairing_attempt_id = ?
                """,
                (pairing_session_id, pairing_attempt_id),
            ).fetchone()

            if side == "client":
                assert claim_secret_digest is not None
                assert short_verification_code is not None
                # Unified claim_invalid: no existence leak; no state mutation.
                if (
                    session is None
                    or attempt is None
                    or not hmac.compare_digest(
                        str(attempt["claim_secret_digest"]), claim_secret_digest
                    )
                ):
                    connection.rollback()
                    raise PairingClaimInvalidError()
                if str(session["boot_id"]) != boot_id:
                    connection.rollback()
                    raise PairingExpiredError()
                if str(session["state"]) in {
                    SESSION_ABORTED_TIMEOUT,
                    SESSION_ABORTED_CANCEL,
                    SESSION_ABORTED_MISMATCH,
                    SESSION_ABORTED_HUB_RESTART,
                    SESSION_ABORTED_PROTOCOL,
                }:
                    connection.rollback()
                    raise PairingExpiredError()
                cred = connection.execute(
                    "SELECT * FROM device_credential WHERE pairing_attempt_id = ?",
                    (pairing_attempt_id,),
                ).fetchone()
                if cred is None:
                    connection.rollback()
                    raise PairingClaimInvalidError()
            else:
                if session is None:
                    connection.rollback()
                    raise PairingNotFoundError()
                if str(session["boot_id"]) != boot_id:
                    connection.rollback()
                    raise PairingExpiredError()
                if str(session["state"]) in {
                    SESSION_ABORTED_TIMEOUT,
                    SESSION_ABORTED_CANCEL,
                    SESSION_ABORTED_MISMATCH,
                    SESSION_ABORTED_HUB_RESTART,
                    SESSION_ABORTED_PROTOCOL,
                }:
                    connection.rollback()
                    raise PairingExpiredError()
                if attempt is None:
                    connection.rollback()
                    raise PairingNotFoundError()
                cred = connection.execute(
                    "SELECT * FROM device_credential WHERE pairing_attempt_id = ?",
                    (pairing_attempt_id,),
                ).fetchone()
                if cred is None:
                    connection.rollback()
                    raise PairingNotFoundError()

            if side == "client":
                assert claim_secret_digest is not None
                assert short_verification_code is not None
                if not hmac.compare_digest(
                    str(attempt["short_verification_code"]),
                    short_verification_code,
                ):
                    # Atomic mismatch counter (BEGIN IMMEDIATE already held).
                    connection.execute(
                        """
                        UPDATE pairing_attempt
                        SET short_code_mismatch_count = short_code_mismatch_count + 1
                        WHERE pairing_attempt_id = ?
                        """,
                        (pairing_attempt_id,),
                    )
                    count_row = connection.execute(
                        """
                        SELECT short_code_mismatch_count
                        FROM pairing_attempt WHERE pairing_attempt_id = ?
                        """,
                        (pairing_attempt_id,),
                    ).fetchone()
                    assert count_row is not None
                    count = int(count_row["short_code_mismatch_count"])
                    if count >= SHORT_CODE_MISMATCH_LIMIT:
                        self._abort_session_locked(
                            connection,
                            pairing_session_id,
                            SESSION_ABORTED_MISMATCH,
                            "short_code_mismatch",
                            expire_pending=True,
                        )
                        self._write_audit(
                            connection,
                            event_type="short_code_limit_reached",
                            pairing_session_id=pairing_session_id,
                            error_code="short_code_mismatch",
                            detail={
                                "reason": "short_code_mismatch",
                                "mismatch_count": count,
                                "to_state": SESSION_ABORTED_MISMATCH,
                                "attempt_id_prefix": pairing_attempt_id[:4],
                            },
                        )
                        connection.commit()
                        raise PairingShortCodeMismatchError()
                    self._write_audit(
                        connection,
                        event_type="short_code_mismatch",
                        pairing_session_id=pairing_session_id,
                        error_code="short_code_mismatch",
                        detail={
                            "reason": "short_code_mismatch",
                            "mismatch_count": count,
                            "attempt_id_prefix": pairing_attempt_id[:4],
                        },
                    )
                    connection.commit()
                    raise PairingShortCodeMismatchError()
                if attempt["client_confirmed_at"] is not None:
                    # idempotent identical confirm
                    pass
                else:
                    connection.execute(
                        """
                        UPDATE pairing_attempt
                        SET client_confirmed_at = ?
                        WHERE pairing_attempt_id = ?
                        """,
                        (now, pairing_attempt_id),
                    )
            else:
                assert granted_capabilities is not None
                requested = json.loads(str(attempt["requested_capabilities_json"]))
                if not set(granted_capabilities).issubset(set(requested)):
                    connection.rollback()
                    raise PairingValidationError("grant_not_subset")
                if attempt["hub_confirmed_at"] is not None:
                    existing_grant = json.loads(str(cred["granted_capabilities_json"]))
                    if existing_grant and existing_grant != granted_capabilities:
                        if str(cred["status"]) == CREDENTIAL_ACTIVE:
                            connection.rollback()
                            raise PairingAttemptConflictError()
                        connection.rollback()
                        raise PairingAttemptConflictError()
                else:
                    grant_json = json.dumps(
                        granted_capabilities,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
                    connection.execute(
                        """
                        UPDATE pairing_attempt
                        SET hub_confirmed_at = ?
                        WHERE pairing_attempt_id = ?
                        """,
                        (now, pairing_attempt_id),
                    )
                    connection.execute(
                        """
                        UPDATE device_credential
                        SET granted_capabilities_json = ?
                        WHERE pairing_attempt_id = ?
                        """,
                        (grant_json, pairing_attempt_id),
                    )

            attempt = connection.execute(
                "SELECT * FROM pairing_attempt WHERE pairing_attempt_id = ?",
                (pairing_attempt_id,),
            ).fetchone()
            assert attempt is not None
            cred = connection.execute(
                "SELECT * FROM device_credential WHERE pairing_attempt_id = ?",
                (pairing_attempt_id,),
            ).fetchone()
            assert cred is not None

            activated = False
            deduplicated = False
            if str(session["state"]) == SESSION_ACTIVE_PAIR and str(
                cred["status"]
            ) == CREDENTIAL_ACTIVE:
                deduplicated = True
            elif (
                attempt["client_confirmed_at"] is not None
                and attempt["hub_confirmed_at"] is not None
                and str(cred["status"]) == CREDENTIAL_PENDING
            ):
                grant_json = str(cred["granted_capabilities_json"])
                granted = json.loads(grant_json)
                connection.execute(
                    """
                    UPDATE device_credential
                    SET status = ?, capability_epoch = 1, paired_at = ?
                    WHERE pairing_attempt_id = ?
                    """,
                    (CREDENTIAL_ACTIVE, now, pairing_attempt_id),
                )
                connection.execute(
                    """
                    UPDATE pairing_session
                    SET state = ?, consumed_at = ?
                    WHERE pairing_session_id = ?
                    """,
                    (SESSION_ACTIVE_PAIR, now, pairing_session_id),
                )
                self._inject("after_dual_confirm_activate")
                self._write_audit(
                    connection,
                    event_type="pairing_activated",
                    pairing_session_id=pairing_session_id,
                    device_id=str(attempt["device_id"]),
                    detail={
                        "to_state": SESSION_ACTIVE_PAIR,
                        "to_status": CREDENTIAL_ACTIVE,
                        "capability_epoch": 1,
                        "granted_count": len(granted),
                        "device_id_prefix": str(attempt["device_id"])[:4],
                    },
                )
                activated = True
                cred = connection.execute(
                    "SELECT * FROM device_credential WHERE pairing_attempt_id = ?",
                    (pairing_attempt_id,),
                ).fetchone()
                session = connection.execute(
                    "SELECT * FROM pairing_session WHERE pairing_session_id = ?",
                    (pairing_session_id,),
                ).fetchone()

            connection.commit()
            assert cred is not None and session is not None
            granted = json.loads(str(cred["granted_capabilities_json"]))
            return ConfirmResult(
                pairing_session_id=pairing_session_id,
                pairing_attempt_id=pairing_attempt_id,
                device_id=str(attempt["device_id"]),
                state=str(session["state"]),
                credential_status=str(cred["status"]),
                capability_epoch=int(cred["capability_epoch"]),
                granted_capabilities=list(granted),
                activated=activated,
                deduplicated=deduplicated,
            )
        except (
            PairingNotFoundError,
            PairingExpiredError,
            PairingClaimInvalidError,
            PairingShortCodeMismatchError,
            PairingAttemptConflictError,
            PairingValidationError,
        ):
            raise
        except sqlite3.Error:
            connection.rollback()
            raise PairingPersistenceError() from None
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _expire_due_locked(
        self, connection: sqlite3.Connection, now_dt: datetime
    ) -> int:
        count = 0
        rows = connection.execute(
            """
            SELECT pairing_session_id, expires_at_server, state
            FROM pairing_session
            WHERE state IN (?, ?)
            """,
            (SESSION_PAIRING_ACTIVE, SESSION_AWAITING_CONFIRM),
        ).fetchall()
        for row in rows:
            if parse_utc_iso(str(row["expires_at_server"])) <= now_dt:
                self._abort_session_locked(
                    connection,
                    str(row["pairing_session_id"]),
                    SESSION_ABORTED_TIMEOUT,
                    "ttl",
                    expire_pending=True,
                )
                count += 1
        # Pending credential TTL
        pending = connection.execute(
            """
            SELECT a.pairing_session_id, a.pending_expires_at, s.state
            FROM pairing_attempt a
            JOIN pairing_session s
              ON s.pairing_session_id = a.pairing_session_id
            WHERE s.state = ?
            """,
            (SESSION_AWAITING_CONFIRM,),
        ).fetchall()
        for row in pending:
            if parse_utc_iso(str(row["pending_expires_at"])) <= now_dt:
                self._abort_session_locked(
                    connection,
                    str(row["pairing_session_id"]),
                    SESSION_ABORTED_TIMEOUT,
                    "pending_ttl",
                    expire_pending=True,
                )
                count += 1
        return count

    def _abort_session_locked(
        self,
        connection: sqlite3.Connection,
        pairing_session_id: str,
        state: str,
        reason: str,
        *,
        expire_pending: bool,
    ) -> None:
        current = connection.execute(
            "SELECT state FROM pairing_session WHERE pairing_session_id = ?",
            (pairing_session_id,),
        ).fetchone()
        if current is None:
            return
        if str(current["state"]) in TERMINAL_SESSION_STATES:
            return
        connection.execute(
            """
            UPDATE pairing_session
            SET state = ?, terminal_reason = ?
            WHERE pairing_session_id = ?
            """,
            (state, reason, pairing_session_id),
        )
        if expire_pending:
            connection.execute(
                """
                UPDATE device_credential
                SET status = ?
                WHERE pairing_attempt_id IN (
                    SELECT pairing_attempt_id FROM pairing_attempt
                    WHERE pairing_session_id = ?
                ) AND status = ?
                """,
                (CREDENTIAL_EXPIRED, pairing_session_id, CREDENTIAL_PENDING),
            )
        self._write_audit(
            connection,
            event_type="pairing_session_aborted",
            pairing_session_id=pairing_session_id,
            detail={
                "reason": reason,
                "from_state": str(current["state"]),
                "to_state": state,
                "session_id_prefix": pairing_session_id[:4],
            },
        )

    def _write_audit(
        self,
        connection: sqlite3.Connection,
        *,
        event_type: str,
        detail: dict[str, Any],
        device_id: str | None = None,
        pairing_session_id: str | None = None,
        error_code: str | None = None,
    ) -> None:
        unknown = set(detail) - AUDIT_DETAIL_ALLOWLIST
        if unknown:
            raise PairingPersistenceError()
        audit_id = generate_ulid(clock=self._clock, randbytes=self._randbytes)
        connection.execute(
            """
            INSERT INTO auth_audit(
                id, device_id, pairing_session_id, event_type,
                error_code, detail_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                audit_id,
                device_id,
                pairing_session_id,
                event_type,
                error_code,
                audit_detail(detail),
                utc_now_iso(self._clock),
            ),
        )

    def _initialize(self) -> None:
        connection = sqlite3.connect(
            self._database_path,
            timeout=self._busy_timeout_ms / 1000,
            isolation_level=None,
        )
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            mode = connection.execute("PRAGMA journal_mode").fetchone()
            if mode is None or str(mode[0]).lower() != "wal":
                raise PairingPersistenceError()
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(f"PRAGMA busy_timeout={self._busy_timeout_ms}")
            # Fail-closed BEFORE applying this version's DDL.
            meta_exists = connection.execute(
                """
                SELECT 1 FROM sqlite_master
                WHERE type = 'table' AND name = 'pairing_schema_meta'
                """
            ).fetchone()
            if meta_exists is not None:
                row = connection.execute(
                    """
                    SELECT schema_version FROM pairing_schema_meta
                    WHERE component = ?
                    """,
                    (SCHEMA_COMPONENT,),
                ).fetchone()
                if row is not None and int(row[0]) != SCHEMA_VERSION:
                    raise PairingSchemaError()
            connection.executescript(_SCHEMA)
            row = connection.execute(
                """
                SELECT schema_version FROM pairing_schema_meta
                WHERE component = ?
                """,
                (SCHEMA_COMPONENT,),
            ).fetchone()
            if row is None:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    INSERT INTO pairing_schema_meta(component, schema_version)
                    VALUES (?, ?)
                    """,
                    (SCHEMA_COMPONENT, SCHEMA_VERSION),
                )
                connection.commit()
            elif int(row[0]) != SCHEMA_VERSION:
                raise PairingSchemaError()
        except PairingSchemaError:
            raise
        except sqlite3.Error:
            raise PairingPersistenceError() from None
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        self._ensure_open()
        try:
            connection = sqlite3.connect(
                self._database_path,
                timeout=self._busy_timeout_ms / 1000,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(f"PRAGMA busy_timeout={self._busy_timeout_ms}")
            return connection
        except sqlite3.Error:
            raise PairingPersistenceError() from None

    def _ensure_open(self) -> None:
        with self._state_lock:
            if self._closed:
                raise PairingClosedError()

    def _require_hub_id(self) -> str:
        if self._hub_id is None:
            raise PairingStateError()
        return self._hub_id

    def _now(self) -> datetime:
        moment = self._clock() if self._clock is not None else datetime.now(timezone.utc)
        if moment.tzinfo is None:
            raise PairingValidationError("clock_must_be_timezone_aware_utc")
        return moment.astimezone(timezone.utc)

    def _inject(self, stage: str) -> None:
        if self._fault_injector is not None:
            self._fault_injector(stage)


def _validated_text(field: str, value: object, *, max_length: int) -> str:
    if not isinstance(value, str):
        raise PairingValidationError(f"{field}_invalid")
    if value != value.strip() or not value or len(value) > max_length:
        raise PairingValidationError(f"{field}_invalid")
    return value


def _identity_from_row(row: sqlite3.Row) -> HubIdentity:
    rotated = row["rotated_at"]
    return HubIdentity(
        hub_id=str(row["hub_id"]),
        cert_fingerprint=str(row["cert_fingerprint"]),
        tls_storage_kind=str(row["tls_storage_kind"]),
        tls_key_ref_id=str(row["tls_key_ref_id"]),
        created_at=str(row["created_at"]),
        rotated_at=str(rotated) if rotated is not None else None,
    )


def _session_from_row(row: sqlite3.Row) -> PairingSessionView:
    return PairingSessionView(
        pairing_session_id=str(row["pairing_session_id"]),
        hub_id=str(row["hub_id"]),
        boot_id=str(row["boot_id"]),
        state=str(row["state"]),
        expires_at_server=str(row["expires_at_server"]),
        terminal_reason=(
            str(row["terminal_reason"])
            if row["terminal_reason"] is not None
            else None
        ),
        created_at=str(row["created_at"]),
        consumed_at=(
            str(row["consumed_at"]) if row["consumed_at"] is not None else None
        ),
    )


def _require_capability_epoch(value: object) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 1
        or value > MAX_SQLITE_INTEGER
    ):
        raise PairingValidationError("capability_epoch_invalid")
    return value


def _credential_view_from_row(row: sqlite3.Row) -> DeviceCredentialView:
    return DeviceCredentialView(
        device_id=str(row["device_id"]),
        hub_id=str(row["hub_id"]),
        pairing_attempt_id=str(row["pairing_attempt_id"]),
        status=str(row["status"]),
        requested_capabilities=list(
            json.loads(str(row["requested_capabilities_json"]))
        ),
        granted_capabilities=list(json.loads(str(row["granted_capabilities_json"]))),
        capability_epoch=int(row["capability_epoch"]),
        display_name=(
            None if row["display_name"] is None else str(row["display_name"])
        ),
        platform=str(row["platform"]),
        paired_at=str(row["paired_at"]) if row["paired_at"] is not None else None,
        revoked_at=str(row["revoked_at"]) if row["revoked_at"] is not None else None,
        last_auth_at=(
            str(row["last_auth_at"]) if row["last_auth_at"] is not None else None
        ),
    )
