"""Stable, redacted domain errors for pairing storage (no paths/secrets)."""


class PairingError(Exception):
    """Base pairing-storage error safe for local callers."""

    error_code: str = "pairing_error"

    def __init__(self, message: str | None = None) -> None:
        super().__init__(message or self.error_code)


class PairingValidationError(PairingError):
    error_code = "pairing_validation_error"


class PairingNotFoundError(PairingError):
    error_code = "pairing_not_found"


class PairingIdentityConflictError(PairingError):
    error_code = "identity_conflict"


class PairingIdentityCasError(PairingError):
    error_code = "identity_cas_mismatch"


class PairingBusyError(PairingError):
    error_code = "pairing_busy"


class PairingAttemptConflictError(PairingError):
    error_code = "pairing_attempt_conflict"


class PairingExpiredError(PairingError):
    error_code = "pairing_expired"


class PairingRejectedError(PairingError):
    error_code = "pairing_rejected"


class PairingStateError(PairingError):
    error_code = "pairing_state_invalid"


class PairingClaimInvalidError(PairingError):
    error_code = "claim_invalid"


class PairingShortCodeMismatchError(PairingError):
    error_code = "short_code_mismatch"


class PairingAuthInvalidError(PairingError):
    error_code = "auth_invalid"


class PairingAuthRevokedError(PairingError):
    error_code = "auth_revoked"


class PairingAuthExpiredError(PairingError):
    error_code = "auth_expired"


class PairingCapabilityDeniedError(PairingError):
    error_code = "capability_denied"


class PairingCapabilityEpochStaleError(PairingError):
    error_code = "capability_epoch_stale"


class PairingSchemaError(PairingError):
    error_code = "pairing_schema_unsupported"


class PairingPersistenceError(PairingError):
    error_code = "pairing_persistence_error"


class PairingClosedError(PairingError):
    error_code = "pairing_store_closed"
