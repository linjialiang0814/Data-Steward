"""Fail-closed TLS identity errors (no secret-bearing messages)."""

from __future__ import annotations


class TlsIdentityError(ValueError):
    """Identity load or validation failed before listen."""

    error_code = "tls_identity_invalid"


class AclBlockedError(TlsIdentityError):
    error_code = "tls_acl_blocked"


class TlsPathSafetyError(TlsIdentityError):
    error_code = "tls_path_unsafe"


class TlsManifestError(TlsIdentityError):
    error_code = "tls_manifest_invalid"


class TlsDpapiError(TlsIdentityError):
    error_code = "tls_dpapi_failed"


class TlsPinError(TlsIdentityError):
    error_code = "tls_pin_mismatch"


class TlsProvisionError(TlsIdentityError):
    error_code = "tls_provision_failed"


class TlsCertificatePolicyError(TlsIdentityError):
    error_code = "tls_certificate_policy_invalid"


class TlsPermanentPathError(TlsIdentityError):
    error_code = "tls_permanent_path_invalid"


def redacted_error(stage: str, exc: BaseException) -> str:
    """Stable stage + exception type only; never raw str(exc)."""
    import re

    stage_key = re.sub(r"[^A-Z0-9_]", "", stage.upper())[:48] or "STAGE"
    return f"{stage_key}:{type(exc).__name__}"
