"""Production TLS identity loader (CurrentUser DPAPI + encrypted PKCS#8)."""

from .certificate_policy import (
    CERT_VALIDITY_DAYS,
    verify_certificate_policy,
)
from .dacl import apply_and_verify_identity_dacl, verify_path_dacl_exact
from .dpapi import dpapi_protect_current_user, dpapi_unprotect_current_user
from .errors import (
    AclBlockedError,
    TlsCertificatePolicyError,
    TlsIdentityError,
    TlsPermanentPathError,
    TlsPinError,
    TlsProvisionError,
    redacted_error,
)
from .permanent_identity import (
    PermanentBootstrapResult,
    audit_permanent_identity_tree,
    file_content_digests,
    file_mtimes_ns,
    provision_or_load_permanent_identity,
    redacted_bootstrap_evidence,
)
from .loader import (
    LoadedTlsIdentity,
    build_ssl_context_factory,
    cert_der_sha256_hex,
    load_tls_identity,
)
from .manifest import (
    IDENTITY_MANIFEST_NAME,
    IdentityManifest,
    format_fingerprint_display,
    normalize_fingerprint,
    parse_identity_manifest,
    require_fingerprint_sha256,
    write_identity_manifest,
)
from .memory import zero_bytearray
from .permanent_paths import (
    permanent_hub_parent,
    permanent_identity_root,
    permanent_product_base,
    permanent_steady_state_paths,
    preflight_permanent_identity_parents,
    set_local_app_data_resolver_for_tests,
)
from .provisioner import (
    ProvisionResult,
    RotationCandidate,
    count_transient_siblings,
    create_rotation_candidate,
    discard_rotation_candidate,
    finish_publication_if_needed,
    provision_or_load_identity,
    set_provision_inject_hook,
)

__all__ = [
    "AclBlockedError",
    "CERT_VALIDITY_DAYS",
    "IDENTITY_MANIFEST_NAME",
    "IdentityManifest",
    "LoadedTlsIdentity",
    "PermanentBootstrapResult",
    "ProvisionResult",
    "RotationCandidate",
    "TlsCertificatePolicyError",
    "TlsIdentityError",
    "TlsPermanentPathError",
    "TlsPinError",
    "TlsProvisionError",
    "apply_and_verify_identity_dacl",
    "audit_permanent_identity_tree",
    "build_ssl_context_factory",
    "cert_der_sha256_hex",
    "count_transient_siblings",
    "create_rotation_candidate",
    "discard_rotation_candidate",
    "dpapi_protect_current_user",
    "dpapi_unprotect_current_user",
    "file_content_digests",
    "file_mtimes_ns",
    "finish_publication_if_needed",
    "format_fingerprint_display",
    "load_tls_identity",
    "normalize_fingerprint",
    "parse_identity_manifest",
    "permanent_hub_parent",
    "permanent_identity_root",
    "permanent_product_base",
    "permanent_steady_state_paths",
    "preflight_permanent_identity_parents",
    "provision_or_load_identity",
    "provision_or_load_permanent_identity",
    "redacted_bootstrap_evidence",
    "redacted_error",
    "require_fingerprint_sha256",
    "set_local_app_data_resolver_for_tests",
    "set_provision_inject_hook",
    "verify_certificate_policy",
    "verify_path_dacl_exact",
    "write_identity_manifest",
    "zero_bytearray",
]
