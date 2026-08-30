"""Permanent CurrentUser TLS identity bootstrap (Known Folder paths only).

Creates only:
  <KnownFolder LocalAppData>\\DataSteward
  <KnownFolder LocalAppData>\\DataSteward\\hub
  <KnownFolder LocalAppData>\\DataSteward\\hub\\tls-identity-v1
  + steady-state four files via provision_or_load_identity.

Does not accept path overrides. Does not create databases, candidates, or logs.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .certificate_policy import load_certificate_pem, verify_certificate_policy
from .dacl import (
    REQUIRED_SID_CATEGORIES,
    apply_and_verify_identity_dacl,
    verify_identity_root_dacl,
    verify_path_dacl_exact,
)
from .errors import TlsPermanentPathError, redacted_error
from .loader import OWNER_MARKER_FILENAME, load_tls_identity
from .path_safety import is_reparse_point
from .permanent_paths import (
    HUB_DIR_NAME,
    IDENTITY_DIR_NAME,
    PRODUCT_DIR_NAME,
    STEADY_STATE_FILES,
    local_app_data_root,
    permanent_hub_parent,
    permanent_identity_root,
    permanent_product_base,
    permanent_steady_state_paths,
)
from .provisioner import (
    CANDIDATE_PREFIX,
    STAGING_PREFIX,
    ProvisionResult,
    count_transient_siblings,
    provision_or_load_identity,
)

_MAX_FILE_BYTES = {
    "cert.pem": 64 * 1024,
    "private_key.encrypted.pem": 64 * 1024,
    "key_password.dpapi": 8 * 1024,
    "identity.json": 16 * 1024,
}


@dataclass(frozen=True)
class PermanentBootstrapResult:
    """In-process result. Callers must redact before logging or docs."""

    created: bool
    hub_id: str
    cert_fingerprint_sha256: str
    created_product_dir: bool
    created_hub_dir: bool
    provision: ProvisionResult


def _assert_safe_existing_dir(path: Path, *, label: str) -> None:
    if not path.exists():
        raise TlsPermanentPathError(f"{label}_missing")
    if not path.is_dir():
        raise TlsPermanentPathError(f"{label}_not_directory")
    if is_reparse_point(path):
        raise TlsPermanentPathError(f"{label}_reparse")


def _assert_absent_or_safe_dir(path: Path, *, label: str) -> None:
    if not path.exists():
        return
    if not path.is_dir() or is_reparse_point(path):
        raise TlsPermanentPathError(f"{label}_preexisting_unsafe")


def _create_protected_dir(path: Path) -> None:
    if path.exists():
        raise TlsPermanentPathError("directory_already_exists")
    if is_reparse_point(path.parent):
        raise TlsPermanentPathError("parent_reparse")
    path.mkdir()
    if is_reparse_point(path) or not path.is_dir():
        raise TlsPermanentPathError("created_dir_unsafe")
    apply_and_verify_identity_dacl(path)
    if is_reparse_point(path):
        raise TlsPermanentPathError("created_dir_reparse")


def _rmdir_if_empty_owned(path: Path) -> None:
    """Bottom-up empty rmdir only; never recursive delete."""
    if not path.exists():
        return
    if not path.is_dir() or is_reparse_point(path):
        return
    try:
        next(path.iterdir())
        return
    except StopIteration:
        pass
    try:
        path.rmdir()
    except OSError:
        return


def _rollback_created_parents(
    *,
    created_hub: bool,
    created_product: bool,
    hub: Path,
    product: Path,
    identity: Path,
) -> None:
    """
    On failure before/without committed identity: remove only empty dirs
    created by this run. Never delete pre-existing directories or recurse.
    """
    if identity.exists():
        # Publication may have committed — do not delete identity or parents.
        return
    if created_hub:
        _rmdir_if_empty_owned(hub)
    if created_product and (not hub.exists()):
        _rmdir_if_empty_owned(product)


def provision_or_load_permanent_identity(
    *,
    identity_root: Path | None = None,
    **forbidden: Any,
) -> PermanentBootstrapResult:
    """
    Idempotent permanent identity bootstrap.

    Path overrides are rejected. Product always uses Known Folder resolution.
    """
    if identity_root is not None or forbidden:
        raise TlsPermanentPathError("permanent_path_override_forbidden")

    appdata = local_app_data_root()
    _assert_safe_existing_dir(appdata, label="local_app_data")

    product = permanent_product_base()
    hub = permanent_hub_parent()
    identity = permanent_identity_root()
    if product != appdata / PRODUCT_DIR_NAME:
        raise TlsPermanentPathError("permanent_product_mismatch")
    if hub != product / HUB_DIR_NAME:
        raise TlsPermanentPathError("permanent_hub_mismatch")
    if identity != hub / IDENTITY_DIR_NAME:
        raise TlsPermanentPathError("permanent_identity_mismatch")

    _assert_absent_or_safe_dir(product, label="product")
    _assert_absent_or_safe_dir(hub, label="hub")
    if identity.exists() and (not identity.is_dir() or is_reparse_point(identity)):
        raise TlsPermanentPathError("identity_preexisting_unsafe")

    created_product = False
    created_hub = False
    try:
        if not product.exists():
            _create_protected_dir(product)
            created_product = True
        else:
            verify_identity_root_dacl(product)
            if is_reparse_point(product):
                raise TlsPermanentPathError("product_reparse")

        if not hub.exists():
            _create_protected_dir(hub)
            created_hub = True
        else:
            verify_identity_root_dacl(hub)
            if is_reparse_point(hub):
                raise TlsPermanentPathError("hub_reparse")
            # Hub must only contain tls-identity-v1 (and maybe nothing yet).
            for child in hub.iterdir():
                if child.name == IDENTITY_DIR_NAME:
                    continue
                if child.name.startswith(STAGING_PREFIX) or child.name.startswith(
                    CANDIDATE_PREFIX
                ):
                    # Transient siblings should not remain; fail-closed.
                    raise TlsPermanentPathError("hub_transient_sibling_present")
                raise TlsPermanentPathError("hub_unknown_entry")

        result = provision_or_load_identity(identity)
        audit_permanent_identity_tree()
        return PermanentBootstrapResult(
            created=result.created,
            hub_id=result.hub_id,
            cert_fingerprint_sha256=result.cert_fingerprint_sha256,
            created_product_dir=created_product,
            created_hub_dir=created_hub,
            provision=result,
        )
    except Exception as primary:
        # Prefer publication recovery over regenerating a second identity.
        if identity.exists() and identity.is_dir() and not is_reparse_point(identity):
            try:
                recovered = provision_or_load_identity(identity)
                audit_permanent_identity_tree()
                return PermanentBootstrapResult(
                    created=False,
                    hub_id=recovered.hub_id,
                    cert_fingerprint_sha256=recovered.cert_fingerprint_sha256,
                    created_product_dir=created_product,
                    created_hub_dir=created_hub,
                    provision=recovered,
                )
            except Exception as recovery_exc:
                # Keep the original fail-closed outer error. Do not chain
                # recovery_exc (may embed absolute paths in its traceback).
                # Store only a redacted stage:ExceptionType diagnostic note.
                primary.add_note(redacted_error("PERMANENT_RECOVERY", recovery_exc))
                raise primary from None
        _rollback_created_parents(
            created_hub=created_hub,
            created_product=created_product,
            hub=hub,
            product=product,
            identity=identity,
        )
        raise


def audit_permanent_identity_tree() -> dict[str, Any]:
    """Read-only permanent resource audit (no secrets / no absolute paths)."""
    product = permanent_product_base()
    hub = permanent_hub_parent()
    identity = permanent_identity_root()

    for path, label in (
        (product, "product"),
        (hub, "hub"),
        (identity, "identity"),
    ):
        _assert_safe_existing_dir(path, label=label)
        verify_identity_root_dacl(path)

    children = {p.name: p for p in hub.iterdir()}
    allowed_directories = {
        IDENTITY_DIR_NAME,
        "file-scope-v1",
        "organizer-v1",
    }
    allowed_files = {
        "steward.sqlite3",
        "steward.sqlite3-wal",
        "steward.sqlite3-shm",
    }
    if IDENTITY_DIR_NAME not in children or any(
        name not in allowed_directories | allowed_files for name in children
    ):
        raise TlsPermanentPathError("hub_contents_invalid")
    for name, path in children.items():
        if is_reparse_point(path):
            raise TlsPermanentPathError("hub_component_reparse")
        if name in allowed_directories and not path.is_dir():
            raise TlsPermanentPathError("hub_component_type_invalid")
        if name in allowed_files and not path.is_file():
            raise TlsPermanentPathError("hub_component_type_invalid")

    entries = sorted(p.name for p in identity.iterdir())
    if entries != sorted(STEADY_STATE_FILES):
        raise TlsPermanentPathError("identity_contents_invalid")
    if (identity / OWNER_MARKER_FILENAME).exists():
        raise TlsPermanentPathError("publication_marker_present")
    if count_transient_siblings(hub) != 0:
        raise TlsPermanentPathError("transient_siblings_present")

    file_rows: list[dict[str, Any]] = []
    for name in STEADY_STATE_FILES:
        path = identity / name
        if not path.is_file() or is_reparse_point(path):
            raise TlsPermanentPathError("identity_file_unsafe")
        verify_path_dacl_exact(path)
        size = path.stat().st_size
        if size > _MAX_FILE_BYTES[name]:
            raise TlsPermanentPathError("identity_file_too_large")
        raw = path.read_bytes()
        if name == "private_key.encrypted.pem":
            text = raw.decode("utf-8", errors="replace")
            if "BEGIN ENCRYPTED PRIVATE KEY" not in text:
                raise TlsPermanentPathError("encrypted_key_missing")
            if "BEGIN PRIVATE KEY" in text or "BEGIN RSA PRIVATE KEY" in text:
                raise TlsPermanentPathError("plaintext_key_forbidden")
        file_rows.append(
            {
                "name": name,
                "size_bytes": size,
                "dacl_categories": list(REQUIRED_SID_CATEGORIES),
            }
        )

    loaded = load_tls_identity(identity)
    cert = load_certificate_pem((identity / "cert.pem").read_bytes())
    verify_certificate_policy(cert)

    return {
        "path_template": (
            r"%LOCALAPPDATA%\DataSteward\hub\tls-identity-v1"
        ),
        "dacl_categories": list(REQUIRED_SID_CATEGORIES),
        "directories": {
            "DataSteward": {"reparse": False, "dacl_categories": list(REQUIRED_SID_CATEGORIES)},
            "hub": {
                "reparse": False,
                "dacl_categories": list(REQUIRED_SID_CATEGORIES),
                "children": [IDENTITY_DIR_NAME],
            },
            "tls-identity-v1": {
                "reparse": False,
                "dacl_categories": list(REQUIRED_SID_CATEGORIES),
                "children": list(STEADY_STATE_FILES),
                "owner_marker": 0,
                "unknown_entries": 0,
            },
        },
        "files": file_rows,
        "cert_not_before_utc": cert.not_valid_before_utc.date().isoformat(),
        "cert_not_after_utc": cert.not_valid_after_utc.date().isoformat(),
        "fingerprint_prefix8": loaded.cert_fingerprint_sha256[:8],
        "fingerprint_suffix8": loaded.cert_fingerprint_sha256[-8:],
        "fingerprint_evidence_sha256": hashlib.sha256(
            loaded.cert_fingerprint_sha256.encode("ascii")
        ).hexdigest(),
        "hub_id_evidence_sha256": hashlib.sha256(
            loaded.manifest.hub_id.encode("ascii")
        ).hexdigest(),
        "loader_ok": True,
        "certificate_policy_ok": True,
    }


def redacted_bootstrap_evidence(result: PermanentBootstrapResult) -> dict[str, Any]:
    """Evidence safe for docs/logs (no full path / hub_id / fingerprint)."""
    audit = audit_permanent_identity_tree()
    return {
        "created": result.created,
        "created_product_dir": result.created_product_dir,
        "created_hub_dir": result.created_hub_dir,
        "idempotent": not result.created,
        "fingerprint_prefix8": result.cert_fingerprint_sha256[:8],
        "fingerprint_suffix8": result.cert_fingerprint_sha256[-8:],
        "fingerprint_evidence_sha256": hashlib.sha256(
            result.cert_fingerprint_sha256.encode("ascii")
        ).hexdigest(),
        "hub_id_evidence_sha256": hashlib.sha256(
            result.hub_id.encode("ascii")
        ).hexdigest(),
        "audit": audit,
    }


def file_content_digests() -> dict[str, str]:
    """SHA-256 of each steady-state file (for idempotent mtime/content checks)."""
    out: dict[str, str] = {}
    for path in permanent_steady_state_paths():
        out[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return out


def file_mtimes_ns() -> dict[str, int]:
    out: dict[str, int] = {}
    for path in permanent_steady_state_paths():
        out[path.name] = path.stat().st_mtime_ns
    return out
