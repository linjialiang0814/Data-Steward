"""Atomic CurrentUser TLS identity provisioning (stdlib + cryptography only)."""

from __future__ import annotations

import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from ..pairing_codec import generate_ulid
from .certificate_policy import (
    generate_hub_tls_material,
    load_certificate_pem,
    verify_certificate_policy,
)
from .dacl import apply_and_verify_identity_dacl, verify_path_dacl_exact
from .dpapi import dpapi_protect_current_user
from .errors import TlsIdentityError, TlsProvisionError
from .loader import OWNER_MARKER_FILENAME, LoadedTlsIdentity, load_tls_identity
from .manifest import (
    IDENTITY_MANIFEST_NAME,
    IdentityManifest,
    write_identity_manifest,
)
from .memory import zero_bytearray
from .path_safety import is_reparse_point

CERT_FILENAME = "cert.pem"
KEY_FILENAME = "private_key.encrypted.pem"
BLOB_FILENAME = "key_password.dpapi"
OWNER_FILENAME = OWNER_MARKER_FILENAME
STAGING_PREFIX = ".tls-identity-staging-"
CANDIDATE_PREFIX = ".tls-identity-candidate-"

# 32-byte CSPRNG as lowercase hex (64 chars).
OWNER_TOKEN_BYTES = 32
OWNER_TOKEN_HEX_LEN = OWNER_TOKEN_BYTES * 2

_STEADY_STATE_NAMES = frozenset(
    {
        CERT_FILENAME,
        KEY_FILENAME,
        BLOB_FILENAME,
        IDENTITY_MANIFEST_NAME,
    }
)
_CLEANUP_ALLOWED = _STEADY_STATE_NAMES | {
    OWNER_FILENAME,
    IDENTITY_MANIFEST_NAME + ".tmp",
}

_PUBLICATION_WAIT_S = 5.0
_PUBLICATION_POLL_S = 0.05

_INJECT_HOOK: Callable[[str], None] | None = None


def set_provision_inject_hook(hook: Callable[[str], None] | None) -> None:
    """Test-only failure injection hook (points: after_* / before_*)."""
    global _INJECT_HOOK
    _INJECT_HOOK = hook


def _inject(point: str) -> None:
    if _INJECT_HOOK is not None:
        _INJECT_HOOK(point)


@dataclass(frozen=True)
class ProvisionResult:
    identity: LoadedTlsIdentity
    created: bool
    hub_id: str
    cert_fingerprint_sha256: str


@dataclass(frozen=True)
class RotationCandidate:
    candidate_root: Path
    owner_token: str
    identity: LoadedTlsIdentity
    cert_fingerprint_sha256: str


def _new_owner_token() -> str:
    return secrets.token_hex(OWNER_TOKEN_BYTES)


def _is_valid_owner_token(token: object) -> bool:
    if not isinstance(token, str) or len(token) != OWNER_TOKEN_HEX_LEN:
        return False
    try:
        raw = bytes.fromhex(token)
    except ValueError:
        return False
    return len(raw) == OWNER_TOKEN_BYTES and token == token.lower()


def _write_exclusive(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_BINARY
    fd = os.open(str(path), flags, 0o600)
    try:
        written = 0
        while written < len(data):
            written += os.write(fd, data[written:])
        os.fsync(fd)
    finally:
        os.close(fd)
    verify_path_dacl_exact(path)


def _write_owner(path: Path, owner_token: str) -> None:
    if not _is_valid_owner_token(owner_token):
        raise TlsProvisionError("owner_token_invalid")
    payload = json.dumps(
        {"owner_token": owner_token, "schema_version": 1},
        sort_keys=True,
    ).encode("utf-8")
    _write_exclusive(path / OWNER_FILENAME, payload)


def _read_owner_token_raw(path: Path) -> str | None:
    """Return marker token string, or None if missing/unreadable/corrupt JSON."""
    owner = path / OWNER_FILENAME
    if not owner.is_file() or is_reparse_point(owner):
        return None
    try:
        data = json.loads(owner.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    token = data.get("owner_token")
    if not isinstance(token, str):
        return None
    return token


def _validate_publication_marker(path: Path) -> str:
    """Strict marker validation for publish recovery (fail-closed)."""
    owner = path / OWNER_FILENAME
    if not owner.is_file() or is_reparse_point(owner):
        raise TlsProvisionError("publication_marker_invalid")
    try:
        data = json.loads(owner.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError) as exc:
        raise TlsProvisionError("publication_marker_invalid") from exc
    if not isinstance(data, dict):
        raise TlsProvisionError("publication_marker_invalid")
    if data.get("schema_version") != 1:
        raise TlsProvisionError("publication_marker_invalid")
    token = data.get("owner_token")
    if not _is_valid_owner_token(token):
        raise TlsProvisionError("publication_marker_invalid")
    assert isinstance(token, str)
    return token


def is_reparse_unsafe(path: Path) -> bool:
    return is_reparse_point(path)


def _resolve_absolute(path: Path) -> Path:
    try:
        resolved = path if path.is_absolute() else path.resolve(strict=False)
        if not resolved.is_absolute():
            resolved = resolved.resolve(strict=False)
    except OSError as exc:
        raise TlsProvisionError("path_unresolvable") from exc
    if not resolved.is_absolute():
        raise TlsProvisionError("path_not_absolute")
    return resolved


def _assert_no_reparse_chain(path: Path) -> None:
    """Reject reparse/symlink on path and every existing ancestor."""
    current: Path | None = path
    while current is not None:
        if current.exists() and is_reparse_point(current):
            raise TlsProvisionError("parent_reparse")
        if current.parent == current:
            break
        current = current.parent


def _assert_identity_parent(identity_root: Path) -> tuple[Path, Path]:
    """
    Validate identity_root intent and existing parent.

    Does not create missing parent levels.
    """
    root = _resolve_absolute(Path(identity_root))
    parent = root.parent
    if parent == root:
        raise TlsProvisionError("parent_missing")
    _assert_no_reparse_chain(parent)
    if not parent.exists() or not parent.is_dir():
        raise TlsProvisionError("parent_missing")
    if is_reparse_point(parent):
        raise TlsProvisionError("parent_reparse")
    try:
        parent_resolved = parent.resolve(strict=True)
    except OSError as exc:
        raise TlsProvisionError("parent_unresolvable") from exc
    if is_reparse_point(parent_resolved):
        raise TlsProvisionError("parent_reparse")
    # Identity root itself must not already be a reparse if present.
    if root.exists() and is_reparse_point(root):
        raise TlsProvisionError("identity_root_invalid")
    return root, parent_resolved


def count_transient_siblings(parent: Path) -> int:
    """Count staging/candidate leftovers under parent (for Smoke/tests)."""
    if not parent.is_dir():
        return 0
    total = 0
    for child in parent.iterdir():
        if child.name.startswith(STAGING_PREFIX) or child.name.startswith(
            CANDIDATE_PREFIX
        ):
            total += 1
    return total


def _cleanup_owned_dir(
    path: Path,
    *,
    owner_token: str,
    expected_name: str,
    expected_parent: Path,
) -> None:
    """
    Delete only a directory owned by this run's owner token (fail-closed).

    ``expected_name`` is an additive basename check and never substitutes for
    a present matching owner token.
    """
    if not path.exists():
        return
    if not _is_valid_owner_token(owner_token):
        raise TlsProvisionError("cleanup_owner_token_invalid")
    if not path.is_dir():
        raise TlsProvisionError("cleanup_not_directory")
    if is_reparse_point(path):
        raise TlsProvisionError("cleanup_reparse")

    try:
        resolved = path.resolve(strict=True)
        parent_resolved = expected_parent.resolve(strict=True)
    except OSError as exc:
        raise TlsProvisionError("cleanup_path_unresolvable") from exc

    if resolved.parent != parent_resolved:
        raise TlsProvisionError("cleanup_parent_mismatch")
    if resolved.name != expected_name or path.name != expected_name:
        raise TlsProvisionError("cleanup_name_mismatch")
    if is_reparse_point(resolved):
        raise TlsProvisionError("cleanup_reparse")

    actual = _read_owner_token_raw(resolved)
    if actual is None:
        raise TlsProvisionError("cleanup_owner_missing")
    if not _is_valid_owner_token(actual):
        raise TlsProvisionError("cleanup_owner_invalid")
    if not hmac.compare_digest(actual, owner_token):
        raise TlsProvisionError("cleanup_owner_mismatch")

    # Validate the full allow-list first; never partially delete on refusal.
    children = list(resolved.iterdir())
    for child in children:
        if child.name not in _CLEANUP_ALLOWED:
            raise TlsProvisionError("cleanup_unknown_entry")
        if child.is_dir() or child.is_symlink() or is_reparse_point(child):
            raise TlsProvisionError("cleanup_unexpected_entry")
        try:
            child_resolved = child.resolve(strict=True)
            child_resolved.relative_to(resolved)
        except (OSError, ValueError) as exc:
            raise TlsProvisionError("cleanup_path_escape") from exc
        if child_resolved.parent != resolved:
            raise TlsProvisionError("cleanup_path_escape")
    for child in children:
        child.unlink()
    resolved.rmdir()


def _try_cleanup_owned_dir(
    path: Path,
    *,
    owner_token: str,
    expected_name: str,
    expected_parent: Path,
) -> Exception | None:
    try:
        if path.exists() and path.is_dir():
            _cleanup_owned_dir(
                path,
                owner_token=owner_token,
                expected_name=expected_name,
                expected_parent=expected_parent,
            )
        return None
    except Exception as exc:  # noqa: BLE001
        return exc


def _raise_with_optional_cleanup_failure(
    primary: Exception,
    cleanup_exc: Exception | None,
) -> None:
    if cleanup_exc is not None:
        raise TlsProvisionError("cleanup_failed") from primary
    raise primary


def _materialize_identity_files(
    staging: Path,
    *,
    hub_id: str,
) -> LoadedTlsIdentity:
    password = bytearray(secrets.token_bytes(32))
    try:
        material = generate_hub_tls_material(password=password)
        _inject("after_material_generated")
        blob = dpapi_protect_current_user(bytes(password))
    finally:
        zero_bytearray(password)

    _write_exclusive(staging / CERT_FILENAME, material.cert_pem)
    _inject("after_cert_written")
    _write_exclusive(staging / KEY_FILENAME, material.encrypted_key_pem)
    _inject("after_key_written")
    _write_exclusive(staging / BLOB_FILENAME, blob)
    _inject("after_dpapi_written")

    cert = load_certificate_pem(material.cert_pem)
    verify_certificate_policy(cert)
    _inject("after_policy_verified")

    manifest = IdentityManifest(
        schema_version=1,
        hub_id=hub_id,
        cert_fingerprint_sha256=material.cert_fingerprint_sha256,
        cert_filename=CERT_FILENAME,
        encrypted_key_filename=KEY_FILENAME,
        dpapi_blob_filename=BLOB_FILENAME,
        tls_storage_kind="dpapi_encrypted_pkcs8",
    )
    _inject("before_manifest_written")
    tmp_manifest = staging / (IDENTITY_MANIFEST_NAME + ".tmp")
    write_identity_manifest(tmp_manifest, manifest)
    data = tmp_manifest.read_bytes()
    tmp_manifest.unlink()
    _write_exclusive(staging / IDENTITY_MANIFEST_NAME, data)
    _inject("after_manifest_written")

    # Staging may contain publication/owner marker.
    loaded = load_tls_identity(staging, allow_owner_marker=True)
    _inject("after_validation")
    if loaded.cert_fingerprint_sha256 != material.cert_fingerprint_sha256:
        raise TlsProvisionError("fingerprint_mismatch")
    if loaded.manifest.hub_id != hub_id:
        raise TlsProvisionError("hub_id_mismatch")
    return loaded


def _verify_published_material(identity_root: Path) -> LoadedTlsIdentity:
    """Validate published dir that may still hold the publication marker."""
    _validate_publication_marker(identity_root)
    loaded = load_tls_identity(identity_root, allow_owner_marker=True)
    cert_pem = (identity_root / loaded.manifest.cert_filename).read_bytes()
    verify_certificate_policy(load_certificate_pem(cert_pem))
    return loaded


def _remove_publication_marker(identity_root: Path) -> None:
    marker = identity_root / OWNER_FILENAME
    if not marker.exists():
        return
    if is_reparse_point(marker) or marker.is_symlink() or not marker.is_file():
        raise TlsProvisionError("publication_marker_invalid")
    # Exact name only; never recursive.
    if marker.name != OWNER_FILENAME:
        raise TlsProvisionError("publication_marker_invalid")
    marker.unlink()


def finish_publication_if_needed(identity_root: Path) -> LoadedTlsIdentity:
    """
    Complete publish recovery when final exists with publication marker.

    On validation failure: fail-closed, keep marker, never overwrite.
    """
    root, _parent = _assert_identity_parent(identity_root)
    marker = root / OWNER_FILENAME
    if not marker.exists():
        return load_tls_identity(root)

    try:
        _verify_published_material(root)
        _inject("before_publication_marker_remove")
        _remove_publication_marker(root)
        _inject("after_publication_marker_remove")
        _inject("before_final_strict_load")
        return load_tls_identity(root)
    except TlsProvisionError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise TlsProvisionError("publication_recovery_failed") from exc


def _wait_load_published(
    identity_root: Path, *, timeout_s: float = _PUBLICATION_WAIT_S
) -> LoadedTlsIdentity:
    """Bounded wait / assist recovery for concurrent losers."""
    deadline = time.monotonic() + timeout_s
    last: Exception | None = None
    while time.monotonic() < deadline:
        if not identity_root.exists():
            time.sleep(_PUBLICATION_POLL_S)
            continue
        try:
            return finish_publication_if_needed(identity_root)
        except TlsProvisionError as exc:
            # Permanent fail-closed (corrupt published+marker): do not loop.
            if exc.args and exc.args[0] == "publication_recovery_failed":
                raise
            last = exc
            time.sleep(_PUBLICATION_POLL_S)
        except TlsIdentityError as exc:
            last = exc
            time.sleep(_PUBLICATION_POLL_S)
    if last is not None:
        raise TlsProvisionError("identity_not_ready") from last
    raise TlsProvisionError("identity_not_ready")


def _is_legally_published_final(identity_root: Path) -> bool:
    """True when final looks like a concurrent winner publication (possibly pending)."""
    if not identity_root.exists() or not identity_root.is_dir():
        return False
    if is_reparse_point(identity_root):
        return False
    marker = identity_root / OWNER_FILENAME
    required = [
        identity_root / CERT_FILENAME,
        identity_root / KEY_FILENAME,
        identity_root / BLOB_FILENAME,
        identity_root / IDENTITY_MANIFEST_NAME,
    ]
    if not all(p.is_file() and not is_reparse_point(p) for p in required):
        return False
    # Marker optional (winner may have finished); if present must be a file.
    if marker.exists() and (not marker.is_file() or is_reparse_point(marker)):
        return False
    return True


def _complete_publish(identity_root: Path) -> LoadedTlsIdentity:
    """Post-rename publish steps until steady-state strict load."""
    _inject("immediately_after_rename")
    _inject("after_publish")
    _verify_published_material(identity_root)
    _inject("before_publication_marker_remove")
    _remove_publication_marker(identity_root)
    _inject("after_publication_marker_remove")
    _inject("before_final_strict_load")
    return load_tls_identity(identity_root)


def provision_or_load_identity(
    identity_root: Path,
    *,
    hub_id: str | None = None,
) -> ProvisionResult:
    """
    Idempotent first-run provisioner.

    - Missing final → stage, verify, atomic publish (rename = commit).
    - Existing final with publication marker → recover (never regenerate).
    - Existing steady-state final → strict load only (never overwrite).
    """
    root, parent = _assert_identity_parent(identity_root)

    if root.exists():
        if not root.is_dir() or is_reparse_point(root):
            raise TlsProvisionError("identity_root_invalid")
        try:
            loaded = finish_publication_if_needed(root)
        except TlsProvisionError:
            raise
        except TlsIdentityError as exc:
            raise TlsProvisionError("existing_identity_invalid") from exc
        return ProvisionResult(
            identity=loaded,
            created=False,
            hub_id=loaded.manifest.hub_id,
            cert_fingerprint_sha256=loaded.cert_fingerprint_sha256,
        )

    owner_token = _new_owner_token()
    run_id = secrets.token_hex(16)
    staging = parent / f"{STAGING_PREFIX}{run_id}"
    if staging.exists():
        raise TlsProvisionError("staging_exists")

    staging.mkdir()
    try:
        apply_and_verify_identity_dacl(staging)
        _write_owner(staging, owner_token)
        _inject("after_dacl")
        clean_hub = hub_id if hub_id is not None else generate_ulid()
        loaded = _materialize_identity_files(staging, hub_id=clean_hub)
        _inject("before_publish")
        _inject("immediately_before_rename")
        try:
            # Same verified parent → rename cannot cross volumes.
            if staging.parent.resolve(strict=True) != parent:
                raise TlsProvisionError("staging_parent_mismatch")
            os.rename(str(staging), str(root))
        except TlsProvisionError:
            raise
        except OSError as exc:
            if _is_legally_published_final(root):
                cleanup_exc = _try_cleanup_owned_dir(
                    staging,
                    owner_token=owner_token,
                    expected_name=staging.name,
                    expected_parent=parent,
                )
                if cleanup_exc is not None:
                    raise TlsProvisionError("cleanup_failed") from exc
                winner = _wait_load_published(root)
                return ProvisionResult(
                    identity=winner,
                    created=False,
                    hub_id=winner.manifest.hub_id,
                    cert_fingerprint_sha256=winner.cert_fingerprint_sha256,
                )
            raise TlsProvisionError("rename_failed") from exc

        final = _complete_publish(root)
        return ProvisionResult(
            identity=final,
            created=True,
            hub_id=final.manifest.hub_id,
            cert_fingerprint_sha256=final.cert_fingerprint_sha256,
        )
    except Exception as primary:
        # After successful rename, staging path is gone — do not delete final.
        should_cleanup = False
        try:
            should_cleanup = staging.exists() and (
                not root.exists()
                or staging.resolve(strict=False) != root.resolve(strict=False)
            )
        except OSError:
            should_cleanup = staging.exists() and not root.exists()
        cleanup_exc = None
        if should_cleanup:
            cleanup_exc = _try_cleanup_owned_dir(
                staging,
                owner_token=owner_token,
                expected_name=staging.name,
                expected_parent=parent,
            )
        _raise_with_optional_cleanup_failure(primary, cleanup_exc)
        raise  # pragma: no cover


def create_rotation_candidate(
    identity_root: Path,
    *,
    parent: Path | None = None,
) -> RotationCandidate:
    """
    Create a verified rotation candidate with a different key/fingerprint.

    Does NOT activate, replace, or delete the current identity.
    """
    root, default_parent = _assert_identity_parent(identity_root)
    current = load_tls_identity(root)
    base = _resolve_absolute(Path(parent)) if parent is not None else default_parent
    _assert_no_reparse_chain(base)
    if not base.exists() or not base.is_dir() or is_reparse_point(base):
        raise TlsProvisionError("parent_missing")
    try:
        base = base.resolve(strict=True)
    except OSError as exc:
        raise TlsProvisionError("parent_unresolvable") from exc

    owner_token = _new_owner_token()
    run_id = secrets.token_hex(16)
    candidate = base / f"{CANDIDATE_PREFIX}{run_id}"
    if candidate.exists():
        raise TlsProvisionError("candidate_exists")
    candidate.mkdir()
    try:
        apply_and_verify_identity_dacl(candidate)
        _write_owner(candidate, owner_token)
        loaded = _materialize_identity_files(
            candidate, hub_id=current.manifest.hub_id
        )
        if loaded.cert_fingerprint_sha256 == current.cert_fingerprint_sha256:
            raise TlsProvisionError("candidate_fingerprint_collision")
        return RotationCandidate(
            candidate_root=candidate,
            owner_token=owner_token,
            identity=loaded,
            cert_fingerprint_sha256=loaded.cert_fingerprint_sha256,
        )
    except Exception as primary:
        cleanup_exc = _try_cleanup_owned_dir(
            candidate,
            owner_token=owner_token,
            expected_name=candidate.name,
            expected_parent=base,
        )
        _raise_with_optional_cleanup_failure(primary, cleanup_exc)
        raise  # pragma: no cover


def discard_rotation_candidate(candidate: RotationCandidate) -> None:
    """Precisely discard a candidate owned by this token; never touches active identity."""
    parent = candidate.candidate_root.parent
    try:
        parent_resolved = parent.resolve(strict=True)
    except OSError as exc:
        raise TlsProvisionError("cleanup_failed") from exc
    try:
        _cleanup_owned_dir(
            candidate.candidate_root,
            owner_token=candidate.owner_token,
            expected_name=candidate.candidate_root.name,
            expected_parent=parent_resolved,
        )
    except TlsProvisionError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise TlsProvisionError("cleanup_failed") from exc


def wait_identity_stable(
    identity_root: Path, *, timeout_s: float = 5.0
) -> LoadedTlsIdentity:
    """Utility for concurrent tests: wait until final identity is loadable."""
    return _wait_load_published(Path(identity_root), timeout_s=timeout_s)
