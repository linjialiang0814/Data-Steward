"""Load CurrentUser DPAPI + encrypted PKCS#8 into a prebuilt SSLContext factory."""

from __future__ import annotations

import hashlib
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .dacl import verify_identity_root_dacl, verify_path_dacl_exact
from .dpapi import dpapi_unprotect_current_user
from .errors import TlsIdentityError
from .manifest import (
    IDENTITY_MANIFEST_NAME,
    IdentityManifest,
    load_identity_manifest,
    require_fingerprint_sha256,
)
from .memory import zero_bytearray
from .path_safety import assert_path_inside_root, is_reparse_point

MAX_CERT_BYTES = 64 * 1024
MAX_ENCRYPTED_KEY_BYTES = 64 * 1024
MAX_DPAPI_BLOB_BYTES = 8 * 1024

_STEADY_STATE_FILE_NAMES = frozenset(
    {
        IDENTITY_MANIFEST_NAME,
        "cert.pem",
        "tls_cert.pem",
        "private_key.encrypted.pem",
        "tls_key.enc.pem",
        "key_password.dpapi",
        "tls_key_password.dpapi",
    }
)
# Staging / publication-recovery only; never accepted by default strict load.
OWNER_MARKER_FILENAME = ".provision_owner"


@dataclass
class LoadedTlsIdentity:
    """Validated identity paths + fingerprint (no password retained)."""

    identity_root: Path
    manifest: IdentityManifest
    cert_path: Path
    key_path: Path
    dpapi_blob_path: Path
    cert_fingerprint_sha256: str


def read_bounded_bytes(path: Path, *, max_bytes: int, error_code: str) -> bytes:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise TlsIdentityError(error_code) from exc
    if size > max_bytes:
        raise TlsIdentityError(error_code)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise TlsIdentityError(error_code) from exc
    if len(data) > max_bytes:
        raise TlsIdentityError(error_code)
    return data


def cert_der_sha256_hex(cert_path: Path) -> str:
    pem = read_bounded_bytes(
        cert_path, max_bytes=MAX_CERT_BYTES, error_code="cert_too_large"
    )
    try:
        der = ssl.PEM_cert_to_DER_cert(pem.decode("ascii"))
    except (UnicodeError, ValueError) as exc:
        raise TlsIdentityError("cert_unreadable") from exc
    return hashlib.sha256(der).hexdigest()


def _assert_identity_root_entries(
    root: Path, *, allow_owner_marker: bool
) -> None:
    allowed = set(_STEADY_STATE_FILE_NAMES)
    if allow_owner_marker:
        allowed.add(OWNER_MARKER_FILENAME)
    for entry in root.iterdir():
        if is_reparse_point(entry):
            raise TlsIdentityError("unknown_identity_reparse")
        if entry.is_dir():
            raise TlsIdentityError("unknown_identity_directory")
        if not entry.is_file():
            raise TlsIdentityError("unknown_identity_entry")
        if entry.name not in allowed:
            raise TlsIdentityError("unknown_identity_files")


def load_tls_identity(
    identity_root: Path,
    *,
    verify_root_dacl: bool = True,
    allow_owner_marker: bool = False,
) -> LoadedTlsIdentity:
    """
    Validate identity root, DACL, manifest, files, and fingerprint match
    before any network listen. Does not retain the key password.

    ``allow_owner_marker`` is for staging / publication-recovery only.
    Steady-state product loads must leave it false.
    """
    root = assert_path_inside_root(identity_root, identity_root)
    _assert_identity_root_entries(root, allow_owner_marker=allow_owner_marker)
    if verify_root_dacl:
        verify_identity_root_dacl(root)

    manifest_path = assert_path_inside_root(root / IDENTITY_MANIFEST_NAME, root)
    if not manifest_path.is_file():
        raise TlsIdentityError("manifest_missing")
    manifest = load_identity_manifest(manifest_path)

    cert_path = assert_path_inside_root(root / manifest.cert_filename, root)
    key_path = assert_path_inside_root(root / manifest.encrypted_key_filename, root)
    blob_path = assert_path_inside_root(root / manifest.dpapi_blob_filename, root)
    for path in (cert_path, key_path, blob_path):
        if not path.is_file() or is_reparse_point(path):
            raise TlsIdentityError("identity_file_missing")
        verify_path_dacl_exact(path)

    key_bytes = read_bounded_bytes(
        key_path,
        max_bytes=MAX_ENCRYPTED_KEY_BYTES,
        error_code="encrypted_key_too_large",
    )
    try:
        key_text = key_bytes.decode("utf-8")
    except UnicodeError as exc:
        raise TlsIdentityError("encrypted_key_unreadable") from exc
    if "BEGIN ENCRYPTED PRIVATE KEY" not in key_text:
        raise TlsIdentityError("encrypted_key_missing")
    if "BEGIN PRIVATE KEY" in key_text or "BEGIN RSA PRIVATE KEY" in key_text:
        raise TlsIdentityError("plaintext_key_forbidden")

    actual_fp = require_fingerprint_sha256(cert_der_sha256_hex(cert_path))
    if actual_fp != manifest.cert_fingerprint_sha256:
        raise TlsIdentityError("fingerprint_mismatch")

    # Prove DPAPI + key load before returning (password wiped in finally).
    password = bytearray()
    try:
        blob = read_bounded_bytes(
            blob_path,
            max_bytes=MAX_DPAPI_BLOB_BYTES,
            error_code="dpapi_blob_too_large",
        )
        password = dpapi_unprotect_current_user(blob)
        _load_ssl_context(cert_path, key_path, password)
    except TlsIdentityError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise TlsIdentityError("cert_key_load_failed") from exc
    finally:
        zero_bytearray(password)

    return LoadedTlsIdentity(
        identity_root=root,
        manifest=manifest,
        cert_path=cert_path,
        key_path=key_path,
        dpapi_blob_path=blob_path,
        cert_fingerprint_sha256=actual_fp,
    )


def _load_ssl_context(
    cert_path: Path,
    key_path: Path,
    password: bytearray,
) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    def _provider() -> bytes:
        return bytes(password)

    ctx.load_cert_chain(str(cert_path), str(key_path), password=_provider)
    return ctx


def build_ssl_context_factory(
    identity: LoadedTlsIdentity,
) -> tuple[Callable[..., ssl.SSLContext], Callable[[], None]]:
    """
    Decrypt once, build a complete SSLContext, wipe password immediately.

    The returned factory closes only over the ready SSLContext — never over
    password, bytearray, password provider, or DPAPI blob bytes.
    """
    password = bytearray()
    context: ssl.SSLContext | None = None
    try:
        blob = read_bounded_bytes(
            identity.dpapi_blob_path,
            max_bytes=MAX_DPAPI_BLOB_BYTES,
            error_code="dpapi_blob_too_large",
        )
        password = dpapi_unprotect_current_user(blob)
        context = _load_ssl_context(
            identity.cert_path, identity.key_path, password
        )
    except TlsIdentityError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise TlsIdentityError("cert_key_load_failed") from exc
    finally:
        zero_bytearray(password)

    if context is None:
        raise TlsIdentityError("ssl_context_missing")

    ready = context

    def ssl_context_factory(
        config: Any = None, default_factory: Any = None
    ) -> ssl.SSLContext:
        del config, default_factory
        return ready

    def cleanup() -> None:
        # Password already wiped at construction; nothing secret remains.
        return None

    return ssl_context_factory, cleanup
