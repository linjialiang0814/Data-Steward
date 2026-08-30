"""Test-only TLS identity fixture builders (OpenSSL CLI is fixture-only)."""

from __future__ import annotations

import secrets
import subprocess
import sys
from pathlib import Path

from steward_hub.tls_identity import (
    IDENTITY_MANIFEST_NAME,
    IdentityManifest,
    apply_and_verify_identity_dacl,
    cert_der_sha256_hex,
    dpapi_protect_current_user,
    require_fingerprint_sha256,
    verify_path_dacl_exact,
    write_identity_manifest,
    zero_bytearray,
)

_TOOL = Path(__file__).resolve().parents[1] / "tool"
if str(_TOOL) not in sys.path:
    sys.path.insert(0, str(_TOOL))

from spike_windows_tls_identity import find_openssl_cli  # noqa: E402


def require_openssl() -> Path:
    path = find_openssl_cli()
    if path is None:
        raise RuntimeError("openssl_fixture_unavailable")
    return path


def create_temp_identity(
    identity_root: Path,
    *,
    hub_id: str,
    wrong_password: bool = False,
    tamper_dpapi: bool = False,
    wrong_manifest_fingerprint: str | None = None,
) -> tuple[IdentityManifest, str]:
    """
    Build a CurrentUser DPAPI-protected identity under identity_root.
    Applies DACL before writing secrets. Returns (manifest, fingerprint).
    """
    identity_root.mkdir(parents=True, exist_ok=False)
    apply_and_verify_identity_dacl(identity_root)

    openssl = require_openssl()
    key_name = "private_key.encrypted.pem"
    cert_name = "cert.pem"
    blob_name = "key_password.dpapi"
    key_path = identity_root / key_name
    cert_path = identity_root / cert_name
    blob_path = identity_root / blob_name

    password = bytearray(secrets.token_hex(32), "ascii")
    try:
        gen = subprocess.run(
            [
                str(openssl),
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-aes-256-cbc",
                "-pass",
                "stdin",
                "-out",
                str(key_path),
            ],
            input=bytes(password) + b"\n",
            capture_output=True,
            timeout=60,
            check=False,
        )
        if gen.returncode != 0:
            raise RuntimeError("openssl_genpkey_failed")
        key_text = key_path.read_text(encoding="utf-8", errors="replace")
        if "BEGIN ENCRYPTED PRIVATE KEY" not in key_text:
            raise RuntimeError("encrypted_header_missing")
        if "BEGIN PRIVATE KEY" in key_text or "BEGIN RSA PRIVATE KEY" in key_text:
            raise RuntimeError("plaintext_key_detected")

        req = subprocess.run(
            [
                str(openssl),
                "req",
                "-new",
                "-x509",
                "-key",
                str(key_path),
                "-passin",
                "stdin",
                "-out",
                str(cert_path),
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost,IP:127.0.0.1",
            ],
            input=bytes(password) + b"\n",
            capture_output=True,
            timeout=60,
            check=False,
        )
        if req.returncode != 0:
            raise RuntimeError("openssl_req_failed")

        fingerprint = require_fingerprint_sha256(cert_der_sha256_hex(cert_path))
        if wrong_password:
            alt = bytearray(b"definitely-wrong-password-0001")
            blob = dpapi_protect_current_user(bytes(alt))
            zero_bytearray(alt)
        else:
            blob = dpapi_protect_current_user(bytes(password))
        if tamper_dpapi:
            mutable = bytearray(blob)
            mutable[-1] ^= 0x5A
            blob = bytes(mutable)
        blob_path.write_bytes(blob)
        verify_path_dacl_exact(key_path)
        verify_path_dacl_exact(cert_path)
        verify_path_dacl_exact(blob_path)

        manifest_fp = (
            require_fingerprint_sha256(wrong_manifest_fingerprint)
            if wrong_manifest_fingerprint is not None
            else fingerprint
        )
        manifest = IdentityManifest(
            schema_version=1,
            hub_id=hub_id,
            cert_fingerprint_sha256=manifest_fp,
            cert_filename=cert_name,
            encrypted_key_filename=key_name,
            dpapi_blob_filename=blob_name,
            tls_storage_kind="dpapi_encrypted_pkcs8",
        )
        write_identity_manifest(identity_root / IDENTITY_MANIFEST_NAME, manifest)
        verify_path_dacl_exact(identity_root / IDENTITY_MANIFEST_NAME)
        return manifest, fingerprint
    finally:
        zero_bytearray(password)
