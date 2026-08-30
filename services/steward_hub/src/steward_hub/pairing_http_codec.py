"""Raw pairing secret boundary: base64url decode + SHA-256 digests only."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re

from .pairing_codec import PROTOCOL_VERSION

SECRET_B64URL_LEN = 43
SECRET_RAW_LEN = 32
NONCE_B64URL_LEN = 22
NONCE_RAW_LEN = 16
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_PAIRING_AUTH_RE = re.compile(r"^Pairing[ \t]+([A-Za-z0-9_-]+)$")


class PairingHttpCodecError(Exception):
    """HTTP-layer codec failure with stable error_code (no secret material)."""

    def __init__(self, error_code: str) -> None:
        self.error_code = error_code
        super().__init__(error_code)


def require_protocol_version(value: object) -> str:
    if not isinstance(value, str) or value != PROTOCOL_VERSION:
        raise PairingHttpCodecError("protocol_version_rejected")
    return value


def digest_raw_secret(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def decode_unpadded_base64url(value: object, *, expected_raw_len: int) -> bytes:
    """Strict unpadded base64url → raw bytes; rejects padding and non-canonical forms."""
    if not isinstance(value, str):
        raise PairingHttpCodecError("pairing_validation_error")
    expected_b64 = {32: SECRET_B64URL_LEN, 16: NONCE_B64URL_LEN}.get(expected_raw_len)
    if expected_b64 is None or len(value) != expected_b64:
        raise PairingHttpCodecError("pairing_validation_error")
    if "=" in value or not _B64URL_RE.fullmatch(value):
        raise PairingHttpCodecError("pairing_validation_error")
    pad = (-len(value)) % 4
    try:
        raw = base64.b64decode(
            (value + ("=" * pad)).encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error):
        raise PairingHttpCodecError("pairing_validation_error") from None
    if len(raw) != expected_raw_len:
        raise PairingHttpCodecError("pairing_validation_error")
    canonical = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    if canonical != value:
        raise PairingHttpCodecError("pairing_validation_error")
    return raw


def digest_secret_b64url(value: object) -> str:
    raw = decode_unpadded_base64url(value, expected_raw_len=SECRET_RAW_LEN)
    digest = digest_raw_secret(raw)
    del raw
    return digest


def parse_pairing_authorization(header_value: str | None) -> str:
    """
    Parse Authorization: Pairing <43-char-claim-secret-base64url>.

    Returns claim_secret_digest. Never includes raw secret in exceptions.
    """
    if header_value is None or not str(header_value).strip():
        raise PairingHttpCodecError("claim_missing")
    text = str(header_value).strip()
    match = _PAIRING_AUTH_RE.fullmatch(text)
    if match is None:
        raise PairingHttpCodecError("claim_missing")
    token = match.group(1)
    try:
        return digest_secret_b64url(token)
    except PairingHttpCodecError:
        raise PairingHttpCodecError("claim_invalid") from None
