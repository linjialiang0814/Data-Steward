"""ULID, Human32, digest, and capability helpers for pairing storage."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from typing import Any

from .pairing_errors import PairingValidationError

DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
ULID_RE = re.compile(r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$")
# 22-char unpadded base64url (16 raw bytes)
CLIENT_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{22}$")
CAPABILITY_TOKEN_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,63}$")
CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
HUMAN32_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
PROTOCOL_VERSION = "pairing_auth/1"
TLS_STORAGE_KIND_DPAPI = "dpapi_encrypted_pkcs8"
ALLOWED_TLS_STORAGE_KINDS = frozenset({TLS_STORAGE_KIND_DPAPI})
MAX_CAPABILITIES = 32
MAX_CAPABILITY_ITEM_LEN = 64
# Secondary defense: count/item caps already keep max legal JSON under 4096 UTF-8 bytes.
MAX_CAPABILITY_JSON = 4_096
MAX_DISPLAY_NAME = 64
MAX_PLATFORM = 32
SHORT_CODE_MISMATCH_LIMIT = 5


def require_digest(field: str, value: object) -> str:
    if not isinstance(value, str) or not DIGEST_RE.fullmatch(value):
        raise PairingValidationError(f"{field}_invalid")
    return value


def require_ulid(field: str, value: object) -> str:
    if not isinstance(value, str) or not ULID_RE.fullmatch(value):
        raise PairingValidationError(f"{field}_invalid")
    return value


def require_client_nonce(value: object) -> str:
    if not isinstance(value, str) or not CLIENT_NONCE_RE.fullmatch(value):
        raise PairingValidationError("client_nonce_invalid")
    return value


def _reject_control_chars(field: str, value: str) -> str:
    if any(ord(ch) < 32 for ch in value):
        raise PairingValidationError(f"{field}_invalid")
    return value


def require_optional_display_name(value: object | None) -> str | None:
    """Protocol optional display_name: None means absent (SQL NULL)."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise PairingValidationError("display_name_invalid")
    if value != value.strip() or not value or len(value) > MAX_DISPLAY_NAME:
        raise PairingValidationError("display_name_invalid")
    return _reject_control_chars("display_name", value)


def require_platform(value: object) -> str:
    if not isinstance(value, str):
        raise PairingValidationError("platform_invalid")
    if value != value.strip() or not value or len(value) > MAX_PLATFORM:
        raise PairingValidationError("platform_invalid")
    return _reject_control_chars("platform", value)


def utc_now_iso(clock: Callable[[], datetime] | None = None) -> str:
    moment = clock() if clock is not None else datetime.now(timezone.utc)
    if moment.tzinfo is None:
        raise PairingValidationError("clock_must_be_timezone_aware_utc")
    as_utc = moment.astimezone(timezone.utc)
    return as_utc.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_utc_iso(value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise PairingValidationError("timestamp_invalid")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def generate_ulid(
    *,
    clock: Callable[[], datetime] | None = None,
    randbytes: Callable[[int], bytes] | None = None,
) -> str:
    """48-bit ms timestamp + 80-bit CSPRNG as Crockford Base32 ULID."""
    moment = clock() if clock is not None else datetime.now(timezone.utc)
    if moment.tzinfo is None:
        raise PairingValidationError("clock_must_be_timezone_aware_utc")
    ms = int(moment.astimezone(timezone.utc).timestamp() * 1000)
    if ms < 0 or ms >= (1 << 48):
        raise PairingValidationError("ulid_timestamp_out_of_range")
    entropy = (randbytes or secrets.token_bytes)(10)
    if len(entropy) != 10:
        raise PairingValidationError("ulid_entropy_invalid")
    value = (ms << 80) | int.from_bytes(entropy, "big")
    chars: list[str] = []
    for shift in range(125, -1, -5):
        chars.append(CROCKFORD_ALPHABET[(value >> shift) & 31])
    text = "".join(chars)
    require_ulid("ulid", text)
    return text


def encode_human32_from_digest_prefix(first5: bytes) -> str:
    if len(first5) != 5:
        raise PairingValidationError("human32_input_invalid")
    n = int.from_bytes(first5, "big")
    return "".join(
        HUMAN32_ALPHABET[(n >> (35 - 5 * i)) & 31] for i in range(8)
    )


def build_pairing_transcript(
    *,
    hub_id: str,
    cert_fingerprint: str,
    pairing_session_id: str,
    pairing_attempt_id: str,
    ott_digest: str,
    device_credential_digest: str,
    claim_secret_digest: str,
    client_nonce: str,
    requested_capabilities_digest: str,
) -> bytes:
    lines = [
        f"protocol_version={PROTOCOL_VERSION}",
        f"hub_id={hub_id}",
        f"cert_fingerprint={cert_fingerprint}",
        f"pairing_session_id={pairing_session_id}",
        f"pairing_attempt_id={pairing_attempt_id}",
        f"ott_digest={ott_digest}",
        f"device_credential_digest={device_credential_digest}",
        f"claim_secret_digest={claim_secret_digest}",
        f"client_nonce={client_nonce}",
        f"requested_capabilities_digest={requested_capabilities_digest}",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def compute_short_verification_code(
    *,
    hub_id: str,
    cert_fingerprint: str,
    pairing_session_id: str,
    pairing_attempt_id: str,
    ott_digest: str,
    device_credential_digest: str,
    claim_secret_digest: str,
    client_nonce: str,
    requested_capabilities_digest: str,
) -> str:
    transcript = build_pairing_transcript(
        hub_id=hub_id,
        cert_fingerprint=cert_fingerprint,
        pairing_session_id=pairing_session_id,
        pairing_attempt_id=pairing_attempt_id,
        ott_digest=ott_digest,
        device_credential_digest=device_credential_digest,
        claim_secret_digest=claim_secret_digest,
        client_nonce=client_nonce,
        requested_capabilities_digest=requested_capabilities_digest,
    )
    digest = hashlib.sha256(transcript).digest()
    return encode_human32_from_digest_prefix(digest[:5])


def canonicalize_capabilities(capabilities: Sequence[str]) -> tuple[list[str], str, str]:
    """Strict canonicalization: reject blanks/dupes/unsorted; no silent repair."""
    if not isinstance(capabilities, (list, tuple)):
        raise PairingValidationError("capabilities_invalid")
    if len(capabilities) == 0 or len(capabilities) > MAX_CAPABILITIES:
        raise PairingValidationError("capabilities_count_invalid")
    if any(not isinstance(item, str) for item in capabilities):
        raise PairingValidationError("capabilities_invalid")
    for item in capabilities:
        if item != item.strip() or not item:
            raise PairingValidationError("capabilities_blank")
        if len(item) > MAX_CAPABILITY_ITEM_LEN:
            raise PairingValidationError("capabilities_item_too_long")
        if not CAPABILITY_TOKEN_RE.fullmatch(item):
            raise PairingValidationError("capabilities_token_invalid")
    if len(set(capabilities)) != len(capabilities):
        raise PairingValidationError("capabilities_duplicate")
    ordered = sorted(capabilities)
    if list(capabilities) != ordered:
        raise PairingValidationError("capabilities_unsorted")
    payload = json.dumps(ordered, ensure_ascii=False, separators=(",", ":"))
    if len(payload.encode("utf-8")) > MAX_CAPABILITY_JSON:
        raise PairingValidationError("capabilities_json_too_large")
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return ordered, payload, digest


def stable_json(data: dict[str, Any]) -> str:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def sha256_hex_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hello_payload_hash(
    *,
    pairing_session_id: str,
    pairing_attempt_id: str,
    claim_secret_digest: str,
    device_credential_digest: str,
    client_nonce: str,
    requested_capabilities_json: str,
    requested_capabilities_digest: str,
    display_name: str | None,
    platform: str,
) -> str:
    """Hash of client hello inputs only (device_id is Hub-issued, excluded).

    Absent display_name is encoded as JSON null (not a fabricated string).
    """
    return sha256_hex_bytes(
        stable_json(
            {
                "claim_secret_digest": claim_secret_digest,
                "client_nonce": client_nonce,
                "device_credential_digest": device_credential_digest,
                "display_name": display_name,
                "pairing_attempt_id": pairing_attempt_id,
                "pairing_session_id": pairing_session_id,
                "platform": platform,
                "requested_capabilities_digest": requested_capabilities_digest,
                "requested_capabilities_json": requested_capabilities_json,
            }
        ).encode("utf-8")
    )


def max_capabilities_json_utf8_len() -> int:
    """UTF-8 byte length of the largest legal capability JSON under current caps."""
    items = [f"c{i:02d}{'x' * (MAX_CAPABILITY_ITEM_LEN - 3)}" for i in range(MAX_CAPABILITIES)]
    # Ensure tokens remain valid: c00xxx... length 64
    payload = json.dumps(sorted(items), ensure_ascii=False, separators=(",", ":"))
    return len(payload.encode("utf-8"))
