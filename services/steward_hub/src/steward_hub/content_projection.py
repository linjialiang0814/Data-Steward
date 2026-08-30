"""Encrypted, revision-bound local content projections."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

CONTENT_PROJECTION_SCHEMA = "data-steward.content-projection/v2"
MAX_PROJECTION_CHARS = 20_000
MAX_PROJECTION_BLOB_BYTES = 256 * 1024
SUPPORTED_PROJECTION_FORMATS = frozenset({"txt", "md", "docx", "pptx", "pdf"})

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_ROOT_ID_RE = re.compile(r"^(?:[0-9a-f]{64}|pc-[0-9a-f]{12})$")
_DEVICE_ID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")


class ContentProjectionError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ContentProjection:
    asset_id: str
    device_id: str
    catalog_root_id: str
    revision: str
    format: str
    source_label: str
    text: str
    text_sha256: str
    char_count: int
    truncated: bool
    unit_count: int
    created_at: str
    expires_at: str


def seal_content_projection(
    projection: ContentProjection, *, protect: Callable[[bytes], bytes]
) -> bytes:
    _validate_projection(projection)
    raw = json.dumps(
        {
            "schema": CONTENT_PROJECTION_SCHEMA,
            "projection": asdict(projection),
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(raw) > MAX_PROJECTION_BLOB_BYTES:
        raise ContentProjectionError("content_projection_invalid")
    try:
        sealed = protect(raw)
    except Exception:
        raise ContentProjectionError("content_projection_unavailable") from None
    if not isinstance(sealed, bytes) or not sealed or len(sealed) > MAX_PROJECTION_BLOB_BYTES:
        raise ContentProjectionError("content_projection_unavailable")
    return sealed


def open_content_projection(
    blob: bytes,
    *,
    unprotect: Callable[[bytes], bytearray],
    expected_asset_id: str,
    expected_device_id: str,
    expected_root_id: str,
    expected_revision: str,
) -> ContentProjection:
    if not isinstance(blob, bytes) or not blob or len(blob) > MAX_PROJECTION_BLOB_BYTES:
        raise ContentProjectionError("content_projection_integrity_error")
    plaintext: bytearray | None = None
    try:
        plaintext = unprotect(blob)
        if not isinstance(plaintext, bytearray) or not plaintext:
            raise ValueError("plaintext_invalid")
        value = json.loads(
            bytes(plaintext).decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
        if (
            not isinstance(value, dict)
            or set(value) != {"schema", "projection"}
            or value["schema"] != CONTENT_PROJECTION_SCHEMA
            or not isinstance(value["projection"], dict)
        ):
            raise ValueError("envelope_invalid")
        projection = ContentProjection(**value["projection"])
        _validate_projection(projection)
        if (
            projection.asset_id != expected_asset_id
            or projection.device_id != expected_device_id
            or projection.catalog_root_id != expected_root_id
            or projection.revision != expected_revision
        ):
            raise ValueError("binding_invalid")
        return projection
    except ContentProjectionError:
        raise
    except Exception:
        raise ContentProjectionError("content_projection_integrity_error") from None
    finally:
        if plaintext is not None:
            for index in range(len(plaintext)):
                plaintext[index] = 0
            plaintext.clear()


def _validate_projection(value: ContentProjection) -> None:
    if (
        _DIGEST_RE.fullmatch(value.asset_id) is None
        or _DEVICE_ID_RE.fullmatch(value.device_id) is None
        or _ROOT_ID_RE.fullmatch(value.catalog_root_id) is None
        or _DIGEST_RE.fullmatch(value.revision) is None
        or value.format not in SUPPORTED_PROJECTION_FORMATS
        or not _safe_label(value.source_label)
        or not isinstance(value.text, str)
        or not value.text
        or len(value.text) > MAX_PROJECTION_CHARS
        or value.char_count != len(value.text)
        or _DIGEST_RE.fullmatch(value.text_sha256) is None
        or hashlib.sha256(value.text.encode("utf-8")).hexdigest() != value.text_sha256
        or not isinstance(value.truncated, bool)
        or isinstance(value.unit_count, bool)
        or not isinstance(value.unit_count, int)
        or not 1 <= value.unit_count <= 2_000
    ):
        raise ContentProjectionError("content_projection_invalid")
    created = _parse_utc(value.created_at)
    expires = _parse_utc(value.expires_at)
    if expires <= created:
        raise ContentProjectionError("content_projection_invalid")


def _safe_label(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and len(value) <= 255
        and "/" not in value
        and "\\" not in value
        and not any(ord(char) < 32 for char in value)
    )


def _parse_utc(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ContentProjectionError("content_projection_invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise ContentProjectionError("content_projection_invalid") from None
    if parsed.tzinfo != UTC:
        raise ContentProjectionError("content_projection_invalid")
    return parsed


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_key")
        result[key] = value
    return result
