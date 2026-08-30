"""Validated metadata-only Catalog Sync V1 projections."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import asdict, dataclass
from typing import Any

CATALOG_SYNC_SCHEMA = "data-steward.catalog-sync/v1"
CATALOG_SNAPSHOT_SCHEMA = "data-steward.catalog-snapshot/v1"
MAX_CATALOG_ITEMS = 512
MAX_DISPLAY_NAME_BYTES = 255
MAX_ROOT_LABEL_CHARS = 80

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_ROOT_ID_RE = re.compile(r"^(?:[0-9a-f]{64}|pc-[0-9a-f]{12})$")
_LOCATOR_RE = _DIGEST_RE
_EXTENSION_RE = re.compile(r"^[a-z0-9]{0,16}$")
_PROVIDER_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")
_IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")
_MIME_FAMILIES = frozenset(
    {"image", "audio", "video", "text", "document", "archive", "other"}
)
_PLATFORMS = frozenset({"android", "windows"})
_UNSAFE_CODEPOINTS = frozenset(
    {
        0x200B,
        0x200C,
        0x200D,
        0x200E,
        0x200F,
        0x2028,
        0x2029,
        0x202A,
        0x202B,
        0x202C,
        0x202D,
        0x202E,
        0x2066,
        0x2067,
        0x2068,
        0x2069,
        0xFEFF,
    }
)


class CatalogValidationError(ValueError):
    """Stable validation error without source metadata."""


@dataclass(frozen=True, slots=True)
class CatalogItemInput:
    locator_token: str
    display_name: str
    extension: str
    mime_family: str
    size_bytes: int | None
    modified_at_ms: int | None
    revision: str
    content_eligible: bool

    def wire(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class CatalogSnapshotBatch:
    idempotency_key: str
    catalog_root_id: str
    platform: str
    provider: str
    display_name: str
    base_seq: int
    snapshot_sha256: str
    generated_at_ms: int
    item_count: int
    skipped_count: int
    complete_snapshot: bool
    items: tuple[CatalogItemInput, ...]

    def request_sha256(self) -> str:
        payload = {
            "schema_version": CATALOG_SYNC_SCHEMA,
            "idempotency_key": self.idempotency_key,
            "catalog_root_id": self.catalog_root_id,
            "platform": self.platform,
            "provider": self.provider,
            "display_name": self.display_name,
            "base_seq": self.base_seq,
            "snapshot_sha256": self.snapshot_sha256,
            "generated_at_ms": self.generated_at_ms,
            "item_count": self.item_count,
            "skipped_count": self.skipped_count,
            "complete_snapshot": self.complete_snapshot,
            "items": [item.wire() for item in self.items],
        }
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class CatalogSyncResult:
    device_id: str
    catalog_root_id: str
    accepted_seq: int
    snapshot_sha256: str
    item_count: int
    tombstone_count: int
    changed: bool
    deduplicated: bool
    projection_sha256: str


@dataclass(frozen=True, slots=True)
class CatalogRootView:
    device_id: str
    catalog_root_id: str
    platform: str
    provider: str
    display_name: str
    catalog_seq: int
    snapshot_sha256: str
    item_count: int
    skipped_count: int
    last_synced_at: str


@dataclass(frozen=True, slots=True)
class CatalogAssetView:
    asset_id: str
    device_id: str
    catalog_root_id: str
    platform: str
    source_display_name: str
    locator_token: str
    display_name: str
    extension: str
    mime_family: str
    size_bytes: int | None
    modified_at_ms: int | None
    observed_at: str
    revision: str
    content_eligible: bool
    catalog_seq: int
    deleted_at: str | None


def catalog_item_from_mapping(value: Any) -> CatalogItemInput:
    if not isinstance(value, dict) or set(value) != {
        "locator_token",
        "display_name",
        "extension",
        "mime_family",
        "size_bytes",
        "modified_at_ms",
        "revision",
        "content_eligible",
    }:
        raise CatalogValidationError("catalog_item_invalid")
    name = _safe_display_name(value["display_name"], MAX_DISPLAY_NAME_BYTES)
    locator = _require_string(value["locator_token"])
    extension = _require_string(value["extension"])
    family = _require_string(value["mime_family"])
    revision = _require_string(value["revision"])
    eligible = value["content_eligible"]
    if (
        _LOCATOR_RE.fullmatch(locator) is None
        or _EXTENSION_RE.fullmatch(extension) is None
        or family not in _MIME_FAMILIES
        or _DIGEST_RE.fullmatch(revision) is None
        or not isinstance(eligible, bool)
    ):
        raise CatalogValidationError("catalog_item_invalid")
    return CatalogItemInput(
        locator_token=locator,
        display_name=name,
        extension=extension,
        mime_family=family,
        size_bytes=_optional_non_negative_int(value["size_bytes"]),
        modified_at_ms=_optional_non_negative_int(value["modified_at_ms"]),
        revision=revision,
        content_eligible=eligible,
    )


def catalog_batch_from_mapping(value: Any) -> CatalogSnapshotBatch:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "idempotency_key",
        "catalog_root_id",
        "platform",
        "provider",
        "display_name",
        "base_seq",
        "snapshot_sha256",
        "generated_at_ms",
        "item_count",
        "skipped_count",
        "complete_snapshot",
        "items",
    }:
        raise CatalogValidationError("catalog_request_invalid")
    if value["schema_version"] != CATALOG_SYNC_SCHEMA:
        raise CatalogValidationError("catalog_schema_invalid")
    idempotency_key = _require_string(value["idempotency_key"])
    root_id = _require_string(value["catalog_root_id"])
    platform = _require_string(value["platform"])
    provider = _require_string(value["provider"])
    root_label = _safe_display_name(value["display_name"], MAX_ROOT_LABEL_CHARS * 4)
    snapshot_hash = _require_string(value["snapshot_sha256"])
    raw_items = value["items"]
    if (
        _IDEMPOTENCY_RE.fullmatch(idempotency_key) is None
        or _ROOT_ID_RE.fullmatch(root_id) is None
        or platform not in _PLATFORMS
        or _PROVIDER_RE.fullmatch(provider) is None
        or _DIGEST_RE.fullmatch(snapshot_hash) is None
        or len(root_label) > MAX_ROOT_LABEL_CHARS
        or value["complete_snapshot"] is not True
        or not isinstance(raw_items, list)
        or len(raw_items) > MAX_CATALOG_ITEMS
    ):
        raise CatalogValidationError("catalog_request_invalid")
    items = tuple(catalog_item_from_mapping(item) for item in raw_items)
    if len({item.locator_token for item in items}) != len(items):
        raise CatalogValidationError("catalog_duplicate_item")
    if tuple(sorted(items, key=lambda item: item.locator_token)) != items:
        raise CatalogValidationError("catalog_order_invalid")
    base_seq = _non_negative_int(value["base_seq"])
    generated = _non_negative_int(value["generated_at_ms"])
    item_count = _non_negative_int(value["item_count"])
    skipped_count = _non_negative_int(value["skipped_count"])
    if item_count != len(items) or item_count + skipped_count > MAX_CATALOG_ITEMS:
        raise CatalogValidationError("catalog_count_invalid")
    expected = catalog_snapshot_sha256(root_id, items, skipped_count)
    if expected != snapshot_hash:
        raise CatalogValidationError("catalog_snapshot_hash_invalid")
    return CatalogSnapshotBatch(
        idempotency_key=idempotency_key,
        catalog_root_id=root_id,
        platform=platform,
        provider=provider,
        display_name=root_label,
        base_seq=base_seq,
        snapshot_sha256=snapshot_hash,
        generated_at_ms=generated,
        item_count=item_count,
        skipped_count=skipped_count,
        complete_snapshot=True,
        items=items,
    )


def catalog_snapshot_sha256(
    root_id: str,
    items: tuple[CatalogItemInput, ...] | list[CatalogItemInput],
    skipped_count: int,
) -> str:
    projection = [_canonical_fields(CATALOG_SNAPSHOT_SCHEMA, root_id)]
    for item in items:
        projection.append(
            _canonical_fields(
                item.locator_token,
                item.display_name,
                item.extension,
                item.mime_family,
                "null" if item.size_bytes is None else str(item.size_bytes),
                "null" if item.modified_at_ms is None else str(item.modified_at_ms),
                item.revision,
                "true" if item.content_eligible else "false",
            )
        )
    projection.append(_canonical_fields("skipped", str(skipped_count)))
    return hashlib.sha256("".join(projection).encode("utf-8")).hexdigest()


def catalog_projection_sha256(rows: list[dict[str, Any]]) -> str:
    raw = json.dumps(
        rows,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def stable_asset_id(device_id: str, root_id: str, locator_token: str) -> str:
    raw = f"{device_id}\0{root_id}\0{locator_token}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _canonical_fields(*fields: str) -> str:
    return "".join(f"{len(field.encode('utf-8'))}:{field}" for field in fields) + "\n"


def _safe_display_name(value: Any, max_bytes: int) -> str:
    text = unicodedata.normalize("NFC", _require_string(value))
    if (
        not text.strip()
        or text in {".", ".."}
        or len(text.encode("utf-8")) > max_bytes
        or "/" in text
        or "\\" in text
        or any(ord(char) in _UNSAFE_CODEPOINTS for char in text)
        or any(unicodedata.category(char) in {"Cc", "Cs"} for char in text)
    ):
        raise CatalogValidationError("catalog_name_invalid")
    return text


def _require_string(value: Any) -> str:
    if not isinstance(value, str):
        raise CatalogValidationError("catalog_type_invalid")
    return value


def _non_negative_int(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value >= 2**63:
        raise CatalogValidationError("catalog_integer_invalid")
    return value


def _optional_non_negative_int(value: Any) -> int | None:
    if value is None:
        return None
    return _non_negative_int(value)
