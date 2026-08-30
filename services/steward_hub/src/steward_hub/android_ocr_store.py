"""Revision-bound encrypted projections produced by Android on-device OCR."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .catalog_models import CatalogAssetView, stable_asset_id
from .catalog_store import CatalogStore
from .tls_identity.dpapi import dpapi_protect_current_user, dpapi_unprotect_current_user

ANDROID_OCR_SYNC_SCHEMA = "data-steward.android-ocr-sync/v1"
ANDROID_OCR_SCHEMA_VERSION = 1
MAX_ITEMS = 6
MAX_ITEM_CHARS = 4_000
MAX_BATCH_CHARS = 20_000
MAX_SEALED_BYTES = 128 * 1024
RETENTION_DAYS = 7
MIN_CONTEXT_CONFIDENCE = 0.55

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_ROOT_RE = re.compile(r"^[0-9a-f]{64}$")
_IDEMPOTENCY_RE = re.compile(r"^ocr-[0-9]{1,24}-[0-9a-f]{12}$")
_LANGUAGE_RE = re.compile(r"^(?:und|[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*)$")


class AndroidOcrStoreError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class AndroidOcrItem:
    locator_token: str
    revision: str
    format: str
    status: str
    text: str
    text_sha256: str
    char_count: int
    truncated: bool
    confidence: float | None
    language_hints: tuple[str, ...]
    extractor_id: str
    extractor_version: str


@dataclass(frozen=True, slots=True)
class AndroidOcrBatch:
    idempotency_key: str
    catalog_root_id: str
    snapshot_sha256: str
    generated_at_ms: int
    items: tuple[AndroidOcrItem, ...]


@dataclass(frozen=True, slots=True)
class AndroidOcrReceipt:
    schema_version: str
    device_id: str
    catalog_root_id: str
    accepted_count: int
    recognized_count: int
    no_text_count: int
    low_confidence_count: int
    deduplicated: bool
    projection_sha256: str


def android_ocr_batch_from_mapping(value: Any) -> AndroidOcrBatch:
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version", "idempotency_key", "catalog_root_id",
        "snapshot_sha256", "generated_at_ms", "items",
    } or value["schema_version"] != ANDROID_OCR_SYNC_SCHEMA:
        raise AndroidOcrStoreError("ocr_request_invalid")
    key = value["idempotency_key"]
    root_id = value["catalog_root_id"]
    snapshot = value["snapshot_sha256"]
    generated = value["generated_at_ms"]
    raw_items = value["items"]
    if (
        not isinstance(key, str) or _IDEMPOTENCY_RE.fullmatch(key) is None
        or not isinstance(root_id, str) or _ROOT_RE.fullmatch(root_id) is None
        or not isinstance(snapshot, str) or _DIGEST_RE.fullmatch(snapshot) is None
        or isinstance(generated, bool) or not isinstance(generated, int) or generated < 0
        or not isinstance(raw_items, list) or not 1 <= len(raw_items) <= MAX_ITEMS
    ):
        raise AndroidOcrStoreError("ocr_request_invalid")
    items = tuple(_item_from_mapping(item) for item in raw_items)
    if len({item.locator_token for item in items}) != len(items):
        raise AndroidOcrStoreError("ocr_request_invalid")
    if tuple(sorted(items, key=lambda item: item.locator_token)) != items:
        raise AndroidOcrStoreError("ocr_request_invalid")
    if sum(item.char_count for item in items) > MAX_BATCH_CHARS:
        raise AndroidOcrStoreError("ocr_request_invalid")
    return AndroidOcrBatch(key, root_id, snapshot, generated, items)


def _item_from_mapping(value: Any) -> AndroidOcrItem:
    expected = {
        "locator_token", "revision", "format", "status", "text", "text_sha256",
        "char_count", "truncated", "confidence", "language_hints", "extractor_id",
        "extractor_version",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise AndroidOcrStoreError("ocr_request_invalid")
    locator = value["locator_token"]
    revision = value["revision"]
    text = value["text"]
    text_sha = value["text_sha256"]
    char_count = value["char_count"]
    confidence = value["confidence"]
    hints = value["language_hints"]
    if (
        not isinstance(locator, str) or _DIGEST_RE.fullmatch(locator) is None
        or not isinstance(revision, str) or _DIGEST_RE.fullmatch(revision) is None
        or not isinstance(value["format"], str)
        or value["format"] not in {"jpg", "jpeg", "png"}
        or not isinstance(value["status"], str)
        or value["status"] not in {"recognized", "no_text"}
        or not isinstance(text, str)
        or isinstance(char_count, bool) or not isinstance(char_count, int)
        or not 0 <= char_count <= MAX_ITEM_CHARS or len(text) != char_count
        or (value["status"] == "recognized") != bool(text)
        or not isinstance(text_sha, str) or _DIGEST_RE.fullmatch(text_sha) is None
        or hashlib.sha256(text.encode("utf-8")).hexdigest() != text_sha
        or not isinstance(value["truncated"], bool)
        or (confidence is not None and (
            isinstance(confidence, bool) or not isinstance(confidence, (int, float))
            or not 0 <= float(confidence) <= 1
        ))
        or not isinstance(hints, list) or len(hints) > 8
        or any(not isinstance(item, str) or _LANGUAGE_RE.fullmatch(item) is None for item in hints)
        or hints != sorted(set(hints))
        or value["extractor_id"] != "mlkit-chinese-bundled"
        or value["extractor_version"] != "16.0.1"
        or any(ord(char) < 32 and char not in {"\n", "\t"} for char in text)
    ):
        raise AndroidOcrStoreError("ocr_request_invalid")
    return AndroidOcrItem(
        locator_token=locator,
        revision=revision,
        format=str(value["format"]),
        status=str(value["status"]),
        text=text,
        text_sha256=text_sha,
        char_count=char_count,
        truncated=value["truncated"],
        confidence=None if confidence is None else float(confidence),
        language_hints=tuple(hints),
        extractor_id="mlkit-chinese-bundled",
        extractor_version="16.0.1",
    )


class AndroidOcrStore:
    def __init__(
        self,
        database_path: str | Path,
        *,
        catalog: CatalogStore,
        protect: Callable[[bytes], bytes] = dpapi_protect_current_user,
        unprotect: Callable[[bytes], bytearray] = dpapi_unprotect_current_user,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._closed = False
        self._catalog = catalog
        self._protect = protect
        self._unprotect = unprotect
        self._now = now or (lambda: datetime.now(UTC))
        try:
            self._connection = sqlite3.connect(
                str(database_path), isolation_level=None, check_same_thread=False,
                timeout=5.0,
            )
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA busy_timeout = 5000")
            self._connection.execute("PRAGMA secure_delete = ON")
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._initialize_schema()
        except AndroidOcrStoreError:
            connection = getattr(self, "_connection", None)
            if connection is not None:
                connection.close()
            raise
        except Exception as exc:  # noqa: BLE001
            connection = getattr(self, "_connection", None)
            if connection is not None:
                connection.close()
            raise AndroidOcrStoreError("ocr_persistence_unavailable") from exc

    def _initialize_schema(self) -> None:
        tables = {
            str(row[0]) for row in self._connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'android_ocr_%'"
            )
        }
        if "android_ocr_schema_meta" in tables:
            rows = list(self._connection.execute(
                "SELECT component,schema_version FROM android_ocr_schema_meta"
            ))
            if len(rows) != 1 or tuple(rows[0]) != ("android_ocr", ANDROID_OCR_SCHEMA_VERSION):
                raise AndroidOcrStoreError("ocr_schema_unsupported")
        elif tables:
            raise AndroidOcrStoreError("ocr_schema_unsupported")
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS android_ocr_schema_meta(
              component TEXT PRIMARY KEY, schema_version INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS android_ocr_projection(
              asset_id TEXT NOT NULL CHECK(length(asset_id)=64 AND asset_id NOT GLOB '*[^0-9a-f]*'),
              device_id TEXT NOT NULL CHECK(length(device_id)=26),
              catalog_root_id TEXT NOT NULL,
              revision TEXT NOT NULL CHECK(length(revision)=64 AND revision NOT GLOB '*[^0-9a-f]*'),
              format TEXT NOT NULL CHECK(format IN ('jpg','jpeg','png')),
              status TEXT NOT NULL CHECK(status IN ('recognized','no_text')),
              text_sha256 TEXT NOT NULL CHECK(length(text_sha256)=64 AND text_sha256 NOT GLOB '*[^0-9a-f]*'),
              char_count INTEGER NOT NULL CHECK(char_count BETWEEN 0 AND 4000),
              usable_for_context INTEGER NOT NULL CHECK(usable_for_context IN (0,1)),
              encrypted_projection BLOB NOT NULL,
              created_at TEXT NOT NULL,
              expires_at TEXT NOT NULL,
              PRIMARY KEY(asset_id,revision)
            );
            CREATE INDEX IF NOT EXISTS android_ocr_root_idx
              ON android_ocr_projection(device_id,catalog_root_id,expires_at);
            CREATE TABLE IF NOT EXISTS android_ocr_request(
              device_id TEXT NOT NULL CHECK(length(device_id)=26),
              idempotency_key TEXT NOT NULL,
              request_sha256 TEXT NOT NULL CHECK(length(request_sha256)=64),
              receipt_json TEXT NOT NULL,
              created_at TEXT NOT NULL,
              PRIMARY KEY(device_id,idempotency_key)
            );
            """
        )
        if not tables:
            self._connection.execute(
                "INSERT INTO android_ocr_schema_meta(component,schema_version) VALUES(?,?)",
                ("android_ocr", ANDROID_OCR_SCHEMA_VERSION),
            )

    def apply(self, *, device_id: str, batch: AndroidOcrBatch) -> AndroidOcrReceipt:
        request_json = json.dumps(asdict(batch), ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        request_sha = hashlib.sha256(request_json.encode("utf-8")).hexdigest()
        with self._lock:
            self._ensure_open()
            prior = self._connection.execute(
                "SELECT request_sha256,receipt_json FROM android_ocr_request WHERE device_id=? AND idempotency_key=?",
                (device_id, batch.idempotency_key),
            ).fetchone()
            if prior is not None:
                return _deduplicated_receipt(prior, request_sha)
        roots, assets, _ = self._catalog.current_view()
        roots_for_device = [
            root for root in roots
            if root.device_id == device_id and root.catalog_root_id == batch.catalog_root_id
        ]
        if len(roots_for_device) != 1 or roots_for_device[0].platform != "android":
            raise AndroidOcrStoreError("ocr_catalog_binding_invalid")
        if roots_for_device[0].snapshot_sha256 != batch.snapshot_sha256:
            raise AndroidOcrStoreError("ocr_snapshot_stale")
        current = {
            item.locator_token: item for item in assets
            if item.device_id == device_id and item.catalog_root_id == batch.catalog_root_id
        }
        sealed_items: list[tuple[AndroidOcrItem, str, bytes]] = []
        now = self._now()
        created_at = _utc(now)
        expires_at = _utc(now + timedelta(days=RETENTION_DAYS))
        for item in batch.items:
            asset = current.get(item.locator_token)
            if (
                asset is None or asset.revision != item.revision
                or asset.extension != item.format or asset.mime_family != "image"
            ):
                raise AndroidOcrStoreError("ocr_revision_changed")
            asset_id = stable_asset_id(device_id, batch.catalog_root_id, item.locator_token)
            raw = json.dumps(
                {"schema": ANDROID_OCR_SYNC_SCHEMA, "item": asdict(item)},
                ensure_ascii=False, separators=(",", ":"), sort_keys=True,
            ).encode("utf-8")
            try:
                sealed = self._protect(raw)
            except Exception:
                raise AndroidOcrStoreError("ocr_projection_unavailable") from None
            if not isinstance(sealed, bytes) or not sealed or len(sealed) > MAX_SEALED_BYTES:
                raise AndroidOcrStoreError("ocr_projection_unavailable")
            sealed_items.append((item, asset_id, sealed))
        projection_hash = hashlib.sha256(
            "\n".join(
                json.dumps(
                    {
                        "asset_id": asset_id,
                        "revision": item.revision,
                        "status": item.status,
                        "text_sha256": item.text_sha256,
                        "truncated": item.truncated,
                        "confidence": item.confidence,
                        "language_hints": item.language_hints,
                        "extractor_id": item.extractor_id,
                        "extractor_version": item.extractor_version,
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                )
                for item, asset_id, _ in sealed_items
            ).encode("utf-8")
        ).hexdigest()
        receipt = AndroidOcrReceipt(
            schema_version=ANDROID_OCR_SYNC_SCHEMA,
            device_id=device_id,
            catalog_root_id=batch.catalog_root_id,
            accepted_count=len(batch.items),
            recognized_count=sum(item.status == "recognized" for item in batch.items),
            no_text_count=sum(item.status == "no_text" for item in batch.items),
            low_confidence_count=sum(
                item.status == "recognized"
                and item.confidence is not None
                and item.confidence < MIN_CONTEXT_CONFIDENCE
                for item in batch.items
            ),
            deduplicated=False,
            projection_sha256=projection_hash,
        )
        with self._lock:
            self._ensure_open()
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                prior = self._connection.execute(
                    "SELECT request_sha256,receipt_json FROM android_ocr_request WHERE device_id=? AND idempotency_key=?",
                    (device_id, batch.idempotency_key),
                ).fetchone()
                if prior is not None:
                    self._connection.execute("ROLLBACK")
                    return _deduplicated_receipt(prior, request_sha)
                self._connection.execute(
                    "DELETE FROM android_ocr_projection WHERE device_id=? AND catalog_root_id=? AND expires_at<=?",
                    (device_id, batch.catalog_root_id, created_at),
                )
                for item, asset_id, sealed in sealed_items:
                    self._connection.execute(
                        "DELETE FROM android_ocr_projection WHERE asset_id=? AND revision<>?",
                        (asset_id, item.revision),
                    )
                    self._connection.execute(
                        """INSERT INTO android_ocr_projection(
                          asset_id,device_id,catalog_root_id,revision,format,status,text_sha256,
                          char_count,usable_for_context,encrypted_projection,created_at,expires_at
                        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                        ON CONFLICT(asset_id,revision) DO UPDATE SET
                          format=excluded.format,status=excluded.status,text_sha256=excluded.text_sha256,
                          char_count=excluded.char_count,usable_for_context=excluded.usable_for_context,
                          encrypted_projection=excluded.encrypted_projection,
                          created_at=excluded.created_at,expires_at=excluded.expires_at""",
                        (asset_id, device_id, batch.catalog_root_id, item.revision, item.format,
                         item.status, item.text_sha256, item.char_count,
                         int(item.status == "recognized" and (
                             item.confidence is None or item.confidence >= MIN_CONTEXT_CONFIDENCE
                         )), sealed, created_at, expires_at),
                    )
                receipt_json = json.dumps(asdict(receipt), separators=(",", ":"), sort_keys=True)
                self._connection.execute(
                    "INSERT INTO android_ocr_request(device_id,idempotency_key,request_sha256,receipt_json,created_at) VALUES(?,?,?,?,?)",
                    (device_id, batch.idempotency_key, request_sha, receipt_json, created_at),
                )
                self._connection.execute("COMMIT")
                return receipt
            except AndroidOcrStoreError:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise
            except Exception as exc:  # noqa: BLE001
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise AndroidOcrStoreError("ocr_persistence_unavailable") from exc

    def forget_root(self, *, device_id: str, root_id: str) -> int:
        if _ROOT_RE.fullmatch(root_id) is None:
            raise AndroidOcrStoreError("ocr_request_invalid")
        with self._lock:
            self._ensure_open()
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                cursor = self._connection.execute(
                    "DELETE FROM android_ocr_projection WHERE device_id=? AND catalog_root_id=?",
                    (device_id, root_id),
                )
                self._connection.execute("DELETE FROM android_ocr_request WHERE device_id=?", (device_id,))
                self._connection.execute("COMMIT")
                return int(cursor.rowcount)
            except sqlite3.Error:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise AndroidOcrStoreError("ocr_persistence_unavailable") from None

    def list_projected_assets(self) -> tuple[CatalogAssetView, ...]:
        roots, assets, _ = self._catalog.current_view()
        del roots
        by_binding = {
            (asset.asset_id, asset.device_id, asset.catalog_root_id, asset.revision): asset
            for asset in assets
            if asset.platform == "android" and asset.mime_family == "image"
        }
        with self._lock:
            self._ensure_open()
            now = _utc(self._now())
            try:
                self._connection.execute(
                    "DELETE FROM android_ocr_projection WHERE expires_at<=?", (now,)
                )
                rows = self._connection.execute(
                    """SELECT asset_id,device_id,catalog_root_id,revision
                       FROM android_ocr_projection
                       WHERE status='recognized' AND usable_for_context=1
                         AND char_count>0 AND expires_at>?
                       ORDER BY asset_id""",
                    (now,),
                ).fetchall()
            except sqlite3.Error:
                raise AndroidOcrStoreError("ocr_persistence_unavailable") from None
        return tuple(
            by_binding[key]
            for row in rows
            if (key := (
                str(row["asset_id"]), str(row["device_id"]),
                str(row["catalog_root_id"]), str(row["revision"]),
            )) in by_binding
        )

    def load_text(
        self,
        *,
        asset_id: str,
        device_id: str,
        root_id: str,
        revision: str,
    ) -> AndroidOcrItem | None:
        with self._lock:
            self._ensure_open()
            row = self._connection.execute(
                """SELECT encrypted_projection FROM android_ocr_projection
                   WHERE asset_id=? AND device_id=? AND catalog_root_id=? AND revision=?
                     AND status='recognized' AND usable_for_context=1 AND expires_at>?""",
                (asset_id, device_id, root_id, revision, _utc(self._now())),
            ).fetchone()
        if row is None:
            return None
        plaintext: bytearray | None = None
        try:
            plaintext = self._unprotect(bytes(row[0]))
            if not isinstance(plaintext, bytearray) or not plaintext:
                raise ValueError("plaintext_invalid")
            value = json.loads(
                bytes(plaintext).decode("utf-8"),
                object_pairs_hook=_reject_duplicate_pairs,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
            )
            if not isinstance(value, dict) or set(value) != {"schema", "item"} or value["schema"] != ANDROID_OCR_SYNC_SCHEMA:
                raise ValueError("projection_invalid")
            item = _item_from_mapping(value["item"])
            if stable_asset_id(device_id, root_id, item.locator_token) != asset_id or item.revision != revision:
                raise ValueError("projection_binding_invalid")
            return item
        except Exception:
            raise AndroidOcrStoreError("ocr_projection_integrity_error") from None
        finally:
            if plaintext is not None:
                for index in range(len(plaintext)):
                    plaintext[index] = 0
                plaintext.clear()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._connection.close()

    def _ensure_open(self) -> None:
        if self._closed:
            raise AndroidOcrStoreError("ocr_store_closed")


def _utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _reject_duplicate_pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise ValueError("duplicate_key")
        result[key] = value
    return result


def _deduplicated_receipt(row: sqlite3.Row, request_sha: str) -> AndroidOcrReceipt:
    if str(row["request_sha256"]) != request_sha:
        raise AndroidOcrStoreError("ocr_idempotency_conflict")
    try:
        value = json.loads(str(row["receipt_json"]), object_pairs_hook=_reject_duplicate_pairs)
        if not isinstance(value, dict):
            raise ValueError("receipt_invalid")
        value["deduplicated"] = True
        receipt = AndroidOcrReceipt(**value)
        if (
            receipt.schema_version != ANDROID_OCR_SYNC_SCHEMA
            or _DIGEST_RE.fullmatch(receipt.projection_sha256) is None
            or receipt.accepted_count != receipt.recognized_count + receipt.no_text_count
            or not 0 <= receipt.low_confidence_count <= receipt.recognized_count
        ):
            raise ValueError("receipt_invalid")
        return receipt
    except (TypeError, ValueError, json.JSONDecodeError):
        raise AndroidOcrStoreError("ocr_projection_integrity_error") from None
