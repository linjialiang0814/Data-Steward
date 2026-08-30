"""CurrentUser-protected persistence for one default PC file scope."""

from __future__ import annotations

import json
import os
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .tls_identity.dacl import (
    apply_and_verify_identity_dacl,
    verify_identity_root_dacl,
    verify_path_dacl_exact,
)
from .tls_identity.dpapi import (
    dpapi_protect_current_user,
    dpapi_unprotect_current_user,
)
from .tls_identity.path_safety import is_reparse_point
from .tls_identity.permanent_paths import (
    permanent_hub_parent,
    preflight_permanent_identity_parents,
)

FILE_SCOPE_SCHEMA_VERSION = 1
FILE_SCOPE_DIR_NAME = "file-scope-v1"
FILE_SCOPE_RECORD_NAME = "authorization.dpapi"
MAX_RECORD_BYTES = 16 * 1024
_ROOT_ID_RE = re.compile(r"^pc-[0-9a-f]{12}$")


class PcFileScopePersistenceError(RuntimeError):
    """Stable persistence failure which never contains a local path."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class PersistedPcFileScope:
    root_id: str
    canonical_path: str
    authorized_at: str
    path_identity: str


class PcFileScopePersistence:
    """Atomic DPAPI record with injectable hermetic test boundaries."""

    def __init__(
        self,
        record_path: Path,
        *,
        protect: Callable[[bytes], bytes] = dpapi_protect_current_user,
        unprotect: Callable[[bytes], bytearray] = dpapi_unprotect_current_user,
        apply_root_security: Callable[[Path], object] = apply_and_verify_identity_dacl,
        verify_root_security: Callable[[Path], None] = verify_identity_root_dacl,
        verify_file_security: Callable[[Path], None] = verify_path_dacl_exact,
    ) -> None:
        path = Path(record_path)
        if not path.is_absolute() or path.name != FILE_SCOPE_RECORD_NAME:
            raise PcFileScopePersistenceError("file_scope_store_path_invalid")
        self._record_path = path
        self._protect = protect
        self._unprotect = unprotect
        self._apply_root_security = apply_root_security
        self._verify_root_security = verify_root_security
        self._verify_file_security = verify_file_security

    @property
    def record_path(self) -> Path:
        return self._record_path

    def load(self) -> PersistedPcFileScope | None:
        path = self._record_path
        if not path.exists():
            return None
        try:
            self._assert_safe_record(path)
            size = path.stat().st_size
            if size <= 0 or size > MAX_RECORD_BYTES:
                raise PcFileScopePersistenceError("file_scope_store_invalid")
            plaintext = self._unprotect(path.read_bytes())
            try:
                value = _strict_record_json(bytes(plaintext))
            finally:
                for index in range(len(plaintext)):
                    plaintext[index] = 0
                plaintext.clear()
            return _record_from_json(value)
        except PcFileScopePersistenceError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise PcFileScopePersistenceError("file_scope_store_unavailable") from exc

    def save(self, record: PersistedPcFileScope) -> None:
        raw = json.dumps(
            _record_to_json(record),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        if len(raw) > MAX_RECORD_BYTES:
            raise PcFileScopePersistenceError("file_scope_store_invalid")
        sealed = self._protect(raw)
        if not sealed or len(sealed) > MAX_RECORD_BYTES:
            raise PcFileScopePersistenceError("file_scope_store_invalid")
        root = self._record_path.parent
        temp = root / f".{FILE_SCOPE_RECORD_NAME}.{secrets.token_hex(8)}.tmp"
        try:
            self._prepare_root(root)
            with temp.open("xb") as handle:
                handle.write(sealed)
                handle.flush()
                os.fsync(handle.fileno())
            self._verify_file_security(temp)
            if self._record_path.exists():
                self._assert_safe_record(self._record_path)
            os.replace(temp, self._record_path)
            self._assert_safe_record(self._record_path)
        except PcFileScopePersistenceError:
            _unlink_exact_temp(temp)
            raise
        except Exception as exc:  # noqa: BLE001
            _unlink_exact_temp(temp)
            raise PcFileScopePersistenceError("file_scope_store_unavailable") from exc

    def clear(self) -> None:
        path = self._record_path
        if not path.exists():
            return
        try:
            self._assert_safe_record(path)
            path.unlink()
        except PcFileScopePersistenceError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise PcFileScopePersistenceError("file_scope_store_unavailable") from exc

    def _prepare_root(self, root: Path) -> None:
        preflight_permanent_identity_parents(root)
        root.mkdir(parents=True, exist_ok=True)
        if is_reparse_point(root) or not root.is_dir():
            raise PcFileScopePersistenceError("file_scope_store_unsafe")
        self._apply_root_security(root)

    def _assert_safe_record(self, path: Path) -> None:
        if path.name != FILE_SCOPE_RECORD_NAME:
            raise PcFileScopePersistenceError("file_scope_store_path_invalid")
        root = path.parent
        if is_reparse_point(root) or is_reparse_point(path) or not path.is_file():
            raise PcFileScopePersistenceError("file_scope_store_unsafe")
        self._verify_root_security(root)
        self._verify_file_security(path)


def permanent_pc_file_scope_persistence() -> PcFileScopePersistence:
    root = permanent_hub_parent() / FILE_SCOPE_DIR_NAME
    return PcFileScopePersistence(root / FILE_SCOPE_RECORD_NAME)


def _record_to_json(record: PersistedPcFileScope) -> dict[str, object]:
    if (
        not _ROOT_ID_RE.fullmatch(record.root_id)
        or not record.canonical_path
        or len(record.canonical_path) > 1_024
        or any(ord(char) < 32 for char in record.canonical_path)
        or not _valid_utc_timestamp(record.authorized_at)
        or not re.fullmatch(r"[0-9a-f]{64}", record.path_identity)
    ):
        raise PcFileScopePersistenceError("file_scope_store_invalid")
    return {
        "authorized_at": record.authorized_at,
        "canonical_path": record.canonical_path,
        "path_identity": record.path_identity,
        "restore_enabled": True,
        "root_id": record.root_id,
        "schema_version": FILE_SCOPE_SCHEMA_VERSION,
    }


def _strict_record_json(raw: bytes) -> dict[str, object]:
    def reject_constant(_: str) -> None:
        raise ValueError("non_finite")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_key")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise PcFileScopePersistenceError("file_scope_store_invalid") from exc
    if not isinstance(value, dict):
        raise PcFileScopePersistenceError("file_scope_store_invalid")
    return value


def _record_from_json(value: dict[str, object]) -> PersistedPcFileScope:
    if set(value) != {
        "authorized_at",
        "canonical_path",
        "path_identity",
        "restore_enabled",
        "root_id",
        "schema_version",
    } or value.get("schema_version") != FILE_SCOPE_SCHEMA_VERSION or value.get(
        "restore_enabled"
    ) is not True:
        raise PcFileScopePersistenceError("file_scope_store_invalid")
    record = PersistedPcFileScope(
        root_id=value.get("root_id") if isinstance(value.get("root_id"), str) else "",
        canonical_path=(
            value.get("canonical_path")
            if isinstance(value.get("canonical_path"), str)
            else ""
        ),
        authorized_at=(
            value.get("authorized_at")
            if isinstance(value.get("authorized_at"), str)
            else ""
        ),
        path_identity=(
            value.get("path_identity")
            if isinstance(value.get("path_identity"), str)
            else ""
        ),
    )
    _record_to_json(record)
    return record


def _unlink_exact_temp(path: Path) -> None:
    try:
        if path.exists() and path.is_file() and not is_reparse_point(path):
            path.unlink()
    except OSError:
        pass


def _valid_utc_timestamp(value: str) -> bool:
    if not value.endswith("Z") or len(value) > 40:
        return False
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        return False
    return parsed.utcoffset() is not None and parsed.utcoffset().total_seconds() == 0
