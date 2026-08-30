"""DPAPI-sealed recovery journal for reversible direct-child organization."""

from __future__ import annotations

import json
import os
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .tls_identity.dacl import (
    apply_and_verify_identity_dacl,
    verify_identity_root_dacl,
    verify_path_dacl_exact,
)
from .tls_identity.dpapi import dpapi_protect_current_user, dpapi_unprotect_current_user
from .tls_identity.path_safety import is_reparse_point
from .tls_identity.permanent_paths import (
    permanent_hub_parent,
    preflight_permanent_identity_parents,
)


MAX_JOURNAL_BYTES = 512 * 1024
JOURNAL_FILE_NAME = "journal.dpapi"
_ID_RE = re.compile(r"^org-[0-9a-f]{16}$")
_ROOT_RE = re.compile(r"^pc-[0-9a-f]{12}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


class OrganizerJournalError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class OrganizerMove:
    source_name: str
    category: str


@dataclass(frozen=True, slots=True)
class OrganizerJournal:
    journal_id: str
    root_id: str
    evidence_sha256: str
    state: str
    moves: tuple[OrganizerMove, ...]


class OrganizerJournalStore:
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
        self._path = Path(record_path)
        if not self._path.is_absolute() or self._path.name != JOURNAL_FILE_NAME:
            raise OrganizerJournalError("organizer_journal_path_invalid")
        self._protect = protect
        self._unprotect = unprotect
        self._apply_root_security = apply_root_security
        self._verify_root_security = verify_root_security
        self._verify_file_security = verify_file_security

    def load(self) -> OrganizerJournal | None:
        if not self._path.exists():
            return None
        try:
            self._assert_safe(self._path)
            if not 0 < self._path.stat().st_size <= MAX_JOURNAL_BYTES:
                raise OrganizerJournalError("organizer_journal_invalid")
            plaintext = self._unprotect(self._path.read_bytes())
            try:
                value = _strict_json(bytes(plaintext))
            finally:
                for index in range(len(plaintext)):
                    plaintext[index] = 0
                plaintext.clear()
            return _decode(value)
        except OrganizerJournalError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise OrganizerJournalError("organizer_journal_unavailable") from exc

    def save(self, journal: OrganizerJournal) -> None:
        raw = json.dumps(
            _encode(journal),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        sealed = self._protect(raw)
        if not sealed or len(sealed) > MAX_JOURNAL_BYTES:
            raise OrganizerJournalError("organizer_journal_invalid")
        root = self._path.parent
        temp = root / f".{JOURNAL_FILE_NAME}.{secrets.token_hex(8)}.tmp"
        try:
            preflight_permanent_identity_parents(root)
            root.mkdir(parents=True, exist_ok=True)
            if is_reparse_point(root) or not root.is_dir():
                raise OrganizerJournalError("organizer_journal_unsafe")
            self._apply_root_security(root)
            with temp.open("xb") as handle:
                handle.write(sealed)
                handle.flush()
                os.fsync(handle.fileno())
            self._verify_file_security(temp)
            if self._path.exists():
                self._assert_safe(self._path)
            os.replace(temp, self._path)
            self._assert_safe(self._path)
        except OrganizerJournalError:
            _remove_temp(temp)
            raise
        except Exception as exc:  # noqa: BLE001
            _remove_temp(temp)
            raise OrganizerJournalError("organizer_journal_unavailable") from exc

    def clear(self) -> None:
        if not self._path.exists():
            return
        try:
            self._assert_safe(self._path)
            self._path.unlink()
        except OrganizerJournalError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise OrganizerJournalError("organizer_journal_unavailable") from exc

    def _assert_safe(self, path: Path) -> None:
        if path.name != JOURNAL_FILE_NAME:
            raise OrganizerJournalError("organizer_journal_path_invalid")
        if is_reparse_point(path.parent) or is_reparse_point(path) or not path.is_file():
            raise OrganizerJournalError("organizer_journal_unsafe")
        self._verify_root_security(path.parent)
        self._verify_file_security(path)


def permanent_organizer_journal_store() -> OrganizerJournalStore:
    return OrganizerJournalStore(
        permanent_hub_parent() / "organizer-v1" / JOURNAL_FILE_NAME
    )


def _encode(journal: OrganizerJournal) -> dict[str, object]:
    if (
        not _ID_RE.fullmatch(journal.journal_id)
        or not _ROOT_RE.fullmatch(journal.root_id)
        or not _DIGEST_RE.fullmatch(journal.evidence_sha256)
        or journal.state not in {"prepared", "completed"}
        or not 1 <= len(journal.moves) <= 2_000
    ):
        raise OrganizerJournalError("organizer_journal_invalid")
    moves = []
    for move in journal.moves:
        if (
            not move.source_name
            or len(move.source_name) > 255
            or Path(move.source_name).name != move.source_name
            or any(ord(char) < 32 for char in move.source_name)
            or move.category not in {"images", "documents", "media", "archives", "other"}
        ):
            raise OrganizerJournalError("organizer_journal_invalid")
        moves.append({"category": move.category, "source_name": move.source_name})
    return {
        "evidence_sha256": journal.evidence_sha256,
        "journal_id": journal.journal_id,
        "moves": moves,
        "root_id": journal.root_id,
        "schema_version": 1,
        "state": journal.state,
    }


def _decode(value: dict[str, object]) -> OrganizerJournal:
    if set(value) != {
        "evidence_sha256",
        "journal_id",
        "moves",
        "root_id",
        "schema_version",
        "state",
    } or value.get("schema_version") != 1 or not isinstance(value.get("moves"), list):
        raise OrganizerJournalError("organizer_journal_invalid")
    moves: list[OrganizerMove] = []
    for raw in value["moves"]:  # type: ignore[index]
        if not isinstance(raw, dict) or set(raw) != {"category", "source_name"}:
            raise OrganizerJournalError("organizer_journal_invalid")
        moves.append(
            OrganizerMove(
                source_name=raw.get("source_name") if isinstance(raw.get("source_name"), str) else "",
                category=raw.get("category") if isinstance(raw.get("category"), str) else "",
            )
        )
    journal = OrganizerJournal(
        journal_id=value.get("journal_id") if isinstance(value.get("journal_id"), str) else "",
        root_id=value.get("root_id") if isinstance(value.get("root_id"), str) else "",
        evidence_sha256=value.get("evidence_sha256") if isinstance(value.get("evidence_sha256"), str) else "",
        state=value.get("state") if isinstance(value.get("state"), str) else "",
        moves=tuple(moves),
    )
    _encode(journal)
    return journal


def _strict_json(raw: bytes) -> dict[str, object]:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")),
        )
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise OrganizerJournalError("organizer_journal_invalid") from exc
    if not isinstance(value, dict):
        raise OrganizerJournalError("organizer_journal_invalid")
    return value


def _remove_temp(path: Path) -> None:
    try:
        if path.exists() and path.is_file() and not is_reparse_point(path):
            path.unlink()
    except OSError:
        pass
