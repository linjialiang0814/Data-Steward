"""Strict TLS identity manifest schema."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import TlsManifestError
from .path_safety import (
    ALLOWED_CERT_NAMES,
    ALLOWED_DPAPI_NAMES,
    ALLOWED_ENCRYPTED_KEY_NAMES,
    assert_relative_filename,
    reject_absolute_or_parent_ref,
)

IDENTITY_MANIFEST_NAME = "identity.json"
SCHEMA_VERSION = 1
TLS_STORAGE_KIND = "dpapi_encrypted_pkcs8"
MAX_MANIFEST_BYTES = 16 * 1024
_ULID_RE = re.compile(r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$")
_FP_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class IdentityManifest:
    schema_version: int
    hub_id: str
    cert_fingerprint_sha256: str
    cert_filename: str
    encrypted_key_filename: str
    dpapi_blob_filename: str
    tls_storage_kind: str

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "hub_id": self.hub_id,
            "cert_fingerprint_sha256": self.cert_fingerprint_sha256,
            "cert_filename": self.cert_filename,
            "encrypted_key_filename": self.encrypted_key_filename,
            "dpapi_blob_filename": self.dpapi_blob_filename,
            "tls_storage_kind": self.tls_storage_kind,
        }


def require_fingerprint_sha256(value: object) -> str:
    """Auth-path fingerprint: exact lowercase 64-hex, no formatting allowed."""
    if not isinstance(value, str) or not _FP_RE.fullmatch(value):
        raise TlsManifestError("fingerprint_invalid")
    return value


def format_fingerprint_display(value: str) -> str:
    """UI-only formatter; never use on authentication input paths."""
    fp = require_fingerprint_sha256(value)
    return ":".join(fp[i : i + 2] for i in range(0, 64, 2))


# Back-compat alias: now strict (no strip/lower/colon loosening).
normalize_fingerprint = require_fingerprint_sha256


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TlsManifestError("manifest_duplicate_key")
        result[key] = value
    return result


def _reject_parse_constant(name: str) -> None:
    raise TlsManifestError("manifest_non_finite_number")


def parse_identity_manifest(data: dict[str, Any]) -> IdentityManifest:
    if not isinstance(data, dict):
        raise TlsManifestError("manifest_not_object")
    allowed = {
        "schema_version",
        "hub_id",
        "cert_fingerprint_sha256",
        "cert_filename",
        "encrypted_key_filename",
        "dpapi_blob_filename",
        "tls_storage_kind",
    }
    unknown = set(data) - allowed
    if unknown:
        raise TlsManifestError("manifest_unknown_field")
    if "schema_version" not in data:
        raise TlsManifestError("schema_version_invalid")
    version = data["schema_version"]
    if type(version) is not int or version != SCHEMA_VERSION:
        raise TlsManifestError("schema_version_invalid")
    hub_id = data.get("hub_id")
    if not isinstance(hub_id, str) or not _ULID_RE.fullmatch(hub_id):
        raise TlsManifestError("hub_id_invalid")
    fingerprint = require_fingerprint_sha256(data.get("cert_fingerprint_sha256"))
    storage = data.get("tls_storage_kind")
    if storage != TLS_STORAGE_KIND:
        raise TlsManifestError("tls_storage_kind_invalid")
    for key in (
        "cert_filename",
        "encrypted_key_filename",
        "dpapi_blob_filename",
    ):
        raw = data.get(key)
        if not isinstance(raw, str):
            raise TlsManifestError("filename_invalid")
        reject_absolute_or_parent_ref(raw)
    cert_name = assert_relative_filename(
        str(data["cert_filename"]), allowed=ALLOWED_CERT_NAMES
    )
    key_name = assert_relative_filename(
        str(data["encrypted_key_filename"]), allowed=ALLOWED_ENCRYPTED_KEY_NAMES
    )
    blob_name = assert_relative_filename(
        str(data["dpapi_blob_filename"]), allowed=ALLOWED_DPAPI_NAMES
    )
    return IdentityManifest(
        schema_version=version,
        hub_id=hub_id,
        cert_fingerprint_sha256=fingerprint,
        cert_filename=cert_name,
        encrypted_key_filename=key_name,
        dpapi_blob_filename=blob_name,
        tls_storage_kind=TLS_STORAGE_KIND,
    )


def load_identity_manifest(path: Path) -> IdentityManifest:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise TlsManifestError("manifest_unreadable") from exc
    if size > MAX_MANIFEST_BYTES:
        raise TlsManifestError("manifest_too_large")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise TlsManifestError("manifest_unreadable") from exc
    if len(raw) > MAX_MANIFEST_BYTES:
        raise TlsManifestError("manifest_too_large")
    try:
        text = raw.decode("utf-8")
        data = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_parse_constant,
        )
    except TlsManifestError:
        raise
    except (UnicodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
        raise TlsManifestError("manifest_unreadable") from exc
    if not isinstance(data, dict):
        raise TlsManifestError("manifest_not_object")
    return parse_identity_manifest(data)


def write_identity_manifest(path: Path, manifest: IdentityManifest) -> None:
    path.write_text(
        json.dumps(manifest.to_public_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
