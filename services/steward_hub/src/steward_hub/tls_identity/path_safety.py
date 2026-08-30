"""Path containment, reparse rejection, and filename allow-lists."""

from __future__ import annotations

import ctypes
import platform
import re
from pathlib import Path

from .errors import TlsPathSafetyError

FILE_ATTRIBUTE_REPARSE_POINT = 0x400
ALLOWED_ENCRYPTED_KEY_NAMES = frozenset(
    {"private_key.encrypted.pem", "tls_key.enc.pem"}
)
ALLOWED_CERT_NAMES = frozenset({"cert.pem", "tls_cert.pem"})
ALLOWED_DPAPI_NAMES = frozenset({"key_password.dpapi", "tls_key_password.dpapi"})
PLAINTEXT_KEY_NAME_PATTERN = re.compile(
    r"(^|[/\\])(key|private[_-]?key|privkey)(\.pem|\.key)?$",
    re.IGNORECASE,
)

_KERNEL32 = (
    ctypes.WinDLL("kernel32", use_last_error=True)
    if platform.system() == "Windows"
    else None
)
if _KERNEL32 is not None:
    _KERNEL32.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
    _KERNEL32.GetFileAttributesW.restype = ctypes.c_uint32


def is_reparse_point(path: Path) -> bool:
    if path.is_symlink():
        return True
    if platform.system() != "Windows" or _KERNEL32 is None:
        return False
    attrs = _KERNEL32.GetFileAttributesW(str(path))
    if attrs == 0xFFFFFFFF:
        return False
    return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)


def assert_relative_filename(name: str, *, allowed: frozenset[str]) -> str:
    if not name or Path(name).name != name or "/" in name or "\\" in name:
        raise TlsPathSafetyError("filename_not_relative")
    if ".." in name:
        raise TlsPathSafetyError("filename_traversal")
    if PLAINTEXT_KEY_NAME_PATTERN.search(name) and name not in allowed:
        raise TlsPathSafetyError("plaintext_key_name_forbidden")
    if name not in allowed:
        raise TlsPathSafetyError("filename_not_allowed")
    return name


def assert_path_inside_root(path: Path, identity_root: Path) -> Path:
    """Resolve path and require it stays under identity_root; ban reparse points."""
    try:
        root = identity_root.resolve(strict=True)
    except OSError as exc:
        raise TlsPathSafetyError("identity_root_unresolvable") from exc
    if is_reparse_point(root):
        raise TlsPathSafetyError("identity_root_reparse")
    try:
        resolved = path.resolve(strict=False)
    except OSError as exc:
        raise TlsPathSafetyError("path_unresolvable") from exc
    if resolved.is_absolute() and path != resolved and str(path).startswith(("\\\\", "//")):
        raise TlsPathSafetyError("unc_path_forbidden")
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise TlsPathSafetyError("path_outside_identity_root") from exc
    if is_reparse_point(resolved) or (
        resolved.parent != root and is_reparse_point(resolved.parent)
    ):
        # Ban reparse on the target if it exists, and on root (already checked).
        if resolved.exists() and is_reparse_point(resolved):
            raise TlsPathSafetyError("path_reparse")
    if resolved.exists() and is_reparse_point(resolved):
        raise TlsPathSafetyError("path_reparse")
    return resolved


def reject_absolute_or_parent_ref(raw: str) -> None:
    if not raw:
        raise TlsPathSafetyError("empty_path")
    if Path(raw).is_absolute() or raw.startswith(("/", "\\")):
        raise TlsPathSafetyError("absolute_path_forbidden")
    parts = Path(raw).parts
    if ".." in parts:
        raise TlsPathSafetyError("parent_ref_forbidden")
