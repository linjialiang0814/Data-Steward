"""Locked permanent LocalAppData identity paths (Known Folder API).

This module does NOT create directories or files. Permanent creation requires
explicit human approval in a later task (B2B-B2).

Product resolution uses SHGetKnownFolderPath(FOLDERID_LocalAppData) only.
It does not read LOCALAPPDATA, usernames, the registry, or LocalMachine.
"""

from __future__ import annotations

import ctypes
import platform
from collections.abc import Callable
from ctypes import wintypes
from pathlib import Path

from .errors import TlsPermanentPathError
from .path_safety import is_reparse_point

PRODUCT_DIR_NAME = "DataSteward"
HUB_DIR_NAME = "hub"
IDENTITY_DIR_NAME = "tls-identity-v1"

STEADY_STATE_FILES = (
    "cert.pem",
    "private_key.encrypted.pem",
    "key_password.dpapi",
    "identity.json",
)

# FOLDERID_LocalAppData = {F1B32785-6FBA-4FCF-9D55-7B8E7F157091}
_FOLDERID_LOCAL_APP_DATA = (
    0xF1B32785,
    0x6FBA,
    0x4FCF,
    0x9D,
    0x55,
    0x7B,
    0x8E,
    0x7F,
    0x15,
    0x70,
    0x91,
)

# Test-only override for temporary path verification. Product default is None.
_LocalAppDataResolver: Callable[[], Path] | None = None


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", wintypes.BYTE * 8),
    ]


def set_local_app_data_resolver_for_tests(
    resolver: Callable[[], Path] | None,
) -> None:
    """Inject Local AppData root for tests only. Product code must leave None."""
    global _LocalAppDataResolver
    _LocalAppDataResolver = resolver


def _folderid_local_app_data() -> _GUID:
    d1, d2, d3, *d4 = _FOLDERID_LOCAL_APP_DATA
    return _GUID(d1, d2, d3, (wintypes.BYTE * 8)(*d4))


def _known_folder_local_app_data() -> Path:
    """Resolve current-user Local AppData via Known Folder API (fail-closed)."""
    if platform.system() != "Windows":
        raise TlsPermanentPathError("known_folder_unsupported_platform")

    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    ole32 = ctypes.WinDLL("ole32", use_last_error=True)

    sh_get = shell32.SHGetKnownFolderPath
    sh_get.argtypes = [
        ctypes.POINTER(_GUID),
        wintypes.DWORD,
        wintypes.HANDLE,
        ctypes.POINTER(ctypes.c_wchar_p),
    ]
    sh_get.restype = ctypes.HRESULT

    co_free = ole32.CoTaskMemFree
    co_free.argtypes = [wintypes.LPVOID]
    co_free.restype = None

    path_ptr = ctypes.c_wchar_p()
    folder_id = _folderid_local_app_data()
    try:
        hr = int(
            sh_get(
                ctypes.byref(folder_id),
                0,
                None,
                ctypes.byref(path_ptr),
            )
        )
    except OSError as exc:
        raise TlsPermanentPathError("known_folder_api_failed") from exc

    try:
        if hr != 0 or not path_ptr.value:
            raise TlsPermanentPathError("known_folder_api_failed")
        raw = path_ptr.value
    finally:
        # Exact release of the SHGetKnownFolderPath buffer.
        if path_ptr:
            co_free(path_ptr)

    try:
        resolved = Path(raw)
    except (TypeError, ValueError) as exc:
        raise TlsPermanentPathError("known_folder_path_invalid") from exc
    if not resolved.is_absolute():
        raise TlsPermanentPathError("known_folder_not_absolute")
    if resolved.as_posix().startswith("//") or str(resolved).startswith("\\\\"):
        raise TlsPermanentPathError("known_folder_unc_forbidden")
    return resolved


def local_app_data_root() -> Path:
    """
    Current-user Local AppData root.

    Product default: SHGetKnownFolderPath(FOLDERID_LocalAppData).
    Does not consult LOCALAPPDATA or other environment variables.
    """
    if _LocalAppDataResolver is not None:
        try:
            root = Path(_LocalAppDataResolver())
        except TlsPermanentPathError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise TlsPermanentPathError("known_folder_resolver_failed") from exc
        if not root.is_absolute():
            raise TlsPermanentPathError("known_folder_not_absolute")
        return root
    return _known_folder_local_app_data()


# Backward-compatible alias used by earlier B1 helpers/docs.
def localappdata_root() -> Path:
    return local_app_data_root()


def permanent_product_base() -> Path:
    """<KnownFolder LocalAppData>\\DataSteward (absolute; not created here)."""
    return local_app_data_root() / PRODUCT_DIR_NAME


def permanent_hub_parent() -> Path:
    """<KnownFolder LocalAppData>\\DataSteward\\hub (absolute; not created here)."""
    return permanent_product_base() / HUB_DIR_NAME


def permanent_identity_root() -> Path:
    """
    <KnownFolder LocalAppData>\\DataSteward\\hub\\tls-identity-v1

    Absolute path only. Does not create the directory.
    """
    root = permanent_hub_parent() / IDENTITY_DIR_NAME
    if not root.is_absolute():
        raise TlsPermanentPathError("permanent_identity_not_absolute")
    return root


def permanent_steady_state_paths() -> tuple[Path, ...]:
    root = permanent_identity_root()
    return tuple(root / name for name in STEADY_STATE_FILES)


def preflight_permanent_identity_parents(
    identity_root: Path | None = None,
) -> Path:
    """
    Read-only B2B-B2-oriented preflight: reject reparse on existing ancestors.

    Does not create directories or delete anything. Callers must not treat a
    passing check as authorization to create permanent resources.
    """
    root = Path(identity_root) if identity_root is not None else permanent_identity_root()
    if not root.is_absolute():
        raise TlsPermanentPathError("permanent_identity_not_absolute")
    current: Path | None = root
    while current is not None:
        if current.exists() and is_reparse_point(current):
            raise TlsPermanentPathError("permanent_parent_reparse")
        parent = current.parent
        if parent == current:
            break
        current = parent
    return root
