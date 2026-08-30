"""CurrentUser-scope DPAPI protect/unprotect for key passwords."""

from __future__ import annotations

import ctypes
import platform
from ctypes import wintypes

from .errors import TlsDpapiError

CRYPTPROTECT_UI_FORBIDDEN = 0x1

_KERNEL32 = (
    ctypes.WinDLL("kernel32", use_last_error=True)
    if platform.system() == "Windows"
    else None
)
_CRYPT32 = (
    ctypes.WinDLL("crypt32", use_last_error=True)
    if platform.system() == "Windows"
    else None
)


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_char)),
    ]


def _setup() -> None:
    if platform.system() != "Windows" or _CRYPT32 is None or _KERNEL32 is None:
        return
    _CRYPT32.CryptProtectData.argtypes = [
        ctypes.POINTER(DATA_BLOB),
        wintypes.LPCWSTR,
        ctypes.POINTER(DATA_BLOB),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(DATA_BLOB),
    ]
    _CRYPT32.CryptProtectData.restype = wintypes.BOOL
    _CRYPT32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(DATA_BLOB),
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(DATA_BLOB),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(DATA_BLOB),
    ]
    _CRYPT32.CryptUnprotectData.restype = wintypes.BOOL
    _KERNEL32.LocalFree.argtypes = [ctypes.c_void_p]
    _KERNEL32.LocalFree.restype = ctypes.c_void_p


_setup()


def _blob_from_bytes(data: bytes) -> tuple[DATA_BLOB, ctypes.Array[ctypes.c_char]]:
    buf = ctypes.create_string_buffer(data, len(data))
    blob = DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    return blob, buf


def dpapi_protect_current_user(plaintext: bytes) -> bytes:
    if platform.system() != "Windows" or _CRYPT32 is None or _KERNEL32 is None:
        raise TlsDpapiError("dpapi_requires_windows")
    in_blob, in_buf = _blob_from_bytes(plaintext)
    out_blob = DATA_BLOB()
    ok = _CRYPT32.CryptProtectData(
        ctypes.byref(in_blob),
        None,
        None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    )
    ctypes.memset(in_buf, 0, len(plaintext))
    if not ok:
        raise TlsDpapiError("dpapi_protect_failed")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        _KERNEL32.LocalFree(out_blob.pbData)


def dpapi_unprotect_current_user(blob: bytes) -> bytearray:
    if platform.system() != "Windows" or _CRYPT32 is None or _KERNEL32 is None:
        raise TlsDpapiError("dpapi_requires_windows")
    in_blob, in_buf = _blob_from_bytes(blob)
    out_blob = DATA_BLOB()
    ok = _CRYPT32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    )
    ctypes.memset(in_buf, 0, len(blob))
    if not ok:
        raise TlsDpapiError("dpapi_unprotect_failed")
    try:
        raw = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        return bytearray(raw)
    finally:
        if out_blob.pbData:
            ctypes.memset(out_blob.pbData, 0, out_blob.cbData)
            _KERNEL32.LocalFree(out_blob.pbData)
