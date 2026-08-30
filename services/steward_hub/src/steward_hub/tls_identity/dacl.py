"""Exact CurrentUser / SYSTEM / Administrators DACL apply and verify."""

from __future__ import annotations

import ctypes
import os
import platform
import subprocess
from ctypes import wintypes
from pathlib import Path
from typing import Any

from .errors import AclBlockedError

SID_SYSTEM = "S-1-5-18"
SID_ADMINS = "S-1-5-32-544"
SID_EVERYONE = "S-1-1-0"
SID_BUILTIN_USERS = "S-1-5-32-545"
SID_AUTH_USERS = "S-1-5-11"
SID_GUEST = "S-1-5-32-546"
SID_ANONYMOUS = "S-1-5-7"
FORBIDDEN_SIDS = frozenset(
    {SID_EVERYONE, SID_BUILTIN_USERS, SID_AUTH_USERS, SID_GUEST, SID_ANONYMOUS}
)
REQUIRED_SID_CATEGORIES = ("CURRENT_USER", "SYSTEM", "ADMINISTRATORS")

_KERNEL32 = (
    ctypes.WinDLL("kernel32", use_last_error=True)
    if platform.system() == "Windows"
    else None
)
_ADVAPI32 = (
    ctypes.WinDLL("advapi32", use_last_error=True)
    if platform.system() == "Windows"
    else None
)


def _setup() -> None:
    if platform.system() != "Windows" or _ADVAPI32 is None or _KERNEL32 is None:
        return
    _KERNEL32.GetCurrentProcess.argtypes = []
    _KERNEL32.GetCurrentProcess.restype = wintypes.HANDLE
    _KERNEL32.CloseHandle.argtypes = [wintypes.HANDLE]
    _KERNEL32.CloseHandle.restype = wintypes.BOOL
    _KERNEL32.LocalFree.argtypes = [ctypes.c_void_p]
    _KERNEL32.LocalFree.restype = ctypes.c_void_p
    _ADVAPI32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    _ADVAPI32.OpenProcessToken.restype = wintypes.BOOL
    _ADVAPI32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _ADVAPI32.GetTokenInformation.restype = wintypes.BOOL
    _ADVAPI32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    _ADVAPI32.ConvertSidToStringSidW.restype = wintypes.BOOL


_setup()


def current_user_sid_string() -> str:
    if platform.system() != "Windows" or _ADVAPI32 is None or _KERNEL32 is None:
        raise AclBlockedError("ACL_UNSUPPORTED_PLATFORM")
    token = wintypes.HANDLE()
    if not _ADVAPI32.OpenProcessToken(
        _KERNEL32.GetCurrentProcess(),
        0x0008,
        ctypes.byref(token),
    ):
        raise AclBlockedError("ACL_TOKEN_OPEN_FAILED")
    try:
        size = wintypes.DWORD(0)
        _ADVAPI32.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        buf = ctypes.create_string_buffer(size.value)
        if not _ADVAPI32.GetTokenInformation(
            token, 1, buf, size, ctypes.byref(size)
        ):
            raise AclBlockedError("ACL_TOKEN_QUERY_FAILED")

        class _SID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

        class _TOKEN_USER(ctypes.Structure):
            _fields_ = [("User", _SID_AND_ATTRIBUTES)]

        user = ctypes.cast(buf, ctypes.POINTER(_TOKEN_USER)).contents
        sid_str = wintypes.LPWSTR()
        if not _ADVAPI32.ConvertSidToStringSidW(user.User.Sid, ctypes.byref(sid_str)):
            raise AclBlockedError("ACL_SID_CONVERT_FAILED")
        try:
            return str(sid_str.value)
        finally:
            _KERNEL32.LocalFree(sid_str)
    finally:
        _KERNEL32.CloseHandle(token)


def read_allow_sids(path: Path, *, require_protected: bool = True) -> set[str]:
    protect_check = (
        "if (-not $acl.AreAccessRulesProtected) { Write-Output 'INHERIT_ENABLED'; exit 2 }; "
        if require_protected
        else ""
    )
    script = (
        "$p = $env:DS_TLS_ACL_PATH; "
        "$acl = Get-Acl -LiteralPath $p; "
        f"{protect_check}"
        "foreach ($r in $acl.Access) { "
        "  if ($r.AccessControlType -ne 'Allow') { continue }; "
        "  try { "
        "    $sid = ($r.IdentityReference.Translate("
        "[System.Security.Principal.SecurityIdentifier])).Value; "
        "    Write-Output $sid "
        "  } catch { Write-Output 'SID_TRANSLATE_FAILED'; exit 3 } "
        "}"
    )
    env = {**os.environ, "DS_TLS_ACL_PATH": str(path)}
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-Command", script],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env=env,
    )
    if completed.returncode == 2:
        raise AclBlockedError("ACL_INHERITANCE_ENABLED")
    if completed.returncode != 0:
        raise AclBlockedError("ACL_READ_FAILED")
    sids: set[str] = set()
    for line in (completed.stdout or "").splitlines():
        line = line.strip()
        if line == "SID_TRANSLATE_FAILED":
            raise AclBlockedError("ACL_SID_TRANSLATE_FAILED")
        if line.startswith("S-1-"):
            sids.add(line)
    return sids


def _assert_exact_three_sids(allow_sids: set[str], user_sid: str) -> None:
    if allow_sids & FORBIDDEN_SIDS:
        raise AclBlockedError("ACL_FORBIDDEN_PRINCIPAL")
    if SID_SYSTEM not in allow_sids:
        raise AclBlockedError("ACL_MISSING_SYSTEM")
    if SID_ADMINS not in allow_sids:
        raise AclBlockedError("ACL_MISSING_ADMINISTRATORS")
    if user_sid not in allow_sids:
        raise AclBlockedError("ACL_MISSING_CURRENT_USER")
    if allow_sids != {user_sid, SID_SYSTEM, SID_ADMINS}:
        raise AclBlockedError("ACL_UNEXPECTED_PRINCIPAL")


def verify_identity_root_dacl(identity_root: Path) -> None:
    """Fail-closed verify: protected DACL with exact three allow SIDs."""
    if platform.system() != "Windows":
        raise AclBlockedError("ACL_UNSUPPORTED_PLATFORM")
    user_sid = current_user_sid_string()
    allow_sids = read_allow_sids(identity_root, require_protected=True)
    _assert_exact_three_sids(allow_sids, user_sid)


def apply_and_verify_identity_dacl(identity_root: Path) -> dict[str, Any]:
    """Apply explicit DACL with inheritance disabled before any secret write."""
    if platform.system() != "Windows":
        raise AclBlockedError("ACL_UNSUPPORTED_PLATFORM")
    user_sid = current_user_sid_string()
    commands = [
        ["icacls", str(identity_root), "/inheritance:r"],
        [
            "icacls",
            str(identity_root),
            "/grant:r",
            f"*{SID_SYSTEM}:(OI)(CI)F",
            f"*{SID_ADMINS}:(OI)(CI)F",
            f"*{user_sid}:(OI)(CI)F",
        ],
    ]
    for cmd in commands:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if completed.returncode != 0:
            raise AclBlockedError("ACL_APPLY_FAILED")
    verify_identity_root_dacl(identity_root)
    return {
        "ACL_APPLIED_BEFORE_SECRET": True,
        "acl_principals": list(REQUIRED_SID_CATEGORIES),
    }


def verify_path_dacl_exact(path: Path) -> None:
    """Sensitive files must allow exactly CURRENT_USER + SYSTEM + Administrators."""
    user_sid = current_user_sid_string()
    allow_sids = read_allow_sids(path, require_protected=False)
    expected = {user_sid, SID_SYSTEM, SID_ADMINS}
    if allow_sids & FORBIDDEN_SIDS:
        raise AclBlockedError("ACL_FORBIDDEN_PRINCIPAL")
    if allow_sids != expected:
        if user_sid not in allow_sids:
            raise AclBlockedError("ACL_MISSING_CURRENT_USER")
        if SID_SYSTEM not in allow_sids:
            raise AclBlockedError("ACL_MISSING_SYSTEM")
        if SID_ADMINS not in allow_sids:
            raise AclBlockedError("ACL_MISSING_ADMINISTRATORS")
        raise AclBlockedError("ACL_UNEXPECTED_PRINCIPAL")
