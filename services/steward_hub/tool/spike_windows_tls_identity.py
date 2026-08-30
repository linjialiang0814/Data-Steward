"""P0-S1-T02D-B1A Windows TLS identity storage feasibility spike.

OS-persisting probes require explicit human approval. Certificate Store writes,
LocalMachine scope, LAN binds, and credential enumeration are forbidden.
"""

from __future__ import annotations

import argparse
import asyncio
import ctypes
import hashlib
import ipaddress
import json
import os
import platform
import re
import secrets
import socket
import ssl
import subprocess
import sys
import time
from ctypes import wintypes
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

RUN_ID_PREFIX = "DataSteward-P0-S1-B1A-"
RUN_ID_PATTERN = re.compile(r"^DataSteward-P0-S1-B1A-[A-Za-z0-9]{16,64}$")
SPIKE_REL_PARTS = ("DataSteward", "spikes", "B1A")
OWNER_MARKER_NAME = "owner.marker.json"
MANIFEST_NAME = "cleanup_manifest.json"
APPROVAL_FLAG = "--i-approve-b1a-os-probe"
APPROVAL_VALUE = "YES"
APPROVAL_ENV = "B1A_OS_PROBE_APPROVED"
LOOPBACK_HOST = "127.0.0.1"
SCHEMA_VERSION = 1
CRED_NAME_SUFFIX = "-tls-key-password"
ALLOWED_ENCRYPTED_KEY_NAMES = frozenset(
    {"private_key.encrypted.pem", "tls_key.enc.pem"}
)
ENCRYPTED_KEY_FILENAME = "private_key.encrypted.pem"
CERT_FILENAME = "cert.pem"
DPAPI_BLOB_FILENAME = "key_password.dpapi"
PORT_FILENAME = "server_port.txt"
READY_FILENAME = "server_ready.txt"
STOP_FILENAME = "server_stop.txt"
PLAINTEXT_KEY_NAME_PATTERN = re.compile(
    r"(^|[/\\])(key|private[_-]?key|privkey)(\.pem|\.key)?$",
    re.IGNORECASE,
)
FORBIDDEN_BIND_HOSTS = frozenset(
    {"0.0.0.0", "::", "::0", "localhost", "[::]", "[::0]"}
)

CRYPTPROTECT_UI_FORBIDDEN = 0x1
CRED_TYPE_GENERIC = 1
CRED_PERSIST_LOCAL_MACHINE = 2  # current-user persist on this machine (not cert LM)
ERROR_NOT_FOUND = 1168
FILE_ATTRIBUTE_REPARSE_POINT = 0x400

_KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True) if platform.system() == "Windows" else None
_CRYPT32 = ctypes.WinDLL("crypt32", use_last_error=True) if platform.system() == "Windows" else None
_ADVAPI32 = ctypes.WinDLL("advapi32", use_last_error=True) if platform.system() == "Windows" else None


class CandidateResult(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    NOT_TESTED = "NOT_TESTED"


class SpikeSafetyError(ValueError):
    """Fail-closed safety violation."""


class ApprovalRequiredError(RuntimeError):
    """OS probe requested without approval."""


class CleanupBlockedError(RuntimeError):
    """Cleanup could not be proven safe or failed non-idempotently."""


class AclBlockedError(RuntimeError):
    """DACL could not be applied or verified before secrets."""


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


@dataclass
class ParentDirPlan:
    """Tracks which LocalAppData parent dirs pre-existed vs created this run."""

    datasteward_existed: bool
    spikes_existed: bool
    b1a_existed: bool
    created_datasteward: bool = False
    created_spikes: bool = False
    created_b1a: bool = False


@dataclass
class ManagedProcess:
    """Exact Popen ownership for the current run only."""

    run_id: str
    process: subprocess.Popen[bytes]
    process_role: str
    pid: int


@dataclass
class ProbeLogEvent:
    candidate: str
    result: CandidateResult
    detail: str = ""
    file_size: int | None = None
    cert_fingerprint_sha256: str | None = None
    path_category: str | None = None

    def as_public_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "candidate": self.candidate,
            "result": self.result.value,
        }
        if self.detail:
            payload["detail"] = self.detail
        if self.file_size is not None:
            payload["file_size"] = self.file_size
        if self.cert_fingerprint_sha256 is not None:
            payload["cert_fingerprint_sha256"] = self.cert_fingerprint_sha256
        if self.path_category is not None:
            payload["path_category"] = self.path_category
        return payload


@dataclass
class CleanupManifest:
    run_id: str
    ownership_nonce: str
    schema_version: int = SCHEMA_VERSION
    entries: list[dict[str, str]] = field(default_factory=list)
    parent_plan: ParentDirPlan | None = None

    def record(self, kind: str, token: str) -> None:
        if not kind or not token:
            raise SpikeSafetyError("cleanup manifest requires kind and token")
        if kind == "process":
            raise SpikeSafetyError("use record_process for process entries")
        self.entries.append({"kind": kind, "token": token})

    def record_process(self, *, pid: int, process_role: str) -> None:
        if pid <= 0 or not process_role:
            raise SpikeSafetyError("invalid process record")
        self.entries.append(
            {
                "kind": "process",
                "run_id": self.run_id,
                "pid": str(pid),
                "process_role": process_role,
            }
        )

    def to_json(self) -> str:
        payload: dict[str, Any] = {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "ownership_nonce": self.ownership_nonce,
            "entries": self.entries,
        }
        if self.parent_plan is not None:
            payload["parent_plan"] = {
                "datasteward_existed": self.parent_plan.datasteward_existed,
                "spikes_existed": self.parent_plan.spikes_existed,
                "b1a_existed": self.parent_plan.b1a_existed,
                "created_datasteward": self.parent_plan.created_datasteward,
                "created_spikes": self.parent_plan.created_spikes,
                "created_b1a": self.parent_plan.created_b1a,
            }
        return json.dumps(payload, indent=2, sort_keys=True)

    @classmethod
    def from_json(cls, text: str) -> CleanupManifest:
        data = json.loads(text)
        run_id = validate_run_id(str(data["run_id"]))
        nonce = str(data["ownership_nonce"])
        if not re.fullmatch(r"[A-Fa-f0-9]{32,128}", nonce):
            raise SpikeSafetyError("invalid ownership_nonce")
        parent_plan = None
        raw_plan = data.get("parent_plan")
        if isinstance(raw_plan, dict):
            parent_plan = ParentDirPlan(
                datasteward_existed=bool(raw_plan.get("datasteward_existed")),
                spikes_existed=bool(raw_plan.get("spikes_existed")),
                b1a_existed=bool(raw_plan.get("b1a_existed")),
                created_datasteward=bool(raw_plan.get("created_datasteward")),
                created_spikes=bool(raw_plan.get("created_spikes")),
                created_b1a=bool(raw_plan.get("created_b1a")),
            )
        manifest = cls(
            run_id=run_id,
            ownership_nonce=nonce,
            schema_version=int(data.get("schema_version", SCHEMA_VERSION)),
            parent_plan=parent_plan,
        )
        for item in data.get("entries", []):
            kind = str(item.get("kind", ""))
            if kind == "process":
                if str(item.get("run_id")) != run_id:
                    raise SpikeSafetyError("process run_id mismatch")
                manifest.record_process(
                    pid=int(item["pid"]),
                    process_role=str(item["process_role"]),
                )
            else:
                manifest.record(kind, str(item["token"]))
        return manifest


def validate_run_id(run_id: str) -> str:
    if not RUN_ID_PATTERN.fullmatch(run_id):
        raise SpikeSafetyError(f"run_id must match {RUN_ID_PATTERN.pattern}")
    return run_id


def new_run_id() -> str:
    # 128-bit CSPRNG suffix (32 hex chars)
    return f"{RUN_ID_PREFIX}{secrets.token_hex(16)}"


def validate_loopback_bind_host(host: str) -> str:
    if host != LOOPBACK_HOST:
        raise SpikeSafetyError("only 127.0.0.1 bind host is allowed")
    return host


def reject_non_loopback_address(value: str) -> None:
    if value == "localhost":
        return
    if value in FORBIDDEN_BIND_HOSTS:
        raise SpikeSafetyError("forbidden address")
    try:
        ip = ipaddress.ip_address(value)
    except ValueError as exc:
        raise SpikeSafetyError("invalid address") from exc
    if not ip.is_loopback or str(ip) != LOOPBACK_HOST:
        raise SpikeSafetyError("non-loopback address rejected")


def local_app_data_root(environ: Mapping[str, str] | None = None) -> Path:
    env = environ or os.environ
    raw = env.get("LOCALAPPDATA")
    if not raw:
        raise SpikeSafetyError("LOCALAPPDATA is required")
    root = Path(raw)
    if not root.is_absolute():
        raise SpikeSafetyError("LOCALAPPDATA must be absolute")
    text = str(root)
    if text.startswith("\\\\") or text.startswith("//"):
        raise SpikeSafetyError("UNC LOCALAPPDATA is forbidden")
    return root


def b1a_root(local_app_data: Path) -> Path:
    return local_app_data.joinpath(*SPIKE_REL_PARTS)


def expected_run_dir(local_app_data: Path, run_id: str) -> Path:
    validate_run_id(run_id)
    return b1a_root(local_app_data) / run_id


def path_category(path: Path, run_id: str) -> str:
    validate_run_id(run_id)
    return f"LOCALAPPDATA_SPIKE_B1A/{run_id}/{path.name}"


def assert_safe_encrypted_key_name(name: str) -> str:
    base = Path(name).name
    if base != name or "/" in name or "\\" in name:
        raise SpikeSafetyError("key name must be a bare filename")
    if PLAINTEXT_KEY_NAME_PATTERN.search(base):
        raise SpikeSafetyError("plaintext key filename is forbidden")
    if base not in ALLOWED_ENCRYPTED_KEY_NAMES:
        raise SpikeSafetyError("key filename not in encrypted allow-list")
    return base


def _is_reparse_point(path: Path) -> bool:
    """True only when the path exists and is a symlink/junction/reparse point."""
    if not path.exists():
        return False
    if path.is_symlink():
        return True
    if platform.system() != "Windows" or _KERNEL32 is None:
        return False
    attrs = _KERNEL32.GetFileAttributesW(str(path))
    if attrs == 0xFFFFFFFF:
        return False
    return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)


def assert_path_inside_run_dir(path: Path, run_dir: Path, run_id: str) -> Path:
    validate_run_id(run_id)
    resolved_run = run_dir.resolve(strict=False)
    resolved = path.resolve(strict=False)
    try:
        resolved.relative_to(resolved_run)
    except ValueError as exc:
        raise SpikeSafetyError("path escapes run_id directory") from exc
    if resolved_run.name != run_id:
        raise SpikeSafetyError("run directory name must equal run_id")
    expected_suffix = SPIKE_REL_PARTS + (run_id,)
    parts = resolved_run.parts
    if len(parts) < len(expected_suffix):
        raise SpikeSafetyError("run directory is not a B1A spike path")
    if parts[-len(expected_suffix) :] != expected_suffix:
        raise SpikeSafetyError("run directory is not a B1A spike path")
    if _is_reparse_point(resolved_run) or _is_reparse_point(resolved):
        raise SpikeSafetyError("reparse point / symlink / junction forbidden")
    return resolved


def approval_granted(
    *,
    cli_value: str | None = None,
    environ: Mapping[str, str] | None = None,
) -> bool:
    env = environ or os.environ
    return cli_value == APPROVAL_VALUE or env.get(APPROVAL_ENV) == APPROVAL_VALUE


def require_os_probe_approval(
    *,
    cli_value: str | None = None,
    environ: Mapping[str, str] | None = None,
) -> None:
    if not approval_granted(cli_value=cli_value, environ=environ):
        raise ApprovalRequiredError(
            "OS-persisting B1A probes are blocked until human approval "
            f"({APPROVAL_FLAG} {APPROVAL_VALUE} or {APPROVAL_ENV}={APPROVAL_VALUE})"
        )


def owner_marker_payload(run_id: str, ownership_nonce: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "ownership_nonce": ownership_nonce,
    }


def write_owner_marker(run_dir: Path, run_id: str, ownership_nonce: str) -> Path:
    marker = run_dir / OWNER_MARKER_NAME
    marker.write_text(
        json.dumps(
            owner_marker_payload(run_id, ownership_nonce),
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return marker


def read_owner_marker(run_dir: Path) -> dict[str, Any]:
    marker = run_dir / OWNER_MARKER_NAME
    data = json.loads(marker.read_text(encoding="utf-8"))
    validate_run_id(str(data["run_id"]))
    if int(data.get("schema_version", -1)) != SCHEMA_VERSION:
        raise SpikeSafetyError("owner marker schema mismatch")
    nonce = str(data["ownership_nonce"])
    if not re.fullmatch(r"[A-Fa-f0-9]{32,128}", nonce):
        raise SpikeSafetyError("owner marker nonce invalid")
    for banned in ("username", "password", "private_key", "LOCALAPPDATA"):
        if banned in data:
            raise SpikeSafetyError("owner marker contains forbidden field")
    return data


def verify_ownership(run_dir: Path, manifest: CleanupManifest) -> None:
    assert_path_inside_run_dir(run_dir, run_dir, manifest.run_id)
    if not run_dir.is_dir():
        raise SpikeSafetyError("run_dir is not a directory")
    marker = read_owner_marker(run_dir)
    if marker["run_id"] != manifest.run_id:
        raise SpikeSafetyError("owner marker run_id mismatch")
    if marker["ownership_nonce"] != manifest.ownership_nonce:
        raise SpikeSafetyError("owner marker ownership_nonce mismatch")
    if manifest.schema_version != SCHEMA_VERSION:
        raise SpikeSafetyError("manifest schema mismatch")


def current_user_sid_string() -> str:
    """Return current process user SID string without logging username."""
    if platform.system() != "Windows" or _ADVAPI32 is None or _KERNEL32 is None:
        raise AclBlockedError("ACL_UNSUPPORTED_PLATFORM")
    token = wintypes.HANDLE()
    if not _ADVAPI32.OpenProcessToken(
        _KERNEL32.GetCurrentProcess(),
        0x0008,  # TOKEN_QUERY
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
        # TOKEN_USER: SID pointer at offset 0
        class _TOKEN_USER(ctypes.Structure):
            _fields_ = [("User", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

        # Actually SID_AND_ATTRIBUTES is first field
        class _SID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

        class _TOKEN_USER2(ctypes.Structure):
            _fields_ = [("User", _SID_AND_ATTRIBUTES)]

        user = ctypes.cast(buf, ctypes.POINTER(_TOKEN_USER2)).contents
        sid_str = wintypes.LPWSTR()
        if not _ADVAPI32.ConvertSidToStringSidW(user.User.Sid, ctypes.byref(sid_str)):
            raise AclBlockedError("ACL_SID_CONVERT_FAILED")
        try:
            return str(sid_str.value)
        finally:
            _KERNEL32.LocalFree(sid_str)
    finally:
        _KERNEL32.CloseHandle(token)


def _read_allow_sids(path: Path, *, require_protected: bool = True) -> set[str]:
    """Read allow ACE SIDs via PowerShell; no usernames logged."""
    protect_check = (
        "if (-not $acl.AreAccessRulesProtected) { Write-Output 'INHERIT_ENABLED'; exit 2 }; "
        if require_protected
        else ""
    )
    script = (
        "$p = $env:B1A_ACL_PATH; "
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
    env = {**os.environ, "B1A_ACL_PATH": str(path)}
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-Command", script],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env=env,
    )
    if completed.returncode != 0:
        raise AclBlockedError(f"ACL_READ_FAILED:{completed.returncode}")
    sids: set[str] = set()
    for line in (completed.stdout or "").splitlines():
        line = line.strip()
        if line == "SID_TRANSLATE_FAILED":
            raise AclBlockedError("ACL_SID_TRANSLATE_FAILED")
        if line.startswith("S-1-"):
            sids.add(line)
    return sids


def apply_and_verify_run_dacl(run_dir: Path) -> dict[str, Any]:
    """Apply explicit CurrentUser/SYSTEM/Administrators DACL; disable inheritance."""
    if platform.system() != "Windows":
        raise AclBlockedError("ACL_UNSUPPORTED_PLATFORM")
    user_sid = current_user_sid_string()
    # icacls with SID principals only (no usernames in argv)
    commands = [
        ["icacls", str(run_dir), "/inheritance:r"],
        [
            "icacls",
            str(run_dir),
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
            raise AclBlockedError(f"ACL_APPLY_FAILED:{completed.returncode}")

    allow_sids = _read_allow_sids(run_dir)
    forbidden_hits = sorted(allow_sids & FORBIDDEN_SIDS)
    if forbidden_hits:
        raise AclBlockedError("ACL_FORBIDDEN_PRINCIPAL")
    if SID_SYSTEM not in allow_sids:
        raise AclBlockedError("ACL_MISSING_SYSTEM")
    if SID_ADMINS not in allow_sids:
        raise AclBlockedError("ACL_MISSING_ADMINISTRATORS")
    if user_sid not in allow_sids:
        raise AclBlockedError("ACL_MISSING_CURRENT_USER")
    # Only the three required allow principals
    if allow_sids - {user_sid, SID_SYSTEM, SID_ADMINS}:
        raise AclBlockedError("ACL_UNEXPECTED_PRINCIPAL")
    return {
        "ACL_APPLIED_BEFORE_SECRET": True,
        "ACL_CURRENT_USER": True,
        "ACL_SYSTEM": True,
        "ACL_ADMINISTRATORS": True,
        "ACL_FORBIDDEN_PRINCIPAL_COUNT": 0,
        "acl_principals": list(REQUIRED_SID_CATEGORIES),
    }


def verify_path_dacl_not_expanded(path: Path) -> None:
    """Sensitive child files must allow exactly CURRENT_USER + SYSTEM + Administrators."""
    user_sid = current_user_sid_string()
    allow_sids = _read_allow_sids(path, require_protected=False)
    expected = {user_sid, SID_SYSTEM, SID_ADMINS}
    if allow_sids & FORBIDDEN_SIDS:
        raise AclBlockedError("ACL_FORBIDDEN_PRINCIPAL")
    if user_sid not in allow_sids:
        raise AclBlockedError("ACL_MISSING_CURRENT_USER")
    if SID_SYSTEM not in allow_sids:
        raise AclBlockedError("ACL_MISSING_SYSTEM")
    if SID_ADMINS not in allow_sids:
        raise AclBlockedError("ACL_MISSING_ADMINISTRATORS")
    if allow_sids != expected:
        raise AclBlockedError("ACL_UNEXPECTED_PRINCIPAL")


def _parent_paths(local_app_data: Path) -> tuple[Path, Path, Path]:
    ds = local_app_data / "DataSteward"
    spikes = ds / "spikes"
    b1a = spikes / "B1A"
    return ds, spikes, b1a


def create_run_directory_atomic(
    *,
    run_id: str,
    environ: Mapping[str, str] | None = None,
) -> tuple[Path, CleanupManifest, dict[str, Any]]:
    """Atomically create run dir, apply DACL before secrets, write owner marker."""
    validate_run_id(run_id)
    root = local_app_data_root(environ)
    ds, spikes, b1a = _parent_paths(root)
    plan = ParentDirPlan(
        datasteward_existed=ds.exists(),
        spikes_existed=spikes.exists(),
        b1a_existed=b1a.exists(),
    )
    if not plan.datasteward_existed:
        ds.mkdir(parents=False, exist_ok=False)
        plan.created_datasteward = True
    if not plan.spikes_existed:
        spikes.mkdir(parents=False, exist_ok=False)
        plan.created_spikes = True
    if not plan.b1a_existed:
        b1a.mkdir(parents=False, exist_ok=False)
        plan.created_b1a = True
    if _is_reparse_point(b1a):
        raise SpikeSafetyError("B1A root is a reparse point")
    run_dir = expected_run_dir(root, run_id)
    try:
        run_dir.mkdir(parents=False, exist_ok=False)
    except FileExistsError as exc:
        raise SpikeSafetyError(
            "run_id directory already exists; refusing reuse (BLOCKED)"
        ) from exc
    if _is_reparse_point(run_dir):
        raise SpikeSafetyError("run_dir became a reparse point")

    acl_report = apply_and_verify_run_dacl(run_dir)

    ownership_nonce = secrets.token_hex(16)
    manifest = CleanupManifest(
        run_id=run_id,
        ownership_nonce=ownership_nonce,
        parent_plan=plan,
    )
    marker = write_owner_marker(run_dir, run_id, ownership_nonce)
    manifest.record("file", str(marker.resolve()))
    manifest_path = run_dir / MANIFEST_NAME
    manifest_path.write_text(manifest.to_json(), encoding="utf-8")
    manifest.record("file", str(manifest_path.resolve()))
    manifest_path.write_text(manifest.to_json(), encoding="utf-8")
    verify_ownership(run_dir, manifest)
    verify_path_dacl_not_expanded(marker)
    verify_path_dacl_not_expanded(manifest_path)
    return run_dir, manifest, acl_report


def persist_manifest(run_dir: Path, manifest: CleanupManifest) -> None:
    verify_ownership(run_dir, manifest)
    path = run_dir / MANIFEST_NAME
    path.write_text(manifest.to_json(), encoding="utf-8")


def cleanup_exact(
    manifest: CleanupManifest,
    *,
    environ: Mapping[str, str] | None = None,
    run_dir: Path | None = None,
) -> list[str]:
    """Delete only exact recorded files/creds; rmdir empty verified run dir only."""
    validate_run_id(manifest.run_id)
    root = local_app_data_root(environ)
    resolved_run = expected_run_dir(root, manifest.run_id)
    actions: list[str] = []

    owned = False
    if resolved_run.exists():
        try:
            verify_ownership(resolved_run, manifest)
            owned = True
        except SpikeSafetyError as exc:
            raise CleanupBlockedError(
                f"ownership verification failed; refusing cleanup: {exc}"
            ) from exc
    elif run_dir is not None and run_dir.exists():
        raise CleanupBlockedError("run_dir path mismatch vs expected location")

    kind_order = {"process": 0, "file": 1, "cred": 2, "dir": 3}
    ordered = sorted(
        manifest.entries,
        key=lambda item: kind_order.get(item["kind"], 99),
    )

    for entry in ordered:
        kind = entry["kind"]
        if kind == "process":
            # Process entries are audit-only at cleanup; never kill by PID scan.
            if entry.get("run_id") != manifest.run_id:
                raise CleanupBlockedError("PROCESS_RUN_MISMATCH")
            actions.append(
                f"process_record:{entry.get('process_role')}:{entry.get('pid')}"
            )
            continue
        token = entry["token"]
        if kind == "file":
            path = Path(token)
            if owned or resolved_run.exists():
                assert_path_inside_run_dir(path, resolved_run, manifest.run_id)
            elif path.exists():
                raise CleanupBlockedError(
                    "file exists but run_dir missing; refusing delete"
                )
            if path.exists():
                if path.is_dir():
                    raise CleanupBlockedError("file token points to directory")
                path.unlink()
                actions.append(
                    f"removed_file:{path_category(path, manifest.run_id)}"
                )
            else:
                actions.append(
                    f"missing_file:{path_category(path, manifest.run_id)}"
                )
        elif kind == "cred":
            if manifest.run_id not in token or not token.startswith(RUN_ID_PREFIX):
                raise CleanupBlockedError("credential token not owned by run_id")
            if not token.endswith(CRED_NAME_SUFFIX):
                raise CleanupBlockedError("credential token suffix invalid")
            result = cred_delete_exact(token)
            actions.append(f"cred_{result}:{token}")
        elif kind == "dir":
            path = Path(token)
            if path.resolve() != resolved_run.resolve():
                raise CleanupBlockedError("refusing to remove non-run_dir path")
            if not path.exists():
                actions.append(
                    f"missing_dir:{path_category(path, manifest.run_id)}"
                )
                continue
            if _is_reparse_point(path):
                raise CleanupBlockedError("run_dir is a reparse point")
            remaining = list(path.iterdir())
            if remaining:
                names = sorted(p.name for p in remaining)
                raise CleanupBlockedError(
                    f"unexpected_artifact:{','.join(names)}"
                )
            path.rmdir()
            actions.append(f"removed_dir:{path_category(path, manifest.run_id)}")
        else:
            raise CleanupBlockedError(f"unknown cleanup kind: {kind}")

    if resolved_run.exists():
        if _is_reparse_point(resolved_run):
            raise CleanupBlockedError("run_dir is a reparse point")
        remaining = list(resolved_run.iterdir())
        if remaining:
            raise CleanupBlockedError(
                "unexpected_artifact:"
                + ",".join(sorted(p.name for p in remaining))
            )
        resolved_run.rmdir()
        actions.append(
            f"removed_dir:{path_category(resolved_run, manifest.run_id)}"
        )

    # Parent dirs: only remove ones this run created and that are now empty.
    actions.extend(_cleanup_created_parents(manifest, environ=environ))
    return actions


def _cleanup_created_parents(
    manifest: CleanupManifest,
    *,
    environ: Mapping[str, str] | None = None,
) -> list[str]:
    actions: list[str] = []
    plan = manifest.parent_plan
    if plan is None:
        return actions
    root = local_app_data_root(environ)
    ds, spikes, b1a = _parent_paths(root)
    # deepest first
    for created, path, label in (
        (plan.created_b1a, b1a, "B1A"),
        (plan.created_spikes, spikes, "spikes"),
        (plan.created_datasteward, ds, "DataSteward"),
    ):
        if not created:
            actions.append(f"parent_preserved:{label}")
            continue
        if not path.exists():
            actions.append(f"parent_missing:{label}")
            continue
        if any(path.iterdir()):
            raise CleanupBlockedError(f"parent_not_empty:{label}")
        path.rmdir()
        actions.append(f"parent_removed:{label}")
    return actions


def evaluate_certificate_store_cng() -> ProbeLogEvent:
    return ProbeLogEvent(
        candidate="certificate_store_cng",
        result=CandidateResult.NOT_SUPPORTED,
        detail=(
            "ssl.SSLContext.load_cert_chain is filesystem-path based; no CNG "
            "handle API in stdlib ssl; Schannel/http.sys proxy out of MVP budget. "
            "No Certificate Store objects created this spike."
        ),
    )


def evaluate_dpapi_design() -> ProbeLogEvent:
    return ProbeLogEvent(
        candidate="dpapi_encrypted_keyfile",
        result=CandidateResult.NOT_TESTED,
        detail="See OS probe results when approved.",
    )


def evaluate_credential_manager_design() -> ProbeLogEvent:
    return ProbeLogEvent(
        candidate="credential_manager_key_password",
        result=CandidateResult.NOT_TESTED,
        detail="Password-only adjunct; see OS probe results when approved.",
    )


# --- Windows DPAPI / CredMan (ctypes) ---


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _setup_crypto_prototypes() -> None:
    if platform.system() != "Windows" or _CRYPT32 is None or _ADVAPI32 is None:
        return
    assert _KERNEL32 is not None
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
    _KERNEL32.GetCurrentProcess.argtypes = []
    _KERNEL32.GetCurrentProcess.restype = wintypes.HANDLE
    _KERNEL32.CloseHandle.argtypes = [wintypes.HANDLE]
    _KERNEL32.CloseHandle.restype = wintypes.BOOL
    _KERNEL32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _KERNEL32.OpenProcess.restype = wintypes.HANDLE
    _KERNEL32.GetExitCodeProcess.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _KERNEL32.GetExitCodeProcess.restype = wintypes.BOOL
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
    _ADVAPI32.CredWriteW.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    _ADVAPI32.CredWriteW.restype = wintypes.BOOL
    _ADVAPI32.CredReadW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    _ADVAPI32.CredReadW.restype = wintypes.BOOL
    _ADVAPI32.CredDeleteW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    _ADVAPI32.CredDeleteW.restype = wintypes.BOOL
    _ADVAPI32.CredFree.argtypes = [ctypes.c_void_p]
    _ADVAPI32.CredFree.restype = None


_setup_crypto_prototypes()


def _blob_from_bytes(data: bytes) -> tuple[DATA_BLOB, ctypes.Array[ctypes.c_char]]:
    buf = ctypes.create_string_buffer(data, len(data))
    blob = DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    return blob, buf


def dpapi_protect_current_user(plaintext: bytes) -> bytes:
    if platform.system() != "Windows" or _CRYPT32 is None or _KERNEL32 is None:
        raise SpikeSafetyError("DPAPI requires Windows")
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
    # Best-effort wipe input buffer
    ctypes.memset(in_buf, 0, len(plaintext))
    if not ok:
        raise SpikeSafetyError(
            f"CryptProtectData failed winerr={ctypes.get_last_error()}"
        )
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        _KERNEL32.LocalFree(out_blob.pbData)


def dpapi_unprotect_current_user(blob: bytes) -> bytearray:
    if platform.system() != "Windows" or _CRYPT32 is None or _KERNEL32 is None:
        raise SpikeSafetyError("DPAPI requires Windows")
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
        raise SpikeSafetyError(
            f"CryptUnprotectData failed winerr={ctypes.get_last_error()}"
        )
    try:
        raw = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        return bytearray(raw)
    finally:
        if out_blob.pbData:
            ctypes.memset(out_blob.pbData, 0, out_blob.cbData)
            _KERNEL32.LocalFree(out_blob.pbData)


class CREDENTIALW(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("TargetName", wintypes.LPWSTR),
        ("Comment", wintypes.LPWSTR),
        ("LastWritten", wintypes.FILETIME),
        ("CredentialBlobSize", wintypes.DWORD),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_char)),
        ("Persist", wintypes.DWORD),
        ("AttributeCount", wintypes.DWORD),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", wintypes.LPWSTR),
        ("UserName", wintypes.LPWSTR),
    ]


def cred_target_name(run_id: str) -> str:
    validate_run_id(run_id)
    return f"{run_id}{CRED_NAME_SUFFIX}"


def cred_write_exact(target: str, secret: bytes) -> None:
    if platform.system() != "Windows" or _ADVAPI32 is None:
        raise SpikeSafetyError("CredMan requires Windows")
    if not target.startswith(RUN_ID_PREFIX) or not target.endswith(CRED_NAME_SUFFIX):
        raise SpikeSafetyError("credential target name rejected")
    blob = ctypes.create_string_buffer(secret, len(secret))
    try:
        cred = CREDENTIALW()
        cred.Flags = 0
        cred.Type = CRED_TYPE_GENERIC
        cred.TargetName = target
        cred.CredentialBlobSize = len(secret)
        cred.CredentialBlob = ctypes.cast(blob, ctypes.POINTER(ctypes.c_char))
        cred.Persist = CRED_PERSIST_LOCAL_MACHINE
        cred.UserName = "DataStewardB1A"
        if not _ADVAPI32.CredWriteW(ctypes.byref(cred), 0):
            raise SpikeSafetyError(
                f"CREDMAN_WRITE_FAILED:{ctypes.get_last_error()}"
            )
    finally:
        ctypes.memset(blob, 0, len(secret))


def cred_read_exact(target: str) -> bytearray:
    if platform.system() != "Windows" or _ADVAPI32 is None:
        raise SpikeSafetyError("CredMan requires Windows")
    ptr = ctypes.c_void_p()
    if not _ADVAPI32.CredReadW(target, CRED_TYPE_GENERIC, 0, ctypes.byref(ptr)):
        err = ctypes.get_last_error()
        raise SpikeSafetyError(f"CREDMAN_READ_FAILED:{err}")
    try:
        cred = ctypes.cast(ptr, ctypes.POINTER(CREDENTIALW)).contents
        size = int(cred.CredentialBlobSize)
        copied = bytearray(ctypes.string_at(cred.CredentialBlob, size))
        if cred.CredentialBlob and size > 0:
            ctypes.memset(cred.CredentialBlob, 0, size)
        return copied
    finally:
        _ADVAPI32.CredFree(ptr)


def cred_delete_exact(target: str) -> str:
    if platform.system() != "Windows" or _ADVAPI32 is None:
        raise SpikeSafetyError("CredMan requires Windows")
    if not _ADVAPI32.CredDeleteW(target, CRED_TYPE_GENERIC, 0):
        err = ctypes.get_last_error()
        if err == ERROR_NOT_FOUND:
            return "missing_idempotent"
        raise CleanupBlockedError(f"CredDeleteW failed winerr={err}")
    return "removed"


def cred_exists_exact(target: str) -> bool:
    if platform.system() != "Windows" or _ADVAPI32 is None:
        raise SpikeSafetyError("CredMan requires Windows")
    ptr = ctypes.c_void_p()
    if _ADVAPI32.CredReadW(target, CRED_TYPE_GENERIC, 0, ctypes.byref(ptr)):
        _ADVAPI32.CredFree(ptr)
        return True
    err = ctypes.get_last_error()
    if err == ERROR_NOT_FOUND:
        return False
    raise SpikeSafetyError(f"CredReadW unexpected winerr={err}")


# --- OpenSSL fixture ---


def find_openssl_cli() -> Path | None:
    import shutil

    which = shutil.which("openssl")
    candidates: list[Path] = []
    if which:
        candidates.append(Path(which))
    git = shutil.which("git")
    if git:
        root = Path(git).resolve().parent.parent
        for rel in ("usr/bin/openssl.exe", "mingw64/bin/openssl.exe"):
            cand = root.joinpath(*rel.split("/"))
            if cand.is_file():
                candidates.append(cand)
    for path in candidates:
        try:
            completed = subprocess.run(
                [str(path), "version"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if completed.returncode == 0:
            return path
    return None


def _zero_bytearray(buf: bytearray) -> None:
    for i in range(len(buf)):
        buf[i] = 0
    buf.clear()


def pid_still_running(pid: int) -> bool:
    """True only when the OS reports the PID is still active (not exited)."""
    if pid <= 0:
        return False
    if platform.system() == "Windows" and _KERNEL32 is not None:
        # PROCESS_QUERY_LIMITED_INFORMATION
        handle = _KERNEL32.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        try:
            code = wintypes.DWORD()
            if not _KERNEL32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return False
            return int(code.value) == 259  # STILL_ACTIVE
        finally:
            _KERNEL32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def generate_encrypted_localhost_identity(
    run_dir: Path,
    manifest: CleanupManifest,
    password: bytearray,
    openssl: Path,
) -> tuple[Path, Path, str]:
    """Create encrypted PKCS#8 key + short-lived localhost cert. No plaintext key."""
    assert_safe_encrypted_key_name(ENCRYPTED_KEY_FILENAME)
    key_path = run_dir / ENCRYPTED_KEY_FILENAME
    cert_path = run_dir / CERT_FILENAME
    # Record before create for cleanup-on-failure
    manifest.record("file", str(key_path.resolve()))
    manifest.record("file", str(cert_path.resolve()))
    persist_manifest(run_dir, manifest)

    # 1) encrypted private key via stdin password only
    gen = subprocess.run(
        [
            str(openssl),
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-aes-256-cbc",
            "-pass",
            "stdin",
            "-out",
            str(key_path),
        ],
        input=bytes(password) + b"\n",
        capture_output=True,
        timeout=60,
        check=False,
    )
    if gen.returncode != 0:
        raise SpikeSafetyError("openssl genpkey failed")

    key_text = key_path.read_text(encoding="utf-8", errors="replace")
    if "BEGIN ENCRYPTED PRIVATE KEY" not in key_text:
        raise SpikeSafetyError("encrypted PKCS#8 PEM header missing")
    if "BEGIN PRIVATE KEY" in key_text or "BEGIN RSA PRIVATE KEY" in key_text:
        raise SpikeSafetyError("plaintext private key PEM detected; abort")

    # 2) self-signed cert; password via stdin; SAN localhost + 127.0.0.1 only
    req = subprocess.run(
        [
            str(openssl),
            "req",
            "-new",
            "-x509",
            "-key",
            str(key_path),
            "-passin",
            "stdin",
            "-out",
            str(cert_path),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        input=bytes(password) + b"\n",
        capture_output=True,
        timeout=60,
        check=False,
    )
    if req.returncode != 0:
        raise SpikeSafetyError("openssl req failed")

    fingerprint = cert_der_sha256_hex(cert_path)
    verify_path_dacl_not_expanded(key_path)
    verify_path_dacl_not_expanded(cert_path)
    return key_path, cert_path, fingerprint


def cert_der_sha256_hex(cert_path: Path) -> str:
    pem = cert_path.read_bytes()
    der = ssl.PEM_cert_to_DER_cert(pem.decode("ascii"))
    return hashlib.sha256(der).hexdigest()


def load_ssl_context(
    cert_path: Path,
    key_path: Path,
    password: bytearray | bytes | Callable[[], bytes],
) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if callable(password):
        ctx.load_cert_chain(str(cert_path), str(key_path), password=password)
    else:
        pwd = bytes(password)

        def _provider() -> bytes:
            return pwd

        ctx.load_cert_chain(str(cert_path), str(key_path), password=_provider)
    return ctx


# --- Uvicorn worker (same interpreter module) ---


def _minimal_health_app() -> Any:
    async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            return
        path = scope.get("path", "")
        if path != "/health":
            await send(
                {
                    "type": "http.response.start",
                    "status": 404,
                    "headers": [(b"content-type", b"text/plain")],
                }
            )
            await send({"type": "http.response.body", "body": b"not found"})
            return
        body = b'{"status":"ok","spike":"b1a"}'
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": body})

    return app


def worker_serve(
    *,
    run_dir: Path,
    password_source: str,
    cred_target: str | None = None,
    cert_name: str = CERT_FILENAME,
    key_name: str = ENCRYPTED_KEY_FILENAME,
    dpapi_name: str = DPAPI_BLOB_FILENAME,
) -> int:
    """Serve /health on pre-bound 127.0.0.1:0. Password never on argv/env."""
    import uvicorn

    run_id = run_dir.name
    validate_run_id(run_id)
    for name in (cert_name, key_name, dpapi_name):
        if Path(name).name != name or "/" in name or "\\" in name:
            raise SpikeSafetyError("invalid worker artifact name")
    cert_path = run_dir / cert_name
    key_path = run_dir / key_name
    assert_path_inside_run_dir(cert_path, run_dir, run_id)
    assert_path_inside_run_dir(key_path, run_dir, run_id)
    err_path = run_dir / "worker_error.txt"
    password = bytearray()
    try:
        if password_source == "dpapi":
            blob_path = run_dir / dpapi_name
            assert_path_inside_run_dir(blob_path, run_dir, run_id)
            blob = blob_path.read_bytes()
            password = dpapi_unprotect_current_user(blob)
        elif password_source == "credman":
            if not cred_target:
                raise SpikeSafetyError("cred_target required")
            password = cred_read_exact(cred_target)
        else:
            raise SpikeSafetyError("unknown password_source")

        # Prove key loads before advertising readiness (password stays in-process only).
        load_ssl_context(cert_path, key_path, password)

        # Uvicorn Config.ssl_keyfile_password is typed as str|None and does not accept
        # callables. Prefer ssl_context_factory so the password never enters Config as a
        # durable string field; load_cert_chain may still briefly materialize bytes.
        pwd_box: list[bytearray | None] = [password]

        def ssl_context_factory(config: Any, default_factory: Any) -> ssl.SSLContext:
            del config, default_factory
            current = pwd_box[0]
            if current is None:
                raise SpikeSafetyError("password already cleared")

            def _password() -> bytes:
                assert pwd_box[0] is not None
                return bytes(pwd_box[0])

            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(
                str(cert_path),
                str(key_path),
                password=_password,
            )
            return ctx

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        validate_loopback_bind_host(LOOPBACK_HOST)
        sock.bind((LOOPBACK_HOST, 0))
        sock.listen(16)
        port = int(sock.getsockname()[1])
        (run_dir / PORT_FILENAME).write_text(str(port), encoding="utf-8")

        config = uvicorn.Config(
            _minimal_health_app(),
            host=LOOPBACK_HOST,
            port=port,
            ssl_certfile=str(cert_path),
            ssl_keyfile=str(key_path),
            ssl_context_factory=ssl_context_factory,
            access_log=False,
            log_level="error",
            lifespan="off",
            proxy_headers=False,
            server_header=False,
            date_header=False,
        )
        server = uvicorn.Server(config)

        async def _run() -> None:
            async def _watch_stop() -> None:
                while not server.should_exit:
                    if (run_dir / STOP_FILENAME).exists():
                        server.should_exit = True
                        break
                    await asyncio.sleep(0.05)

            watch = asyncio.create_task(_watch_stop())
            serve = asyncio.create_task(server.serve(sockets=[sock]))
            # Wait until uvicorn marks itself started, then publish ready.
            deadline = time.time() + 15
            while time.time() < deadline and not server.started:
                if serve.done():
                    exc = serve.exception()
                    raise SpikeSafetyError(
                        f"uvicorn exited before start: {type(exc).__name__ if exc else 'ok'}"
                    )
                await asyncio.sleep(0.02)
            if not server.started:
                raise SpikeSafetyError("uvicorn failed to start")
            (run_dir / READY_FILENAME).write_text("ready", encoding="utf-8")
            try:
                await serve
            finally:
                watch.cancel()
                try:
                    sock.close()
                except OSError:
                    pass

        asyncio.run(_run())
        return 0
    except Exception as exc:  # noqa: BLE001
        try:
            err_path.write_text(redacted_error("WORKER", exc), encoding="utf-8")
        except OSError:
            pass
        return 1
    finally:
        if password:
            _zero_bytearray(password)


def redacted_error(stage: str, exc: BaseException) -> str:
    """Stable stage + exception type only; never raw str(exc)."""
    stage_key = re.sub(r"[^A-Z0-9_]", "", stage.upper())[:48] or "STAGE"
    return f"{stage_key}:{type(exc).__name__}"



def start_worker_process(
    *,
    script_path: Path,
    run_dir: Path,
    password_source: str,
    cred_target: str | None,
    python_exe: str,
    cert_name: str = CERT_FILENAME,
    key_name: str = ENCRYPTED_KEY_FILENAME,
    dpapi_name: str = DPAPI_BLOB_FILENAME,
) -> subprocess.Popen[bytes]:
    for name in (PORT_FILENAME, READY_FILENAME, STOP_FILENAME, "worker_error.txt"):
        path = run_dir / name
        if path.exists():
            path.unlink()
    args = [
        python_exe,
        str(script_path),
        "--worker-serve",
        "--run-dir",
        str(run_dir),
        "--password-source",
        password_source,
        "--cert-name",
        cert_name,
        "--key-name",
        key_name,
        "--dpapi-name",
        dpapi_name,
    ]
    if cred_target:
        args.extend(["--cred-target", cred_target])
    child_env = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("SSL_KEY")
        and "PASSWORD" not in key.upper()
    }
    return subprocess.Popen(
        args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=child_env,
    )


def wait_ready(
    run_dir: Path,
    process: subprocess.Popen[bytes] | ManagedProcess,
    timeout: float = 30.0,
) -> int:
    proc = process.process if isinstance(process, ManagedProcess) else process
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise SpikeSafetyError("UVICORN_START_FAILED:RuntimeError")
        if (run_dir / READY_FILENAME).exists() and (run_dir / PORT_FILENAME).exists():
            return int((run_dir / PORT_FILENAME).read_text(encoding="utf-8").strip())
        time.sleep(0.05)
    raise SpikeSafetyError("UVICORN_READY_TIMEOUT:TimeoutError")


def stop_managed_process(
    *,
    run_dir: Path,
    managed: ManagedProcess,
) -> None:
    """Stop only the exact Popen owned by this run. Never scan other PIDs."""
    validate_run_id(managed.run_id)
    if managed.process.pid != managed.pid:
        raise SpikeSafetyError("PROCESS_PID_MISMATCH")
    if run_dir.name != managed.run_id:
        raise SpikeSafetyError("PROCESS_RUN_DIR_MISMATCH")
    (run_dir / STOP_FILENAME).write_text("stop", encoding="utf-8")
    try:
        managed.process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        managed.process.terminate()
        try:
            managed.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            managed.process.kill()
            managed.process.wait(timeout=5)
    if managed.process.poll() is None:
        managed.process.kill()
        managed.process.wait(timeout=5)
    time.sleep(0.2)


def stop_worker(run_dir: Path, process: subprocess.Popen[bytes]) -> None:
    """Backward-compatible wrapper; prefers ManagedProcess via stop_managed_process."""
    stop_managed_process(
        run_dir=run_dir,
        managed=ManagedProcess(
            run_id=run_dir.name,
            process=process,
            process_role="uvicorn_worker",
            pid=int(process.pid),
        ),
    )


def https_health_check(port: int, expected_fingerprint: str) -> str:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((LOOPBACK_HOST, port), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname=LOOPBACK_HOST) as tls:
            der = tls.getpeercert(binary_form=True)
            assert der is not None
            fp = hashlib.sha256(der).hexdigest()
            if fp != expected_fingerprint:
                raise SpikeSafetyError("certificate fingerprint mismatch")
            tls.sendall(
                b"GET /health HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Connection: close\r\n\r\n"
            )
            data = b""
            while True:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                data += chunk
    if b"200" not in data.split(b"\r\n", 1)[0] or b'"status":"ok"' not in data:
        raise SpikeSafetyError("health request failed")
    return fp


# --- OS probe orchestration ---


def run_os_probes(
    *,
    approval_cli: str | None,
    environ: Mapping[str, str] | None = None,
    python_exe: str | None = None,
) -> dict[str, Any]:
    require_os_probe_approval(cli_value=approval_cli, environ=environ)
    if platform.system() != "Windows":
        raise SpikeSafetyError("OS probes require Windows")

    env = dict(environ or os.environ)
    # Soft residual check: foreign B1A children block without auto-kill.
    b1a = b1a_root(local_app_data_root(env))
    if b1a.exists() and any(b1a.iterdir()):
        return {
            "status": "BLOCKED",
            "reason": "B1A_RESIDUAL_PRESENT",
            "candidates": [evaluate_certificate_store_cng().as_public_dict()],
        }

    script_path = Path(__file__).resolve()
    py = python_exe or sys.executable
    openssl = find_openssl_cli()
    if openssl is None:
        return {
            "status": "BLOCKED",
            "reason": "OpenSSL CLI fixture candidate not runnable",
            "candidates": [evaluate_certificate_store_cng().as_public_dict()],
        }

    run_id = new_run_id()
    run_dir: Path | None = None
    manifest: CleanupManifest | None = None
    active: ManagedProcess | None = None
    managed_pids: list[int] = []
    # 256-bit entropy as hex so OpenSSL -pass stdin cannot truncate on 0x0a bytes.
    password = bytearray(secrets.token_hex(32).encode("ascii"))
    cred_target = cred_target_name(run_id)
    results: dict[str, Any] = {
        "run_id": run_id,
        "status": "RUNNING",
        "candidates": [],
        "fingerprints": {},
        "negatives": {},
        "rotation": {},
        "cleanup": {},
        "recommendation": {},
        "acl": {},
        "process_safety": {
            "CURRENT_RUN_PIDS_ONLY": True,
            "SCRIPT_NAME_KILL_USED": False,
        },
        "limits": {
            "openssl_cli_product_dependency": False,
            "cross_machine_restore_verified": False,
            "certificate_store_writes": False,
        },
    }
    cleanup_error: str | None = None

    def _stop_active() -> None:
        nonlocal active
        if active is not None and run_dir is not None:
            stop_managed_process(run_dir=run_dir, managed=active)
            active = None

    def _start_worker(**kwargs: Any) -> ManagedProcess:
        nonlocal active
        if active is not None:
            raise SpikeSafetyError("PROCESS_CONCURRENCY_VIOLATION")
        proc = start_worker_process(**kwargs)
        managed = ManagedProcess(
            run_id=run_id,
            process=proc,
            process_role="uvicorn_worker",
            pid=int(proc.pid),
        )
        assert manifest is not None
        manifest.record_process(pid=managed.pid, process_role=managed.process_role)
        if run_dir is not None:
            persist_manifest(run_dir, manifest)
        managed_pids.append(managed.pid)
        active = managed
        return managed

    try:
        run_dir, manifest, acl_report = create_run_directory_atomic(
            run_id=run_id, environ=env
        )
        results["acl"] = acl_report
        results["process_safety"]["PREEXISTING_PARENT_PRESERVED"] = True
        # Record credential target BEFORE CredWrite
        manifest.record("cred", cred_target)
        persist_manifest(run_dir, manifest)

        key_path, cert_path, fp1 = generate_encrypted_localhost_identity(
            run_dir, manifest, password, openssl
        )
        results["fingerprints"]["identity_1"] = fp1
        results["files"] = {
            "encrypted_key": path_category(key_path, run_id),
            "cert": path_category(cert_path, run_id),
            "encrypted_key_size": key_path.stat().st_size,
            "cert_size": cert_path.stat().st_size,
        }

        # DPAPI blob
        blob_path = run_dir / DPAPI_BLOB_FILENAME
        manifest.record("file", str(blob_path.resolve()))
        persist_manifest(run_dir, manifest)
        protected = dpapi_protect_current_user(bytes(password))
        blob_path.write_bytes(protected)
        verify_path_dacl_not_expanded(blob_path)

        # Round-trip
        unlocked = dpapi_unprotect_current_user(blob_path.read_bytes())
        if bytes(unlocked) != bytes(password):
            raise SpikeSafetyError("DPAPI round-trip mismatch")
        _zero_bytearray(unlocked)

        # Tamper fail-closed
        tampered = bytearray(blob_path.read_bytes())
        if not tampered:
            raise SpikeSafetyError("empty dpapi blob")
        tampered[0] ^= 0x5A
        try:
            dpapi_unprotect_current_user(bytes(tampered))
            results["negatives"]["tampered_dpapi"] = "FAIL_NOT_CLOSED"
        except SpikeSafetyError:
            results["negatives"]["tampered_dpapi"] = "PASS_FAIL_CLOSED"
        _zero_bytearray(tampered)

        # Wrong password fail-closed
        wrong = bytearray(secrets.token_hex(32).encode("ascii"))
        try:
            load_ssl_context(cert_path, key_path, wrong)
            results["negatives"]["wrong_password"] = "FAIL_NOT_CLOSED"
        except ssl.SSLError:
            results["negatives"]["wrong_password"] = "PASS_FAIL_CLOSED"
        except Exception:
            results["negatives"]["wrong_password"] = "PASS_FAIL_CLOSED"
        finally:
            _zero_bytearray(wrong)

        # Cert/key mismatch fail-closed (other encrypted key + original cert)
        other_key = run_dir / "tls_key.enc.pem"
        other_pwd = bytearray(secrets.token_hex(32).encode("ascii"))
        try:
            gen_other = subprocess.run(
                [
                    str(openssl),
                    "genpkey",
                    "-algorithm",
                    "RSA",
                    "-pkeyopt",
                    "rsa_keygen_bits:2048",
                    "-aes-256-cbc",
                    "-pass",
                    "stdin",
                    "-out",
                    str(other_key),
                ],
                input=bytes(other_pwd) + b"\n",
                capture_output=True,
                timeout=60,
                check=False,
            )
            if gen_other.returncode != 0:
                raise SpikeSafetyError("mismatch fixture genpkey failed")
            manifest.record("file", str(other_key.resolve()))
            persist_manifest(run_dir, manifest)
            try:
                load_ssl_context(cert_path, other_key, other_pwd)
                results["negatives"]["cert_key_mismatch"] = "FAIL_NOT_CLOSED"
            except Exception:
                results["negatives"]["cert_key_mismatch"] = "PASS_FAIL_CLOSED"
            other_key.unlink(missing_ok=True)
        finally:
            _zero_bytearray(other_pwd)

        # Process 1
        managed1 = _start_worker(
            script_path=script_path,
            run_dir=run_dir,
            password_source="dpapi",
            cred_target=None,
            python_exe=py,
        )
        port1 = wait_ready(run_dir, managed1)
        fp_p1 = https_health_check(port1, fp1)
        results["fingerprints"]["process_1"] = fp_p1
        _stop_active()

        # Process 2 restart
        managed2 = _start_worker(
            script_path=script_path,
            run_dir=run_dir,
            password_source="dpapi",
            cred_target=None,
            python_exe=py,
        )
        port2 = wait_ready(run_dir, managed2)
        fp_p2 = https_health_check(port2, fp1)
        results["fingerprints"]["process_2"] = fp_p2
        _stop_active()

        dpapi_pass = (
            fp_p1 == fp1 == fp_p2
            and results["negatives"].get("tampered_dpapi") == "PASS_FAIL_CLOSED"
            and results["negatives"].get("wrong_password") == "PASS_FAIL_CLOSED"
        )
        results["candidates"].append(
            ProbeLogEvent(
                candidate="dpapi_encrypted_keyfile",
                result=CandidateResult.PASS if dpapi_pass else CandidateResult.FAIL,
                detail=(
                    "two-process restart + pin + health; encrypted PKCS#8; "
                    "CurrentUser DPAPI UI_FORBIDDEN; password not on argv/env"
                ),
                file_size=key_path.stat().st_size,
                cert_fingerprint_sha256=fp1,
                path_category=path_category(key_path, run_id),
            ).as_public_dict()
        )

        # CredMan candidate
        cred_ok = False
        try:
            cred_write_exact(cred_target, bytes(password))
            read_back = cred_read_exact(cred_target)
            if bytes(read_back) != bytes(password):
                raise SpikeSafetyError("cred round-trip mismatch")
            _zero_bytearray(read_back)
            # SSLContext load using cred password
            cred_pwd = cred_read_exact(cred_target)
            try:
                load_ssl_context(cert_path, key_path, cred_pwd)
            finally:
                _zero_bytearray(cred_pwd)
            # One loopback uvicorn via credman
            managed_c = _start_worker(
                script_path=script_path,
                run_dir=run_dir,
                password_source="credman",
                cred_target=cred_target,
                python_exe=py,
            )
            port_c = wait_ready(run_dir, managed_c)
            https_health_check(port_c, fp1)
            _stop_active()
            cred_ok = True
        finally:
            # exact delete in finally
            try:
                del1 = cred_delete_exact(cred_target)
                del2 = cred_delete_exact(cred_target)
                exists = cred_exists_exact(cred_target)
                results["credman_cleanup"] = {
                    "delete1": del1,
                    "delete2": del2,
                    "exists_after": exists,
                }
                if exists:
                    raise CleanupBlockedError("CRED_RESIDUAL")
            except CleanupBlockedError:
                raise
            except Exception as exc:
                raise CleanupBlockedError(redacted_error("CREDMAN_CLEANUP", exc)) from exc

        results["candidates"].append(
            ProbeLogEvent(
                candidate="credential_manager_key_password",
                result=CandidateResult.PASS if cred_ok else CandidateResult.FAIL,
                detail=(
                    "exact Generic Credential write/read/uvicorn/delete; "
                    "no CredEnumerate; password-only adjunct"
                ),
                cert_fingerprint_sha256=fp1,
            ).as_public_dict()
        )

        # Rotation — second identity
        password2 = bytearray(secrets.token_hex(32).encode("ascii"))
        try:
            key2 = run_dir / "tls_key.enc.pem"
            cert2 = run_dir / "cert_rot.pem"
            blob2 = run_dir / "key_password_rot.dpapi"
            for path in (key2, cert2, blob2):
                manifest.record("file", str(path.resolve()))
            persist_manifest(run_dir, manifest)

            # Generate into temp names by temporarily swapping filenames via openssl outs
            gen = subprocess.run(
                [
                    str(openssl),
                    "genpkey",
                    "-algorithm",
                    "RSA",
                    "-pkeyopt",
                    "rsa_keygen_bits:2048",
                    "-aes-256-cbc",
                    "-pass",
                    "stdin",
                    "-out",
                    str(key2),
                ],
                input=bytes(password2) + b"\n",
                capture_output=True,
                timeout=60,
                check=False,
            )
            if gen.returncode != 0:
                raise SpikeSafetyError("rotation genpkey failed")
            key2_text = key2.read_text(encoding="utf-8", errors="replace")
            if "BEGIN ENCRYPTED PRIVATE KEY" not in key2_text:
                raise SpikeSafetyError("rotation key not encrypted")
            if "BEGIN PRIVATE KEY" in key2_text or "BEGIN RSA PRIVATE KEY" in key2_text:
                raise SpikeSafetyError("rotation plaintext key detected")
            req = subprocess.run(
                [
                    str(openssl),
                    "req",
                    "-new",
                    "-x509",
                    "-key",
                    str(key2),
                    "-passin",
                    "stdin",
                    "-out",
                    str(cert2),
                    "-days",
                    "1",
                    "-subj",
                    "/CN=localhost",
                    "-addext",
                    "subjectAltName=DNS:localhost,IP:127.0.0.1",
                ],
                input=bytes(password2) + b"\n",
                capture_output=True,
                timeout=60,
                check=False,
            )
            if req.returncode != 0:
                raise SpikeSafetyError("rotation req failed")
            fp2 = cert_der_sha256_hex(cert2)
            if fp2 == fp1:
                raise SpikeSafetyError("rotation fingerprint not distinct")
            results["fingerprints"]["identity_2"] = fp2
            blob2.write_bytes(dpapi_protect_current_user(bytes(password2)))

            # load_cert_chain for new identity
            load_ssl_context(cert2, key2, password2)

            # Third sequential Uvicorn uses rotated artifacts by name (no overwrite race).
            managed3 = _start_worker(
                script_path=script_path,
                run_dir=run_dir,
                password_source="dpapi",
                cred_target=None,
                python_exe=py,
                cert_name=cert2.name,
                key_name=key2.name,
                dpapi_name=blob2.name,
            )
            port3 = wait_ready(run_dir, managed3)
            fp_p3 = https_health_check(port3, fp2)
            results["fingerprints"]["process_3_rotated"] = fp_p3
            _stop_active()

            # Delete old primary identity; rotated files remain until cleanup_exact.
            for old in (
                run_dir / ENCRYPTED_KEY_FILENAME,
                run_dir / CERT_FILENAME,
                run_dir / DPAPI_BLOB_FILENAME,
            ):
                if old.exists():
                    old.unlink()
            try:
                load_ssl_context(
                    run_dir / CERT_FILENAME,
                    run_dir / ENCRYPTED_KEY_FILENAME,
                    password,
                )
                results["rotation"]["old_identity_after_delete"] = "FAIL_STILL_LOADABLE"
            except Exception:
                results["rotation"]["old_identity_after_delete"] = "PASS_UNAVAILABLE"
            # Old password must not unlock rotated key
            try:
                load_ssl_context(cert2, key2, password)
                results["rotation"]["old_password_on_new_key"] = "FAIL_NOT_CLOSED"
            except Exception:
                results["rotation"]["old_password_on_new_key"] = "PASS_FAIL_CLOSED"

            results["rotation"]["fingerprint_changed"] = fp2 != fp1
            results["rotation"]["new_health_ok"] = fp_p3 == fp2
        finally:
            _zero_bytearray(password2)

        results["candidates"].append(evaluate_certificate_store_cng().as_public_dict())

        # Recommendation
        results["recommendation"] = {
            "primary": "dpapi_encrypted_keyfile",
            "reason": (
                "Meets non-interactive Uvicorn file+password load with CurrentUser "
                "DPAPI and encrypted PKCS#8; no extra packaging dependency; simpler "
                "lifecycle than CredMan+file dual store."
            ),
            "credman": (
                "PASS as optional password adjunct but adds ctypes surface and "
                "duplicate secret storage; not preferred when DPAPI blob beside "
                "keyfile already works."
            ),
            "cng": "NOT_SUPPORTED for direct load without custom TLS stack.",
            "backup_cross_machine": "Not verified; CurrentUser DPAPI is machine/user bound.",
        }

        rotation_ok = bool(
            results["rotation"].get("fingerprint_changed")
            and results["rotation"].get("new_health_ok")
            and results["rotation"].get("old_identity_after_delete")
            == "PASS_UNAVAILABLE"
            and results["rotation"].get("old_password_on_new_key")
            == "PASS_FAIL_CLOSED"
        )
        if dpapi_pass and cred_ok and rotation_ok:
            results["status"] = "READY_FOR_B1A_REVIEW_PENDING_CLEANUP"
        else:
            results["status"] = "BLOCKED_PENDING_CLEANUP"

    except AclBlockedError as exc:
        results["status"] = "BLOCKED_ACL"
        results["error"] = type(exc).__name__
        results["error_detail"] = redacted_error("ACL", exc)
    except CleanupBlockedError as exc:
        results["status"] = "BLOCKED_CLEANUP"
        results["error"] = type(exc).__name__
        results["error_detail"] = redacted_error("CLEANUP", exc)
    except Exception as exc:  # noqa: BLE001
        results["status"] = "BLOCKED"
        results["error"] = type(exc).__name__
        results["error_detail"] = redacted_error("PROBE", exc)
    finally:
        _stop_active()
        _zero_bytearray(password)
        results["process_safety"]["managed_pids"] = list(managed_pids)
        results["process_safety"]["CURRENT_RUN_PIDS_ONLY"] = True
        # Ensure cred gone even if earlier finally partially ran
        try:
            if cred_exists_exact(cred_target):
                cred_delete_exact(cred_target)
            if cred_exists_exact(cred_target):
                cleanup_error = "CRED_RESIDUAL"
        except Exception as exc:  # noqa: BLE001
            cleanup_error = redacted_error("CRED_FINAL", exc)

        if manifest is not None and run_dir is not None:
            try:
                # Record dir for rmdir phase
                if not any(e["kind"] == "dir" for e in manifest.entries):
                    manifest.record("dir", str(run_dir.resolve()))
                    if run_dir.exists():
                        persist_manifest(run_dir, manifest)
                # Remove transient server control files if present (must be in manifest)
                for name in (
                    PORT_FILENAME,
                    READY_FILENAME,
                    STOP_FILENAME,
                    "worker_error.txt",
                ):
                    path = run_dir / name
                    if path.exists():
                        token = str(path.resolve())
                        if not any(
                            e["kind"] == "file" and e["token"] == token
                            for e in manifest.entries
                        ):
                            manifest.record("file", token)
                        if run_dir.exists():
                            persist_manifest(run_dir, manifest)
                actions = cleanup_exact(manifest, environ=env, run_dir=run_dir)
                results["cleanup"]["actions"] = actions
                # Idempotent second pass
                actions2 = cleanup_exact(manifest, environ=env, run_dir=run_dir)
                results["cleanup"]["actions_second"] = actions2
                if manifest.parent_plan is not None:
                    root = local_app_data_root(env)
                    ds, spikes, b1a_path = _parent_paths(root)
                    if manifest.parent_plan.datasteward_existed and not ds.exists():
                        raise CleanupBlockedError("PREEXISTING_PARENT_REMOVED")
                    if manifest.parent_plan.spikes_existed and not spikes.exists():
                        raise CleanupBlockedError("PREEXISTING_PARENT_REMOVED")
                    if manifest.parent_plan.b1a_existed and not b1a_path.exists():
                        raise CleanupBlockedError("PREEXISTING_PARENT_REMOVED")
                    results["process_safety"]["PREEXISTING_PARENT_PRESERVED"] = True
            except Exception as exc:  # noqa: BLE001
                cleanup_error = redacted_error("CLEANUP", exc)

        # Residual scans (never auto-delete pre-existing parents here)
        residual = {
            "run_dir_exists": bool(run_dir and run_dir.exists()),
            "cred_exists": False,
            "b1a_child_count": 0,
            "managed_pids_alive": [],
        }
        try:
            residual["cred_exists"] = cred_exists_exact(cred_target)
        except Exception:
            residual["cred_exists"] = True
        b1a = b1a_root(local_app_data_root(env))
        if b1a.exists():
            residual["b1a_child_count"] = len(list(b1a.iterdir()))
        for pid in managed_pids:
            if pid_still_running(pid):
                residual["managed_pids_alive"].append(pid)
        results["cleanup"]["residual"] = residual

        if (
            cleanup_error
            or residual["run_dir_exists"]
            or residual["cred_exists"]
            or residual["b1a_child_count"] > 0
            or residual["managed_pids_alive"]
        ):
            results["status"] = "BLOCKED_CLEANUP"
            results["cleanup"]["error"] = cleanup_error or "residual_present"
        elif results.get("status") == "BLOCKED_ACL":
            pass
        elif results.get("status") == "READY_FOR_B1A_REVIEW_PENDING_CLEANUP":
            results["status"] = "READY_FOR_B1A_REVIEW_R2"
        elif results.get("status") == "BLOCKED_PENDING_CLEANUP":
            results["status"] = "BLOCKED"

    return results


def readonly_environment_audit() -> dict[str, Any]:
    import inspect

    load_sig = str(inspect.signature(ssl.SSLContext.load_cert_chain))
    uvicorn_info: dict[str, Any] = {"present": False}
    try:
        import uvicorn
        from uvicorn.config import Config

        params = list(inspect.signature(Config.__init__).parameters)
        uvicorn_info = {
            "present": True,
            "version": getattr(uvicorn, "__version__", "unknown"),
            "has_ssl_keyfile": "ssl_keyfile" in params,
            "has_ssl_certfile": "ssl_certfile" in params,
            "has_ssl_keyfile_password": "ssl_keyfile_password" in params,
        }
    except Exception as exc:  # noqa: BLE001
        uvicorn_info = {"present": False, "error": type(exc).__name__}

    modules = {}
    for name in ("cryptography", "win32cred", "fastapi", "httpx"):
        try:
            __import__(name)
            modules[name] = "PRESENT"
        except Exception:
            modules[name] = "ABSENT"

    openssl = find_openssl_cli()
    api_surface = {
        "CryptProtectData": _CRYPT32 is not None,
        "CredWriteW": _ADVAPI32 is not None,
        "CredEnumerate_called": False,
        "LocalMachine_write_attempted": False,
        "CertificateStore_write_attempted": False,
    }
    return {
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "python_bits": 64 if sys.maxsize > 2**32 else 32,
            "username": "REDACTED",
        },
        "python": {
            "version": sys.version.split()[0],
            "ssl_openssl_version": ssl.OPENSSL_VERSION,
            "load_cert_chain_signature": load_sig,
        },
        "uvicorn": uvicorn_info,
        "hub_modules": modules,
        "openssl_cli_fixture_candidate": (
            {"present": True, "product_runtime_dependency": False}
            if openssl
            else None
        ),
        "windows_api_surface": api_surface,
        "candidates": [
            evaluate_certificate_store_cng().as_public_dict(),
            evaluate_dpapi_design().as_public_dict(),
            evaluate_credential_manager_design().as_public_dict(),
        ],
    }


def planned_os_resources(run_id: str) -> dict[str, Any]:
    validate_run_id(run_id)
    return {
        "run_id": run_id,
        "resources": [
            {"type": "directory", "category": f"LOCALAPPDATA_SPIKE_B1A/{run_id}/"},
            {"type": "dpapi_blob_file", "scope": "CurrentUser"},
            {"type": "encrypted_pkcs8_pem"},
            {"type": "public_cert_pem", "san": ["localhost", "127.0.0.1"]},
            {
                "type": "generic_credential",
                "name": cred_target_name(run_id),
            },
            {"type": "certificate_store", "needed": False},
            {"type": "uvicorn_loopback", "max_concurrent": 1, "max_sequential": 3},
        ],
    }


def prepare_run_directory(
    *,
    run_id: str,
    environ: Mapping[str, str] | None = None,
    create: bool = False,
) -> Path:
    validate_run_id(run_id)
    run_dir = expected_run_dir(local_app_data_root(environ), run_id)
    assert_path_inside_run_dir(run_dir, run_dir, run_id)
    if create:
        raise ApprovalRequiredError(
            "use create_run_directory_atomic under OS probe approval only"
        )
    return run_dir


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="B1A Windows TLS identity spike")
    parser.add_argument("--readonly-audit", action="store_true")
    parser.add_argument("--print-plan", action="store_true")
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--run-os-probes", action="store_true")
    parser.add_argument(APPROVAL_FLAG, dest="approval", default=None)
    parser.add_argument("--worker-serve", action="store_true")
    parser.add_argument("--run-dir", default=None)
    parser.add_argument("--password-source", choices=("dpapi", "credman"), default=None)
    parser.add_argument("--cred-target", default=None)
    parser.add_argument("--cert-name", default=CERT_FILENAME)
    parser.add_argument("--key-name", default=ENCRYPTED_KEY_FILENAME)
    parser.add_argument("--dpapi-name", default=DPAPI_BLOB_FILENAME)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.worker_serve:
        if not args.run_dir or not args.password_source:
            print(json.dumps({"status": "BLOCKED", "reason": "worker args incomplete"}))
            return 2
        return worker_serve(
            run_dir=Path(args.run_dir),
            password_source=args.password_source,
            cred_target=args.cred_target,
            cert_name=args.cert_name,
            key_name=args.key_name,
            dpapi_name=args.dpapi_name,
        )
    if args.readonly_audit:
        print(json.dumps(readonly_environment_audit(), indent=2, sort_keys=True))
        return 0
    run_id = validate_run_id(args.run_id) if args.run_id else new_run_id()
    if args.print_plan:
        print(json.dumps(planned_os_resources(run_id), indent=2, sort_keys=True))
        return 0
    if args.run_os_probes:
        try:
            report = run_os_probes(approval_cli=args.approval)
        except ApprovalRequiredError as exc:
            print(json.dumps({"status": "BLOCKED", "reason": str(exc)}))
            return 2
        print(json.dumps(report, indent=2, sort_keys=True))
        status = report.get("status")
        if status == "READY_FOR_B1A_REVIEW_R2":
            return 0
        if status in {"BLOCKED_CLEANUP", "BLOCKED_ACL"}:
            return 3
        return 1
    print(
        json.dumps(
            {
                "status": "WAITING_FOR_HUMAN_B1A_OS_PROBE_APPROVAL",
                "run_id_example": run_id,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
