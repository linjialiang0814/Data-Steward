"""Process-bound Windows DNS-SD advertisement for trusted endpoint discovery."""

from __future__ import annotations

import ctypes
import hashlib
import ipaddress
import threading
from ctypes import wintypes
from dataclasses import dataclass
from typing import Protocol

from .models import PROTOCOL_VERSION
from .pairing_discovery import build_mdns_projection

SERVICE_TYPE = "_datasteward._tcp.local"
DNS_REQUEST_PENDING = 9506
DNS_QUERY_REQUEST_VERSION1 = 1


class DnsSdAdvertisementError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class DnsSdAdvertisement:
    instance_name: str
    host_name: str
    private_host: str
    port: int
    properties: tuple[tuple[str, str], ...]


class DnsSdRegistration(Protocol):
    def register(self, advertisement: DnsSdAdvertisement) -> object: ...

    def deregister(self, handle: object) -> None: ...


class WindowsDnsSdAdvertiser:
    """Idempotent lifecycle wrapper; advertisement never authenticates a peer."""

    def __init__(
        self,
        *,
        hub_id: str,
        cert_fingerprint: str,
        private_host: str,
        port: int,
        registration: DnsSdRegistration | None = None,
    ) -> None:
        projection = build_mdns_projection(
            hub_id=hub_id,
            host=private_host,
            port=port,
            cert_fingerprint=cert_fingerprint,
            pairing_available=False,
        )
        label = hashlib.sha256(hub_id.encode("ascii")).hexdigest()[:12]
        self.advertisement = DnsSdAdvertisement(
            instance_name=f"DataSteward-{label}.{SERVICE_TYPE}",
            # Keep the host label DNS-safe and independent from the service
            # instance. The associated address is supplied explicitly below.
            host_name=f"datasteward-{label}",
            private_host=private_host,
            port=port,
            properties=tuple(
                (key, str(projection[key]).lower() if isinstance(projection[key], bool) else str(projection[key]))
                for key in (
                    "hub_id",
                    "protocol_version",
                    "cert_fingerprint",
                    "pairing_available",
                )
            ),
        )
        self._registration = registration or _WindowsDnsApi()
        self._handle: object | None = None
        self._closed = False
        self._lock = threading.Lock()

    def start(self) -> bool:
        with self._lock:
            if self._closed:
                raise DnsSdAdvertisementError("dns_sd_closed")
            if self._handle is not None:
                return True
            self._handle = self._registration.register(self.advertisement)
            return True

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            handle = self._handle
            self._handle = None
        if handle is not None:
            self._registration.deregister(handle)


_REGISTER_COMPLETE = ctypes.WINFUNCTYPE(
    None,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.LPVOID,
)


class _DnsServiceRegisterRequest(ctypes.Structure):
    _fields_ = (
        ("Version", wintypes.ULONG),
        ("InterfaceIndex", wintypes.ULONG),
        ("pServiceInstance", wintypes.LPVOID),
        ("pRegisterCompletionCallback", _REGISTER_COMPLETE),
        ("pQueryContext", wintypes.LPVOID),
        ("hCredentials", wintypes.HANDLE),
        ("unicastEnabled", wintypes.BOOL),
    )


@dataclass(slots=True)
class _WindowsRegistrationHandle:
    instance: int
    request: _DnsServiceRegisterRequest
    callback: object
    event: threading.Event
    statuses: list[int]
    callback_instances: list[int]
    keepalive: tuple[object, ...]
    deregistered: bool = False


class _WindowsDnsApi:
    def __init__(self) -> None:
        self._orphaned_handles: list[_WindowsRegistrationHandle] = []
        if not hasattr(ctypes, "WinDLL"):
            raise DnsSdAdvertisementError("dns_sd_unsupported")
        try:
            self._dnsapi = ctypes.WinDLL("dnsapi.dll", use_last_error=True)
        except OSError:
            raise DnsSdAdvertisementError("dns_sd_unsupported") from None
        self._construct = self._dnsapi.DnsServiceConstructInstance
        self._construct.argtypes = (
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            ctypes.POINTER(wintypes.ULONG),
            wintypes.LPVOID,
            wintypes.WORD,
            wintypes.WORD,
            wintypes.WORD,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.LPCWSTR),
            ctypes.POINTER(wintypes.LPCWSTR),
        )
        self._construct.restype = wintypes.LPVOID
        self._register = self._dnsapi.DnsServiceRegister
        self._register.argtypes = (ctypes.POINTER(_DnsServiceRegisterRequest), wintypes.LPVOID)
        self._register.restype = wintypes.DWORD
        self._deregister = self._dnsapi.DnsServiceDeRegister
        self._deregister.argtypes = (ctypes.POINTER(_DnsServiceRegisterRequest), wintypes.LPVOID)
        self._deregister.restype = wintypes.DWORD
        self._free = self._dnsapi.DnsServiceFreeInstance
        self._free.argtypes = (wintypes.LPVOID,)
        self._free.restype = None

    def register(self, advertisement: DnsSdAdvertisement) -> object:
        try:
            packed = ipaddress.IPv4Address(advertisement.private_host).packed
        except ipaddress.AddressValueError:
            raise DnsSdAdvertisementError("dns_sd_request_invalid") from None
        ip4 = wintypes.ULONG(int.from_bytes(packed, "little"))
        keys = (wintypes.LPCWSTR * len(advertisement.properties))(
            *(key for key, _ in advertisement.properties)
        )
        values = (wintypes.LPCWSTR * len(advertisement.properties))(
            *(value for _, value in advertisement.properties)
        )
        instance = self._construct(
            advertisement.instance_name,
            advertisement.host_name,
            ctypes.byref(ip4),
            None,
            advertisement.port,
            0,
            0,
            len(advertisement.properties),
            keys,
            values,
        )
        if not instance:
            raise DnsSdAdvertisementError("dns_sd_construct_failed")
        event = threading.Event()
        statuses: list[int] = []
        callback_instances: list[int] = []

        def completed(status: int, _context: object, returned: object) -> None:
            statuses.append(int(status))
            address = int(returned or 0)
            if address:
                callback_instances.append(address)
            event.set()

        callback = _REGISTER_COMPLETE(completed)
        request = _DnsServiceRegisterRequest(
            Version=DNS_QUERY_REQUEST_VERSION1,
            InterfaceIndex=0,
            pServiceInstance=instance,
            pRegisterCompletionCallback=callback,
            pQueryContext=None,
            hCredentials=None,
            unicastEnabled=False,
        )
        handle = _WindowsRegistrationHandle(
            instance=int(instance),
            request=request,
            callback=callback,
            event=event,
            statuses=statuses,
            callback_instances=callback_instances,
            keepalive=(ip4, keys, values),
        )
        result = int(self._register(ctypes.byref(request), None))
        if result != DNS_REQUEST_PENDING:
            self._free(wintypes.LPVOID(handle.instance))
            raise DnsSdAdvertisementError("dns_sd_register_failed")
        if not event.wait(timeout=3.0) or not statuses or statuses[-1] != 0:
            self._safe_deregister(handle)
            raise DnsSdAdvertisementError("dns_sd_register_failed")
        self._free_callback_copies(handle)
        return handle

    def deregister(self, handle: object) -> None:
        if not isinstance(handle, _WindowsRegistrationHandle):
            raise DnsSdAdvertisementError("dns_sd_handle_invalid")
        self._safe_deregister(handle)

    def _safe_deregister(self, handle: _WindowsRegistrationHandle) -> None:
        if handle.deregistered:
            return
        handle.deregistered = True
        handle.event.clear()
        result = int(self._deregister(ctypes.byref(handle.request), None))
        if result == DNS_REQUEST_PENDING:
            if not handle.event.wait(timeout=3.0):
                # Keep request/callback/instance memory alive until process exit.
                # Windows ties the registration to the process lifetime.
                self._orphaned_handles.append(handle)
                return
        elif result != 0:
            self._orphaned_handles.append(handle)
            return
        self._free_callback_copies(handle)
        if handle.instance:
            self._free(wintypes.LPVOID(handle.instance))
            handle.instance = 0

    def _free_callback_copies(self, handle: _WindowsRegistrationHandle) -> None:
        while handle.callback_instances:
            address = handle.callback_instances.pop(0)
            if address != handle.instance:
                self._free(wintypes.LPVOID(address))
