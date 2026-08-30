"""Pin-first loopback HTTPS client — test/smoke protocol harness only.

Not a Flutter/product client. No redirects, proxies, cookies, or automatic
retries. Pin/TLS/HTTP parse errors are never retried by this client.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import socket
import ssl
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

from .tls_identity.errors import TlsPinError
from .tls_identity.manifest import require_fingerprint_sha256

LOOPBACK_HOST = "127.0.0.1"
MAX_RESPONSE_HEADER_BYTES = 32 * 1024
MAX_RESPONSE_BODY_BYTES = 1 * 1024 * 1024
MAX_REQUEST_HEADER_TOTAL_BYTES = 8 * 1024
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_HEADER_VALUE_RE = re.compile(r"^[\t\x20-\x7e]*$")
_FORBIDDEN_CALLER_HEADERS = frozenset({"host", "connection", "content-length"})
_CONTROL_IN_PATH = re.compile(r"[\x00-\x1f\x7f]")


class PinFirstHttpError(RuntimeError):
    """HTTP parse/limit failure; socket is closed and must not be reused."""

    error_code = "pin_http_error"


@dataclass
class PinFirstResponse:
    status_code: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


def peer_cert_fingerprint_sha256(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def compare_fingerprints(actual: str, expected: str) -> bool:
    left = require_fingerprint_sha256(actual)
    right = require_fingerprint_sha256(expected)
    return hmac.compare_digest(left, right)


def _validate_request_path(path: str) -> None:
    if not isinstance(path, str) or not path.startswith("/"):
        raise ValueError("path_invalid")
    if "://" in path or "#" in path:
        raise ValueError("path_invalid")
    if _CONTROL_IN_PATH.search(path):
        raise ValueError("path_invalid")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in path):
        raise ValueError("path_invalid")


class PinFirstHttpsClient:
    """
    TLS connect → DER SHA-256 pin → only then HTTP/1.1.

    Test/smoke harness only. No redirects, proxies, cookies, or retries.
    """

    def __init__(
        self,
        *,
        host: str,
        port: int,
        expected_fingerprint: str,
        timeout_s: float = 5.0,
    ) -> None:
        if host != LOOPBACK_HOST:
            raise ValueError("only 127.0.0.1 is allowed")
        self._host = host
        self._port = int(port)
        self._expected = require_fingerprint_sha256(expected_fingerprint)
        self._timeout_s = float(timeout_s)
        self._sock: ssl.SSLSocket | None = None
        self._closed_for_error = False
        self.http_requests_sent = 0
        self.pin_verified = False

    def connect_and_pin(self) -> str:
        if self._sock is not None:
            raise RuntimeError("already connected")
        if self._closed_for_error:
            raise RuntimeError("socket_closed")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        # Trust is established solely by pin after handshake (self-signed Hub).
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((self._host, self._port), timeout=self._timeout_s)
        try:
            ssock = ctx.wrap_socket(raw, server_hostname=self._host)
        except Exception:
            raw.close()
            raise
        try:
            der = ssock.getpeercert(binary_form=True)
            if not der:
                ssock.close()
                raise TlsPinError("peer_cert_missing")
            actual = peer_cert_fingerprint_sha256(der)
            if not compare_fingerprints(actual, self._expected):
                ssock.close()
                raise TlsPinError("fingerprint_mismatch")
            self._sock = ssock
            self.pin_verified = True
            return require_fingerprint_sha256(actual)
        except TlsPinError:
            raise
        except Exception:
            ssock.close()
            raise

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def detach_verified_socket(self) -> ssl.SSLSocket:
        """Transfer the already pinned TLS socket to another protocol owner."""
        if not self.pin_verified or self._sock is None or self._closed_for_error:
            raise TlsPinError("pin_not_verified")
        sock = self._sock
        self._sock = None
        self.pin_verified = False
        self._closed_for_error = True
        return sock

    def _fail_close(self, error: Exception) -> None:
        self._closed_for_error = True
        self.pin_verified = False
        self.close()
        raise error

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        query: dict[str, str] | None = None,
    ) -> PinFirstResponse:
        if not self.pin_verified or self._sock is None or self._closed_for_error:
            raise TlsPinError("pin_not_verified")
        if method.upper() not in {"GET", "POST", "PUT", "DELETE", "HEAD"}:
            raise ValueError("method_unsupported")
        _validate_request_path(path)
        target = path
        if query:
            for qk, qv in query.items():
                if _CONTROL_IN_PATH.search(qk) or _CONTROL_IN_PATH.search(qv):
                    raise ValueError("query_invalid")
            target = f"{path}?{urlencode(query)}"
            _validate_request_path(target.split("?", 1)[0])
            if _CONTROL_IN_PATH.search(target) or "#" in target:
                raise ValueError("path_invalid")
        payload = body or b""
        header_map: dict[str, str] = {}
        for key, value in (headers or {}).items():
            lower = key.lower()
            if lower in _FORBIDDEN_CALLER_HEADERS:
                raise ValueError("header_forbidden")
            if not _HEADER_NAME_RE.fullmatch(key):
                raise ValueError("header_invalid")
            if not isinstance(value, str) or not _HEADER_VALUE_RE.fullmatch(value):
                raise ValueError("header_invalid")
            header_map[lower] = value
        header_map["host"] = f"{self._host}:{self._port}"
        header_map["connection"] = "keep-alive"
        if payload:
            header_map["content-length"] = str(len(payload))
        elif "content-length" not in header_map and method.upper() != "GET":
            header_map["content-length"] = "0"
        lines = [f"{method.upper()} {target} HTTP/1.1"]
        total = 0
        for key, value in header_map.items():
            line = f"{key}: {value}"
            total += len(line) + 2
            if total > MAX_REQUEST_HEADER_TOTAL_BYTES:
                raise ValueError("headers_too_large")
            lines.append(line)
        request_bytes = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + payload
        self.http_requests_sent += 1
        try:
            self._sock.sendall(request_bytes)
            return self._read_response()
        except PinFirstHttpError:
            raise
        except Exception as exc:  # noqa: BLE001
            self._fail_close(PinFirstHttpError("request_failed"))
            raise PinFirstHttpError("request_failed") from exc

    def get(self, path: str, **kwargs: Any) -> PinFirstResponse:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> PinFirstResponse:
        return self.request("POST", path, **kwargs)

    def _read_response(self) -> PinFirstResponse:
        assert self._sock is not None
        buffer = bytearray()
        try:
            while b"\r\n\r\n" not in buffer:
                if len(buffer) > MAX_RESPONSE_HEADER_BYTES:
                    self._fail_close(PinFirstHttpError("headers_too_large"))
                chunk = self._sock.recv(4096)
                if not chunk:
                    self._fail_close(PinFirstHttpError("headers_truncated"))
                buffer.extend(chunk)
                if len(buffer) > MAX_RESPONSE_HEADER_BYTES and b"\r\n\r\n" not in buffer:
                    self._fail_close(PinFirstHttpError("headers_too_large"))
            header_blob, _, rest = bytes(buffer).partition(b"\r\n\r\n")
            if len(header_blob) > MAX_RESPONSE_HEADER_BYTES:
                self._fail_close(PinFirstHttpError("headers_too_large"))
            status_line, *header_lines = header_blob.decode("iso-8859-1").split("\r\n")
            parts = status_line.split(" ", 2)
            if len(parts) < 2 or not parts[1].isdigit():
                self._fail_close(PinFirstHttpError("status_invalid"))
            status_code = int(parts[1])
            headers: dict[str, str] = {}
            seen_length = False
            content_length: int | None = None
            for line in header_lines:
                if ":" not in line:
                    self._fail_close(PinFirstHttpError("header_invalid"))
                key, value = line.split(":", 1)
                name = key.strip().lower()
                val = value.strip()
                if name == "transfer-encoding":
                    self._fail_close(PinFirstHttpError("transfer_encoding_unsupported"))
                if name == "content-length":
                    if seen_length:
                        self._fail_close(PinFirstHttpError("content_length_conflict"))
                    seen_length = True
                    if not val.isdigit():
                        self._fail_close(PinFirstHttpError("content_length_invalid"))
                    content_length = int(val)
                    if content_length < 0:
                        self._fail_close(PinFirstHttpError("content_length_invalid"))
                    if content_length > MAX_RESPONSE_BODY_BYTES:
                        self._fail_close(PinFirstHttpError("body_too_large"))
                headers[name] = val
            body = bytearray(rest)
            if content_length is None:
                # HTTP/1.1 without Content-Length and without chunked is not accepted.
                self._fail_close(PinFirstHttpError("content_length_missing"))
            while len(body) < content_length:
                need = content_length - len(body)
                chunk = self._sock.recv(min(4096, need))
                if not chunk:
                    self._fail_close(PinFirstHttpError("body_truncated"))
                body.extend(chunk)
                if len(body) > MAX_RESPONSE_BODY_BYTES:
                    self._fail_close(PinFirstHttpError("body_too_large"))
            return PinFirstResponse(
                status_code=status_code,
                headers=headers,
                body=bytes(body[:content_length]),
            )
        except PinFirstHttpError:
            raise
        except Exception as exc:  # noqa: BLE001
            self._fail_close(PinFirstHttpError("response_parse_failed"))
            raise PinFirstHttpError("response_parse_failed") from exc

    def __enter__(self) -> PinFirstHttpsClient:
        self.connect_and_pin()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
