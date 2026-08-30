"""B2B-A / R1 TLS identity loader, pin-first client, and loopback HTTPS tests."""

from __future__ import annotations

import json
import os
import platform
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from helpers_tls_fixture import create_temp_identity, require_openssl
from steward_hub.https_runtime import (
    EXIT_PRE_LISTEN,
    allocate_loopback_port,
    build_https_config,
    serve_https_hub,
    validate_loopback_bind_host,
)
from steward_hub.pairing_store import PairingStore
from steward_hub.pin_client import (
    PinFirstHttpError,
    PinFirstHttpsClient,
    compare_fingerprints,
)
from steward_hub.tls_identity import (
    TlsIdentityError,
    TlsPinError,
    build_ssl_context_factory,
    format_fingerprint_display,
    load_tls_identity,
    require_fingerprint_sha256,
)
from steward_hub.tls_identity import loader as tls_loader
from steward_hub.tls_identity.errors import AclBlockedError, TlsManifestError
from steward_hub.tls_identity.manifest import (
    MAX_MANIFEST_BYTES,
    load_identity_manifest,
    parse_identity_manifest,
)
from steward_hub.tls_identity.path_safety import assert_path_inside_root

HUB_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
SRC = Path(__file__).resolve().parents[1] / "src"


def _python() -> str:
    return sys.executable


class HttpsWebSocketConfigurationTest(unittest.TestCase):
    def test_authenticated_runtime_bounds_reassembled_websocket_message(self) -> None:
        identity = mock.Mock(
            cert_path=Path("fixture-cert.pem"),
            key_path=Path("fixture-key.pem"),
        )
        config = build_https_config(
            app=mock.Mock(),
            host="127.0.0.1",
            port=12345,
            identity=identity,
            ssl_context_factory=mock.Mock(),
        )
        self.assertEqual(4096, config.ws_max_size)
        self.assertEqual("127.0.0.1", config.host)
        self.assertEqual(1, config.workers)
        self.assertFalse(config.proxy_headers)


@unittest.skipUnless(platform.system() == "Windows", "B2B-A TLS identity requires Windows")
class TlsIdentityLoaderTest(unittest.TestCase):
    def setUp(self) -> None:
        require_openssl()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_load_happy_path(self) -> None:
        identity_root = self.root / "id"
        manifest, fp = create_temp_identity(identity_root, hub_id=HUB_ID)
        loaded = load_tls_identity(identity_root)
        self.assertEqual(fp, loaded.cert_fingerprint_sha256)
        self.assertEqual(manifest.hub_id, loaded.manifest.hub_id)

    def test_fingerprint_strict_rejects_formatting(self) -> None:
        with self.assertRaises(TlsManifestError):
            require_fingerprint_sha256("ABCD")
        with self.assertRaises(TlsManifestError):
            require_fingerprint_sha256("a" * 63)
        with self.assertRaises(TlsManifestError):
            require_fingerprint_sha256("a" * 65)
        with self.assertRaises(TlsManifestError):
            require_fingerprint_sha256("g" * 64)
        with self.assertRaises(TlsManifestError):
            require_fingerprint_sha256("A" * 64)
        with self.assertRaises(TlsManifestError):
            require_fingerprint_sha256(":".join(["aa"] * 32))
        with self.assertRaises(TlsManifestError):
            require_fingerprint_sha256(" " + ("a" * 64))
        with self.assertRaises(TlsManifestError):
            require_fingerprint_sha256(("a" * 64) + " ")
        with self.assertRaises(TlsManifestError):
            require_fingerprint_sha256(("aa " * 32).strip())
        fp = "a" * 64
        self.assertEqual(fp, require_fingerprint_sha256(fp))
        self.assertEqual(
            ":".join(["aa"] * 32),
            format_fingerprint_display(fp),
        )

    def test_manifest_schema_type_and_duplicates(self) -> None:
        base = {
            "schema_version": 1,
            "hub_id": HUB_ID,
            "cert_fingerprint_sha256": "a" * 64,
            "cert_filename": "cert.pem",
            "encrypted_key_filename": "private_key.encrypted.pem",
            "dpapi_blob_filename": "key_password.dpapi",
            "tls_storage_kind": "dpapi_encrypted_pkcs8",
        }
        parse_identity_manifest(base)
        for bad in (True, 1.0, "1"):
            data = dict(base)
            data["schema_version"] = bad
            with self.subTest(bad=bad):
                with self.assertRaises(TlsManifestError):
                    parse_identity_manifest(data)

        path = self.root / "dup.json"
        path.write_text(
            '{"schema_version":1,"schema_version":1,'
            f'"hub_id":"{HUB_ID}",'
            '"cert_fingerprint_sha256":"' + ("a" * 64) + '",'
            '"cert_filename":"cert.pem",'
            '"encrypted_key_filename":"private_key.encrypted.pem",'
            '"dpapi_blob_filename":"key_password.dpapi",'
            '"tls_storage_kind":"dpapi_encrypted_pkcs8"}',
            encoding="utf-8",
        )
        with self.assertRaises(TlsManifestError):
            load_identity_manifest(path)

        nan_path = self.root / "nan.json"
        nan_path.write_text(
            json.dumps({**base, "schema_version": 1}).replace(
                '"schema_version": 1', '"schema_version": NaN'
            ),
            encoding="utf-8",
        )
        # Force NaN token into JSON text.
        nan_path.write_text(
            "{"
            '"schema_version": NaN,'
            f'"hub_id": "{HUB_ID}",'
            f'"cert_fingerprint_sha256": "{"a" * 64}",'
            '"cert_filename": "cert.pem",'
            '"encrypted_key_filename": "private_key.encrypted.pem",'
            '"dpapi_blob_filename": "key_password.dpapi",'
            '"tls_storage_kind": "dpapi_encrypted_pkcs8"'
            "}",
            encoding="utf-8",
        )
        with self.assertRaises(TlsManifestError):
            load_identity_manifest(nan_path)

        inf_path = self.root / "inf.json"
        inf_path.write_text(
            "{"
            '"schema_version": Infinity,'
            f'"hub_id": "{HUB_ID}",'
            f'"cert_fingerprint_sha256": "{"a" * 64}",'
            '"cert_filename": "cert.pem",'
            '"encrypted_key_filename": "private_key.encrypted.pem",'
            '"dpapi_blob_filename": "key_password.dpapi",'
            '"tls_storage_kind": "dpapi_encrypted_pkcs8"'
            "}",
            encoding="utf-8",
        )
        with self.assertRaises(TlsManifestError):
            load_identity_manifest(inf_path)

    def test_manifest_and_artifact_size_limits(self) -> None:
        big = self.root / "big-manifest.json"
        big.write_bytes(b"{" + b"a" * (MAX_MANIFEST_BYTES + 8) + b"}")
        with self.assertRaises(TlsManifestError):
            load_identity_manifest(big)

        identity_root = self.root / "oversized"
        create_temp_identity(identity_root, hub_id=HUB_ID)
        # Enlarge cert beyond limit without breaking DACL apply path: append zeros.
        cert = identity_root / "cert.pem"
        padding = b"#" * (tls_loader.MAX_CERT_BYTES + 1 - cert.stat().st_size)
        cert.write_bytes(cert.read_bytes() + padding)
        with self.assertRaises(TlsIdentityError):
            load_tls_identity(identity_root)

    def test_wrong_manifest_fingerprint(self) -> None:
        identity_root = self.root / "bad-fp"
        create_temp_identity(
            identity_root,
            hub_id=HUB_ID,
            wrong_manifest_fingerprint="b" * 64,
        )
        with self.assertRaises(TlsIdentityError):
            load_tls_identity(identity_root)

    def test_tampered_dpapi(self) -> None:
        identity_root = self.root / "tamper"
        create_temp_identity(identity_root, hub_id=HUB_ID, tamper_dpapi=True)
        with self.assertRaises(TlsIdentityError):
            load_tls_identity(identity_root)

    def test_wrong_key_password(self) -> None:
        identity_root = self.root / "bad-pass"
        create_temp_identity(identity_root, hub_id=HUB_ID, wrong_password=True)
        with self.assertRaises(TlsIdentityError):
            load_tls_identity(identity_root)

    def test_cert_key_mismatch(self) -> None:
        a = self.root / "a"
        b = self.root / "b"
        create_temp_identity(a, hub_id=HUB_ID)
        create_temp_identity(b, hub_id=HUB_ID)
        (a / "private_key.encrypted.pem").write_bytes(
            (b / "private_key.encrypted.pem").read_bytes()
        )
        (a / "key_password.dpapi").write_bytes(
            (b / "key_password.dpapi").read_bytes()
        )
        with self.assertRaises(TlsIdentityError):
            load_tls_identity(a)

    def test_path_traversal_and_absolute_rejected(self) -> None:
        identity_root = self.root / "trav"
        create_temp_identity(identity_root, hub_id=HUB_ID)
        with self.assertRaises(Exception):
            assert_path_inside_root(self.root / "other" / "x", identity_root)
        with self.assertRaises(Exception):
            parse_identity_manifest(
                {
                    "schema_version": 1,
                    "hub_id": HUB_ID,
                    "cert_fingerprint_sha256": "a" * 64,
                    "cert_filename": "../cert.pem",
                    "encrypted_key_filename": "private_key.encrypted.pem",
                    "dpapi_blob_filename": "key_password.dpapi",
                    "tls_storage_kind": "dpapi_encrypted_pkcs8",
                }
            )

    def test_unknown_file_and_directory_rejected(self) -> None:
        identity_root = self.root / "extra"
        create_temp_identity(identity_root, hub_id=HUB_ID)
        (identity_root / "notes.txt").write_text("x", encoding="utf-8")
        with self.assertRaises(TlsIdentityError):
            load_tls_identity(identity_root)

        identity_root2 = self.root / "subdir"
        create_temp_identity(identity_root2, hub_id=HUB_ID)
        (identity_root2 / "nested").mkdir()
        with self.assertRaises(TlsIdentityError):
            load_tls_identity(identity_root2)

    def test_dacl_extra_sid_rejected(self) -> None:
        identity_root = self.root / "acl"
        create_temp_identity(identity_root, hub_id=HUB_ID)
        subprocess.run(
            ["icacls", str(identity_root), "/grant", "*S-1-1-0:F"],
            capture_output=True,
            text=True,
            check=False,
        )
        with self.assertRaises(AclBlockedError):
            load_tls_identity(identity_root)

    def test_bind_host_rejects_non_loopback(self) -> None:
        for host in ("0.0.0.0", "localhost", "::1", "192.168.1.1"):
            with self.subTest(host=host):
                with self.assertRaises(ValueError):
                    validate_loopback_bind_host(host)
        self.assertEqual("127.0.0.1", validate_loopback_bind_host("127.0.0.1"))

    def test_password_zeroed_and_factory_holds_only_context(self) -> None:
        identity_root = self.root / "pwd"
        create_temp_identity(identity_root, hub_id=HUB_ID)
        loaded = load_tls_identity(identity_root)
        tracked: list[bytearray] = []
        real_unprotect = tls_loader.dpapi_unprotect_current_user

        def capturing(blob: bytes) -> bytearray:
            pwd = real_unprotect(blob)
            tracked.append(pwd)
            return pwd

        with mock.patch.object(tls_loader, "dpapi_unprotect_current_user", capturing):
            factory, cleanup = build_ssl_context_factory(loaded)
        self.assertEqual(1, len(tracked))
        self.assertEqual(0, len(tracked[0]))
        self.assertIsNotNone(factory.__closure__)
        for cell in factory.__closure__:  # type: ignore[union-attr]
            value = cell.cell_contents
            self.assertNotIsInstance(value, bytearray)
            self.assertFalse(callable(value) and value.__name__ == "_provider")
        ctx = factory()
        self.assertEqual(ctx.minimum_version.name, "TLSv1_2")
        cleanup()

        # Exception path also zeros.
        tracked.clear()
        real_load = tls_loader._load_ssl_context

        def boom(cert_path, key_path, password):  # noqa: ANN001
            tracked.append(password)
            raise RuntimeError("forced_load_failure")

        with mock.patch.object(tls_loader, "dpapi_unprotect_current_user", capturing):
            with mock.patch.object(tls_loader, "_load_ssl_context", boom):
                with self.assertRaises(TlsIdentityError):
                    build_ssl_context_factory(loaded)
        self.assertGreaterEqual(len(tracked), 1)
        self.assertTrue(all(len(item) == 0 for item in tracked))
        _ = real_load


@unittest.skipUnless(platform.system() == "Windows", "B2B-A pin client requires Windows")
class PinFirstClientTest(unittest.TestCase):
    def setUp(self) -> None:
        require_openssl()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.identity_root = self.root / "id"
        self.manifest, self.fp = create_temp_identity(
            self.identity_root, hub_id=HUB_ID
        )
        self.db = self.root / "hub.sqlite3"
        self.port = allocate_loopback_port()
        self.reply = self.root / "control-reply.json"
        self.proc: subprocess.Popen[bytes] | None = None

    def tearDown(self) -> None:
        if self.proc is not None:
            if self.proc.poll() is None:
                try:
                    if self.proc.stdin:
                        self.proc.stdin.write(b"shutdown\n")
                        self.proc.stdin.flush()
                except OSError:
                    pass
                try:
                    self.proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                    self.proc.wait(timeout=3)
            for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass
        self.tmp.cleanup()

    def _start_hub(self) -> subprocess.Popen[bytes]:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(SRC)
        proc = subprocess.Popen(
            [
                _python(),
                "-m",
                "steward_hub.https_runtime",
                "--database",
                str(self.db),
                "--identity-root",
                str(self.identity_root),
                "--host",
                "127.0.0.1",
                "--port",
                str(self.port),
                "--shutdown-stdin",
                "--control-reply",
                str(self.reply),
            ],
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
        )
        self.proc = proc
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                err = (proc.stderr.read() if proc.stderr else b"").decode(
                    "utf-8", errors="replace"
                )
                raise RuntimeError(f"hub_exited:{err[:400]}")
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                    return proc
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("hub_listen_timeout")

    def test_wrong_pin_zero_http(self) -> None:
        self._start_hub()
        client = PinFirstHttpsClient(
            host="127.0.0.1",
            port=self.port,
            expected_fingerprint="c" * 64,
        )
        with self.assertRaises(TlsPinError):
            client.connect_and_pin()
        self.assertFalse(client.pin_verified)
        self.assertEqual(0, client.http_requests_sent)
        with self.assertRaises(TlsPinError):
            client.get("/health")
        self.assertEqual(0, client.http_requests_sent)
        if self.db.exists():
            conn = sqlite3.connect(self.db)
            try:
                row = conn.execute(
                    "SELECT COUNT(*) FROM pairing_attempt"
                ).fetchone()
                self.assertEqual(0, int(row[0]))
            finally:
                conn.close()

    def test_correct_pin_health(self) -> None:
        self._start_hub()
        with PinFirstHttpsClient(
            host="127.0.0.1",
            port=self.port,
            expected_fingerprint=self.fp,
        ) as client:
            self.assertTrue(client.pin_verified)
            resp = client.get("/health")
            self.assertEqual(200, resp.status_code)
            self.assertEqual(1, client.http_requests_sent)
            body = resp.json()
            self.assertEqual("ok", body["status"])

    def test_compare_digest_requires_strict_hex(self) -> None:
        self.assertTrue(compare_fingerprints(self.fp, self.fp))
        with self.assertRaises(TlsManifestError):
            compare_fingerprints(self.fp.upper(), self.fp)
        self.assertFalse(compare_fingerprints(self.fp, "d" * 64))

    def test_path_and_header_injection_rejected(self) -> None:
        self._start_hub()
        with PinFirstHttpsClient(
            host="127.0.0.1",
            port=self.port,
            expected_fingerprint=self.fp,
        ) as client:
            with self.assertRaises(ValueError):
                client.get("/health\r\nX-Injected: 1")
            with self.assertRaises(ValueError):
                client.get("/health#frag")
            with self.assertRaises(ValueError):
                client.get("https://evil/health")
            with self.assertRaises(ValueError):
                client.get(
                    "/health",
                    headers={"Host": "evil.example"},
                )
            with self.assertRaises(ValueError):
                client.get(
                    "/health",
                    headers={"X-Test": "bad\r\nX-Injected: 1"},
                )


@unittest.skipUnless(platform.system() == "Windows", "B2B-A load-fail listener test")
class IdentityLoadFailsNoListenerTest(unittest.TestCase):
    def test_listener_not_created_on_bad_identity(self) -> None:
        require_openssl()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            identity_root = root / "id"
            create_temp_identity(
                identity_root, hub_id=HUB_ID, tamper_dpapi=True
            )
            port = allocate_loopback_port()
            env = os.environ.copy()
            env["PYTHONPATH"] = str(SRC)
            proc = subprocess.Popen(
                [
                    _python(),
                    "-m",
                    "steward_hub.https_runtime",
                    "--database",
                    str(root / "db.sqlite3"),
                    "--identity-root",
                    str(identity_root),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                    "--shutdown-stdin",
                ],
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                code = proc.wait(timeout=20)
                self.assertEqual(EXIT_PRE_LISTEN, code)
                with self.assertRaises(OSError):
                    with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                        pass
            finally:
                for stream in (proc.stdin, proc.stdout, proc.stderr):
                    if stream is not None:
                        try:
                            stream.close()
                        except OSError:
                            pass


@unittest.skipUnless(platform.system() == "Windows", "B2B-A runtime lifecycle")
class RuntimeLifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        require_openssl()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_port_occupied_cleans_stores(self) -> None:
        identity_root = self.root / "id"
        create_temp_identity(identity_root, hub_id=HUB_ID)
        db = self.root / "hub.sqlite3"
        port = allocate_loopback_port()
        holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        holder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            holder.bind(("127.0.0.1", port))
            holder.listen(1)
            code = serve_https_hub(
                database_path=db,
                identity_root=identity_root,
                host="127.0.0.1",
                port=port,
                shutdown_stdin=False,
            )
            self.assertEqual(EXIT_PRE_LISTEN, code)
            # DB must be reopenable immediately (no lingering lock).
            store = PairingStore(db, auto_start_runtime=False)
            try:
                self.assertIsNotNone(store)
            finally:
                store.close()
            conn = sqlite3.connect(db)
            try:
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            finally:
                conn.close()
            for suffix in ("-wal", "-shm"):
                self.assertFalse(
                    Path(str(db) + suffix).exists(),
                    msg=f"residual {suffix}",
                )
        finally:
            holder.close()

    def test_identity_conflict_db_reopenable(self) -> None:
        identity_root = self.root / "id"
        _, fp = create_temp_identity(identity_root, hub_id=HUB_ID)
        db = self.root / "conflict.sqlite3"
        prep = PairingStore(db, auto_start_runtime=False)
        try:
            prep.initialize_hub_identity(
                hub_id=HUB_ID,
                cert_fingerprint="c" * 64,
                tls_storage_kind="dpapi_encrypted_pkcs8",
                tls_key_ref_id="other-ref",
            )
        finally:
            prep.close()
        port = allocate_loopback_port()
        code = serve_https_hub(
            database_path=db,
            identity_root=identity_root,
            host="127.0.0.1",
            port=port,
            shutdown_stdin=False,
        )
        self.assertEqual(EXIT_PRE_LISTEN, code)
        again = PairingStore(db, auto_start_runtime=False)
        try:
            conn = sqlite3.connect(db)
            try:
                hub = conn.execute("SELECT cert_fingerprint FROM hub_identity").fetchone()
                self.assertEqual("c" * 64, hub[0])
            finally:
                conn.close()
        finally:
            again.close()
        _ = fp


@unittest.skipUnless(platform.system() == "Windows", "pin client parse limits")
class PinFirstParseLimitTest(unittest.TestCase):
    def test_response_parse_helpers_reject_chunked_and_bad_length(self) -> None:
        client = PinFirstHttpsClient(
            host="127.0.0.1",
            port=9,
            expected_fingerprint="a" * 64,
        )
        # Simulate a connected pinned socket with crafted responses.
        class _FakeSock:
            def __init__(self, payload: bytes) -> None:
                self._data = payload
                self.closed = False

            def recv(self, n: int) -> bytes:
                if not self._data:
                    return b""
                chunk, self._data = self._data[:n], self._data[n:]
                return chunk

            def sendall(self, data: bytes) -> None:
                return None

            def close(self) -> None:
                self.closed = True

        client.pin_verified = True
        client._sock = _FakeSock(  # type: ignore[assignment]
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        )
        with self.assertRaises(PinFirstHttpError):
            client.request("GET", "/health")
        self.assertTrue(client._closed_for_error)

        client2 = PinFirstHttpsClient(
            host="127.0.0.1",
            port=9,
            expected_fingerprint="a" * 64,
        )
        client2.pin_verified = True
        client2._sock = _FakeSock(  # type: ignore[assignment]
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\nabcd"
        )
        with self.assertRaises(PinFirstHttpError):
            client2.request("GET", "/health")

        client3 = PinFirstHttpsClient(
            host="127.0.0.1",
            port=9,
            expected_fingerprint="a" * 64,
        )
        client3.pin_verified = True
        client3._sock = _FakeSock(  # type: ignore[assignment]
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort"
        )
        with self.assertRaises(PinFirstHttpError):
            client3.request("GET", "/health")


if __name__ == "__main__":
    unittest.main()
