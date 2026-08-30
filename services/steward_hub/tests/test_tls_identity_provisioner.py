"""B2B-B1/R1 product TLS identity provisioner tests (no OpenSSL CLI)."""

from __future__ import annotations

import importlib
import json
import os
import platform
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
import ipaddress

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from steward_hub.https_runtime import allocate_loopback_port
from steward_hub.pin_client import PinFirstHttpsClient
from steward_hub.tls_identity import (
    TlsCertificatePolicyError,
    TlsPermanentPathError,
    TlsProvisionError,
    count_transient_siblings,
    create_rotation_candidate,
    discard_rotation_candidate,
    load_tls_identity,
    permanent_hub_parent,
    permanent_identity_root,
    permanent_product_base,
    permanent_steady_state_paths,
    preflight_permanent_identity_parents,
    provision_or_load_identity,
    set_local_app_data_resolver_for_tests,
    set_provision_inject_hook,
)
from steward_hub.tls_identity.permanent_paths import (
    HUB_DIR_NAME,
    IDENTITY_DIR_NAME,
    PRODUCT_DIR_NAME,
    local_app_data_root,
)
from steward_hub.tls_identity.certificate_policy import (
    SUBJECT_CN,
    generate_hub_tls_material,
    load_certificate_pem,
    verify_certificate_policy,
)
from steward_hub.tls_identity.dacl import apply_and_verify_identity_dacl
from steward_hub.tls_identity.provisioner import (
    OWNER_FILENAME,
    OWNER_TOKEN_HEX_LEN,
    STAGING_PREFIX,
    _cleanup_owned_dir,
    _new_owner_token,
    _write_owner,
)

SRC = Path(__file__).resolve().parents[1] / "src"


def _snapshot_tree(path: Path) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    if not path.exists():
        return out
    for child in sorted(path.rglob("*")):
        if child.is_file():
            out[str(child.relative_to(path))] = child.read_bytes()
    return out


@unittest.skipUnless(platform.system() == "Windows", "provisioner requires Windows")
class ProductProvisionerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        set_provision_inject_hook(None)

    def tearDown(self) -> None:
        set_provision_inject_hook(None)
        self.tmp.cleanup()

    def test_first_run_and_idempotent(self) -> None:
        identity = self.root / "identity"
        first = provision_or_load_identity(identity)
        self.assertTrue(first.created)
        self.assertEqual(64, len(first.cert_fingerprint_sha256))
        second = provision_or_load_identity(identity)
        self.assertFalse(second.created)
        self.assertEqual(first.hub_id, second.hub_id)
        self.assertEqual(
            first.cert_fingerprint_sha256, second.cert_fingerprint_sha256
        )
        loaded = load_tls_identity(identity)
        self.assertEqual(first.cert_fingerprint_sha256, loaded.cert_fingerprint_sha256)
        self.assertEqual(
            [
                "cert.pem",
                "identity.json",
                "key_password.dpapi",
                "private_key.encrypted.pem",
            ],
            sorted(p.name for p in identity.iterdir()),
        )
        self.assertEqual(0, count_transient_siblings(self.root))

    def test_strict_load_rejects_publication_marker(self) -> None:
        identity = self.root / "id-marker-strict"
        provision_or_load_identity(identity)
        token = _new_owner_token()
        apply_and_verify_identity_dacl(identity)
        _write_owner(identity, token)
        with self.assertRaises(Exception):
            load_tls_identity(identity)
        recovered = provision_or_load_identity(identity)
        self.assertFalse(recovered.created)
        self.assertFalse((identity / OWNER_FILENAME).exists())

    def test_certificate_policy_fields(self) -> None:
        identity = self.root / "id-policy"
        provision_or_load_identity(identity)
        cert = load_certificate_pem((identity / "cert.pem").read_bytes())
        verify_certificate_policy(cert)
        self.assertEqual(x509.Version.v3, cert.version)
        self.assertIsInstance(cert.public_key(), ec.EllipticCurvePublicKey)
        self.assertEqual("secp256r1", cert.public_key().curve.name)
        self.assertEqual(SUBJECT_CN, cert.subject.rfc4514_string().split("=")[-1])
        self.assertEqual(cert.subject, cert.issuer)
        basic = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        self.assertTrue(basic.critical)
        self.assertFalse(basic.value.ca)
        self.assertIsNone(basic.value.path_length)
        ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        self.assertEqual(ski.value.digest, aki.value.key_identifier)
        self.assertIsNone(aki.value.authority_cert_issuer)
        self.assertIsNone(aki.value.authority_cert_serial_number)
        expected_ski = x509.SubjectKeyIdentifier.from_public_key(cert.public_key())
        self.assertEqual(expected_ski.digest, ski.value.digest)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        ips = list(san.value.get_values_for_type(x509.IPAddress))
        self.assertEqual(1, len(ips))
        self.assertEqual("127.0.0.1", str(ips[0]))

    def test_certificate_policy_negative_tamper(self) -> None:
        password = bytearray(secrets.token_bytes(32))
        material = generate_hub_tls_material(password=password)
        password[:] = b"\x00" * len(password)
        cert = load_certificate_pem(material.cert_pem)
        # Rebuild a policy-violating cert with same key material is hard from PEM;
        # instead mint an over-long validity cert and assert rejection.
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, SUBJECT_CN)])
        ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
        bad = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=400))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]
                ),
                False,
            )
            .add_extension(ski, False)
            .add_extension(
                x509.AuthorityKeyIdentifier(
                    key_identifier=ski.digest,
                    authority_cert_issuer=None,
                    authority_cert_serial_number=None,
                ),
                False,
            )
            .sign(key, hashes.SHA256())
        )
        with self.assertRaises(TlsCertificatePolicyError):
            verify_certificate_policy(bad)

        # ca must remain false (path_length non-None only legal when ca=True)
        bad_ca = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]
                ),
                False,
            )
            .add_extension(ski, False)
            .add_extension(
                x509.AuthorityKeyIdentifier(
                    key_identifier=ski.digest,
                    authority_cert_issuer=None,
                    authority_cert_serial_number=None,
                ),
                False,
            )
            .sign(key, hashes.SHA256())
        )
        with self.assertRaises(TlsCertificatePolicyError):
            verify_certificate_policy(bad_ca)
        # Extra subject attribute
        other = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, SUBJECT_CN),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "X"),
            ]
        )
        bad_subj = (
            x509.CertificateBuilder()
            .subject_name(other)
            .issuer_name(other)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]
                ),
                False,
            )
            .add_extension(ski, False)
            .add_extension(
                x509.AuthorityKeyIdentifier(
                    key_identifier=ski.digest,
                    authority_cert_issuer=None,
                    authority_cert_serial_number=None,
                ),
                False,
            )
            .sign(key, hashes.SHA256())
        )
        with self.assertRaises(TlsCertificatePolicyError):
            verify_certificate_policy(bad_subj)
        _ = cert

    def test_concurrent_first_run_single_identity(self) -> None:
        identity = self.root / "id-race"
        results: list = []
        errors: list = []

        def worker() -> None:
            try:
                results.append(provision_or_load_identity(identity))
            except Exception as exc:  # noqa: BLE001
                errors.append(type(exc).__name__)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
        self.assertEqual([], errors)
        self.assertEqual(8, len(results))
        hub_ids = {item.hub_id for item in results}
        fps = {item.cert_fingerprint_sha256 for item in results}
        self.assertEqual(1, len(hub_ids))
        self.assertEqual(1, len(fps))
        self.assertEqual(1, sum(1 for item in results if item.created))
        self.assertEqual([], list(self.root.glob(f"{STAGING_PREFIX}*")))
        self.assertEqual(0, count_transient_siblings(self.root))
        self.assertFalse((identity / OWNER_FILENAME).exists())

    def test_invalid_existing_not_overwritten(self) -> None:
        identity = self.root / "id-bad"
        first = provision_or_load_identity(identity)
        fp = first.cert_fingerprint_sha256
        (identity / "cert.pem").write_bytes(b"not-a-cert")
        with self.assertRaises(TlsProvisionError):
            provision_or_load_identity(identity)
        self.assertTrue(identity.exists())
        self.assertEqual(b"not-a-cert", (identity / "cert.pem").read_bytes())
        _ = fp

    def test_partial_staging_cleanup_on_inject(self) -> None:
        identity = self.root / "id-partial"
        points = [
            "after_dacl",
            "after_cert_written",
            "after_key_written",
            "after_dpapi_written",
            "before_manifest_written",
            "after_manifest_written",
            "after_validation",
            "before_publish",
            "immediately_before_rename",
        ]
        for point in points:
            with self.subTest(point=point):

                def _hook(p: str, expected: str = point) -> None:
                    if p == expected:
                        raise RuntimeError("inject")

                set_provision_inject_hook(_hook)
                with self.assertRaises(RuntimeError):
                    provision_or_load_identity(identity)
                self.assertFalse(identity.exists())
                self.assertEqual([], list(self.root.glob(f"{STAGING_PREFIX}*")))
                self.assertEqual(0, count_transient_siblings(self.root))
        set_provision_inject_hook(None)
        ok = provision_or_load_identity(identity)
        self.assertTrue(ok.created)

    def test_publish_fault_points_recover_or_fail_closed(self) -> None:
        points = [
            "immediately_after_rename",
            "before_publication_marker_remove",
            "after_publication_marker_remove",
            "before_final_strict_load",
        ]
        for point in points:
            with self.subTest(point=point):
                identity = self.root / f"id-pub-{point}"
                parent = identity.parent

                def _hook(p: str, expected: str = point) -> None:
                    if p == expected:
                        raise RuntimeError("inject_publish")

                set_provision_inject_hook(_hook)
                with self.assertRaises(RuntimeError):
                    provision_or_load_identity(identity)
                set_provision_inject_hook(None)
                self.assertEqual(0, count_transient_siblings(parent))
                # Rename commit point reached for these faults → final exists.
                self.assertTrue(identity.exists())
                before_fp = None
                if (identity / "identity.json").is_file():
                    before_fp = json.loads(
                        (identity / "identity.json").read_text(encoding="utf-8")
                    )["cert_fingerprint_sha256"]
                recovered = provision_or_load_identity(identity)
                self.assertFalse(recovered.created)
                self.assertFalse((identity / OWNER_FILENAME).exists())
                self.assertEqual(
                    [
                        "cert.pem",
                        "identity.json",
                        "key_password.dpapi",
                        "private_key.encrypted.pem",
                    ],
                    sorted(p.name for p in identity.iterdir()),
                )
                if before_fp is not None:
                    self.assertEqual(before_fp, recovered.cert_fingerprint_sha256)
                again = provision_or_load_identity(identity)
                self.assertEqual(recovered.hub_id, again.hub_id)
                self.assertEqual(
                    recovered.cert_fingerprint_sha256, again.cert_fingerprint_sha256
                )

    def test_marker_present_invalid_identity_fail_closed(self) -> None:
        identity = self.root / "id-bad-marker"
        first = provision_or_load_identity(identity)
        _write_owner(identity, _new_owner_token())
        (identity / "cert.pem").write_bytes(b"not-a-cert")
        with self.assertRaises(TlsProvisionError) as ctx:
            provision_or_load_identity(identity)
        self.assertEqual("publication_recovery_failed", ctx.exception.args[0])
        self.assertTrue((identity / OWNER_FILENAME).exists())
        self.assertEqual(b"not-a-cert", (identity / "cert.pem").read_bytes())
        self.assertEqual(first.hub_id, first.hub_id)

    def test_cleanup_owner_negatives_fail_closed(self) -> None:
        staging = self.root / f"{STAGING_PREFIX}neg"
        staging.mkdir()
        apply_and_verify_identity_dacl(staging)
        token = _new_owner_token()
        _write_owner(staging, token)
        (staging / "cert.pem").write_bytes(b"cert-bytes")
        (staging / "private_key.encrypted.pem").write_bytes(b"key-bytes")
        (staging / "key_password.dpapi").write_bytes(b"blob")
        (staging / "identity.json").write_bytes(b"{}")
        parent = staging.parent.resolve(strict=True)

        def assert_unchanged(label: str, mutate) -> None:
            before = _snapshot_tree(staging)
            with self.assertRaises(TlsProvisionError, msg=label):
                mutate()
            self.assertEqual(before, _snapshot_tree(staging), msg=label)
            self.assertTrue(staging.exists(), msg=label)

        # marker missing
        owner_path = staging / OWNER_FILENAME
        owner_bytes = owner_path.read_bytes()
        owner_path.unlink()

        assert_unchanged(
            "marker_missing",
            lambda: _cleanup_owned_dir(
                staging,
                owner_token=token,
                expected_name=staging.name,
                expected_parent=parent,
            ),
        )
        owner_path.write_bytes(owner_bytes)
        apply_and_verify_identity_dacl(staging)

        # JSON corrupt
        owner_path.write_bytes(b"{not-json")
        assert_unchanged(
            "marker_corrupt",
            lambda: _cleanup_owned_dir(
                staging,
                owner_token=token,
                expected_name=staging.name,
                expected_parent=parent,
            ),
        )
        owner_path.unlink()
        _write_owner(staging, token)

        # token missing field
        owner_path.write_bytes(b'{"schema_version":1}')
        assert_unchanged(
            "token_missing",
            lambda: _cleanup_owned_dir(
                staging,
                owner_token=token,
                expected_name=staging.name,
                expected_parent=parent,
            ),
        )
        owner_path.unlink()
        _write_owner(staging, token)

        # token length/format abnormal
        owner_path.write_bytes(
            json.dumps({"owner_token": "abcd", "schema_version": 1}).encode("utf-8")
        )
        assert_unchanged(
            "token_format",
            lambda: _cleanup_owned_dir(
                staging,
                owner_token=token,
                expected_name=staging.name,
                expected_parent=parent,
            ),
        )
        owner_path.unlink()
        _write_owner(staging, token)

        # mismatch
        other = _new_owner_token()
        assert_unchanged(
            "token_mismatch",
            lambda: _cleanup_owned_dir(
                staging,
                owner_token=other,
                expected_name=staging.name,
                expected_parent=parent,
            ),
        )

        # same basename expectation mismatch
        assert_unchanged(
            "name_mismatch",
            lambda: _cleanup_owned_dir(
                staging,
                owner_token=token,
                expected_name=f"{STAGING_PREFIX}other",
                expected_parent=parent,
            ),
        )

        # unknown file
        unknown = staging / "evil.bin"
        unknown.write_bytes(b"x")
        assert_unchanged(
            "unknown_file",
            lambda: _cleanup_owned_dir(
                staging,
                owner_token=token,
                expected_name=staging.name,
                expected_parent=parent,
            ),
        )
        unknown.unlink()

        # unknown dir
        nested = staging / "nested"
        nested.mkdir()
        assert_unchanged(
            "unknown_dir",
            lambda: _cleanup_owned_dir(
                staging,
                owner_token=token,
                expected_name=staging.name,
                expected_parent=parent,
            ),
        )
        nested.rmdir()

        # symlink/reparse when available (do not skip the rest of the test)
        link = staging / "link.pem"
        try:
            link.symlink_to(staging / "cert.pem")
        except (OSError, NotImplementedError):
            pass
        else:
            assert_unchanged(
                "symlink_entry",
                lambda: _cleanup_owned_dir(
                    staging,
                    owner_token=token,
                    expected_name=staging.name,
                    expected_parent=parent,
                ),
            )
            link.unlink(missing_ok=True)

        # happy path still works
        _cleanup_owned_dir(
            staging,
            owner_token=token,
            expected_name=staging.name,
            expected_parent=parent,
        )
        self.assertFalse(staging.exists())
        self.assertEqual(OWNER_TOKEN_HEX_LEN, len(token))

    def test_cleanup_failed_not_silent(self) -> None:
        identity = self.root / "id-cleanup-fail"

        def _hook(p: str) -> None:
            if p == "after_cert_written":
                # Poison staging so owned cleanup refuses (unknown entry).
                staging = next(self.root.glob(f"{STAGING_PREFIX}*"))
                (staging / "poison.bin").write_bytes(b"x")
                raise RuntimeError("inject_then_cleanup_fail")

        set_provision_inject_hook(_hook)
        with self.assertRaises(TlsProvisionError) as ctx:
            provision_or_load_identity(identity)
        self.assertEqual("cleanup_failed", ctx.exception.args[0])
        self.assertIsInstance(ctx.exception.__cause__, RuntimeError)
        leftovers = list(self.root.glob(f"{STAGING_PREFIX}*"))
        self.assertEqual(1, len(leftovers))
        self.assertGreater(count_transient_siblings(self.root), 0)
        # Manual recovery only: do not auto-expand delete. Remove in test teardown via tmp.

    def test_rotation_candidate_not_activated(self) -> None:
        identity = self.root / "id-rot"
        current = provision_or_load_identity(identity)
        candidate = create_rotation_candidate(identity)
        self.assertNotEqual(
            current.cert_fingerprint_sha256, candidate.cert_fingerprint_sha256
        )
        still = load_tls_identity(identity)
        self.assertEqual(
            current.cert_fingerprint_sha256, still.cert_fingerprint_sha256
        )
        discard_rotation_candidate(candidate)
        self.assertFalse(candidate.candidate_root.exists())
        self.assertEqual(
            current.cert_fingerprint_sha256,
            load_tls_identity(identity).cert_fingerprint_sha256,
        )

    def test_product_modules_have_no_openssl(self) -> None:
        package = Path(SRC / "steward_hub" / "tls_identity")
        forbidden = (
            "openssl.exe",
            "find_openssl",
            "spike_windows_tls_identity",
            "helpers_tls_fixture",
            "certreq",
            "new-selfsignedcertificate",
        )
        for path in package.rglob("*.py"):
            text = path.read_text(encoding="utf-8").lower()
            for token in forbidden:
                self.assertNotIn(token, text, msg=f"{path.name}:{token}")
        for path in package.rglob("*.py"):
            if path.name == "dacl.py":
                continue
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("subprocess", text, msg=path.name)
            self.assertNotIn("Popen", text, msg=path.name)

    def test_dependency_version_asserted(self) -> None:
        import cryptography

        self.assertEqual("49.0.0", cryptography.__version__)
        dist = importlib.metadata.distribution("cryptography")
        self.assertEqual("cryptography", dist.metadata["Name"])
        self.assertEqual("49.0.0", dist.version)

    def test_known_folder_absolute_and_hierarchy(self) -> None:
        set_local_app_data_resolver_for_tests(None)
        base = local_app_data_root()
        product = permanent_product_base()
        hub = permanent_hub_parent()
        identity = permanent_identity_root()
        self.assertTrue(base.is_absolute())
        self.assertTrue(product.is_absolute())
        self.assertTrue(hub.is_absolute())
        self.assertTrue(identity.is_absolute())
        self.assertEqual(PRODUCT_DIR_NAME, product.name)
        self.assertEqual(HUB_DIR_NAME, hub.name)
        self.assertEqual(IDENTITY_DIR_NAME, identity.name)
        self.assertEqual(product, hub.parent)
        self.assertEqual(hub, identity.parent)
        self.assertEqual(base, product.parent)
        for path in permanent_steady_state_paths():
            self.assertEqual(identity, path.parent)
        # Do not log the full user path string.

    def test_known_folder_api_failure_fail_closed(self) -> None:
        def _boom() -> Path:
            raise TlsPermanentPathError("known_folder_api_failed")

        set_local_app_data_resolver_for_tests(_boom)
        try:
            with self.assertRaises(TlsPermanentPathError) as ctx:
                permanent_identity_root()
            self.assertEqual("known_folder_api_failed", ctx.exception.args[0])
        finally:
            set_local_app_data_resolver_for_tests(None)

    def test_product_resolver_ignores_localappdata_env_tamper(self) -> None:
        set_local_app_data_resolver_for_tests(None)
        before = local_app_data_root()
        fake = self.root / "fake-localappdata"
        fake.mkdir()
        previous = os.environ.get("LOCALAPPDATA")
        os.environ["LOCALAPPDATA"] = str(fake)
        try:
            after = local_app_data_root()
            identity = permanent_identity_root()
        finally:
            if previous is None:
                os.environ.pop("LOCALAPPDATA", None)
            else:
                os.environ["LOCALAPPDATA"] = previous
        self.assertEqual(before, after)
        self.assertNotEqual(fake, after)
        self.assertNotEqual(fake / PRODUCT_DIR_NAME / HUB_DIR_NAME / IDENTITY_DIR_NAME, identity)
        self.assertEqual(IDENTITY_DIR_NAME, identity.name)

    def test_reparse_parent_rejected_by_preflight(self) -> None:
        # Injected temp tree simulates a reparse in the permanent parent chain.
        # Future B2B-B2 creation must fail-closed via this preflight.
        target = self.root / "real-base"
        target.mkdir()
        link = self.root / "reparse-base"
        # Prefer junction (reparse) — works without Developer Mode symlink rights.
        created = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            capture_output=True,
            text=True,
            check=False,
        )
        if created.returncode != 0 or not link.exists():
            try:
                link.symlink_to(target, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("directory reparse unavailable")

        set_local_app_data_resolver_for_tests(lambda: link)
        try:
            identity = permanent_identity_root()
            with self.assertRaises(TlsPermanentPathError) as ctx:
                preflight_permanent_identity_parents(identity)
            self.assertEqual("permanent_parent_reparse", ctx.exception.args[0])
        finally:
            set_local_app_data_resolver_for_tests(None)
            if link.exists():
                link.rmdir()

    def test_permanent_paths_hierarchy_locked(self) -> None:
        set_local_app_data_resolver_for_tests(None)
        root = permanent_identity_root()
        self.assertEqual(IDENTITY_DIR_NAME, root.name)
        self.assertEqual(
            (PRODUCT_DIR_NAME, HUB_DIR_NAME, IDENTITY_DIR_NAME),
            (root.parent.parent.name, root.parent.name, root.name),
        )
        for path in permanent_steady_state_paths():
            self.assertEqual(root, path.parent)
        # Existence is owned by B2B-B2 bootstrap; this test only locks hierarchy.

    def test_https_restart_fingerprint_stable(self) -> None:
        identity = self.root / "id-https"
        db = self.root / "hub.sqlite3"
        result = provision_or_load_identity(identity)
        port = allocate_loopback_port()
        env = os.environ.copy()
        env["PYTHONPATH"] = str(SRC)
        reply = self.root / "ctrl.json"
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "steward_hub.https_runtime",
                "--database",
                str(db),
                "--identity-root",
                str(identity),
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--shutdown-stdin",
                "--control-reply",
                str(reply),
            ],
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
        )
        try:
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    err = (proc.stderr.read() or b"").decode("utf-8", "replace")
                    raise RuntimeError(err[:400])
                try:
                    import socket

                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                raise RuntimeError("listen_timeout")
            with PinFirstHttpsClient(
                host="127.0.0.1",
                port=port,
                expected_fingerprint=result.cert_fingerprint_sha256,
            ) as client:
                health = client.get("/health")
                self.assertEqual(200, health.status_code)
            bad = PinFirstHttpsClient(
                host="127.0.0.1",
                port=port,
                expected_fingerprint="a" * 64,
            )
            with self.assertRaises(Exception):
                bad.connect_and_pin()
            self.assertEqual(0, bad.http_requests_sent)
            if db.exists():
                conn = sqlite3.connect(db)
                try:
                    count = conn.execute(
                        "SELECT COUNT(*) FROM pairing_attempt"
                    ).fetchone()[0]
                    self.assertEqual(0, int(count))
                finally:
                    conn.close()
        finally:
            if proc.poll() is None and proc.stdin:
                proc.stdin.write(b"shutdown\n")
                proc.stdin.flush()
                proc.wait(timeout=10)
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream is not None:
                    stream.close()
        again = provision_or_load_identity(identity)
        self.assertFalse(again.created)
        self.assertEqual(
            result.cert_fingerprint_sha256, again.cert_fingerprint_sha256
        )


if __name__ == "__main__":
    unittest.main()
