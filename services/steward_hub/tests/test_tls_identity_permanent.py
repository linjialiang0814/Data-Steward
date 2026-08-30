"""B2B-B2/R1 permanent identity tests (hermetic + read-only real checks)."""

from __future__ import annotations

import os
import platform
import subprocess
import tempfile
import unittest
from pathlib import Path

from steward_hub.https_runtime import validate_loopback_bind_host
from steward_hub.tls_identity import (
    TlsPermanentPathError,
    TlsProvisionError,
    audit_permanent_identity_tree,
    file_content_digests,
    file_mtimes_ns,
    load_tls_identity,
    permanent_hub_parent,
    permanent_identity_root,
    permanent_product_base,
    preflight_permanent_identity_parents,
    provision_or_load_permanent_identity,
    set_local_app_data_resolver_for_tests,
)
from steward_hub.tls_identity.dacl import apply_and_verify_identity_dacl
from steward_hub.tls_identity.permanent_paths import (
    HUB_DIR_NAME,
    IDENTITY_DIR_NAME,
    PRODUCT_DIR_NAME,
    STEADY_STATE_FILES,
    local_app_data_root,
)
from steward_hub.tls_identity.provisioner import (
    OWNER_FILENAME,
    count_transient_siblings,
)


def _snapshot_real_identity() -> tuple[bool, dict[str, str] | None, dict[str, int] | None]:
    """Read-only snapshot of the real Known Folder identity (resolver cleared)."""
    set_local_app_data_resolver_for_tests(None)
    root = permanent_identity_root()
    if not root.exists():
        return False, None, None
    return True, file_content_digests(), file_mtimes_ns()


@unittest.skipUnless(platform.system() == "Windows", "permanent identity is Windows-only")
class PermanentIdentityTest(unittest.TestCase):
    def tearDown(self) -> None:
        set_local_app_data_resolver_for_tests(None)

    def test_product_bootstrap_rejects_path_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "override"
            with self.assertRaises(TlsPermanentPathError) as ctx:
                provision_or_load_permanent_identity(identity_root=fake)
            self.assertEqual("permanent_path_override_forbidden", ctx.exception.args[0])
            with self.assertRaises(TlsPermanentPathError):
                provision_or_load_permanent_identity(something="x")  # type: ignore[arg-type]

    def test_localappdata_env_tamper_ignored_by_known_folder(self) -> None:
        set_local_app_data_resolver_for_tests(None)
        before = local_app_data_root()
        with tempfile.TemporaryDirectory() as tmp:
            previous = os.environ.get("LOCALAPPDATA")
            os.environ["LOCALAPPDATA"] = tmp
            try:
                after = local_app_data_root()
                identity = permanent_identity_root()
            finally:
                if previous is None:
                    os.environ.pop("LOCALAPPDATA", None)
                else:
                    os.environ["LOCALAPPDATA"] = previous
        self.assertEqual(before, after)
        self.assertEqual(IDENTITY_DIR_NAME, identity.name)
        self.assertNotEqual(Path(tmp), after)

    def test_non_loopback_host_rejected(self) -> None:
        validate_loopback_bind_host("127.0.0.1")
        with self.assertRaises(ValueError):
            validate_loopback_bind_host("0.0.0.0")
        with self.assertRaises(ValueError):
            validate_loopback_bind_host("192.168.1.1")

    def test_reparse_fixture_rejected_by_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "real"
            target.mkdir()
            link = root / "reparse"
            created = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(link), str(target)],
                capture_output=True,
                text=True,
                check=False,
            )
            if created.returncode != 0 or not link.exists():
                self.skipTest("junction unavailable")
            try:
                set_local_app_data_resolver_for_tests(lambda: link)
                identity = permanent_identity_root()
                with self.assertRaises(TlsPermanentPathError) as ctx:
                    preflight_permanent_identity_parents(identity)
                self.assertEqual("permanent_parent_reparse", ctx.exception.args[0])
            finally:
                set_local_app_data_resolver_for_tests(None)
                if link.exists():
                    link.rmdir()

    def test_real_permanent_identity_read_only_when_present(self) -> None:
        """Optional integration: read-only audit/load only; never provision/recover."""
        set_local_app_data_resolver_for_tests(None)
        identity = permanent_identity_root()
        if not identity.exists():
            self.skipTest("permanent identity root absent")
        before_digests = file_content_digests()
        before_mtimes = file_mtimes_ns()
        loaded = load_tls_identity(identity)
        audit = audit_permanent_identity_tree()
        after_digests = file_content_digests()
        after_mtimes = file_mtimes_ns()
        self.assertEqual(before_digests, after_digests)
        self.assertEqual(before_mtimes, after_mtimes)
        self.assertEqual(64, len(loaded.cert_fingerprint_sha256))
        self.assertTrue(audit["loader_ok"])
        self.assertEqual(0, audit["directories"]["tls-identity-v1"]["owner_marker"])
        blob = str(audit)
        self.assertNotIn("C:\\Users\\", blob)
        self.assertNotIn("/Users/", blob)
        # Must not call provision_or_load_permanent_identity in this test.

    def test_hermetic_bootstrap_idempotent_in_temp_known_folder(self) -> None:
        existed, real_digests, real_mtimes = _snapshot_real_identity()
        real_root = permanent_identity_root()
        with tempfile.TemporaryDirectory() as tmp:
            kf = Path(tmp)
            set_local_app_data_resolver_for_tests(lambda: kf)
            self.assertNotEqual(real_root, permanent_identity_root())
            first = provision_or_load_permanent_identity()
            self.assertTrue(first.created)
            digests = file_content_digests()
            mtimes = file_mtimes_ns()
            second = provision_or_load_permanent_identity()
            self.assertFalse(second.created)
            self.assertEqual(first.hub_id, second.hub_id)
            self.assertEqual(
                first.cert_fingerprint_sha256, second.cert_fingerprint_sha256
            )
            self.assertEqual(digests, file_content_digests())
            self.assertEqual(mtimes, file_mtimes_ns())
            identity = permanent_identity_root()
            self.assertEqual(
                sorted(STEADY_STATE_FILES),
                sorted(p.name for p in identity.iterdir()),
            )
            self.assertFalse((identity / OWNER_FILENAME).exists())
            self.assertEqual(0, count_transient_siblings(permanent_hub_parent()))
            audit = audit_permanent_identity_tree()
            self.assertTrue(audit["loader_ok"])
        set_local_app_data_resolver_for_tests(None)
        self.assertEqual(existed, real_root.exists())
        if existed:
            self.assertEqual(real_digests, file_content_digests())
            self.assertEqual(real_mtimes, file_mtimes_ns())
        else:
            self.assertFalse(real_root.exists())

    def test_identity_audit_allows_only_known_hub_component_siblings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            set_local_app_data_resolver_for_tests(lambda: Path(tmp))
            provision_or_load_permanent_identity()
            hub = permanent_hub_parent()
            (hub / "steward.sqlite3").write_bytes(b"sqlite-fixture")
            (hub / "file-scope-v1").mkdir()
            (hub / "organizer-v1").mkdir()

            self.assertTrue(audit_permanent_identity_tree()["loader_ok"])

            unknown = hub / "unexpected-component"
            unknown.mkdir()
            with self.assertRaisesRegex(TlsPermanentPathError, "hub_contents_invalid"):
                audit_permanent_identity_tree()

    def test_hermetic_product_exists_without_identity_stays_isolated(self) -> None:
        """Temp DataSteward/hub present without identity must not touch real KF."""
        existed, real_digests, real_mtimes = _snapshot_real_identity()
        real_root = permanent_identity_root()
        real_product = permanent_product_base()
        with tempfile.TemporaryDirectory() as tmp:
            kf = Path(tmp)
            set_local_app_data_resolver_for_tests(lambda: kf)
            product = kf / PRODUCT_DIR_NAME
            hub = product / HUB_DIR_NAME
            product.mkdir()
            apply_and_verify_identity_dacl(product)
            hub.mkdir()
            apply_and_verify_identity_dacl(hub)
            self.assertFalse(permanent_identity_root().exists())
            # Bootstrap under injected KF only.
            result = provision_or_load_permanent_identity()
            self.assertTrue(result.created)
            self.assertTrue(permanent_identity_root().exists())
            self.assertTrue(str(permanent_identity_root()).startswith(str(kf)))
        set_local_app_data_resolver_for_tests(None)
        self.assertEqual(existed, real_root.exists())
        self.assertEqual(real_product.exists(), permanent_product_base().exists())
        if existed:
            self.assertEqual(real_digests, file_content_digests())
            self.assertEqual(real_mtimes, file_mtimes_ns())
        else:
            self.assertFalse(real_root.exists())

    def test_recovery_failure_fully_redacted_exception_chain(self) -> None:
        """Primary + recovery both fail: no cause chain, redacted note only."""
        existed, real_digests, real_mtimes = _snapshot_real_identity()
        real_root = permanent_identity_root()
        with tempfile.TemporaryDirectory() as tmp:
            kf = Path(tmp)
            set_local_app_data_resolver_for_tests(lambda: kf)
            product = kf / PRODUCT_DIR_NAME
            hub = product / HUB_DIR_NAME
            identity = hub / IDENTITY_DIR_NAME
            product.mkdir()
            apply_and_verify_identity_dacl(product)
            hub.mkdir()
            apply_and_verify_identity_dacl(hub)
            identity.mkdir()
            apply_and_verify_identity_dacl(identity)
            # Corrupt steady-state-shaped fixture (load/recovery must fail-closed).
            for name in STEADY_STATE_FILES:
                (identity / name).write_bytes(b"not-valid-identity-material")
            before = {name: (identity / name).read_bytes() for name in STEADY_STATE_FILES}
            with self.assertRaises((TlsProvisionError, TlsPermanentPathError)) as ctx:
                provision_or_load_permanent_identity()
            exc = ctx.exception
            self.assertIsNone(exc.__cause__)
            self.assertTrue(exc.__suppress_context__)
            notes = list(getattr(exc, "__notes__", []))
            self.assertTrue(notes)
            for note in notes:
                self.assertRegex(note, r"^PERMANENT_RECOVERY:[A-Za-z_][A-Za-z0-9_]*$")
                self.assertNotIn(str(kf), note)
                self.assertNotIn("C:\\Users\\", note)
                self.assertNotIn("not-valid-identity-material", note)
                for name in STEADY_STATE_FILES:
                    self.assertNotIn(name, note)
            msg = " ".join(str(a) for a in exc.args) + " " + " ".join(notes)
            self.assertNotIn(str(kf), msg)
            self.assertNotIn("C:\\Users\\", msg)
            self.assertNotIn("not-valid-identity-material", msg)
            for name in STEADY_STATE_FILES:
                self.assertNotIn(name, msg)
            after = {name: (identity / name).read_bytes() for name in STEADY_STATE_FILES}
            self.assertEqual(before, after)
            self.assertTrue(identity.exists())
            # No second identity regenerated beside fixture.
            self.assertEqual(
                sorted(STEADY_STATE_FILES),
                sorted(p.name for p in identity.iterdir()),
            )
        set_local_app_data_resolver_for_tests(None)
        self.assertEqual(existed, real_root.exists())
        if existed:
            self.assertEqual(real_digests, file_content_digests())
            self.assertEqual(real_mtimes, file_mtimes_ns())
        else:
            self.assertFalse(real_root.exists())


if __name__ == "__main__":
    unittest.main()
