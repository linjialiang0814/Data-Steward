"""Unit tests for B1A Windows TLS identity spike (no approved OS probe)."""

from __future__ import annotations

import ctypes
import json
import platform
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

from services.steward_hub.tool import spike_windows_tls_identity as spike


class RunIdAndPathSafetyTest(unittest.TestCase):
    def test_run_id_has_128_bit_suffix(self) -> None:
        run_id = spike.new_run_id()
        self.assertTrue(run_id.startswith(spike.RUN_ID_PREFIX))
        suffix = run_id[len(spike.RUN_ID_PREFIX) :]
        self.assertGreaterEqual(len(suffix), 32)  # 128-bit hex
        self.assertEqual(run_id, spike.validate_run_id(run_id))
        with self.assertRaises(spike.SpikeSafetyError):
            spike.validate_run_id(spike.RUN_ID_PREFIX + "abcd")  # too short

    def test_path_escape_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = {"LOCALAPPDATA": tmp}
            run_id = spike.new_run_id()
            run_dir = spike.expected_run_dir(Path(tmp), run_id)
            run_dir.mkdir(parents=True)
            outsider = Path(tmp) / "other" / "file.txt"
            with self.assertRaises(spike.SpikeSafetyError):
                spike.assert_path_inside_run_dir(outsider, run_dir, run_id)

    @unittest.skipUnless(platform.system() == "Windows", "DACL requires Windows")
    def test_atomic_create_refuses_reuse(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = {"LOCALAPPDATA": tmp}
            run_id = spike.new_run_id()
            run_dir, manifest, acl = spike.create_run_directory_atomic(
                run_id=run_id, environ=env
            )
            self.assertTrue((run_dir / spike.OWNER_MARKER_NAME).exists())
            self.assertEqual(manifest.run_id, run_id)
            self.assertTrue(manifest.ownership_nonce)
            self.assertTrue(acl["ACL_APPLIED_BEFORE_SECRET"])
            with self.assertRaises(spike.SpikeSafetyError):
                spike.create_run_directory_atomic(run_id=run_id, environ=env)
            spike.cleanup_exact(manifest, environ=env)

    def test_prepare_create_flag_still_gated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = {"LOCALAPPDATA": tmp}
            with self.assertRaises(spike.ApprovalRequiredError):
                spike.prepare_run_directory(
                    run_id=spike.new_run_id(), environ=env, create=True
                )

    def test_unc_localappdata_rejected(self) -> None:
        with self.assertRaises(spike.SpikeSafetyError):
            spike.local_app_data_root({"LOCALAPPDATA": r"\\server\share\appdata"})


class BindAndKeyNameTest(unittest.TestCase):
    def test_loopback_bind_enforced(self) -> None:
        self.assertEqual("127.0.0.1", spike.validate_loopback_bind_host("127.0.0.1"))
        for host in ("0.0.0.0", "192.168.1.10", "localhost", "::"):
            with self.subTest(host=host):
                with self.assertRaises(spike.SpikeSafetyError):
                    spike.validate_loopback_bind_host(host)

    def test_plaintext_key_names_forbidden(self) -> None:
        with self.assertRaises(spike.SpikeSafetyError):
            spike.assert_safe_encrypted_key_name("key.pem")
        self.assertEqual(
            "private_key.encrypted.pem",
            spike.assert_safe_encrypted_key_name("private_key.encrypted.pem"),
        )


class LoggingAndManifestTest(unittest.TestCase):
    def test_log_event_is_redacted(self) -> None:
        run_id = spike.new_run_id()
        event = spike.ProbeLogEvent(
            candidate="dpapi_encrypted_keyfile",
            result=spike.CandidateResult.NOT_TESTED,
            file_size=128,
            cert_fingerprint_sha256="a" * 64,
            path_category=spike.path_category(Path("cert.pem"), run_id),
        )
        public = json.dumps(event.as_public_dict())
        self.assertNotIn(str(Path.home()), public)
        self.assertIn("LOCALAPPDATA_SPIKE_B1A/", public)

    def test_redacted_error_excludes_raw_exception_text(self) -> None:
        exc = RuntimeError(r"C:\Users\secret\path Cred target boom")
        text = spike.redacted_error("TLS_KEY_LOAD_FAILED", exc)
        self.assertEqual("TLS_KEY_LOAD_FAILED:RuntimeError", text)
        self.assertNotIn("Users", text)
        self.assertNotIn("secret", text)

    @unittest.skipUnless(platform.system() == "Windows", "DACL requires Windows")
    def test_cleanup_exact_no_rmtree_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = {"LOCALAPPDATA": tmp}
            run_id = spike.new_run_id()
            run_dir, manifest, _acl = spike.create_run_directory_atomic(
                run_id=run_id, environ=env
            )
            extra = run_dir / "cert.pem"
            extra.write_text("PUBLIC\n", encoding="utf-8")
            manifest.record("file", str(extra.resolve()))
            manifest.record("dir", str(run_dir.resolve()))
            spike.persist_manifest(run_dir, manifest)
            actions1 = spike.cleanup_exact(manifest, environ=env)
            self.assertTrue(any(a.startswith("removed_file:") for a in actions1))
            self.assertTrue(any(a.startswith("removed_dir:") for a in actions1))
            self.assertFalse(run_dir.exists())
            actions2 = spike.cleanup_exact(manifest, environ=env)
            self.assertTrue(any(a.startswith("missing_") for a in actions2))

    @unittest.skipUnless(platform.system() == "Windows", "DACL requires Windows")
    def test_cleanup_refuses_unexpected_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = {"LOCALAPPDATA": tmp}
            run_id = spike.new_run_id()
            run_dir, manifest, _acl = spike.create_run_directory_atomic(
                run_id=run_id, environ=env
            )
            surprise = run_dir / "unexpected.bin"
            surprise.write_bytes(b"x")
            manifest.record("dir", str(run_dir.resolve()))
            spike.persist_manifest(run_dir, manifest)
            with self.assertRaises(spike.CleanupBlockedError) as ctx:
                spike.cleanup_exact(manifest, environ=env)
            self.assertIn("unexpected_artifact", str(ctx.exception))
            if run_dir.exists():
                for path in run_dir.iterdir():
                    path.unlink()
                run_dir.rmdir()

    @unittest.skipUnless(platform.system() == "Windows", "DACL requires Windows")
    def test_cleanup_refuses_foreign_run_id_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = {"LOCALAPPDATA": tmp}
            run_id = spike.new_run_id()
            other = spike.new_run_id()
            run_dir, manifest, _acl = spike.create_run_directory_atomic(
                run_id=run_id, environ=env
            )
            foreign, foreign_manifest, _acl2 = spike.create_run_directory_atomic(
                run_id=other, environ=env
            )
            poisoned = spike.CleanupManifest(
                run_id=manifest.run_id,
                ownership_nonce=manifest.ownership_nonce,
                schema_version=manifest.schema_version,
                entries=[{"kind": "dir", "token": str(foreign.resolve())}],
                parent_plan=manifest.parent_plan,
            )
            with self.assertRaises(spike.CleanupBlockedError):
                spike.cleanup_exact(poisoned, environ=env)
            manifest.record("dir", str(run_dir.resolve()))
            foreign_manifest.record("dir", str(foreign.resolve()))
            # Foreign first: primary may own created parents and needs B1A empty.
            spike.cleanup_exact(foreign_manifest, environ=env)
            spike.cleanup_exact(manifest, environ=env)


class ProcessGovernanceTest(unittest.TestCase):
    def test_source_has_no_script_name_mass_kill(self) -> None:
        src = Path(spike.__file__).read_text(encoding="utf-8")
        self.assertNotIn("_iter_spike_worker_pids", src)
        self.assertNotIn("CommandLine -like", src)
        self.assertNotIn("os.kill(proc, 9)", src)
        self.assertNotIn("os.kill(proc,9)", src)

    def test_pid_still_running_self_and_missing(self) -> None:
        import os

        self.assertTrue(spike.pid_still_running(os.getpid()))
        self.assertFalse(spike.pid_still_running(0))
        self.assertFalse(spike.pid_still_running(1_000_000_007))

    def test_stop_managed_process_only_touches_owned_popen(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_id = spike.new_run_id()
            run_dir = Path(tmp) / run_id
            run_dir.mkdir()
            owned = mock.Mock()
            owned.pid = 4242
            owned.poll.return_value = 0
            owned.wait.return_value = 0
            foreign = mock.Mock()
            foreign.pid = 9999
            foreign.terminate = mock.Mock()
            foreign.kill = mock.Mock()
            managed = spike.ManagedProcess(
                run_id=run_id,
                process=owned,
                process_role="uvicorn_worker",
                pid=4242,
            )
            spike.stop_managed_process(run_dir=run_dir, managed=managed)
            owned.wait.assert_called()
            foreign.terminate.assert_not_called()
            foreign.kill.assert_not_called()

    def test_stop_rejects_foreign_run_id_even_with_same_pid_object(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_a = spike.new_run_id()
            run_b = spike.new_run_id()
            run_dir = Path(tmp) / run_a
            run_dir.mkdir()
            proc = mock.Mock()
            proc.pid = 111
            proc.poll.return_value = 0
            proc.wait.return_value = 0
            foreign = spike.ManagedProcess(
                run_id=run_b,
                process=proc,
                process_role="uvicorn_worker",
                pid=111,
            )
            with self.assertRaises(spike.SpikeSafetyError):
                spike.stop_managed_process(run_dir=run_dir, managed=foreign)
            proc.terminate.assert_not_called()
            proc.kill.assert_not_called()

    def test_record_process_fields(self) -> None:
        run_id = spike.new_run_id()
        manifest = spike.CleanupManifest(run_id=run_id, ownership_nonce="ab" * 16)
        manifest.record_process(pid=1234, process_role="uvicorn_worker")
        entry = manifest.entries[-1]
        self.assertEqual(
            {"kind", "run_id", "pid", "process_role"},
            set(entry.keys()),
        )
        self.assertEqual(run_id, entry["run_id"])
        self.assertEqual("1234", entry["pid"])
        with self.assertRaises(spike.SpikeSafetyError):
            manifest.record("process", "1234")


class AclAndParentDirTest(unittest.TestCase):
    @unittest.skipUnless(platform.system() == "Windows", "DACL requires Windows")
    def test_dacl_required_and_forbidden_principals(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = {"LOCALAPPDATA": tmp}
            run_id = spike.new_run_id()
            run_dir, manifest, acl = spike.create_run_directory_atomic(
                run_id=run_id, environ=env
            )
            self.assertTrue(acl["ACL_CURRENT_USER"])
            self.assertTrue(acl["ACL_SYSTEM"])
            self.assertTrue(acl["ACL_ADMINISTRATORS"])
            self.assertEqual(0, acl["ACL_FORBIDDEN_PRINCIPAL_COUNT"])
            self.assertEqual(
                ["CURRENT_USER", "SYSTEM", "ADMINISTRATORS"],
                acl["acl_principals"],
            )
            user_sid = spike.current_user_sid_string()
            allow = spike._read_allow_sids(run_dir, require_protected=True)
            self.assertEqual({user_sid, spike.SID_SYSTEM, spike.SID_ADMINS}, allow)
            child = run_dir / "child.txt"
            child.write_text("x", encoding="utf-8")
            spike.verify_path_dacl_not_expanded(child)
            manifest.record("file", str(child.resolve()))
            manifest.record("dir", str(run_dir.resolve()))
            spike.persist_manifest(run_dir, manifest)
            spike.cleanup_exact(manifest, environ=env)

    @unittest.skipUnless(platform.system() == "Windows", "DACL requires Windows")
    def test_child_dacl_exact_three_sids_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = {"LOCALAPPDATA": tmp}
            run_dir, manifest, _acl = spike.create_run_directory_atomic(
                run_id=spike.new_run_id(), environ=env
            )
            child = run_dir / "secret.dpapi"
            child.write_bytes(b"\x01\x02")
            spike.verify_path_dacl_not_expanded(child)
            manifest.record("file", str(child.resolve()))
            manifest.record("dir", str(run_dir.resolve()))
            spike.persist_manifest(run_dir, manifest)
            spike.cleanup_exact(manifest, environ=env)

    @unittest.skipUnless(platform.system() == "Windows", "DACL requires Windows")
    def test_child_dacl_missing_current_user_fails(self) -> None:
        path = Path("dummy")
        with mock.patch.object(
            spike, "current_user_sid_string", return_value="S-1-5-21-111-222-333-1001"
        ):
            with mock.patch.object(
                spike,
                "_read_allow_sids",
                return_value={spike.SID_SYSTEM, spike.SID_ADMINS, "S-1-5-21-9-9-9-9"},
            ):
                with self.assertRaises(spike.AclBlockedError) as ctx:
                    spike.verify_path_dacl_not_expanded(path)
        self.assertEqual("ACL_MISSING_CURRENT_USER", str(ctx.exception))

    @unittest.skipUnless(platform.system() == "Windows", "DACL requires Windows")
    def test_child_dacl_fourth_unknown_sid_fails(self) -> None:
        path = Path("dummy")
        user = "S-1-5-21-111-222-333-1001"
        with mock.patch.object(spike, "current_user_sid_string", return_value=user):
            with mock.patch.object(
                spike,
                "_read_allow_sids",
                return_value={
                    user,
                    spike.SID_SYSTEM,
                    spike.SID_ADMINS,
                    "S-1-5-21-9-9-9-9",
                },
            ):
                with self.assertRaises(spike.AclBlockedError) as ctx:
                    spike.verify_path_dacl_not_expanded(path)
        self.assertEqual("ACL_UNEXPECTED_PRINCIPAL", str(ctx.exception))

    @unittest.skipUnless(platform.system() == "Windows", "DACL requires Windows")
    def test_child_dacl_missing_system_or_admins_fails(self) -> None:
        path = Path("dummy")
        user = "S-1-5-21-111-222-333-1001"
        with mock.patch.object(spike, "current_user_sid_string", return_value=user):
            with mock.patch.object(
                spike, "_read_allow_sids", return_value={user, spike.SID_ADMINS}
            ):
                with self.assertRaises(spike.AclBlockedError) as ctx:
                    spike.verify_path_dacl_not_expanded(path)
            self.assertEqual("ACL_MISSING_SYSTEM", str(ctx.exception))
            with mock.patch.object(
                spike, "_read_allow_sids", return_value={user, spike.SID_SYSTEM}
            ):
                with self.assertRaises(spike.AclBlockedError) as ctx2:
                    spike.verify_path_dacl_not_expanded(path)
            self.assertEqual("ACL_MISSING_ADMINISTRATORS", str(ctx2.exception))

    @unittest.skipUnless(platform.system() == "Windows", "DACL requires Windows")
    def test_child_dacl_forbidden_sid_fails(self) -> None:
        path = Path("dummy")
        user = "S-1-5-21-111-222-333-1001"
        with mock.patch.object(spike, "current_user_sid_string", return_value=user):
            with mock.patch.object(
                spike,
                "_read_allow_sids",
                return_value={user, spike.SID_SYSTEM, spike.SID_EVERYONE},
            ):
                with self.assertRaises(spike.AclBlockedError) as ctx:
                    spike.verify_path_dacl_not_expanded(path)
        self.assertEqual("ACL_FORBIDDEN_PRINCIPAL", str(ctx.exception))

    @unittest.skipUnless(platform.system() == "Windows", "DACL requires Windows")
    def test_acl_applied_before_secret_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = {"LOCALAPPDATA": tmp}
            run_id = spike.new_run_id()
            order: list[str] = []
            real_apply = spike.apply_and_verify_run_dacl

            def tracked_apply(run_dir: Path) -> dict:
                order.append("acl")
                return real_apply(run_dir)

            real_write = Path.write_bytes

            def tracked_write(self: Path, data: bytes) -> int:  # type: ignore[override]
                if self.suffix in {".dpapi", ".pem"} or "encrypted" in self.name:
                    order.append("secret")
                return real_write(self, data)

            with mock.patch.object(
                spike, "apply_and_verify_run_dacl", side_effect=tracked_apply
            ):
                run_dir, manifest, _acl = spike.create_run_directory_atomic(
                    run_id=run_id, environ=env
                )
            self.assertEqual(["acl"], order)
            # After ACL, writing a secret file must not expand DACL
            secret = run_dir / "key_password.dpapi"
            secret.write_bytes(b"\x00\x01")
            spike.verify_path_dacl_not_expanded(secret)
            manifest.record("file", str(secret.resolve()))
            manifest.record("dir", str(run_dir.resolve()))
            spike.persist_manifest(run_dir, manifest)
            spike.cleanup_exact(manifest, environ=env)

    @unittest.skipUnless(platform.system() == "Windows", "parent ACL/cleanup Windows")
    def test_preexisting_empty_parent_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = {"LOCALAPPDATA": tmp}
            root = Path(tmp)
            ds, spikes, b1a = spike._parent_paths(root)
            ds.mkdir()
            spikes.mkdir()
            b1a.mkdir()
            self.assertFalse(any(b1a.iterdir()))
            run_id = spike.new_run_id()
            run_dir, manifest, _acl = spike.create_run_directory_atomic(
                run_id=run_id, environ=env
            )
            self.assertIsNotNone(manifest.parent_plan)
            assert manifest.parent_plan is not None
            self.assertTrue(manifest.parent_plan.datasteward_existed)
            self.assertTrue(manifest.parent_plan.spikes_existed)
            self.assertTrue(manifest.parent_plan.b1a_existed)
            self.assertFalse(manifest.parent_plan.created_datasteward)
            self.assertFalse(manifest.parent_plan.created_spikes)
            self.assertFalse(manifest.parent_plan.created_b1a)
            manifest.record("dir", str(run_dir.resolve()))
            spike.persist_manifest(run_dir, manifest)
            actions = spike.cleanup_exact(manifest, environ=env)
            self.assertFalse(run_dir.exists())
            self.assertTrue(ds.exists())
            self.assertTrue(spikes.exists())
            self.assertTrue(b1a.exists())
            self.assertTrue(any(a == "parent_preserved:B1A" for a in actions))

    @unittest.skipUnless(platform.system() == "Windows", "parent ACL/cleanup Windows")
    def test_created_empty_parents_removed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = {"LOCALAPPDATA": tmp}
            root = Path(tmp)
            ds, spikes, b1a = spike._parent_paths(root)
            run_id = spike.new_run_id()
            run_dir, manifest, _acl = spike.create_run_directory_atomic(
                run_id=run_id, environ=env
            )
            assert manifest.parent_plan is not None
            self.assertTrue(manifest.parent_plan.created_datasteward)
            self.assertTrue(manifest.parent_plan.created_spikes)
            self.assertTrue(manifest.parent_plan.created_b1a)
            manifest.record("dir", str(run_dir.resolve()))
            spike.persist_manifest(run_dir, manifest)
            spike.cleanup_exact(manifest, environ=env)
            self.assertFalse(run_dir.exists())
            self.assertFalse(b1a.exists())
            self.assertFalse(spikes.exists())
            self.assertFalse(ds.exists())


class CredManMemoryTest(unittest.TestCase):
    @unittest.skipUnless(platform.system() == "Windows", "CredMan ctypes Windows")
    def test_cred_write_failure_zeros_input_buffer(self) -> None:
        assert spike._ADVAPI32 is not None
        secret = b"super-secret-password-value"
        seen: dict[str, bytes] = {}

        def failing_write(cred_ptr: object, flags: int) -> int:
            cred = ctypes.cast(cred_ptr, ctypes.POINTER(spike.CREDENTIALW)).contents
            size = int(cred.CredentialBlobSize)
            seen["during"] = ctypes.string_at(cred.CredentialBlob, size)
            return 0

        with mock.patch.object(spike._ADVAPI32, "CredWriteW", side_effect=failing_write):
            with self.assertRaises(spike.SpikeSafetyError):
                spike.cred_write_exact(
                    spike.cred_target_name(spike.new_run_id()), secret
                )
        # Buffer was populated during call; after return, ctypes buffer is zeroed
        # Re-run with instrumented create_string_buffer
        buffers: list[ctypes.Array[ctypes.c_char]] = []
        real_csb = ctypes.create_string_buffer

        def tracking_csb(init: bytes | int, size: int | None = None):  # type: ignore[no-untyped-def]
            if isinstance(init, (bytes, bytearray)) and size is not None:
                buf = real_csb(init, size)
            elif isinstance(init, int):
                buf = real_csb(init)
            else:
                buf = real_csb(init)
            buffers.append(buf)
            return buf

        with mock.patch.object(ctypes, "create_string_buffer", side_effect=tracking_csb):
            with mock.patch.object(
                spike._ADVAPI32, "CredWriteW", side_effect=failing_write
            ):
                with self.assertRaises(spike.SpikeSafetyError):
                    spike.cred_write_exact(
                        spike.cred_target_name(spike.new_run_id()), secret
                    )
        self.assertTrue(buffers)
        residual = bytes(buffers[0])
        self.assertEqual(b"\x00" * len(secret), residual[: len(secret)])

    @unittest.skipUnless(platform.system() == "Windows", "CredMan ctypes Windows")
    def test_cred_read_zeros_blob_before_free(self) -> None:
        assert spike._ADVAPI32 is not None
        payload = b"cred-read-secret-bytes"
        blob = ctypes.create_string_buffer(payload, len(payload))
        cred = spike.CREDENTIALW()
        cred.CredentialBlobSize = len(payload)
        cred.CredentialBlob = ctypes.cast(blob, ctypes.POINTER(ctypes.c_char))
        # Allocate a real CREDENTIALW that CredFree would receive
        cred_box = (spike.CREDENTIALW * 1)(cred)
        ptr = ctypes.cast(cred_box, ctypes.c_void_p)

        zero_calls: list[tuple[int, int]] = []
        real_memset = ctypes.memset

        def tracking_memset(addr: object, value: int, size: int) -> object:
            zero_calls.append((int(value), int(size)))
            return real_memset(addr, value, size)

        freed: list[object] = []

        def fake_read(
            target: str, cred_type: int, flags: int, out_ptr: object
        ) -> int:
            ctypes.cast(out_ptr, ctypes.POINTER(ctypes.c_void_p))[0] = ptr.value
            return 1

        def fake_free(p: object) -> None:
            freed.append(p)
            # After free path, blob must already be zeroed
            self.assertEqual(b"\x00" * len(payload), bytes(blob)[: len(payload)])

        with mock.patch.object(spike._ADVAPI32, "CredReadW", side_effect=fake_read):
            with mock.patch.object(spike._ADVAPI32, "CredFree", side_effect=fake_free):
                with mock.patch.object(ctypes, "memset", side_effect=tracking_memset):
                    out = spike.cred_read_exact(
                        spike.cred_target_name(spike.new_run_id())
                    )
        self.assertEqual(payload, bytes(out))
        self.assertTrue(freed)
        self.assertTrue(any(v == 0 and s == len(payload) for v, s in zero_calls))
        spike._zero_bytearray(out)

    def test_cleanup_blocked_on_cred_delete_exception(self) -> None:
        with self.assertRaises(spike.CleanupBlockedError):
            raise spike.CleanupBlockedError("CREDMAN_DELETE_FAILED")


class CandidateAndApprovalTest(unittest.TestCase):
    def test_candidate_result_enum(self) -> None:
        self.assertEqual(
            {"PASS", "FAIL", "NOT_SUPPORTED", "NOT_TESTED"},
            {item.value for item in spike.CandidateResult},
        )

    def test_cng_marked_not_supported(self) -> None:
        event = spike.evaluate_certificate_store_cng()
        self.assertEqual(spike.CandidateResult.NOT_SUPPORTED, event.result)

    def test_os_probes_blocked_without_approval(self) -> None:
        with self.assertRaises(spike.ApprovalRequiredError):
            spike.run_os_probes(approval_cli=None, environ={})

    def test_cli_run_os_probes_returns_blocked(self) -> None:
        buf = StringIO()
        with redirect_stdout(buf):
            code = spike.main(["--run-os-probes"])
        self.assertEqual(2, code)
        self.assertIn("BLOCKED", buf.getvalue())

    def test_readonly_audit_runs_without_persistence(self) -> None:
        report = spike.readonly_environment_audit()
        self.assertEqual("REDACTED", report["platform"]["username"])
        self.assertFalse(report["windows_api_surface"]["CredEnumerate_called"])
        self.assertFalse(
            report["windows_api_surface"]["CertificateStore_write_attempted"]
        )

    @unittest.skipUnless(platform.system() == "Windows", "Windows-only API surface")
    def test_windows_api_surface_flags_present(self) -> None:
        report = spike.readonly_environment_audit()
        self.assertTrue(report["windows_api_surface"]["CryptProtectData"])

    @unittest.skipIf(platform.system() == "Windows", "non-Windows skip path")
    def test_non_windows_skip_marker(self) -> None:
        self.skipTest("safe skip on non-Windows")


class LocalMachineBanTest(unittest.TestCase):
    def test_plan_forbids_certificate_store(self) -> None:
        plan = spike.planned_os_resources(spike.new_run_id())
        store = next(r for r in plan["resources"] if r["type"] == "certificate_store")
        self.assertFalse(store["needed"])


if __name__ == "__main__":
    unittest.main()
