import errno
import hashlib
import importlib.util
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parents[1] / "ops" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


reader = load("image_reader")
stage = load("image_stage")
SOURCE = "/nix/store/" + "0" * 32 + "-qcl-negf-compute-root/nixos.qcow2"
IMAGE = struct.pack(">4sI", b"QFI\xfb", 3) + bytes(96) + bytes(range(256)) * 4096


class BoundedOutput(io.BytesIO):
    largest = 0

    def write(self, data):
        self.largest = max(self.largest, len(data))
        return super().write(data)


class ImageTransferTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.source = self.directory / "source.qcow2"
        self.source.write_bytes(IMAGE)
        self.destination = self.directory / "import.qcow2"
        self.metadata = {
            "image_path": SOURCE,
            "image_sha256": hashlib.sha256(IMAGE).hexdigest(),
            "image_bytes": len(IMAGE),
        }

    def command(self, *, exit_code=0, truncate=0, extra=False, delay=False):
        code = "import pathlib,sys,time;data=pathlib.Path(sys.argv[1]).read_bytes();"
        code += f"sys.stdout.buffer.write(data[:len(data)-{truncate}]);sys.stdout.buffer.flush();"
        if extra:
            code += "sys.stdout.buffer.write(b'extra');sys.stdout.buffer.flush();"
        if delay:
            code += "time.sleep(10);"
        code += f"sys.exit({exit_code})"
        return [sys.executable, "-c", code, str(self.source)]

    def transfer(self, command=None, **kwargs):
        return stage.transfer_image(
            self.metadata, self.destination, command or self.command(), reserve_bytes=0, **kwargs
        )

    def assert_unpublished(self):
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.directory.glob(".qcl-image-*.partial")), [])

    def test_forced_reader_rejects_shell_commands_and_paths_outside_the_nix_store(self):
        self.assertEqual(reader.parse_command(f"qcl-negf-image-read {SOURCE}"), Path(SOURCE))
        for command in (
            f"cat {SOURCE}", f"qcl-negf-image-read {SOURCE}; id",
            "qcl-negf-image-read /etc/shadow", f"qcl-negf-image-read {SOURCE}/../secret",
            f"qcl-negf-image-read {SOURCE}\n", f"qcl-negf-image-read {SOURCE} extra",
        ):
            with self.subTest(command=command), self.assertRaises(ValueError):
                reader.parse_command(command)

    def test_reader_streams_native_bytes_in_bounded_chunks_and_rejects_symlinks(self):
        output = BoundedOutput()
        reader.stream_image(self.source, output)
        self.assertEqual(output.getvalue(), IMAGE)
        self.assertLessEqual(output.largest, 65536)
        link = self.directory / "link.qcow2"
        link.symlink_to(self.source)
        with self.assertRaises(ValueError):
            reader.stream_image(link, io.BytesIO())

    def test_v2_and_v3_headers_are_accepted_and_other_formats_rejected(self):
        for version in (2, 3):
            stage.validate_header(struct.pack(">4sI", b"QFI\xfb", version))
        for header in (b"not qcow", struct.pack(">4sI", b"QFI\xfb", 4)):
            with self.assertRaises(ValueError):
                stage.validate_header(header)

    def test_complete_stream_is_verified_and_existing_valid_image_is_not_copied(self):
        self.assertTrue(self.transfer())
        self.assertEqual(self.destination.read_bytes(), IMAGE)
        self.assertFalse(self.transfer(command=["a-command-that-must-not-run"]))

    def test_hash_mismatch_never_publishes_an_image(self):
        self.metadata["image_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            self.transfer()
        self.assert_unpublished()

    def test_truncated_extra_bytes_and_ssh_failure_never_publish(self):
        for command in (self.command(truncate=1), self.command(extra=True), self.command(exit_code=7)):
            with self.subTest(command=command), self.assertRaises((ValueError, RuntimeError)):
                self.transfer(command=command)
            self.assert_unpublished()

    def test_storage_failure_cleans_partial_file(self):
        with mock.patch.object(stage.os, "write", side_effect=OSError(errno.ENOSPC, "disk full")):
            with self.assertRaises(OSError):
                self.transfer()
        self.assert_unpublished()

    def test_transfer_timeout_cancels_process_and_cleans_partial_file(self):
        with self.assertRaises(TimeoutError):
            self.transfer(command=self.command(delay=True), timeout_seconds=0.1)
        self.assert_unpublished()

    def test_existing_collision_is_never_overwritten(self):
        self.destination.write_bytes(b"unmanaged content")
        with self.assertRaises(ValueError):
            self.transfer()
        self.assertEqual(self.destination.read_bytes(), b"unmanaged content")

    def test_directory_fsync_failure_rolls_back_new_publication(self):
        real_fsync = stage.os.fsync
        calls = 0

        def fail_directory(fd):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError(errno.EIO, "directory sync failed")
            return real_fsync(fd)

        with mock.patch.object(stage.os, "fsync", side_effect=fail_directory):
            with self.assertRaises(OSError):
                self.transfer()
        self.assert_unpublished()

    def test_source_ssh_options_pin_host_key_and_never_forward_an_agent(self):
        command = stage.ssh_command({
            "host": "builder.example.org", "user": "ci", "port": 22,
            "identity_file": "/root/.ssh/qcl-image-pull",
            "known_hosts_file": "/root/.ssh/qcl-image-pull-known_hosts",
        }, SOURCE)
        for expected in ("IdentityAgent=none", "ForwardAgent=no", "IdentitiesOnly=yes",
                         "StrictHostKeyChecking=yes", "BatchMode=yes"):
            self.assertIn(expected, command)
        self.assertEqual(command[-1], f"qcl-negf-image-read {SOURCE}")

    def test_staged_provider_inputs_drop_remote_local_paths_and_preserve_hashes(self):
        images = {role: self.metadata.copy() for role in stage.ROLES}
        base = {"vms": {role: {"vm_id": i, **self.metadata} for i, role in enumerate(stage.ROLES)}}
        prepared = stage.provider_inputs(base, images, "local")
        for role, vm in prepared["vms"].items():
            self.assertNotIn("image_path", vm)
            self.assertEqual(vm["image_sha256"], self.metadata["image_sha256"])
            self.assertEqual(vm["image_file_id"],
                             f"local:import/qcl-negf-{role}-{self.metadata['image_sha256']}.qcow2")
        self.assertIn("image_path", base["vms"]["storage"])
        del images["compute"]["image_bytes"]
        with self.assertRaises(ValueError):
            stage.provider_inputs(base, images, "local")

    def test_fresh_import_directory_is_planned_without_writes_then_created_once(self):
        directory = self.directory / "import"
        self.assertTrue(stage.prepare_import_directory(directory, create=False))
        self.assertFalse(directory.exists())
        with mock.patch.object(stage, "sync_directory", wraps=stage.sync_directory) as sync:
            self.assertTrue(stage.prepare_import_directory(directory, create=True))
            sync.assert_called_once_with(self.directory)
        self.assertTrue(directory.is_dir())
        self.assertEqual(directory.stat().st_mode & 0o777, 0o755)
        self.assertFalse(stage.prepare_import_directory(directory, create=True))

    def test_import_directory_rejects_symlinks_unsafe_base_and_other_names(self):
        directory = self.directory / "import"
        directory.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaises(ValueError):
            stage.prepare_import_directory(directory, create=True)
        directory.unlink()
        self.directory.chmod(0o777)
        with self.assertRaises(ValueError):
            stage.prepare_import_directory(directory, create=True)
        self.assertFalse(directory.exists())
        self.directory.chmod(0o700)
        with self.assertRaises(ValueError):
            stage.prepare_import_directory(self.directory / "foreign", create=True)

    def test_check_mode_reports_missing_import_directory_without_creating_it(self):
        images = {role: self.metadata.copy() for role in stage.ROLES}
        base = {"vms": {role: {} for role in stage.ROLES}}
        request = {"images": images, "base": base, "datastore": "local", "source": {
            "host": "builder.example.org", "user": "ci", "port": 22,
            "identity_file": "/root/.ssh/qcl-image-pull",
            "known_hosts_file": "/root/.ssh/qcl-image-pull-known_hosts",
        }}
        directory = self.directory / "import"

        def resolve_file(command, **_):
            return mock.Mock(stdout=str(directory / command[-1].split("/", 1)[1]))

        with mock.patch.object(stage.os, "geteuid", return_value=0), \
                mock.patch.object(stage, "require_private_file"), \
                mock.patch.object(stage.subprocess, "run", side_effect=resolve_file), \
                mock.patch.object(stage, "prepare_import_directory", return_value=True) as prepare:
            result = stage.run(request, check=True)
        self.assertTrue(result["changed"])
        self.assertTrue(result["checked"])
        self.assertEqual(result["create_import_directories"], [str(directory)])
        self.assertFalse(directory.exists())
        for call in prepare.call_args_list:
            self.assertEqual(call.kwargs, {"create": False})


if __name__ == "__main__":
    unittest.main()
