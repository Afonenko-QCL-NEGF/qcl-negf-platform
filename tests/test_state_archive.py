import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "state_archive", Path(__file__).parents[1] / "ops" / "state_archive.py"
)
archive = importlib.util.module_from_spec(spec)
spec.loader.exec_module(archive)


class StateArchiveTests(unittest.TestCase):
    def fixture(self, root):
        sources = {"aiida": root / "profile", "slurm": root / "slurm"}
        for source in sources.values():
            source.mkdir()
        (sources["aiida"] / "repository").mkdir()
        (sources["aiida"] / ".hidden-config").write_bytes(b"profile")
        (sources["aiida"] / "repository" / "object").write_bytes(bytes(range(256)))
        (sources["slurm"] / "state").write_bytes(b"queue")
        dump = root / "dump"
        dump.write_bytes(b"PGDMP test fixture")
        staging = root / "staging"
        staging.mkdir()
        metadata = {"source_revision": "a" * 40, "database": "qcl-negf", "postgresql_version_num": "170006"}
        return sources, dump, staging / "controller.tar.gz", metadata

    def test_complete_local_state_archive_verifies_and_restores_exact_fixture_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources, dump, output, metadata = self.fixture(root)
            archive.pack(output, sources, dump, metadata, 256 * 1024**2)
            manifest = archive.verify(output)
            self.assertEqual(manifest["offhost_backup"], "not_copied")
            self.assertEqual(manifest["nfs_data"], "not_included")
            restored = root / "restored"
            with tarfile.open(output) as handle:
                handle.extractall(restored, filter="data")
            for name, source in archive.source_files(sources).items():
                self.assertEqual((restored / name).read_bytes(), source.read_bytes())
            self.assertEqual((restored / "postgresql.dump").read_bytes(), dump.read_bytes())
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_retention_and_budget_fail_without_deleting_previous_good_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            sources, dump, output, metadata = self.fixture(Path(directory))
            with self.assertRaisesRegex(ValueError, "budget"):
                archive.pack(output, sources, dump, metadata, 1)
            self.assertFalse(output.exists())
            archive.pack(output, sources, dump, metadata, 256 * 1024**2)
            original = output.read_bytes()
            with self.assertRaisesRegex(ValueError, "Retention"):
                archive.pack(output.with_name("next.tar.gz"), sources, dump, metadata, 256 * 1024**2)
            self.assertEqual(output.read_bytes(), original)
            archive.verify(output)

    def test_corrupt_archive_and_unsupported_source_fail_explicitly(self):
        with tempfile.TemporaryDirectory() as directory:
            sources, dump, output, metadata = self.fixture(Path(directory))
            (sources["aiida"] / "external").symlink_to(dump)
            with self.assertRaisesRegex(ValueError, "omit"):
                archive.pack(output, sources, dump, metadata, 256 * 1024**2)
            (sources["aiida"] / "external").unlink()
            archive.pack(output, sources, dump, metadata, 256 * 1024**2)
            output.write_bytes(output.read_bytes()[:-8] + b"bad data")
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                archive.verify(output)

    def test_checksums_do_not_admit_path_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "unsafe.tar.gz"
            with tarfile.open(output, "w:gz") as handle:
                info = tarfile.TarInfo("../escape")
                info.size = 1
                handle.addfile(info, io.BytesIO(b"x"))
                value = json.dumps({"format": archive.FORMAT, "files": {}}).encode()
                info = tarfile.TarInfo("manifest.json")
                info.size = len(value)
                handle.addfile(info, io.BytesIO(value))
            Path(str(output) + ".sha256").write_text(hashlib.sha256(output.read_bytes()).hexdigest())
            with self.assertRaisesRegex(ValueError, "Unsafe"):
                archive.verify(output)
            self.assertFalse((Path(directory).parent / "escape").exists())

    def test_controller_only_stop_checks_queue_before_stopping_scheduler(self):
        calls = []

        def run(args, **_kwargs):
            calls.append(args)
            active = args[-1] == "slurmctld.service"
            return type("Result", (), {"returncode": 0 if active else 3})()

        with patch.object(archive.subprocess, "run", run), patch.object(archive.subprocess, "check_output", return_value=""):
            self.assertEqual(archive.stop_services(), ["slurmctld.service"])
        self.assertEqual(calls[-1], ["systemctl", "stop", "slurmctld.service"])


if __name__ == "__main__":
    unittest.main()
