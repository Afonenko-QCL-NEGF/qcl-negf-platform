import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location(
    "state_archive", Path(__file__).parents[1] / "ops" / "state_archive.py"
)
archive = importlib.util.module_from_spec(spec)
spec.loader.exec_module(archive)


class StateArchiveTests(unittest.TestCase):
    def restore_case(self, root, aiida_bytes, slurm_bytes, database_bytes):
        sources = {"aiida": root / "aiida", "slurm": root / "slurm"}
        database = root / "postgresql"
        staging = root / "staging"
        for path in [*sources.values(), database, staging]:
            path.mkdir()
        (database / "pg_wal").mkdir()
        output = staging / "controller.tar.gz"
        output.write_bytes(b"fixture")
        manifest = {
            "database": "qcl-negf", "postgresql_version_num": "170006",
            "postgresql_database_bytes": database_bytes,
            "source_paths": {name: str(path) for name, path in sources.items()},
            "files": {"aiida/object": {"bytes": aiida_bytes},
                      "slurm/state": {"bytes": slurm_bytes},
                      "postgresql.dump": {"bytes": 1024}},
        }
        sql = {
            "SHOW server_version_num": "170006", "SHOW data_directory": str(database),
            "SELECT count(*) FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema')": "0",
            "SELECT count(*) FROM pg_tablespace WHERE spcname NOT IN ('pg_default','pg_global')": "0",
        }
        argv = ["restore", str(output), "--profile-directory", str(sources["aiida"]),
                "--slurm-directory", str(sources["slurm"]), "--disk-budget-bytes", str(64 * 1024**3),
                "--writers-paused"]
        return sources, database, staging, manifest, sql, argv

    def virtual_disks(self, root, source_devices, free_bytes):
        # External filesystem boundaries are simulated; filesystem traversal,
        # CLI checks and the admission decision remain real production code.
        real_stat = Path.stat

        def stat(path, *args, **kwargs):
            value = real_stat(path, *args, **kwargs)
            for location, device in source_devices.items():
                if path == location or path.is_relative_to(location):
                    fields = list(value)
                    fields[2] = device
                    return os.stat_result(fields)
            return value

        def disk_usage(path):
            path = Path(path)
            for location, size in free_bytes.items():
                if path == location or path.is_relative_to(location):
                    return SimpleNamespace(free=size)
            return SimpleNamespace(free=free_bytes[root])

        return stat, disk_usage

    def test_restore_rejects_combined_aiida_and_slurm_on_one_filesystem_before_stop(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources, database, staging, manifest, sql, argv = self.restore_case(root, 1024**3, 1024**3, 1024)
            stat, usage = self.virtual_disks(root, {sources["aiida"]: 101, sources["slurm"]: 101,
                                                  database: 102, staging: 103},
                                             {staging: 64 * 1024**3, database: 64 * 1024**3,
                                              root: 3 * 1024**3 // 2})
            with patch.object(archive.os, "geteuid", return_value=0), patch.object(Path, "stat", stat), \
                    patch.object(archive.shutil, "disk_usage", usage), patch.object(archive, "verify", return_value=manifest), \
                    patch.object(archive, "query", side_effect=lambda _args, statement: sql[statement]), \
                    patch.object(archive, "stop_services", side_effect=AssertionError("Insufficient shared filesystem reached service stop")):
                with self.assertRaisesRegex(ValueError, "space|budget"):
                    archive.main(argv)

    def test_restore_rejects_physical_database_reserve_before_stop(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources, database, staging, manifest, sql, argv = self.restore_case(root, 1024, 1024, 2 * 1024**3)
            stat, usage = self.virtual_disks(root, {sources["aiida"]: 101, sources["slurm"]: 101,
                                                  database: 102, staging: 103},
                                             {database: 3 * 1024**3 // 2, root: 64 * 1024**3})
            with patch.object(archive.os, "geteuid", return_value=0), patch.object(Path, "stat", stat), \
                    patch.object(archive.shutil, "disk_usage", usage), patch.object(archive, "verify", return_value=manifest), \
                    patch.object(archive, "query", side_effect=lambda _args, statement: sql[statement]), \
                    patch.object(archive, "stop_services", side_effect=AssertionError("Insufficient PostgreSQL filesystem reached service stop")):
                with self.assertRaisesRegex(ValueError, "space|budget"):
                    archive.main(argv)

    def test_restore_total_budget_includes_physical_database_and_staging(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources, database, staging, manifest, sql, argv = self.restore_case(root, 1024, 1024, 2 * 1024**3)
            argv[argv.index("--disk-budget-bytes") + 1] = str(3 * 1024**3)
            stat, usage = self.virtual_disks(root, {sources["aiida"]: 101, sources["slurm"]: 101,
                                                  database: 102, staging: 103}, {root: 64 * 1024**3})
            with patch.object(archive.os, "geteuid", return_value=0), patch.object(Path, "stat", stat), \
                    patch.object(archive.shutil, "disk_usage", usage), patch.object(archive, "verify", return_value=manifest), \
                    patch.object(archive, "query", side_effect=lambda _args, statement: sql[statement]), \
                    patch.object(archive, "stop_services", side_effect=AssertionError("Physical PostgreSQL bytes were omitted from total budget")):
                with self.assertRaisesRegex(ValueError, "budget"):
                    archive.main(argv)

    def test_create_manifest_records_physical_database_size_for_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources, dump, output, _metadata = self.fixture(root)
            database = root / "postgresql"
            database.mkdir()
            (database / "pg_wal").mkdir()
            config = {"profiles": {"qcl-negf": {"storage": {"backend": "core.psql_dos", "config": {
                "database_name": "qcl-negf", "database_hostname": "/run/postgresql",
                "database_port": 5432, "database_username": "qcl-negf", "database_password": "",
                "repository_uri": (sources["aiida"] / "repository").as_uri(),
            }}}}}
            (sources["aiida"] / ".aiida").mkdir()
            (sources["aiida"] / ".aiida" / "config.json").write_text(json.dumps(config))
            (sources["aiida"] / "config.json").write_text("root-level decoy is not AiiDA configuration")
            sql = {"SELECT pg_database_size(current_database())": str(8 * 1024**2),
                   "SHOW server_version_num": "170006", "SHOW data_directory": str(database),
                   "SELECT count(*) FROM pg_tablespace WHERE spcname NOT IN ('pg_default','pg_global')": "0"}
            stat, _usage = self.virtual_disks(root, {sources["aiida"]: 101, sources["slurm"]: 101,
                                                    database: 101}, {root: 64 * 1024**3})

            def pg_dump(command, **kwargs):
                self.assertIn("pg_dump", command)
                kwargs["stdout"].write(dump.read_bytes())

            with patch.object(archive.os, "geteuid", return_value=0), patch.object(Path, "stat", stat), \
                    patch.object(archive, "query", side_effect=lambda _args, statement: sql[statement]), \
                    patch.object(archive, "stop_services", return_value=[]), patch.object(archive.subprocess, "run", pg_dump):
                archive.main(["create", str(output), "--profile-directory", str(sources["aiida"]),
                              "--slurm-directory", str(sources["slurm"]), "--source-revision", "a" * 40,
                              "--disk-budget-bytes", str(256 * 1024**2), "--writers-paused"])
            saved = archive.verify(output)
            self.assertEqual(saved.get("postgresql_database_bytes"), 8388608)
            self.assertIn("aiida/.aiida/config.json", saved["files"])
            self.assertIn("aiida/repository/object", saved["files"])

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
