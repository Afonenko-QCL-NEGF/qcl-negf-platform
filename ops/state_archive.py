"""Local controller state staging archive. Never uploads or deletes older archives."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile

FORMAT = "qcl-negf-controller-state.v1"
UNITS = ["qcl-negf-api.service", "qcl-negf-aiida.service", "slurmctld.service"]
RESTORE_HEADROOM = 64 * 1024**2
POSTGRESQL_EXTRA_RESERVE = 1024**3


def digest(path):
    with open(path, "rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def source_files(sources):
    files = {}
    for prefix, source in sources.items():
        source = Path(source)
        if not source.is_dir() or source.is_symlink():
            raise ValueError(f"Required state directory missing or indirect: {source}")
        for path in sorted(source.rglob("*")):
            if path.is_symlink() or not (path.is_dir() or path.is_file()):
                raise ValueError(f"Unsupported state entry; archive must not omit it: {path}")
            if path.is_file():
                files[f"{prefix}/{path.relative_to(source).as_posix()}"] = path
    return files


def admission(output, sources, database_bytes, budget, retention):
    output = Path(output)
    if not output.name.endswith(".tar.gz") or output.exists() or Path(str(output) + ".sha256").exists():
        raise ValueError("Choose a new .tar.gz destination; existing archives are never overwritten")
    if not output.parent.is_dir():
        raise ValueError("Create a dedicated staging directory first")
    for source in sources.values():
        if output.resolve().is_relative_to(Path(source).resolve()):
            raise ValueError("Staging must be outside all source directories")
    retained = list(output.parent.glob("*.tar.gz"))
    if len(retained) >= retention:
        raise ValueError("Retention limit reached; copy and review older archives explicitly")
    files = source_files(sources)
    payload = sum(path.stat().st_size for path in files.values()) + 2 * database_bytes
    required = int(payload * 1.02) + len(files) * 4096 + 64 * 1024**2
    retained_bytes = sum(path.stat().st_size for path in retained)
    if required + retained_bytes > budget or required > shutil.disk_usage(output.parent).free:
        raise ValueError("Controller archive exceeds the declared disk budget or available free space")
    return files


def pack(output, sources, dump, metadata, budget, retention=1):
    files = admission(output, sources, Path(dump).stat().st_size, budget, retention)
    files["postgresql.dump"] = Path(dump)
    manifest = {"format": FORMAT, **metadata,
                "offhost_backup": "not_copied", "nfs_data": "not_included",
                "files": {name: {"sha256": digest(path), "bytes": path.stat().st_size}
                          for name, path in files.items()}}
    output = Path(output)
    with tempfile.TemporaryDirectory(prefix=".qcl-state-", dir=output.parent) as directory:
        stage = Path(directory)
        (stage / "manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n")
        archive = stage / "archive.tar.gz"
        with tarfile.open(archive, "w:gz", dereference=True) as handle:
            for prefix, source in sources.items():
                handle.add(source, arcname=prefix, recursive=False)
                for path in sorted(Path(source).rglob("*")):
                    handle.add(path, arcname=f"{prefix}/{path.relative_to(source).as_posix()}", recursive=False)
            handle.add(dump, arcname="postgresql.dump")
            handle.add(stage / "manifest.json", arcname="manifest.json")
        checksum = digest(archive)
        verify_pack_files = {name: digest(path) for name, path in files.items()}
        if any(value != manifest["files"][name]["sha256"] for name, value in verify_pack_files.items()):
            raise ValueError("Controller state changed while creating the archive; writers must remain paused")
        # Same-filesystem publication without overwrite; a crash before the
        # sidecar appears leaves an explicitly unverifiable archive.
        os.chmod(archive, 0o600)
        os.link(archive, output)
        with open(str(output) + ".sha256", "x") as sidecar:
            sidecar.write(checksum + "\n")
        os.chmod(str(output) + ".sha256", 0o600)
    return manifest


def verify(archive):
    archive = Path(archive)
    expected = Path(str(archive) + ".sha256").read_text().strip()
    if not re.fullmatch(r"[0-9a-f]{64}", expected) or digest(archive) != expected:
        raise ValueError("Archive SHA-256 mismatch")
    with tarfile.open(archive, "r:gz") as handle:
        members = handle.getmembers()
        names = [member.name for member in members]
        if len(names) != len(set(names)):
            raise ValueError("Duplicate archive member")
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not (member.isfile() or member.isdir()):
                raise ValueError("Unsafe archive member")
        manifest = json.load(handle.extractfile("manifest.json"))
        if manifest.get("format") != FORMAT:
            raise ValueError("Unsupported controller archive format")
        files = {member.name: member for member in members if member.isfile() and member.name != "manifest.json"}
        if set(files) != set(manifest["files"]):
            raise ValueError("Manifest omits or invents archive files")
        for name, member in files.items():
            actual = hashlib.file_digest(handle.extractfile(member), "sha256").hexdigest()
            if actual != manifest["files"][name]["sha256"] or member.size != manifest["files"][name]["bytes"]:
                raise ValueError(f"State file mismatch: {name}")
    return manifest


def pg(args, command):
    return ["runuser", "-u", "postgres", "--", command, "--host=/run/postgresql", f"--dbname={args.database}"]


def query(args, sql):
    return subprocess.check_output(pg(args, "psql") + ["--no-psqlrc", "--tuples-only", "--no-align", "--command", sql], text=True).strip()


def postgresql_directory(args):
    directory = Path(query(args, "SHOW data_directory"))
    if (not directory.is_absolute() or not directory.is_dir() or directory.is_symlink()
            or directory.stat().st_dev == Path("/").stat().st_dev):
        raise ValueError("PostgreSQL data_directory must reside on a separate mounted data disk")
    wal = directory / "pg_wal"
    if (not wal.is_dir() or wal.is_symlink() or wal.stat().st_dev != directory.stat().st_dev
            or query(args, "SELECT count(*) FROM pg_tablespace WHERE spcname NOT IN ('pg_default','pg_global')") != "0"):
        raise ValueError("External PostgreSQL WAL or nondefault tablespaces require a separate restore procedure")
    return directory


def restore_admission(args, manifest, sources, database_directory):
    database_bytes = manifest.get("postgresql_database_bytes")
    if type(database_bytes) is not int or database_bytes <= 0:
        raise ValueError("Archive lacks a positive physical PostgreSQL size; restore budget cannot be established")
    sizes = {name: item["bytes"] for name, item in manifest["files"].items()}
    if any(type(size) is not int or size < 0 for size in sizes.values()):
        raise ValueError("Archive file sizes must be nonnegative integers")
    allocations = [(args.archive.parent, sum(sizes.values()) + len(sizes) * 4096)]
    for name, destination in sources.items():
        files = [size for key, size in sizes.items() if key.startswith(name + "/")]
        allocations.append((destination, sum(files) + len(files) * 4096))
    # pg_database_size already includes indexes. Reserve a second physical
    # copy plus explicit extra space for transient index/WAL growth.
    allocations.append((database_directory, 2 * database_bytes + args.postgresql_reserve_bytes))
    devices = {}
    for path, size in allocations:
        while not path.exists():
            path = path.parent
        device = path.stat().st_dev
        free = shutil.disk_usage(path).free
        allocation = devices.setdefault(device, {"bytes": 0, "free": free})
        allocation["bytes"] += size
        allocation["free"] = min(allocation["free"], free)
    required = sum(value["bytes"] + RESTORE_HEADROOM for value in devices.values())
    # The retained input archive consumes the overall budget already, but is
    # not new allocation and must not be charged against free space twice.
    if required + args.archive.stat().st_size > args.disk_budget_bytes:
        raise ValueError("Restore exceeds the declared total disk budget")
    if any(value["bytes"] + RESTORE_HEADROOM > value["free"] for value in devices.values()):
        raise ValueError("Restore exceeds available space on a staging, state or PostgreSQL filesystem")


def stop_services():
    active = [unit for unit in UNITS if subprocess.run(["systemctl", "is-active", "--quiet", unit]).returncode == 0]
    stopped = []
    try:
        for unit in UNITS[:2]:
            if unit not in active:
                continue
            subprocess.run(["systemctl", "stop", unit], check=True)
            stopped.append(unit)
        if "slurmctld.service" in active:
            if subprocess.check_output(["squeue", "--noheader"], text=True).strip():
                raise ValueError("Slurm queue must be empty before a coordinated state archive")
            subprocess.run(["systemctl", "stop", "slurmctld.service"], check=True)
            stopped.append("slurmctld.service")
    except BaseException:
        for unit in reversed(stopped):
            subprocess.run(["systemctl", "start", unit], check=True)
        raise
    return stopped


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["create", "verify", "restore"])
    parser.add_argument("archive", type=Path)
    parser.add_argument("--profile-directory", type=Path, default=Path("/var/lib/qcl-negf/aiida"))
    parser.add_argument("--slurm-directory", type=Path, default=Path("/var/lib/qcl-negf-state/slurm"))
    parser.add_argument("--database", default="qcl-negf")
    parser.add_argument("--source-revision")
    parser.add_argument("--disk-budget-bytes", type=int)
    parser.add_argument("--postgresql-reserve-bytes", type=int, default=POSTGRESQL_EXTRA_RESERVE)
    parser.add_argument("--max-archives", type=int, default=1)
    parser.add_argument("--writers-paused", action="store_true")
    parser.add_argument("--secret-reference", action="append", default=[])
    parser.add_argument("--nfs-reference", default="/srv/qcl-negf/jobs")
    args = parser.parse_args(argv)
    if args.operation == "verify":
        print(json.dumps(verify(args.archive), sort_keys=True))
        return
    if os.geteuid() != 0 or not args.writers_paused:
        raise ValueError("Administrative create/restore requires root and --writers-paused")
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,62}", args.database):
        raise ValueError("Invalid database name")
    if not args.disk_budget_bytes or args.disk_budget_bytes <= 0 or args.max_archives <= 0:
        raise ValueError("Declare a finite positive disk budget and retention count")
    if args.postgresql_reserve_bytes < POSTGRESQL_EXTRA_RESERVE:
        raise ValueError("PostgreSQL restore requires at least 1 GiB additional reserve; increase it for the site's measured workload")
    sources = {"aiida": args.profile_directory, "slurm": args.slurm_directory}
    root_device = Path("/").stat().st_dev
    if any((path if path.exists() else path.parent).stat().st_dev == root_device for path in sources.values()):
        raise ValueError("Controller state must be on its separate mounted data disk")
    if args.operation == "create":
        if not args.source_revision or not re.fullmatch(r"[0-9a-f]{40}", args.source_revision):
            raise ValueError("Record the deployed root Git revision")
        profile = json.loads((args.profile_directory / ".aiida" / "config.json").read_text())["profiles"]["qcl-negf"]
        if (profile["storage"]["backend"] != "core.psql_dos"
                or profile["storage"]["config"]["database_name"] != args.database
                or profile["storage"]["config"].get("database_hostname") != "/run/postgresql"
                or profile["storage"]["config"].get("database_port") != 5432
                or profile["storage"]["config"].get("database_username") != "qcl-negf"
                or profile["storage"]["config"].get("database_password") != ""
                or profile["storage"]["config"]["repository_uri"] != (args.profile_directory / "repository").absolute().as_uri()
                or not (args.profile_directory / "repository").is_dir()):
            raise ValueError("Profile storage must identify the archived database and included repository")
        database_bytes = int(query(args, "SELECT pg_database_size(current_database())"))
        if database_bytes <= 0:
            raise ValueError("PostgreSQL physical database size must be positive")
        postgresql_directory(args)
        admission(args.archive, sources, database_bytes, args.disk_budget_bytes, args.max_archives)
        stopped = stop_services()
        try:
            version = query(args, "SHOW server_version_num")
            with tempfile.TemporaryDirectory(prefix=".qcl-dump-", dir=args.archive.parent) as directory:
                dump = Path(directory) / "postgresql.dump"
                # Root opens the descriptor: postgres needs no path access to a
                # private backup directory, and no password enters argv/store.
                with dump.open("wb") as stream:
                    subprocess.run(pg(args, "pg_dump") + ["--format=custom"], stdout=stream, check=True, timeout=1800)
                pack(args.archive, sources, dump, {"source_revision": args.source_revision,
                     "postgresql_version_num": version, "database": args.database,
                     "postgresql_database_bytes": database_bytes,
                     "source_paths": {name: str(path) for name, path in sources.items()},
                     "secret_references": args.secret_reference, "nfs_reference": args.nfs_reference},
                     args.disk_budget_bytes, args.max_archives)
            verify(args.archive)
        finally:
            for unit in reversed(stopped):
                subprocess.run(["systemctl", "start", unit], check=True)
    else:
        manifest = verify(args.archive)
        if any(str(path) != manifest["source_paths"][name] for name, path in sources.items()):
            raise ValueError("Restore requires original state paths; relocation is a separate procedure")
        if manifest["database"] != args.database or int(manifest["postgresql_version_num"]) // 10000 != int(query(args, "SHOW server_version_num")) // 10000:
            raise ValueError("Restore requires the same database name and PostgreSQL major version")
        if query(args, "SELECT count(*) FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema')") != "0":
            raise ValueError("Restore requires an empty database; existing provenance is never overwritten")
        if any(path.exists() and (not path.is_dir() or any(path.iterdir())) for path in sources.values()):
            raise ValueError("Restore requires empty destination state directories")
        restore_admission(args, manifest, sources, postgresql_directory(args))
        stop_services()
        with tempfile.TemporaryDirectory(prefix=".qcl-restore-", dir=args.archive.parent) as directory:
            with tarfile.open(args.archive, "r:gz") as handle:
                handle.extractall(directory, filter="data")
            with (Path(directory) / "postgresql.dump").open("rb") as stream:
                subprocess.run(pg(args, "pg_restore") + ["--exit-on-error", "--single-transaction", "--no-owner", "--role=qcl-negf"], stdin=stream, check=True, timeout=1800)
            for name, destination in sources.items():
                if destination.exists():
                    destination.rmdir()
                shutil.copytree(Path(directory) / name, destination, copy_function=shutil.copy2)
                subprocess.run(["chown", "-R", "qcl-negf:qcl-negf" if name == "aiida" else "slurm:slurm", str(destination)], check=True)
        print("State restored; services remain stopped pending profile, UUID and storage verification")


if __name__ == "__main__":
    main()
