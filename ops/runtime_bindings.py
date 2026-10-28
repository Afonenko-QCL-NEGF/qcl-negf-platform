"""Bind read-only application features to explicit immutable runtime metadata.

The NixOS module owns the static service/mount envelope. The active application
owns its catalog descriptor. Neither identity is an engineering qualification
or a scientific acceptance result.
"""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

from application_release import (CommandFailure, PROFILE, RUNTIME, command, quantum_context,
                                 release_envelope, unique_json)
from release_trust import protected_directory, read_protected_file, trusted_stat


APPLICATION_SCHEMA = "qcl-negf-application-runtime-v1"
STORE_MEMBER = re.compile(r"/nix/store/[A-Za-z0-9][A-Za-z0-9+._?-]*(?:/[A-Za-z0-9_.+-]+)*\Z")
RECORD = RUNTIME / "release.json"
FAILURE_DIRECTORY = Path("/var/lib/qcl-negf/runtime-failures")
SAVED_PATH_PROBE = """import os, sys
from pathlib import Path
for raw in sys.argv[1:]:
    path = Path(raw)
    if path.resolve(strict=True) != path or not path.is_dir():
        raise SystemExit('noncanonical saved-results directory')
if not os.access(sys.argv[-1], os.R_OK | os.X_OK):
    raise SystemExit('unreadable saved-results alias')
"""


def application_descriptor(value):
    if (not isinstance(value, dict) or set(value) != {"schema", "configurator"}
            or value["schema"] != APPLICATION_SCHEMA
            or not isinstance(value["configurator"], dict)
            or set(value["configurator"]) != {"catalog_root"}):
        raise ValueError("Unknown application runtime descriptor")
    root = value["configurator"]["catalog_root"]
    if (not isinstance(root, str) or len(root) > 1024 or not STORE_MEMBER.fullmatch(root)
            or any(part in (".", "..") for part in root.split("/"))):
        raise ValueError("Catalog root must be an explicit immutable store member")
    return value


def read_store_file(path, limit=65536):
    """Read a root-owned store member; the native store itself may be sticky g+w.

    Only /nix/store gets this exception. The selected store entry and every
    descendant must remain root-owned, non-writable and free of symlinks.
    Artifact integrity is the release qualifier's separate responsibility.
    """
    path = str(path)
    if (not STORE_MEMBER.fullmatch(path)
            or any(part in (".", "..") for part in path.split("/"))):
        raise ValueError("Expected an explicit immutable store member")
    with protected_directory("/nix") as nix:
        descriptor = os.open("store", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=nix)
    try:
        info = os.fstat(descriptor)
        if (info.st_uid != 0 or not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o002
                or (info.st_mode & 0o020 and not info.st_mode & stat.S_ISVTX)):
            raise ValueError("Untrusted native Nix store")
        parts = path.split("/")[3:]
        for index, part in enumerate(parts):
            directory = index < len(parts) - 1
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if directory:
                flags |= os.O_DIRECTORY
            following = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = following
            trusted_stat(os.fstat(descriptor), directory=directory)
        raw = bytearray()
        while len(raw) <= limit:
            chunk = os.read(descriptor, min(4096, limit + 1 - len(raw)))
            if not chunk:
                return bytes(raw)
            raw.extend(chunk)
        raise ValueError("Store metadata exceeds bound")
    finally:
        os.close(descriptor)


def read_trusted_file(path, limit=65536):
    if str(path).startswith("/nix/store/"):
        return read_store_file(path, limit=limit)
    return read_protected_file(path, limit=limit)


def read_runtime_json(path):
    return unique_json(read_trusted_file(path, limit=65536), 65536)


def runtime_bindings(record, descriptor, *, application_target, solver_target, cgroup_root,
                     require_ready=False):
    """Read configuration may bind during startup; execution requires current readiness.

    This pure projection never qualifies an artifact or opens job admission.
    A caller requesting current-execution metadata must opt into require_ready;
    the Portal additionally rechecks the protected record at each quantum request.
    """
    expected = release_envelope(record)
    descriptor = application_descriptor(descriptor)
    if (type(require_ready) is not bool or type(record.get("ready")) is not bool
            or (require_ready and not record["ready"])
            or expected["application_path"] != str(application_target)
            or expected["solver_executable"] != str(solver_target) + "/bin/qcl-negf"):
        raise ValueError("Current runtime record/profile binding differs")
    if (not isinstance(cgroup_root, str)
            or not re.fullmatch(r"/sys/fs/cgroup/[A-Za-z0-9_.:/-]+[.]service", cgroup_root)
            or any(part in ("", ".", "..") for part in cgroup_root.split("/")[1:])):
        raise ValueError("Invalid delegated API cgroup")
    graph = expected.get("sources", {})
    matches = [row["revision"] for row in graph.get("components", [])
               if row["path"] == "components/qcl-negf-research"]
    if len(matches) != 1:
        raise ValueError("Missing exact Research source identity")
    result = {
        "QCL_NEGF_CONFIGURATOR_EXECUTABLE": expected["solver_executable"],
        "QCL_NEGF_CONFIGURATOR_CATALOG_ROOT": descriptor["configurator"]["catalog_root"],
        "QCL_NEGF_CONFIGURATOR_CATALOG_SOURCE_ID": matches[0],
        "QCL_NEGF_CONFIGURATOR_CGROUP_ROOT": cgroup_root,
    }
    context = quantum_context(expected)
    if record.get("quantum_runtime_context") != context:
        raise ValueError("Quantum runtime context differs")
    if context is not None:
        result.update(QCL_NEGF_QUANTUM_RUNTIME_CONTEXT_SHA256=context["context_sha256"],
                      QCL_NEGF_QUANTUM_RUNTIME_RELEASE_FILE=str(RECORD))
    return result


def child_environment(environment):
    return {name: value for name, value in environment.items()
            if not name.startswith("QCL_NEGF_CONFIGURATOR_")
            and not name.startswith("QCL_NEGF_QUANTUM_RUNTIME_")
            and name != "QCL_NEGF_SAVED_RESULTS_BINDING_FILE"}


def saved_results_binding(value, *, run, read_protected):
    required = {"binding_file", "root", "alias", "nfs_source", "storage_identity_file"}
    if (not isinstance(value, dict) or set(value) != required
            or any(not isinstance(item, str) or not item for item in value.values())):
        raise ValueError("Invalid static saved-results envelope")
    root, alias = Path(value["root"]), Path(value["alias"])
    if any(not path.is_absolute() for path in (root, alias)):
        raise ValueError("Saved results require absolute directories")
    # Hard NFS metadata can block even before a payload is opened. Keep these
    # owned probes inside the existing command timeout/cleanup boundary.
    run([sys.executable, "-I", "-c", SAVED_PATH_PROBE, str(root), str(alias)],
        timeout_seconds=3.0, cleanup_seconds=1.0, output_bytes=4096)
    for path in (root, alias):
        for field, expected in (("FSTYPE", "nfs4"), ("SOURCE", value["nfs_source"])):
            actual = run(["findmnt", "-rn", "-M", str(path), "-o", field],
                         timeout_seconds=3.0, cleanup_seconds=1.0, output_bytes=4096)
            if actual.strip() != expected:
                raise ValueError("Saved results mount identity differs")
    options = run(["findmnt", "-rn", "-M", str(alias), "-o", "OPTIONS"],
                  timeout_seconds=3.0, cleanup_seconds=1.0, output_bytes=4096).strip().split(",")
    if "ro" not in options or "rw" in options:
        raise ValueError("Saved results alias must be readable and read-only")
    raw = read_protected(value["binding_file"], limit=65536)
    binding = unique_json(raw)
    identity = read_protected(value["storage_identity_file"], limit=257).decode("utf-8").rstrip("\n")
    if (not isinstance(binding, dict) or binding.get("root") != str(alias)
            or binding.get("storage_identity") != identity):
        raise ValueError("Saved results storage identity differs")
    return {"QCL_NEGF_SAVED_RESULTS_BINDING_FILE": value["binding_file"]}


def logged_command(argv, *, log_directory=FAILURE_DIRECTORY, run=command, **bounds):
    """Reuse the owning command engine and retain its original bounded failure."""
    try:
        return run(argv, **bounds)
    except CommandFailure as error:
        # The caller's private service directory has a native tmpfiles retention.
        # No argv/env is recorded: future owning commands may carry credentials.
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", prefix="command-",
                                             suffix=".json", dir=log_directory, delete=False) as handle:
                json.dump(error.record, handle, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
                error.log_path = handle.name
        except OSError as log_error:
            error.log_error = "failure_log_unavailable"
            raise error from log_error
        raise


def profile_target(profile):
    profile = Path(profile)
    with protected_directory(profile.parent) as parent:
        info = os.stat(profile.name, dir_fd=parent, follow_symlinks=False)
        if info.st_uid != 0 or not stat.S_ISLNK(info.st_mode):
            raise ValueError("Application profile must be a root-owned symlink")
        selected = str(profile.resolve(strict=True))
    if not re.fullmatch(r"/nix/store/[A-Za-z0-9][A-Za-z0-9+._?-]*", selected):
        raise ValueError("Application profile must select an immutable store root")
    return selected


def require_configurator_files(bindings):
    executable = Path(bindings["QCL_NEGF_CONFIGURATOR_EXECUTABLE"])
    catalog = Path(bindings["QCL_NEGF_CONFIGURATOR_CATALOG_ROOT"])
    if (executable.resolve(strict=True) != executable or not executable.is_file()
            or not os.access(executable, os.X_OK)
            or catalog.resolve(strict=True) != catalog
            or not os.access(catalog / "config/configurator-catalog.json", os.R_OK)):
        raise ValueError("Selected solver/catalog is unavailable")


def launch(config, *, port, environment=None, read_json=read_runtime_json,
           target=profile_target, run=logged_command, execve=os.execve,
           probe=require_configurator_files):
    """Launch the active API with argv/env; unavailable optional features stay explicit."""
    if (not isinstance(config, dict)
            or not {"schema", "configurator", "saved_results"} <= set(config)
            or not set(config) <= {"schema", "configurator", "saved_results", "allowed_codes_file"}
            or config["schema"] != "qcl-negf-application-launch-v1"
            or (config["configurator"] is not None and not isinstance(config["configurator"], dict))
            or (config["saved_results"] is not None and not isinstance(config["saved_results"], dict))
            or type(port) is not int or not 1 <= port <= 65535):
        raise ValueError("Invalid application launch envelope")
    selected = target(PROFILE)
    child = child_environment(os.environ if environment is None else environment)
    child["PATH"] = selected + "/bin:" + child.get("PATH", "")
    allowed_codes = config.get("allowed_codes_file")
    if allowed_codes is not None:
        if not isinstance(allowed_codes, str) or not Path(allowed_codes).is_absolute():
            raise ValueError("Code allowlist requires an explicit runtime path")
        descriptor = os.open(allowed_codes, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 4096:
                raise ValueError("Code allowlist exceeds its bound/type")
            raw = stream.read(4097)
        value = raw.decode("utf-8").strip()
        if len(raw) > 4096 or not value or "\0" in value:
            raise ValueError("Code allowlist must be finite and nonempty")
        child["QCL_NEGF_ALLOWED_CODES"] = value
    if config["configurator"] is not None:
        try:
            settings = config["configurator"]
            if set(settings) != {"cgroup_root"}:
                raise ValueError("Unknown configurator settings")
            record = read_json(RECORD)
            solver = target(str(PROFILE) + "-solver")
            descriptor = read_json(Path(selected) / "share/qcl-negf/runtime.json")
            bindings = runtime_bindings(record, descriptor, application_target=selected,
                                        solver_target=solver, cgroup_root=settings["cgroup_root"],
                                        require_ready=False)
            probe(bindings)
            current = read_json(RECORD)
            if (release_envelope(current) != release_envelope(record)
                    or runtime_bindings(current, descriptor, application_target=selected,
                                        solver_target=solver, cgroup_root=settings["cgroup_root"],
                                        require_ready=False) != bindings
                    or target(PROFILE) != selected
                    or target(str(PROFILE) + "-solver") != solver):
                raise ValueError("Runtime selection changed during launch")
            child.update(bindings)
            child.update(QCL_NEGF_RELEASE_ID=record["release_id"],
                         QCL_NEGF_SOLVER_EXECUTABLE=record["solver_executable"])
        except (OSError, ValueError, KeyError, TypeError):
            print("configurator binding unavailable: invalid_runtime_binding", file=sys.stderr)
    if config["saved_results"] is not None:
        try:
            child.update(saved_results_binding(config["saved_results"], run=run,
                                               read_protected=read_trusted_file))
        except (OSError, ValueError, KeyError, TypeError, CommandFailure) as error:
            reference = getattr(error, "log_path", None)
            print("saved results binding unavailable: invalid_storage_binding"
                  + ("; original log: " + reference if reference else ""), file=sys.stderr)
    # Pin parent and nested verdi lookup to the same immutable selected APP.
    executable = selected + "/bin/qcl-negf-api"
    execve(executable, [executable, "--host", "127.0.0.1", "--port", str(port)], child)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    launch(read_runtime_json(args.config), port=args.port)


if __name__ == "__main__":
    main()
