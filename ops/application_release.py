"""Small application-only release procedure, not a daemon or OS deployment tool.

Run delivery on the controller after the user's maintenance decision. Nix closures
are immutable; runtime readiness and the shared admission gate are atomic files.
The command boundary is injectable for local fault-injection tests.
"""
import argparse
import base64
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import subprocess
import tempfile
from urllib.parse import urlsplit


RUNTIME = Path("/var/lib/qcl-negf/runtime")
PROFILE = Path("/nix/var/nix/profiles/qcl-negf-application")
GATE = Path("/srv/qcl-negf/jobs/.release-admission.json")
IDENTIFIER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}\Z")
STORE_PATH = re.compile(r"/nix/store/[a-zA-Z0-9][a-zA-Z0-9+._?-]*\Z")
TARGET = re.compile(r"(?:[a-z_][a-z0-9_-]*@)?[a-zA-Z0-9][a-zA-Z0-9.-]*\Z")
NAR_HASH = re.compile(r"sha256-[A-Za-z0-9+/]{43}=\Z")


def command(args):
    """No shell for local commands; a failed command cannot publish readiness."""
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout


def manifest(value):
    if not isinstance(value, dict) or value.get("schema") != "qcl-negf-release-v1":
        raise ValueError("Expected qcl-negf-release-v1 manifest")
    if not isinstance(value.get("release_id"), str) or not IDENTIFIER.fullmatch(value["release_id"]):
        raise ValueError("Invalid release identity")
    if not isinstance(value.get("application_path"), str) or not STORE_PATH.fullmatch(value["application_path"]):
        raise ValueError("Application must be an immutable Nix store path")
    solver = value.get("solver_executable", "")
    if not isinstance(solver, str) or not solver.endswith("/bin/qcl-negf") or not STORE_PATH.fullmatch(solver[:-len("/bin/qcl-negf")]):
        raise ValueError("Solver must be an immutable /nix/store/.../bin/qcl-negf executable")
    return {key: value[key] for key in ("schema", "release_id", "application_path", "solver_executable")}


def prefetch_controller_closures(value, run=command):
    """Fetch and verify immutable release evidence before maintenance begins."""
    expected = manifest(value)
    paths = [expected["application_path"], str(Path(expected["solver_executable"]).parents[1])]
    required = set(paths)
    cache = value.get("cache_uri")
    if "cache_uri" in value:
        if (not isinstance(cache, str) or not cache or cache.startswith("-")
                or any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in cache)):
            raise ValueError("Invalid cache URI argument")
        try:
            if urlsplit(cache).password is not None:
                raise ValueError("Cache URI must not embed a password")
        except ValueError as error:
            raise ValueError("Invalid cache URI; embedded credentials are not supported") from error
    inventory = value.get("closures")
    if not isinstance(inventory, list) or len(inventory) != len(paths):
        raise ValueError("Delivery requires manifest closure hashes for application and solver")
    hashes = {}
    for item in inventory:
        if (not isinstance(item, dict) or not isinstance(item.get("path"), str) or item["path"] not in required
                or not isinstance(item.get("narHash"), str) or not NAR_HASH.fullmatch(item["narHash"])
                or item["path"] in hashes):
            raise ValueError("Malformed or duplicated manifest closure hash evidence")
        hashes[item["path"]] = item["narHash"]
    if set(hashes) != required:
        raise ValueError("Manifest lacks application or solver closure hash evidence")
    if "cache_uri" in value:
        run(["nix", "copy", "--from", cache, *paths])
    raw = run(["nix", "path-info", "--json", *paths])
    def unique_object(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("Duplicate local closure evidence")
            result[key] = item
        return result
    try:
        if not isinstance(raw, str) or len(raw.encode()) > 1024 * 1024:
            raise ValueError("Local closure evidence exceeds its metadata budget")
        evidence = json.loads(raw, object_pairs_hook=unique_object)
    except (ValueError, TypeError) as error:
        raise ValueError("Malformed local closure hash evidence") from error
    if isinstance(evidence, list):
        if (not all(isinstance(item, dict) and isinstance(item.get("path"), str) for item in evidence)
                or len({item["path"] for item in evidence}) != len(evidence)):
            raise ValueError("Malformed or duplicate local closure evidence")
        evidence = {item["path"]: item for item in evidence}
    if not isinstance(evidence, dict) or set(evidence) != required:
        raise ValueError("Local closure evidence lacks application or solver")
    for path, digest in hashes.items():
        if not isinstance(evidence[path], dict) or evidence[path].get("narHash") != digest:
            raise ValueError("Local closure narHash differs from the manifest")
    return hashes


def publish(path, value):
    """Publish complete public runtime configuration and fsync the directory."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        try:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
            os.fchmod(handle.fileno(), 0o644)
            os.replace(temporary, path)
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)


def publish_json(path, value):
    publish(path, json.dumps(value, sort_keys=True) + "\n")


def publish_admission(path, value):
    """NFS uses root_squash: publish the shared gate as the scientific UID."""
    if Path(path) != GATE or os.geteuid() != 0:
        publish_json(path, value)
        return
    user = pwd.getpwnam("qcl-negf")
    previous_group = os.getegid()
    try:
        os.setegid(user.pw_gid)
        os.seteuid(user.pw_uid)
        publish_json(path, value)
    finally:
        os.seteuid(0)
        os.setegid(previous_group)


def load(path):
    return json.loads(Path(path).read_text())


@contextmanager
def admission_reader(path):
    """Read the shared gate with its NFS owner; retain authority for local state."""
    if Path(path) != GATE or os.geteuid() != 0:
        yield
        return
    user = pwd.getpwnam("qcl-negf")
    previous_group = os.getegid()
    try:
        os.setegid(user.pw_gid)
        os.seteuid(user.pw_uid)
        yield
    finally:
        os.seteuid(0)
        os.setegid(previous_group)


def read_admission(path, *, missing=False):
    """Only ENOENT means absent; permission errors must remain failures."""
    with admission_reader(path):
        try:
            return Path(path).read_bytes()
        except FileNotFoundError:
            if not missing:
                raise
            return None


def load_admission(path):
    return json.loads(read_admission(path))


def bootstrap_selection(runtime, initial_solver, initial_label):
    """A reboot must not publish the image seed Code after a CD release switch."""
    if Path(runtime).exists():
        selected = manifest(load(runtime))
        return selected["solver_executable"], "qcl-negf-" + selected["release_id"]
    return initial_solver, initial_label


def solver_self_check(expected, run):
    output = run(["timeout", "--kill-after=10s", "300s", "runuser", "-u", "qcl-negf", "--",
                  "env", "JULIA_NUM_THREADS=1", "OPENBLAS_NUM_THREADS=1",
                  expected["solver_executable"], "self-check"])
    receipt = json.loads(output.strip().splitlines()[-1])
    if (receipt.get("schema") != "qcl-negf-self-check-v1" or receipt.get("status") != "completed"
            or receipt.get("scientific_accepted") is not False):
        raise ValueError("Pinned solver execution self-check failed")
    return receipt


def check(manifest_value, *, profile=PROFILE, runtime=RUNTIME, role="worker", run=command):
    expected = manifest(manifest_value)
    current = load(Path(runtime) / "release.json")
    if current.get("ready") is not True or manifest(current) != expected or Path(profile).resolve() != Path(expected["application_path"]):
        raise ValueError("Installed application profile or runtime release identity differs")
    solver_profile = Path(profile).with_name(Path(profile).name + "-solver")
    if solver_profile.resolve() != Path(expected["solver_executable"]).parents[1]:
        raise ValueError("Installed solver profile differs from the selected closure")
    run(["nix-store", "--verify-path", expected["application_path"],
         str(Path(expected["solver_executable"]).parents[1])])
    units = ["slurmd.service"] if role == "worker" else ["qcl-negf-aiida.service", "qcl-negf-api.service"]
    for unit in units:
        run(["systemctl", "is-active", "--quiet", unit])
    solver_self_check(expected, run)
    return current


def prepare_initial(manifest_value, *, profile=PROFILE, runtime=RUNTIME, gate=GATE,
                    role="worker", run=command):
    """Prepare a cold role switch with closed admission, without starting services.

    This is initial provisioning, never a replacement for normal CD activation.
    Only absent profiles/runtime files are initialized; existing exact evidence
    (including readiness, Code UUID and provenance) is preserved byte for byte.
    """
    expected = manifest(manifest_value)
    if role not in ("controller", "worker"):
        raise ValueError("Initial preparation role must be controller or worker")
    profile, runtime, gate = Path(profile), Path(runtime), Path(gate)
    record, environment = runtime / "release.json", runtime / "service.env"
    record_exists = os.path.lexists(record)
    current = load(record) if record_exists else None
    if record_exists and (manifest(current) != expected or
            not (current.get("ready") is True or current.get("ready") is False)):
        raise ValueError("Existing release identity conflicts; use normal CD activation")
    profiles = [(profile, expected["application_path"]),
                (profile.with_name(profile.name + "-solver"),
                 str(Path(expected["solver_executable"]).parents[1]))]
    for path, selected in profiles:
        if os.path.lexists(path) and path.resolve() != Path(selected):
            raise ValueError("Existing application or solver profile conflicts; use normal CD activation")
    service_environment = "\n".join([
        "QCL_NEGF_RELEASE_ID=" + expected["release_id"],
        "QCL_NEGF_SOLVER_EXECUTABLE=" + expected["solver_executable"],
        "QCL_NEGF_RELEASE_GATE=" + str(gate),
    ]) + "\n"
    if os.path.lexists(environment) and environment.read_text() != service_environment:
        raise ValueError("Existing runtime environment conflicts; use normal CD activation")
    gate_bytes = read_admission(gate, missing=True)
    if gate_bytes is None:
        if role != "controller" or current is not None or os.path.lexists(environment):
            raise ValueError("Only a cold initial controller may create the missing admission gate")
    else:
        admission = json.loads(gate_bytes)
        if (not isinstance(admission, dict) or admission.get("open") is not False
                or admission.get("release_id") != expected["release_id"]):
            raise ValueError("Initial preparation requires the matching closed admission gate")
    # Verify local contents before publishing anything. Optional manifest narHash
    # receipts are checked locally too; initial provisioning never fetches a cache.
    run(["nix-store", "--verify-path", *[selected for _, selected in profiles]])
    if "closures" in manifest_value:
        prefetch_controller_closures({key: value for key, value in manifest_value.items()
                                      if key != "cache_uri"}, run)
    if gate_bytes is None and run(["squeue", "--all", "--noheader", "--format", "%i"]).strip():
        raise RuntimeError("Slurm still has running or queued jobs; resolve them before initial preparation")
    # A gate changed during local verification belongs to another operation.
    if read_admission(gate, missing=True) != gate_bytes:
        raise ValueError("Admission gate changed during initial preparation")
    if gate_bytes is None:
        publish_admission(gate, {"open": False, "release_id": expected["release_id"]})
    for path, selected in profiles:
        if not os.path.lexists(path):
            run(["nix-env", "--profile", str(path), "--set", selected])
        if path.resolve() != Path(selected):
            raise ValueError("Initial application or solver profile differs from the selected closure")
    if not os.path.lexists(environment):
        publish(environment, service_environment)
    if current is None:
        current = {**expected, "ready": False}
        publish_json(record, current)
    return current


def activate(manifest_value, *, profile=PROFILE, runtime=RUNTIME, role="worker", run=command,
             email=None, allowed_codes_file=Path("/var/lib/qcl-negf/aiida/code-uuid")):
    expected = manifest(manifest_value)
    if role not in ("controller", "worker"):
        raise ValueError("Activation role must be controller or worker")
    profile, runtime = Path(profile), Path(runtime)
    runtime.mkdir(parents=True, exist_ok=True)
    record = runtime / "release.json"
    current = load(record) if record.exists() else None
    same = current is not None and current.get("ready") is True and manifest(current) == expected and profile.resolve() == Path(expected["application_path"])
    # An interrupted activation cannot leave a local ready marker for new jobs.
    record.unlink(missing_ok=True)
    run(["nix-store", "--verify-path", expected["application_path"],
         str(Path(expected["solver_executable"]).parents[1])])
    # Each profile is an independent GC root; an identical release can lose one.
    profiles = [(profile, expected["application_path"]),
                (profile.with_name(profile.name + "-solver"),
                 str(Path(expected["solver_executable"]).parents[1]))]
    for path, selected in profiles:
        if path.resolve() != Path(selected):
            run(["nix-env", "--profile", str(path), "--set", selected])
        if path.resolve() != Path(selected):
            raise ValueError("Installed application or solver profile differs from the selected closure")
    identity = dict(expected)
    if role == "controller":
        if not email:
            raise ValueError("Controller activation requires the declared service email")
        output = run(["runuser", "-u", "qcl-negf", "--", "env",
                      "AIIDA_PATH=/var/lib/qcl-negf/aiida", str(profile / "bin/verdi"),
                      "-p", "qcl-negf", "run", str(Path(__file__).with_name("register_aiida.py")),
                      "--", email, expected["solver_executable"], "qcl-negf-" + expected["release_id"]])
        registered = json.loads(output.strip().splitlines()[-1])
        if registered.get("solver_executable") != expected["solver_executable"] or not registered.get("code_uuid"):
            raise ValueError("InstalledCode identity does not match the immutable solver")
        identity["code_uuid"] = registered["code_uuid"]
        publish(allowed_codes_file, identity["code_uuid"] + "\n")
    publish(runtime / "service.env", "\n".join([
        "QCL_NEGF_RELEASE_ID=" + expected["release_id"],
        "QCL_NEGF_SOLVER_EXECUTABLE=" + expected["solver_executable"],
        "QCL_NEGF_RELEASE_GATE=" + str(GATE),
    ]) + "\n")
    # A prepared configuration may start slurmd for a closed release delivery.
    # Jobs still fail the ready+shared-admission guard until health succeeds.
    publish_json(record, {**identity, "ready": False})
    units = ["slurmd.service"] if role == "worker" else ["qcl-negf-aiida.service", "qcl-negf-api.service"]
    # Fleet delivery quiesces the controller even on an identical retry.
    # Reuse the immutable profile/Code, but ensure stopped units run again.
    run(["systemctl", "start" if same else "restart", *units])
    for unit in units:
        run(["systemctl", "is-active", "--quiet", unit])
    solver_self_check(expected, run)
    identity["ready"] = True
    publish_json(record, identity)
    return identity


def guard(release_id, solver_executable, runtime=RUNTIME / "release.json", gate=GATE):
    current, admission = load(runtime), load_admission(gate)
    if admission.get("open") is not True:
        raise ValueError("Application admission is closed")
    if current.get("ready") is not True:
        raise ValueError("Worker application release is not ready")
    if release_id != admission.get("release_id") or release_id != current.get("release_id"):
        raise ValueError("Job or worker release differs from the selected release")
    if solver_executable != current.get("solver_executable"):
        raise ValueError("Job solver executable differs from the immutable solver identity")
    manifest(current)
    return current


def node_check(runtime=RUNTIME / "release.json", gate=GATE, profile=PROFILE, *, run=command):
    """slurmd boot gate: selected immutable identity; job guard checks admission."""
    current, admission = manifest(load(runtime)), load_admission(gate)
    if current["release_id"] != admission.get("release_id"):
        raise ValueError("Worker release differs from the selected release")
    if Path(profile).resolve() != Path(current["application_path"]):
        raise ValueError("Worker application profile differs from the selected release")
    run(["nix-store", "--verify-path", current["application_path"],
         str(Path(current["solver_executable"]).parents[1])])
    return current


def deliver_pool(manifest_value, nodes, gate=GATE, *, deliver, quiesce, admit=lambda: None):
    expected = manifest(manifest_value)
    if not nodes or len(set(nodes)) != len(nodes):
        raise ValueError("Select a nonempty pool of unique active nodes")
    publish_admission(gate, {"open": False, "release_id": expected["release_id"]})
    quiesce()
    report = {"release_id": expected["release_id"], "open": False, "nodes": {}}
    for node in nodes:
        try:
            identity = deliver(node, expected)
            if not isinstance(identity, dict) or identity.get("ready") is not True or manifest(identity) != expected:
                raise ValueError("Node verified a different release identity")
            report["nodes"][node] = {"status": "verified", "identity": identity}
        except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
            report["nodes"][node] = {"status": "failed", "reason": str(error)}
    if all(item["status"] == "verified" for item in report["nodes"].values()):
        try:
            admit()
            publish_admission(gate, {"open": True, "release_id": expected["release_id"]})
            report["open"] = True
        except (RuntimeError, OSError, subprocess.SubprocessError) as error:
            report["admission_error"] = str(error)
    return report


def ssh(target, args, run=command):
    if not TARGET.fullmatch(target):
        raise ValueError("Invalid SSH target")
    return run(["ssh", "-oBatchMode=yes", target, shlex.join(args)])


def deliver_cli(expected, pool, run=command):
    """Controller-local orchestration; explicit active inventory, no discovery."""
    nodes = pool.get("nodes", [])
    if not nodes or not all(isinstance(node, dict) and IDENTIFIER.fullmatch(node.get("name", ""))
                            and node.get("role") in ("controller", "worker")
                            and TARGET.fullmatch(node.get("target", "")) for node in nodes):
        raise ValueError("Pool requires named controller/worker nodes and SSH targets")
    if len({node["name"] for node in nodes}) != len(nodes):
        raise ValueError("Pool node names must be unique")
    if sum(node["role"] == "controller" for node in nodes) != 1:
        raise ValueError("Select exactly one controller in the active pool")
    # The controller initially receives only the manifest, never CI's local store.
    # A bad cache or hash must leave both admission and current services untouched.
    prefetch_controller_closures(expected, run)
    expected = manifest(expected)
    workers = [node["name"] for node in nodes if node["role"] == "worker"]
    by_name = {node["name"]: node for node in nodes}
    encoded = base64.urlsafe_b64encode(json.dumps(expected).encode()).decode()

    def quiesce():
        run(["systemctl", "stop", "qcl-negf-api.service", "qcl-negf-aiida.service"])
        for worker in workers:
            run(["scontrol", "update", "NodeName=" + worker, "State=DRAIN", "Reason=application-release"])
        # All queued/running research must be resolved by the maintenance owner;
        # never cancel, requeue, or silently accept an old workflow here.
        if run(["squeue", "--all", "--noheader", "--format", "%i"]).strip():
            raise RuntimeError("Slurm still has running or queued jobs; resolve the old research before delivery")

    def deliver(name, value):
        node = by_name[name]
        run(["nix", "copy", "--to", "ssh-ng://" + node["target"], value["application_path"],
             str(Path(value["solver_executable"]).parents[1])])
        ssh(node["target"], ["sudo", "-n", "qcl-negf-release", "activate", "--manifest-base64", encoded,
                            "--role", node["role"]], run)
        result = ssh(node["target"], ["sudo", "-n", "qcl-negf-release", "check", "--manifest-base64", encoded,
                                     "--role", node["role"]], run)
        return json.loads(result)

    def admit():
        for worker in workers:
            run(["scontrol", "update", "NodeName=" + worker, "State=RESUME"])

    return deliver_pool(expected, list(by_name), deliver=deliver, quiesce=quiesce, admit=admit)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare-initial", "activate", "check", "guard", "node-check", "bootstrap-identity", "deliver"])
    parser.add_argument("--manifest")
    parser.add_argument("--manifest-base64")
    parser.add_argument("--role", choices=["controller", "worker"], default="worker")
    parser.add_argument("--pool")
    parser.add_argument("--release-id")
    parser.add_argument("--solver-executable")
    parser.add_argument("--runtime", type=Path, default=RUNTIME)
    parser.add_argument("--gate", type=Path, default=GATE)
    parser.add_argument("--returning-worker", action="store_true")
    parser.add_argument("--initial-label")
    args = parser.parse_args()
    if args.action == "bootstrap-identity":
        solver, label = bootstrap_selection(args.runtime / "release.json", args.solver_executable, args.initial_label)
        print(solver + "\n" + label)
        return
    if args.action == "node-check":
        node_check(args.runtime / "release.json", args.gate)
        return
    if args.action == "guard":
        guard(args.release_id, args.solver_executable, args.runtime / "release.json", args.gate)
        return
    if bool(args.manifest) == bool(args.manifest_base64):
        parser.error("Provide exactly one --manifest or --manifest-base64")
    manifest_value = load(args.manifest) if args.manifest else json.loads(base64.urlsafe_b64decode(args.manifest_base64))
    expected = manifest(manifest_value)
    if args.action == "check":
        result = check(expected, runtime=args.runtime, role=args.role)
    else:
        args.runtime.mkdir(parents=True, exist_ok=True)
        # One finite invocation at a time. This is a local flock, not a lease
        # service; a dead process releases it automatically.
        lock_file = "delivery.lock" if args.action == "deliver" else "activation.lock"
        with (args.runtime / lock_file).open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if args.action == "deliver":
                if not args.pool:
                    parser.error("Delivery requires an explicit --pool")
                result = deliver_cli(manifest_value, load(args.pool))
                publish_json(args.runtime / "delivery-report.json", result)
            elif args.action == "prepare-initial":
                result = prepare_initial(manifest_value, runtime=args.runtime, gate=args.gate, role=args.role)
            else:
                admission = load_admission(args.gate)
                if admission.get("release_id") != expected["release_id"] or (
                    admission.get("open") is not False and not (args.returning_worker and args.role == "worker")
                ):
                    raise ValueError("Close admission for the selected release before activation")
                settings = load("/etc/qcl-negf/release-config.json")
                result = activate(expected, runtime=args.runtime, role=args.role, email=settings.get("email"),
                                  allowed_codes_file=Path(settings.get("allowed_codes_file") or "/var/lib/qcl-negf/aiida/code-uuid"))
    print(json.dumps(result, sort_keys=True))
    if args.action == "deliver" and not result["open"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
