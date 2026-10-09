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
import math
import hashlib
import stat
import socket
from types import MappingProxyType
import selectors
import signal
import time
import uuid
from datetime import datetime, timezone
import tempfile
from urllib.parse import urlsplit


RUNTIME = Path("/var/lib/qcl-negf/runtime")
PROFILE = Path("/nix/var/nix/profiles/qcl-negf-application")
GATE = Path("/srv/qcl-negf/jobs/.release-admission.json")
IDENTIFIER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}\Z")
STORE_PATH = re.compile(r"/nix/store/[a-zA-Z0-9][a-zA-Z0-9+._?-]*\Z")
TARGET = re.compile(r"(?:[a-z_][a-z0-9_-]*@)?[a-zA-Z0-9][a-zA-Z0-9.-]*\Z")
NAR_HASH = re.compile(r"sha256-[A-Za-z0-9+/]{43}=\Z")


class CommandOutput(str):
    pass


class CommandFailure(RuntimeError):
    def __init__(self, record):
        self.record = record
        super().__init__("Command failed: " + record["failure"])


def duration(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
        raise ValueError(name + " must be finite and positive")
    return value


def output_bound(value):
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError("Output bound must be a positive integer")
    return value


def deadline_check(deadline):
    if deadline is not None and time.monotonic() >= deadline:
        raise CommandFailure({"failure": "deadline", "returncode": None, "elapsed_seconds": 0,
                              "stdout": "", "stderr": "", "output_truncated": False,
                              "cleanup_confirmed": True, "child_started": False})


def group_cleanup_confirmed(group, end):
    """Linux process evidence: zombies cannot execute or retain output pipes.

    Signal submission alone is not confirmation. Unknown /proc visibility or a
    live group member after the original cleanup reserve expires fails closed.
    """
    while time.monotonic() < end:
        live = False
        try:
            for entry in Path("/proc").iterdir():
                if time.monotonic() >= end:
                    return False
                if not entry.name.isdigit():
                    continue
                try:
                    fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
                    if int(fields[2]) == group and fields[0] not in ("Z", "X"):
                        live = True
                        break
                except (FileNotFoundError, ProcessLookupError):
                    continue
                except (PermissionError, ValueError, IndexError):
                    return False
        except OSError:
            return False
        if not live:
            return True
        time.sleep(min(.005, max(0, end - time.monotonic())))
    return False


def command(args, *, timeout_seconds=360.0, output_bytes=1048576,
            deadline=None, cleanup_seconds=2.0, env=None):
    """Bound only our local process group; killing SSH does not establish remote completion."""
    duration(timeout_seconds, "Command timeout")
    duration(cleanup_seconds, "Cleanup timeout")
    output_bound(output_bytes)
    if timeout_seconds <= cleanup_seconds:
        raise ValueError("Command timeout must exceed cleanup reserve")
    if deadline is not None:
        duration(deadline, "Deadline")
    start = time.monotonic()
    end = min(start + timeout_seconds, deadline) if deadline is not None else start + timeout_seconds
    record = {"failure": None, "returncode": None, "elapsed_seconds": 0,
              "stdout": "", "stderr": "", "output_truncated": False,
              "cleanup_confirmed": True, "child_started": False, "output_bytes": 0}
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    process = None
    selector = selectors.DefaultSelector()
    try:
        if start >= end - cleanup_seconds:
            record["failure"] = "deadline"
        else:
            try:
                process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, shell=False, start_new_session=True, env=env)
                record["child_started"] = True
            except OSError:
                record["failure"] = "spawn"
        if process is not None:
            for name in buffers:
                pipe = getattr(process, name)
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            while selector.get_map() or process.poll() is None:
                remaining = end - cleanup_seconds - time.monotonic()
                if remaining <= 0:
                    record["failure"] = "timeout"
                    break
                for key, _ in selector.select(min(.05, remaining)):
                    chunk = os.read(key.fileobj.fileno(), min(4096, output_bytes - record["output_bytes"] + 1))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    retained = min(len(chunk), output_bytes - record["output_bytes"])
                    buffers[key.data].extend(chunk[:retained])
                    record["output_bytes"] += retained
                    if retained < len(chunk):
                        record["failure"] = "output_limit"
                        record["output_truncated"] = True
                        break
                if record["failure"]:
                    break
            record["returncode"] = process.poll()
            if not record["failure"] and record["returncode"] != 0:
                record["failure"] = "nonzero"
    finally:
        # Even a successful immediate parent may have left descendants behind.
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=max(.001, end - time.monotonic()))
                record["returncode"] = process.returncode
                record["cleanup_confirmed"] = group_cleanup_confirmed(process.pid, end)
                if not record["cleanup_confirmed"]:
                    record["failure"] = "cleanup_unconfirmed"
            except subprocess.TimeoutExpired:
                record["cleanup_confirmed"] = False
                record["failure"] = "cleanup_unconfirmed"
            for name in buffers:
                getattr(process, name).close()
        selector.close()
        record["elapsed_seconds"] = time.monotonic() - start
        for name, data in buffers.items():
            record[name] = data.decode(errors="ignore")
    if record["failure"]:
        raise CommandFailure(record)
    output = CommandOutput(record["stdout"])
    output.output_bytes = record["output_bytes"]
    return output


TRUST_SNAPSHOTS = Path("/var/lib/qcl-negf/trust-snapshots")
IDENTITY_SCHEMA = "qcl-negf-node-identity-v1"
ENVELOPE_SCHEMA = "qcl-negf-node-release-check-v1"


def unique_json(raw, limit=65536):
    if not isinstance(raw, (str, bytes)) or len(raw.encode() if isinstance(raw, str) else raw) > limit:
        raise ValueError("Metadata exceeds its bound")
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate metadata key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=object_pairs)


def normalized_uuid(value):
    if not isinstance(value, str):
        raise ValueError("Missing UUID")
    try:
        result = uuid.UUID(value)
    except (ValueError, AttributeError) as error:
        raise ValueError("Invalid UUID") from error
    if result.int == 0:
        raise ValueError("Nil UUID")
    return str(result)


def identity_value(value):
    if not isinstance(value, dict) or value.get("schema") != IDENTITY_SCHEMA:
        raise ValueError("Expected observed node identity")
    result = {key: value.get(key) for key in ("schema", "role", "hostname", "node_name", "machine_uuid", "machine_id", "boot_id")}
    if result["role"] not in ("controller", "worker") or not isinstance(result["hostname"], str) or not TARGET.fullmatch(result["hostname"]) or "@" in result["hostname"]:
        raise ValueError("Invalid observed role/hostname")
    if result["role"] == "controller":
        if result["node_name"] is not None:
            raise ValueError("Controller must have node_name null")
    elif not isinstance(result["node_name"], str) or not IDENTIFIER.fullmatch(result["node_name"]):
        raise ValueError("Invalid observed NodeName")
    for key in ("machine_uuid", "boot_id"):
        result[key] = normalized_uuid(result[key])
    if not isinstance(result["machine_id"], str) or not re.fullmatch(r"[0-9a-f]{32}", result["machine_id"]) or int(result["machine_id"], 16) == 0:
        raise ValueError("Missing/invalid observed machine-id")
    return result


def enrollment_records(registry):
    if not isinstance(registry, dict) or registry.get("schema") != "qcl-negf-node-enrollment-v1":
        raise ValueError("Expected protected node enrollment v1")
    normalized_uuid(registry.get("inventory_id"))
    protected_parts(registry.get("known_hosts_file"))
    if set(registry) != {"schema", "inventory_id", "known_hosts_file", "nodes"}:
        raise ValueError("Unknown enrollment metadata fields")
    records = registry.get("nodes")
    if not isinstance(records, list) or not records:
        raise ValueError("Enrollment requires nodes")
    seen = {key: set() for key in ("enrollment_id", "name", "machine_uuid", "machine_id", "target")}
    result = []
    for raw in records:
        if not isinstance(raw, dict):
            raise ValueError("Malformed enrolled node")
        allowed = {"enrollment_id", "name", "role", "hostname", "node_name", "machine_uuid", "machine_id", "targets"}
        if raw.get("role") == "controller":
            allowed.add("primary_target")
        if set(raw) != allowed:
            raise ValueError("Unknown/missing enrolled node fields")
        record = dict(raw)
        record["enrollment_id"] = normalized_uuid(record.get("enrollment_id"))
        permanent = identity_value({**record, "schema": IDENTITY_SCHEMA,
                                   "boot_id": "11111111-1111-1111-1111-111111111111"})
        record.update({key: permanent[key] for key in ("role", "hostname", "node_name", "machine_uuid", "machine_id")})
        if not isinstance(record.get("name"), str) or not IDENTIFIER.fullmatch(record["name"]):
            raise ValueError("Invalid enrolled name")
        if record["role"] == "worker" and record["node_name"] != record["name"]:
            raise ValueError("Enrolled worker NodeName must equal name")
        for key in ("enrollment_id", "name", "machine_uuid", "machine_id"):
            if record[key] in seen[key]:
                raise ValueError("Duplicate enrolled " + key)
            seen[key].add(record[key])
        targets = record.get("targets")
        if not isinstance(targets, list) or not targets or not all(isinstance(target, str) and TARGET.fullmatch(target) for target in targets):
            raise ValueError("Enrollment requires explicit accepted targets")
        for target in targets:
            if target in seen["target"]:
                raise ValueError("Duplicate enrolled target")
            seen["target"].add(target)
        if record["role"] == "controller" and record.get("primary_target") not in targets:
            raise ValueError("Controller requires enrolled primary_target")
        record["targets"] = tuple(targets)
        result.append(MappingProxyType(record))
    if sum(record["role"] == "controller" for record in result) != 1:
        raise ValueError("Enrollment requires exactly one authoritative controller")
    return tuple(result)


def validate_enrollment(pool, registry):
    records = enrollment_records(registry)
    if not isinstance(pool, dict) or pool.get("schema") != "qcl-negf-active-pool-v2" or not isinstance(pool.get("nodes"), list) or not pool["nodes"]:
        raise ValueError("Expected active pool v2 with enrollment references")
    by_id = {record["enrollment_id"]: record for record in records}
    seen = {key: set() for key in ("enrollment_id", "name", "target")}
    selected = []
    for entry in pool["nodes"]:
        if not isinstance(entry, dict):
            raise ValueError("Malformed selected node")
        for key in seen:
            value = entry.get(key)
            if not isinstance(value, str) or value in seen[key]:
                raise ValueError("Missing/duplicate selected " + key)
            seen[key].add(value)
        if set(entry) != {"enrollment_id", "name", "role", "target"}:
            raise ValueError("Selected node must reference enrollment, not duplicate authority")
        record = by_id.get(entry["enrollment_id"])
        if record is None or entry.get("name") != record["name"] or entry.get("role") != record["role"] or entry["target"] not in record["targets"]:
            raise ValueError("Selected NodeName/role/target differs from enrollment")
        selected.append(MappingProxyType({**record, "target": entry["target"]}))
    if sum(record["role"] == "controller" for record in selected) != 1:
        raise ValueError("Select exactly one enrolled controller")
    return tuple(selected)


def bind_node_observation(binding, observation, *, prior_boot=None):
    actual = identity_value(observation)
    for key in ("role", "hostname", "node_name", "machine_uuid", "machine_id"):
        if actual[key] != binding.get(key):
            raise ValueError("Node identity " + key + " mismatch: expected " + str(binding.get(key)) + ", observed " + str(actual[key]))
    if prior_boot is not None and actual["boot_id"] != normalized_uuid(prior_boot):
        raise ValueError("Node boot_id changed")
    return MappingProxyType({**binding, "identity": MappingProxyType(actual)})


def verify_controller_authority(controller_binding, local_observation, remote_observation):
    if controller_binding.get("role") != "controller" or controller_binding.get("node_name") is not None:
        raise ValueError("Local owner requires enrolled controller")
    local = bind_node_observation(controller_binding, local_observation)
    bind_node_observation(controller_binding, remote_observation, prior_boot=local["identity"]["boot_id"])
    return local


def protected_parts(path):
    if not isinstance(path, (str, Path)):
        raise ValueError("Protected path must be absolute")
    path = str(path)
    if not path.startswith("/") or any(part in ("", ".", "..") for part in path.split("/")[1:]):
        raise ValueError("Protected path must be absolute without traversal")
    return path.split("/")[1:]


def trusted_stat(info, *, directory):
    if info.st_uid != 0 or info.st_mode & 0o022 or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise ValueError("Unprotected namespace owner/mode/type")


@contextmanager
def protected_directory(path):
    parts = [] if str(path) == "/" else protected_parts(path)
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        trusted_stat(os.fstat(descriptor), directory=True)
        for part in parts:
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = following
            trusted_stat(os.fstat(descriptor), directory=True)
        yield descriptor
    finally:
        os.close(descriptor)


def read_protected_file(path, limit=65536):
    parts = protected_parts(path)
    with protected_directory("/" + "/".join(parts[:-1])) as parent:
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            trusted_stat(os.fstat(descriptor), directory=False)
            chunks = bytearray()
            while len(chunks) <= limit:
                chunk = os.read(descriptor, min(4096, limit + 1 - len(chunks)))
                if not chunk:
                    return bytes(chunks)
                chunks.extend(chunk)
            raise ValueError("Protected metadata exceeds bound")
        finally:
            os.close(descriptor)


def load_enrollment(path):
    raw = read_protected_file(path)
    registry = unique_json(raw)
    enrollment_records(registry)
    known = read_protected_file(registry["known_hosts_file"])
    if not known:
        raise ValueError("Enrollment known_hosts is empty")
    return {"registry": registry, "registry_sha256": hashlib.sha256(raw).hexdigest(), "known_hosts_bytes": known}


def freeze_ssh_trust(verified_bytes, *, snapshot_root=TRUST_SNAPSHOTS):
    if not isinstance(verified_bytes, bytes) or not verified_bytes or len(verified_bytes) > 65536:
        raise ValueError("Invalid verified known_hosts bytes")
    name = str(uuid.uuid4())
    with protected_directory(snapshot_root) as parent:
        os.mkdir(name, 0o700, dir_fd=parent)
        directory = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            trusted_stat(os.fstat(directory), directory=True)
            descriptor = os.open("known_hosts", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=directory)
            try:
                trusted_stat(os.fstat(descriptor), directory=False)
                view = memoryview(verified_bytes)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError("Trust snapshot write made no progress")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.fsync(directory)
            os.fsync(parent)
        finally:
            os.close(directory)
    return MappingProxyType({"path": str(Path(snapshot_root) / name / "known_hosts"),
                             "sha256": hashlib.sha256(verified_bytes).hexdigest()})


def trust_options(trust_snapshot):
    if not isinstance(trust_snapshot, (dict, MappingProxyType)) or not re.fullmatch(r"[0-9a-f]{64}", str(trust_snapshot.get("sha256", ""))):
        raise ValueError("Required frozen SSH trust snapshot")
    protected_parts(trust_snapshot.get("path"))
    return ["-F", "/dev/null", "-oStrictHostKeyChecking=yes", "-oUserKnownHostsFile=" + trust_snapshot["path"],
            "-oGlobalKnownHostsFile=/dev/null", "-oUpdateHostKeys=no", "-oKnownHostsCommand=none"]


def local_metadata(path, limit=16384):
    with Path(path).open("rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Local identity metadata exceeds bound")
    return data


def slurmd_pids():
    result = []
    for path in Path("/proc").iterdir():
        if not path.name.isdigit():
            continue
        try:
            if local_metadata(path / "comm", 256).strip() == b"slurmd":
                result.append(int(path.name))
        except (FileNotFoundError, ProcessLookupError):
            continue
    return result


def worker_daemon_binding(config, hostname, run):
    conf = config.get("slurm_conf")
    if not isinstance(conf, str) or not Path(conf).is_absolute():
        raise ValueError("Unsupported worker: missing explicit SLURM_CONF")
    config_bytes = local_metadata(conf)
    raw = run(["systemctl", "show", "slurmd.service", "--property=MainPID", "--property=InvocationID", "--property=Environment"])
    service = {}
    for line in raw.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in service:
            raise ValueError("Unsupported worker: ambiguous daemon service")
        service[key] = value
    pid = service.get("MainPID", "")
    if not pid.isdigit() or int(pid) <= 0 or not re.fullmatch(r"[0-9a-f]{32}", service.get("InvocationID", "")):
        raise ValueError("Unsupported worker: missing daemon invocation")
    if slurmd_pids() != [int(pid)]:
        raise ValueError("Unsupported worker: multiple/missing slurmd daemons")
    args = [part.decode() for part in local_metadata("/proc/" + pid + "/cmdline").split(b"\0") if part]
    if not args or Path(args[0]).name != "slurmd" or any(arg not in ("-D", "-s", "-v", "-vv") for arg in args[1:]):
        raise ValueError("Unsupported worker: slurmd NodeName/dynamic/config override")
    environment = [part.decode() for part in local_metadata("/proc/" + pid + "/environ").split(b"\0") if part]
    runtime_confs = [value.split("=", 1)[1] for value in environment if value.startswith("SLURM_CONF=")]
    unit_confs = [value.split("=", 1)[1] for value in shlex.split(service.get("Environment", "")) if value.startswith("SLURM_CONF=")]
    if runtime_confs != [conf] or unit_confs != [conf]:
        raise ValueError("Unsupported worker: different daemon SLURM_CONF")
    aliases = run(["env", "SLURM_CONF=" + conf, "scontrol", "show", "aliases", hostname]).strip()
    # Narrow supported response; actual pinned-site format still needs a smoke gate.
    match = re.fullmatch(r"NodeName=([a-zA-Z0-9][a-zA-Z0-9._-]{0,63})", aliases)
    if not match:
        raise ValueError("Unsupported worker: ambiguous/missing canonical aliases")
    return match.group(1), (config_bytes, service, tuple(args), tuple(runtime_confs))


def observe_node_identity(*, run=command, controller_only=False):
    def machine():
        return {"machine_uuid": local_metadata("/sys/class/dmi/id/product_uuid").decode().strip().lower(),
                "machine_id": local_metadata("/etc/machine-id").decode().strip(),
                "boot_id": local_metadata("/proc/sys/kernel/random/boot_id").decode().strip().lower()}
    configuration = local_metadata("/etc/qcl-negf/release-config.json")
    config = unique_json(configuration, 16384)
    role = config.get("role")
    if controller_only and role != "controller":
        raise ValueError("Local invoking machine is not the enrolled controller")
    hostname = socket.gethostname()
    before = machine()
    daemon_before = None
    node = None
    if role == "worker":
        node, daemon_before = worker_daemon_binding(config, hostname, run)
    elif role != "controller":
        raise ValueError("Missing Nix-generated observed local role")
    after = machine()
    if before != after or hostname != socket.gethostname() or configuration != local_metadata("/etc/qcl-negf/release-config.json"):
        raise ValueError("Local machine/boot/config changed during observation")
    if role == "worker":
        node_after, daemon_after = worker_daemon_binding(config, hostname, run)
        if node_after != node or daemon_after != daemon_before:
            raise ValueError("Worker daemon/config changed during observation")
    return identity_value({"schema": IDENTITY_SCHEMA, "role": role, "hostname": hostname, "node_name": node, **before})


def identity_probe(target, *, trust_snapshot, run):
    return unique_json(ssh(target, ["sudo", "-n", "qcl-negf-release", "identity"], run,
                           trust_snapshot=trust_snapshot), 16384)


def preflight_controller_authority(enrollment_path, pool=None, *, observe_local=None,
                                   run=command, deadline, command_timeout_seconds,
                                   command_output_bytes, delivery_output_bytes,
                                   snapshot_root=TRUST_SNAPSHOTS, before_remote=None):
    if duration(command_timeout_seconds, "Authority command timeout") <= 2:
        raise ValueError("Authority command timeout must exceed cleanup reserve")
    duration(deadline, "Authority deadline")
    output_bound(command_output_bytes)
    output_bound(delivery_output_bytes)
    loaded = load_enrollment(enrollment_path)
    registry = loaded["registry"]
    records = enrollment_records(registry)
    bindings = validate_enrollment(pool, registry) if pool is not None else tuple(
        MappingProxyType({**record, "target": record.get("primary_target")}) for record in records)
    controller = next(record for record in bindings if record["role"] == "controller")
    used = 0
    def bounded(args):
        nonlocal used
        deadline_check(deadline)
        available = min(command_output_bytes, delivery_output_bytes - used)
        if available <= 0:
            raise ValueError("Authority output budget exhausted")
        output = (run(args, timeout_seconds=command_timeout_seconds, output_bytes=available, deadline=deadline)
                  if run is command else run(args))
        count = getattr(output, "output_bytes", len(output.encode()))
        used += count
        if count > available or used > delivery_output_bytes:
            raise ValueError("Authority output budget exceeded")
        deadline_check(deadline)
        return output
    observer = observe_local or observe_node_identity
    local = observer(run=bounded, controller_only=True)
    bind_node_observation(controller, local)
    if before_remote is not None:
        before_remote()
    deadline_check(deadline)
    snapshot = freeze_ssh_trust(loaded["known_hosts_bytes"], snapshot_root=snapshot_root)
    remote = identity_probe(controller["target"], trust_snapshot=snapshot, run=bounded)
    verify_controller_authority(controller, local, remote)
    current = observer(run=bounded, controller_only=True)
    verify_controller_authority(controller, current, remote)
    if identity_value(current) != identity_value(local):
        raise ValueError("Local controller generation changed during preflight")
    return {"schema": "qcl-negf-controller-authority-v1", "registry": registry,
            "registry_sha256": loaded["registry_sha256"], "controller_binding": controller,
            "local_identity": identity_value(local), "remote_identity": identity_value(remote),
            "trust_snapshot": snapshot, "used_output_bytes": used, "bindings": bindings}


def recheck_controller_authority(authority, *, run=command):
    if not isinstance(authority, dict) or authority.get("schema") != "qcl-negf-controller-authority-v1":
        raise ValueError("Required controller authority context")
    current = observe_node_identity(run=run, controller_only=True)
    verify_controller_authority(authority["controller_binding"], current, authority["remote_identity"])
    if identity_value(current) != authority["local_identity"]:
        raise ValueError("Local controller generation changed")
    return current


def verify_node_envelope(binding, envelope, expected):
    if not isinstance(envelope, dict) or envelope.get("schema") != ENVELOPE_SCHEMA:
        error = ValueError("Fleet requires bound node release envelope")
        error.uncertain = True
        raise error
    try:
        bind_node_observation(binding, envelope.get("node_identity"), prior_boot=binding["identity"]["boot_id"])
    except ValueError as error:
        error.uncertain = True
        raise
    value = envelope.get("release")
    if not isinstance(value, dict) or value.get("ready") is not True or manifest(value) != expected:
        raise ValueError("Node release verification failed")
    return value


def assert_expected_node(expected_node_identity, *, role, run=command):
    expected = identity_value(expected_node_identity)
    if expected["role"] != role:
        raise ValueError("Caller role conflicts with observed expected node")
    actual = observe_node_identity(run=run)
    bind_node_observation(expected, actual, prior_boot=expected["boot_id"])
    return actual


def unresolved_deliveries(runtime):
    attempts = Path(runtime) / "delivery-attempts"
    if attempts.exists():
        for path in attempts.glob("*.json"):
            previous = load(path)
            if previous.get("schema") == "qcl-negf-admission-intent-v1" or previous.get("requires_reconciliation") or (previous.get("status") == "running" and previous.get("pending_command", {}).get("mutation")):
                raise RuntimeError("Unresolved delivery requires trusted operator reconciliation")


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


def prefetch_controller_closures(value, run=command, *, validate_only=False):
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
    if validate_only:
        return hashes
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


def publish(path, value, *, mode=0o644):
    """Publish complete public runtime configuration and fsync the directory."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        try:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
            os.fchmod(handle.fileno(), mode)
            os.replace(temporary, path)
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)


def publish_json(path, value, *, mode=0o644):
    publish(path, json.dumps(value, sort_keys=True) + "\n", mode=mode)


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


def check(manifest_value, *, profile=PROFILE, runtime=RUNTIME, role="worker", run=command,
          expected_node_identity=None):
    bound_before = assert_expected_node(expected_node_identity, role=role, run=run) if expected_node_identity is not None else None
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
    if bound_before is not None:
        bound_after = assert_expected_node(expected_node_identity, role=role, run=run)
        if bound_before != bound_after:
            raise ValueError("Node changed during release check")
        return {"schema": ENVELOPE_SCHEMA, "node_identity": bound_after, "release": current}
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
             email=None, allowed_codes_file=Path("/var/lib/qcl-negf/aiida/code-uuid"),
             expected_node_identity=None):
    bound_node = assert_expected_node(expected_node_identity, role=role, run=run) if expected_node_identity is not None else None
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
    if bound_node is not None:
        identity["node_identity"] = bound_node
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


def deliver_pool(manifest_value, nodes, gate=GATE, *, deliver, quiesce, admit=lambda: None,
                 deadline=None, checkpoint=None, bindings=None, authority=None, authority_run=command):
    expected = manifest(manifest_value)
    if not isinstance(bindings, dict) or set(bindings) != set(nodes):
        raise ValueError("Required full selected node bindings")
    observed = [bindings[node].get("identity") for node in nodes]
    if any(identity is None for identity in observed):
        raise ValueError("Missing preflight observed node binding")
    for key in ("machine_uuid", "machine_id"):
        if len({identity[key] for identity in observed}) != len(nodes):
            raise ValueError("Duplicate actual selected machine")
    recheck_controller_authority(authority, run=authority_run)
    if not nodes or len(set(nodes)) != len(nodes):
        raise ValueError("Select a nonempty pool of unique active nodes")
    report = {"release_id": expected["release_id"], "open": False, "status": "running",
              "gate_changed": False, "nodes": {node: {"status": "not_attempted"} for node in nodes}}
    def save(phase):
        report["phase"] = phase
        if checkpoint:
            checkpoint(report)
    save("close_admission")
    deadline_check(deadline)
    publish_admission(gate, {"open": False, "release_id": expected["release_id"]})
    report["gate_changed"] = True
    save("quiesce")
    deadline_check(deadline)
    quiesce()
    save("quiesced")
    for node in nodes:
        report["node"] = node
        save("deliver")
        try:
            deadline_check(deadline)
            envelope = deliver(node, expected)
            deadline_check(deadline)
            identity = verify_node_envelope(bindings[node], envelope, expected)
            report["nodes"][node] = {"status": "verified", "identity": identity,
                                      "node_identity": dict(bindings[node]["identity"])}
        except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
            report["nodes"][node] = {"status": "failed", "reason": str(error)}
            if isinstance(error, CommandFailure):
                report["command_failure"] = error.record
            if getattr(error, "uncertain", False):
                report.update(requires_reconciliation=True, remote_outcome="unknown")
            save("node_failed")
            if isinstance(error, CommandFailure) or getattr(error, "uncertain", False):
                break
        save("node_finished")
    if all(item["status"] == "verified" for item in report["nodes"].values()):
        try:
            save("admit")
            deadline_check(deadline)
            recheck_controller_authority(authority, run=authority_run)
            admit()
            deadline_check(deadline)
            report["admission_pending"] = True
            save("open_admission")
            deadline_check(deadline)
            recheck_controller_authority(authority, run=authority_run)
            publish_admission(gate, {"open": True, "release_id": expected["release_id"]})
            report.update(open=True, status="completed")
            save("finished")
            return report
        except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
            report["admission_error"] = str(error)
            if report.get("admission_pending"):
                close_after_failure(report, expected, gate)
            elif getattr(error, "uncertain", False):
                report.update(requires_reconciliation=True, remote_outcome="unknown")
    report["status"] = "failed"
    save("finished")
    return report


def close_after_failure(report, expected, gate):
    """One recovery publication, never assume replace/fsync failure left old bytes."""
    report.update(status="failed", requires_reconciliation=True, admission_outcome="unknown")
    try:
        publish_admission(gate, {"open": False, "release_id": expected["release_id"]})
        report.update(open=False, admission_state="closed")
    except (ValueError, RuntimeError, OSError) as error:
        report.update(open=None, admission_state="unknown", critical_admission_failure=True,
                      close_error=str(error))


SSH_OPTIONS = ["-oBatchMode=yes", "-oConnectionAttempts=1", "-oConnectTimeout=10",
               "-oServerAliveInterval=15", "-oServerAliveCountMax=2",
               "-oControlMaster=no", "-oControlPath=none"]

def ssh(target, args, run=command, *, trust_snapshot):
    if not TARGET.fullmatch(target):
        raise ValueError("Invalid SSH target")
    return run(["ssh", *SSH_OPTIONS, *trust_options(trust_snapshot), target, shlex.join(args)])


def deliver_cli(expected, pool, run=command, *, enrollment, runtime=RUNTIME, gate=GATE,
                delivery_timeout_seconds=1800.0, command_timeout_seconds=360.0,
                command_output_bytes=1048576, delivery_output_bytes=8388608):
    """Authority precondition precedes local writes and lock; no inventory fallback."""
    start = time.monotonic()
    for value in (delivery_timeout_seconds, command_timeout_seconds):
        if duration(value, "CLI timeout") <= 2:
            raise ValueError("CLI timeout must exceed 2 seconds")
    output_bound(command_output_bytes)
    output_bound(delivery_output_bytes)
    deadline = start + delivery_timeout_seconds
    prefetch_controller_closures(expected, validate_only=True)
    authority = preflight_controller_authority(enrollment, pool, run=run, deadline=deadline,
        command_timeout_seconds=command_timeout_seconds, command_output_bytes=command_output_bytes,
        delivery_output_bytes=delivery_output_bytes, before_remote=lambda: unresolved_deliveries(runtime))
    deadline_check(deadline)
    runtime = Path(runtime)
    runtime.mkdir(parents=True, exist_ok=True)
    with (runtime / "delivery.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        recheck_controller_authority(authority, run=run)
        unresolved_deliveries(runtime)
        return _deliver_cli_locked(expected, pool, run, runtime=runtime, gate=gate, authority=authority,
            start=start, deadline=deadline, command_timeout_seconds=command_timeout_seconds,
            command_output_bytes=command_output_bytes, delivery_output_bytes=delivery_output_bytes)


def _deliver_cli_locked(expected, pool, run, *, runtime, gate, authority, start, deadline,
                        command_timeout_seconds, command_output_bytes, delivery_output_bytes):
    runtime = Path(runtime)
    attempts = runtime / "delivery-attempts"
    attempts.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(attempts, 0o700)
    attempt_id = str(uuid.uuid4())
    receipt_path = attempts / (attempt_id + ".json")
    intent_path = attempts / (attempt_id + ".admission-intent.json")
    receipt = {"schema": "qcl-negf-delivery-attempt-v1", "attempt_id": attempt_id,
               "manifest": expected, "identity": manifest(expected), "status": "running",
               "started_utc": datetime.now(timezone.utc).isoformat(), "gate_changed": False,
               "admission_before": None, "commands": [], "nodes": {}, "open": False,
               "controller_authority": {"registry_sha256": authority["registry_sha256"],
                   "inventory_id": authority["registry"]["inventory_id"],
                   "local_identity": authority["local_identity"], "remote_identity": authority["remote_identity"],
                   "trust_snapshot": dict(authority["trust_snapshot"])}}
    raw_gate = read_admission(gate, missing=True)
    if raw_gate is not None:
        try:
            receipt["admission_before"] = json.loads(raw_gate)
        except ValueError:
            receipt["admission_before"] = {"unparsed": True}
    def safe_summary():
        summary = {key: receipt[key] for key in ("attempt_id", "status", "open", "gate_changed",
                   "release_id", "requires_reconciliation", "remote_outcome", "admission_state",
                   "critical_admission_failure") if key in receipt}
        summary["receipt"] = str(receipt_path)
        return summary
    def checkpoint(report=None):
        if report:
            receipt.update(report)
        if receipt.get("admission_pending") and not intent_path.exists():
            publish_json(intent_path, {"schema": "qcl-negf-admission-intent-v1",
                "attempt_id": attempt_id, "identity": receipt["identity"]}, mode=0o600)
        receipt["elapsed_seconds"] = time.monotonic() - start
        if receipt["status"] != "running":
            receipt["ended_utc"] = datetime.now(timezone.utc).isoformat()
        publish_json(receipt_path, receipt, mode=0o600)
        publish_json(runtime / "delivery-report.json", safe_summary())
    checkpoint()
    native = run is command
    original_run = run
    used_output = authority["used_output_bytes"]
    stage = {"phase": "prefetch", "node": None, "remote": False, "mutation": False}
    def dispatch(args):
        nonlocal used_output
        deadline_check(deadline)
        available = min(command_output_bytes, delivery_output_bytes - used_output)
        if available <= 0:
            raise CommandFailure({"failure": "output_limit", "returncode": None,
                "elapsed_seconds": 0, "stdout": "", "stderr": "", "output_truncated": True,
                "cleanup_confirmed": True, "child_started": False})
        pending = {**stage, "executable": Path(args[0]).name}
        if args[0] in ("squeue",) or args[:2] == ["nix", "path-info"]:
            pending["mutation"] = False
        receipt.update(phase=stage["phase"], node=stage["node"], pending_command=pending)
        checkpoint()
        completed_dispatch = False
        entered_callable = False
        try:
            env = None
            if native and args[:2] == ["nix", "copy"]:
                env = dict(os.environ)
                env["NIX_SSHOPTS"] = shlex.join(SSH_OPTIONS + trust_options(authority["trust_snapshot"]) + shlex.split(env.get("NIX_SSHOPTS", "")))
            entered_callable = True
            output = (original_run(args, timeout_seconds=command_timeout_seconds, output_bytes=available,
                                   deadline=deadline, env=env) if native else original_run(args))
            completed_dispatch = True
            count = getattr(output, "output_bytes", len(output.encode()))
            used_output += count
            if count > available:
                raise CommandFailure({"failure": "output_limit", "returncode": None,
                    "elapsed_seconds": 0, "stdout": output.encode()[:available].decode(errors="replace"),
                    "stderr": "", "output_truncated": True, "cleanup_confirmed": True,
                    "child_started": True})
            deadline_check(deadline)
            receipt["commands"].append({**pending, "status": "completed", "output_bytes": count})
            receipt.pop("pending_command", None)
            checkpoint()
            return output
        except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
            record = error.record if isinstance(error, CommandFailure) else {"failure": type(error).__name__,
                      "returncode": None, "stdout": "", "stderr": "", "child_started": entered_callable}
            if completed_dispatch:
                record["child_started"] = True
            used_output += record.get("output_bytes", 0)
            receipt["commands"].append({**pending, "status": "failed", "record": record})
            started = record.get("child_started", True)
            uncertain = (not record.get("cleanup_confirmed", True) or
                         (started and pending["mutation"] and record["failure"] in ("timeout", "deadline", "output_limit")) or
                         (stage["remote"] and started and
                         (stage["mutation"] or record.get("returncode") == 255 or isinstance(error, RuntimeError))))
            if uncertain:
                error.uncertain = True
                receipt.update(requires_reconciliation=True, remote_outcome="unknown")
            receipt.pop("pending_command", None)
            checkpoint()
            raise
    run = dispatch
    try:
        nodes = pool["nodes"]
        selected = {binding["name"]: binding for binding in authority["bindings"]}
        bindings = {}
        mutation_started = False
        def probe(name, *, prior_boot=None):
            stage.update(phase="node_identity", node=name, remote=False, mutation=False)
            try:
                actual = identity_probe(selected[name]["target"], trust_snapshot=authority["trust_snapshot"], run=run)
                bound = bind_node_observation(selected[name], actual, prior_boot=prior_boot)
                if selected[name]["role"] == "controller":
                    verify_controller_authority(selected[name], authority["local_identity"], actual)
                return bound
            except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
                if mutation_started:
                    error.uncertain = True
                    receipt.update(requires_reconciliation=True, remote_outcome="unknown")
                raise
        for name in selected:
            bindings[name] = probe(name)
        for key in ("machine_uuid", "machine_id"):
            if len({binding["identity"][key] for binding in bindings.values()}) != len(bindings):
                raise ValueError("Duplicate actual selected machine")
        receipt["node_bindings"] = {name: dict(binding["identity"]) for name, binding in bindings.items()}
        checkpoint()
        stage.update(phase="prefetch", node=None, remote=False, mutation=False)
        # The controller initially receives only the manifest, never CI's local store.
        # A bad cache or hash must leave both admission and current services untouched.
        prefetch_controller_closures(expected, run)
        expected = manifest(expected)
        workers = [node["name"] for node in nodes if node["role"] == "worker"]
        by_name = {node["name"]: node for node in nodes}
        encoded = base64.urlsafe_b64encode(json.dumps(expected).encode()).decode()

        def quiesce():
            nonlocal mutation_started
            # deliver_pool already published the closed gate: identity drift is
            # terminal from maintenance onward, including the first pre-copy probe.
            mutation_started = True
            stage.update(phase="quiesce", remote=False, mutation=True)
            run(["systemctl", "stop", "qcl-negf-api.service", "qcl-negf-aiida.service"])
            for worker in workers:
                run(["scontrol", "update", "NodeName=" + worker, "State=DRAIN", "Reason=application-release"])
            # All queued/running research must be resolved by the maintenance owner;
            # never cancel, requeue, or silently accept an old workflow here.
            if run(["squeue", "--all", "--noheader", "--format", "%i"]).strip():
                raise RuntimeError("Slurm still has running or queued jobs; resolve the old research before delivery")

        def deliver(name, value):
            nonlocal mutation_started
            node = by_name[name]
            probe(name, prior_boot=bindings[name]["identity"]["boot_id"])
            mutation_started = True
            expected_node = base64.urlsafe_b64encode(json.dumps(dict(bindings[name]["identity"])).encode()).decode()
            stage.update(phase="copy", node=name, remote=True, mutation=True)
            run(["nix", "copy", "--to", "ssh-ng://" + node["target"], value["application_path"],
                 str(Path(value["solver_executable"]).parents[1])])
            stage.update(phase="activate", mutation=True)
            ssh(node["target"], ["sudo", "-n", "qcl-negf-release", "activate", "--manifest-base64", encoded,
                                "--role", node["role"], "--command-timeout-seconds", str(command_timeout_seconds),
                                "--command-output-bytes", str(command_output_bytes),
                                "--expected-node-identity-base64", expected_node], run,
                                trust_snapshot=authority["trust_snapshot"])
            stage.update(phase="check", mutation=False)
            result = ssh(node["target"], ["sudo", "-n", "qcl-negf-release", "check", "--manifest-base64", encoded,
                                         "--role", node["role"], "--command-timeout-seconds", str(command_timeout_seconds),
                                "--command-output-bytes", str(command_output_bytes),
                                "--expected-node-identity-base64", expected_node], run,
                                trust_snapshot=authority["trust_snapshot"])
            try:
                return unique_json(result, command_output_bytes)
            except ValueError as error:
                error.uncertain = True
                receipt.update(requires_reconciliation=True, remote_outcome="unknown",
                               response_prefix=result[:command_output_bytes])
                raise

        def admit():
            for name in selected:
                probe(name, prior_boot=bindings[name]["identity"]["boot_id"])
            recheck_controller_authority(authority, run=run)
            stage.update(phase="admit", remote=False, mutation=True)
            for worker in workers:
                run(["scontrol", "update", "NodeName=" + worker, "State=RESUME"])

        report = deliver_pool(expected, list(by_name), gate, deliver=deliver, quiesce=quiesce, admit=admit,
                              deadline=deadline, checkpoint=checkpoint, bindings=bindings, authority=authority, authority_run=run)
        if report.get("status") == "completed" and intent_path.exists():
            try:
                # Last fallible success action. Crash may restore an unsynced deletion,
                # conservatively blocking reconciliation, never erasing a pending failure.
                intent_path.unlink()
            except OSError as error:
                close_after_failure(report, expected, gate)
                report["admission_error"] = str(error)
                checkpoint(report)
        return {**report, "attempt_id": attempt_id, "receipt": str(receipt_path),
                "requires_reconciliation": receipt.get("requires_reconciliation", False)}

    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
        receipt.update(status="failed", reason=str(error))
        try:
            checkpoint()
        except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as write_error:
            write_error.delivery_summary = safe_summary()
            raise
        error.delivery_summary = safe_summary()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare-initial", "activate", "check", "guard", "node-check", "bootstrap-identity", "identity", "deliver"])
    parser.add_argument("--manifest")
    parser.add_argument("--manifest-base64")
    parser.add_argument("--role", choices=["controller", "worker"], default="worker")
    parser.add_argument("--pool")
    parser.add_argument("--enrollment")
    parser.add_argument("--expected-node-identity-base64")
    parser.add_argument("--release-id")
    parser.add_argument("--solver-executable")
    parser.add_argument("--runtime", type=Path, default=RUNTIME)
    parser.add_argument("--gate", type=Path, default=GATE)
    parser.add_argument("--returning-worker", action="store_true")
    parser.add_argument("--initial-label")
    parser.add_argument("--delivery-timeout-seconds", type=float, default=1800)
    parser.add_argument("--command-timeout-seconds", type=float, default=360)
    parser.add_argument("--command-output-bytes", type=int, default=1048576)
    parser.add_argument("--delivery-output-bytes", type=int, default=8388608)
    args = parser.parse_args()
    def native_run(argv):
        return command(argv, timeout_seconds=args.command_timeout_seconds, output_bytes=args.command_output_bytes)
    if args.action == "identity":
        print(json.dumps(observe_node_identity(run=native_run), sort_keys=True))
        return
    if args.action == "bootstrap-identity":
        solver, label = bootstrap_selection(args.runtime / "release.json", args.solver_executable, args.initial_label)
        print(solver + "\n" + label)
        return
    if args.action == "node-check":
        node_check(args.runtime / "release.json", args.gate, run=native_run)
        return
    if args.action == "guard":
        guard(args.release_id, args.solver_executable, args.runtime / "release.json", args.gate)
        return
    if bool(args.manifest) == bool(args.manifest_base64):
        parser.error("Provide exactly one --manifest or --manifest-base64")
    manifest_value = load(args.manifest) if args.manifest else json.loads(base64.urlsafe_b64decode(args.manifest_base64))
    expected = manifest(manifest_value)
    expected_node = unique_json(base64.urlsafe_b64decode(args.expected_node_identity_base64), 16384) if args.expected_node_identity_base64 else None
    if args.action == "activate" and expected_node is not None:
        assert_expected_node(expected_node, role=args.role, run=native_run)
    if args.action == "deliver":
        if not args.pool or not args.enrollment:
            parser.error("Delivery requires --pool v2 and protected --enrollment")
        try:
            result = deliver_cli(manifest_value, load(args.pool), enrollment=args.enrollment,
                runtime=args.runtime, gate=args.gate, delivery_timeout_seconds=args.delivery_timeout_seconds,
                command_timeout_seconds=args.command_timeout_seconds,
                command_output_bytes=args.command_output_bytes, delivery_output_bytes=args.delivery_output_bytes)
        except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
            result = getattr(error, "delivery_summary", None)
            if result is None:
                result = {"open": None, "admission_state": "unknown", "requires_reconciliation": True}
            result = {**result, "status": "failed", "error": type(error).__name__}
    elif args.action == "check":
        result = check(expected, runtime=args.runtime, role=args.role, run=native_run, expected_node_identity=expected_node)
    else:
        args.runtime.mkdir(parents=True, exist_ok=True)
        # One finite invocation at a time. This is a local flock, not a lease
        # service; a dead process releases it automatically.
        lock_file = "delivery.lock" if args.action == "deliver" else "activation.lock"
        with (args.runtime / lock_file).open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if args.action == "prepare-initial":
                result = prepare_initial(manifest_value, runtime=args.runtime, gate=args.gate, role=args.role, run=native_run)
            else:
                admission = load_admission(args.gate)
                if admission.get("release_id") != expected["release_id"] or (
                    admission.get("open") is not False and not (args.returning_worker and args.role == "worker")
                ):
                    raise ValueError("Close admission for the selected release before activation")
                settings = load("/etc/qcl-negf/release-config.json")
                result = activate(expected, runtime=args.runtime, role=args.role, email=settings.get("email"),
                                  run=native_run, allowed_codes_file=Path(settings.get("allowed_codes_file") or "/var/lib/qcl-negf/aiida/code-uuid"),
                                  expected_node_identity=expected_node)
    print(json.dumps(result, sort_keys=True))
    if args.action == "deliver" and (result.get("status") != "completed" or not result.get("open")):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
