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
def protected_directory(path, *, budget=None):
    parts = [] if str(path) == "/" else protected_parts(path)
    if budget:budget.before()
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if budget:budget.before()
        trusted_stat(os.fstat(descriptor), directory=True)
        for part in parts:
            if budget:budget.before()
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = following
            if budget:budget.before()
            trusted_stat(os.fstat(descriptor), directory=True)
        yield descriptor
    finally:
        os.close(descriptor)


def read_protected_file(path, limit=65536, *, budget=None):
    if budget:budget.reserve(min(4096,limit+1))
    parts = protected_parts(path)
    first_read=True
    with protected_directory("/" + "/".join(parts[:-1]),budget=budget) as parent:
        if budget:budget.before()
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            if budget:budget.before()
            trusted_stat(os.fstat(descriptor), directory=False)
            chunks = bytearray()
            while len(chunks) <= limit:
                n=min(4096,limit+1-len(chunks))
                if budget and not first_read:budget.reserve(n)
                first_read=False
                chunk = os.read(descriptor,n)
                if budget:budget.actual_bytes+=len(chunk);budget.before()
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


def slurmd_pids(*,metadata_budget=None):
    result = []
    for path in (metadata_budget.entries("/proc","pid") if metadata_budget else Path("/proc").iterdir()):
        if not path.name.isdigit():
            continue
        try:
            if (metadata_budget.read if metadata_budget else local_metadata)(path / "comm", 256).strip() == b"slurmd":
                result.append(int(path.name))
        except (FileNotFoundError, ProcessLookupError):
            continue
    return result


def worker_daemon_binding(config, hostname, run,metadata_budget=None):
    read=metadata_budget.read if metadata_budget else local_metadata
    conf = config.get("slurm_conf")
    if not isinstance(conf, str) or not Path(conf).is_absolute():
        raise ValueError("Unsupported worker: missing explicit SLURM_CONF")
    config_bytes = read(conf)
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
    if (slurmd_pids(metadata_budget=metadata_budget) if metadata_budget else slurmd_pids()) != [int(pid)]:
        raise ValueError("Unsupported worker: multiple/missing slurmd daemons")
    args = [part.decode() for part in read("/proc/" + pid + "/cmdline").split(b"\0") if part]
    if not args or Path(args[0]).name != "slurmd" or any(arg not in ("-D", "-s", "-v", "-vv") for arg in args[1:]):
        raise ValueError("Unsupported worker: slurmd NodeName/dynamic/config override")
    environment = [part.decode() for part in read("/proc/" + pid + "/environ").split(b"\0") if part]
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


def observe_node_identity(*, run=command, controller_only=False,metadata_budget=None):
    read=metadata_budget.read if metadata_budget else local_metadata
    def machine():
        return {"machine_uuid": read("/sys/class/dmi/id/product_uuid").decode().strip().lower(),
                "machine_id": read("/etc/machine-id").decode().strip(),
                "boot_id": read("/proc/sys/kernel/random/boot_id").decode().strip().lower()}
    configuration = read("/etc/qcl-negf/release-config.json")
    config = unique_json(configuration, 16384)
    role = config.get("role")
    if controller_only and role != "controller":
        raise ValueError("Local invoking machine is not the enrolled controller")
    hostname = socket.gethostname()
    before = machine()
    daemon_before = None
    node = None
    if role == "worker":
        node, daemon_before = worker_daemon_binding(config, hostname, run,metadata_budget=metadata_budget) if metadata_budget else worker_daemon_binding(config, hostname, run)
    elif role != "controller":
        raise ValueError("Missing Nix-generated observed local role")
    after = machine()
    if before != after or hostname != socket.gethostname() or configuration != read("/etc/qcl-negf/release-config.json"):
        raise ValueError("Local machine/boot/config changed during observation")
    if role == "worker":
        node_after, daemon_after = worker_daemon_binding(config, hostname, run,metadata_budget=metadata_budget) if metadata_budget else worker_daemon_binding(config, hostname, run)
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


def assert_expected_node(expected_node_identity, *, role, run=command,metadata_budget=None):
    expected = identity_value(expected_node_identity)
    if expected["role"] != role:
        raise ValueError("Caller role conflicts with observed expected node")
    actual = observe_node_identity(run=run,metadata_budget=metadata_budget) if metadata_budget else observe_node_identity(run=run)
    bind_node_observation(expected, actual, prior_boot=expected["boot_id"])
    return actual


def unresolved_deliveries(runtime):
    attempts = Path(runtime) / "delivery-attempts"
    if attempts.exists():
        for path in attempts.glob("*.json"):
            previous = load(path)
            if previous.get('operation')=='whole_cluster_update' and previous.get('status') in ('running','failed'):
                for drain in previous.get('slurm_drain',{}).values():
                    if isinstance(drain,dict) and drain.get('status')=='completed' and drain.get('resume_status')!='completed' and not retained_drain_complete(drain):raise RuntimeError('Unresolved causal DRAIN evidence requires trusted operator reconciliation')
            if previous.get("schema") == "qcl-negf-admission-intent-v1" or previous.get("requires_reconciliation") or previous.get("pending_stopped_observation") or any(v.get("resume_status")=="pending" or v.get("status")=="pending" for v in previous.get("slurm_drain",{}).values()) or (previous.get("status") == "running" and previous.get("pending_command", {}).get("mutation")):
                raise RuntimeError("Unresolved delivery requires trusted operator reconciliation")


SHUTDOWN_SCHEMA = "qcl-negf-shutdown-intent-v2"
SHUTDOWN_PHASES = {"requested", "capture_pending", "awaiting_jobs", "safe_to_power_off",
                   "returning", "resumed", "reconciliation_required"}


def validate_shutdown_intent(value, node):
    if not isinstance(value, dict) or value.get("schema") != SHUTDOWN_SCHEMA or value.get("node") != node:
        raise ValueError("Malformed/legacy normal shutdown intent requires reconciliation")
    if not isinstance(node, str) or not IDENTIFIER.fullmatch(node) or value.get("node_name") != node:
        raise ValueError("Shutdown intent canonical NodeName mismatch")
    if value.get("phase") not in SHUTDOWN_PHASES or not isinstance(value.get("jobs"), dict):
        raise ValueError("Malformed shutdown phase/captured jobs")
    for key in ("inventory_id", "enrollment_id", "machine_uuid"):
        normalized_uuid(value.get(key))
    if not isinstance(value.get("machine_id"), str) or not re.fullmatch(r"[0-9a-f]{32}", value["machine_id"]) or int(value["machine_id"], 16) == 0:
        raise ValueError("Shutdown intent missing permanent machine-id")
    if value.get("role") != "worker" or not isinstance(value.get("hostname"), str) or not TARGET.fullmatch(value["hostname"]):
        raise ValueError("Shutdown intent missing observed worker binding")
    if not isinstance(value.get("target"), str) or not TARGET.fullmatch(value["target"]):
        raise ValueError("Shutdown intent missing enrolled route")
    origin = value.get("origin", "normal_shutdown")
    if origin == "normal_shutdown":
        normalized_uuid(value.get("shutdown_id"))
        normalized_uuid(value.get("boot_id"))
        if type(value.get("capture_complete")) is not bool:
            raise ValueError("Shutdown capture status is unknown")
    elif origin == "legacy_v1":
        if value.get("phase") != "reconciliation_required" or value.get("capture_complete") is not False or not value.get("requires_reconciliation") or not isinstance(value.get("legacy_evidence_base64"), str):
            raise ValueError("Legacy intent cannot imply stop/boot proof")
        normalized_uuid(value.get("shutdown_id"))
        if value.get("boot_id") is not None:
            raise ValueError("Legacy intent cannot invent previous boot")
    elif origin == "initial_enrollment":
        if value.get("shutdown_id") is not None or value.get("boot_id") is not None or value.get("capture_complete") is not None:
            raise ValueError("Initial enrollment cannot invent previous shutdown proof")
    else:
        raise ValueError("Unknown shutdown intent origin")
    if value["phase"] == "safe_to_power_off" and (origin != "normal_shutdown" or value.get("capture_complete") is not True or value["jobs"] or value.get("requires_reconciliation") or value.get("pending_action")):
        raise ValueError("Safe power-off lacks completed scoped capture/stop proof")
    if value["phase"] == "resumed":
        event = value.get("startup_event")
        if (value.get("requires_reconciliation") or value.get("pending_action") or value["jobs"]
                or not isinstance(event, dict) or event.get("schema") != "qcl-negf-startup-event-v1"
                or event.get("node") != node or event.get("enrollment_id") != value["enrollment_id"]
                or event.get("inventory_id") != value["inventory_id"]
                or type(event.get("actor_uid")) is not int or event.get("actor_uid") != 0 or event.get("entrypoint") != "privileged-controller-operator") :
            raise ValueError("Resumed intent lacks authorized startup/current binding evidence")
        normalized_uuid(event.get("event_id"))
        normalized_uuid(event.get("controller_machine_uuid"))
        returned = normalized_uuid(value.get("return_boot_id"))
        if origin == "normal_shutdown" and (value.get("capture_complete") is not True or returned == normalized_uuid(value["boot_id"])):
            raise ValueError("Resumed normal intent lacks a new generation")
    return value


def read_shutdown_intent(path, node):
    with Path(path).open("rb") as handle:
        raw = handle.read(1048577)
    value = unique_json(raw, 1048576)
    return validate_shutdown_intent(value, node)


def lifecycle_guard(runtime, *, normal_intents=True):
    """No write/clear: unrelated CR04 outcomes retain independent authority."""
    runtime = Path(runtime)
    unresolved_deliveries(runtime)
    # No I14 adapter exists here: any durable update ownership marker is unknown.
    if os.path.lexists(runtime / "cluster-update.json"):
        raise RuntimeError("Cluster update ownership requires trusted reconciliation")
    if normal_intents:
        state = runtime / "shutdown"
        if state.exists():
            for path in state.glob("*.json"):
                try:
                    value = read_shutdown_intent(path, path.stem)
                except (ValueError, OSError, TypeError) as error:
                    raise RuntimeError("Unresolved normal shutdown state requires reconciliation") from error
                if value["phase"] != "resumed" or value.get("requires_reconciliation"):
                    raise RuntimeError("Normal shutdown intent inhibits delivery until authorized new-boot startup")


@contextmanager
def lifecycle_owner(runtime):
    runtime = Path(runtime)
    runtime.mkdir(parents=True, exist_ok=True)
    with (runtime / "delivery.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


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


def publish(path, value, *, mode=0o644, before=None):
    """Publish complete public runtime configuration and fsync the directory."""
    check_before=before or (lambda:None)
    check_before()
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    check_before()
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        try:
            check_before()
            handle.write(value)
            check_before()
            handle.flush()
            check_before()
            os.fsync(handle.fileno())
            check_before()
            os.fchmod(handle.fileno(), mode)
            check_before()
            os.replace(temporary, path)
            check_before()
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                check_before()
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            try:check_before();temporary.unlink(missing_ok=True)
            except (OSError,CommandFailure) as error:
                error.cleanup_pending={'path':str(temporary),'operation':'own publication cleanup'};raise


def publish_json(path, value, *, mode=0o644, before=None):
    publish(path, json.dumps(value, sort_keys=True) + "\n", mode=mode, before=before)


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
          expected_node_identity=None,metadata_budget=None):
    def before():
        if metadata_budget:metadata_budget.before()
    before()
    bound_before = assert_expected_node(expected_node_identity,role=role,run=run,metadata_budget=metadata_budget) if expected_node_identity is not None else None
    expected = manifest(manifest_value)
    current = unique_json(metadata_budget.read(Path(runtime)/"release.json"),65536) if metadata_budget else load(Path(runtime) / "release.json")
    before()
    if current.get("ready") is not True or manifest(current) != expected or Path(profile).resolve() != Path(expected["application_path"]):
        raise ValueError("Installed application profile or runtime release identity differs")
    solver_profile = Path(profile).with_name(Path(profile).name + "-solver")
    before()
    if solver_profile.resolve() != Path(expected["solver_executable"]).parents[1]:
        raise ValueError("Installed solver profile differs from the selected closure")
    before();run(["nix-store", "--verify-path", expected["application_path"],
         str(Path(expected["solver_executable"]).parents[1])])
    units = ["slurmd.service"] if role == "worker" else ["qcl-negf-aiida.service", "qcl-negf-api.service"]
    for unit in units:
        before();run(["systemctl", "is-active", "--quiet", unit])
    before();solver_self_check(expected, run)
    if bound_before is not None:
        bound_after = assert_expected_node(expected_node_identity, role=role, run=run,metadata_budget=metadata_budget) if metadata_budget else assert_expected_node(expected_node_identity, role=role, run=run)
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
             expected_node_identity=None,update_attempt_id=None,gate=GATE,deadline=None,metadata_budget=None):
    action_budget=(metadata_budget or UpdateScan(deadline)) if update_attempt_id else metadata_budget
    if action_budget:
        underlying_run=run
        def run(argv):action_budget.before();result=underlying_run(argv);action_budget.before();return result
    if update_attempt_id and role=='worker':
        stopped=observe_stopped_update(manifest(manifest_value),update_attempt_id,runtime=runtime,gate=gate,run=run,deadline=deadline,budget=action_budget)
        bind_node_observation(identity_value(expected_node_identity),stopped['node_identity'],prior_boot=expected_node_identity['boot_id'])
        action_budget.before();run(['systemctl','unmask','--runtime','slurmd.service'])
        unit=unit_state(run)
        if unit['LoadState']!='loaded' or unit['UnitFileState'].startswith('masked'):raise ValueError('Own update mask not removed')
        bound_node=stopped['node_identity']
    else:
        bound_node = assert_expected_node(expected_node_identity, role=role, run=run,metadata_budget=action_budget) if expected_node_identity is not None else None
    expected = manifest(manifest_value)
    if role not in ("controller", "worker"):
        raise ValueError("Activation role must be controller or worker")
    profile, runtime = Path(profile), Path(runtime)
    if action_budget:action_budget.before()
    runtime.mkdir(parents=True, exist_ok=True)
    record = runtime / "release.json"
    if action_budget:action_budget.before()
    current = (unique_json(action_budget.read(record),65536) if action_budget else load(record)) if record.exists() else None
    if action_budget:action_budget.before()
    same = current is not None and current.get("ready") is True and manifest(current) == expected and profile.resolve() == Path(expected["application_path"])
    # An interrupted activation cannot leave a local ready marker for new jobs.
    if action_budget:action_budget.before()
    record.unlink(missing_ok=True)
    run(["nix-store", "--verify-path", expected["application_path"],
         str(Path(expected["solver_executable"]).parents[1])])
    # Each profile is an independent GC root; an identical release can lose one.
    profiles = [(profile, expected["application_path"]),
                (profile.with_name(profile.name + "-solver"),
                 str(Path(expected["solver_executable"]).parents[1]))]
    for path, selected in profiles:
        if action_budget:action_budget.before()
        if path.resolve() != Path(selected):
            run(["nix-env", "--profile", str(path), "--set", selected])
        if action_budget:action_budget.before()
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
        publish(allowed_codes_file, identity["code_uuid"] + "\n",before=action_budget.before if action_budget else None)
    publish(runtime / "service.env", "\n".join([
        "QCL_NEGF_RELEASE_ID=" + expected["release_id"],
        "QCL_NEGF_SOLVER_EXECUTABLE=" + expected["solver_executable"],
        "QCL_NEGF_RELEASE_GATE=" + str(GATE),
    ]) + "\n",before=action_budget.before if action_budget else None)
    # A prepared configuration may start slurmd for a closed release delivery.
    # Jobs still fail the ready+shared-admission guard until health succeeds.
    publish_json(record, {**identity, "ready": False},before=action_budget.before if action_budget else None)
    units = ["slurmd.service"] if role == "worker" else ["qcl-negf-aiida.service", "qcl-negf-api.service"]
    # Fleet delivery quiesces the controller even on an identical retry.
    # Reuse the immutable profile/Code, but ensure stopped units run again.
    if action_budget and role=='worker':
        marker=unique_json(action_budget.protected(runtime/'update-stop.json'),65536)
        marker['restart_window']={'requested_epoch':utc_epoch(run,action_budget),'captured_epoch':None}
        publish_json(runtime/'update-stop.json',marker,mode=0o600,before=action_budget.before)
    if action_budget:action_budget.before()
    run(["systemctl", "start" if same else "restart", *units])
    if action_budget and role=='worker':
        assert_expected_node(expected_node_identity,role='worker',run=run,metadata_budget=action_budget)
        marker['restart_window']['captured_epoch']=utc_epoch(run,action_budget)
        publish_json(runtime/'update-stop.json',marker,mode=0o600,before=action_budget.before)
    for unit in units:
        run(["systemctl", "is-active", "--quiet", unit])
    solver_self_check(expected, run)
    identity["ready"] = True
    publish_json(record, identity,before=action_budget.before if action_budget else None)
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
                 deadline=None, checkpoint=None, bindings=None, authority=None, authority_run=command,
                 runtime=RUNTIME):
    recheck_controller_authority(authority, run=authority_run)
    lifecycle_guard(runtime)
    deadline_check(deadline)
    with lifecycle_owner(runtime):
        recheck_controller_authority(authority, run=authority_run)
        lifecycle_guard(runtime)
        return _deliver_pool_owned(manifest_value, nodes, gate, deliver=deliver, quiesce=quiesce,
            admit=admit, deadline=deadline, checkpoint=checkpoint, bindings=bindings,
            authority=authority, authority_run=authority_run, runtime=runtime)


def _deliver_pool_owned(manifest_value, nodes, gate=GATE, *, deliver, quiesce, admit=lambda: None,
                        deadline=None, checkpoint=None, bindings=None, authority=None,
                        authority_run=command, runtime=RUNTIME):
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
    lifecycle_guard(runtime)
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
            lifecycle_guard(runtime)
            admit()
            deadline_check(deadline)
            report["admission_pending"] = True
            save("open_admission")
            deadline_check(deadline)
            recheck_controller_authority(authority, run=authority_run)
            # The final preexisting-state guard above preceded creation of this
            # operation's CR04 admission marker under the SAME owner. That own
            # marker now inhibits retries; do not classify it as a competing attempt.
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


UPDATE_SCHEMA='qcl-negf-update-stop-v1'
STOP_PROPERTIES=('LoadState','ActiveState','SubState','MainPID','ControlGroup','InvocationID','UnitFileState','FragmentPath','DropInPaths')

class UpdateScan:
    """Charged upper bounds reserved before IO; returned bytes counted separately."""
    CAP=32*1024*1024
    def __init__(self,deadline):
        duration(deadline,'Update deadline');deadline_check(deadline)
        self.deadline=deadline;self.bytes=0;self.actual_bytes=0;self.pid_entries=0;self.cgroup_entries=0
    def before(self):deadline_check(self.deadline)
    def reserve(self,n):
        self.before()
        if self.bytes+n>self.CAP:raise ValueError('Update metadata cumulative bound')
        self.bytes+=n
    def read(self,path,limit=65536):
        self.before();limit=min(output_bound(limit),65536);request=min(4096,limit+1)
        if self.bytes+request>self.CAP:raise ValueError('Update metadata cumulative bound')
        self.reserve(request)
        with Path(path).open('rb') as handle:
            data=bytearray()
            for index in range(18):
                n=min(4096,limit+1-len(data))
                if index:self.reserve(n)
                chunk=handle.read(n);self.actual_bytes+=len(chunk);self.before()
                if not chunk:return bytes(data)
                data.extend(chunk)
                if len(data)>limit:raise ValueError('Update metadata exceeds bound')
            raise ValueError('Unsupported metadata short-read layout')
    def entries(self,path,kind):
        self.before()
        with os.scandir(path) as iterator:
            while True:
                self.before();key='pid_entries' if kind=='pid' else 'cgroup_entries';cap=32768 if kind=='pid' else 4096
                if getattr(self,key)>=cap:raise ValueError('Update enumeration cumulative bound')
                setattr(self,key,getattr(self,key)+1)
                try:item=next(iterator)
                except StopIteration:return
                self.before()
                if kind!='pid' or item.name.isdigit():yield Path(item.path)
    def stat(self,path,*,follow_symlinks=False):
        self.before();result=os.stat(path,follow_symlinks=follow_symlinks);self.before();return result
    def link(self,path):
        self.reserve(4097);result=os.readlink(path);self.before()
        if len(os.fsencode(result))>4096:raise ValueError('Update readlink metadata bound')
        return result
    def protected(self,path,limit=65536):
        self.before();return read_protected_file(path,limit,budget=self)
    def admission(self,path):
        self.before()
        with admission_reader(path):return unique_json(self.read(path,65536),65536)

def unit_state(run,unit='slurmd.service'):
    raw=run(['systemctl','show',unit,*['--property='+key for key in STOP_PROPERTIES]])
    result={}
    for line in raw.splitlines():
        key,sep,value=line.partition('=')
        if not sep or key in result or key not in STOP_PROPERTIES:raise ValueError('Unknown systemd readback')
        result[key]=value
    if set(result)!=set(STOP_PROPERTIES) or not result['MainPID'].isdigit():raise ValueError('Incomplete systemd readback')
    return result

def process_state_class(record):
    state=record.get('state')
    if state in ('Z','X'):return 'nonexecuting'
    if isinstance(state,str) and len(state)==1 and state in 'RSDTtIWKPx':return 'live'
    raise ValueError('Unsupported process state metadata')


def process_identity(record,*,include_executable=True):
    keys=('pid','start_ticks','cgroup','uids','comm')+ (('executable',) if include_executable else ())
    return {key:record[key] for key in keys}


def same_process(left,right,*,include_executable=True):
    return process_identity(left,include_executable=include_executable)==process_identity(right,include_executable=include_executable) and process_state_class(left)==process_state_class(right)


def process_metadata(budget,path):
    raw={key:budget.read(path/key,256 if key=='comm' else 65536).decode() for key in ('comm','status','cgroup','stat')}
    comm=raw['comm'].strip();stat_raw=raw['stat'];start=stat_raw.find('(');end=stat_raw.rfind(')')
    prefix=stat_raw[:start].strip();fields=stat_raw[end+2:].split()
    if start<0 or end<=start or not prefix.isdigit() or int(prefix)!=int(path.name) or stat_raw[start+1:end]!=comm or stat_raw[end+1:end+2]!=' ' or len(fields)<20 or not fields[19].isdigit() or int(fields[19])<=0:raise ValueError('Incomplete PID/stat generation metadata')
    uidlines=[line for line in raw['status'].splitlines() if line.startswith('Uid:')]
    cgroups=raw['cgroup'].splitlines()
    if len(uidlines)!=1 or len(cgroups)!=1 or not cgroups[0].startswith('0::'):raise ValueError('Incomplete process UID/cgroup metadata')
    uidfields=uidlines[0].split()[1:]
    if len(uidfields)!=4 or any(not value.isdigit() or int(value)>4294967295 for value in uidfields):raise ValueError('Unsupported UID tuple')
    cgroup=cgroups[0][3:]
    if not cgroup.startswith('/') or '..' in Path(cgroup).parts or not comm:raise ValueError('Unsupported process scope metadata')
    result={'pid':int(path.name),'start_ticks':int(fields[19]),'cgroup':cgroup,'state':fields[0],'uids':[int(v) for v in uidfields],'comm':comm}
    process_state_class(result)
    return result,raw


def process_classification(budget,path):
    before,raw_before=process_metadata(budget,path);after,raw_after=process_metadata(budget,path)
    if not same_process(before,after,include_executable=False):raise ValueError('Process classification identity/state-class changed')
    return {**after,'observations':{'before':raw_before,'after':raw_after}}


def process_record(budget,path):
    before,raw_before=process_metadata(budget,path);executable=budget.link(path/'exe')
    after,raw_after=process_metadata(budget,path);later_executable=budget.link(path/'exe')
    if not executable.startswith('/') or executable!=later_executable or not same_process(before,after,include_executable=False):raise ValueError('Process generation/executable identity changed')
    return {**after,'executable':executable,'observations':{'before':raw_before,'after':raw_after}}

def physical_stop_scan(budget,service):
    budget.read('/sys/fs/cgroup/cgroup.controllers')
    uid=pwd.getpwnam('qcl-negf').pw_uid;records={};jobs=[];daemon=[]
    for path in budget.entries('/proc','pid'):
        try:record=process_classification(budget,path)
        except (FileNotFoundError,ProcessLookupError) as error:raise ValueError('Incomplete process generation') from error
        records[record['pid']]=record
        if record['state'] in ('Z','X'):continue
        if record['comm']=='slurmd':
            full=process_record(budget,path)
            if not same_process(full,record,include_executable=False):raise ValueError('Daemon classification generation changed')
            record=full
            if record['cgroup']!=service['ControlGroup'] or not record['executable'].startswith('/nix/store/') or Path(record['executable']).name!='slurmd':raise ValueError('Unbound daemon scope/executable')
            daemon.append(record)
        elif record['comm'].startswith(('slurmstepd','slurm_script')) or '/job_' in record['cgroup'] or '/step_' in record['cgroup'] or uid in record['uids']:jobs.append(record['pid'])
    cg=service['ControlGroup'];members=[]
    if cg:
        if not cg.startswith('/') or '..' in Path(cg).parts:raise ValueError('Invalid service scope')
        root=Path('/sys/fs/cgroup')/cg.lstrip('/')
        if len(Path(cg).parts)>64:raise ValueError('Unsupported service scope depth')
        prefix=Path('/sys/fs/cgroup')
        for component in Path(cg).parts[1:]:
            prefix=prefix/component
            try:info=budget.stat(prefix)
            except FileNotFoundError:
                if daemon:raise ValueError('Daemon scope namespace disappeared')
                break
            if not stat.S_ISDIR(info.st_mode):raise ValueError('Unsupported cgroup protected namespace')
        try:
            initial=budget.stat(root)
        except FileNotFoundError:
            if daemon:raise ValueError('Daemon scope disappeared')
            initial=None
        if initial is not None:
            if not stat.S_ISDIR(initial.st_mode):raise ValueError('Unsupported service scope layout')
            snapshots={};stack=[root];seen=set()
            while stack:
                directory=stack.pop();info=budget.stat(directory)
                if not stat.S_ISDIR(info.st_mode):raise ValueError('Unsupported cgroup directory')
                raw=budget.read(directory/'cgroup.procs');pids=raw.decode().split()
                if any(not p.isdigit() or int(p)<=0 for p in pids) or len(set(pids))!=len(pids):raise ValueError('Malformed service member PID')
                snapshots[directory]=(info.st_dev,info.st_ino,raw)
                for text in pids:
                    pid=int(text)
                    if pid in seen or pid not in records:raise ValueError('Incomplete or duplicate service member')
                    seen.add(pid);record=process_record(budget,Path('/proc')/text)
                    if not same_process(record,records[pid],include_executable=False) or record['cgroup']!='/'+str(directory.relative_to('/sys/fs/cgroup')):raise ValueError('Service member generation/cgroup changed')
                    members.append(record)
                for entry in budget.entries(directory,'cgroup'):
                    info=budget.stat(entry)
                    if stat.S_ISLNK(info.st_mode):raise ValueError('Unsupported cgroup symlink')
                    if stat.S_ISDIR(info.st_mode):stack.append(entry)
            for directory,(dev,ino,raw) in snapshots.items():
                info=budget.stat(directory)
                if (info.st_dev,info.st_ino)!=(dev,ino) or budget.read(directory/'cgroup.procs')!=raw:raise ValueError('Service membership snapshot changed')
            final=budget.stat(root)
            if (initial.st_dev,initial.st_ino)!=(final.st_dev,final.st_ino):raise ValueError('Service scope generation changed')
    return {'job_processes_measured':True,'job_processes_empty':not jobs,'job_pids':jobs,'daemon_processes':daemon,
            'service_members':members,'service_members_measured':True,'service_scope_complete':True,
            'metadata_bytes':budget.bytes,'metadata_actual_bytes':budget.actual_bytes,'pid_entries':budget.pid_entries,'cgroup_entries':budget.cgroup_entries}


def singleton_scope(scan,service,captured=None):
    members=scan['service_members'];daemons=scan['daemon_processes']
    if not scan['service_scope_complete'] or not scan['service_members_measured'] or len(members)!=1 or len(daemons)!=1 or not same_process(members[0],daemons[0]) or members[0]['pid']!=int(service['MainPID']):raise ValueError('Positive singleton daemon scope/member proof required')
    if captured is not None and not same_process(members[0],captured):raise ValueError('Daemon generation/executable identity changed')
    return members[0]

def stopped_machine(budget):
    configuration=budget.read('/etc/qcl-negf/release-config.json')
    config=unique_json(configuration,65536)
    if config.get('role')!='worker':raise ValueError('Stopped observer requires worker role')
    conf=config.get('slurm_conf')
    if not isinstance(conf,str) or not Path(conf).is_absolute():raise ValueError('Missing stopped SLURM_CONF')
    return {'machine_uuid':budget.read('/sys/class/dmi/id/product_uuid').decode().strip().lower(),
            'machine_id':budget.read('/etc/machine-id').decode().strip(),
            'boot_id':budget.read('/proc/sys/kernel/random/boot_id').decode().strip().lower(),
            'hostname':socket.gethostname(),'release_config_sha256':hashlib.sha256(configuration).hexdigest(),
            'slurm_conf':conf,'slurm_conf_sha256':hashlib.sha256(budget.read(conf)).hexdigest()}

def update_marker(runtime,attempt_id,expected,gate,*,budget):
    normalized_uuid(attempt_id)
    path=Path(runtime)/'update-stop.json'
    raw=budget.protected(path,limit=65536)
    marker=unique_json(raw,65536)
    if marker.get('schema')!=UPDATE_SCHEMA or marker.get('attempt_id')!=attempt_id or marker.get('release')!=manifest(expected):raise ValueError('Missing own update marker')
    admission=budget.admission(gate)
    if admission.get('open') is not False or admission.get('release_id')!=expected['release_id']:raise ValueError('Stopped identity requires matching closed gate')
    return marker

def observe_stopped_update(expected,attempt_id,*,runtime=RUNTIME,gate=GATE,run=command,deadline=None,budget=None):
    budget=budget or UpdateScan(deadline);budget.before()
    marker=update_marker(runtime,attempt_id,expected,gate,budget=budget)
    before=stopped_machine(budget)
    if before!=marker['machine']:raise ValueError('Stopped machine boot/config changed')
    service=unit_state(run)
    if service['LoadState']!='masked' or service['UnitFileState']!='masked-runtime' or service['ActiveState']!='inactive' or service['SubState']!='dead' or service['MainPID']!='0':raise ValueError('Worker is not measured stopped/masked')
    if service['ControlGroup'] or service['InvocationID']:raise ValueError('Inactive daemon retains unknown invocation/cgroup')
    scan=physical_stop_scan(budget,{**service,'ControlGroup':marker['daemon']['ControlGroup']})
    if scan['daemon_processes'] or any(m['state'] not in ('Z','X') for m in scan['service_members']) or not scan['service_scope_complete'] or not scan['service_members_measured'] or not scan['job_processes_empty']:raise ValueError('Stopped worker retains daemon/job processes')
    if stopped_machine(budget)!=before:raise ValueError('Stopped identity raced')
    actual=identity_value({**marker['node_identity'],'hostname':before['hostname'],**{k:before[k] for k in ('machine_uuid','machine_id','boot_id')}})
    return {'schema':UPDATE_SCHEMA,'attempt_id':attempt_id,'enrollment_id':normalized_uuid(marker.get('enrollment_id')),'node_identity':actual,'machine':before,
            'original_config_digest':before['slurm_conf_sha256'],'systemd':service,'stop_window':marker['stop_window'],
            **scan,'restart_inhibited':True,'forced_daemon_stop':marker['forced_daemon_stop']}

def stop_update(expected,attempt_id,expected_node_identity,*,runtime=RUNTIME,gate=GATE,run=command,deadline=None,prior_attempt_id=None,enrollment_id=None,metadata_budget=None):
    normalized_uuid(attempt_id);enrollment_id=normalized_uuid(enrollment_id);expected=manifest(expected)
    budget=metadata_budget or UpdateScan(deadline)
    machine=stopped_machine(budget)
    path=Path(runtime)/'update-stop.json';prior=None
    budget.before()
    if os.path.lexists(path):
        if not prior_attempt_id:raise ValueError('Existing own update marker requires known-failure authority')
        prior=update_marker(runtime,prior_attempt_id,expected,gate,budget=budget)
        if prior.get('enrollment_id')!=enrollment_id or prior['machine']!=machine or prior['node_identity']!=identity_value(expected_node_identity):raise ValueError('Prior update boot/config/binding changed')
        state=unit_state(run)
        if state['UnitFileState']=='masked-runtime':
            observe_stopped_update(expected,prior_attempt_id,runtime=runtime,gate=gate,run=run,budget=budget)
            prior['attempt_id']=attempt_id;publish_json(path,prior,mode=0o600,before=budget.before)
            return observe_stopped_update(expected,attempt_id,runtime=runtime,gate=gate,run=run,budget=budget)
    actual=assert_expected_node(expected_node_identity,role='worker',run=run,metadata_budget=budget)
    service=unit_state(run)
    if service['LoadState']!='loaded' or service['ActiveState']!='active' or service['UnitFileState'].startswith('masked') or service['DropInPaths'] or not service['ControlGroup'] or not re.fullmatch('[0-9a-f]{32}',service['InvocationID']):raise ValueError('Unsupported/colliding daemon mask or invocation')
    budget.before()
    if os.path.lexists('/run/systemd/system/slurmd.service'):raise ValueError('Runtime unit/mask collision')
    scan=physical_stop_scan(budget,service)
    if unit_state(run)!=service:raise ValueError('Service invocation changed during initial scope snapshot')
    if not scan['job_processes_empty']:raise ValueError('Worker job process cancellation incomplete')
    captured=singleton_scope(scan,service)
    if stopped_machine(budget)!=machine:raise ValueError('Running worker boot/config raced')
    admission=budget.admission(gate)
    if admission.get('open') is not False or admission.get('release_id')!=expected['release_id']:raise ValueError('Update stop requires matching closed gate')
    marker={'schema':UPDATE_SCHEMA,'attempt_id':attempt_id,'enrollment_id':enrollment_id,'release':expected,'node_identity':actual,
        'machine':machine,'daemon':service,'daemon_pid':captured,'forced_daemon_stop':False,
        'stop_window':{'requested_epoch':utc_epoch(run,budget),'captured_epoch':None}}
    if len(json.dumps(marker).encode())>65536:raise ValueError('Full update marker observations exceed bound')
    budget.before()
    if os.path.lexists(path) and prior is None:raise ValueError('Existing update marker requires reconciliation')
    publish_json(path,marker,mode=0o600,before=budget.before)
    budget.before();run(['systemctl','mask','--runtime','slurmd.service'])
    budget.before();run(['systemctl','stop','--no-block','slurmd.service'])
    for _ in range(30):
        budget.before();state=unit_state(run);scan=physical_stop_scan(budget,service)
        if not scan['job_processes_empty']:raise ValueError('Worker job process cancellation incomplete')
        if state['ActiveState']=='inactive' and state['MainPID']=='0' and not scan['daemon_processes'] and not any(m['state'] not in ('Z','X') for m in scan['service_members']):
            marker['stop_window']['captured_epoch']=utc_epoch(run,budget);publish_json(path,marker,mode=0o600,before=budget.before)
            return observe_stopped_update(expected,attempt_id,runtime=runtime,gate=gate,run=run,budget=budget)
        budget.before();time.sleep(min(1,max(0,deadline-time.monotonic())) if deadline else 1)
    budget.before();state=unit_state(run);scan=physical_stop_scan(budget,service)
    if state['ControlGroup']!=service['ControlGroup'] or state['InvocationID']!=service['InvocationID'] or state['MainPID']!=service['MainPID']:raise ValueError('Daemon cgroup/invocation/generation changed; force forbidden')
    singleton_scope(scan,state,captured)
    if unit_state(run)!=state:raise ValueError('Daemon generation changed before force')
    if not scan['job_processes_empty'] or stopped_machine(budget)!=machine:raise ValueError('Force scope/job/machine changed')
    budget.before();run(['systemctl','kill','--kill-whom=all','--signal=SIGKILL','slurmd.service'])
    budget.before();run(['systemctl','reset-failed','slurmd.service'])
    marker['forced_daemon_stop']=True;publish_json(path,marker,mode=0o600,before=budget.before)
    for _ in range(10):
        budget.before();state=unit_state(run);scan=physical_stop_scan(budget,service)
        if not scan['job_processes_empty']:raise ValueError('Job processes after force')
        if state['ActiveState']=='inactive' and state['MainPID']=='0' and not scan['daemon_processes'] and not any(m['state'] not in ('Z','X') for m in scan['service_members']):
            marker['stop_window']['captured_epoch']=utc_epoch(run,budget);publish_json(path,marker,mode=0o600,before=budget.before)
            return observe_stopped_update(expected,attempt_id,runtime=runtime,gate=gate,run=run,budget=budget)
        budget.before();time.sleep(min(1,max(0,deadline-time.monotonic())) if deadline else 1)
    raise ValueError('Daemon force readback incomplete')

def aiida_cancellation_check(run):
    raw=run(['runuser','-u','qcl-negf','--','env','AIIDA_PATH=/var/lib/qcl-negf/aiida',
        str(PROFILE/'bin/verdi'),'-p','qcl-negf','run',str(Path(__file__).with_name('aiida_update_check.py'))])
    value=unique_json(raw,4096)
    keys={'schema','profile','roots_checked','calcjobs_checked','active_root_found','active_calcjob_found','root_sample','calcjob_sample'}
    if set(value)!=keys or value['schema']!='qcl-negf-aiida-update-check-v1' or value['profile']!='qcl-negf' or value['roots_checked'] is not True or value['calcjobs_checked'] is not True:raise ValueError('Incomplete AiiDA cancellation proof')
    for label in ('root','calcjob'):
        found=value['active_'+label+'_found'];sample=value[label+'_sample']
        if type(found) is not bool or (found and not isinstance(sample,dict)) or (not found and sample is not None):raise ValueError('Malformed AiiDA active process proof')
        if found:
            expected_keys={'uuid','process_state','process_type','paused'} if label=='root' else {'uuid','process_state'}
            if set(sample)!=expected_keys or sample['process_state'] in ('finished','killed','excepted'):raise ValueError('Invalid active process sample')
            normalized_uuid(sample['uuid'])
            if sample['process_state'] is not None and (not isinstance(sample['process_state'],str) or len(sample['process_state'])>64):raise ValueError('Unknown process state type')
            if label=='root' and (sample['process_type'] not in ('aiida.workflows:qcl_negf.plan','aiida.workflows:qcl_negf.execution_restart') or type(sample['paused']) is not bool):raise ValueError('Incomplete owned workflow probe')
    if value['active_root_found'] or value['active_calcjob_found']:raise RuntimeError('AiiDA workflow/CalcJob cancellation incomplete')
    return value

def verify_stop_response(value,binding,attempt_id):
    if not isinstance(value,dict) or value.get('schema')!=UPDATE_SCHEMA or value.get('attempt_id')!=attempt_id:raise ValueError('Unknown stopped receipt')
    bind_node_observation(binding,value.get('node_identity'),prior_boot=binding['identity']['boot_id'])
    if value.get('enrollment_id')!=binding.get('enrollment_id'):raise ValueError('Stopped enrollment binding changed')
    if not isinstance(value.get('service_members'),list) or any(not isinstance(member,dict) for member in value['service_members']):raise ValueError('Incomplete physical stopped proof')
    if value.get('job_processes_measured') is not True or value.get('job_processes_empty') is not True or value.get('restart_inhibited') is not True or type(value.get('forced_daemon_stop')) is not bool or value.get('daemon_processes')!=[] or value.get('service_members_measured') is not True or value.get('service_scope_complete') is not True or not isinstance(value.get('service_members'),list) or any(m.get('state') not in ('Z','X') for m in value['service_members']):raise ValueError('Incomplete physical stopped proof')
    state=value.get('systemd')
    if not isinstance(state,dict):raise ValueError('Incomplete measured stop fields')
    if any(state.get(k)!=v for k,v in {'LoadState':'masked','UnitFileState':'masked-runtime','ActiveState':'inactive','SubState':'dead','MainPID':'0','ControlGroup':'','InvocationID':''}.items()):raise ValueError('Incomplete measured stop fields')
    machine=value.get('machine')
    if not isinstance(machine,dict) or any(machine.get(k)!=value['node_identity'][k] for k in ('hostname','machine_uuid','machine_id','boot_id')) or not isinstance(machine.get('slurm_conf'),str) or not machine['slurm_conf'].startswith('/') or any(not re.fullmatch('[0-9a-f]{64}',str(machine.get(k,''))) for k in ('release_config_sha256','slurm_conf_sha256')):raise ValueError('Incomplete stopped machine/config binding')
    if value.get('original_config_digest')!=machine['slurm_conf_sha256']:raise ValueError('Missing original config digest')
    return value


REGISTRATION_FIELDS=('NodeName','CPUTot','RealMemory','Version','BootTime','SlurmdStartTime')

def registration_fields(raw):
    # Owner-equivalent single-record parser; optional native Reason only in healthy IDLE.
    if not isinstance(raw,str) or len(raw.encode())>65536 or len(raw.splitlines())!=1:raise ValueError('One bounded exact registration record required')
    rows=re.findall(r'(?:^|\s)(\w+)=(.*?)(?=\s\w+=|$)',raw.strip())
    if len(rows)!=len({k for k,_ in rows}):raise ValueError('Ambiguous registration record')
    values=dict(rows)
    if any(not values.get(k) for k in (*REGISTRATION_FIELDS,'CPUAlloc','AllocMem','State')):raise ValueError('Incomplete registration record')
    if any(not values[k].isdigit() or int(values[k])<=0 for k in ('CPUTot','RealMemory')) or any(values[k]!='0' for k in ('CPUAlloc','AllocMem')):raise ValueError('Allocated or invalid registration')
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',values['Version']):raise ValueError('Invalid registered version')
    for key in ('BootTime','SlurmdStartTime'):
        if values[key]=='None' and values['State']=='IDLE+NOT_RESPONDING':continue
        if not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d',values[key]):raise ValueError('Invalid registration timestamp')
        try:datetime.strptime(values[key],'%Y-%m-%dT%H:%M:%S')
        except ValueError as error:raise ValueError('Invalid registration calendar timestamp') from error
    if not values.get('Reason'):
        if values['State']!='IDLE':raise ValueError('Missing non-IDLE registration Reason')
        values['Reason']=''
    values['_raw']=raw
    return values


def registration_safety(value):
    result={k:value[k] for k in (*REGISTRATION_FIELDS,'CPUAlloc','AllocMem','State','Reason')}
    if result['State']=='IDLE' and result['Reason'] in ('None',''):result['Reason']=''
    return result


def drain_actor(run,*,deadline):
    deadline_check(deadline);uid=run(['id','-u']).strip();deadline_check(deadline)
    name=run(['id','-un']).strip();deadline_check(deadline)
    if not re.fullmatch(r'0|[1-9][0-9]*',uid) or int(uid)>4294967295 or not name or len(name.encode())>128 or any(char.isspace() or char in '@[]\x00' for char in name):raise ValueError('Unsupported measured DRAIN effective actor')
    return int(uid),name


def own_drain_reason(reason,drain):
    if not isinstance(drain,dict):raise ValueError('Missing own DRAIN provenance')
    evidence=drain.get('reason_evidence');tag=drain.get('requested_reason')
    if not isinstance(evidence,dict) or not isinstance(tag,str) or tag!='application-release:'+normalized_uuid(drain.get('attempt_id')):raise ValueError('Missing causal own DRAIN evidence')
    uid=evidence.get('actor_uid');actor=evidence.get('actor_name');left=evidence.get('requested_epoch');right=evidence.get('captured_epoch')
    if type(uid) is not int or not 0<=uid<=4294967295 or not isinstance(actor,str) or not actor or len(actor.encode())>128 or any(c.isspace() or c in '@[]\x00' for c in actor) or type(left) is not int or type(right) is not int or not 0<=left<=right:raise ValueError('Incomplete causal own DRAIN actor/window')
    if reason==tag:return True
    match=re.fullmatch(re.escape(tag)+r' \['+re.escape(actor)+r'@(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)\]',str(reason))
    if not match:raise ValueError('Foreign or malformed own DRAIN Reason')
    try:epoch=datetime.strptime(match.group(1),'%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc).timestamp()
    except ValueError as error:raise ValueError('Invalid own DRAIN Reason calendar') from error
    if not left<=epoch<=right:raise ValueError('Own DRAIN Reason outside measured UTC window')
    return True


def retained_drain_complete(drain):
    try:
        if not isinstance(drain,dict) or drain.get('status')!='completed' or not isinstance(drain.get('after_readback'),dict):return False
        after=drain['after_readback']
        if not isinstance(after.get('_raw'),str) or registration_fields(after['_raw'])!=after:return False
        own_drain_reason(after.get('Reason'),drain)
        return after.get('State')=='IDLE+DRAIN'
    except (ValueError,KeyError,TypeError):return False

def final_registration(run,worker,*,slurm_conf):
    if not isinstance(slurm_conf,str) or not slurm_conf.startswith('/') or '..' in Path(slurm_conf).parts:raise ValueError('Missing explicit registered SLURM_CONF')
    values=registration_fields(run(['env','TZ=UTC','LC_ALL=C','SLURM_CONF='+slurm_conf,'scontrol','show','node',worker,'--oneliner']))
    if values['NodeName']!=worker:raise ValueError('Registered worker name changed')
    return values


def registration_tuple(value):return {k:value[k] for k in REGISTRATION_FIELDS}

def registration_ready(wanted,value):
    # Owner-equivalent registration_ready: ops/slurm_maintenance.py:88–104.
    if any(value[k]!=wanted[k] for k in ('NodeName','CPUTot','RealMemory','Version')):raise ValueError('Current registration tuple changed')
    if value['State']=='IDLE+NOT_RESPONDING':
        if value['Reason'] not in ('None',''):raise ValueError('Unexpected post-RESUME registration Reason')
        if any(value[k] not in ('None',wanted[k]) for k in ('BootTime','SlurmdStartTime')):raise ValueError('Registration generation changed')
        return False
    if value['State']!='IDLE' or registration_tuple(value)!=wanted or value['Reason'] not in ('None',''):raise ValueError('Final same-generation IDLE registration not established')
    return True

def current_worker_health(value,binding,original):
    wanted=value.get('registration');generation=value.get('daemon_generation');window=value.get('restart_window')
    if not isinstance(wanted,dict) or set(wanted)!=set(REGISTRATION_FIELDS) or not isinstance(generation,dict) or not isinstance(window,dict):raise ValueError('Incomplete current registration generation health')
    registration_fields(' '.join(k+'='+str(v) for k,v in {**wanted,'State':'IDLE','Reason':'None','CPUAlloc':'0','AllocMem':'0'}.items()))
    if wanted['NodeName']!=binding['name'] or wanted['BootTime']!=original['BootTime']:raise ValueError('Current worker boot registration changed')
    if type(generation.get('pid')) is not int or generation['pid']<=0 or type(generation.get('start_ticks')) is not int or generation['start_ticks']<=0 or not str(generation.get('executable','')).startswith('/nix/store/') or not re.fullmatch('[0-9a-f]{32}',str(generation.get('InvocationID',''))) or not re.fullmatch('[0-9a-f]{64}',str(generation.get('slurm_conf_sha256',''))):raise ValueError('Missing current daemon generation')
    start=datetime.strptime(wanted['SlurmdStartTime'],'%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc).timestamp()
    left,right=window.get('requested_epoch'),window.get('captured_epoch')
    if type(left) is not int or type(right) is not int or left>right or not left<=start<=right:raise ValueError('Stale registration outside current daemon generation window')
    return wanted


def owned_resume_state(value,drain,stop,health):
    if not retained_drain_complete(drain) or not stop:raise ValueError('Missing original Slurm DRAIN/stop provenance')
    reason=value['Reason'];tag=drain['requested_reason']
    if value['State']=='IDLE+DRAIN':
        if retained_drain_complete(drain) and reason==drain['after_readback']['Reason']:
            own_drain_reason(reason,drain);return
        raise ValueError('Retained full own DRAIN Reason changed')
    match=re.fullmatch(r'Not responding \[slurm@(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)\]',reason)
    if value['State']=='DOWN' and match:
        epoch=datetime.strptime(match.group(1),'%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc).timestamp()
        window=stop.get('stop_window',{});returned=health.get('restart_window',{}).get('captured_epoch')
        if type(window.get('requested_epoch')) is int and type(window.get('captured_epoch')) is int and type(returned) is int and window['requested_epoch']<=window['captured_epoch']<=returned and window['requested_epoch']<=epoch<=returned:return
    raise ValueError('Unexpected Slurm state/reason; own RESUME forbidden')

def utc_epoch(run,budget=None,*,deadline=None):
    if budget is None:duration(deadline,'UTC observation deadline')
    before=budget.before if budget else lambda:deadline_check(deadline)
    before();raw=run(['env','TZ=UTC','LC_ALL=C','date','+%s']).strip();before()
    if not raw.isdigit():raise ValueError('Unsupported native UTC clock')
    return int(raw)


def fleet_health(expected,expected_node_identity,*,runtime=RUNTIME,gate=GATE,run=command,deadline=None,metadata_budget=None):
    budget=metadata_budget or UpdateScan(deadline);admission=budget.admission(gate)
    if admission.get('open') is not False or admission.get('release_id')!=expected['release_id']:raise ValueError('Fleet health requires closed selected gate')
    role=identity_value(expected_node_identity)['role']
    before=assert_expected_node(expected_node_identity,role=role,run=run,metadata_budget=budget)
    config=unique_json(budget.read('/etc/qcl-negf/release-config.json'))
    generation=None;registration=None;window=None
    if role=='worker':
        unit=unit_state(run)
        scan=physical_stop_scan(budget,unit);record=singleton_scope(scan,unit)
        marker=unique_json(budget.protected(Path(runtime)/'update-stop.json'),65536)
        window=marker.get('restart_window');registration=registration_tuple(final_registration(run,before['node_name'],slurm_conf=config['slurm_conf']))
        generation={'pid':record['pid'],'start_ticks':record['start_ticks'],'executable':record['executable'],'InvocationID':unit['InvocationID'],'slurm_conf_sha256':hashlib.sha256(budget.read(config['slurm_conf'])).hexdigest()}
    budget.before();envelope=check(expected,runtime=runtime,role=role,run=run,expected_node_identity=expected_node_identity,metadata_budget=budget)
    budget.before();run(['systemctl','is-active','--quiet','munged.service'])
    source=config.get('nfs_source')
    if not isinstance(source,str) or not source:raise ValueError('Missing configured NFS endpoint')
    budget.before();data=unique_json(run(['findmnt','--json','--target',str(Path(gate).parent),'--output','TARGET,SOURCE,FSTYPE']),65536)
    mounts=data.get('filesystems')
    if not isinstance(mounts,list) or len(mounts)!=1 or mounts[0].get('target')!=str(Path(gate).parent) or mounts[0].get('source')!=source or mounts[0].get('fstype') not in ('nfs','nfs4'):raise ValueError('NFS endpoint/mount mismatch')
    budget.before()
    with admission_reader(gate):
        budget.before();descriptor,name=tempfile.mkstemp(prefix='.update-probe-',dir=Path(gate).parent)
        try:
            budget.before();os.write(descriptor,b'qcl-negf-update\n')
            budget.before();os.fsync(descriptor)
            budget.before();os.lseek(descriptor,0,os.SEEK_SET)
            budget.before()
            if os.read(descriptor,32)!=b'qcl-negf-update\n':raise ValueError('NFS own probe mismatch')
        finally:
            os.close(descriptor)
            try:budget.before();Path(name).unlink()
            except (OSError,CommandFailure) as error:
                error.cleanup_pending={'path':name,'operation':'own NFS probe unlink'};raise
    budget.before();after=assert_expected_node(expected_node_identity,role=role,run=run,metadata_budget=budget)
    if before!=after:raise ValueError('Fleet health machine/config changed')
    if role=='worker':
        later=unit_state(run);later_record=singleton_scope(physical_stop_scan(budget,later),later)
        if later!=unit or not same_process(later_record,record) or unique_json(budget.read('/etc/qcl-negf/release-config.json'))!=config:raise ValueError('Current daemon generation/config changed')
        current_worker_health({'registration':registration,'daemon_generation':generation,'restart_window':window},{'name':before['node_name']},registration)
    result={**envelope,'nfs_verified':True,'nfs_source':source,'auth_verified':True}
    if role=='worker':result.update(registration=registration,daemon_generation=generation,restart_window=window)
    return result


def finish_update(expected,attempt_id,expected_node_identity,*,runtime=RUNTIME,gate=GATE,run=command,deadline=None,metadata_budget=None):
    budget=metadata_budget or UpdateScan(deadline);path=Path(runtime)/'update-stop.json'
    marker=unique_json(budget.protected(path),65536)
    if marker.get('schema')!=UPDATE_SCHEMA or marker.get('attempt_id')!=attempt_id or marker.get('release')!=manifest(expected):raise ValueError('Foreign update marker cleanup forbidden')
    actual=assert_expected_node(expected_node_identity,role='worker',run=run,metadata_budget=budget)
    admission=budget.admission(gate)
    if admission.get('open') is not True or admission.get('release_id')!=expected['release_id']:raise ValueError('Terminal success required before marker removal')
    if actual!=marker['node_identity'] or stopped_machine(budget)!=marker['machine']:raise ValueError('Marker machine/config changed')
    budget.before();path.unlink()
    budget.before();directory=os.open(runtime,os.O_RDONLY|os.O_DIRECTORY)
    try:budget.before();os.fsync(directory)
    finally:os.close(directory)
    return {'attempt_id':attempt_id,'marker_removed':True}


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
        delivery_output_bytes=delivery_output_bytes, before_remote=lambda: lifecycle_guard(runtime))
    if {entry['enrollment_id'] for entry in pool['nodes']} != {entry['enrollment_id'] for entry in authority['registry']['nodes']}:
        raise ValueError('Whole update requires complete enrollment coverage; offline nodes cannot be skipped')
    if expected.get('requires_os_maintenance',False) is not False:
        raise ValueError('Candidate requires a separate reviewed OS maintenance gate')
    deadline_check(deadline)
    runtime = Path(runtime)
    runtime.mkdir(parents=True, exist_ok=True)
    with (runtime / "delivery.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        recheck_controller_authority(authority, run=run)
        lifecycle_guard(runtime)
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
               "operation":"whole_cluster_update","required_nodes":[n["name"] for n in pool["nodes"]],
               "worker_stop":{},"fleet_health":{},"cancellation_check":{},"slurm_before":{},"slurm_drain":{},
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
        prior_stops={};prior_drain={}
        for path in sorted(attempts.glob('*.json')):
            if path.name.endswith('.admission-intent.json') or path==receipt_path:continue
            previous=unique_json(local_metadata(path,1048576),1048576)
            if previous.get('status')=='failed' and not previous.get('requires_reconciliation') and not previous.get('pending_command') and not previous.get('pending_stopped_observation') and previous.get('identity')==manifest(expected) and previous.get('operation')=='whole_cluster_update':
                for name,drain in previous.get('slurm_drain',{}).items():
                    if drain.get('status')=='completed' and name in selected and all(previous.get('node_bindings',{}).get(name,{}).get(k)==selected[name].get(k) for k in ('machine_uuid','machine_id','hostname','node_name','role')):
                        prior_drain[name]=(previous.get('slurm_before',{}).get(name),drain,previous['node_bindings'][name])
                for name,value in previous.get('worker_stop',{}).items():
                    if value.get('attempt_id')==previous.get('attempt_id'):prior_stops[name]=normalized_uuid(previous['attempt_id'])
        def probe(name, *, prior_boot=None):
            stage.update(phase="node_identity", node=name, remote=False, mutation=False)
            try:
                if name in prior_stops and name not in bindings:
                    pin=base64.urlsafe_b64encode(json.dumps(manifest(expected)).encode()).decode()
                    stop=unique_json(ssh(selected[name]['target'],['sudo','-n','qcl-negf-release','update-identity','--manifest-base64',pin,'--update-attempt-id',prior_stops[name],'--update-enrollment-id',selected[name]['enrollment_id'],'--delivery-timeout-seconds',str(max(0,deadline-time.monotonic()-2))],run,trust_snapshot=authority['trust_snapshot']),65536)
                    actual=stop
                else:actual = identity_probe(selected[name]["target"], trust_snapshot=authority["trust_snapshot"], run=run)
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
        for name in selected:
            stage.update(phase='update_capability',node=name,remote=True,mutation=False)
            value=unique_json(ssh(selected[name]['target'],['sudo','-n','qcl-negf-release','update-capabilities'],run,trust_snapshot=authority['trust_snapshot']),16384)
            if value!={'schema':'qcl-negf-local-update-capability-v1','stop_update':True,'stopped_identity':True,'fleet_health':True,'aiida_two_workflow_types':True}:
                raise ValueError('Uninstalled update capability on '+name)
        receipt["node_bindings"] = {name: dict(binding["identity"]) for name, binding in bindings.items()}
        checkpoint()
        stage.update(phase="prefetch", node=None, remote=False, mutation=False)
        # The controller initially receives only the manifest, never CI's local store.
        # A bad cache or hash must leave both admission and current services untouched.
        prefetch_controller_closures(expected, run)
        expected = manifest(expected)
        controller_budget=UpdateScan(deadline)
        controller_config=unique_json(controller_budget.read('/etc/qcl-negf/release-config.json'),65536)
        slurm_conf=controller_config.get('slurm_conf')
        if not isinstance(slurm_conf,str) or not slurm_conf.startswith('/'):raise ValueError('Missing controller SLURM_CONF')
        slurm_argv=['env','TZ=UTC','LC_ALL=C','SLURM_CONF='+slurm_conf,'scontrol']
        workers = [node["name"] for node in nodes if node["role"] == "worker"]
        by_name = {node["name"]: node for node in nodes}
        encoded = base64.urlsafe_b64encode(json.dumps(expected).encode()).decode()

        def cancellation():
            stage.update(phase='cancellation_check',node=None,remote=False,mutation=False)
            aiida=aiida_cancellation_check(run)
            queue=run(['squeue','--all','--noheader','--format','%i']).strip()
            if queue:raise RuntimeError('Slurm cancellation incomplete')
            receipt['cancellation_check']={'aiida':aiida,'slurm':{'queue_empty':True}}
            checkpoint()
        def remote_args(name,action):
            remaining=deadline-time.monotonic()-2
            if remaining<=2:deadline_check(deadline+0) ; raise ValueError('Insufficient remote update duration')
            node=base64.urlsafe_b64encode(json.dumps(dict(bindings[name]['identity'])).encode()).decode()
            argv=['sudo','-n','qcl-negf-release',action,'--manifest-base64',encoded,'--role',selected[name]['role'],
                '--expected-node-identity-base64',node,'--update-attempt-id',attempt_id,'--update-enrollment-id',selected[name]['enrollment_id'],
                '--command-timeout-seconds',str(command_timeout_seconds),'--command-output-bytes',str(command_output_bytes),
                '--delivery-timeout-seconds',str(remaining)]
            if name in prior_stops:argv+=['--prior-update-attempt-id',prior_stops[name]]
            return argv
        def capture_original(worker):
            stage.update(phase='slurm_original',node=worker,remote=False,mutation=False)
            value=final_registration(run,worker,slurm_conf=slurm_conf)
            if worker in prior_drain:
                original,drain,previous_identity=prior_drain[worker]
                if previous_identity!=dict(bindings[worker]['identity']):raise ValueError('Retained original Slurm binding/boot changed')
                if not original or original.get('State')!='IDLE' or original.get('Reason') not in ('None','') or value['State']!='IDLE+DRAIN' or not retained_drain_complete(drain) or value['Reason']!=drain['after_readback']['Reason'] or registration_tuple(value)!=registration_tuple(original):raise ValueError('Retained Slurm provenance/generation changed')
                receipt['slurm_before'][worker]=original
            else:
                if value['State']!='IDLE' or value['Reason'] not in ('None',''):raise ValueError('Original Slurm state/reason requires retained provenance')
                receipt['slurm_before'][worker]=value
            return value
        original_current={worker:capture_original(worker) for worker in workers}
        checkpoint()

        def stopped_observation(worker,action):
            receipt['pending_stopped_observation']={'node':worker,'action':action,'after_mutation':True};checkpoint()
            stage.update(phase='worker_stop' if action=='stop-update' else 'stopped_identity',node=worker,remote=True,mutation=action=='stop-update')
            raw=None
            try:
                raw=ssh(selected[worker]['target'],remote_args(worker,action),run,trust_snapshot=authority['trust_snapshot'])
                value=verify_stop_response(unique_json(raw,65536),bindings[worker],attempt_id)
                if action=='stop-update':receipt['worker_stop'][worker]=value
                elif any(value.get(k)!=receipt['worker_stop'][worker].get(k) for k in ('machine','original_config_digest','stop_window')):raise ValueError('Stopped boot/config/member context changed before copy')
                receipt.pop('pending_stopped_observation',None);checkpoint();return value
            except (ValueError,RuntimeError,OSError,subprocess.SubprocessError) as error:
                error.uncertain=True;receipt.update(requires_reconciliation=True,remote_outcome='unknown',stopped_observation_failure={'node':worker,'action':action,'reason':str(error)[:4096],
                    'response':raw.encode()[:65536].decode(errors='replace') if isinstance(raw,str) else None})
                checkpoint();raise

        def quiesce():
            nonlocal mutation_started
            mutation_started=True
            stage.update(phase='quiesce',remote=False,mutation=True)
            run(['systemctl','stop','qcl-negf-api.service','qcl-negf-aiida.service'])
            for unit in ('qcl-negf-api.service','qcl-negf-aiida.service'):
                state=unit_state(run,unit)
                if state['ActiveState']!='inactive' or state['MainPID']!='0':raise ValueError('Controller unit not stopped')
            for worker in workers:
                stage.update(phase='slurm_drain_recheck',node=worker,remote=False,mutation=False)
                current=final_registration(run,worker,slurm_conf=slurm_conf)
                if registration_safety(current)!=registration_safety(original_current[worker]):raise ValueError('Slurm original state/reason changed before DRAIN')
                reason='application-release:'+attempt_id
                actor_uid,actor_name=drain_actor(run,deadline=deadline)
                requested_epoch=utc_epoch(run,deadline=deadline)
                receipt['slurm_drain'][worker]={'attempt_id':attempt_id,'before_recheck':current,'requested_reason':reason,'status':'pending','reason_evidence':{'actor_uid':actor_uid,'actor_name':actor_name,'requested_epoch':requested_epoch,'captured_epoch':None}};checkpoint()
                stage.update(phase='slurm_drain',node=worker,mutation=True)
                run([*slurm_argv,'update','NodeName='+worker,'State=DRAIN','Reason='+reason])
                try:
                    stage.update(phase='slurm_drain_readback',mutation=False)
                    after=final_registration(run,worker,slurm_conf=slurm_conf)
                    receipt['slurm_drain'][worker]['observed_after_readback']=after;checkpoint()
                    captured_epoch=utc_epoch(run,deadline=deadline)
                    receipt['slurm_drain'][worker]['reason_evidence']['captured_epoch']=captured_epoch
                    own_drain_reason(after['Reason'],receipt['slurm_drain'][worker])
                    if after['State']!='IDLE+DRAIN' or registration_tuple(after)!=registration_tuple(current):raise ValueError('Unexpected Slurm DRAIN readback')
                    receipt['slurm_drain'][worker].update(status='completed',after_readback=after);checkpoint()
                except (ValueError,RuntimeError,OSError,subprocess.SubprocessError) as error:
                    error.uncertain=True;receipt.update(requires_reconciliation=True,remote_outcome='unknown');checkpoint();raise
            cancellation()
            for worker in workers:stopped_observation(worker,'stop-update')
            if set(receipt['worker_stop'])!=set(workers):raise ValueError('Incomplete all-worker barrier')
            cancellation()

        def deliver(name, value):
            nonlocal mutation_started
            node = by_name[name]
            if node['role']=='worker':stopped_observation(name,'stopped-identity')
            else:probe(name,prior_boot=bindings[name]['identity']['boot_id'])
            mutation_started = True
            expected_node = base64.urlsafe_b64encode(json.dumps(dict(bindings[name]["identity"])).encode()).decode()
            stage.update(phase="copy", node=name, remote=True, mutation=True)
            run(["nix", "copy", "--to", "ssh-ng://" + node["target"], value["application_path"],
                 str(Path(value["solver_executable"]).parents[1])])
            stage.update(phase="activate", mutation=True)
            ssh(node["target"], ["sudo", "-n", "qcl-negf-release", "activate", "--manifest-base64", encoded,
                                "--role", node["role"], "--command-timeout-seconds", str(command_timeout_seconds),
                                "--command-output-bytes", str(command_output_bytes),
                                "--expected-node-identity-base64", expected_node,
                                "--update-attempt-id",attempt_id,"--delivery-timeout-seconds",str(max(0,deadline-time.monotonic()-2))], run,
                                trust_snapshot=authority["trust_snapshot"])
            stage.update(phase="check", mutation=False)
            result = ssh(node["target"], ["sudo", "-n", "qcl-negf-release", "check", "--manifest-base64", encoded,
                                         "--role", node["role"], "--command-timeout-seconds", str(command_timeout_seconds),
                                "--command-output-bytes", str(command_output_bytes),
                                "--expected-node-identity-base64", expected_node,"--update-attempt-id",attempt_id,
                                "--delivery-timeout-seconds",str(max(0,deadline-time.monotonic()-2))], run,
                                trust_snapshot=authority["trust_snapshot"])
            try:
                return unique_json(result, command_output_bytes)
            except ValueError as error:
                error.uncertain = True
                receipt.update(requires_reconciliation=True, remote_outcome="unknown",
                               response_prefix=result[:command_output_bytes])
                raise

        def admit():
            lifecycle_guard(runtime)
            for name in selected:
                probe(name,prior_boot=bindings[name]['identity']['boot_id'])
                stage.update(phase='fleet_health',node=name,remote=True,mutation=False)
                health=unique_json(ssh(selected[name]['target'],remote_args(name,'health-update'),run,trust_snapshot=authority['trust_snapshot']),65536)
                verify_node_envelope(bindings[name],health,expected)
                if health.get('nfs_verified') is not True or health.get('auth_verified') is not True or not health.get('nfs_source'):raise ValueError('Incomplete NFS/auth fleet health')
                receipt['fleet_health'][name]=health;checkpoint()
            if set(receipt['fleet_health'])!=set(selected):raise ValueError('Incomplete final fleet health')
            cancellation()
            recheck_controller_authority(authority,run=run)
            for worker in workers:
                stage.update(phase='registration',node=worker,remote=False,mutation=False)
                wanted=current_worker_health(receipt['fleet_health'][worker],bindings[worker],receipt['slurm_before'][worker])
                value=final_registration(run,worker,slurm_conf=slurm_conf)
                if registration_tuple(value)!=wanted:raise ValueError('Controller/current worker registration generation changed')
                receipt['slurm_drain'][worker]['before_resume']=value;checkpoint()
                owned_resume_state(value,receipt['slurm_drain'].get(worker),receipt['worker_stop'].get(worker),receipt['fleet_health'][worker])
                probe(worker,prior_boot=bindings[worker]['identity']['boot_id'])
                cancellation()
                stage.update(phase='admit',node=worker,remote=False,mutation=True)
                receipt['slurm_drain'][worker]['resume_status']='pending';checkpoint()
                try:
                    run([*slurm_argv,'update','NodeName='+worker,'State=RESUME'])
                    accepted=False
                    for _ in range(10):
                        stage.update(phase='resume_readback',node=worker,remote=False,mutation=False)
                        cancellation();value=final_registration(run,worker,slurm_conf=slurm_conf)
                        stage.update(phase='resume_generation',node=worker,remote=True,mutation=False)
                        health=unique_json(ssh(selected[worker]['target'],remote_args(worker,'health-update'),run,trust_snapshot=authority['trust_snapshot']),65536)
                        verify_node_envelope(bindings[worker],health,expected)
                        if health.get('daemon_generation')!=receipt['fleet_health'][worker].get('daemon_generation') or current_worker_health(health,bindings[worker],receipt['slurm_before'][worker])!=wanted:raise ValueError('Current daemon generation changed after RESUME')
                        if registration_ready(wanted,value):accepted=True;break
                        deadline_check(deadline);time.sleep(min(1,max(0,deadline-time.monotonic())))
                    if not accepted:
                        error=RuntimeError('Bounded post-RESUME registration unknown');error.uncertain=True
                        receipt.update(requires_reconciliation=True,remote_outcome='unknown');raise error
                    receipt['slurm_drain'][worker]['resume_status']='completed';checkpoint()
                except (ValueError,RuntimeError,OSError,subprocess.SubprocessError) as error:
                    error.uncertain=True;receipt.update(requires_reconciliation=True,remote_outcome='unknown');checkpoint();raise
            cancellation()
            for name in selected:probe(name,prior_boot=bindings[name]['identity']['boot_id'])

        report = _deliver_pool_owned(expected, list(by_name), gate, deliver=deliver, quiesce=quiesce, admit=admit,
                              deadline=deadline, checkpoint=checkpoint, bindings=bindings, authority=authority, authority_run=run, runtime=runtime)
        report.update(operation='whole_cluster_update',required_nodes=receipt['required_nodes'],worker_stop=receipt['worker_stop'],fleet_health=receipt['fleet_health'],cancellation_check=receipt['cancellation_check'])
        if report.get('status')=='completed':
            try:
                for worker in workers:
                    stage.update(phase='finish_update',node=worker,remote=True,mutation=True)
                    finish=unique_json(ssh(selected[worker]['target'],remote_args(worker,'finish-update'),run,trust_snapshot=authority['trust_snapshot']),4096)
                    if finish!={'attempt_id':attempt_id,'marker_removed':True}:raise ValueError('Update marker cleanup incomplete')
            except (ValueError,RuntimeError,OSError,subprocess.SubprocessError) as error:
                close_after_failure(report,expected,gate);report['admission_error']=str(error);checkpoint(report)
        if report.get("status") == "completed" and intent_path.exists():
            try:
                # Last fallible success action. Crash may restore an unsynced deletion,
                # conservatively blocking reconciliation, never erasing a pending failure.
                deadline_check(deadline);intent_path.unlink()
            except (OSError,CommandFailure) as error:
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
        if getattr(error,'uncertain',False):
            return {**safe_summary(),'status':'failed','error':type(error).__name__,'nodes':{name:{'status':value.get('status','not_attempted')} for name,value in receipt.get('nodes',{}).items()},'requires_reconciliation':True,'remote_outcome':'unknown'}
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["update","update-identity","update-capabilities","stop-update","stopped-identity","health-update","finish-update","prepare-initial", "activate", "check", "guard", "node-check", "bootstrap-identity", "identity", "deliver"])
    parser.add_argument("--update-attempt-id")
    parser.add_argument("--prior-update-attempt-id")
    parser.add_argument("--update-enrollment-id")
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
    if args.action in ('stop-update','stopped-identity','update-identity','health-update','finish-update') or args.update_attempt_id:
        for value in (args.delivery_timeout_seconds,args.command_timeout_seconds):
            if duration(value,'Update duration')<=2:raise ValueError('Update duration must exceed cleanup reserve')
        output_bound(args.command_output_bytes);output_bound(args.delivery_output_bytes)
    action_deadline=time.monotonic()+args.delivery_timeout_seconds
    update_scan=UpdateScan(action_deadline) if args.action in ('stop-update','stopped-identity','update-identity','health-update','finish-update') or args.update_attempt_id else None
    def native_run(argv):
        bounds={'timeout_seconds':args.command_timeout_seconds,'output_bytes':args.command_output_bytes}
        if args.update_attempt_id:bounds['deadline']=action_deadline
        return command(argv,**bounds)
    if args.action=='update-capabilities':
        if not Path(__file__).with_name('aiida_update_check.py').is_file():raise ValueError('Uninstalled readonly update helper')
        print(json.dumps({'schema':'qcl-negf-local-update-capability-v1','stop_update':True,'stopped_identity':True,'fleet_health':True,'aiida_two_workflow_types':True}))
        return
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
    manifest_value = (unique_json(update_scan.read(args.manifest,65536),65536) if update_scan else load(args.manifest)) if args.manifest else unique_json(base64.urlsafe_b64decode(args.manifest_base64),65536)
    expected = manifest(manifest_value)
    expected_node = unique_json(base64.urlsafe_b64decode(args.expected_node_identity_base64), 16384) if args.expected_node_identity_base64 else None
    if args.action == "activate" and expected_node is not None and not args.update_attempt_id:
        assert_expected_node(expected_node, role=args.role, run=native_run)
    if args.action in ("deliver","update"):
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
    elif args.action in ('stop-update','stopped-identity','update-identity','health-update','finish-update'):
        if (expected_node is None and args.action not in ('stopped-identity','update-identity')) or not args.update_attempt_id:parser.error('Update action requires bound identity and own attempt')
        if args.action=='stop-update':result=stop_update(expected,args.update_attempt_id,expected_node,runtime=args.runtime,gate=args.gate,run=native_run,deadline=action_deadline,prior_attempt_id=args.prior_update_attempt_id,enrollment_id=args.update_enrollment_id,metadata_budget=update_scan)
        elif args.action=='update-identity':
            budget=update_scan
            marker=update_marker(args.runtime,args.update_attempt_id,expected,args.gate,budget=budget)
            if marker.get('enrollment_id')!=args.update_enrollment_id:raise ValueError('Prior enrolled identity changed')
            state=unit_state(native_run)
            result=observe_stopped_update(expected,args.update_attempt_id,runtime=args.runtime,gate=args.gate,run=native_run,deadline=action_deadline,budget=budget)['node_identity'] if state['UnitFileState']=='masked-runtime' else observe_node_identity(run=native_run,metadata_budget=budget)
            if result!=marker['node_identity']:raise ValueError('Prior own update identity changed')
        elif args.action=='stopped-identity':result=observe_stopped_update(expected,args.update_attempt_id,runtime=args.runtime,gate=args.gate,run=native_run,deadline=action_deadline,budget=update_scan)
        elif args.action=='health-update':result=fleet_health(expected,expected_node,runtime=args.runtime,gate=args.gate,run=native_run,deadline=action_deadline,metadata_budget=update_scan)
        else:result=finish_update(expected,args.update_attempt_id,expected_node,runtime=args.runtime,gate=args.gate,run=native_run,deadline=action_deadline,metadata_budget=update_scan)
    elif args.action == "check":
        result = check(expected, runtime=args.runtime, role=args.role, run=native_run, expected_node_identity=expected_node,metadata_budget=update_scan)
    else:
        if update_scan:update_scan.before()
        args.runtime.mkdir(parents=True, exist_ok=True)
        # One finite invocation at a time. This is a local flock, not a lease
        # service; a dead process releases it automatically.
        lock_file = "delivery.lock" if args.action == "deliver" else "activation.lock"
        if update_scan:update_scan.before()
        with (args.runtime / lock_file).open("w") as lock:
            if update_scan:update_scan.before()
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if args.action == "prepare-initial":
                result = prepare_initial(manifest_value, runtime=args.runtime, gate=args.gate, role=args.role, run=native_run)
            else:
                admission = update_scan.admission(args.gate) if update_scan else load_admission(args.gate)
                if admission.get("release_id") != expected["release_id"] or (
                    admission.get("open") is not False and not (args.returning_worker and args.role == "worker")
                ):
                    raise ValueError("Close admission for the selected release before activation")
                settings = unique_json(update_scan.read("/etc/qcl-negf/release-config.json",16384),16384) if update_scan else load("/etc/qcl-negf/release-config.json")
                result = activate(expected, runtime=args.runtime, role=args.role, email=settings.get("email"),
                                  run=native_run, allowed_codes_file=Path(settings.get("allowed_codes_file") or "/var/lib/qcl-negf/aiida/code-uuid"),
                                  expected_node_identity=expected_node,update_attempt_id=args.update_attempt_id,gate=args.gate,deadline=action_deadline,metadata_budget=update_scan)
    print(json.dumps(result, sort_keys=True))
    if args.action in ("deliver","update") and (result.get("status") != "completed" or not result.get("open")):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
