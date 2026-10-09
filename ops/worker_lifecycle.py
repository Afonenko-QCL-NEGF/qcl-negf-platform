"""Controller-side bridge using Slurm lifecycle and Runner's scoped stop proof.

No attempt is submitted here. AiiDA remains the only owner of recovery attempts.
Windows waits for this command while guest, Hyper-V and network remain available.
"""
import argparse
import base64
import fcntl
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import os
import shlex
import uuid
import copy
import application_release as release

from application_release import (GATE, IDENTIFIER, RUNTIME, STORE_PATH, TARGET, command,
                                 guard, load, manifest, publish_json, ssh)


JOB = re.compile(r"[0-9]+(?:[_+][0-9]+)?\Z")
OWNER = re.compile(r"[a-z_][a-z0-9_-]{0,63}\Z")
PREFIX = "qcl-negf-attempt-v1:"
TERMINAL_STATES = {"BOOT_FAIL", "CANCELLED", "COMPLETED", "DEADLINE", "FAILED",
                   "NODE_FAIL", "OUT_OF_MEMORY", "PREEMPTED", "TIMEOUT"}


def jobs(node, run=command, shared_root=Path("/srv/qcl-negf/jobs")):
    if not IDENTIFIER.fullmatch(node):
        raise ValueError("Invalid Slurm node")
    listing = run(["squeue", "--all", "--noheader", "--nodes", node,
                   "--states", "all", "--format", "%i|%u|%k|%Z|%N|%T"])
    result = {}
    for line in listing.splitlines():
        if not line.strip():
            continue
        parts = line.strip().split("|", 5)
        if len(parts) != 6 or not JOB.fullmatch(parts[0]) or not OWNER.fullmatch(parts[1]):
            raise ValueError("Malformed Slurm job identity/owner")
        job_id, owner, comment, workdir, allocated_nodes, state = parts
        if allocated_nodes in ("", "(null)", "N/A", "None"):
            continue
        # Completed records may remain in squeue for MinJobAge. Any captured
        # earlier attempt remains in shutdown's durable snapshot until proof.
        if state in TERMINAL_STATES:
            continue
        if state not in ("RUNNING", "COMPLETING", "CONFIGURING"):
            raise ValueError(f"Allocated job {job_id} is {state}; release or resume it before shutdown")
        if not comment.startswith(PREFIX):
            raise ValueError("Active job has no Runner attempt descriptor; manual resolution required")
        try:
            descriptor = json.loads(base64.b64decode(comment[len(PREFIX):], altchars=b"-_", validate=True))
        except (ValueError, json.JSONDecodeError) as error:
            raise ValueError("Malformed Runner attempt descriptor") from error
        if not isinstance(descriptor, dict):
            raise ValueError("Runner attempt descriptor must be an object")
        output = descriptor.get("output_directory")
        execution = descriptor.get("execution_id")
        attempt = descriptor.get("attempt")
        solver = descriptor.get("solver_executable", "")
        if not isinstance(execution, str) or not IDENTIFIER.fullmatch(execution) or type(attempt) is not int or attempt < 1:
            raise ValueError("Attempt descriptor requires scoped execution_id and positive attempt")
        if not isinstance(output, str) or not output or Path(output).is_absolute() or any(part in ("", ".", "..") for part in output.split("/")):
            raise ValueError("Attempt output_directory must be relative without traversal")
        if not isinstance(solver, str) or not solver.endswith("/bin/qcl-negf") or not STORE_PATH.fullmatch(solver[:-len("/bin/qcl-negf")]):
            raise ValueError("Attempt solver must be immutable")
        directory = Path(workdir) / output
        if not Path(workdir).is_absolute() or not directory.resolve().is_relative_to(shared_root.resolve()):
            raise ValueError("Attempt output must be on the shared job filesystem")
        if job_id in result:
            raise ValueError("Duplicate Slurm job identity")
        result[job_id] = {"owner": owner, "output": str(directory), "execution_id": execution,
                          "attempt": attempt, "solver_executable": solver}
    return result


def runner_args(job, action):
    return ["runuser", "-u", job["owner"], "--", job["solver_executable"], action, job["output"],
            "--execution-id", job["execution_id"], "--attempt", str(job["attempt"])]


def _authority_reference(authority):
    return {"registry_sha256": authority["registry_sha256"],
            "controller_identity": dict(authority["local_identity"]),
            "trust_snapshot": dict(authority["trust_snapshot"])}


def _worker_record(authority, node, target):
    matches = [record for record in release.enrollment_records(authority["registry"])
               if record["name"] == node and record["role"] == "worker" and target in record["targets"]]
    if len(matches) != 1:
        raise ValueError("Worker NodeName/route is not enrolled")
    return {**matches[0], "target": target}


def _shutdown_budget(authority, run, *, timeout_seconds, command_timeout_seconds,
                     command_output_bytes, delivery_output_bytes, initial=False, deadline=None):
    deadline = time.monotonic() + timeout_seconds if deadline is None else deadline
    used = authority["used_output_bytes"] if initial else 0
    def bounded(args):
        nonlocal used
        release.deadline_check(deadline)
        available = min(command_output_bytes, delivery_output_bytes - used)
        if available <= 0:
            raise ValueError("Shutdown step output budget exhausted")
        output = (run(args, timeout_seconds=command_timeout_seconds, output_bytes=available, deadline=deadline)
                  if run is command else run(args))
        count = getattr(output, "output_bytes", len(output.encode()))
        used += count
        if count > available or used > delivery_output_bytes:
            raise ValueError("Shutdown step output budget exceeded")
        release.deadline_check(deadline)
        return output
    return bounded


def _shutdown_preflight(node, target, enrollment, runtime, run, *, timeout_seconds,
                        command_timeout_seconds, command_output_bytes, delivery_output_bytes):
    if not IDENTIFIER.fullmatch(node) or not isinstance(target, str) or not TARGET.fullmatch(target):
        raise ValueError("Shutdown needs canonical node, protected enrollment and enrolled target")
    for value in (timeout_seconds, command_timeout_seconds):
        if release.duration(value, "Shutdown step timeout") <= 2:
            raise ValueError("Shutdown step timeout must exceed cleanup reserve")
    release.output_bound(command_output_bytes)
    release.output_bound(delivery_output_bytes)
    start = time.monotonic()
    authority = release.preflight_controller_authority(enrollment, run=run,
        deadline=start + timeout_seconds, command_timeout_seconds=command_timeout_seconds,
        command_output_bytes=command_output_bytes, delivery_output_bytes=delivery_output_bytes,
        before_remote=lambda: release.lifecycle_guard(runtime, normal_intents=False))
    record = _worker_record(authority, node, target)
    # Budget begins before authority; first owned step never renews its deadline.
    bounded = _shutdown_budget(authority, run, timeout_seconds=timeout_seconds,
        command_timeout_seconds=command_timeout_seconds, command_output_bytes=command_output_bytes,
        delivery_output_bytes=delivery_output_bytes, initial=True, deadline=start + timeout_seconds)
    return authority, record, bounded


def _durable_directory_namespace(path):
    """Confirm every containing entry, even on retry after prior fsync failure.

    The filesystem root is the reachable anchor. Each ancestor is opened without
    following symlinks and pinned until its child inode and containing entry are
    synchronized. Runtime/ancestors must be locally protected from rename by
    untrusted actors; the existing controller owner serializes managed callers.
    Privileged concurrent namespace replacement is outside this private-root
    contract (later path publication is not a capability-safe filesystem API).
    """
    path = Path(path).absolute()
    if ".." in path.parts or path == Path("/"):
        raise ValueError("Private lifecycle namespace needs an absolute non-root path")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = os.open("/", flags)
    try:
        for index, name in enumerate(path.parts[1:]):
            try:
                os.mkdir(name, mode=0o700, dir_fd=parent)
            except FileExistsError:
                pass
            child = os.open(name, flags, dir_fd=parent)
            try:
                if index == len(path.parts) - 2:
                    os.fchmod(child, 0o700)
                os.fsync(child)
                # Existing entries also require this barrier: a previous call
                # may have created them but failed before syncing their parent.
                os.fsync(parent)
            except BaseException:
                os.close(child)
                raise
            os.close(parent)
            parent = child
    finally:
        os.close(parent)


def _state_write(path, value):
    _durable_directory_namespace(path.parent)
    publish_json(path, value, mode=0o600)


def _pending_jobs(value):
    if not isinstance(value, dict):
        raise ValueError("Captured jobs scope is missing")
    for job_id, descriptor in value.items():
        if not isinstance(job_id, str) or not JOB.fullmatch(job_id) or not isinstance(descriptor, dict):
            raise ValueError("Malformed captured job identity")
        if (not isinstance(descriptor.get("owner"), str) or not OWNER.fullmatch(descriptor["owner"])
                or not isinstance(descriptor.get("execution_id"), str) or not IDENTIFIER.fullmatch(descriptor["execution_id"])
                or type(descriptor.get("attempt")) is not int or descriptor["attempt"] < 1):
            raise ValueError("Captured job ownership/execution/attempt is malformed")
        solver, output = descriptor.get("solver_executable"), descriptor.get("output")
        if not isinstance(solver, str) or not solver.endswith("/bin/qcl-negf") or not STORE_PATH.fullmatch(solver[:-len("/bin/qcl-negf")]):
            raise ValueError("Captured job solver is not immutable")
        if not isinstance(output, str) or not Path(output).is_absolute() or not Path(output).resolve().is_relative_to(Path("/srv/qcl-negf/jobs")):
            raise ValueError("Captured job output escapes shared scope")
    return value


def _intent_binding(value, record, authority):
    for key in ("enrollment_id", "machine_uuid", "machine_id", "node_name", "role", "hostname"):
        if value.get(key) != record.get(key):
            raise ValueError("Persistent intent " + key + " differs from current enrollment")
    if value.get("inventory_id") != release.normalized_uuid(authority["registry"]["inventory_id"]):
        raise ValueError("Persistent intent inventory authority differs")


def _new_shutdown_intent(node, record, bound, authority, runtime):
    selected = manifest(load(Path(runtime) / "release.json"))
    return {"schema": release.SHUTDOWN_SCHEMA, "origin": "normal_shutdown", "node": node,
            "shutdown_id": str(uuid.uuid4()), "phase": "requested", "capture_complete": False,
            "inventory_id": release.normalized_uuid(authority["registry"]["inventory_id"]),
            "enrollment_id": record["enrollment_id"], "role": "worker", "hostname": bound["identity"]["hostname"],
            "machine_uuid": bound["identity"]["machine_uuid"], "machine_id": bound["identity"]["machine_id"],
            "node_name": bound["identity"]["node_name"], "boot_id": bound["identity"]["boot_id"],
            "target": record["target"], "jobs": {}, "release_id": selected["release_id"],
            "pending_action": None, "requires_reconciliation": False,
            "authority_context": _authority_reference(authority)}


def _merge_scope(pending, active):
    for job_id, descriptor in active.items():
        if job_id in pending and pending[job_id] != descriptor:
            raise ValueError("Slurm job reused with different captured scoped descriptor")
        pending[job_id] = descriptor


def _shutdown_owned_poll(node, state, authority, record, bounded):
    runtime, path = Path(state).parent, Path(state) / (node + ".json")
    with release.lifecycle_owner(runtime):
        release.recheck_controller_authority(authority, run=bounded)
        release.lifecycle_guard(runtime, normal_intents=False)
        observation = release.identity_probe(record["target"], trust_snapshot=authority["trust_snapshot"], run=bounded)
        bound = release.bind_node_observation(record, observation)
        value = None
        if path.exists():
            raw = path.read_bytes()
            value = release.unique_json(raw, 1048576)
            if isinstance(value, dict) and value.get("schema") == "qcl-negf-shutdown-pending-v1":
                if value.get("node") != node:
                    raise ValueError("Legacy shutdown node differs")
                old_jobs = _pending_jobs(value.get("jobs"))
                migrated = _new_shutdown_intent(node, record, bound, authority, runtime)
                migrated.update(origin="legacy_v1", boot_id=None, phase="reconciliation_required",
                    capture_complete=False, jobs=old_jobs, requires_reconciliation=True,
                    reason="legacy_missing_boot_and_scope_authority", legacy_evidence_base64=base64.b64encode(raw).decode())
                _state_write(path, migrated)
                raise RuntimeError("Legacy shutdown evidence retained; trusted reconciliation required")
            release.validate_shutdown_intent(value, node)
            _pending_jobs(value["jobs"])
            _intent_binding(value, record, authority)
            if value.get("requires_reconciliation") or value["phase"] in ("returning", "reconciliation_required"):
                raise RuntimeError("Shutdown ownership/outcome requires reconciliation")
            if value["phase"] != "resumed":
                release.bind_node_observation(record, observation, prior_boot=value["boot_id"])
                if value.get("capture_complete") is not True:
                    value.update(phase="reconciliation_required", requires_reconciliation=True,
                                 reason="orphan_capture_unknown_scope")
                    _state_write(path, value)
                    raise RuntimeError("Orphan capture cannot become idle/safe on empty retry")
        if value is None or value["phase"] == "resumed":
            value = _new_shutdown_intent(node, record, bound, authority, runtime)
            _state_write(path, value)
        shutdown_id = value["shutdown_id"]
        value.update(phase="capture_pending", capture_complete=False, pending_action="drain_capture")
        _state_write(path, value)
        bounded(["scontrol", "update", "NodeName=" + node, "State=DRAIN", "Reason=windows-shutdown"])
        active = jobs(node, bounded)
        pending = copy.deepcopy(value["jobs"])
        _merge_scope(pending, active)
        value.update(phase="awaiting_jobs", capture_complete=True, pending_action=None, jobs=pending)
        _state_write(path, value)
    # Scoped Runner waits are deliberately outside common owner, under per-node flock.
    verified = []
    for job_id, descriptor in pending.items():
        try:
            bounded(runner_args(descriptor, "pause"))
            bounded(runner_args(descriptor, "verify-stop"))
            verified.append(job_id)
        except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
            print(f"Waiting for job {job_id} ({descriptor['execution_id']} attempt {descriptor['attempt']}): {error}", file=sys.stderr)
    with release.lifecycle_owner(runtime):
        release.recheck_controller_authority(authority, run=bounded)
        release.lifecycle_guard(runtime, normal_intents=False)
        value = release.read_shutdown_intent(path, node)
        if value["shutdown_id"] != shutdown_id or value["phase"] != "awaiting_jobs":
            raise RuntimeError("Shutdown ownership changed during stop verification")
        try:
            observation = release.identity_probe(record["target"], trust_snapshot=authority["trust_snapshot"], run=bounded)
            release.bind_node_observation(record, observation, prior_boot=value["boot_id"])
            final_active = jobs(node, bounded)
            remaining = copy.deepcopy(value["jobs"])
            _merge_scope(remaining, final_active)
            for job_id in verified:
                if job_id not in final_active:
                    remaining.pop(job_id, None)
            value.update(jobs=remaining, phase="awaiting_jobs" if remaining else "safe_to_power_off")
            _state_write(path, value)
        except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
            value.update(phase="reconciliation_required", requires_reconciliation=True,
                         reason="capture_finalize_unknown")
            _state_write(path, value)
            raise
    return value["phase"] == "safe_to_power_off"


def shutdown_step(node, state=RUNTIME / "shutdown", *, enrollment, target, run=command,
                  timeout_seconds=1800.0, command_timeout_seconds=360.0,
                  command_output_bytes=1048576, delivery_output_bytes=8388608):
    """One owned finite poll; safe output retains node inhibit across client death."""
    state = Path(state)
    authority, record, bounded = _shutdown_preflight(node, target, enrollment, state.parent, run,
        timeout_seconds=timeout_seconds, command_timeout_seconds=command_timeout_seconds,
        command_output_bytes=command_output_bytes, delivery_output_bytes=delivery_output_bytes)
    state.parent.mkdir(parents=True, exist_ok=True)
    with (state.parent / ("shutdown-" + node + ".lock")).open("w") as owner:
        fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return _shutdown_owned_poll(node, state, authority, record, bounded)


def _authorized_startup_event(node, record, authority):
    """Existing privileged operator/sudo boundary; caller UUID/flags are not proof."""
    if os.getuid() != 0 or os.geteuid() != 0:
        raise PermissionError("Startup requires authenticated privileged controller entrypoint")
    return {"schema": "qcl-negf-startup-event-v1", "event_id": str(uuid.uuid4()), "node": node,
            "inventory_id": release.normalized_uuid(authority["registry"]["inventory_id"]),
            "enrollment_id": record["enrollment_id"], "controller_machine_uuid": authority["local_identity"]["machine_uuid"],
            "actor_uid": 0, "entrypoint": "privileged-controller-operator"}


def _validate_startup_event(event, node, record, authority):
    if (not isinstance(event, dict) or event.get("schema") != "qcl-negf-startup-event-v1"
            or event.get("node") != node or event.get("enrollment_id") != record["enrollment_id"]
            or event.get("inventory_id") != release.normalized_uuid(authority["registry"]["inventory_id"])
            or event.get("controller_machine_uuid") != authority["local_identity"]["machine_uuid"]
            or type(event.get("actor_uid")) is not int or event.get("actor_uid") != 0 or event.get("entrypoint") != "privileged-controller-operator"):
        raise PermissionError("Missing/untrusted/wrong-binding authorized startup event")
    release.normalized_uuid(event.get("event_id"))
    return event


def _public_startup(actual, node, bound, value):
    return {**manifest(actual), "ready": True, "node": node, "node_name": bound["identity"]["node_name"],
            "boot_id": bound["identity"]["boot_id"], "enrollment_id": value["enrollment_id"],
            "shutdown_id": value.get("shutdown_id"), "phase": "resumed"}


def _exclusive_attempt_json(path, value):
    """New immutable owner evidence only: never replace any preexisting CR04 bytes."""
    _durable_directory_namespace(path.parent)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        raw = memoryview((json.dumps(value, sort_keys=True) + "\n").encode())
        while raw:
            count = os.write(descriptor, raw)
            if count <= 0:
                raise OSError("Startup evidence write made no progress")
            raw = raw[count:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def startup(node, target, *, enrollment, runtime=RUNTIME, gate=GATE, run=command,
            delivery_timeout_seconds=1800.0, command_timeout_seconds=360.0,
            command_output_bytes=1048576, delivery_output_bytes=8388608):
    """Same enrolled machine/boot and controller authority, no recovery submission."""
    if not IDENTIFIER.fullmatch(node) or not TARGET.fullmatch(target):
        raise ValueError("Use a valid Slurm node and explicit SSH target")
    for value in (delivery_timeout_seconds, command_timeout_seconds):
        if release.duration(value, "Startup timeout") <= 2:
            raise ValueError("Startup timeout must exceed cleanup reserve")
    release.output_bound(command_output_bytes)
    release.output_bound(delivery_output_bytes)
    deadline = time.monotonic() + delivery_timeout_seconds
    authority = release.preflight_controller_authority(enrollment, run=run, deadline=deadline,
        command_timeout_seconds=command_timeout_seconds, command_output_bytes=command_output_bytes,
        delivery_output_bytes=delivery_output_bytes, before_remote=lambda: release.lifecycle_guard(runtime, normal_intents=False))
    records = release.enrollment_records(authority["registry"])
    matches = [record for record in records if record["name"] == node and record["role"] == "worker" and target in record["targets"]]
    if len(matches) != 1:
        raise ValueError("Returning worker target/NodeName is not enrolled")
    binding = {**matches[0], "target": target}
    used = authority["used_output_bytes"]
    mutation_started = False
    def bounded(args):
        nonlocal used
        release.deadline_check(deadline)
        available = min(command_output_bytes, delivery_output_bytes - used)
        if available <= 0:
            raise ValueError("Startup output budget exhausted")
        env = None
        if run is command and args[:2] == ["nix", "copy"]:
            env = dict(os.environ)
            env["NIX_SSHOPTS"] = shlex.join(release.SSH_OPTIONS + release.trust_options(authority["trust_snapshot"]) + shlex.split(env.get("NIX_SSHOPTS", "")))
        output = (run(args, timeout_seconds=command_timeout_seconds, output_bytes=available, deadline=deadline, env=env)
                  if run is command else run(args))
        count = getattr(output, "output_bytes", len(output.encode()))
        used += count
        if count > available or used > delivery_output_bytes:
            error = ValueError("Startup output budget exceeded")
            error.uncertain = mutation_started
            raise error
        release.deadline_check(deadline)
        return output
    def probe(prior_boot=None):
        actual = release.identity_probe(target, trust_snapshot=authority["trust_snapshot"], run=bounded)
        return release.bind_node_observation(binding, actual, prior_boot=prior_boot)
    runtime = Path(runtime)
    runtime.mkdir(parents=True, exist_ok=True)
    with (runtime / "delivery.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        release.recheck_controller_authority(authority, run=bounded)
        release.lifecycle_guard(runtime, normal_intents=False)
        bound = probe()
        expected = manifest(load(runtime / "release.json"))
        guard(expected["release_id"], expected["solver_executable"], runtime / "release.json", gate)
        state_path = runtime / "shutdown" / (node + ".json")
        value = release.read_shutdown_intent(state_path, node) if state_path.exists() else None
        if value is not None:
            _pending_jobs(value["jobs"])
            _intent_binding(value, binding, authority)
            if value.get("requires_reconciliation") or value.get("pending_action"):
                raise RuntimeError("Normal startup cannot clear uncertain/pending intent")
            if value["phase"] == "resumed":
                if bound["identity"]["boot_id"] != value["return_boot_id"]:
                    raise ValueError("Already resumed intent belongs to another admitted generation")
            elif value["phase"] != "safe_to_power_off" or value.get("capture_complete") is not True or value["jobs"]:
                raise RuntimeError("Normal startup lacks complete safe-stop scope")
            elif bound["identity"]["boot_id"] == value["boot_id"]:
                raise ValueError("Normal return requires a NEW boot of the SAME enrolled machine")
        event = _validate_startup_event(_authorized_startup_event(node, binding, authority), node, binding, authority)
        encoded = base64.urlsafe_b64encode(json.dumps(expected).encode()).decode()
        expected_node = base64.urlsafe_b64encode(json.dumps(dict(bound["identity"])).encode()).decode()
        flags = ["--expected-node-identity-base64", expected_node,
                 "--command-timeout-seconds", str(command_timeout_seconds),
                 "--command-output-bytes", str(command_output_bytes)]
        if value is not None and value["phase"] == "resumed":
            raw = ssh(target, ["sudo", "-n", "qcl-negf-release", "check", "--manifest-base64", encoded,
                              "--role", "worker", *flags], bounded, trust_snapshot=authority["trust_snapshot"])
            actual = release.verify_node_envelope(bound, release.unique_json(raw), expected)
            probe(bound["identity"]["boot_id"])
            release.recheck_controller_authority(authority, run=bounded)
            return _public_startup(actual, node, bound, value)
        if value is None:
            value = {"schema": release.SHUTDOWN_SCHEMA, "origin": "initial_enrollment", "node": node,
                "shutdown_id": None, "boot_id": None, "capture_complete": None, "jobs": {},
                "inventory_id": release.normalized_uuid(authority["registry"]["inventory_id"]),
                "enrollment_id": binding["enrollment_id"], "role": "worker", "hostname": bound["identity"]["hostname"],
                "machine_uuid": bound["identity"]["machine_uuid"], "machine_id": bound["identity"]["machine_id"],
                "node_name": bound["identity"]["node_name"], "target": target, "release_id": expected["release_id"],
                "authority_context": _authority_reference(authority)}
        value.update(phase="returning", pending_action="drain_health_activation", startup_event=event,
            pending_return_boot_id=bound["identity"]["boot_id"], requires_reconciliation=False,
            startup_authority_context=_authority_reference(authority))
        _state_write(state_path, value)
        resume_marker = None
        try:
            mutation_started = True
            bounded(["scontrol", "update", "NodeName=" + node, "State=DRAIN", "Reason=returning-worker"])
            if jobs(node, bounded):
                raise ValueError("Returning worker still has active jobs")
            probe(bound["identity"]["boot_id"])
            bounded(["nix", "copy", "--to", "ssh-ng://" + target, expected["application_path"],
                     str(Path(expected["solver_executable"]).parents[1])])
            ssh(target, ["sudo", "-n", "qcl-negf-release", "activate", "--manifest-base64", encoded,
                         "--role", "worker", "--returning-worker", *flags], bounded,
                trust_snapshot=authority["trust_snapshot"])
            raw = ssh(target, ["sudo", "-n", "qcl-negf-release", "check", "--manifest-base64", encoded,
                               "--role", "worker", *flags], bounded, trust_snapshot=authority["trust_snapshot"])
            try:
                envelope = release.unique_json(raw)
            except ValueError as error:
                error.uncertain = True
                raise
            actual = release.verify_node_envelope(bound, envelope, expected)
            try:
                probe(bound["identity"]["boot_id"])
                release.recheck_controller_authority(authority, run=bounded)
            except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
                error.uncertain = True
                raise
            guard(expected["release_id"], expected["solver_executable"], runtime / "release.json", gate)
            release.deadline_check(deadline)
            release.lifecycle_guard(runtime, normal_intents=False)
            current = release.read_shutdown_intent(state_path, node)
            if current.get("startup_event", {}).get("event_id") != event["event_id"] or current["phase"] != "returning":
                raise RuntimeError("Startup intent ownership changed")
            # All preexisting guards completed under common owner. This independent
            # CR04 primitive protects terminal node replace/fsync failure after RESUME.
            resume_marker = runtime / "delivery-attempts" / (str(uuid.uuid4()) + ".startup-admission-intent.json")
            _exclusive_attempt_json(resume_marker, {"schema": "qcl-negf-admission-intent-v1",
                "attempt_id": resume_marker.name.split(".")[0], "identity": expected, "node": node,
                "startup_event_id": event["event_id"]})
            value.update(return_boot_id=bound["identity"]["boot_id"], pending_action="resume")
            _state_write(state_path, value)
            bounded(["scontrol", "update", "NodeName=" + node, "State=RESUME"])
            value.update(phase="resumed", pending_action=None, requires_reconciliation=False)
            _state_write(state_path, value)
            result = _public_startup(actual, node, bound, value)
            resume_marker.unlink()  # Only our new marker; last fallible success action.
            return result
        except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
            value.update(phase="reconciliation_required", requires_reconciliation=True,
                         reason="startup_outcome_unknown", pending_action=value.get("pending_action") or "startup")
            try:
                _state_write(state_path, value)
            except OSError:
                # A separate marker, when created, is never cleared on failure.
                pass
            if getattr(error, "uncertain", False) or mutation_started or isinstance(error, (RuntimeError, OSError, subprocess.SubprocessError)):
                report = {"schema": "qcl-negf-delivery-attempt-v1", "status": "failed",
                          "requires_reconciliation": True, "remote_outcome": "unknown", "open": False,
                          "manifest": expected, "node_identity": dict(bound["identity"]),
                          "trust_snapshot": dict(authority["trust_snapshot"])}
                release.close_after_failure(report, expected, gate)
                attempts = runtime / "delivery-attempts"
                _exclusive_attempt_json(attempts / (str(uuid.uuid4()) + ".json"), report)
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["startup", "shutdown"])
    parser.add_argument("--node", required=True)
    parser.add_argument("--target")
    parser.add_argument("--enrollment")
    parser.add_argument("--poll-seconds", type=float, default=5.0)
    args = parser.parse_args()
    if not IDENTIFIER.fullmatch(args.node) or args.poll_seconds <= 0:
        parser.error("Use a valid node and positive poll interval")
    if args.action == "startup":
        if not args.target or not args.enrollment:
            parser.error("Startup needs explicit --target and protected --enrollment")
        print(json.dumps(startup(args.node, args.target, enrollment=args.enrollment), sort_keys=True))
        return
    if not args.target or not args.enrollment:
        parser.error("Shutdown needs explicit --target and protected --enrollment")
    authority, record, bounded = _shutdown_preflight(args.node, args.target, args.enrollment, RUNTIME, command,
        timeout_seconds=1800.0, command_timeout_seconds=360.0,
        command_output_bytes=1048576, delivery_output_bytes=8388608)
    RUNTIME.mkdir(parents=True, exist_ok=True)
    with (RUNTIME / ("shutdown-" + args.node + ".lock")).open("w") as owner:
        fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Unlimited normal wait, finite owned step; no global lock while waiting.
        while True:
            try:
                if _shutdown_owned_poll(args.node, RUNTIME / "shutdown", authority, record, bounded):
                    intent = release.read_shutdown_intent(RUNTIME / "shutdown" / (args.node + ".json"), args.node)
                    print(json.dumps({"node": args.node, "safe_to_shutdown": True,
                        "shutdown_id": intent["shutdown_id"], "enrollment_id": intent["enrollment_id"],
                        "node_name": intent["node_name"], "boot_id": intent["boot_id"], "phase": intent["phase"]}))
                    break
            except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
                print(f"Shutdown remains waiting: {error}", file=sys.stderr)
            time.sleep(args.poll_seconds)
            bounded = _shutdown_budget(authority, command, timeout_seconds=1800.0,
                command_timeout_seconds=360.0, command_output_bytes=1048576, delivery_output_bytes=8388608)



if __name__ == "__main__":
    main()
