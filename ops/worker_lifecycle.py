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


def shutdown_step(node, state=RUNTIME / "shutdown", *, run=command):
    """One retryable poll; durable snapshot survives SSH/GPO interruptions."""
    if not IDENTIFIER.fullmatch(node):
        raise ValueError("Invalid Slurm node")
    state = Path(state)
    snapshot = state / (node + ".json")
    run(["scontrol", "update", "NodeName=" + node, "State=DRAIN", "Reason=windows-shutdown"])
    active = jobs(node, run)
    pending = load(snapshot)["jobs"] if snapshot.exists() else {}
    for job_id, descriptor in active.items():
        if job_id in pending and pending[job_id] != descriptor:
            raise ValueError("Slurm job reused with a different attempt descriptor")
        pending[job_id] = descriptor
    if not pending:
        return True
    # Snapshot BEFORE any marker request, including jobs of other owners.
    publish_json(snapshot, {"schema": "qcl-negf-shutdown-pending-v1", "node": node, "jobs": pending})
    complete = []
    for job_id, descriptor in pending.items():
        try:
            run(runner_args(descriptor, "pause"))
            # This executes Runner's actual integrity/identity verifier on the
            # permanent node. A JSON 'verified' flag or telemetry is no proof.
            run(runner_args(descriptor, "verify-stop"))
            if job_id not in active:
                complete.append(job_id)
        except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
            print(f"Waiting for job {job_id} ({descriptor['execution_id']} attempt {descriptor['attempt']}): {error}", file=sys.stderr)
    for job_id in complete:
        del pending[job_id]
    if pending:
        publish_json(snapshot, {"schema": "qcl-negf-shutdown-pending-v1", "node": node, "jobs": pending})
        return False
    snapshot.unlink()
    return True


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
        delivery_output_bytes=delivery_output_bytes, before_remote=lambda: release.unresolved_deliveries(runtime))
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
        release.unresolved_deliveries(runtime)
        bound = probe()
        expected = manifest(load(runtime / "release.json"))
        guard(expected["release_id"], expected["solver_executable"], runtime / "release.json", gate)
        bounded(["scontrol", "update", "NodeName=" + node, "State=DRAIN", "Reason=returning-worker"])
        if jobs(node, bounded):
            raise ValueError("Returning worker still has active jobs")
        if (runtime / "shutdown" / (node + ".json")).exists():
            raise ValueError("Previous shutdown still lacks durable stop proof")
        probe(bound["identity"]["boot_id"])
        encoded = base64.urlsafe_b64encode(json.dumps(expected).encode()).decode()
        expected_node = base64.urlsafe_b64encode(json.dumps(dict(bound["identity"])).encode()).decode()
        flags = ["--expected-node-identity-base64", expected_node,
                 "--command-timeout-seconds", str(command_timeout_seconds),
                 "--command-output-bytes", str(command_output_bytes)]
        try:
            mutation_started = True
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
            bounded(["scontrol", "update", "NodeName=" + node, "State=RESUME"])
            return actual
        except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
            if getattr(error, "uncertain", False) or isinstance(error, (RuntimeError, OSError, subprocess.SubprocessError)):
                report = {"schema": "qcl-negf-delivery-attempt-v1", "status": "failed",
                          "requires_reconciliation": True, "remote_outcome": "unknown", "open": False,
                          "manifest": expected, "node_identity": dict(bound["identity"]),
                          "trust_snapshot": dict(authority["trust_snapshot"])}
                release.close_after_failure(report, expected, gate)
                attempts = runtime / "delivery-attempts"
                attempts.mkdir(mode=0o700, exist_ok=True)
                os.chmod(attempts, 0o700)
                publish_json(attempts / (str(uuid.uuid4()) + ".json"), report, mode=0o600)
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
    RUNTIME.mkdir(parents=True, exist_ok=True)
    lock_path = RUNTIME / ("shutdown-" + args.node + ".lock")
    with lock_path.open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Intentional unlimited normal-shutdown wait. Poll failures report
        # their cause and never authorize Windows to stop the guest.
        while True:
            try:
                if shutdown_step(args.node):
                    print(json.dumps({"node": args.node, "safe_to_shutdown": True}))
                    break
            except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
                print(f"Shutdown remains waiting: {error}", file=sys.stderr)
            time.sleep(args.poll_seconds)


if __name__ == "__main__":
    main()
