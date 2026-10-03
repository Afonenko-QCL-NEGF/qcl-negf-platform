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

from application_release import (GATE, IDENTIFIER, RUNTIME, STORE_PATH, TARGET, command,
                                 guard, load, manifest, publish_json, ssh)


JOB = re.compile(r"[0-9]+(?:[_+][0-9]+)?\Z")
OWNER = re.compile(r"[a-z_][a-z0-9_-]{0,63}\Z")
PREFIX = "qcl-negf-attempt-v1:"


def jobs(node, run=command, shared_root=Path("/srv/qcl-negf/jobs")):
    if not IDENTIFIER.fullmatch(node):
        raise ValueError("Invalid Slurm node")
    listing = run(["squeue", "--all", "--noheader", "--nodes", node,
                   "--states", "RUNNING,COMPLETING", "--format", "%i|%u|%k|%Z"])
    result = {}
    for line in listing.splitlines():
        if not line.strip():
            continue
        parts = line.strip().split("|", 3)
        if len(parts) != 4 or not JOB.fullmatch(parts[0]) or not OWNER.fullmatch(parts[1]):
            raise ValueError("Malformed Slurm job identity/owner")
        job_id, owner, comment, workdir = parts
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


def startup(node, target, *, runtime=RUNTIME, gate=GATE, run=command):
    """Returning worker stays drained until the selected release is verified."""
    if not IDENTIFIER.fullmatch(node) or not TARGET.fullmatch(target):
        raise ValueError("Use a valid Slurm node and explicit SSH target")
    expected = manifest(load(Path(runtime) / "release.json"))
    guard(expected["release_id"], expected["solver_executable"], Path(runtime) / "release.json", gate)
    run(["scontrol", "update", "NodeName=" + node, "State=DRAIN", "Reason=returning-worker"])
    if jobs(node, run):
        raise ValueError("Returning worker still has active jobs")
    if (Path(runtime) / "shutdown" / (node + ".json")).exists():
        raise ValueError("Previous shutdown still lacks durable stop proof")
    run(["nix", "copy", "--to", "ssh-ng://" + target, expected["application_path"],
         str(Path(expected["solver_executable"]).parents[1])])
    encoded = base64.urlsafe_b64encode(json.dumps(expected).encode()).decode()
    ssh(target, ["sudo", "-n", "qcl-negf-release", "activate", "--manifest-base64", encoded,
                 "--role", "worker", "--returning-worker"], run)
    actual = json.loads(ssh(target, ["sudo", "-n", "qcl-negf-release", "check", "--manifest-base64", encoded,
                                   "--role", "worker"], run))
    if actual.get("ready") is not True or manifest(actual) != expected:
        raise ValueError("Returning worker release verification failed")
    guard(expected["release_id"], expected["solver_executable"], Path(runtime) / "release.json", gate)
    run(["scontrol", "update", "NodeName=" + node, "State=RESUME"])
    return actual


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["startup", "shutdown"])
    parser.add_argument("--node", required=True)
    parser.add_argument("--target")
    parser.add_argument("--poll-seconds", type=float, default=5.0)
    args = parser.parse_args()
    if not IDENTIFIER.fullmatch(args.node) or args.poll_seconds <= 0:
        parser.error("Use a valid node and positive poll interval")
    RUNTIME.mkdir(parents=True, exist_ok=True)
    lock_path = RUNTIME / ("delivery.lock" if args.action == "startup" else "shutdown-" + args.node + ".lock")
    with lock_path.open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.action == "startup":
            if not args.target:
                parser.error("Startup needs the returning worker's explicit SSH --target")
            print(json.dumps(startup(args.node, args.target), sort_keys=True))
        else:
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
