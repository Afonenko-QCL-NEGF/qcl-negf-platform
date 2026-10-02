#!/usr/bin/env python3
"""Validate a private, freshly collected snapshot. No host commands or mutation."""
import argparse
import json
import os
import stat
import time
from pathlib import Path

HOST_RESERVE_MIB = 8192
PNETLAB_MAX_MIB = 8192
HOST_RESERVED_CPUS = 2
MAX_AGE_SECONDS = 60
MAX_SNAPSHOT_BYTES = 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, label, minimum=0):
    require(type(value) is int and value >= minimum, f"Invalid {label}")
    return value


def admit(snapshot, profile, *, now=None):
    require(type(snapshot) is dict, "Snapshot must be a JSON object")
    profiles = json.loads((Path(__file__).parent / "build-profiles.json").read_text())
    require(profile in profiles, "Unknown build profile")
    target = profiles[profile]
    require(snapshot.get("schema") == "qcl-build-admission.v1", "Invalid snapshot schema")
    require(snapshot.get("complete_host_inventory") is True, "A complete host VM inventory is required")
    captured = integer(snapshot["captured_at"], "capture timestamp")
    now = time.time() if now is None else now
    require(0 <= now - captured <= MAX_AGE_SECONDS, "Snapshot must be fresh, never future-dated")
    host = snapshot["host"]
    total = integer(host["memory_total_mib"], "host total memory", 1)
    available = integer(host["memory_available_mib"], "host available memory")
    cpus = integer(host["logical_cpus"], "host CPU count", 1)
    require(available <= total, "Invalid available memory")
    roles = snapshot["roles"]
    role_ids = [integer(roles[name], f"{name} VM ID", 100) for name in ("builder", "pnetlab", "control", "compute")]
    require(len(set(role_ids)) == len(role_ids), "Role VM IDs must be distinct")
    vms = {}
    for vm in snapshot["vms"]:
        vm_id = integer(vm["vm_id"], "inventory VM ID", 100)
        require(vm_id not in vms, "Inventory contains duplicate VM IDs")
        require(vm["status"] in ("running", "stopped"), "Unknown VM state is not stopped")
        integer(vm["memory_mib"], "VM maximum memory", 1)
        integer(vm["vcpus"], "VM CPU count", 1)
        vms[vm_id] = vm
    require(roles["builder"] in vms, "Builder must exist in the actual inventory")
    require(roles["pnetlab"] in vms, "pnetlab must exist in the actual inventory")
    require(vms[roles["pnetlab"]]["memory_mib"] <= PNETLAB_MAX_MIB, "pnetlab maximum exceeds 8 GiB")
    compute = vms.get(roles["compute"])
    if profile == "burst":
        require(compute is None or compute["status"] == "stopped", "Burst requires actual compute off")
    idle = snapshot["idle"]
    require(all(integer(idle[name], name) == 0 for name in ("build_jobs", "nix_builds", "runner_jobs")), "Builder must be idle")
    queue = snapshot["queue"]
    jobs = integer(queue["jobs"], "queue job count")
    control = vms.get(roles["control"])
    if control is None and compute is None:
        require(queue["status"] == "undeployed" and jobs == 0, "Initial queue exemption requires both scientific VMs undeployed")
    else:
        require(control is not None and queue["status"] == "read" and jobs == 0, "Existing controller queue must be successfully read and empty")
    builder = vms[roles["builder"]]
    running_others = [vm for vm in vms.values() if vm["status"] == "running" and vm["vm_id"] != roles["builder"]]
    guest_memory = sum(vm["memory_mib"] for vm in running_others) + target["memory_mib"]
    guest_cpus = sum(vm["vcpus"] for vm in running_others) + target["vcpus"]
    require(guest_memory <= total - HOST_RESERVE_MIB, "Planned guests exceed host memory budget")
    require(guest_cpus <= cpus - HOST_RESERVED_CPUS, "Planned guests exceed host CPU budget")
    current_builder_memory = builder["memory_mib"] if builder["status"] == "running" else 0
    # Conservative additional free-memory policy: host reserve, full pnetlab
    # allowance and the builder's increase. This is admission, not a reservation.
    required_available = HOST_RESERVE_MIB + PNETLAB_MAX_MIB + max(0, target["memory_mib"] - current_builder_memory)
    require(available >= required_available, "Insufficient available host memory for profile transition")
    return {
        "schema": "qcl-build-admission-result.v1",
        "profile": profile,
        "captured_at": captured,
        "expires_at": captured + MAX_AGE_SECONDS,
        "planned_guest_memory_mib": guest_memory,
        "planned_guest_vcpus": guest_cpus,
        "required_available_memory_mib": required_available,
    }


def read_snapshot(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        require(stat.S_ISREG(metadata.st_mode), "Snapshot must be a regular file")
        require(metadata.st_size <= MAX_SNAPSHOT_BYTES, "Snapshot exceeds 1 MiB")
        raw = stream.read(MAX_SNAPSHOT_BYTES + 1)
        require(len(raw) <= MAX_SNAPSHOT_BYTES, "Snapshot exceeds 1 MiB")
    return json.loads(raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--profile", required=True, choices=("standard", "burst"))
    args = parser.parse_args()
    try:
        result = admit(read_snapshot(args.snapshot), args.profile)
    except (ValueError, KeyError, TypeError, OSError) as error:
        parser.exit(1, f"Admission refused: {error}\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
