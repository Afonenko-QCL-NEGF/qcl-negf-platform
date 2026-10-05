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


def resolve_profile(profile, resources):
    profiles = json.loads((Path(__file__).parent / "build-profiles.json").read_text())
    require(profile in profiles, "Unknown build profile")
    target = profiles[profile]
    if not target.get("dynamic", False):
        require(resources is None, "Explicit resources belong only production-build")
        return target
    require(type(resources) is dict and set(resources) == {"vcpus", "memory_mib"},
            "production-build requires complete CPU/RAM resources")
    cpus = integer(resources["vcpus"], "production vCPUs", 1)
    memory = integer(resources["memory_mib"], "production memory", target["guest_reserve_mib"] + 1)
    return {**target, "vcpus": cpus, "memory_mib": memory, "build_cores": cpus,
            "cpu_quota": f"{cpus * 100}%", "memory_max": f"{memory - target['guest_reserve_mib']}M"}


def anonymous_memory_credit(snapshot, builder, target):
    measured = snapshot.get("builder_memory")
    require(type(measured) is dict and set(measured) == {"resident_anonymous_mib", "source", "vm_id", "pid"},
            "production-build requires an anonymous memory measurement with source/owner/PID")
    require(integer(measured["vm_id"], "memory measurement owner", 100) == builder["vm_id"],
            "Anonymous memory measurement owner differs from builder")
    resident = integer(measured["resident_anonymous_mib"], "anonymous resident memory")
    if builder["status"] == "stopped":
        require(resident == 0 and measured["source"] == "stopped" and measured["pid"] is None,
                "Stopped builder memory measurement must be zero with no PID")
        return 0
    require(measured["source"] in ("RssAnon", "Pss_Anon"), "Use anonymous resident memory, never raw RSS")
    integer(measured["pid"], "memory measurement PID", 1)
    return max(0, min(builder["memory_mib"], resident) - target["memory_credit_reserve_mib"])


def admit(snapshot, profile, *, now=None, resources=None):
    require(type(snapshot) is dict, "Snapshot must be a JSON object")
    target = resolve_profile(profile, resources)
    production = profile == "production-build"
    if production:
        require(snapshot.get("temporary_bootstrap") is True,
                "Shared CPUs require explicit temporary bootstrap production-build")
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
    if profile in ("burst", "production-build"):
        require(compute is None or compute["status"] == "stopped", "Build profile requires actual compute off")
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
    if production:
        require(target["vcpus"] <= cpus, "Builder vCPUs exceed actual host CPU count")
    else:
        require(guest_cpus <= cpus - HOST_RESERVED_CPUS, "Planned guests exceed host CPU budget")
    current_builder_memory = builder["memory_mib"] if builder["status"] == "running" else 0
    if production:
        current_builder_memory = anonymous_memory_credit(snapshot, builder, target)
    # Conservative additional free-memory policy: host reserve, full pnetlab
    # allowance and the builder's increase. This is admission, not a reservation.
    required_available = HOST_RESERVE_MIB + PNETLAB_MAX_MIB + max(0, target["memory_mib"] - current_builder_memory)
    require(available >= required_available, "Insufficient available host memory for profile transition")
    result = {
        "schema": "qcl-build-admission-result.v1",
        "profile": profile,
        "captured_at": captured,
        "expires_at": captured + MAX_AGE_SECONDS,
        "planned_guest_memory_mib": guest_memory,
        "planned_guest_vcpus": guest_cpus,
        "required_available_memory_mib": required_available,
        "builder_resources": target,
        "shared_host_cpus": production,
    }
    if production:
        result["builder_memory_credit_mib"] = current_builder_memory
        result["builder_memory_measurement"] = dict(snapshot["builder_memory"])
    return result


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
    parser.add_argument("--profile", required=True, choices=("standard", "burst", "local-debug", "production-build"))
    parser.add_argument("--vcpus", type=int, help="Explicit admitted temporary production-build guest CPU count")
    parser.add_argument("--memory-mib", type=int, help="Explicit admitted temporary production-build guest RAM")
    args = parser.parse_args()
    try:
        resources = None if args.vcpus is None and args.memory_mib is None else {
            "vcpus": args.vcpus, "memory_mib": args.memory_mib}
        result = admit(read_snapshot(args.snapshot), args.profile, resources=resources)
    except (ValueError, KeyError, TypeError, OSError) as error:
        parser.exit(1, f"Admission refused: {error}\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
