# Build profile admission

The administrative operator selects standard or burst before an idle build.
`ops/build_admission.py` reads a private JSON snapshot and validates a finite
resource policy. It runs no SSH, service, hypervisor or build command and does
not acquire the evidence itself. Its success is conditional on the collector's
complete, accurate input; it is not an authorization token or a resource lock.
The snapshot must be a regular file of at most 1 MiB. Nonblocking admission
rejects FIFOs and symlink leaves before reading or parsing JSON.

Collect a full actual host VM inventory, Linux `MemTotal`/`MemAvailable` in MiB
and logical CPU count. VM memory is the configured maximum, not current balloon
memory. Identify the builder, pnetlab, controller and compute by reviewed VM IDs.
Capture successful queue and idle evidence at the same boundary; use the start
of collection as `captured_at` (Unix seconds). Collection errors must abort
without producing an admissible snapshot. Never convert SSH failure into
`undeployed`, an empty queue, zero activity or a stopped VM.

The snapshot shape is:

```json
{
  "schema": "qcl-build-admission.v1",
  "captured_at": 1000,
  "complete_host_inventory": true,
  "host": {"memory_total_mib": 65536, "memory_available_mib": 50000, "logical_cpus": 32},
  "roles": {"builder": 709, "pnetlab": 201, "control": 712, "compute": 713},
  "vms": [
    {"vm_id": 709, "status": "running", "memory_mib": 8192, "vcpus": 4},
    {"vm_id": 201, "status": "running", "memory_mib": 8192, "vcpus": 8}
  ],
  "idle": {"build_jobs": 0, "nix_builds": 0, "runner_jobs": 0},
  "queue": {"status": "undeployed", "jobs": 0}
}
```

These are synthetic facts, not current measurements. `vms` contains **every**
VM on the host; omitted controller and compute qualify for the initial-install
queue exemption only when both are absent from the actual complete inventory.
Otherwise the controller must exist and queue status must be `read` with zero
jobs. Idle evidence covers manual build units, Nix daemon builds and active
runner jobs; an idle persistent runner listener is not an active job.

```sh
python3 ops/build_admission.py --snapshot /absolute/private/admission.json --profile burst
```

Snapshots expire after 60 seconds and future timestamps fail. Burst refuses an
actually running compute VM. Every transition requires zero active jobs. The
planned builder plus all other running VM maximum allocations must fit host
RAM minus 8 GiB and logical CPUs minus two. pnetlab maximum RAM is at most
8 GiB. An additional conservative available-memory gate requires 8 GiB host
reserve + 8 GiB pnetlab allowance + any builder RAM increase (or its complete
target allocation when stopped). The policy does not reserve that capacity.

Repeat fresh collection immediately before applying the reviewed saved plan;
other operators must not start jobs or guests during the transition. After
reboot, verify the selected VM CPU/RAM and the shared NixOS slice/daemon limits.
Both `compute.started` and `compute.on_boot` remain false through burst. Return
the builder to standard before starting compute. No running job is cancelled.
The source-only helper does not prove a collector, an actual reboot or live
capacity admission; those need bounded runtime validation at the private site.
