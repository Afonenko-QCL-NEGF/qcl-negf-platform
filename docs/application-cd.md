# Application CD and closed admission

The existing umbrella GitHub Actions workflow owns build/test/publish/deliver/check. This component
adds no second CI, deploy daemon, discovery or revision lock catalog. The initial deployment is
CPU-only and selects one release for the active pool.

## One-time image preparation

Pass the same `qclNegf.release.applicationPackage` and immutable `qclNegf.cluster.solverPackage` to
controller and Linux workers; the private-site example does this. The image installs
release/lifecycle commands, profile initialization and a slurmd boot gate. API/AiiDA/bootstrap run
from the stable `/nix/var/nix/profiles/qcl-negf-application`; initialization sets it only when
absent, so reboot retains the CD-selected release. Services read runtime
`/var/lib/qcl-negf/runtime/service.env`. The solver profile is a GC root only; InstalledCode always
uses immutable `/nix/store/.../bin/qcl-negf`.

OS changes require the deployment procedure again. Database schema changes are explicit maintenance
with backup. Routine activation runs neither migrations nor `nixos-rebuild`.

## Inputs and delivery

Derive release identity from the existing umbrella graph/artifact hashes and keep that provenance
with the release. JSON manifest:

```json
{
  "schema": "qcl-negf-release-v1",
  "release_id": "example-release",
  "application_path": "/nix/store/EXAMPLE-application",
  "solver_executable": "/nix/store/EXAMPLE-solver/bin/qcl-negf",
  "closures": [
    {
      "path": "/nix/store/EXAMPLE-application",
      "narHash": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    },
    {
      "path": "/nix/store/EXAMPLE-solver",
      "narHash": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    }
  ],
  "cache_uri": "https://cache.example.invalid"
}
```

The paths and hashes above are placeholders. The umbrella assembler supplies the actual application
and solver `narHash` evidence. `cache_uri` is an optional delivery route and does not change release
identity. It must be a nonempty string without whitespace, control characters, a leading dash or an
embedded password. Keep credentials outside the URI and manifest. Nix retains its normal signature
and trust checks; this procedure does not disable `require-sigs`.

An explicit private pool is separate from the manual credentials inventory; offline daytime workers
are omitted. This synthetic v2 example references the enrollment example below; actual protected
inventory and host-key enrollment must be supplied by the operator:

```json
{
  "schema": "qcl-negf-active-pool-v2",
  "nodes": [
    {
      "name": "controller",
      "target": "admin@controller.invalid",
      "role": "controller",
      "enrollment_id": "10000000-0000-0000-0000-000000000001"
    },
    {
      "name": "worker",
      "target": "admin@worker.invalid",
      "role": "worker",
      "enrollment_id": "20000000-0000-0000-0000-000000000002"
    }
  ]
}
```

Build/test/publish closures through the existing workflow. Its protected delivery job/environment
receives reviewed limited SSH deployment access; build jobs do not receive production credentials or
become unrestricted administrators. In the user's maintenance window run on the permanent
controller:

```console
sudo qcl-negf-release deliver --manifest /private/release.json --pool /private/active-pool-v2.json --enrollment /operator-protected/enrollment.json
```

For an SSH pipeline, `--manifest /dev/stdin` accepts the manifest without copying the controller's
private pool to CI. SSH keys/cache signing keys remain outside Git, Nix inputs and scientific
archives.

Before maintenance, protected enrollment and readonly identity probes bind the actual local
controller and all selected nodes. The controller then fetches both named closures with
`nix copy --from CACHE_URI APPLICATION SOLVER` and verifies their exact manifest hashes using local
`nix path-info --json APPLICATION SOLVER`. Fetch failure, malformed or missing evidence, and either
hash mismatch stop delivery before any gate change, service stop, worker drain or remote mutation.
Readonly identity SSH probes may already have run. An older assembled manifest without `cache_uri`
remains supported when both closures already exist in the controller store and match its declared
hashes. Delivery cannot accept a manifest without both hashes; minimal four-field manifests remain
valid for activation and runtime identity checks.

After this preflight, delivery closes `/srv/qcl-negf/jobs/.release-admission.json`, stops API/AiiDA,
drains selected workers and rejects a nonempty Slurm queue. The maintenance owner first
completes/cancels the old research and removes its automatic resume/queued attempts. The command
never cancels or restarts research on the user's behalf. `JobRequeue=0` and AiiDA's `--no-requeue`
prevent a second independent owner. The shared NFS gate is published as the scientific UID because
the export retains `root_squash`; local runtime state remains administrative. Scientific submitters
require access to the shared job group, whose UID/GID mapping is a site check.

`nix copy` delivers application+solver closures; activation switches the profile, reconciles a new
release-specific InstalledCode label with the exact solver path, updates runtime UUID, restarts
affected services and checks closure/profile identity and service health on every selected node.
`ready:false` marks prepared configuration; `ready:true` is published only after checks. Old Code
provenance is not relabelled/deleted. Only after all selected nodes verify and resume succeed does
admission open. Partial failure leaves it closed and publishes node statuses in
`/var/lib/qcl-negf/runtime/delivery-report.json`; for a known failure, fix the cause and explicitly
repeat the same idempotent command. An uncertain outcome requires trusted reconciliation first. A
repeated successful activation retains profile/Code identity and repeats checks. Application and
solver profiles are reconciled independently. An identical retry repairs a missing or wrong solver
GC root without changing the selected release, immutable solver executable or InstalledCode
identity. Healthy profiles receive no extra `nix-env --set`; each setter is followed by a resolved
closure identity check. Setter failure or a mismatched result leaves no ready record. The `check`
command rejects a missing or wrong solver profile before checking services or running the solver
self-check. Each required unit is checked separately. Activation also runs the pinned solver
`self-check` as `qcl-negf`, with one Julia/BLAS thread and a 300-second limit, before readiness.
This small analytic PV/HDF5 execution check verifies the installed runtime, not stationary
convergence or scientific acceptance. An identical retry starts any services stopped by maintenance
while retaining the selected immutable closure and Code identity. Targeted activation/check
regressions use injected stdlib command fakes for Nix, systemd and Code registration, with real
temporary profile links and runtime records. They do not establish real Nix, service or AiiDA
reconciliation behavior. After reboot, bootstrap derives solver/Code selection from the current
runtime release instead of publishing the original image's seed Code UUID again.

## Jobs and returning workers

AiiDA pins release and immutable Code for each attempt and executes before solver:

```console
/run/current-system/sw/bin/qcl-negf-release guard --release-id PINNED_RELEASE --solver-executable /nix/store/PINNED-solver/bin/qcl-negf
```

It requires shared gate open, exact pinned release/solver and local ready status; missing files,
stale jobs and stale workers fail closed. `slurmd` runs `qcl-negf-release node-check` to validate
the selected profile/closure before boot. That boot check allows a closed gate during activation;
job guard still blocks. `ReturnToService=0` forbids automatic DOWN-to-service transition. Return a
worker:

```console
sudo qcl-negf-worker-lifecycle startup --node day-worker --target deploy@day-worker --enrollment /operator-protected/enrollment.json
```

The controller drains it, rejects active jobs/unresolved shutdown snapshots, delivers and verifies
the current release, then resumes that worker. It launches no recovery attempt.

## Evidence boundary

`deno task check` runs local Deno/Python behavior tests. External Nix/SSH/systemd commands are
replaced in activation tests; JSON writes, gates and barriers are real. Merged NixOS services can be
evaluated with:

```console
nix-instantiate --store dummy:// --eval --strict --json tests/infrastructure/application-release.nix --argstr nixpkgs /absolute/pinned-nixpkgs-source
```

No server was available. Real short Slurm scientific jobs on each node, delivery, VM boot,
service/database compatibility, storage durability and backups remain `not_verified`; local health
checks are not scientific acceptance.

## Bounded delivery and uncertain outcomes

Controller delivery defaults to 1800 seconds in total, 360 seconds per native command (including a
2-second cleanup reserve), 1 MiB combined stdout/stderr per command and 8 MiB per delivery. Optional
flags are `--delivery-timeout-seconds`, `--command-timeout-seconds`, `--command-output-bytes`,
`--delivery-output-bytes`. These engineering defaults are not measured production capacity, CPU/RAM
limits or a scientific solver budget. The existing 300-second self-check is unchanged.

```console
sudo qcl-negf-release deliver --manifest release.json --pool pool-v2.json --enrollment /operator-protected/enrollment.json --delivery-timeout-seconds 1800 --command-timeout-seconds 360 --command-output-bytes 1048576 --delivery-output-bytes 8388608
```

One monotonic controller deadline covers prefetch, every node and final admission. Native commands
stream bounded output, own a local process group, and reserve finite cleanup time. SSH uses one
connection attempt, connection/keepalive bounds and no borrowed multiplex master; native Nix SSH
copies receive the same options in an isolated environment, preserving site identity and known-host
settings. These bounds do not prove that a remote mutation stopped after transport loss.

Private `runtime/delivery-attempts/<uuid>.json` receipts (0700 directory, 0600 files) retain
original manifest/source/closure identity, phase, pending command, bounded failure prefixes and
verified nodes. `delivery-report.json` remains the public latest summary; it excludes targets and
raw command output. Failure before maintenance retains the original gate; failure after closing
leaves it closed. A failed activation or incomplete check response stops dispatch to later nodes; no
RESUME or open admission follows an uncertain outcome.

Known identity/health failures may be explicitly retried after correcting their cause. A receipt
with `requires_reconciliation: true`, or an interrupted running receipt with pending mutation,
blocks subsequent delivery before any command. Trusted operator reconciliation must establish the
pending mutation's outcome and current exact identities, preserve the original receipt, and
explicitly resolve the uncertainty. CR04 supplies no force/retry/reopen bypass and performs no
automatic rollback, cancellation or remote reconciliation. Merely waiting or removing the latest
summary provides no evidence of remote completion.

Normal worker shutdown retains its unlimited outer safe-stop wait. Local child fixtures and fake
transport failures do not establish production, service, scientific or whole-cluster acceptance.
Scheduler starvation, uninterruptible kernel I/O and failed filesystem durability remain outside
hard real-time bounds; unconfirmed cleanup fails closed. Competing lifecycle entrypoints need CR02.

Before final gate opening, delivery writes a separate private durable admission intent. A failed
gate replace/fsync or terminal receipt publication attempts one close and retains this blocker for
trusted reconciliation. If closing cannot be confirmed, admission state is explicitly unknown and
critical; no closed-state claim or retry is allowed. The intent is removed only after terminal
publication succeeds, as the last fallible success action. A crash may restore that unsynced
deletion and conservatively require reconciliation. Failed storage cannot promise durable recovery
writes; the prior intent is the independent guard. Selected command flags apply to prepare-initial
and node-check as well as activate/check/deliver. Native SSH option parsing before dispatch is a
known pre-child failure, not evidence of remote mutation.

When recovery receipt writes also fail, CLI stdout carries the current safe in-memory
unknown/critical summary. Without current evidence it reports unknown; it never infers a closed gate
from an older delivery-report.json. Failure output excludes raw command output, environment and
manifest data.

## Enrolled node identity (CR03)

Delivery requires `qcl-negf-active-pool-v2` and an explicit protected
`--enrollment /operator-protected/enrollment.json`. Targets are routes, not VM identity. The
operator enrolls actual guest DMI UUID, Linux machine-id, hostname, canonical worker Slurm NodeName
and accepted SSH routes after provider/guest and host-key verification. Controller NodeName is null.
Inventory, host keys and source paths are private inputs; none are generated from pool labels or
stored in the Nix store. The following identities are synthetic examples only:

```json
{
  "schema": "qcl-negf-node-enrollment-v1",
  "inventory_id": "99999999-9999-9999-9999-999999999999",
  "known_hosts_file": "/operator-protected/known_hosts",
  "nodes": [
    {
      "enrollment_id": "10000000-0000-0000-0000-000000000001",
      "name": "controller",
      "role": "controller",
      "hostname": "controller.invalid",
      "node_name": null,
      "machine_uuid": "11111111-1111-1111-1111-111111111111",
      "machine_id": "11111111111111111111111111111111",
      "primary_target": "admin@controller.invalid",
      "targets": ["admin@controller.invalid"]
    },
    {
      "enrollment_id": "20000000-0000-0000-0000-000000000002",
      "name": "worker",
      "role": "worker",
      "hostname": "worker.invalid",
      "node_name": "worker",
      "machine_uuid": "22222222-2222-2222-2222-222222222222",
      "machine_id": "22222222222222222222222222222222",
      "targets": ["admin@worker.invalid"]
    }
  ]
}
```

```json
{
  "schema": "qcl-negf-active-pool-v2",
  "nodes": [
    {
      "name": "controller",
      "role": "controller",
      "target": "admin@controller.invalid",
      "enrollment_id": "10000000-0000-0000-0000-000000000001"
    },
    {
      "name": "worker",
      "role": "worker",
      "target": "admin@worker.invalid",
      "enrollment_id": "20000000-0000-0000-0000-000000000002"
    }
  ]
}
```

Registry and known_hosts must be bounded root-owned regular files beneath a complete root-owned
namespace with no group/other write or symlink components. User homes and /tmp are not production
trust inputs. Verified bytes are frozen in unique root0700 operations beneath
/var/lib/qcl-negf/trust-snapshots, file0600; all later SSH/Nix copies use that snapshot with strict
verification and no global known_hosts/config fallback. Source pathname substitution cannot change
the snapshot. Snapshot hashes link private receipts to bytes; they are not source revision locks.
Snapshots are conservatively retained, including unknown attempts; operator housekeeping must
preserve references until reconciliation/child cleanup. Trusted root/operator mutation and hardware
attestation are outside this contract.

Before any runtime write/flock or fleet mutation, actual local controller must match sole
enrolled/selected controller; its remote observation must match local machine and boot. After
protected enrollment and local-only binding, unresolved CR04 receipts are checked read-only before
snapshot creation/remote probing; the check repeats under lock after full authority. No enrollment
change clears old uncertainty. Every selected worker is probed before prefetch/quiesce, before copy,
and again before RESUME; remote activate binds its own machine/boot before writes. Bound check
envelopes prove node identity and exact existing ready release. Controller receives no Slurm RESUME.
All probes consume the original CR04 deadline and output budgets; they never renew them per node or
phase.

`qcl-negf-release identity` is read-only, requires no manifest, and observes local Nix-generated
role, hostname, DMI/machine/boot IDs. Worker support is intentionally limited to one static slurmd,
declared SLURM_CONF and unchanged MainPID/InvocationID, cmdline/config/environment across reads.
NodeName comes from a single explicit `NodeName=NAME` aliases response for actual hostname. Missing
DMI, ambiguous aliases, unsupported `-N`/dynamic/config override or daemon changes fail closed
without echoing caller identity. Actual pinned Slurm command/output compatibility has not been
tested; a separately budgeted site smoke gate is required before production.

Legacy pool or release-only remote check responses are rejected for fleet use. Local diagnostic
check without expected identity remains release-only. Privileged manual activate without identity
remains diagnostic and must satisfy old gate checks; it is not enrolled fleet evidence. Older
installed tooling without identity or role metadata must be upgraded through separately authorized
initial bootstrap; there is no permissive copy/install before preflight or auto enrollment fallback.
Startup uses the same authority/trust/worker binding and rejects unresolved receipts; CR02 global
lifecycle intent/owner coordination is still a separate blocker. Synthetic API tests establish none
of real inventory completeness, provider/SSH trust, service/VM health, all-worker I14 gates, or
scientific acceptance.
