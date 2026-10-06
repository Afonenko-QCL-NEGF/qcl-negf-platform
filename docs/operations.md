# Operating the cluster

## Identity, networks and storage

Use a private network between storage, controller and workers. Resolve their short hostnames
consistently and set each role's private interface accordingly. Slurm and NFS ports belong on that
network. Scientific nodes share the `qclNegf.uid` identity, default 3000; reserve it before
installation and verify shared file ownership. CI has a separate subnet and no scientific mounts.

`srun` also needs incoming worker callbacks for launch and I/O, beyond the daemon
ports 6817/6818. `qclNegf.cluster.srunPortRange` defaults to
`{ from = 60001; to = 60128; }`, emitted into Slurm configuration and opened only
on `qclNegf.privateInterface` for active cluster roles. Use the same range on
controller, submit hosts and workers; a worker may start `srun` inside a batch
allocation. Keep at least five ports and size for concurrent steps: up to 48
hosts use four listeners per `srun`, plus one for `--pty`.
See the [Slurm network guide](https://slurm.schedmd.com/network.html) and
[SrunPortRange](https://slurm.schedmd.com/slurm.conf.html#OPT_SrunPortRange).
An `sbatch` script that invokes one executable directly does not exercise this
callback path. Check an owned bounded `srun hostname` separately after activating
the matching role configurations; successful batch jobs do not prove it.

Provision one random Munge key to `qclNegf.cluster.mungeKeyFile` on the controller and workers,
owned by `munge:munge`, mode 0400. Use a runtime string path such as `/run/secrets/munge.key`; a Nix
path literal copies the secret into the store. The site's secret manager must restore persistent
keys before `munged` starts.

The storage VM exports `/srv/qcl-negf/jobs` from its separate data disk to explicit NFS clients. The
controller and workers mount that same path. Submission scripts and frozen plans are therefore
visible at identical paths. The controller's separate state disk holds PostgreSQL, the AiiDA
profile/file repository and Slurm controller state. Missing data mounts must prevent service
startup; they must never be replaced by empty directories on a root disk.

Workers calculate on local `/scratch/qcl-negf`. Configure the trusted application scratch setting to
pass that root through AiiDA to QCLNEGFRunner.jl. Each execution gets a fresh local workspace. The
runner verifies and copies its result tree to temporary storage beside the shared destination, then
publishes the directory by rename. This keeps iterative I/O off the 1 Gb NFS link. Successful
delivery removes the local workspace; execution exceptions or failed staging retain it for
inspection. Incomplete work is not automatically resumed. A killed process may leave local work or
temporary shared files, and a lost worker disk loses work not yet delivered. See
[infrastructure](infrastructure.md) for disk provisioning and replacement rules.

## Create the AiiDA profile

Enable `qclNegf.application` with the root's concrete application package and
`application.bootstrap.enable = true`. Supply the private site's service email,
stable Code label and `cluster.solverPackage`. The bootstrap oneshot waits for
PostgreSQL and the persistent profile mount, reconciles the local Slurm Computer
and immutable installed Code, and publishes `aiida/bootstrap.json` plus
`aiida/code-uuid`. Daemon/API startup requires this completed service. The API's
runtime UUID allowlist reads that file, so a first installation does not need
a guessed UUID in Nix configuration. With this installation's
`AIIDA_PATH=/var/lib/qcl-negf/aiida`, AiiDA stores its configuration in
`aiida/.aiida/config.json`. Bootstrap and service startup read that nested file;
the published identity files and repository remain directly under `aiida/`.

For manual provisioning, run the same operations from this repository as the
`qcl-negf` Unix account with `verdi` and the immutable solver on PATH:

```sh
deno task bootstrap research@example.org /nix/store/SOLVER/bin/qcl-negf --label qcl-negf-v1
deno task bootstrap research@example.org /nix/store/SOLVER/bin/qcl-negf --label qcl-negf-v1 --apply
```

Use the service address appropriate for your installation. The command creates a PostgreSQL profile
using local socket peer authentication and AiiDA's ZeroMQ broker for the single-controller daemon.
It registers a local Slurm Computer and `core.code.installed` Code with
`qcl_negf.execution` and `with_mpi=False`. Retrying after a partial setup retains
stored UUIDs and completes missing authentication/readiness. An existing profile,
Computer or Code with different storage/transport/solver settings fails instead
of being replaced. Use a new Code label for a new immutable solver path. Services wait
until the profile configuration exists. Restart `qcl-negf-aiida` after manual provisioning, then check
`AIIDA_PATH=/var/lib/qcl-negf/aiida verdi -p qcl-negf status` as the service account.

Retain the same solver store path on the controller and every worker. Automatic
bootstrap uses `application.api.allowedCodesFile`; with manual provisioning set
that runtime file or record the published Code UUID in `api.allowedCodes`.
HTTP submissions select only configured Codes.
The API binds to loopback. Use a TLS reverse proxy or an SSH tunnel, and provide its configured
authentication token.

Declare `qclNegf.runtimeSecretUnits` for the private site's secret provisioner.
The private-site example's `site.modules` can import its NixOS secret-service
declarations without modifying the public host definitions.
Munge, API, cache signing and runner registration wait for those units rather
than racing files under `/run/secrets`. Declare only the units needed on each
role: CI receives its own registration secret and no scientific credentials.
Set `api.exportDiskBytes` and `api.exportTtlSeconds` from the controller's
measured free temporary disk and retention policy. A capacity setting does not
reserve physical disk space.

Each calculation uses one process on one node. Slurm assigns its CPUs and RAM; numerical threads
stay within that allocation. Independent executions scale across workers through AiiDA. The solver
owns convergence, and AiiDA parses scientific completion separately from the operating-system exit
code. Use the parsed result status when accepting a calculation.

## Source, CI and delivery

GitHub stores source, pull requests, workflow definitions and logs. The single runner is registered
to `Afonenko-QCL-NEGF/qcl-negf`, whose committed gitlinks select all eight components. The runner connects
outbound to GitHub; no inbound webhook service is needed. Component repositories do not have
separate integration runners or source-revision manifests.

From a clean root checkout:

```sh
git submodule update --init --recursive
deno task graph
deno task prepare
deno task check
deno task test
deno task release /absolute/artifacts --build
```

The root native `uv.lock` selects Python 3.14.7 dependencies. Julia projects and their manifests
select numerical dependencies; `deno task solver:depot` prepares their depot artifact. Browser
dependencies use the portal's `package-lock.json`. Nix inputs use their generated flake locks. The
root release command retains four Python wheels, their hashes and a source-graph record. Its
optional build produces the Nix application. Julia packages and VM images are separate outputs;
follow [application composition](application.md) and [infrastructure](infrastructure.md) to build
and deploy the complete site.

Keep the repository-management PAT on the administrative controller. Request a short-lived
repository registration token there, then provision only that token at
`qclNegf.runner.tokenDirectory/qcl-negf`, outside Git, Nix inputs and OpenTofu state. The file must
contain the token without a trailing newline and be readable only by root. A site runtime secret
unit should validate its owner/mode and reject access-token prefixes before starting the runner.
Registration is persistent (`ephemeral=false`): an unchanged configuration/token preserves the
registered credentials across service restarts. Changing registration settings or token contents,
or clearing runner state, requires a fresh token; a one-hour registration token cannot renew itself.
Use the [controller registration command](github-registration.md); it prints only path/expiry
metadata and never publishes a PAT to the guest.

Jobs run as `github-runner-qcl-negf`, with a private group and no wheel, Nix trusted-user or
administrative `qcl-negf-build` membership. Their writable release directory is
`/var/lib/qcl-negf-ci/releases`; administrative releases/artifacts and private vaults are inaccessible
to the job service. Keep the administrative builder account separate in the private site.

Enabling the runner enables the dedicated builder module by default. Select
`qclNegf.builder.profile="standard"` (4 vCPU/8 GiB) or the admitted `"burst"` profile (12 vCPU/24 GiB).
The Nix daemon, administrative build parents and runner jobs share `qcl-build.slice`, one parallel
Nix build, and the profile's aggregate CPU/memory/swap limits. Former runner options `cpuQuota`,
`memoryMax`, `maxJobs` and `buildCores` are removed; use the owning builder profile. A NixOS profile
selection alone does not resize the VM or establish host admission. Follow the finite deadline and
host/compute checks in [bootstrap](bootstrap.md) before a reviewed resource transition.

Focused evaluation covers runner+builder together under both profiles, including account isolation:

```sh
nix-instantiate --store dummy:// --eval --strict --json tests/infrastructure/runner-isolation.nix --argstr nixpkgs /absolute/pinned-nixpkgs-source
```

This evaluates the merged NixOS configuration; real registration, service restart, runtime group
membership and a bounded GitHub smoke job remain deployment acceptance checks.

The CI role provides `nix-ld` and an explicit library environment for upstream Julia and Python
binary dependencies. These settings are confined to CI; scientific nodes use their built solver and
application closures. The persistent Nix store reuses dependencies across jobs. The signed binary
cache distributes reviewed build artifacts, while scientific data stays on its storage system. Keep
the signing key outside job credentials and configure clients with the public key.

Use `ops build`, `ops test` and `ops switch` with the private site's inventory for OS deployment.
Commands print their argument vectors unless `--apply` is given. The root repository's CI does not
automatically change running scientific machines.

## Replacement and recovery

Routine application updates follow [application CD and admission](application-cd.md).
The [Windows lifecycle adapter](windows-workers.md) uses the same Linux worker
role, release gate and permanent-node Runner verification. Optional
[monitoring](monitoring.md) is best effort; it never replaces checkpoint proof.

Prefer a clean OS installation from the pinned private site configuration when replacing a machine.
Storage and control VM identities/data disks are protected against automatic replacement. Prepare
only a replacement root filesystem and keep the state/data disk attached, or restore it onto a
separately reviewed replacement VM. Follow the protected-disk procedure in
[infrastructure](infrastructure.md); do not remove protection to accept an unexpected replacement.

Before replacing the controller, stop submissions, finish or explicitly preserve running work, stop
the AiiDA daemon/API, and take a coordinated PostgreSQL dump plus the AiiDA file repository and
profile configuration. Preserve required SSH/Munge keys and Slurm controller state. Back up the NFS
dataset separately. Restart only one authoritative controller against the restored data. Copy any
needed incomplete scratch work before replacing a worker; it is not a durable shared checkpoint
service.

For the implemented manual local archive and empty-state restore procedure,
enable `qclNegf.stateArchive` and follow [the state archive contract](state-archive.md).
Local staging counts as an independent backup only after the archive and its
hash have been copied to an external medium and verified there. The NFS data
requires its own external copy and manifest.

Test restoration onto a separate VM with writes paused before relying on backups. PostgreSQL major
version changes and AiiDA storage migrations require their own maintenance procedure. Rolling back a
NixOS generation does not roll back database contents.

The configuration does not include SlurmDBD or high availability. AiiDA retains workflow provenance,
while Slurm's live queue and controller state serve scheduling. Add SlurmDBD with its supported SQL
backend when fair-share accounting or durable scheduler history requires it; it does not use AiiDA's
PostgreSQL database.

## References

- [NixOS modules and options](https://nixos.org/manual/nixos/stable/)
- [Nix binary cache](https://nix.dev/tutorials/nixos/binary-cache-setup.html)
- [AiiDA installation and profiles](https://aiida.readthedocs.io/projects/aiida-core/en/stable/installation/guide_complete.html)
- [Slurm cgroup v2](https://slurm.schedmd.com/cgroup_v2.html)
- [GitHub self-hosted runners](https://docs.github.com/en/actions/concepts/runners/self-hosted-runners)
