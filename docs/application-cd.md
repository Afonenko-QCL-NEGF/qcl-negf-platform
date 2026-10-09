# Application CD and closed admission

The existing umbrella GitHub Actions workflow owns build/test/publish/deliver/check.
This component adds no second CI, deploy daemon, discovery or revision lock catalog.
The initial deployment is CPU-only and selects one release for the active pool.

## One-time image preparation

Pass the same `qclNegf.release.applicationPackage` and immutable
`qclNegf.cluster.solverPackage` to controller and Linux workers; the private-site
example does this. The image installs release/lifecycle commands, profile
initialization and a slurmd boot gate. API/AiiDA/bootstrap run from the stable
`/nix/var/nix/profiles/qcl-negf-application`; initialization sets it only when
absent, so reboot retains the CD-selected release. Services read runtime
`/var/lib/qcl-negf/runtime/service.env`. The solver profile is a GC root only;
InstalledCode always uses immutable `/nix/store/.../bin/qcl-negf`.

OS changes require the deployment procedure again. Database schema changes are
explicit maintenance with backup. Routine activation runs neither migrations
nor `nixos-rebuild`.

## Inputs and delivery

Derive release identity from the existing umbrella graph/artifact hashes and keep
that provenance with the release. JSON manifest:

```json
{"schema":"qcl-negf-release-v1","release_id":"example-release",
"application_path":"/nix/store/EXAMPLE-application",
"solver_executable":"/nix/store/EXAMPLE-solver/bin/qcl-negf",
"closures":[{"path":"/nix/store/EXAMPLE-application","narHash":"sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
{"path":"/nix/store/EXAMPLE-solver","narHash":"sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}],
"cache_uri":"https://cache.example.invalid"}
```

The paths and hashes above are placeholders. The umbrella assembler supplies the
actual application and solver `narHash` evidence. `cache_uri` is an optional
delivery route and does not change release identity. It must be a nonempty string
without whitespace, control characters, a leading dash or an embedded password.
Keep credentials outside the URI and manifest. Nix retains its normal signature
and trust checks; this procedure does not disable `require-sigs`.

An explicit private pool is separate from the manual credentials inventory;
offline daytime workers are omitted:

```json
{"nodes":[{"name":"control","target":"deploy@control","role":"controller"},
{"name":"compute","target":"deploy@compute","role":"worker"}]}
```

Build/test/publish closures through the existing workflow. Its protected delivery
job/environment receives reviewed limited SSH deployment access; build jobs do
not receive production credentials or become unrestricted administrators.
In the user's maintenance window run on the permanent controller:

```console
sudo qcl-negf-release deliver --manifest /private/release.json --pool /private/active-pool.json
```

For an SSH pipeline, `--manifest /dev/stdin` accepts the manifest without copying
the controller's private pool to CI. SSH keys/cache signing keys remain outside
Git, Nix inputs and scientific archives.

Before maintenance, the controller fetches both named closures with
`nix copy --from CACHE_URI APPLICATION SOLVER` and verifies their exact manifest
hashes using local `nix path-info --json APPLICATION SOLVER`. Fetch failure,
malformed or missing evidence, and either hash mismatch stop delivery before any
gate change, service stop, worker drain or remote command. An older assembled
manifest without `cache_uri` remains supported when both closures already exist
in the controller store and match its declared hashes. Delivery cannot accept a
manifest without both hashes; minimal four-field manifests remain valid for
activation and runtime identity checks.

After this preflight, delivery closes `/srv/qcl-negf/jobs/.release-admission.json`, stops API/AiiDA,
drains selected workers and rejects a nonempty Slurm queue. The maintenance owner
first completes/cancels the old research and removes its automatic resume/queued
attempts. The command never cancels or restarts research on the user's behalf.
`JobRequeue=0` and AiiDA's `--no-requeue` prevent a second independent owner.
The shared NFS gate is published as the scientific UID because the export retains
`root_squash`; local runtime state remains administrative. Scientific submitters
require access to the shared job group, whose UID/GID mapping is a site check.

`nix copy` delivers application+solver closures; activation switches the profile,
reconciles a new release-specific InstalledCode label with the exact solver path,
updates runtime UUID, restarts affected services and checks closure/profile
identity and service health on every selected node. `ready:false` marks prepared
configuration; `ready:true` is published only after checks. Old Code provenance
is not relabelled/deleted. Only after all selected nodes verify and resume succeed
does admission open. Partial failure leaves it closed and publishes node statuses
in `/var/lib/qcl-negf/runtime/delivery-report.json`; fix the cause and repeat the
same idempotent command. A repeated successful activation retains profile/Code
identity and repeats checks.
Application and solver profiles are reconciled independently. An identical retry
repairs a missing or wrong solver GC root without changing the selected release,
immutable solver executable or InstalledCode identity. Healthy profiles receive no
extra `nix-env --set`; each setter is followed by a resolved closure identity check.
Setter failure or a mismatched result leaves no ready record. The `check` command
rejects a missing or wrong solver profile before checking services or running the
solver self-check.
Each required unit is checked separately. Activation also runs the pinned
solver `self-check` as `qcl-negf`, with one Julia/BLAS thread and a 300-second
limit, before readiness. This small analytic PV/HDF5 execution check verifies
the installed runtime, not stationary convergence or scientific acceptance.
An identical retry starts any services stopped by maintenance while retaining
the selected immutable closure and Code identity.
Targeted activation/check regressions use injected stdlib command fakes for Nix,
systemd and Code registration, with real temporary profile links and runtime
records. They do not establish real Nix, service or AiiDA reconciliation behavior.
After reboot, bootstrap derives solver/Code selection from the current runtime
release instead of publishing the original image's seed Code UUID again.

## Jobs and returning workers

AiiDA pins release and immutable Code for each attempt and executes before solver:

```console
/run/current-system/sw/bin/qcl-negf-release guard --release-id PINNED_RELEASE --solver-executable /nix/store/PINNED-solver/bin/qcl-negf
```

It requires shared gate open, exact pinned release/solver and local ready status;
missing files, stale jobs and stale workers fail closed. `slurmd` runs
`qcl-negf-release node-check` to validate the selected profile/closure before boot.
That boot check allows a closed gate during activation; job guard still blocks.
`ReturnToService=0` forbids automatic DOWN-to-service transition. Return a worker:

```console
sudo qcl-negf-worker-lifecycle startup --node day-worker --target deploy@day-worker
```

The controller drains it, rejects active jobs/unresolved shutdown snapshots,
delivers and verifies the current release, then resumes that worker. It launches
no recovery attempt.

## Evidence boundary

`deno task check` runs local Deno/Python behavior tests. External Nix/SSH/systemd
commands are replaced in activation tests; JSON writes, gates and barriers are
real. Merged NixOS services can be evaluated with:

```console
nix-instantiate --store dummy:// --eval --strict --json tests/infrastructure/application-release.nix --argstr nixpkgs /absolute/pinned-nixpkgs-source
```

No server was available. Real short Slurm scientific jobs on each node, delivery,
VM boot, service/database compatibility, storage durability and backups remain
`not_verified`; local health checks are not scientific acceptance.
