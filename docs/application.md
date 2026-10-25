# Application composition

The `qcl-negf` superproject selects component revisions with Git submodules under `components/`. Its native Python workspace reads dependencies from the four package `pyproject.toml` files and records the resolved external environment in one generated `uv.lock`. Python is 3.14; the pinned Nixpkgs and the development interpreter both provide 3.14.7.

| Owner | Authoritative input |
| --- | --- |
| Superproject Git tree | Exact component source revisions |
| Python packages | Runtime dependencies, extras, test groups and build backends |
| Superproject `uv.lock` | Resolved external Python versions and artifact hashes |
| Platform `flake.lock` | Nixpkgs, uv2nix and build-system tooling |
| Portal `package-lock.json` | Browser dependency graph |
| Julia projects | Numerical dependencies and their generated manifests |

The platform does not copy Python dependency lists or internal source revisions into another manifest. Its infrastructure modules can be evaluated independently of the application source tree.

## Development and dependency updates

From the superproject root:

```console
git submodule update --init --recursive
uv sync --locked --all-packages --all-extras --group test --group build
```

Update a package's native metadata with `uv add --package PACKAGE DEPENDENCY`, or edit its `pyproject.toml`, then run `uv lock`. Upgrade external dependencies deliberately with `uv lock --upgrade` or `uv lock --upgrade-package NAME`. Run tests and commit the generated lock together with the relevant submodule updates. No internal commit hash needs to be copied into CI configuration.

The shared environment is for integration. Independently distributed packages keep ordinary versioned dependencies and can be installed from built wheels or a package index. Root CI can supply unpublished internal wheels through a wheelhouse; results does not depend on AiiDA or the portal.

## Native Nix build

The superproject flake supplies its complete source tree:

```nix
platform.lib.mkApplication {
  system = "x86_64-linux";
  workspaceRoot = self.outPath;
}
```

`mkApplication` returns a normal uv2nix virtual environment containing contracts, result tools, the AiiDA plugin and the API. uv2nix reads the native workspace and lock, builds each local Python package with the locked Hatchling backend, and installs their standard distribution metadata and entry points. The source-owned portal Nix recipe builds browser assets and includes them in the API wheel. There is no manual wheel unpacker or runtime `PYTHONPATH` assembly.

The build verifies all component versions and the AiiDA calculation, parser and workflow entry points. `lib.mkPythonEnvironment` accepts the same `system` and `workspaceRoot` arguments plus `includeTests = true` to include all development groups and extras. The production environment uses only runtime dependencies.

Use the output as `qclNegf.application.package`; enable the API separately with `qclNegf.application.api.enable = true`. Mutable AiiDA state, credentials and calculation data remain outside the immutable package. Private site configuration defines the service token and allowed Code UUIDs.

### Local profile bootstrap and TLS

Automatic bootstrap uses the Python from the declared application profile, before
`verdi run` can load a database environment. `ops/bootstrap_profile.py` validates
the standard `core.psql_dos` storage fields and supplies the supported
`engine_kwargs.connect_args` for `/run/postgresql`, database `qcl-negf`, port 5432.
The raw declared hostname stays unchanged; PostgreSQL remains peer authenticated
without TCP. The profile CLI alone cannot retain this runtime field.

For a new profile, bootstrap checks the peer identity and an empty database in a
read-only transaction, and requires an absent or completely empty repository.
Only then does it call the public storage lifecycle with `reset=False`, store
the Profile and create its default user. AiiDA can internally clear a partial
container even with `reset=False`; bootstrap therefore refuses all partial or
nonempty repositories rather than resetting or recovering them automatically.
Inspect and preserve such state separately. For a matching existing profile,
bootstrap only fills missing socket connection settings, preserving UUID,
other engine options and provenance; conflicting settings fail closed. Computer
and immutable InstalledCode registration follows the existing reconciliation.

The local Slurm Computer declares `#!/run/current-system/sw/bin/bash` for batch
scripts; the base module installs Bash on every QCL node. NixOS has no portable
`/bin/bash` contract. Reconciliation checks the saved shebang as well as transport,
scheduler and work directory, and refuses a legacy or conflicting Computer without
changing its UUID, Code or provenance. For an existing installation, preserve the
identity and history, verify the declared interpreter is executable on the worker,
then deliberately migrate the existing Computer through AiiDA
`Computer.set_shebang("#!/run/current-system/sw/bin/bash")`. This is a separate
operator action, not automatic bootstrap recovery. A local Slurm
`get_submit_script` render can check the new first line without submitting a job.

An optional common proxy replaces site-local nginx boilerplate:

```nix
qclNegf.application.api.tls = {
  enable = true;
  # Runtime files provisioned by the site's secret service, outside the store.
  certificateFile = "/run/secrets/qcl-negf-tls.crt";
  keyFile = "/run/secrets/qcl-negf-tls.key";
  serverName = "localhost";
};
```

The proxy listens only on `127.0.0.1:443` (TLS port is configurable), uses
`onlySSL = true`, and forwards to the existing loopback API port. systemd
`LoadCredential` supplies readable private copies to nginx after the declared
`qclNegf.runtimeSecretUnits`. The private site supplies certificate identity,
keys and any external access tunnel. Remove a site's duplicate API virtual host
when enabling this option. TLS is opt-in; existing sites remain unchanged.

## Wheels and delivery

After one-time image preparation, [application CD](application-cd.md) updates the
stable profile/runtime configuration without rebuilding the OS and preserves
immutable solver Code identities. Routine delivery uses the existing umbrella
GitHub Actions workflow.

Build the browser before distributable Python wheels:

```console
npm --prefix components/qcl-negf-portal/frontend ci
npm --prefix components/qcl-negf-portal/frontend run build
uv build --all-packages --no-build-isolation --no-sources
nix build .#application
```

The `build` dependency group supplies build backends from the shared lock for the Python build command. Nix builds use the same root workspace plus pinned Nix build tooling. Keep generated wheels and Nix closures in CI artifact storage or the binary cache, outside source history.

Julia is a separate numerical environment owned by `QCLNEGF.jl` and its runtime adapter, `QCLNEGFRunner.jl`. Changing API or result-view code does not require rebuilding the Julia dependency environment. Install the same solver closure on submission and execution nodes.

## Optional bounded configuration preview

The existing API unit can opt into the Runner `configure` catalog/preview command.
It is disabled by default. No scheduler, planner service or sudo grant is added.
Runner owns parsing and scientific resolution; preview does not submit a run or
establish convergence or scientific acceptance.

`mkApplication` exposes `configuratorCatalogRoot` in package passthru. It is the
exact immutable `${workspaceRoot}/components/qcl-negf-research` tree and retains
its catalog and referenced sources in the application closure. The existing Git
source graph remains authoritative; this is not a second revision lock. The
trusted release caller must take the exact Research source identity from that
same graph and select the matching application and solver closures. A package
path by itself does not independently prove the Research commit or installed
Runner identity. Leave enable false when that correspondence is not established.

The private site can then set:

```nix
qclNegf.application.api.configurator = {
  enable = true;
  # Supply this value from the selected release's existing Git graph.
  catalogSourceId = selectedResearchSourceId;
};
```

`catalogRoot` defaults from the selected application's passthru; an explicit root
must match it exactly and be in `/nix/store/`. Source ID is required, finite and
never inferred from a version, PATH, root HEAD or `latest`. Opt-in also requires
an enabled API, the selected `qclNegf.cluster.solverPackage` and systemd >=254.
The executable is fixed to that solver package's `/bin/qcl-negf`; there is no
arbitrary executable option. A missing package passthru, source identity or
mismatched catalog root fails module assertions. The prepared Runner wrapper and
its immutable offline depot remain unchanged.

The same `qcl-negf-api.service` gains `Delegate=cpu memory pids`,
`DelegateSubgroup=api` and `KillMode=control-group`. Its existing non-root user,
NoNewPrivileges, ProtectSystem, writable data paths, authentication and nginx
configuration stay in force. The cgroup root is derived from the unit's actual
Slice (including ordinary nested slice names), with the API in its `api`
subgroup and a separate per-request leaf under the empty delegated parent.
The adapter requires runtime unified v2/controllers/permissions, performs cap
readback and owns child cleanup; Nix wiring alone cannot advertise readiness.
A read-only or mismatched cgroup stays unavailable without remounting `/sys`.

Four fixed unit variables bind the adapter:
`QCL_NEGF_CONFIGURATOR_EXECUTABLE`, `QCL_NEGF_CONFIGURATOR_CATALOG_ROOT`,
`QCL_NEGF_CONFIGURATOR_CATALOG_SOURCE_ID`, and
`QCL_NEGF_CONFIGURATOR_CGROUP_ROOT`. The API launch script first clears inherited
values, including values in an old runtime `service.env`. It exports the selected
binding only if the current stable application profile resolves to the configured
application package, runtime `QCL_NEGF_SOLVER_EXECUTABLE` matches the selected
solver, the executable exists and the catalog asset is readable. Missing or
foreign CD bindings leave all four unset and still start the API: existing read
routes remain usable while `/config.configurator` reports unavailable. Normal
CD does not silently enable a new configurator binding from an old OS unit;
coordinate an explicit reviewed unit binding update when adopting a new pair.

Before enabling on a real installation, retain the exact release graph and
application/solver closures, perform the separately budgeted module evaluation
and runtime delegated-v2/Runner readiness checks, and confirm the API advertises
the intended source identity. No live activation, hard child network isolation
or scientific acceptance follows from these source controls. The source-owned
one-shot Runner contract uses fixed no-URI/offline inputs, not a network sandbox.

## Optional retained NFS saved-results mapping (L1)

`qclNegf.application.api.savedResults.enable` defaults to false. L1 exposes
registered closed results from the existing `qclNegf.cluster.jobDirectory` NFS
mount to the existing API unit at `/run/qcl-negf-saved`. There is no arbitrary
request path/root option. The producer's hard NFSv4 mount and daemon write
access stay unchanged. The API gains `RequiresMountsFor` for that mount and the
site identity file, `BindReadOnlyPaths` for the alias, and `ReadOnlyPaths` for
the original path and identity file. Its writable state paths remain unchanged.
A missing required source is not an optional bind; do not prefix it with `-`.

Enable only after private site admission supplies all of these options:

- `namespaceId`: 1–128 characters, alphanumeric first, then alphanumeric,
  dot, underscore or hyphen. Never reuse an admitted namespace for a different
  disk/export identity.
- `storageIdentity`: measured disk/export binding identity; `storageIdentityFile`:
  canonical absolute runtime path outside the store to its root-owned readable
  witness file. No symlink ancestors or group/other write permission; at most
  257 bytes containing the exact identity, optionally a trailing newline.
- `allowedComputerUuids`: 1–64 distinct canonical lowercase AiiDA Computer UUIDs.
- `retentionPolicyId`, `retentionOwnerId`, `holdRef`, `accessBindingRef`: explicit
  site policy, named owner and evidence references. These and storage identity
  are nonempty finite identifiers, at most 256 characters; no defaults invent
  admission or a retention owner. They must not contain secrets.

The site witness is an admitted statement maintained by the storage owner,
not discovery or cryptographic proof of the backing disk. Before enabling,
measure actual NFS export/source and disk identity and bind the witness to that
receipt. Replacing a disk behind the same server/export requires a new identity
and reviewed binding. Neither an equal hostname nor the witness alone proves
that the actual backing disk is still the admitted one.

The generated store JSON is named by `QCL_NEGF_SAVED_RESULTS_BINDING_FILE`.
Its exact fields are `namespace_id`, `storage_identity`, `root` (always
`/run/qcl-negf-saved`), `allowed_computer_uuids`, `retention_policy_id`,
`retention_owner_id`, `hold_ref`, and `access_binding_ref`. References are private
site metadata; this file is not a browser DTO. The wrapper clears any inherited
binding file setting, including a stale `service.env`, and exports the generated
path only when the current application profile matches the declared package,
both original root and alias are exact NFSv4 mounts with the declared source,
the alias is read-only and readable/searchable, and the site witness matches.
Missing mounts, local directories, symlinked roots, foreign exports, wrong
identity or a foreign application leave the provider binding unset. There is
no `mkdir`, empty local root or repository fallback for a registered NFS source.
The API can still serve its other routes when its wrapper withholds the binding;
a missing mandatory bind/mount may prevent the unit from starting at all.

Consumers must explicitly match each source's `namespace_id` and
`storage_identity` to this mapping and its singular AiiDA `computer_uuid` to one
member of `allowed_computer_uuids`. The Platform mapping supplies no CalcJob,
result path, `remote_root`, `registration_source_id` or per-child `admissions`.
AiiDA must obtain those through its exact owner graph and independently admitted
closed attempt. A global `hold_ref` does not prove scheduler stop, absence of
writers/pruning, exact point/commit identity or a hold for any particular root.
Do not synthesize per-child admission from this global file.

Retention policy is indefinite for closed registered roots until a separate
explicit disposition by the named owner. The hold covers negative results,
metadata and the complete declared dependency closure, including borrowed
checkpoint/import source roots. The owner must confirm no automatic cleanup,
AiiDA remote-clean operation, workdir cleanup or export TTL applies to held
roots. Live recovery pruning remains writer-owned before registration. No new
service, timer, TTL, migration, hardlink, deduplication or cleanup is installed.
This operational policy does not promise protection from every administrator.
Backup/restore and capacity accounting remain separate gates; historical
repository mirrors, retry imports, scratch and backups are counted separately.

Before native use, verify actual numeric service UID/GID, directory ancestry,
ACLs and file modes against Runner directory02750/file0640 and jobs0750;
matching usernames and `root_squash` are insufficient. Do not grant world read
or producer-wide read-only remounts. Readable root metadata does not prove access
to every registered payload. Actual storage/export identity, per-attempt hold,
closed ownership, package binding, read access and finite child-resource checks
remain private native acceptance evidence. This source wiring does not prove
L2 delivery without repository mirrors, R04 completion, backup or scientific
acceptance. Active scientific jobs must not be used as access fixtures.

The authored offline controls are `tests/infrastructure/application-saved-results.nix`
and `tests/test_application_saved_results.py`. The former directly imports only
the owning application module with synthetic package/file constructors; it does
not evaluate many NixOS configurations. A separately dispatched focused packet
can run only this Python file in the existing locked environment with
`QCL_TEST_NIXPKGS` set to the selected source. Its module-scoped fixture performs
one strict source-specific evaluation with a 60-second timeout; wrapper cases
use tiny stand-ins for mount facts and do not prove native NFS behavior. Keep the
shared finite budget (2 CPU, 1 GiB, 10 min, 128 MiB tmp, 32 MiB output); do not
include the multi-configuration `application-release.nix` evaluation under this
memory bound. Exceeding a bound is a failed/pending gate, not permission for an
automatic rerun or larger budget.
