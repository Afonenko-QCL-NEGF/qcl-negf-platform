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
