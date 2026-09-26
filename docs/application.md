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

## Wheels and delivery

Build the browser before distributable Python wheels:

```console
npm --prefix components/qcl-negf-portal/frontend ci
npm --prefix components/qcl-negf-portal/frontend run build
uv build --all-packages --no-build-isolation --no-sources
nix build .#application
```

The `build` dependency group supplies build backends from the shared lock for the Python build command. Nix builds use the same root workspace plus pinned Nix build tooling. Keep generated wheels and Nix closures in CI artifact storage or the binary cache, outside source history.

Julia is a separate numerical environment owned by `QCLNEGF.jl` and its runtime adapter, `QCLNEGFRunner.jl`. Changing API or result-view code does not require rebuilding the Julia dependency environment. Install the same solver closure on submission and execution nodes.
