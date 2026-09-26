# Contributing

Develop this component through the [qcl-negf superproject](https://github.com/AfonenkoA/qcl-negf).
Its Git tree selects every component revision, and its native package-manager locks select external
dependencies. Commit a component change first, then update its gitlink in the root repository. Root
CI tests the complete selected graph using Python 3.14.7 and the project's Julia environment.

Run `nix develop --command deno task check` in this repository for operational changes. When
changing NixOS modules, evaluate the private site's five host configurations and run the relevant
Nix checks. Run `nix build --no-link --no-update-lock-file .#checks.x86_64-linux.slurm-vm` for
Slurm, NFS, identity, scratch or cgroup changes, and retain its logs with the reviewed change.
Follow the provider/image checks in [infrastructure](docs/infrastructure.md) when changing VM
provisioning.

Keep numerical validation in QCLNEGF.jl, QCLNEGFRunner.jl and the research project. A Slurm smoke
job checks scheduling and storage; scientific acceptance uses the solver's parsed result status.

Update generated locks deliberately through their owning package managers, and review dependency
changes. Python metadata and `uv.lock` belong to the native root workspace; this repository's
`flake.lock` owns the Nix build tooling. Do not maintain a second list of internal commit hashes.
Never commit runtime tokens, Munge keys, private SSH keys, generated AiiDA profiles or site
credentials. Document implemented behavior and remove unreachable APIs and commands.

Integration workflows live in the root repository and run on the dedicated CI VM. Public pull
requests must be reviewed before their code runs on trusted infrastructure. Protect the root's
`main` branch and restrict workflow dispatch. Runner registration is ephemeral, but the VM and its
Nix store persist; registration alone does not reset an execution environment. Keep CI isolated from
production and reset its VM after untrusted execution.
