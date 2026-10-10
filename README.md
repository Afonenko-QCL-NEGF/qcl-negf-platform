# QCL-NEGF platform

NixOS modules, VM definitions and typed deployment commands for a scientific Slurm cluster. The
[qcl-negf superproject](https://github.com/Afonenko-QCL-NEGF/qcl-negf) selects eight component revisions
with Git submodules and runs integration CI on one self-hosted GitHub Actions runner. This
repository owns infrastructure and deployment; AiiDA owns workflow provenance and Slurm assigns
compute resources.

## Infrastructure

| VM          | Responsibility                                  | Persistent data                                   |
| ----------- | ----------------------------------------------- | ------------------------------------------------- |
| Storage     | NFSv4 job storage on the primary Proxmox server | Separate scientific data disk                     |
| Control     | AiiDA, PostgreSQL, API and Slurm controller     | Separate application and scheduler state disk     |
| Compute     | Slurm worker on Proxmox                         | Local scratch; delivered results go to NFS        |
| CI          | Root-repository GitHub runner and build cache   | Build artifacts, isolated from scientific storage |
| Arch worker | NixOS guest on the existing Arch/libvirt host   | Separate local scratch disk                       |

The 1 Gb LAN carries submission files and delivered results. Iterative solver I/O stays on worker
scratch. The controller and workers mount `/srv/qcl-negf/jobs` from the dedicated storage VM;
workers run calculations under `/scratch/qcl-negf`. Storage and control remain single points of
availability. See [infrastructure](docs/infrastructure.md) for resource budgets, OpenTofu image
provisioning, disk protection and recovery boundaries.

| Module                | Responsibility                                                                  |
| --------------------- | ------------------------------------------------------------------------------- |
| `qclNegf.cluster`     | Slurm controller/workers, cgroup CPU/RAM limits and shared job mounts           |
| `qclNegf.storage`     | Dedicated NFS server and client allowlist                                       |
| `qclNegf.stateDisk`   | Persistent controller application and scheduler state                           |
| `qclNegf.application` | AiiDA, PostgreSQL and optional authenticated HTTP API                           |
| `qclNegf.builder`     | Shared daemon/admin/jobs slice and standard/burst resource profiles             |
| `qclNegf.runner`      | Isolated persistent root-repository runner with controller-issued registration |
| `qclNegf.cache`       | Signed, read-only Nix binary cache endpoint                                     |
| `qclNegf.stateArchive` | Manual coordinated controller archive, verification and empty-state restore |
| `ops/`                | TypeScript commands for build, activation, clean installation and profile setup |

## Development and validation

From the superproject root:

```sh
git submodule update --init --recursive
deno task prepare
deno task check
deno task test
nix build --no-link --no-update-lock-file .#application
```

The native root `uv.lock` resolves Python dependencies for Python 3.14.7, including AiiDA 2.9.2.
Each Python package owns its dependency declarations. The root Git tree records component source
revisions; no separate source lock is maintained here. Nix inputs are pinned by `flake.lock`. See
[application composition](docs/application.md) for the root workspace and Nix environment.

For platform-only checks, from this repository:

```sh
nix develop --no-update-lock-file --command deno task check
nix build --no-link --no-update-lock-file .#checks.x86_64-linux.slurm-vm
```

The shared operations/devShell environment declares Python 3.14 and ansible-core 2.21.1,
with community.general 13.4.0 and community.library_inventory_filtering_v1 1.1.5 from
fixed upstream archives. Versions are checked against [Ansible requirements](ansible/requirements.yml).
The storage, cutover and swap fixtures require this environment and verify the actual
interpreter, engine files and collection resolver origins before running YAML; missing or
foreign dependencies fail setup. Collection unpacking belongs to the Nix dependency derivation.
These recording fixtures do not establish native host enforcement, boot or scientific acceptance.

The Slurm test boots storage, controller and worker VMs, submits a batch job, checks shared output
ownership and verifies result persistence across controller restart. It needs a Linux builder with
KVM or supported QEMU emulation. Expression evaluation does not establish that a VM boots. Provider
and image checks are described in [infrastructure](docs/infrastructure.md).

## Deployment

For the first CI/build host, use the [platform-only bootstrap](docs/bootstrap.md)
from official installation media. It has no application, solver or Julia-depot
dependency. [The host policy](docs/host-network.md) declaratively creates the
isolated guest bridges while retaining the existing management bridge.

Create a private site flake from `examples/private-site/`, set measured resources, hardware, network
and runtime secrets, and attach the root application's and solver's immutable packages. Copy
`examples/inventory.json` into that private site and replace its flake references and SSH targets.
Set each flake reference to the private site, for example `/absolute/private-site`; `.` resolves
relative to the working directory where the command runs.

Run deployment commands from this repository with an absolute private inventory path:

```sh
deno task ops build /absolute/private-site/inventory.json control
deno task ops build /absolute/private-site/inventory.json control --apply
deno task ops test /absolute/private-site/inventory.json control --apply
deno task ops switch /absolute/private-site/inventory.json control --apply
```

Commands print a plan by default. `--apply` executes upstream tools with argument arrays. `test`
activates a configuration without selecting it for the next boot; `switch` also selects it as the
boot default. `nixos-rebuild` copies store closures and performs remote activation. Application data
migrations are separate maintenance operations.

For a clean installation, boot installation media and prepare a replacement root filesystem,
preserving the protected scientific data or state disk:

```sh
deno task ops install /absolute/private-site/inventory.json compute --root /mnt --apply
```

The command requires a mounted destination other than the running root. It does not partition disks
or set a root password. Provision SSH access in the site configuration. See
[operations](docs/operations.md) for AiiDA setup, delivery and recovery.

## Repository boundaries

Numerical algorithms belong to [QCLNEGF.jl](https://github.com/Afonenko-QCL-NEGF/QCLNEGF.jl); frozen-plan
execution and scratch staging belong to
[QCLNEGFRunner.jl](https://github.com/Afonenko-QCL-NEGF/QCLNEGFRunner.jl). Shared formats belong to
[qcl-negf-contracts](https://github.com/Afonenko-QCL-NEGF/qcl-negf-contracts), result tools to
[qcl-negf-results](https://github.com/Afonenko-QCL-NEGF/qcl-negf-results), workflows to
[qcl-negf-aiida](https://github.com/Afonenko-QCL-NEGF/qcl-negf-aiida), the API/UI to
[qcl-negf-portal](https://github.com/Afonenko-QCL-NEGF/qcl-negf-portal), and reference studies to
[qcl-negf-research](https://github.com/Afonenko-QCL-NEGF/qcl-negf-research).

MIT license. See [CONTRIBUTING.md](CONTRIBUTING.md) for validation expectations.
