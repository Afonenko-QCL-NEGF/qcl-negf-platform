# Bootstrap without a scientific build cycle

The initial builder needs only the platform and its Nixpkgs lock. It does not
import the root application, Julia solver or `solver-depot.json`. Copy
`examples/bootstrap-site/flake.nix.template` to `flake.nix` and
`site.nix.example` to `site.nix` in a private bootstrap repository. Replace the
network and SSH public key, pin the reviewed platform revision with `flake.lock`,
and keep the real inventory private. `runner.enable = false` gives a usable
administrative builder without any GitHub token; enabling registration later
does not introduce a solver dependency.

For a new temporary VM, `tofu/bootstrap/` imports checksum-pinned official
NixOS installation media onto an existing Proxmox node. It provisions only a
4-vCPU, 8-GiB builder with a replaceable root disk and the already prepared CI
bridge. Use [the host network policy](host-network.md) first. Copy its
`site-base.json.example` into the private site, obtain the ISO and SHA-256 from
the official NixOS release, then review `tofu init`, `tofu validate` and `tofu
plan` from this separate provider directory. It needs no application image.
The bootstrap provider state is separate from the four final VM roles.

Inside the official installer, select only the new builder root disk. Prepare
and mount the root filesystem under `/mnt`, generate its hardware module with
`nixos-generate-config --root /mnt`, and copy the generated
`/mnt/etc/nixos/hardware-configuration.nix` into the private bootstrap site.
Review the detected disks and bootloader configuration. Keep the root partition
at or below the authorized installation disk budget; the VM's sparse disk
capacity does not authorize consuming that capacity.

```sh
nixos-install --flake /absolute/private-bootstrap#ci --root /mnt --no-root-password
```

The SSH key in `site.nix` must be real before installation; this command leaves
password login disabled. Existing `ops install` can run the same command from
an installer with Deno available, and verifies that the destination is a mount
point other than `/`. The helper does not partition disks or install Deno into
the official live ISO. Do not install onto scientific data/state disks.
Select the root disk as the next boot device after installation and detach the
ISO through the reviewed VM maintenance configuration.

The example sets `nix.settings.max-jobs = 1` and `cores = 4`, independently of
GitHub registration. Its runner, when enabled, also has a 4-CPU / 8-GiB systemd
slice. The Nix daemon runs builds outside that runner slice, so the VM's resource
ceiling is the total execution limit. Set matching site VM CPU/RAM ceilings,
finite build wall time, output budget and attempt count before any full build.

After boot, establish SSH, inspect the OS generation and available disk space,
and check the installed tool paths. The builder can then fetch the reviewed root
source graph, prepare the authorized immutable application/solver artifacts,
and build the final CI image. Retire the temporary builder only after that
image boots and its reviewed outputs are retained. Do not run temporary and
final compute capacity beyond the declared host memory budget during this
handoff. Initial OS boot is infrastructure evidence; no scientific result is
implied by it.

Runtime runner tokens remain outside Git, Nix store, ISO and provider state.
Supply them through the private site's secret units and declare
`qclNegf.runtimeSecretUnits` (or runner-specific `secretUnits`) before enabling
registration. The final scientific site remains a separate configuration from
this bootstrap host.

References: [official NixOS downloads](https://nixos.org/download/),
[NixOS installation manual](https://nixos.org/manual/nixos/stable/#sec-installation),
[Proxmox VM resource schema](https://github.com/bpg/terraform-provider-proxmox/blob/v0.114.0/docs/resources/virtual_environment_vm.md).
