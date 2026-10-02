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

Initialize the local backend with an absolute state path inside the private
site (`tofu init -backend-config=path=/private/site/state/bootstrap.tfstate`).
Keep that directory mode `0700` and the state files mode `0600`. A plan's
legacy `-state` option alone does not configure the saved plan's apply backend.
When migrating an existing bootstrap, use `init -migrate-state` before creating
another plan; inspect that the existing VM is read from state rather than
planned again.

For headless installation, use the kernel, initrd and `init=` paths from the
chosen official ISO's `isolinux/isolinux.cfg`. After the provider imports the
ISO, apply `ansible/bootstrap-media.yml` with its host ISO path and pinned
SHA-256 from the private site. This creates a systemd read-only mount at
`/var/lib/qclinstaller`; no scientific toolchain is installed on the hypervisor.
Set the playbook's `qcl_installer_media` to the mounted kernel/initrd and the
original Nix store init path, `qcl_installer_vm_id` to the bootstrap VM ID and
`qcl_installer_boot = true`. The playbook boots those official bytes directly with
`console=ttyS0,115200n8`, while the unchanged attached ISO supplies the live
filesystem. Proxmox permits arbitrary QEMU arguments only to its root host
user, even when an API token has VM.Config privileges. This narrowly scoped
host operation is therefore owned by the playbook; OpenTofu ignores only
`kvm_arguments` for this temporary VM. The playbook checks the exact bootstrap
name, tags, unprotected status and root disk serial before changing host state.
It rejects QEMU arguments belonging to another owner instead of overwriting or
removing them. Inspect its check
mode result first. Set `qcl_installer_restart = true` only for an authorized
boot transition; it stops this temporary VM without a guest shutdown.
After installation, set `qcl_installer_boot = false` with restart disabled to
remove direct kernel arguments, set provider `installer_boot = false` to remove
the CD device, then perform the reviewed reboot into the installed OS.

Inside the official installer, select only the new builder root disk. Prepare
and mount the root filesystem under `/mnt`, generate its hardware module with
`nixos-generate-config --root /mnt`, and copy the generated
`/mnt/etc/nixos/hardware-configuration.nix` into the private bootstrap site.
Review the detected disks and bootloader configuration. Keep the root partition
at or below the authorized installation disk budget; the VM's sparse disk
capacity does not authorize consuming that capacity.

The optional `ansible/bootstrap-root.yml` performs this first empty-disk
preparation without needing Python in the minimal ISO. Its private inventory
selects the installer SSH host; `qcl_bootstrap_root_gib` must be an integer from
16 to 100. It selects only `/dev/disk/by-id/virtio-qcl-bootstrap-root`, rejects
partitions, filesystem signatures and mounts, and creates one ext4 partition
with the legacy BIOS boot flag. Run check mode first. It deliberately refuses
to reformat a previously prepared disk. After interruption, an explicit
`qcl_bootstrap_resume = true` checks the sole ext4 partition, label and size and
only resumes mounting and hardware configuration; it never formats the disk.
The mount specifies ext4 explicitly so newly created filesystems do not depend
on stale live-installer filesystem detection.

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
