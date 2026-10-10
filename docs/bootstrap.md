# Bootstrap without a scientific build cycle

If the site's normal DNS selects an unreachable cache edge and public DNS ports
are unavailable, `ansible/bootstrap-dns.yml` optionally supplies loopback DNS
over HTTPS in the official minimal installer. Pin an official DNSCrypt release
URL and SHA-256 from its release metadata and a reviewed public DoH stamp in
the private site. The bootstrap downloads only that verified tool from GitHub;
its temporary service has a six-hour limit and binds only `127.0.0.1:53`.
The transient unit is declared under `/run/systemd/system`, since the live
NixOS `/etc/systemd/system` is read-only; it disappears after reboot.
HTTPS certificate checks and Nix cache signatures stay enabled. This resolver
is installer-only: declare the corresponding standard NixOS
`services.dnscrypt-proxy` configuration in the site before installation, with
`networking.nameservers = lib.mkForce [ "127.0.0.1" ]`, explicit static resolver,
no resolver-list sources and no DHCP DNS. Do not preserve a transient CDN
address in `/etc/hosts` as a permanent network contract.

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
builder with a replaceable root disk and the already prepared CI
bridge. Use [the host network policy](host-network.md) first. Copy its
`site-base.json.example` into the private site, obtain the ISO and SHA-256 from
the official NixOS release, then review `tofu init`, `tofu validate` and `tofu
plan` from this separate provider directory. It needs no application image.
The bootstrap provider state is separate from the four final VM roles.
`build_profile` defaults to `standard` (4 vCPU, 8 GiB RAM). `burst` grants
12 vCPU and 24 GiB RAM only after an idle-build and host-capacity admission,
with compute stopped and its queue empty. CPU/RAM and Nix resource caps share
the owning `ops/build-profiles.json`. Resizing explicitly permits the provider
to reboot the idle builder; it never interrupts an active build.

`local-debug` names the same small 4 CPU/8 GiB budget explicitly. For a finite
production artifact build on the temporary bootstrap only, select
`production-build` and supply `production_build_vcpus`,
`production_build_memory_mib` and the freshly measured `host_logical_cpus` to
`tofu/bootstrap`. All are site decisions; no host size is assumed. Set the same
CPU/RAM in the private NixOS site:

```nix
qclNegf.builder = {
  enable = true;
  profile = "production-build";
  resources = { vcpus = chosenVcpus; memoryMiB = chosenMemoryMiB; };
};
```

These variable names denote the actual admitted site values. The profile runs
one Nix job, sets daemon cores and shared slice CPU quota from that CPU count,
keeps 2048 MiB of guest RAM outside its slice, and disables slice swap. The
bootstrap remains `on_boot=false`. The independent
[fresh admission](build-admission.md#temporary-production-build) must establish
idle/empty queue/compute off, complete maximum guest RAM allocations, 8 GiB host
reserve and enough `MemAvailable`, crediting only the owned QEMU process's
observed anonymous resident RAM minus 256 MiB. Only this explicit temporary
profile permits sharing physical host CPUs with other guests, bounded by the
actual host CPU count per builder; it adds no exclusive pinning or guest/job
cancellation. Provider validation alone establishes none of that runtime
evidence. Final four-role production/CI keeps the conservative standard/burst
contract; restore the small builder before resuming compute or retiring it.

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
the ISO from the explicit `ide2` CD-ROM, then perform the reviewed reboot into
the installed OS. The empty drive remains declared: the pinned provider defaults
an absent `cdrom` block to a physical drive on `ide3`, which can fail to start on
a headless host and is outside q35's supported IDE interfaces. Disk boot keeps
`virtio0` first and the empty `ide2` second. Final role VMs explicitly use an
empty `ide0`, reserve `ide2` for cloud-init and boot `virtio0`. See the pinned
[provider CD-ROM contract](https://github.com/bpg/terraform-provider-proxmox/blob/v0.114.0/docs/resources/virtual_environment_vm.md#argument-reference).

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
nix flake lock /absolute/private-bootstrap
nix eval --no-write-lock-file /absolute/private-bootstrap#nixosConfigurations.ci.config.system.build.toplevel.drvPath
nixos-install --flake /absolute/private-bootstrap#ci --root /mnt --no-root-password
```

Create and review `flake.lock` before evaluating/installing a path flake; an
installer-generated lock can change that path's NAR hash between its source
resolution and build. Commit the lock in the private site. When enforcing a
finite install deadline with a transient systemd service, pass the installer's
PATH explicitly (`--setenv=PATH=/run/current-system/sw/bin:/usr/bin:/bin`);
systemd does not inherit the interactive shell's Nix tool paths. Set one build,
four cores and the remaining authorized time on that service before invoking
`nixos-install`.

The SSH key in `site.nix` must be real before installation; this command leaves
password login disabled. Existing `ops install` can run the same command from
an installer with Deno available, and verifies that the destination is a mount
point other than `/`. The helper does not partition disks or install Deno into
the official live ISO. Do not install onto scientific data/state disks.
Select the root disk as the next boot device after installation and detach the
ISO through the reviewed VM maintenance configuration.

The example enables `qclNegf.builder` independently of GitHub registration.
Its `profile` must match the reviewed VM profile. One Nix build runs at a time;
the Nix daemon, administrative builds and runner jobs share `qcl-build.slice`,
with CPU 400% / RAM 7G for standard or CPU 1200% / RAM 22G for burst, swap0.
`local-debug` uses standard's limits; temporary `production-build` derives
matching CPU and RAM-minus-2-GiB limits from its explicit guest resources.
Administrative transient builds explicitly select this slice. Set matching site VM CPU/RAM ceilings,
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

## Preflight and complete disk accounting

Copy `examples/private-site/production.nix.example` into the private site and
add it with `modules = [ ./production.nix ];` in `site.nix`, only after
replacing its documentation addresses and NIC MAC inventory and
provisioning the actual NIC names and runtime TLS files. With networkd a static
gateway includes both `address` and `interface`; a string leaves the interface
unset. The example uses Nixpkgs' recommended proxy headers, including `Host
$host`, with strict nginx validation enabled. API download links are relative,
so the browser retains a localhost SSH tunnel's port. A raw `$http_host` header
must not bypass this check. The example does not provision secrets or assert
that the guests have booted.

The platform `tofu/build-images.ts` entry point requires
`--preflight-receipt ACTUAL_PREFLIGHT.json`, completes four role evaluations,
and binds its generated nginx config to the passed native test before its first image stage.
It retains the existing private path/flake URI input API; a failed gate starts
no image stage. Its full command budget still belongs to the admitted producer.

Before application/native/image builds, evaluate **all four** production role
toplevels and build only the strict control nginx configuration. Run one finite
preflight, without automatic retry:

```sh
python3 ops/bootstrap_build.py --receipt /absolute/private-site/preflight.json preflight \
  --site /absolute/private-site --nix /run/current-system/sw/bin/nix --check-nginx \
  --openssl /absolute/measured/openssl --mount /absolute/measured/mount \
  --nginx-namespace '["/run/current-system/sw/bin/sudo","-n","/run/current-system/sw/bin/unshare","--mount","--net","--propagation","private"]'
```

The helper applies the unary `nix/site-preflight.nix` function explicitly with
`--apply`; `--file` alone does not apply a Nix function. Each child has a 60-second
deadline and a combined 1 MiB stdout/stderr cap, and cleanup kills its owned
process group even after the immediate parent exits. The receipt retains the
child exit status and bounded primary diagnostics. The namespace entry is an explicit
trusted-builder choice; a root operator can omit sudo. Only engineering TLS
paths are substituted, and production credentials are not read. See the
[native nginx contract](nginx-preflight.md).
Evaluation and a successful native nginx test establish configuration acceptance, not image boot, transport, CI or
scientific acceptance. Without `--check-nginx`, status is `evaluation_only` and `nginx_build` is
`not_measured`; this does not satisfy the pre-build gate.
Strict writer exit0 does not close the configuration gate. A real `nginx -t`
must pass with measured zero warn/error/crit/alert/emerg counters in
`nginx_severity_counters`. A cache hit may print no gixy counters; their absence
does not count as a measured zero.
Keep the lock and source revision fixed between this preflight and the producer.

Systemd build units must name an absolute executable and pass an explicit PATH
for its child tools, e.g. `/run/current-system/sw/bin:/nix/var/nix/profiles/default/bin`.
They also select `qcl-build.slice`, the admitted CPU/RAM limits, one attempt and
a finite wall/output budget. The public application services already use
immutable store executables and declared tool paths. Private source directories
needed by the `ci` Nix client require explicit post-create `chmod 0750` and
`chmod 0640` with the appropriate group: an inherited `UMask=0077` masks modes
passed to `mkdir` and `open`. Secret files retain their separate restrictive
modes; do not make the entire private tree readable.

Final disk accounting runs as root, separately from a `ci` producer. A single
`du` invocation includes the Nix store, **all** release history and artifact
history, deduplicating hardlinks across those roots. Add logical minus allocated
bytes only for the explicitly selected QCOW images inside those roots:

```sh
python3 ops/bootstrap_build.py --receipt /absolute/private-site/disk-usage.json account \
  --du /run/current-system/sw/bin/du --limit-bytes 107374182400 \
  --root /nix/store --root /var/lib/qcl-negf-releases --root /var/lib/qcl-negf-artifacts \
  --image /absolute/accounted/artifacts/storage.qcow2 \
  --image /absolute/accounted/artifacts/control.qcow2 \
  --image /absolute/accounted/artifacts/compute.qcow2 \
  --image /absolute/accounted/artifacts/ci.qcow2
```

Replace those four image paths with actual output paths beneath the supplied
roots. Any `du` permission/error result fails with retained diagnostics; excluding
root-only history would undercount usage. Retain the original terminal unit and
failed accounting report when a later read-only root accounting operation
completes the engineering evidence. Do not rewrite that unit as `SUCCESS`.
Free-space admission remains separate and must be measured on the actual target
filesystems before each authorized stage. A 100 GiB aggregate cap does not prove
that any individual filesystem has sufficient free space.

The local lab intentionally retains its existing cloud-init network owner.
Earlier boot success does not establish an independently generated declarative
`eth0` DHCP configuration. Changing that backend requires a generated-network
oracle and a bounded lab boot check; it is not implied by a private production
gateway correction. Private sibling flake inputs also need a coherent source
boundary: a root flake's relative `../other-site` input crosses that boundary.
Render a reviewed canonical absolute input in an external private overlay, or
keep the sibling beneath one common flake source tree; do not copy a temporary
server path into public source.

## Fresh private inputs and local update

Cold bootstrap starts from the selected fresh source ref and authoritative Gitlinks, not old
private volumes, receipts or a copied scientific depot. The operator explicitly supplies an
already-trusted root-owned 0600 shell input file. Source only that declared file without `set -x`,
environment dumps or token/address echo; never discover or execute shell files from an archive.
It declares fresh site paths, source ref, protected enrollment/known_hosts/pool paths, local
release/cache/signing inputs and actual provider/endpoint/storage/network identities. Standard
NixOS/Proxmox/Slurm resource policy/reserves stay in their owning configurations, not shell text.
The update API consumes validated paths, not shell bodies. Missing/duplicate/unreadable mandatory
inputs and a missing accepted fresh-site producer are blockers; old private state is not a
substitute. The Root fresh-site producer is a separate owning implementation.

Use the existing official pinned builder seed, four-role evaluation, strict native nginx
preflight, executable/flake/owner checks and fresh capacity admission before an explicitly
budgeted build. Build, signing/trust, delivery, guest/restore, final CI and scientific acceptance
remain separate gates. One day is a planning target, not a measured bootstrap SLA.

Install whole-update actions/helper/NFS metadata on every role during one-time preparation.
Subsequent compatible application updates are local serial operations described in
[application CD](application-cd.md); CI does not operate deployment. OS configuration changes
require their separate reviewed prebuilt-role maintenance procedure.

I14 whole F1–F7 repair is source-only pending a separately admitted whole source-test packet
and independent review. Original failed source evidence is retained; native current daemon/UTC
registration, full service membership, SQL NULL handling and NFS ownership remain unmeasured.
An original foreign worker DOWN/DRAIN/reason requires operator diagnosis and is never overwritten
by application update. Stopped worker execution does not authorize VM poweroff or RAM reclamation.

The I14 R1–R5/role-health amendment is prepared only in source. All 97 prior selectors are retained,
with eight new body oracles proposed for the same sole future whole packet. Native global PID/member
applicability, actual Slurm full Reason/effective actor/explicit UTC + configured SLURM_CONF, current
daemon registration, AiiDA SQL NULL, NFS/trust and installed repaired-source provenance remain fresh
Root gates. Controller health has no worker slurmd requirement. Runtime tests/native acceptance have
not been performed by this amendment; the original failed logs remain unchanged.
