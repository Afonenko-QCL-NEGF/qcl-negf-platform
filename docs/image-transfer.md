# Image transfer from an isolated builder

Build the QCOW2 images on the dedicated CI/build VM. Keep its Proxmox API tokens,
scientific credentials and management-network access absent. Run provisioning
from the normal administrative controller. The controller needs only the small
`images.json`, provider input JSON, SSH public keys and staging receipt; QCOW2
bytes travel directly from the builder to the Proxmox host.

The pinned bpg provider 0.114 offers a
[server-side download resource](https://github.com/bpg/terraform-provider-proxmox/blob/v0.114.0/docs/resources/virtual_environment_download_file.md)
using the Proxmox `download-url` API with an expected checksum and TLS
verification. That requires a reachable artifact HTTP(S) service. This platform's
isolated builder already has SSH, so the supported transport here is a
host-initiated restricted SSH reader, followed by existing file IDs. A URL in
[`proxmox_virtual_environment_file.source_file`](https://github.com/bpg/terraform-provider-proxmox/blob/v0.114.0/docs/resources/virtual_environment_file.md)
first downloads locally and then creates an upload payload; it requires roughly
twice the image size on the controller and does not solve limited controller disk
space.

## Separate read-only SSH authorization

Create a dedicated image-pull SSH key on the Proxmox host through the private
site's credential provisioning. Its private key and pinned `known_hosts` file
must be canonical root:root files with mode 0600, outside the Nix store. Pin the
builder's host key after independently verifying its fingerprint. Do not forward
an administrative or production agent.

The private builder's NixOS configuration adds the public image-pull key to its
existing `ci` account with this forced command:

```nix
users.users.ci.openssh.authorizedKeys.keys = [
  "restrict,command=\"${pkgs.python3}/bin/python3 ${platform.outPath}/ops/image_reader.py\" ssh-ed25519 REPLACE_WITH_IMAGE_PULL_PUBLIC_KEY"
];
```

The reader accepts only `qcl-negf-image-read /nix/store/HASH-OUTPUT/FILE.qcow2`.
The output directory must use a full Nix store hash; the file must be canonical,
regular and have no symlink indirection. It streams native bytes in 64 KiB chunks.
Other shell commands, arbitrary filesystem reads, agent forwarding, port
forwarding and interactive sessions are denied for this key. Existing admin SSH
authorization remains a separate private-site decision. No private key reaches
CI, an image, OpenTofu configuration or OpenTofu state.

Host-to-builder SSH uses `StrictHostKeyChecking=yes`, only the declared
`known_hosts`, `IdentityAgent=none`, `IdentitiesOnly=yes`, `ForwardAgent=no`, no
user SSH configuration and no reusable control socket. Permit Proxmox-host
initiated TCP 22 to the builder and its established replies. This requires no
CI-initiated access to management resources.

## Stage, verify and provision

`tofu/build-images.ts` records the actual QCOW2 path, SHA-256 and byte count in
`images.json`. Transfer only that JSON and the generated
`proxmox.tfvars.json` to the administrative controller. Keep the Nix outputs alive
on CI until staging finishes; do not garbage collect or replace the builder while
it supplies its images. Older manifests without measured `image_bytes` are
rejected and must be regenerated from the actual image files.

The private Ansible variables contain metadata and host-runtime key references:

```yaml
qcl_image_source:
  host: builder.example.org
  user: ci
  port: 22
  identity_file: /root/.ssh/qcl-image-pull
  known_hosts_file: /root/.ssh/qcl-image-pull-known_hosts
qcl_image_datastore: local
qcl_image_manifest: /absolute/private-site/generated/images.json
qcl_image_base: /absolute/private-site/generated/proxmox.tfvars.json
qcl_image_receipt: /absolute/private-site/generated/proxmox-staged.tfvars.json
qcl_image_timeout_seconds: 1800
qcl_image_reserve_bytes: 67108864
```

The existing Proxmox image datastore must permit `import` content. The playbook
resolves each file ID through `pvesm path`; it does not guess `/var/lib/vz`, alter
storage ownership or configure a datastore. Both the resolved import directory
and its parent must be canonical, root-owned and not writable by other users.
If only the final `import` directory is missing, apply creates that exact
directory as root with mode 0755 after acquiring the host lock. Missing ancestors,
foreign directory names and symlinks are rejected.

```sh
ansible-playbook -i /absolute/private-site/inventory.ini \
  -e @/absolute/private-site/image-transfer.yml \
  components/qcl-negf-platform/ansible/proxmox-images.yml --check
ansible-playbook -i /absolute/private-site/inventory.ini \
  -e @/absolute/private-site/image-transfer.yml \
  components/qcl-negf-platform/ansible/proxmox-images.yml
```

`--check` validates the metadata, declared key files and datastore paths, and
reports a required import-directory creation without creating it. It does not
read image contents from CI, verify connectivity or publish a receipt.
The apply operation stages the four Proxmox roles serially. Before each transfer,
it checks free host space for the entire incoming file plus the declared reserve.
The timeout is finite per image, 30–3600 seconds; the four-role operation can take
up to four times that budget. A concurrent staging invocation fails at the host
lock instead of waiting indefinitely.
For a finite overall acceptance window, set `qcl_image_timeout_seconds` to at most
one quarter of the remaining transfer window, with time reserved for local
verification and provider operations. For example, four 300-second image budgets
leave ten minutes of a 30-minute window for those other operations. The default
1800 seconds per image is not a 30-minute budget for the complete pipeline.

The host streams into a same-filesystem partial file, rejects missing or extra
bytes and SSH failure, verifies SHA-256 and the QCOW2 v2/v3 header, fsyncs the
complete file, publishes without overwriting an existing object and fsyncs the
directory. A repeated operation rehashes an existing image before reusing it.
Checksum collisions, corrupt existing files and symlinks fail closed. Cancellation,
timeout and handled storage failures remove the current partial file; a directory
fsync failure rolls back the new publication. A power loss or SIGKILL can leave a
named `.qcl-image-*.partial` file, which an operator may remove after confirming
no staging operation holds the lock. Already verified images remain reusable
when a later role fails.

Only after all four images verify does Ansible write a mode 0600 metadata receipt
on the controller. It contains `image_file_id` and `image_sha256` for each VM and
removes the CI-local `image_path`. Images use full checksum filenames such as
`local:import/qcl-negf-compute-SHA256.qcow2`. OpenTofu imports those existing files
through the provider's documented
[`disk.import_from`](https://github.com/bpg/terraform-provider-proxmox/blob/v0.114.0/docs/resources/virtual_environment_vm.md)
contract:

```sh
tofu -chdir=components/qcl-negf-platform/tofu/proxmox plan \
  -var-file=/absolute/private-site/generated/proxmox-staged.tfvars.json
```

The existing-file mode does not evaluate a controller-local image hash or upload
the QCOW2. The administrative controller retains API credentials and its normal
snippet-upload SSH authorization. OpenTofu does not independently hash remote
image bytes: the verified staging receipt is its admission evidence. Reusing a
manually edited receipt without verification is outside this transport contract.

Staged images have their own host lifecycle and are not deleted by OpenTofu.
Retain the receipts and manage old images explicitly after reviewing VM import
dependencies. Switching an existing deployment from provider-owned uploads to
staged file IDs can schedule deletion of old upload resources and root-disk
replacement; inspect the maintenance plan. The protected storage/control VMs and
their separate persistent disks retain their existing protection contract.

Unit tests exercise bounded streaming, native-byte preservation, SHA/size checks,
QCOW2 versions, timeout/ENOSPC cleanup, directory-fsync rollback, immutable-file
reuse, safe missing-directory creation and SSH option restrictions. They do not
establish real SSH trust, Proxmox datastore admission, a large transfer or
successful VM import on a host.
