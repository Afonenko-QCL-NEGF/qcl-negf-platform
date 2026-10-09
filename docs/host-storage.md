# Native Proxmox host root and temporary image preparation

`ansible/proxmox-storage.yml` owns only R1 (existing linear ext4 root growth) and
R2 (new protected thin image LV, ext4 and temporary inspection stage). The private
object is `qcl_host_storage`; see `examples/private-site/host-storage.yml.example`.
`apply`, `root.enabled`, and `stage.enabled` default to false. A disabled invocation
performs no host probes or mutations. Enabled work refuses check mode because
fresh geometry and successful native postconditions are required.

This source does not authorize a runtime apply. A separate native-host attempt
needs fresh host/boot identity, exact PV/VG/LV/FS UUIDs, observed tool executable
paths, accepted ext4 features/online support, owned operation exclusion, complete
consumer, volume-reference and mount namespace admission, finite positive integer targets/caps and
reserves, retained original receipts and a finite runtime budget. `attempt_id`
identifies this operation; `admission.expires_at_epoch` is a finite integer expiry
checked against native host time; `original_receipt` identifies the retained original
attempt (including a failed one). Never overwrite or relabel that attempt. Capture
all Ansible output in the private site's attempt receipt. Missing or failed probes
refuse before the relevant mutation; a partial transition remains a failed attempt.

## R1

Exact mounted `/`, existing linear LV and PV/VG membership are checked against
fresh `findmnt`, LVM JSON and `dumpe2fs` reports. Multiple segment rows must share
one consistent LV/VG identity, repeated LV size and path; every segment must be
linear on the admitted PV. Repeated LV bytes are never summed. Targets/caps are absolute MiB,
positive non-boolean integers aligned to measured VG extent bytes. The outside-pool
ledger is `root_delta + protected_VG_reserve <= VG_free`; thin internal free is
never counted. No swap is created or changed. Unknown geometry is never zero.

`community.general.lvol` is called only for `LV < target`, with absolute size,
`shrink=false`, `force=false`, `resizefs=false`. Independent fresh LV, mount,
block-device and ext4 geometry follows even if LV already equals target. Native
`resize2fs` receives the existing device and explicit filesystem block goal only
when its filesystem is smaller. Thus a failed filesystem grow can be recovered
without another LV operation or any filesystem-create API. Larger FS/LV, wrong
UUID/type/device or unsupported features refuse. Complete correct state is no-op.
Postconditions reread UUIDs, blocks, mounted root, outside reserve, protected LV
records and root `df`; exit status alone is not acceptance.

## R2

Exact existing final `/var/lib/vz` handoff is detected before any R2 mutation:
no remount, alias, unit rewrite or whole-host readiness claim occurs. Otherwise
only a unique absent LV or exact UUID/type/geometry owned resume is accepted, in
the exact existing healthy thin pool. `preparation_data_mib` and
`preparation_metadata_mib` cover creation/format/mount/inspection backing peaks;
`protected_data_mib` and `protected_metadata_mib` include all protected users'
reserves and admitted growth. The observed data and metadata envelopes are separate;
virtual size is not a physical reservation. Excluded future copy capacity is not a
preparation prerequisite. No pool resizing, recreation or autoextend change occurs.

The existing real stage directory must be empty when inactive, disjoint from
source in both directions, without symlink, inode identity, nested mount or bind
alias. Each distinct mount namespace is read through one fresh positive representative
PID (`lsns` plus `nsenter`/`findmnt`, 30-second per-view timeout). Failed, disappeared
or inaccessible views refuse; namespace count alone does not reject a valid stage.
Physical footprints use the covering host mount's root-relative path and device
major/minor identity. Each namespace mapping is checked only for component-wise
physical overlap with source/stage on the same device; transparent baseline views
are allowed, unrelated PrivateTmp/proc/container binds are preserved. Relevant
aliases or incomplete identity refuse; namespace count does not decide safety.
`stage.references_complete`, `reference_receipt` and empty `volume_references`
require independently captured fresh PVE configuration/volume consumers, not
name-based inference; no unsigned existing LV is accepted.
Stage and source sibling directories on the same root filesystem are allowed.
Native `fuser` guards inspect the exact inactive directory or mounted filesystem;
private complete-consumer admission is still required (including namespace and
non-FD consumers), and must remain valid throughout the held owning operation.

The fixed FS UUID is canonical lowercase 8-4-4-4-12 hex, nonzero and distinct
from mounted root, validated before LV creation; random/clear/malformed values refuse.
Only an LV newly created during this attempt and independently proven blank by
`wipefs --no-act` and `blkid -p` reaches `community.general.filesystem`. Resume
never formats. The fixed FS UUID is checked before activation. The mount template
has no install/boot target; the unit is explicitly disabled. Exact active resume
is inspected without rewriting, restarting or reloading its unit. Its loaded
What/Where/type/options/fragment, empty drop-ins, no pending reload and exact
root-owned regular fragment must match the rendered non-boot template. Loaded
LazyUnmount/ForceUnmount must both be no, checked again before stop. Proven
non-boot static and disabled states are accepted; enabled/indirect/unknown refuse.
Canonical device and rdev checks accept normal mapper/UUID device aliases. Busy/unknown
retirement preserves the mount and diagnostics. After a fresh complete no-consumer
guard, ordinary systemd stop retires the temporary mount; no force/lazy unmount or
delete exists. Postconditions require absent stage mount, disabled policy and
retained exact LV. Keyed static mapping projections preserve UUIDs, paths,
segments and geometry while allowing volatile pool usage and report ordering to
change. Fresh final pool health/reserves are separately checked; normal foreign
writes are not blocked to freeze percentages. This LV has protected host-infrastructure lifetime and never
belongs to a QCL wipe set, even while empty.

No retained-content copy, cutover, final mount enable/activation, PVE storage-disable,
network/provider/bootstrap/guest operation, or foreign workload interruption is
implemented. Full final-storage acceptance and its consumer exclusion remain a
separate owning review. Never equate preparation with readiness to copy all images.

## Verification boundary

The targeted Python test executes actual YAML using Ansible's
`PlaybookExecutor`/`TaskExecutor`, retaining real assertions, conditions, register,
fact evaluation and argument/template rendering. A recording action boundary
substitutes all commands, LVM/filesystem and unit IO actions; native module
execution and local connection commands raise immediately. Independently specified
traces cover LV+FS growth, equal-LV FS recovery, no-op, invalid/missing evidence,
size/reserve failures, new versus foreign stage, separate metadata refusal,
bidirectional disjointness and alias refusal, active/busy resume and final no-action.
Only the pinned community.general 13.4.0 resolver is selected. Synthetic tests do
not measure inner LVM/ext4/systemd/kernel enforcement or native admission; those
are `not_measured`, not pass. No scientific solver or full suite is needed for this
bounded host-storage source packet.

Primary contracts: [lvol 13.4.0](https://github.com/ansible-collections/community.general/blob/13.4.0/plugins/modules/lvol.py),
[filesystem 13.4.0](https://github.com/ansible-collections/community.general/blob/13.4.0/plugins/modules/filesystem.py),
[resize2fs](https://github.com/tytso/e2fsprogs/blob/master/resize/resize2fs.8.in).
