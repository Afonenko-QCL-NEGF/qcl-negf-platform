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
LazyUnmount/ForceUnmount must both be no, checked again before stop.
Loaded Options must have one nonempty record: comma-separated semantic tokens
require rw/nodev/nosuid and reject ro/dev/suid, while ordering and ordinary kernel
defaults (relatime/data=ordered) are allowed. The declared fragment still matches
its exact rendered text; semantic loaded options do not relax fragment ownership. Proven
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


## Отдельный opt-in retained image cutover

`ansible/proxmox-storage-cutover.yml` продолжает тот же private `qcl_host_storage`:
`apply=false`, `cutover.enabled=false`, root/stage convergence отключены. Это
отдельная source операция; она не создаёт LV/FS, не меняет root/pool, не удаляет
VM/данные, не создаёт swap и не запускает bootstrap. Действующие чужие block VM
сохраняются. Native admission, source fixtures, boot/persistence и SCI — разные
gates. Synthetic boundary никогда не исполняет native PVE/LVM/systemd/rsync.

До apply coordinator принимает exact D04 receipt о завершённом старом QCL wipe,
accepted native R1/R2 receipt и protected verified new seed. Старый installer
должен быть нормально retired без live loop backing; префикс, tag и пустой FD
list не заменяют ownership/backing evidence. Public example содержит null,
private input содержит observed UUID/rdev, source/parent dev+inode, escaped unit,
полные selected/foreign storage stanzas и статические LV/VM disk projections.
Проценты thin usage не входят в static mapping equality: они повторно измеряются
и сравниваются с отдельными конечными data/metadata/growth/reserve bounds.

Held cooperative window — существующее доверенное соглашение одного owner,
не global lock/service. Protected referenced JSON0600 фиксирует `held=true`,
`host_id`, `boot_id`, `attempt_id`, `owner`, `expires_at_epoch`, полный `scope`
(file-content, cached-workers, direct-paths, hooks, vm-transitions, automation)
и exact allowed `foreign_upids`. Metadata lookup не объявляется content reader.
Новые relevant content opens/reads/writes, hooks, VM transitions и automation
исключены до controlled reopening. Relevant workers естественно drain;
foreign jobs не kill/cancel. Window expiry не включает storage автоматически.
Referenced prerequisite JSON имеет `accepted=true`; SHA-256 и root-owned regular
file identity проверяются вновь. Отсутствие, error, stale/unknown data — refusal.

Перед selected native CAS mandatory config digest фиксируется в durable
`gate_disable_intent`. После disable readback проверяются исходные fixed stanza
и остальные stanzas. Complete FD/cwd/root/maps, kernel loop backing и один
readable representative каждого mount namespace защищают original/stage
physical footprint. Unrelated PrivateTmp/baseline views допустимы; неполный
scan/alias/reader блокирует copy. Stage UUID/LV/rdev идентифицируются независимо
от `/dev/mapper` spelling. Inactive stage запускается только с exact owned empty
underlying mountpoint; active stage не restart. R2-created `lost+found` может
исключаться только по explicitly admitted dev/ino/uid/gid/mode и пустому содержимому.

`ops/host_storage_manifest.py` — независимый read-only stdlib oracle:
SHA-256, logical length/type, numeric UID/GID/mode, mtime_ns, no-follow symlinks,
xattrs (включая default/access POSIX ACL), canonical internal hardlink groups,
inode flags и topology/fstat stability. Empty successful xattr probe допускает
mode-only ACL без getfacl; probe error не означает отсутствие. Unsupported
semantic flags/special files/external hardlinks дают refusal. Source/partial
extras не удаляются. Sparse bytes сохраняются; destination allocation ограничена,
равенство extents/inodes не обещается. Entry/hash/logical/allocation/output/time
bounds действуют при чтении. JSON helper requests имеют hard cap1MiB: private
manifest limits выбираются так, чтобы пары source/destination/request помещались
в этот предел; capped request останавливает attempt, не запускает fallback.

Copy — один deadline-bounded штатный rsync с fixed
`-aHAXS --numeric-ids --one-file-system --ignore-times --modify-window=-1 --whole-file`.
Equal size/mtime seconds не пропускают owned partial bad bytes. No inplace,
delete/remove-source или hidden archive execution. Aggregate worksheet включает
полные дополнительные hash/copy passes; unknown sizes не unlimited. До switch
source-before/source-after/destination SHA/ns/metadata должны совпасть, data
synced, thin health/capacity повторно приняты. Полный bounded manifest сохраняется
atomic file+directory fsync в protected receipt directory; receipt содержит
path/hash/summary. Exit0 producer не является приёмкой.

`ops/host_storage_receipt.py` выполняет только bounded JSON IO, immutable identity,
finite phase transitions и atomic exclusive same-parent temporary0600 -> file
fsync -> os.replace -> parent directory fsync -> readback. Existing root-owned
parent0700 должен уже быть admitted на stable rootFS вне source/stage/rollback,
pmxcfs и wipe scope. Нет native/resource decisions, subprocess, DB или service.
Manifest и helper paths находятся в этом же protected directory и отличаются от
receipt. Original failed logs и старые receipts сохраняются вне wipe/copy.

Durable `rename_intent` предшествует одному exact same-FS rename в absent sibling;
parent fsync и observed original inode предшествуют `source_renamed`. Own empty
mountpoint identity сохраняется отдельно. Loaded mount include перед inspection,
start и каждым ordinary stop проверяет exact root-owned fragment, canonical
block identity+UUID, What/Where/Type, no drop-ins/reload, ForceUnmount=no и
LazyUnmount=no. Parsed effective Options требуют rw/nodev/nosuid; ro/dev/suid и
unknown tokens запрещены, конечные installed harmless defaults relatime и
data=ordered допускаются независимо от порядка. Чужой unit не переписывается.

Stage нормально retired; `final_activation_intent` записывается до final start.
Final unit persistent UUID ext4 Before=pve-guests.service, local-fs.target,
без nofail/automount. Actual final UUID/rdev+manifest/seed/foreign mapping проверены
до boot enable и native is_mountpoint policy CAS/readback. Original rollback tree
никогда не удаляется этим ticket. Host image LV сохраняет
protected-host-infrastructure lifetime даже при пустом/failed partial.

**Durable reopening_intent предшествует любому CAS, снимающему restriction**,
включая restored-original и originally-disabled случаи. Sticky marker содержит
intended_tree=new_final/restored_original и не может исчезнуть/понизиться.
Successful CAS с failed completion write, unknown CAS, corrupt/missing mutated
receipt или дальнейшие новые writes требуют reconciliation. Rescue читает
host receipt заново: после marker нет automatic rollback/CAS retry/copy/rename/
restart/remount/reformat/delete. Historical content oracle после возможных новых
writes не применяется. При ambiguous outcome закрытое состояние не обещается.

До marker только fresh held disabled gate, полные пустые refs и safe loaded policy
допускают guarded original restoration: ordinary stop, rmdir exact own empty
point, exact retained inode rename обратно, fsync и независимая проверка manifest.
Original offline semantics возвращаются под closed gate, потом durable
restored_original reopening marker и один original disable semantics CAS.
Unknown/busy/unsafe policy сохраняет original/gate/partial без forced/lazy unmount.
Incomplete receipt на входе сам по себе не разрешает replay: текущая реализация
возвращает reconcile_required без restart/rename/CAS. Complete fixed final resume
наблюдается без сравнения исторического content oracle. Продолжение interrupted
rename/activation требует отдельного bounded coordinator recovery на fresh state.

Native apply остаётся отдельным одним admitted attempt с private deadlines,
capacity/bytes/entry/log bounds и owner window. Synthetic GREEN не проверяет
installed native probe enforcement, hardware FS support, PVE freshness, native
copy/mount, reboot/persistence, swap или SCI. Optional host swap после accepted
final FS требует собственного support/capacity/budget ticket; существующий active
swap не resize/swapoff, guest memory/Slurm/physics contracts не меняются.


### Cutover operational contract v3 (source review repair)

Enabled native input requires exact primitive integer `contract_version: 3`; null/missing/unknown refuses before host mutation. Receipt and manifest schemas remain1, with no migration. Off/check remains no-op. New positive integer limits are `attempt_seconds`, `cleanup_seconds`, `aggregate_output_bytes`, `aggregate_read_bytes`, `aggregate_write_bytes`, `metadata_read_bytes`, `request_bytes`, `native_commands`, `reference_entries`, `reference_hash_bytes`; exact seed length is `preconditions.seed_bytes`. Request≤1MiB, cleanup<action/attempt, reference entries≤entries. Site inputs stay private.

Child-free bootstrap freezes host monotonic deadline bounded by attempt and admission/held-window expiry before probe/helper/declaration. Every remaining action uses the same clock, current host/boot/wall expiry and a fixed unique source slot. Reservation charged before invocation, including failures/rescue, with no refunds/retries. One source-owned command adapter owns one `start_new_session` PGID; nested commands inherit it. Cumulative stdout/stderr and metadata/command counters are per whole invocation. Cleanup TERM→KILL/reap/group absence covers exited leaders; uncertain native daemon mutation is not accepted by rc0 or own child cleanup. Kernel D-state/fsync stalls remain unknown outcomes, not zero IO.

Conservative fixed-flow reservations: `read >= 6H+17S+3E+4C+90R`, `write >= 2C+90J`, `output >=90*output_bytes`, `aggregate_bytes >= aggregate_read_bytes+aggregate_write_bytes`; H=hash_bytes, S=seed_bytes, E=reference_hash_bytes, C=copy_bytes, R=metadata_read_bytes, J=max(request_bytes,output_bytes,receipt.max_bytes). Copy stays one fixed local whole-file argv; 4C reads/2C writes are prepaid logical multiplicity, not a retry or physical SSD amplification claim. Native owner must independently prove installed support and this copy bound; version alone does not prove it.

References prerequisite is protected root-owned0600 post-D04 schema `qcl.storage-cutover.references.v1`: same exact host/boot/attempt/held-window/source-parent/storage/LV/FS context, trusted receipt hashes, full sorted finite volume/absolute/backing projection and installed tool evidence. Three fresh applicability checks bind manifest context, actual `pvesm path` associations and bounded no-follow external fingerprints. Incomplete/unresolved/changed graph refuses before reopening. Frozen graph is a stated held-context prerequisite; a manifest SHA alone does not discover daemon/parser/backing dependencies. Missing actual native reference/tool proof blocks apply.

Completed `new_final` and `restored_original` paths inspect current fixed identities and original disable/is_mountpoint presence+semantics, allow legitimate current-tree readers/new writes, and never rehash historical content or declare/rewrite helpers/unit/receipt. Unexpected aliases/fixed-state mismatch returns readonly reconciliation. Incomplete records remain readonly refusal, not automatic resume. Final absence is separately frozen and rechecked immediately before declaration; stage observations cannot overwrite it. Exact existing declaration is not rewritten. Directory FD/cwd/root/maps, canonical directory binds/deleted references/loop footprint and unknown overlapping backing are refusal boundaries.

Source slot inventory (84 max; 17 probe / 12 guard / 6 snapshot / 3 reference / 1 copy within90 ceiling):

| Slot | Source action | Kind |
| --- | --- | --- |
| clock-bootstrap | Freeze child-free host attempt clock | clock_bootstrap |
| action-1 | Observe initial native admission and held caller window | probe |
| action-2 | Declare bounded receipt IO helper | declare_file |
| action-3 | Declare bounded read-only manifest helper | declare_file |
| action-4 | Read authoritative host receipt | receipt_io |
| guard-5 | guard-5 | mount_guard |
| guard-6 | guard-6 | mount_guard |
| action-7 | Reconcile fixed completed final identity only | probe |
| guard-8 | guard-8 | mount_guard |
| guard-9 | guard-9 | mount_guard |
| action-10 | Durable receipt admitted | receipt_io |
| action-11 | Durable receipt gate_disable_intent | receipt_io |
| action-12 | CAS selected gate disable once | native_argv |
| action-13 | Observe selected disabled gate and naturally drained callers | probe |
| action-14 | Durable receipt gate_disabled | receipt_io |
| guard-15 | guard-15 | mount_guard |
| action-16 | Activate exact inactive empty stage only | native_argv |
| action-17 | Observe stage active UUID after guarded activation | probe |
| action-18 | Read independent before retained manifest | manifest |
| action-19 | Read independent partial retained manifest | manifest |
| action-20 | Verify independent manifest subset | receipt_io |
| action-21 | Semantic references before copy | reference_check |
| action-22 | Durable receipt copy_started | receipt_io |
| action-23 | Copy retained files once | native_argv |
| action-24 | Sync completed stage data | native_argv |
| action-25 | Read independent after retained manifest | manifest |
| action-26 | Read independent destination retained manifest | manifest |
| action-27 | Verify independent manifest equal | receipt_io |
| action-28 | Verify independent manifest equal | receipt_io |
| action-29 | Persist verified bounded retained manifest | receipt_io |
| action-30 | Observe postcopy pool health and empty reader scope | probe |
| action-31 | Durable receipt copy_verified | receipt_io |
| guard-32 | guard-32 | mount_guard |
| action-33 | Declare exact initially disabled persistent final unit | declare_file |
| action-34 | Load final declaration without starting or enabling | native_argv |
| guard-35 | guard-35 | mount_guard |
| action-36 | Observe fresh exact rename admission | probe |
| action-37 | Durable receipt rename_intent | receipt_io |
| action-38 | Rename exact original once | rename_original |
| action-39 | Observe retained original after rename | probe |
| action-40 | Durable receipt source_renamed | receipt_io |
| guard-41 | guard-41 | mount_guard |
| action-42 | Observe complete empty stage consumers before ordinary stop | probe |
| action-43 | Ordinary stage retirement only | native_argv |
| guard-44 | guard-44 | mount_guard |
| action-45 | Observe stage retired before final activation | probe |
| action-46 | Durable receipt final_activation_intent | receipt_io |
| action-47 | Start exact UUID final once | native_argv |
| guard-48 | guard-48 | mount_guard |
| action-49 | Observe active final UUID retained seed and foreign bindings | probe |
| action-50 | Read independent final retained manifest | manifest |
| action-51 | Verify independent manifest equal | receipt_io |
| action-52 | Durable receipt final_verified | receipt_io |
| action-53 | Enable verified final boot policy only | native_argv |
| guard-54 | guard-54 | mount_guard |
| action-55 | CAS selected offline mount policy once | native_argv |
| action-56 | Observe native offline policy and disabled gate before reopen | probe |
| action-57 | Semantic references before final reopening | reference_check |
| action-58 | Durable receipt reopening_intent | receipt_io |
| action-59 | CAS selected gate reopen original semantics once | native_argv |
| action-60 | Observe reopened fixed state without historical content oracle | probe |
| action-61 | Durable receipt reopened | receipt_io |
| action-62 | Durable receipt complete | receipt_io |
| action-63 | Read authoritative host receipt anew in rescue | receipt_io |
| action-64 | Reconcile actual fixed config mount units and callers read-only | probe |
| guard-65 | guard-65 | mount_guard |
| action-66 | Durable receipt rollback_intent | receipt_io |
| action-67 | Ordinary verified final stop before original restoration | native_argv |
| action-67-disable | Explicit final boot disable before verified original restoration | native_argv |
| action-68 | Observe exact own empty mountpoint after ordinary final stop | probe |
| action-69 | Restore exact retained original once | restore_original |
| action-70 | Read durable historical manifest for pre-marker original only | receipt_io |
| action-71 | Read independent restored retained manifest | manifest |
| action-72 | Verify independent manifest equal | receipt_io |
| action-73 | Observe restored original fixed identity before config restoration | probe |
| action-74 | CAS original offline semantics while gate remains closed | native_argv |
| action-75 | Observe restored original offline semantics and held disabled gate | probe |
| action-76 | Durable receipt rolled_back | receipt_io |
| action-77 | Semantic references before restored reopening | reference_check |
| action-78 | Durable receipt reopening_intent | receipt_io |
| action-79 | CAS restored original gate reopen semantics once | native_argv |
| action-80 | Observe restored original reopening fixed state only | probe |
| action-81 | Durable receipt reopened | receipt_io |
| action-82 | Durable receipt complete | receipt_io |


### NB native boundary enforcement

Recovery first selects an immutable eligible pre-marker candidate from freshly inspected host receipt; action64 measures complete actual consumers before rollback intent or stop. Skipped observations carry `consumers_measured=false` and `refs=null`; they are never quiescence evidence. Native stop changes activation only. Separate action-67-disable changes boot policy; existing probes68/75 read back inactive/disabled, exact fragment and no reload before restoration/reopening. Unknown disable/readback blocks subsequent mutations.

Each invocation partitions R into owner R//4, cleanup R//4 and child remainder; the maxima sum to exactly R. One source-local bounded metadata accessor covers no-follow stable files, stat projections, names, links, Linux xattr maxima, ioctl flags, native output and input/helper/source loading; count units and deadlines precede every accessor/iteration. Pure helpers remain unchanged. Receipt prepayment includes inspect B, transition4B, persist2B, read B, sync3B plus input/load/output, path-component/stat/chunk/native-tempfile collision bounds and8192 fixed accessor headroom before any mutating helper. Manifest content reads retain H; external backing reads retain E; metadata remains in R. Explicit telemetry is owner+child+cleanup; absent child telemetry is null/unknown, not0. Logical accessor/serialized payload accounting is not physical kernel/SSD IO proof.

Normal EOF permits bounded natural exit within remaining work time before own-group cleanup. Cleanup itself uses the same reserved cleanup budget and deadline for every process generation record and repetition; uncertain group identity/cap/expiry stays unknown. Per-invocation Linux subreaper support is checked before mutation and never installed as a global service.

Retained graph volume/absolute/backing relatives share one canonical validator: primitive canonical nonabsolute names, no dot-dot/NUL/normalization, special directory root only, every entry and parent covered by current independent manifest with correct type and no symlink escape. Reference slots21/57/77 receive existing before/final/restored manifests; no new snapshots or graph discovery fallback. Native support, whole graph/header discovery, mapped-process accessibility, installed copy multiplicity, capacity and boot admission remain separate operator gates.
