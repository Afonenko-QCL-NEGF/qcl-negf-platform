# Private B1 storage collector

P20 source добавляет opt-in preparation и collector для **новой полностью owned incarnation**
локального libvirt system QEMU. Код и fixtures не означают native admission. N-H0…H8 ниже,
полный F1 memory scope, исходный output closure и independent review обязательны отдельно.
Default fixed-full-max, healthy C, state v3, публичные actions/DTO и роли не меняются.

## Владение и supported lane

Root/approved libvirt management — доверенный единственный владелец lifecycle/topology с рождения
каждого inode до конца операции. Параллельного authorized клиента нет. Это явная operational
предпосылка квалификации, а не вывод из двух одинаковых snapshots. QEMU/kernel/isolation считаются
корректными в обычной модели. Протокол не строит защиту от злонамеренного Root.

Каждая incarnation получает новый numeric UID/GID, nonlogin account без home/supplementary groups,
root-owned nonwritable ancestry и отдельный каталог root:VMgid0750. Writable files — VMuid:VMgid0600;
private readonly seed/backings — root:VMgid0440. Account creation receipt предшествует image inode
birth. Shared template копируется только как approved artifact, не усыновляется и не удаляется.
Существующие/частичные каталоги, переиспользованный ID, ACL, hardlink, symlink, mount/path alias,
удалённый/заменённый inode и дополнительные members закрывают операцию.

Supported graph — только regular local raw/qcow2, один file child и ноль/один private readonly
backing у qcow2. Каждый node, edge и terminal leaf должен быть учтён. Orphans, jobs, snapshots,
external-data (включая `data-file-raw:false`), encryption, bitmaps, filters, FD groups, block/network/
volume paths, exports/backup/migration, storage io_uring/native AIO/O_DIRECT и unknown variants HOLD.
В XML явно `driver name='qemu' type='raw|qcow2' io='threads' cache='writeback|writethrough'`.
Actual file `-blockdev` JSON, QMP cache flags и FD flags подтверждают threads/buffered lane.
Один inactive XML не доказывает detected backing closure.

Existing C private-memory envelope сохраняется: нет memoryBacking, hostdev/VFIO/GPU/shared shmem,
TPM, filesystem/vhost/user helpers и custom namespace/argv. Обычные RAM/RNG objects разобраны
отдельно: единственный `memory-backend-ram` связан с `-machine memory-backend`, share=false,
reserve=true, external core dump выключен; `rng-random` использует только `/dev/urandom`.
Version-specific defaults share=false и RNG filename получены из pinned QAPI/source, не из общего
правила об optional fields. `machine_require_guest_memfd` требует confidential guest support;
такие objects/machine properties запрещены. File/memfd/shm и произвольные secret/unknown objects HOLD. Единственное secret исключение —
ordinary libvirt `masterKey0`, explicit raw/file по derived privileged default
`/var/lib/libvirt/qemu/domain-ID-ASCII_NAME_FIRST20/master-key.aes`. Другие runtime roots HOLD.
Это созданный libvirt32-byte host metadata object: QEMU загружает данные в host heap,
не guest mapping/registered buffer и не FD export. Collector использует только O_PATH/stat/ACL/
namespace metadata; key contents не читает/не хеширует. Metadata envelope SHA не является key hash.
Этот объект хранится отдельным raw slot, не входит в block files/storage disjointness. Actual
identity/size32/nlink1/mode0600 проверяются при capture/use; data/keyid/IV/encrypted secret variants HOLD. Допускаются
только узкие обычные PM `-global ICH9-LPC|PIIX4_PM.disable_s[34]=[01]`, которые строит libvirt.
Реальный launch может потребовать отдельного нового source review, если его вариант не входит в lane.

## Protected config и Root preparation

Service содержит optional `native_storage`:

```json
{"schema":"qcl.host-resource-storage-config.v1","bindings":"<state_directory>/native-storage","qualification":"/protected/storage-qualifications.json","install_specs":"/protected/storage-installs.json"}
```

Это root files, не job packet. Exact closed структуры опубликованы в
[schema](../schemas/host-resource-storage.schema.json), дополнительные semantic joins выполняет
[модуль](../ops/host_resource_storage.py). `install_specs` имеет schema
`qcl.host-resource-storage-installs.v1`, host_id/owner_id и bounded `specs`. Spec связывает install_id,
incarnation_id, logical VM, новый native UUID/name, namespace_parent, account names/numeric IDs,
independently approved distribution manifest SHA, диски/artifact refs, protected definition_ref,
copy budget и timeout. Все ID задаёт Root. UID/GID/namespace/native identities уникальны между specs.

Существующий Root admin принимает только следующие три пары action/ID:

```text
qcl-negf-resource-admin storage-import INSTALL_UUID
qcl-negf-resource-admin storage-definition INSTALL_UUID
qcl-negf-resource-admin storage-bind INSTALL_UUID
```

Opt-in [Ansible source](../ansible/tasks/host-resource-storage.yml) сначала исключает preexisting
names/IDs/tasks, затем создаёт только named account/group и immutable account receipt.
Потеря receipt после account creation оставляет reconciliation_required: retry не усыновляет account.
Private config и qualification копируются root0600. Parent создаётся только когда его ещё нет.
Нет изменения global qemu.conf, daemon/socket policy, primary hook, restart, VM define/start или
native qualification. Existing protected service.tools должен включать exact qemu-img из tool_ids; автоматической установки tool нет.
Source package включает storage и существующие worker_distribution/image_stage
dependencies; executable/sudo/SSH roles сохраняются.

Import под существующим host operation lock записывает immutable intent, вызывает
`worker_distribution.verify` ровно один раз, проверяет полный accepted inventory, deadline и actual
available space, делает O_EXCL новый каталог/файлы и bounded hash-checked copy. Raw scratch получает
`posix_fallocate`; qcow2 — только fixed protected `qemu-img create` над только что созданным own
placeholder. Никакой исходный VM/scientific payload не читается. Partial IO остаётся intent без
complete; нет blind recopy/overwrite/cleanup. Same-artifact complete retry только проверяет identities
и повторяет F1 durability barriers. Creation receipts связывают реальные FD metadata и provenance.

`StorageBinding.definition_sha256` и replacement subject используют **точно existing**
`libvirt_config_fingerprint(actual inactive XML)`; только controlled currentMemory/runtime id/aliases
исключаются существующим C кодом. Emission receipt отдельно хранит raw XML SHA. Candidate bind
comparison отдельно нормализует лишь whitespace/attribute order; C serialization не меняется.

Definition берётся из protected worker recipe с тем же новым UUID/name, подставляет новые disks,
threads/buffered и literal static DAC:

```xml
<seclabel type='static' model='dac' relabel='no'><label>+UID:+GID</label></seclabel>
```

Команда выдаёт bounded XML и immutable definition receipt, не defines/starts VM. Root отдельно
определяет stopped/no-autostart candidate своей existing authority. Bind сравнивает actual native
static fingerprint с emitted candidate, exact storage/DAC envelope, freshly stopped/no-managedsave/
no-jobs/no-snapshots, полную offline graph и holder exclusion двумя проходами. Binding фиксирует
actual inactive static fingerprint после libvirt normalization. Root заранее подготавливает соответствующий
per-binding qualification profile; missing profile — HOLD. После binding existing cold full-max
reservation предшествует start; boot проходит existing quarantine/readback/registration.

## Native observations и последний use

Для **только owned active UUID**, через explicit protected libvirt endpoint, compiled query set:

```json
{"execute":"query-named-block-nodes","arguments":{"flat":true}}
{"execute":"x-debug-query-block-graph"}
{"execute":"query-block","arguments":{"flat":true}}
{"execute":"query-jobs"}
{"execute":"query-block-jobs"}
```

Libvirt taints этот owned domain CUSTOM_MONITOR; это принятое административное наблюдение.
Foreign QMP/raw-monitor connection не применяется. Даже CLI exit0 с QMP `error` HOLD.
`BlockdevChild.child/node-name` → edge role/child. Named names точно равны debug driver names;
debug IDs действуют только внутри одного ответа. Actual live XML alias и actual `-device id/drive`
соединяются с query-block/debug backend roots. Разбор не угадывает QOM path. Все native drivers
должны быть root-reachable. File-node filenames дают file identities, остальные nodes file_id=null.
`backing_file_depth`, native children и qcow2 metadata termination сверяются независимо.
Named-node writeback=true при blk=NULL не смешивается с реальным backend write cache.

Остановленный candidate использует **отдельный** protocol ID и для каждого уже pinned private файла:

```text
PROTECTED_QEMU_IMG info --output=json -f raw|qcow2 -- ABSOLUTE_PRIVATE_PATH
```

Это `BlockGraphInfo` с required `children`, NO_BACKING|NO_IO. Сначала metadata исключает external
data и задаёт explicit backing path/format; лишь затем следующий private file проверяется отдельно.
`--backing-chain`, `--force-share`, disk payload hash и qemu-img check не используются. Info/OFD
lock не доказывает отсутствие writer: Root lifetime/DAC/holder exclusion независимы.

Domain UUID/XML/power inventories и pool UUID/XML/volume path metadata читаются без refresh;
pool/foreign namespace overlap и active foreign VM без принятого non-tainting closure HOLD.
Privileged process inventory читает actual credentials/namespaces/birth; relevant root/capable и
reserved-ID tasks получают FD/maps checks с task birth recheck. Unknown visibility/races HOLD.
Чужие identities исключаются новой private DAC; другой reserved UID/GID task запрещён. Libvirt
private mount namespace допускается только при actual `/proc/PID/root/PATH` inode mapping.
Collector own storage FDs — строго O_PATH/CLOEXEC. Они не передаются через native argv/SCM_RIGHTS.

`StorageCaptureHandle` существует только в этом процессе, держит O_PATH pins и Root owner birth;
его нельзя восстановить из JSON. Перед seal/use повторно проверяются actual source/tool/library
hashes, loaded liburing/libvirt mapping identities, socket/listener/daemon birth, boot/kernel,
creation binding, parent/file metadata/mount IDs, graph и access. Writable size/mtime не ownership.
Равенство snapshots — дополнительная race проверка; lifetime/DAC/sole-owner assumption закрывает ABA.

Attached immutable capture — `native-mutations/<mutation>.storage.json`, перед target/claim/exec.
Target flat files точно равны closure projection. Final validate-target-use работает в том же service
owner **после durable target+claim**, непосредственно перед existing fixed exec argv. Replacement
handle сохраняется через existing facts; final barrier стоит перед reservation save. Descriptor pins
CLOEXEC, не новый supervisor. Retirement требует исходный attached capture и current exclusions;
историческую UNKNOWN без него не реконструирует.

Exact `native_observation` содержит schema, protocol_id, query_set, raw_refs,
task_inventory_sha256, ring_observations, operation_owner. Raw refs — immutable bounded JSON envelopes
под derived `native-storage/<subject>.<fixed-slot>.<content-sha>.raw.json`, максимум256KiB/response,
4MiB aggregate. Capture не содержит disk/scientific bytes. Raw slots/paths/digests проверяются при
retirement. Native errors/timeout/IO failure удерживают original full UNKNOWN charge.

## io_uring, shutdown и qualification

Storage `aio=threads` не означает глобальный запрет io_uring. Обычный fdmon ring разрешён только
по pinned source/native B1 qualification: POLL_ADD=6, POLL_REMOVE=7, TIMEOUT=11, size128/256,
UserFiles=0, UserBufs=0, SqThread=-1; ring count ограничен explicit per-VM qualified bound.
`io_uring_show_fdinfo` использует mutex_trylock: отсутствие counters — HOLD, не zero. SQE/CQE snapshot
приблизителен; no-registered-resources вывод основан также на actual configured caller/library lane.

Threads/buffered IO копирует user data в filesystem folios. Worker в syscall остаётся task и не
проходит F1. После task/mm teardown KVM MMU notifiers освобождают guest mappings; fdmon mmgrab
удерживает accounting mm structure, не mm_users/guest mappings. Graceful QEMU drain/flush/close
объясняет нормальный путь; forced destroy может его обойти. Existing exact QEMU birth + sealed,
nondelegated cgroup scope quiescence остаётся обязательной. Empty fd/RSS/event/exit0 её не заменяют.
Deferred kernel fput/ring cleanup и Btrfs dirty pages/writeback могут пережить QEMU: это host/kernel
overhead/reserves и filesystem lifecycle, не доказательство сохранённой guest RAM или durability.
Storage не удаляется, старый closure навсегда fenced/disjoint от replacement. Нового sleep, sysctl,
global kernel mutation или произвольного scanner/security platform нет.

Qualification bundle exact per subject: live `qemu-11.1.2-owned-live-v1`, stopped
`qemu-img-11.1.2-owned-offline-v1`, holder `linux-qemu-threads-buffered-owned-v1`.
source_ids — полный closed pinned primary set в source/schema. tool_ids exact:
`virsh,qemu,qemu_img,libvirt_daemon,libvirt_driver,libvirt_client,liburing,kernel_config,kernel_notes,
runtime_config,installation_mapping`. evidence_ref — protected SHA reference к native envelope с
actual boot/kernel/native namespaces, fixed LC_ALL=C/LANG=C, observation bounds, sole-owner authority и case refs N-H0…H8.
N-H0 дополнительно требует refs к десяти actual installed producer source files, которые
исполняет helper. Historical PF1 primary — immutable baseline6af; editable current source нельзя
использовать как frozen historical index. Current implementation hashes квалифицируются отдельно.
Каждый case имеет exact schema/name/result=pass/host/source-profile hash, binding_sha256 и
subject, равные выбранному profile, и immutable primary refs; cross-VM/incarnation/subject reuse HOLD.
not_measured/failed/missing не принимаются. Root source/build receipts не являются этими case passes.

| Case | Native witness, выполняет Root отдельно |
| --- | --- |
| N-H0 | Actual binaries/libraries/modules/config, installed mapping, kernel/config/notes, native namespaces/mounts; source delta qualification |
| N-H1 | New account birth, no reuse/delegation, DAC/ACL/parent/file identities, import partial/crash/space durability |
| N-H2 | Actual XML+argv+QMP+FD: threads/buffered, ordinary objects, no guest-memory/FD export/helper, exact graph/termination |
| N-H3 | Actual fdmon counters, no registrations/SQPOLL/unsupported ops; missing trylock counters HOLD |
| N-H4 | Capture/use races and immutable raw/target/claim joins; no foreign QMP; source/peer/namespace/permissions drift HOLD |
| N-H5 | Normal shutdown, guest task/mm/KVM release, old scope, remaining storage references |
| N-H6 | Forced destroy/crash while IO active; same F1 scope/birth barrier, no graceful assumption |
| N-H7 | Residual kernel/ring/pagecache/writeback overhead and host capacity/pressure reserves; no zero-overhead claim |
| N-H8 | Lost replies/restart, immutable F1 archive/fence/full charge, disjoint replacement and final-use race |

Source pins: libvirt12.8.0 `940c2352cec2f7759d73ad8725d3ce7f3651cbe9`, QEMU11.1.2
`4fc49f46dc95d4a27de2509e7fceb2931e91faeb`; upstream Linux7.2.9 reference is not automatically
byte-identical CachyOS kernel source. Exact source hashes are in module/schema and private S1/H1/
ordinary-object receipts. Installed mapping reconciles trusted distro recipe/archive/binaries;
reproducible build, runtime graph/holders and N-H0…H8 remain separate.

| Утверждение | Свидетельство | Ограничение | Решение |
| --- | --- | --- | --- |
| Source collector/preparation реализованы | Production parser/FD/capture/store fixtures, schema и conditional F1 tests | Native actions не выполнены | сохранить после independent review |
| Полная native storage/memory qualification | N-H0…H8 matrix и protected evidence codecs | Свидетельств actual pass здесь нет | дополнительно измерить |
| Public C/F1/default authority сохранена | Existing adjacent source fixtures; private attached proof opt-in | PVE/output/native gates отдельны | сохранить |
