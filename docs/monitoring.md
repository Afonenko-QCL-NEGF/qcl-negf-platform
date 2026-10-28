# Наблюдение за кластером и best-effort telemetry

P31 предоставляет bounded readonly projection, независимый sampler и optional технический collector.
Наблюдение не выдаёт grants, не меняет Slurm/admission и не принимает научные результаты.
Portal/AiiDA/Runner/P32 пока не подключены к этим API. Source/L и установленная native приёмка —
разные gates. Полный P31 открыт: exact QEMU-victim lifetime protocol пока unsupported; installed
capacity/identity/tool/journal/Slurm проверки ещё нужны. Disabled/unknown storage не мешает view.

## Public API и время

```python
from cluster_projection import read_cluster_projection, validate_cluster_projection
read_cluster_projection(*, request_id=None, cursor=None, limit=64)  # local cache only
validate_cluster_projection(document)
from native_monitoring import read_native_status
read_native_status(*, cursor=None, limit=64)
from slurm_context import read_current_context
read_current_context(*, cursor=None, limit=64)
from monitoring_runtime import read_telemetry_storage, sample_native_status, maintain_telemetry_storage
```

Wire schemas: `qcl.cluster-projection.v2`, `qcl.native-status.v2`, `qcl.telemetry-storage.v2`,
`qcl.current-context.v1`; protected config — `qcl.monitoring-config.v2`. Closed definitions
находятся в [cluster-projection.schema.json](../schemas/cluster-projection.schema.json) и
[monitoring-config.schema.json](../schemas/monitoring-config.schema.json). Config/cache v1
отвергаются; автоматической legacy migration нет. Actual site values/keys остаются в private config,
public examples synthetic и disabled.

Production poll/pagination читают только защищённый local latest snapshot. Они не делают SSH,
observer RPC, native probe, P20 lookup, qualification, NFS write, activation, rehash или history
scan. Controller sampler получает remote cached-observation packets через прежний fixed helper;
remote observer читает **public** P20 `read_resource_projection` и свой P31 cache. B DTO v1 остаётся
целым; private receipts/ledger вторым путём не читаются. Exact `request_id` lookup не выполняется из
cached cluster view: при non-null request_id resource недоступен с reason, а native view остаётся.
Admission/точный request lookup принадлежат B.

Controller сохраняет bounded sequence resource pages с opaque B cursors и одинаковыми B state/
native sample/boot generations. Он прекращает fetch при drift/error/общем deadline/byte budget. Если
следующая страница не сохранена, view даёт partial + `resource_snapshot_partial`, без ложного next
cursor. Missing host packet — unknown/null, не нулевой grant и не fresh empty VM list. Root cursor
связан с config и **всем cached snapshot**, inner resource/native identity тоже проверяется; новый
snapshot даёт `stale_cursor`. Limit1–128 ограничивает host/context pages; сохранённые nested B pages
получены sampler с fixed limit64 и ограничены общим output budget.

`read_at` — UTC seconds чтения view. `native.observed_at` — исходное native observation time; B
observed_at — чтение B state, а не live RAM. Source coverage `controller-cache:<sha256(host_id)>`
отдельно показывает успешный fetch time и controller boot; этот timestamp не освежает native
measurement. Internal cache хранит controller sampler boot/config generation и remote native
boot/sample/B state generation. Failed fetch без packet не получает fresh coverage.

Каждое readonly чтение нормализует copy: future timestamp → inconsistent/unknown, истёкший
fresh_seconds → stale, missing/unsupported не становится fresh. Native/service/storage/context
observed_at и historical OOM confidence сохраняются. Clock rollback/boot/gap не считаются свежим
отсутствием событий. RAM total/available, QEMU RSS, assigned/balloon, config max, grant и technical
allocation/reserve — разные byte величины; CPU weight dimensionless, vCPU count отдельно.

## Fixed roles и sampler

`qcl-negf-cluster-status --query-base64 TOKEN` использует прежний reader helper. Local context:

```text
sudo -n -- /run/current-system/sw/bin/qcl-negf-monitor-context TOKEN
```

TOKEN — URL-safe base64 closed `qcl.cluster-query.v1`:
`{"schema":"qcl.cluster-query.v1","request_id":null,"cursor":null,"limit":64}`. Context helper →
`main('context')`, controller-only, authenticated reader_uid. Ровно один token; нет client-selected
path/tool/UID/job/unit/target/env. Sudo ancestry связывается с настоящим caller, одного SUDO_UID
недостаточно. Reader/observer — разные existing nonroot accounts. SSH observer сохраняет restricted
forced command, P11 strict trust/key checks и фиксированный private key; public read не вызывает
этот transport.

Тот же timer → `qcl-negf-monitor-sample` → `main('sample')` запускает root fixed sampler без args.
Controller делает enabled current-context RPC и bounded remote cache fetch; native_host/worker —
прежние native sources. Один volatile `/run/qcl-negf-monitoring/latest.json`, bounded OOM ring, без
DB/нового daemon. Ошибка оставляет прежний snapshot либо explicit unknown packet; poll покажет
stale. P11 возвращает `CommandOutput(str)` с combined output_bytes; `CommandFailure(record)`
учитывается в shared budget, partial stdout не принимается. Typed cursor reply допускается только
для completed `failure=nonzero`, с прежними exit/cleanup/truncation/bytes guards.

Sampler/maintenance/collector не входят в Before/RequiredBy/PartOf scientific services. Solver не
ждёт telemetry HTTP/fsync/cleanup. Timeouts/output bounds и MemoryMax/CPUQuota относятся только к
техническим services; campaign CPU/RAM/time/attempt quotas не вводятся.

## Slurm current context

Default disabled. Controller profile сейчас строго `25.11.8`. Native identity:
`[scontrol, '--version']` и `[scontrol, 'show', 'config']`, только clean completed responses.
Expected ClusterName из private config сверяется с единственной parsed строкой ClusterName;
другой/duplicate/missing identity закрывает RPC. Raw config/stderr/CommandFailure record остаются в
bounded ephemeral memory и не попадают в cache, receipt, log или exception text. Только allowlisted
cluster/version identity и fixed status/reasons сохраняются в public context.

Далее fixed
`squeue --local --array --noheader --states=all --user=<configured numeric UIDs>
--format=%i|%U|%T|%r|%N`,
selected simple jobs — `scontrol --oneliner show job ID`. Environment фиксирован: LC_ALL/LANG=C,
TZ=UTC, SLURM_TIME_FORMAT=standard, protected SLURM_CONF; ambient credentials/Slurm overrides не
наследуются. Bounds:128 rows/64KiB queue, первые32 simple job details по8KiB, весь context256KiB/5s
включая stderr. Нет sacct, full show jobs, /proc/cgroup scan, stop proof, private P20 parser/ledger
или historical archive.

Arrays/heterogeneous IDs остаются видимы с unsupported detail; budget/missing/reused job даёт
partial, не guessed generation. Per-node/per-CPU memory раздельно; unsuffixed native MB в этом
profile — MiB, unknown dates nullable. Native memory0 (all-node/unbounded semantics) не выдаётся как
zero bytes: memory nullable, detail partial с `slurm_memory_all_node`. Generation имеет namespace
observation-only, **не** P20 admission proof; grants нельзя join по job ID. Чистый complete empty
RPC даёт fresh empty context; failed acquisition сохраняет prior observed_at/jobs с unknown.
Snapshot из последовательных RPC не объявляется атомарным. Cursor привязан к cached context
generation/boot/cluster.

## Optional bounded capacity/backing/reserve

Поддержан один native binding `preallocated_loop_linear_v1`: заранее подготовленный Root initialized
backing file на ext4/linear LVM, loop с explicit hard sizelimit и ext4 filesystem, physical backing
независимо от выбранных protected scientific devices. Это **optional** binding, не обязательный
новый filesystem/framework для всей программы. `dedicated_mount` и `project_quota` без native
producer здесь explicit unsupported. При unqualified/unknown persistence закрыта; readonly
projection продолжает работать.

Native producer читает только metadata: no-follow root-owned regular file0600/nlink1/size B и
allocated blocks; bounded initialized FIEMAP extent coverage без SYNC/holes/shared/unwritten flags;
read-only LOOP_GET_STATUS64/BLKGETSIZE64, actual loop device↔mount dev↔FS UUID/geometry; LVM
selected linear segments и sysfs LV→partition→physical WWID graph. Backing profile допускает direct
PV partition/disk; промежуточный mapper/RAID stack unsupported, даже если верхний LV сообщает
linear. Scientific graph может включать свой thin mapper. Config identities сверяются с native
reads, `qualified:true` не существует. `tools.lvs` указывает canonical LVM multicall executable
(обычно `/usr/sbin/lvm`); fixed subcommand `lvs --readonly --nohints ...`, не writable symlink.
Missing/unknown/multipath identity, root thin/COW/shared allocation, wrong inode/offset/device,
mount drift, syscall/tool/budget failure дают unknown. Distinct statvfs/mount сам по себе не proof.
Science thin-pool data/metadata dependencies входят в выбранный physical graph; полного VM inventory
scan нет. Science graph shared на том же physical disk не считается независимым.

Root отдельно готовит **собственную** allocation B, реальные initialized extents (одного fallocate с
UNWRITTEN extents недостаточно), loop/mount identity, root-owned mount и data/state0770
root:qcl-monitoring. Reserve directory0700 root:root/file0600 содержит initialized allocated R. R
недоступен collector для unlink/truncate и отличается от free bytes. Data/state/reserve paths не
перекрываются. Producer ничего не создаёт/не форматирует/не монтирует/не меняет quota. N stage
устанавливает scope/identity и отсутствие external trim/replacement allocation, сверяет native
tools/ABI/permissions и проверяет свой disposable scope. Не использовать чужой диск/VM, shared
scientific thin pool или unknown file как fixture. Actual values не коммитить.

Whole loop FS задаёт hard bytes/inodes bound unprivileged writer; reserve file сохраняет недоступные
writer блоки. `allocation_bytes` — logical hard allocation size, `allocated_reserve_bytes` —
allocated protected reserve, `available_bytes` — наблюдавшиеся свободные байты для writer,
`keep_free_bytes` — snapshot threshold; это не обещание будущего free пространства. При доказанной
physical независимости `science_charge_bytes=0` только относительно явно выбранных science backings;
общая свободная ёмкость science shared pool этим не квалифицируется.

Existing own Vector instance: file sink `${allocationMount}/data`, data_dir/state внутри
`${allocationMount}/state`; buffer256/drop_newest/no ack, event16KiB, MemoryMax512M.
NoNewPrivileges, empty capabilities, ProtectSystem=strict/PrivateDevices и exact ReadWritePaths
ограничивают writer. Все durable payload/state внутри hard boundary; sampler/collector stdout/
stderr null, global journald policy/vacuum не меняется. Manager lifecycle overhead измеряется N.
Никакие storage directories не создаются module tmpfiles автоматически.

Root ExecCondition разрешает persist только после свежего proof и exact writer properties. Existing
sampler/maintenance при потере proof может stop --no-block **только подтверждённую own
vector.service**, никогда foreign unit; public query не делает service actions. `persist_permitted`
— permission, отдельно `collector_state` — наблюдавшийся active/inactive/unknown. Async stop не
объявляется завершённым; unknown ownership не разрешает stop. Hard allocation изолирует writer между
samples; внешние административные изменения Root требуют нового reconciliation.

Retention касается только own finite `events-YYYY-MM-DD.ndjson` в data scope: owner/dev/inode/
nlink/mtime/size, no symlink, не текущий день. State/reserve/foreign sentinels и scientific outputs
не читаются/не удаляются. Unknown/full scope не prune. Никакого unrelated/global log vacuum.

## Source, installation и gates

[NixOS module](../modules/monitoring.nix) default off: observation/sampler/maintenance/collector
включаются отдельно. `collector.allocationMount` — optional уже prepared path; missing binding
остаётся unknown. Site предоставляет existing reader/observer UID/config/key; enrollment и secret
bootstrap отсутствуют. [Ansible source](../ansible/monitoring.yml) требует prepared dependencies и
published B/P11; не включает service/timer и не создаёт allocation. Optional collector unit
сохраняется как `.source`, не заменяет live foreign vector.service; placement/ownership/activation —
Root gate. HTTPS graph links — exact same-origin private config, endpoints не угадываются и history
не читается.

L: four owning pytest files с literal ioctl/LVM/sysfs/journal/Slurm protocols, real P11 str/failure
controls, actual cache freshness, pagination/no-effects и foreign sentinel. Nix source eval
`tests/infrastructure/monitoring.nix` проверяет disabled defaults/paths/sandbox/independence. Это не
installed build/boot/latency/backing qualification. N отдельно: actual tools/binary mapping,
config/UID/trust, prepared allocation capacity/guard/failure/sentinels, structured journal fields,
current-own Slurm context и repeated-poll cost. Real host OOM/QEMU kill не провоцируется.

| Утверждение                    | Свидетельство                                       | Ограничение                                                       | Решение                |
| ------------------------------ | --------------------------------------------------- | ----------------------------------------------------------------- | ---------------------- |
| Poll имеет native side effects | Public path читает только cache                     | Source/L, installed cost ещё N                                    | изменить               |
| Capacity producer существует   | Native metadata/ioctl/LVM/sysfs path + raw controls | Optional allocation ещё должна пройти N                           | сохранить              |
| Unit OOM равен QEMU victim     | Разные scope/identity protocols                     | Exact victim capability unsupported                               | данных недостаточно    |
| Full P31 завершена             | Producers source и foundation API                   | Independent review/N/exact victim requirement/P32 wiring отдельно | дополнительно измерить |
