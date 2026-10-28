# P20-B: root facts, demand API и cold reservation

Platform владеет одним per-host journal/flock и ресурсной арифметикой P19. P20-B добавляет
production **source** вокруг [P20-A lifecycle](host-resource-operations.md): actual native readers,
разделённые privileged helpers, stateless SSH routing, cold reservation/offline gate и bounded
read-only DTO. Установка, actual qualification и owning P07/P22 launch/start wiring отдельны.
Проверки L используют только synthetic packets/temp files; native pass из них не следует.

## Поддержанный путь и остающийся source

Первый production lane — `conservative_reservation`: actual fixed allocation равна полному maximum
каждой resident VM, все maxima одновременно оплачены P19 вместе с H/F/O. PVE требует explicit
balloon=0 и полный fixed maxmem; libvirt — actual KiB/configured target равные maximum. RSS не
заменяет allocation; host MemAvailable только дополнительный pressure gate. Полный foreign inventory
включает stopped non-template QEMU/LXC/domain и agreed overhead/future bounds. Unknown
VM/container/QEMU PID, изменённый foreign config/cap либо недействующее admin agreement закрывают
admission; чужие ресурсы не меняются.

Private foreign agreement задаёт для каждой строки явные `maximum_bytes` (>0), `overhead_bytes`
(>=0, включая явный ноль) и `config_fingerprint`. Native/enrollment/agreed maxima и paid F
проверяются как целые byte values без bool, float, строк или coercion. Отсутствующий overhead не
означает ноль. Полная сумма agreed maxima + overhead должна помещаться в paid F до выдачи cold
reservation и до live admission; наблюдённый native maximum обязан помещаться в согласованном bound.
Root-protected происхождение не заменяет эту проверку.

В source **нет** adapter/producer, который доказывает завершение server-side dynamic mutator/task/
lock и всех его descendants. `NativeFactsProvider.cleanup()` возвращает None; production factory
отказывает dynamic policy с `native_mutation_protocol` до mutation. Existing P20-A typed dynamic
adapters/fixtures сохраняются для owning qualification work, но installed production динамика этим
PR не готова. Native unit inactive, CLI exit, matching memory не создают cleanup proof.

Owning P04/P07/staging producer durable output publication также **не реализован**. Guest reader
возвращает неизвестное output closure; production finish сохраняет commitment/charge. Он требует
native terminal, отсутствие всего job subtree и отдельный root-observed output publication факт.
COMPLETING, gate/client, желаемый finish и пустой один PID не являются completion. Научные файлы и
массивы reader не сканирует, не fsync-ит и не принимает. Exact existing `CompletionEvidence` —
owning typed boundary; будущий writer должен связать native generation, output publication,
closure/descendants и свежую guest boot identity. Формат scientific staging здесь не угадывается.

Nix daemon/per-build scope join отсутствует: `systemd_build` input распознаётся, production request
возвращает unsupported. Shared parent MemoryMax нельзя поделить на новые job IDs или считать
несколько раз. Оплаченная whole-VM fixed reservation остаётся административным базисом; build
launch/completion producer — отдельный source follow-up. Hyper-V unsupported до P25.

## Exact public client API

```python
NativeWorkloadRef(kind, native_id)  # slurm_allocation | systemd_build
NativeDemand(schema, workload, workload_bytes)
decode_native_demand(document) -> NativeDemand
request_native(demand) -> dict
reconcile_native(workload) -> dict
finish_native(workload) -> dict
read_native_status(workload) -> dict
```

CLI `qcl-negf-resource {request,status,reconcile,finish,launch-gate} --json-stdin` принимает bounded
JSON. [Demand](../schemas/host-resource-native-demand.schema.json) содержит только workload kind,
native allocation/build ID и bytes.
[Reference](../schemas/host-resource-native-reference.schema.json) не содержит demand.
Paths/proofs/argv/host/VM/request-id/qualification flags отклоняются. Root вычисляет generation из
actual Slurm cluster/job owner/submit/start/restart facts, node→VM→host получает из protected
enrollment. Evicted/unknown generation не создаёт новый request и не replay.
Arrays/heterogeneous/multinode/restarts/per-CPU-only memory — unsupported в первом Slurm protocol.
Demand не меньше actual native per-node allocation memory; guest aggregate floor вычисляет owner.

[Operation DTO](../schemas/host-resource-native-operation.schema.json) содержит phase/admission,
request/native generation/host/VM/state-generation IDs, requested/target/charged/current/floor
bytes, cleanup и freshness. Unknown numeric values — null. Output-only `workload=null` разрешён для
unmapped charged typed/legacy row: request-id/full charge видны, admission reconciliation_required.
Строгие inputs не принимают null. Failure только bounded code, без paths/raw native logs. Readonly
RUN row не переавторизует запуск: без actual readback он сохраняет RUN/charge, но
admission=reconciliation_required/readback_not_measured. Каждый новый ответ RUN/ready требует fresh
whole-host owner guard: текущие boot/policy/runtime/startup identities, отсутствие cleanup barriers
на всех VM, полный live workload snapshot и actual readback не ниже aggregate RUN floor. Это
относится и к idempotent request/gate, reconcile и любому no-op finish, оставившему RUN. Успешный
новый admit уже проверяет guard, full target readback и guest limits по pre-admit snapshot; новый
candidate добавляется в RUN после этой проверки. Completed duplicate не выдаёт ready. Pressure
закрывает новую авторизацию, но безопасный finish/release сам по себе не блокирует.

Launch gate ничего привилегированно не исполняет. Exit0 только RUN+ready;75 resource_wait;78
reconciliation_required/unsupported/rejected. Gate делает один bounded RPC; повторное ожидание и
scheduler cancellation observation принадлежат owning launch consumer. Нет resubmit/requeue, выбора
worker или общего числа attempts. До accepted publication/N и owning P07 wiring этот standalone API
не объявляется полной launch chain. Не считать обычный Python executable доказанным trusted gate:
exact unadmitted process protocol/image ещё требует отдельной actual qualification.

## Роли, реальные credentials и транспорт

`qcl-negf-resource-client-root` разрешён через narrow sudo только enrolled native account. SUDO_UID
сопоставляется с реальными `/proc` UIDs, sudo executable ancestry, PPID, birth ticks и cgroup;
environment не является authority. Гость дополнительно связывает caller cgroup с точным native
allocation ID. Controller root frontend query-ит native scheduler и направляет demand на protected
native host route, без второго budget journal. Status маршрутизируется bounded fanout по enrolled
hosts без scheduler/facts refresh; несколько retained owners требуют reconciliation.

Отдельные `authority`, `facts`, `worker`, `admin`, `start-hook` executables не становятся client
sudo правами. Forced SSH command фиксирует роль; bounded original command только разбирается и снова
проходит narrow sudo/real credential join. Runtime private key/known_hosts/root config находятся вне
Nix store. SSH использует принятые P11 `freeze_ssh_trust`/`ssh` и command engine с original owned
cleanup semantics. Второй process supervisor не добавлен.

Каждая mutating resource invocation запускается native systemd oneshot unit. Native service пишет
полный grant/UNKNOWN cleanup barrier до actual resize; v3 row может хранить exact native
unit/InvocationID/cgroup/host boot/mutation context через prepare_mutation. Production fixed lane не
вызывает resize. Динамический proof adapter/source отсутствует, поэтому optional context не выдаётся
за готовую dynamic integration. Disconnect/timeout не снимает charge и не replay-ит intent.
Оригинальные native errors/records при journal/log I/O остаются primary в owner engine.

Защищённые пути фиксированы: `/etc/qcl-negf/host-resources/service.json`, runtime
policy/qualification/ agreement и `/var/lib/qcl-negf/host-resources/`. Root-owned non-writable
ancestry обязательна. Explicit Nix store members проверяет переиспользованный P12 `read_store_file`,
включая его узкое исключение только root-owned sticky group-writable `/nix/store`; descendants и
остальные ancestors не ослаблены. Mutable private files остаются под обычным strict P11/P20 trust.

## Production facts sources

`NativeFactsProvider.request_facts(demand, owner_state=...)` собирает complete native inventory,
actual host MemTotal/boot/kernel/machine/DMI, QEMU executable hash/backend version, guest immutable
image/kernel/boot/machine/DMI и whole live workload cgroup/PID inventory. Actual Slurm version и
oneline protocol проверяются; protected SLURM_CONF передаётся в bounded command environment, не
через client env. `scontrol show config` проверяет actual ClusterName/SlurmctldHost против enrolled
identity; `--oneliner show jobs`, `show node` — read-only. Guest fit не отвергает REQUEST:
task/Slurm/available memory проверяются только в guest_admission после durable HOST_GRANT и
grow/readback. Registration/floor/readback qualification — root-approved exact binding, не новые
true flags от клиента. Version/image/kernel/QEMU/PID-birth/readback change invalidates profile.

`completion` и `cleanup` вызываются только под тем же `store.operation()`/flock, что request/apply.
Ordinary nested `locked()` остаётся запрещённым; explicit same-store operation допускает reuse
существующих controller APIs без второго flock/self-deadlock. Active/unknown grants не TTL-expire.
Probe cache — один bounded private snapshot, не второй ledger; readonly status его не пишет.

## Cold startup API и hook

```python
prepare_start_reservations(cold_evidence=ColdHostEvidence(...))
verify_start_permit(native_vm_id, phase, native_config)
bind_running_startup(native_vm_id)
```

`qcl-negf-resource-admin prepare` собирает root cold facts и сохраняет maximum всех VM при полном
stopped inventory **до** boot, без guest/Slurm dependency. Running unbound inventory требует
adoption_required. Никаких start/stop/reboot команда не выполняет.
[Startup DTO](../schemas/host-resource-native-startup.schema.json) показывает paid peak/reservation
ID/host boot/policy/static config и admission_closed.

`qcl-negf-resource-start-hook libvirt <name> <operation> <suboperation>` читает XML stdin;
`... proxmox <vmid> <phase>` читает только root-derived canonical
`/etc/pve/nodes/<enrolled-node>/qemu-server/<vmid>.conf`. Foreign VM/domain возвращает0 без
действий. Owned pre-start/prepare-begin/start-begin проверяет existing protected state/lock/current
host boot/config/max. Нет virsh/SSH/guest/Slurm queries, mkdir/fsync/refresh или implicit resize
внутри hook. Pending/duplicate PVE config отвергается. Unknown existing hook source installer не
переписывает; owning hook attachment — отдельный P22/ native deployment шаг до autostart.
Отсутствующий permit abort-ит только выбранный owned start.

После boot `admin bind <native-id>` получает guest identity без slurmd prerequisite, сохраняет
running_quarantined и полный charge. Identity-only empty workload tuples не открывают admission:
второй полный guest/native/cgroup/actual slurmd+node snapshot требуется под тем же lock. Только
complete fresh bindings/qualification/registration открывают binding_ready. Неудача boot/bind не
освобождает reservation. Ресурсный code не снимает DRAIN и не запускает solver. Guest
reboot/config/policy/host boot mismatch fail closed.

## Журнал и readonly P31 projection

v3 state добавляет startups, nullable binding только cold/unbound/full-paid VM, native workload
mapping и optional per-mutation native context. Completed archive — v3; workload identity index
сохраняет v1. Published v2 не установлен в этой site: mutating v3 открытие возвращает
upgrade_required, сохраняет исходные bytes/unknown grants/idempotency. Автоматической migration/
reset нет. Несовместимый old completed archive также не интерпретируется как новый запрос.

`read_resource_projection(request_id=None,cursor=None,limit=64)` возвращает
[bounded projection](../schemas/host-resource-native-projection.schema.json): host
H/F/O/pool/charge, все VM floors/boot/maintenance/CPU unknowns и страницу операций. `limit<=128`,
output<=256KiB — пределы ответа, не workload quota. Current allocation/CPU, не измеренные в cache,
остаются null. Generation cursor отвергается после изменения state. Archive читается только по exact
request-id, вся история не сканируется. Open-existing/read-only flock не создаёт
directories/lock/state, не fsync-ит и не refresh-ит probe. Неинициализированный state явен. P31
transport/consumer wiring здесь не реализован.

## Source installation и отдельная N приёмка

`nixosModules.hostResources` и `packages.<system>.hostResources` — opt-in exports; default modules
feature не включают. `modules/host-resources.nix` предоставляет узкие sudo rules, source package и
защищённые directories и optional dedicated authority/facts SSH Match/ForceCommand, без
daemon/service startup. Runtime public authorized-key files лежат под root-owned0755
`/etc/ssh/qcl-negf-resource/` (files0644, root writable only), private keys/config
отдельно0700/0600. Dedicated accounts/UIDs задаёт private site; client/authority/facts реальные UIDs
различаются. Guest→controller client key использует per-key restrict+forced
`qcl-negf-resource-ssh-client`, не меняя существующие unrelated ключи qcl account. Virtual RPC
marker `.../qcl-negf-resource-rpc` разбирается fixed forced command и сам не является executable.
`ansible/host-resources.yml` — отдельный opt-in installer source для existing PVE/libvirt: fixed
role helpers, dedicated restricted SSH account, protected private files; без VM changes/hook
attachment/service start. Private tool paths указывают на exact protected executable, не user
profile/symlink. Existing command engine и P12 store reader co-located read-only; их owning files не
менялись.

Требуют source follow-up: dynamic task/lock cleanup producer, P04/P07 output publication producer,
complete Nix daemon/build join, owning P07/P22/P12/P31 callsites. Отдельно требуют deployment/N:
реальная установка/runtime credentials/enrollment/capacity agreement, installed PVE/libvirt/Slurm/
systemd/Python protocols, actual fixed allocation/image/proc/cgroup/readbacks, hook ordering,
pressure и foreign boundary. Source eval/fixtures не заменяют ни один из этих gates.

| Утверждение                       | Свидетельство                                         | Ограничение                            | Решение                |
| --------------------------------- | ----------------------------------------------------- | -------------------------------------- | ---------------------- |
| Host grant предшествует guest fit | service low-memory fixture, P19 owner API             | Consumer launch wiring отдельно        | сохранить              |
| Cold maximum оплачивается до boot | stopped inventory/offline permit fixtures             | Actual hook/N capacity ещё не измерены | дополнительно измерить |
| Status не пишет и не refresh-ит   | no-writer/no-mtime/schema/cursor fixtures             | P31 transport не установлен            | сохранить              |
| Dynamic/outputs/build готовы      | Отсутствующие owning proof producers перечислены явно | Source follow-up, не только N          | изменить               |
