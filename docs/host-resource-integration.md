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

Для `qualified_dynamic` production factory `open_service()` подключает
`NativeMutationProofs` и `QualifiedMutationBackend` из [P20-C](host-resource-native-cleanup.md).
`NativeFactsProvider.cleanup()` передаёт проверку этому owner; без него возвращает None. C
производит witness только для квалифицированного успешного синхронного native вызова с exact
source/peer binding, завершением owned command и свежими absence/lock checks. Нужны защищённые
per-VM profiles и отдельная установленная N-проверка. Наличие этого source не означает готовности
конкретной установки. Native unit inactive, CLI exit или matching memory не создают cleanup proof.

При потерянном server reply C сохраняет UNKNOWN и полный charge, без replay. Отдельный
[P20-D retirement](host-resource-recovery.md) реализован только для local libvirt; он не
устанавливает исход старого resize и требует собственной qualification. Для PVE этот recovery
source остаётся недоступным. Healthy C, lost-reply recovery и workload/output completion — разные
gates.

Для output completion реализован ограниченный source-путь `completed_final`, описанный ниже.
Он требует отдельно опубликованного и установленного strong Runner publisher, actual qualification
его исходников/вызова/creator association и свежих original Q1/worker/guest joins. Пока такой
qualification нет, production finish сохраняет полный commitment/charge. COMPLETING, CLI exit,
желаемый finish и отсутствие одного PID не создают completion. Scientific acceptance остаётся у
scientific owner; existing `CompletionEvidence` и public API не меняются.

## Ограниченный completed-final output факт

Initial supported subset — физически завершённый original native run: literal `COMPLETED` и `ExitCode=0:0`,
все selected points имеют current produced native closed final, пустой attempt history и direct
capture-source v3 epoch0. Failure/cancel/nonzero, legacy/unknown source, technical-present,
checkpoint-only/restore/import/reopened producer и неполные original records сохраняют HOLD/full
charge. Отсутствие output entry не означает отрицательного научного результата.

Existing controller `facts/scheduler-facts` вызывает private factory без caller operands.
Factory проверяет actual root process, immutable module/interpreter и точные `python -I -c`
expressions установленного facts и forced-SSH entry. Forced-SSH Python остаётся живым родителем
того же sudo argv; root наблюдает actual UID/PPID/birth/cgroup/executable/argv до и после операции.
Его stdout/stderr и exit status передаются без перекодирования, local child lifetime ограничен.
Same-UID shell, direct administrative import или переданные PID/flags эту цепь не заменяют.
Local child fixtures не квалифицируют реальные setuid sudo/PTY/session/signal forwarding:
deployment требует отдельной проверки actual privileged ancestry и cleanup. Timeout/kill не
удостоверяют remote completion. Root administrative qualification использует private read seams.

Optional root native qualification field имеет точную форму:

```text
completed_final = {runner, unit_generation_sha256, worker_generations}
```

`runner` содержит solver/capture executables, опубликованный Runner revision, source-graph и Julia
manifest SHA, и ровно 13 immutable file roles: launcher, julia_launcher, project, manifest,
runner_entry, runner_module, cli, native_lane, execution, publication, capture_entry, capture_cli,
capture_runtime. Первые десять paths выводятся из solver output; capture entry проверяется через
actual immutable origin выбранного executable. Один файл ≤1MiB, сумма ≤2MiB, aliases между roles
отвергаются. Exact bytes/hash/origin/length проверяются existing reader; 13 совпавших SHA не
заменяют qualification whole published build, loaded modules, fixed callpath и native creator.
Root связывает поле с actual publication/build/install, loaded-source/creator qualification и
соответствующими native evidence. Для первого engineering acceptance допускается отдельно
source-qualified engineering admission при честном native status `NOT_PASSED`; оно не является
положительной native qualification. Placeholder hash, self-reported locator PID/start ticks и один
exit status не являются такой qualification.

Внутри existing `runner` разрешён один optional scalar
`engineering_fixture="native-publication-v1"`. Отсутствие допускает прежний `run-plan` scope;
точное значение допускает только fixed `native-publication-fixture` с теми же eleven native argv
words и включённым capture export. Null/empty/unknown отвергаются. Engineering R не квалифицирует
ordinary run-plan, ordinary R не квалифицирует fixture. Whole R сохраняется и строго сравнивается
между protected host expectation и fresh worker tuple; собственных новых public inputs, actions,
RPC/DTO/schema, stores или journal fields нет.

Original submitted-file reader под dropped UID читает исходный `plan.json`, проверяет raw
bytes/SHA и возвращает только finite derived mode. Decode/object workspace оплачивается до JSON
materialization из той же Operation. Reserved `root_definition_id=native-publication-fixture-v1`
требует полного profile-v3 (canonical SHA256
`376aedbbfa31311f40bdffdb988242613629d128c0a97e8cdd2d6b14b8c42e47`). Из preimage исключаются
только top-level fingerprint и execution resource_estimate.worker_capacity; только absolute
provenance locators трёх исходных YAML получают переносимый prefix. Filenames, fragments, порядок
histories, rule origins, configuration/model/scientific fingerprints и все остальные keys/values
сохраняются. Bounded streaming canonical hash не создаёт второй целый план. Это selector,
сам по себе не creator/source proof.

Preflight связывает derived original mode, protected R и literal original submit-script. В S3
ранний root-owned script snapshot проверяется относительно protected R; затем existing held-FD
reader независимо повторяет полный original plan/profile/R join. Только после этого, successful
W1/held-FD recheck/close и остальных original source/generation gates возможен output. Поздняя
подмена plan/script, несовпадение mode или malformed original закрывают весь packet без partial
completion. Общий debit сохраняется без refund/reset; deadline и остальные guards остаются прежними.

Original reader при `controls=None` сохраняет невозвратный debit через настоящую fork boundary:
перед child reserve/file выполняется bounded private debit frame, parent списывает его в исходной
Operation и только затем разрешает child действие. Child дополнительно сохраняет собственные
inherited cap/deadline checks. Private frame count, byte lengths и monotonic actual-byte samples
ограничены existing original-role/operation bounds; mode не становится public field/journal.
Parent принимает metadata только после checked EOF/child reap. Ошибка, cancellation, timeout или
неопределённый cleanup не возвращают уже оплаченный credit, а дальнейшая работа использует тот же
ledger. Это отдельный original-input arm; existing held-FD forecast/slices/W1 path не меняется.

Uniform operational bootstrap ceiling metadata_bytes —16MiB для всех routes. Это предел
невозвратного metadata accounting, отдельно от actual resident memory, VM/unit MemoryMax и научных
параметров. После исправления fork ledger measured Source/L preflight на full131473-byte original
со shared parent payments требует около9.27 млн байт (8.84MiB): два original actor query, protected reads,
original child decode/canonical/frame и script decode. Поэтому private8MiB честно отказывает до
неоплаченного canonical действия; private16MiB допускается только через обычный only-tightening
`_load_policy`. Policy выше uniform ceiling отвергается; остальные memory/time/packet/role caps
не менялись. Родительский счётчик не зависит от fixture mode и не обнуляется между стадиями.
Private native policy ещё не установлена/не квалифицирована этим source change. Финальная
достаточность MemoryMax, callee/process RSS и реальной installed qualification требует Root N;
metadata prepay и local fixture peak не являются таким доказательством.

Только этот engineering scope допускает constructor result `failed` и point `failed/invalid`,
`converged=false`, `observables.scientific_accepted=false`, exact synthetic execution warning
`SYNTHETIC_NATIVE_PUBLICATION_FIXTURE` с message
`synthetic; not_scientific; constructor-only; no SCBA/Poisson`, disabled synthetic phase и absent
optical attachment. Selected execution обязан совпадать с original launch. Это физическая
публикация намеренно не принятого scientific carrier. Ordinary failed/nonzero/cancel и
technical-present остаются HOLD. Standard parser сохраняет scientific failure; stationary
`native5_final_writer_unavailable` gate не снимается. Source/L fixtures не доказывают actual
installed source, engineering native acceptance, resource release или scientific acceptance.

Unit SHA — SHA256 canonical JSON exact projection:

```text
{controller:{identity:I4,units:[U(aiida),U(api)]},workers:[W(node) for sorted(all enrolled nodes)]}
I4 = {machine_id,boot_id,kernel,dmi_uuid}
W = {node,identity:I4,unit:U(slurmd)}
U = {name,state,main,mount_namespace,mount_line}
```

Canonical encoder — existing `encoded` (sorted keys, compact separators, ASCII JSON, no NaN).
U хранит actual InvocationID/MainPID/cgroup/unit fragment, executable/UIDs/start ticks, namespace
device/inode и выбранную raw NFS mountinfo line. Controller units имеют exact readonly native
prefix; каждый enrolled worker — longest covering writable/hard mount того же NFS source.
Unit/main/ns/mount/main/unit повторяются; restart, namespace/mount/source drift либо пропущенный
worker закрывают gate. Старые unit samples из close-observation остаются историческим provenance.
Свежие samples строятся заново, включая все writer routes, до и после held-FD barrier.

На native host fixed protected service config может содержать `facts.output_owner`:
`{owner,controller_identity,runner,worker_generations}`. `owner` — ровно policy SHA native attempt,
raw controller qualification SHA, source-graph SHA, full unit SHA, storage_identity, retention_ref.
Это другой policy/hash domain, чем PVE/resource policy. Config/routes/role/client UID читаются
повторно при resolve/join/completion. Старое отсутствие optional field сохраняет basic facts/Q1;
durable completion при этом недоступен. Present malformed binding отказывает, без fallback.

Factory сохраняет полный jobs snapshot. Bounded existing journal inventory выбирает ровно один
исходный attempt на successful current native tuple; более восьми eligible entries отвергают весь
пакет до первого output barrier. Original claim/dispatch/ACK/job/allocation/domain, fixed script
snapshot, release/Code/graph mappings и paired raw close/close-observation связываются под existing
per-attempt lock. Только capture-enabled fixed native script domain допускается. Произвольный
sbatch, legacy unset/capture fallback и source switch не принимаются. Native-attempt generation
сохраняет preimage whole controller context/job/submit/dispatch/command/workdir; resource generation
сохраняет cluster/job/raw UserId/submit/start/restarts. Эти SHA не подменяют друг друга.

Existing Q1 `_close` выполняет facts requalification без `put`, нового after-record, repair или
submit. Original close worker before/after неизменны. Fresh worker `phase=status` проверяет actual
original tuple/prolog/epilog, terminal status и пустые whole job cgroup/processes. UID3000 child
держит FD четырёх controls, solver.stdout/stderr, original plan/graph/native-execution/script и
capture-spec/source v3 через fresh W1 barrier; checks/fsync/close относятся только к этим named
files и их owned ancestors. Root не читает NFS payload. Capture metadata ≤16KiB/file; original plan
≤1MiB, graph≤64KiB, native-execution≤16KiB. Все selected rows и nested passports проверяются по
тем же original bytes. Arrays/history/checkpoint payloads не обходятся, не копируются и повторно
не fsync-ятся; их produced closed lifetime гарантирует отдельно qualified strong publisher.
Поздний inode/FD close/fsync/guard/budget failure не даёт факта. Timestamp ставится после successful
child close/EOF/reap и final guards.

Guest/worker packet может additive содержать `output_generation={worker,runner}` от того же
fresh local reader до и после capture. Provider связывает этот tuple с protected owner/full unit
SHA, scheduler и guest allocation/boot/source, empty job group и возрастами output≤guest≤now.
Pending/joined map действует только внутри текущей resource invocation под `store.operation()`;
каждый error/cancel/final exit удаляет его. Старый `guest.outputs`, retained cache и свежий
observed_at без original joins не создают `CompletionEvidence`.

Всё использует один nonrefundable Operation/deadline; native policy может только ужесточать
bootstrap limits. Private child получает только два уже parent-debited byte/file остатка;
forecast оплачивается до pipe/fork, превышение отказывает, неиспользованный credit не возвращается.
Actual consumed I/O учитывается отдельно от prepaid upper bound. Inherited RPC заранее оплачивает
prospective JSON/UTF8/base64/argv; existing command credit покрывает bounded raw transport buffers,
а дополнительный decoder workspace оплачивается по actual bounded raw length до parse. Большой
actual packet может исчерпать budget и дать HOLD. Credits и representation caps не являются RSS
измерением, workload/campaign quota или обещанием принять любой valid большой набор. Parent fatal/
cancel остаётся primary при cleanup; delivered fatal child frame сохраняет class/cause, а не
невозможную cross-process object identity. Нет frame после crash/kill — unknown/HOLD.

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
вызывает resize. C использует этот context для exact dispatch и terminal witness успешного квалифицированного
синхронного вызова. Optional context сам по себе не удостоверяет dynamic completion или readiness.
Disconnect/timeout не снимает charge и не replay-ит intent; границы C и отдельного libvirt D
описаны выше.
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

Краткая installed-RPC приёмка для оператора:

- Проверить distinct enrolled role UID и exact root-owned public authorized-key file0644; все
  parent directories должны позволять traverse выбранному account и оставаться защищёнными от его
  записи. Private key/config сохраняют отдельные0700/0600 и не публикуются.
- Для guest→controller client key проверить per-key `restrict` и forced marker; для
  authority/facts — соответствующий Match/ForceCommand. Проверить actual effective `sshd -T -C`
  для каждой роли, запрет shell/PTY/forwarding и exact canonical sudo wrapper. Match/source text
  или копия ключа сами по себе не доказывают effective restrictions.
- Выполнить разрешённый authenticated client/facts/authority RPC и отрицательные cases на actual
  installed helpers; связать caller/UID, executable и process/cgroup generation с kernel readback,
  а reply — с исходным request/receipt. Файл с ожидаемыми PID или скопированный PASS не является
  kernel proof. Caller qualification, capacity/enrollment и backend native protocol принимаются
  отдельно; этот checklist не присваивает им PASS.

Требуют source follow-up: PVE lost-reply recovery, failed/cancelled/nonzero и другие unsupported
output completion subsets, complete Nix daemon/build join и owning P07/P22/P12/P31 callsites.
Successful completed-final source зависит от owning strong Runner publication и отдельной actual
source/creator/ingress/unit/storage qualification. Healthy C и отдельный local-libvirt
D уже имеют source, но не заменяют эти границы. Отдельно требуют deployment/N:
реальная установка/runtime credentials/enrollment/capacity agreement, installed PVE/libvirt/Slurm/
systemd/Python protocols, actual fixed allocation/image/proc/cgroup/readbacks, hook ordering,
pressure и foreign boundary. Source eval/fixtures не заменяют ни один из этих gates.

| Утверждение                       | Свидетельство                                         | Ограничение                            | Решение                |
| --------------------------------- | ----------------------------------------------------- | -------------------------------------- | ---------------------- |
| Host grant предшествует guest fit | service low-memory fixture, P19 owner API             | Consumer launch wiring отдельно        | сохранить              |
| Cold maximum оплачивается до boot | stopped inventory/offline permit fixtures             | Actual hook/N capacity ещё не измерены | дополнительно измерить |
| Status не пишет и не refresh-ит   | no-writer/no-mtime/schema/cursor fixtures             | P31 transport не установлен            | сохранить              |
| completed_final source ограничен | Original Q1/held-FD/G/guest fixtures и строгие joins | Actual strong publisher/creator/ingress ещё требуют N | дополнительно измерить |
| Все output/build outcomes готовы | Unsupported subsets перечислены явно | Failed/cancelled/build producer отсутствуют | изменить |
