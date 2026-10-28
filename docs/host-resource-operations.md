# Выделения памяти физического хоста

P20-A предоставляет lifecycle foundation, а [P20-B](host-resource-integration.md) добавляет opt-in
production facts/helper/transport/startup/projection source для
[контракта P19](resident-memory-policy.md). Владелец — Platform; реальные policy, inventory,
квалификация backend/image и журнал находятся в private site. Этот модуль не запускает solver, не
заменяет Slurm, не вводит daemon или межхостовой ledger.

## Контракт и граница доверия

`ops/host_resource_operations.py` предоставляет
`ResourceRequest(request_id, host_id, vm_id,
owner_id, workload_bytes, workload_id)` и
`HostResourceController(policy, store, backend, clock)`. `request(request, evidence)`,
`grow(request_id, evidence)`, `admit(request_id, guest_evidence, evidence)`,
`finish(request_id, completion_evidence, evidence)`, `shrink(request_id, evidence)` и
`reconcile(request_id, evidence, completion_evidence=None, *, cleanup_evidence=None)` возвращают
неизменяемый `Receipt`. `bootstrap(grants, evidence)` принимает полный исходный snapshot P19.
`HostEvidence`, `GuestEvidence`, `CompletionEvidence`, `NativeCleanupEvidence`, `VMReadback` и
`BackendQualification` — типизированные данные; их поля документированы рядом с объявлениями.
Непроверенный словарь не является свидетельством. Низкий guest MemAvailable не входит в REQUEST:
проверка гостя возможна только после HOST_GRANT и GROW/readback.

`workload_bytes` — дополнительное обязательство конкретной задачи сверх измеренного resident OS
floor, в целых байтах. Полный target вычисляет host: `round_up(minimum_bytes + sum(workload_bytes))`
для **всех** незавершённых commitments VM; charge не меньше прежнего полного grant. Guest/client не
может передать aggregate floor или самостоятельно уменьшить его. Увеличение округляется вверх до MiB
для PVE и KiB для libvirt **до** проверки capacity. Публичный
[request schema](../schemas/host-resource-request.schema.json),
[synthetic example](../examples/host-resource-request.json) и `decode_resource_request(document)`
принимают только demand и identity IDs; неизвестные поля, включая флаги qualification, отклоняются.

`workload_id` обозначает уникальную native allocation/build attempt, включая её дочерние процессы;
это не ID научного run. Новый recovery attempt имеет новую workload identity, а потеря ответа
прежнего request требует reconcile прежнего request-id. Завершённые request/workload IDs не
переиспользуются.

Публичные классы допускают dependency injection для synthetic fixtures. Они сами по себе не являются
границей привилегий. Native вызывающий процесс обязан использовать установленный root ingress P20-B
и `RootNativeBoundary`/controller: root-owned policy, evidence, qualification и state directory без
group/other write, проверенные абсолютные executable paths, доверенное локальное соединение backend
и bounded argv execution. Не принимать policy, evidence, executable, argv или идентичность caller из
job payload. Нативная интеграция с runtime helpers P12 требует отдельного принятого exact interface:
launch binding пока отсутствует, общий command engine P11/P12 переиспользуется. Hyper-V пока
возвращает unsupported.

`RootNativeBoundary(private_config_path).invoke(action, request=ResourceRequest(...))` обрабатывает
REQUEST; остальные действия принимают только `request_id`. Защищённый runtime JSON имеет schema
`qcl.host-resource-runtime.v1` и ровно поля `policy`, `evidence`, `qualification`,
`state_directory`, `backend_config`. В backend_config находятся `backend`, `tool`, `vms`, а также
`node` для PVE либо локальный `uri: qemu:///system` для libvirt. PVE enrollment содержит `vmid`,
`native_id` (SMBIOS UUID); libvirt — `native_id` (domain UUID), `name`, `pid_file`. Пути —
абсолютные, с root-owned ancestry без symlinks и group/other write. Для Nix-инструментов выбирают
реальный store path после проверки доверия; пользовательский профиль не получает root authority.

Отдельный qualification JSON имеет schema `qcl.host-resource-qualification.v1` и массив
`qualifications` из `BackendQualification`. Evidence JSON имеет schema `qcl.host-resource-probe.v2`
и ровно поля `host`, `guests`, `completions`, `cleanups`; последние три — отображения request-id на
защищённые guest/completion/native-cleanup записи. `host` имеет schema
`qcl.host-resource-evidence.v1` и все поля `HostEvidence`, кроме `qualifications`, которые читаются
из отдельного qualification файла. `live_workloads` содержит ровно каждую resident VM и список
фактически живых workload IDs. Missing, дубликаты, неизвестная работа или неполный snapshot
запрещают допуск/освобождение. Bootstrap возможен только один раз из independently verified idle
baseline без чужой или неизвестной работы.

Писатель private probes обязан аутентифицировать актуальные host/guest факты. P20-B реализует
`NativeFactsProvider`, отдельный privileged ingress, demand-only client, cold/offline API и
read-only projection; source installation opt-in и отдельно от реальной установки. Поддержанный
production путь — одновременно оплаченные fixed maxima всех owned VM. Dynamic task/lock cleanup
producer и owning staging completion producer **отсутствуют в source**: это отдельные follow-up, не
просто `not_measured` имеющегося адаптера. P07/P22/P12 launch/start wiring здесь не меняется и не
READY. Точные DTO, источники, роли, ограничения и отдельные N gates описаны в
[руководстве интеграции](host-resource-integration.md). Одно наличие protected JSON не является
измерением.

## Состояния и неатомарные переходы

```text
REQUEST -> HOST_GRANT -> GROW_UNKNOWN -> GUEST_ADMIT -> RUN
RUN + exact completion -> RELEASE (другие commitments той же VM)
                      -> SHRINK_DEFERRED (другой pending владеет хостом)
                      -> SHRINK_READY -> SHRINK_UNKNOWN -> RELEASE
SHRINK_DEFERRED -> SHRINK_READY (только durable metadata после освобождения slot)
```

Журнал `FileReceiptStore` использует один per-host flock, atomic replace и fsync файла/каталога.
Текущий private state — `qcl.host-resource-state.v3`, completed archive —
`qcl.host-resource-completed.v3`, protected probe bundle — `qcl.host-resource-probe.v2`. P20-A v2
опубликован, но в этой site не установлен; mutating v3 entrypoints отвергают v1/v2 с
`upgrade_required`, сохраняя исходные bytes, grants и idempotency. Старые completed v1/v2 не
переинтерпретируются; несовместимость закрывает admission. Автомиграции/reset нет. Resource request
schema и workload-id index сохраняют v1: их demand/identity формат не менялся. До изменения backend
он сохраняет полный округлённый grant и desired target. Одновременно один pending grow/admit/shrink
владеет хостом; несколько RUN commitments могут сосуществовать, в том числе на одной VM. Обычные
Slurm/cgroup limits остаются внутри grant. Завершение одной задачи требует точного snapshot
остальных живых задач и снимает только её commitment; пока другие активны, VM grant не уменьшается.
Последний finish другой VM при занятом pending slot сохраняет `SHRINK_DEFERRED` и полный charge. При
освобождении slot первый deferred receipt под тем же host lock получает `SHRINK_READY`; это только
durable metadata, backend resize/retry не вызывается. Несколько deferred завершений сериализуются
так же. `RELEASE` такого receipt означает завершение workload; физический charge показывает только
`snapshot()`. Host capacity возвращается исключительно после последнего completion и
SHRINK/readback/RELEASE. Повторный request-id с тем же payload возвращает прежний receipt, другой
payload отклоняется. Завершённые id не переиспользуются. Активный state ограничен по объёму (1 MiB),
но **общего лимита числа запросов нет**. Завершённый receipt с исходным host/policy/runtime context
сохраняется отдельно в immutable `completed/<request-hash>.json`; индекс
`workload-ids/<workload-hash>.json` сохраняет запрет повторного workload ID. Поиск старого request
или workload выполняется по одному hash path, без чтения всей истории в RAM. Сначала публикуются
receipt и индекс с fsync их действительных parent directories, затем completed row удаляется из
active state. Crash между этими barriers сохраняет прежний charge; old request не выполняется
повторно. Unknown/active rows не архивируются и не удаляются. История занимает private operational
storage с реальным резервом места; удалять её с потерей idempotency запрещено. Автоматической
очистки и TTL нет. Переполнение active byte buffer закрывает новые запросы до завершения текущей
работы или административной сверки, а не после заданного lifetime числа attempts.

Native argv исполняет принятый `application_release.command` из P11/P12: bounded combined output,
cleanup reserve внутри исходного timeout, проверка отсутствия исполняющихся членов собственной
process group даже после выхода leader. Ошибки сохраняют original bounded stdout/stderr и полный
command record (причина, exit status, child_started, cleanup_confirmed, truncation) в private
`failure-<hash>.json` с request/phase и argv, mode 0600, atomic write и fsync. Truncation при
превышении output bound обозначается явно; полный неизвестный резерв уже сохранён до вызова. Для
каждого receipt возможно не больше двух таких файлов (grow/shrink); их место и retention входят в
private operational storage reserve. Это не замена persistent host journald/pressure/OOM evidence:
его настройка и наблюдаемость требуют отдельной native приёмки P31.

`ResourceError.code` и `PolicyValidationError.code` — причины для вызывающего consumer. `host_busy`,
`host_locked`, `host_pressure`, `pool_overcommit`, `physical_overcommit` означают resource-wait до
научного запуска; они не являются scientific failure. `stale_evidence`, `qualification`,
`incomplete_workloads`, `identity_mismatch`, `reconciliation_required` закрывают admission до
получения свежего доказательства/сверки. Ownership/shape/maximum/conflict errors отклоняют запрос.
`state_full` означает предел размера active metadata, не счётчик completed requests. Ни один из этих
результатов не разрешает запуск Julia или отзыв действующего grant.

HOST_GRANT учитывает `H + F + sum(B + O)` и owned pool через публичный P19 API. RSS не вычитается;
MemAvailable хоста служит только отдельным pressure gate. Conservative mode всегда резервирует
maximum. Dynamic mode требует exact qualification для backend, image, VM, host boot и policy,
активной защиты floor и readback. Округление вверх применяется до проверки capacity.

Каждый guard проверяет readback против уже действующего resident minimum + суммы RUN commitments;
меньший assigned или configured allocation блокирует host с сохранением charge. Будущий HOST_GRANT
резервируется до grow и не входит в этот lower live bound. Завершаемая работа исключается только
после fresh completion с точной identity, zero descendants, durable output и verified cleanup.

GROW_UNKNOWN/SHRINK_UNKNOWN сохраняются **до** вызова backend. Для каждого actual resize intent
создаются новый уникальный `mutation_id`, `mutation_started_at` и `native_cleanup_confirmed=False`;
durable barrier предшествует grow **и** shrink. При сбое этой записи resize не вызывается. No-op,
где actual/configured уже равны target, не вызывает resize и сохраняет cleanup confirmed без
mutation ID: metadata-only crash восстанавливается обычным чтением.

Timeout, потеря ответа и crash не снимают charge и не разрешают запуск. После подтверждённого GROW
guest admission проверяет измеренный OS reserve, total/available memory и существующие task/Slurm
limits. RUN защищает полный grant. Finish требует отсутствие дочерних процессов, verified cleanup и
durable output. Shrink возвращает floor лишь после host readback; release требует также свежего
подтверждения guest и отсутствия работы. При неизвестном исходе charge равен большему из old/target.

Reconcile повторяет только чтение, никогда не посылает повторную mutation вслепую. Рост с полным
readback переходит к GUEST_ADMIT; shrink с полным readback и свежим completion — к RELEASE.
Неподтверждённый native cleanup блокирует весь host: даже совпавший memory target не доказывает
отсутствие позднего эффекта оставшегося процесса. Pending barrier в durable UNKNOWN действует и при
ошибке post-error записи `blocked`/failure. Исходное native exception с original command record
остаётся primary при journal/log I/O error; `.native_journal_error`/`.native_log_error` отмечают
secondary errors. Ни readback, ни потерянный failure reason не снимают barrier после reload.

Успешный backend resize гарантирует cleanup всех собственных native command groups через shared P11
engine; confirmed command failure record позволяет сохранить cleanup confirmed отдельно от
неизвестного memory outcome. Поэтому timeout с подтверждённым cleanup после durable записи такого
результата допускает обычное read-only recovery. Если confirmation не успело сохраниться или cleanup
неизвестен, нужен **отдельный свежий административный** `NativeCleanupEvidence`: `request_id`,
latest `mutation_id`, `host_id`, `owner_id`, `host_boot_id`, `policy_sha256`, точный
`RuntimeBinding`, `observed_at`, `native_mutators_absent=True` и `evidence_ref`. Timestamp не раньше
intent и в обычном окне fresh evidence. Старый grow proof не подходит для нового shrink intent.
Proof не создаётся из memory target, request-id или желаемого результата. Его root-protected writer
обязан фактически установить отсутствие native mutator и всех исполняющихся owned descendants для
данного intent; typed class/true-флаг/строка ref сами не дают privilege или native proof.

Source `RootNativeBoundary` читает proof только из `cleanups` защищённого probe bundle, не из job
payload/пути caller. При принятом proof `reconcile` проверяет полный актуальный host/runtime/
workload snapshot и actual memory readback. Только matching target разрешает GUEST_ADMIT либо
RELEASE со свежим guest completion; при другом allocation остаётся UNKNOWN с полным charge. Cleanup
proof может сохраниться отдельно от memory outcome; backend mutation/retry не выполняется. Receipt в
последующих фазах не потребляет уже ненужный proof повторно. Этот путь снимает только cleanup block:
reboot/policy/config/identity block требует отдельной административной сверки. Production writer
этого dynamic cleanup proof отсутствует и в текущем P20-B: отдельный protocol/source follow-up;
privileged transport source реализован отдельно от установки/N; synthetic injected evidence в
fixtures не является заменой.

Несовпадение host boot, guest boot/machine/image/backend, config fingerprint или policy блокирует
допуск и сохраняет все grants ambiguous. TTL не снимает активное/неизвестное выделение. После reboot
нужна отдельная административная сверка и новый проверенный baseline; автоматического reset нет.

## Backend adapters и native gates

`ops/host_resource_backends.py` использует existing local commands: PVE `pvesh` как в
`ansible/proxmox-storage-cutover.yml`, libvirt `virsh --connect qemu:///system` как в
`ops/local_lab.py`. PVE: `get /nodes/<node>/qemu/<vmid>/config --current 1`, digest-protected
`set .../config --balloon <MiB> --digest <digest>`, `get .../status/current`. Upper cap остаётся
`memory`; dynamic требует enabled balloon и `shares=0`. PID и smbios UUID связывают VM с запущенным
процессом; собственность сверяется с root-protected enrollment, не с произвольным label. Libvirt:
`dumpxml`, `dommemstat` (`actual` в KiB), `domstate`, `setmem <uuid> <KiB> --live --config`. UUID
связывает enrollment; конфигурация без контролируемого memory target хэшируется для защиты от
посторонних изменений. Сохранённый desired target должен быть входом следующего private-site
declarative apply; public code не переписывает private Nix/OpenTofu файлы.

Production wrapper `VerifiedNativeBackend` дополнительно сверяет фактический local host boot ID,
`platform.release()`, SHA-256 **работающего** `/proc/<QEMU PID>/exe` и digest актуального backend
version output. Для PVE `backend_version_id = fingerprint(pvesh get /version JSON)`; для libvirt —
SHA-256 stdout `virsh version --daemon`. `qemu_version_id = sha256:<hex>` от работающего executable.
Остальные version/image/guest boot/readback facts обязан свежо измерить protected probe provider и
сопоставить с exact qualification. `domid` не является PID: source fixtures могут использовать
domid, но production verifier отказывает без проверенного private libvirt pid_file. Изменение
kernel/QEMU/backend/image/guest/readback binding требует новой qualification. Libvirt не имеет PVE
digest CAS для setmem: сериализация QCL и enforceable administrator boundary обязательны; изменения
чужого администратора локальный flock не предотвращает.

Онлайн-изменение показано в
[frozen PVE source](https://github.com/proxmox/qemu-server/blob/71ea0ac7192bb935f63cb64beb59e87d6cecd3bf/src/PVE/QemuServer.pm#L4371),
а единицы и live/config flags — в [virsh manual](https://libvirt.org/manpages/virsh.html#setmem). Ни
config target, ни `status.balloon`/`dommemstat actual` не являются физической reservation.
Доказательства capacity agreement, pressure, guest capacity, floor protection и Slurm registration
предоставляются отдельно для actual backend/image. Source fixtures не дают native pass. Если защита
floor или idle Slurm registration не подтверждены, dynamic unsupported; допускается только
проверенный conservative режим с одновременно оплаченными maximum всех resident VM.

CPU weights из P19 не являются CPU capacity grant. Этот consumer сохраняет их и ordinary limits;
изменение topology/vCPU требует отдельной maintenance operation, здесь не выполняется.

## Проверки

`python3 -m pytest -q tests/test_host_resource_operations.py tests/test_host_resource_backends.py`
проверяет синтетическую арифметику и lifecycle, включая timeout-after-grow, crash/reload, duplicate,
identity/reboot/config mismatch, недостоверную capacity/ownership, failed shrink readback и
неподтверждённую квалификацию. Отдельно проверяются RUN floor до будущего grow, cross-VM deferred
completion, multiple deferred/slot release/crash/reload, exited-leader descendants и сохранение
исходного command record. Import/layout fixture копирует owning ops modules; она не подтверждает
установленный P20 wiring. Вызовы production executables в этих тестах не выполняются.

| Утверждение                          | Свидетельство                       | Ограничение                         | Решение                |
| ------------------------------------ | ----------------------------------- | ----------------------------------- | ---------------------- |
| Полный grant сохраняется до mutation | Synthetic lifecycle/fault tests     | Не native admission                 | сохранить              |
| Unknown не освобождает память        | Durable receipt/reconcile tests     | Reboot требует admin reconciliation | сохранить              |
| Dynamic требует actual qualification | Exact binding/floor checks          | Нативная квалификация отдельно      | дополнительно измерить |
| Foreign resources не изменяются      | Explicit enrollment и argv adapters | Agreement вне локального lock       | сохранить              |
