# Восстановление после потерянного native reply

P20-D добавляет административное **retirement старой native incarnation** для локального
libvirt system backend. Исходный resize сохраняет `GROW_UNKNOWN`/`SHRINK_UNKNOWN`: retirement
не устанавливает, выполнился ли он. До полного proof сохраняется прежний полный charge, после
retirement тот же logical VM slot получает полный cold maximum. Старые UUID и name запрещены
навсегда. Код не создаёт и не запускает replacement VM.

Это source contract с synthetic проверками. Native qualification, фактический source/build mapping,
полный memory scope, hook и owning output closure проверяются отдельно. Full P20 recovery и launch
readiness этим документом не объявляются. Обычный fixed-full-max путь и healthy C witness независимы
от opt-in D. Клиентские B actions, роли sudo/SSH и P31 DTO не меняются.

## Root API и граница фактов

Используется существующий `qcl-negf-resource-admin`, без нового executable или sudo role:

```text
qcl-negf-resource-admin retire RECOVERY_UUID REQUEST_ID ORIGINAL_MUTATION_UUID
qcl-negf-resource-admin recovery-status RECOVERY_UUID
qcl-negf-resource-admin reserve-replacement RECOVERY_UUID NEW_NATIVE_UUID
```

Здесь административные UUID — 32 lowercase hex; native libvirt UUID — canonical UUID с дефисами.
Команды предназначены для Root после проверки текущих operational prerequisites. Client/job/gate
не получает этих actions. Проверяются реальные credentials и PID birth текущего Root процесса и
его родителя; `SUDO_UID`/payload true flags не удостоверяют владельца. `retire` использует
существующий transient owned systemd worker, P11 command engine и native-exec helper. Внутренние
native UUID стадий выбирает владелец, caller их не задаёт. Нет второго process supervisor.

Внутренний source API модуля [host_resource_recovery.py](../ops/host_resource_recovery.py):

```python
NativeRecoveryRequest(recovery_id: str, request_id: str, mutation_id: str)
NativeRecoveryService(controller, provider, proofs, protected_config, runner, *, sources=None)
service.retire(request: NativeRecoveryRequest) -> dict
service.read(recovery_id: str) -> dict
service.reserve_replacement(recovery_id: str, native_id: str) -> StartupReservationView
read_recovery_status(recovery_id: str) -> dict
```

`RecoveryFacts(evidence, readbacks, workload_closures)` и `sources=` — внутренний adapter seam;
injected sources в tests явно synthetic. Production создаёт `NativeRecoverySources` только с
реальным root owner и существующим `NativeCleanupSources`. Typed object сам по себе не proof.
Caller передаёт только IDs: пути, argv, profiles, output provenance и native state читает Root.

Root-only recovery projection имеет schema `qcl.host-resource-recovery.v1` и exact поля
`recovery_id, request_id, mutation_id, host_id, vm_id, phase, original_outcome, charged_bytes,
replacement_native_id, failure_code, state_generation, observed_at` плюс `schema`.
`original_outcome` всегда `unknown`; это не разрешение RUN. Текущий source возвращает
`retiring_unknown`, `target_retired` или `hold`; reservation возвращает существующий startup DTO.
`charged_bytes` — текущий logical slot charge. Старый размер/исход виден в immutable original row.
`recovery-status` открывает только существующие файлы и read lock: без service factory, refresh,
backend/guest probe, записи, fsync и сканирования whole history; `readback_not_measured` явен.

## Protected opt-in configuration

Private service config добавляет `native_recovery` с exact объектом
`{schema: "qcl.host-resource-native-recovery-config.v1", qualification: ABSOLUTE_PROTECTED_PATH}`.
Тот файл — bundle `{schema: "qcl.host-resource-native-retirement-qualifications.v1", profiles: [...]}`.
Profiles непустые, unique по logical `binding.vm_id`; выбирается ровно current binding. Exact
структуры опубликованы в [JSON Schema](../schemas/host-resource-native-recovery.schema.json).
Реальные inventory, paths, receipts и qualification остаются в private site.

Per-VM profile связывает host/owner/boot/policy, полный `RuntimeBinding`, source IDs, текущие
socket/daemon incarnation, storage namespace, memory и permanent start-fence protocols. Libvirt
путь использует explicit protected Unix socket на всех readback/inventory/control calls. Source
support содержит исходные C protocol files, шесть retirement source files и текущие protected
`qemu.conf`, daemon config, start hook, service/runtime config. Неизвестный ключ, дубликат VM,
другой peer/kernel/build/config, changed source hash или неполный профиль закрывают control.
Root profile — qualification input; подтверждение installed source/build correspondence остаётся
отдельным N gate, snapshot upstream не подменяет installed proof.

Первая topology квалифицируется только для private ordinary QEMU RAM в одном root-protected,
nondelegated cgroup v2 VM scope, без external/shared memory holders. Shared memory backing,
filesystem/hostdev/TPM/vhost/external renderer и неизвестные devices не входят в этот протокол.
QEMU executable/birth/`-uuid`, scope inode/device/unit Invocation и storage XML metadata seal
фиксируются **до исходного resize exec** вместе с immutable original dispatch.
Target дополнительно требует `storage_devices`: exact metadata refs `{path, device, inode, kind}`
с `kind=local_regular`, canonical paths и unique path/device+inode. Это только формат identity,
не доказательство полноты backing closure. Block aliases (`st_rdev`), network/volume protocols,
backing/external-data и shared readonly templates не принимаются по этому формату. Историческая
UNKNOWN без такого seal не усыновляется. Научные массивы не читаются.

## Durable protocol

1. Под существующим host operation lock проверить latest UNKNOWN request/mutation, original C
   intent/claim/dispatch/seal, точный charged state, owner/boot/policy/source/peer. Исходный owned
   command и descendants должны быть доказанно завершены. Matching RAM, CLI exit и inactive unit
   этого не доказывают.
2. До native control проверить fresh whole-host/foreign agreement, все другие VM readback/floors,
   bindings, quarantine, qualifications, workloads и cleanup. Нужна terminal native generation,
   descendant и output/staging closure **каждого** affected workload. Один незакрытый output
   сохраняет все commitments. Неполное наблюдение не равнозначно нулю jobs.
3. Immutable O_EXCL/fsynced recovery intent сохраняет original state/row/target/profile hashes и
   отдельные UUID destroy/undefine. UUID/name fence и exact pre-control workload closures durable
   до любого control. Hook проверяет fence до foreign passthrough; прямые cold enrollment,
   running bind и start permit тоже отвергают старый UUID. Fence не снимается по TTL.
4. Каждая стадия имеет attached immutable dispatch с текущим actual worker birth/context и
   exclusive claim до `exec`. Fresh pre-exec checks соединяют profile, original state, current
   native target и direct child birth. Prepared dispatch без claim после crash — UNKNOWN;
   заново исполнять его нельзя. Claimed стадия тоже никогда не повторяется.
5. Для libvirt допустимы только фиксированные argv к sealed UUID и тому же endpoint:
   `virsh --connect ENDPOINT destroy UUID`, затем
   `virsh --connect ENDPOINT undefine UUID --keep-nvram --keep-tpm`.
   Storage не удаляется. Если original target уже положительно quiescent/removed, лишний control
   не вызывается и фиктивный successful claim не создаётся. После потерянного reply новая стадия
   возможна лишь при exact completion/absence/barrier прежней; matching memory не помогает.
6. Положительный proof требует old QEMU birth gone и полного qualified physical-memory scope gone
   либо empty, административных commands/descendants gone, неизменного peer/source/config,
   complete UUID/name inventory, static config и autostart absence. Libvirt persistent removal
   сериализуется с MODIFY и устанавливает object `removing`: late old RPC либо закончит до barrier,
   либо отвергнет removed object. FIFO job order не предполагается. Destroy и restart с прежним
   UUID/name такого barrier не дают.
7. Proof durable; все affected original rows/context архивируются immutable-before-prune, затем
   workload idempotency indexes. Только после полного archive set выполняется один atomic v3 state
   save. IO failure оставляет старое charged state и durable fences; продолжение при exact before-state
   выполняет metadata, а не повтор native calls. Original native error/output record сохраняется
   вместе с secondary log/proof IO error. Unknown error не повышается в success.
   Equal existing artifact после failed sync повторно проверяется через protected file descriptor:
   content, file/parent/store identity, file fsync, actual parent/store и parent-of-store fsync обязательны
   до дальнейшего control/prune. Immutable originals не переписываются. Повторная IO failure снова
   удерживает charge; видимый файл сам по себе не удостоверяет durable publication.
8. Logical slot резервирует full cold maximum, `binding=None`, startup `boot_unknown`. P19
   `H + F + Σ(B + O) ≤ physical RAM` и owned-pool invariant проверяются до commit. Другие grants,
   receipts, bindings и startup rows сохраняются. Если full maximum не помещается — прежний state
   и charge; чужие VM не уменьшаются.
   Ожидаемый отказ возвращает Root view `phase=hold`, `original_outcome=unknown` и исходный
   `failure_code=pool_overcommit`/`physical_overcommit`, до archive/prune; native стадии не повторяются.
9. Root обычным provisioning создаёт новую stopped definition с новой UUID **и name**, обновляет
   protected enrollment и вызывает `reserve-replacement`. API проверяет fresh stopped full maximum,
   foreign bounds и остальные VM; проверяет disjoint полные storage closures по path и device+inode;
   VM не создаёт/стартует. Один новый top disk не исключает старый backing member. Full charge durable до boot. Обычный
   startup permit → binding quarantine → fresh all-host qualification/readback/Slurm registration
   остаются обязательны, slurmd не нужен для начальной full-max reservation.

State остаётся `qcl.host-resource-state.v3`; нет migration/reinterpretation old UNKNOWN.
Новые attached target/intent/stage/proof/fence форматы v1 не ведут второй budget ledger.
Retired archive `qcl.host-resource-retired.v1` хранит exact original receipt/context и отдельные
`recovery_id/recovery_proof_sha256`. Existing completed.v3 остаётся читаемым. Old request lookup
возвращает original UNKNOWN, old workload identity сохраняется без lifetime attempt cap. B native
lookup сначала проверяет exact текущую native generation, затем retired marker: evicted/reused job
не получает новой identity/admission. Root/P31 exact request lookup сохраняет старое свидетельство.

## Открытые gates

| Путь | Source сейчас | Ограничение / следующий gate |
| --- | --- | --- |
| Fixed full-max и healthy C witness | Существующие independent пути сохранены | Их actual qualification не доказывает D recovery |
| Libvirt UUID/name retirement | Controller/barrier/claim/fence/archive и conditional source boundary реализованы | Production storage closure producer отсутствует; до него SOURCE hold. Independent source review и N отдельно |
| PVE lost-reply recovery | SOURCE hold, до controls | Detached qmeventd cleanup/restart и numeric PID fallback требуют exact per-client drain/confinement protocol; Python producer не выдумывает proof |
| Full storage/backing/external-data closure | Exact pre-exec seal/alias predicate и negative fixtures | Production collector отсутствует: даже empty XML не доказывает diskless closure; SOURCE followup |
| Affected workload output/staging closure | Existing owning completion hook потребляется | Текущий guest producer не выдаёт полный output receipt; P04/P07 producer остаётся SOURCE followup, production держит charge |
| Dynamic low-idle/pressure/Slurm startup | C/D source prerequisites | Root actual N: grant-before-guest-reject, assigned readback, protected aggregate floors, pressure и отсутствие Slurmd deadlock; capacity/admin agreement и fresh operational readback |

Production `storage_closure` сейчас всегда возвращает SOURCE hold: в pinned libvirt
`940c2352cec2f7759d73ad8725d3ce7f3651cbe9`, `src/conf/domain_conf.c`,
`virDomainDiskBackingStoreFormat` (24424–24434) inactive XML намеренно пропускает detected backing
members. Нет принятого полного block-graph collector даже для подтверждения diskless.
Список/true flag из payload или tests этого не заменяет. Поэтому opt-in D не включают для
реального worker до отдельного source producer; default fixed/C без D остаются независимыми.
Retired target без нового sealed поля сохраняет hold; metadata не реконструируется после UNKNOWN.

PVE SOURCE gap — не утверждение об отсутствии native capability. Неподтверждённый installed build —
N not_measured; отсутствующий output producer — SOURCE gap. Полный P20 остаётся OPEN. В native
эксперименте Root защищает foreign resources; host OOM не является способом проверки pressure.

## Source-only проверки

`tests/test_host_resource_recovery.py` использует synthetic protocol transcripts, настоящий local
receipt store и fault injection для crash/IO/ownership/argv; не вызывает libvirt/PVE/services.
Соседний scoped packet проверяет policy/operations/backends/C/facts/service/startup/client/P31 и
ownership/P11 command semantics. Public synthetic fixture не содержит реальных inventories.

Existing Nix evaluation не выполняет build/install/start:

```sh
NIX_REMOTE='local?root=/tmp/qcl-nix-eval-root-20261028' \
  nix-instantiate --eval --strict \
  --arg nixpkgs /nix/store/q6zfrswar6d0fkihnxc198vmkdxrmvq5-source \
  tests/infrastructure/host-resources.nix
```

| Утверждение | Свидетельство | Ограничение | Решение |
| --- | --- | --- | --- |
| Retirement даёт новый resize success | Original archived UNKNOWN и отдельный retirement proof | Ответ исходного native resize потерян | сохранить UNKNOWN |
| Scoped libvirt recovery source проверяем локально | Real store/crash/argv/closed synthetic fixtures | Native/installed qualification отдельны | изменить после independent review |
| Matching RAM или unit inactivity освобождают charge | Достаточного proof нет | RPC tails и physical/output scope могут жить | сохранить charge |
| Full P20 recovery завершён | PVE/output/native gates открыты | L source не заменяет N/owning producers | дополнительно измерить; SOURCE followup |
