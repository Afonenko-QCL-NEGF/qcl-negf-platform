# Квалификация памяти на установленной системе

Этот документ описывает реализованный Source и условия его применения. Установка пакета, выполненная
native-операция, достаточность памяти гостя и готовность production — отдельные результаты.
Synthetic unit tests не заменяют измерения на конкретном backend.

## Оплаченная reservation и владелец операции

Квалификация использует существующие `store.operation()`/flock, native worker, C
intent/claim/witness и command engine. Root подготавливает защищённый конечный план с исходными
runtime identities и полной оплатой maxima всех resident VM. Основной journal v3 сохраняет исходные
bytes: калибровка не создаёт workload request, RUN, grant или освобождение capacity. Отдельный fence
закрывает обычные bind/mutation/admission до завершения операции.

`NativeQualificationService` предоставляет `inspect()`, `run_case(name)`, `reconcile()` и
`report()`. Административный entrypoint имеет форму:

```text
qcl-negf-resource-admin qualify UUID inspect
qcl-negf-resource-admin qualify UUID case NAME
qcl-negf-resource-admin qualify UUID reconcile
qcl-negf-resource-admin qualify UUID report
```

`inspect` и `report` читают существующего владельца. Для `case` и `reconcile` Source реализует
защищённый Root dispatcher: он передаёт конечный private запрос существующему transient resource
worker. Admin shell сам C не выполняет. Worker требует фактический root MainPID своего active
`qcl-resource-<32hex>.service`, неизменные cgroup/InvocationID/host boot/process birth и заново
читает исходный plan digest, activation и bootstrap report. Без staged actual idle runtime запрос
отклоняется до нового case/effect/C. Установка Source и проверка actual helper/unit/native chain
остаются отдельными gates; этот маршрут не даёт public action, sudo rule или production RUN.

Worker вызывает единственный existing `run_case()` либо `reconcile()` с plan pin под исходным
`store.operation()`. Новый reconcile worker использует старые original unit/InvocationID/worker и
CLI births выбранного effect; он не заменяет их своими и не вызывает повторный C. Admin отпускает
flock до ожидания worker. Потеря ответа или timeout ожидающего процесса не доказывают остановку
systemd unit и не разрешают повторять dispatch.

`UUID` и `NAME` выбираются из защищённого исходного плана. CLI не принимает произвольный argv,
профиль, доказательство или положительный qualification flag. Перед mutating case нужны актуальные
host/foreign inventory, отсутствие заданий, runtime/Source binding и установленный actual collector.
Неизвестный исход прежней операции сначала сверяется по её исходным receipts; новый dispatch не
заменяет reconciliation.

## Native settlement и физическая оценка

Нативный результат подтверждается по исходному `RETURNED_SUCCESS`, dispatch/claim, PID birth, owned
absence, lock, Source/peer и exact target/readback. Совпавшая память без исходного witness этого не
доказывает. Original before revision сохраняется; after revision читается после операции.

Перед публикацией `READBACK_CONFIRMED` сохраняются исходные парные наблюдения всех resident VM с
собственными contexts и readbacks. Затем обязательно выполняется новая строгая физическая оценка.
Отказ физического predicate сохраняет исходный native outcome и exact mutation UUID; он не
превращает наблюдённый успех C в новый неизвестный native вызов и не разрешает его повторить.
Отсутствующие или недопустимые физические данные остаются `NOT_MEASURED`/отказом, а не PASS.

Ошибка сохранения исходных наблюдений оставляет HOLD и исходный effect slot; успешный case не
публикуется. Исходный terminal witness сохраняется. После восстановления записи `reconcile()`
сверяет тот же UUID без повторения C. Secondary diagnostic failure прикрепляется к исходной ошибке и
не заменяет её. Если metadata settlement уже завершён, последующий physical failure сохраняет ссылку
на завершённый receipt, а не ищет несуществующий pending slot.

Private ответ различает `READBACK_CONFIRMED`, `NO_OP` и `HOLD`, сохраняет точный original mutation,
native outcome, проверенные receipt/evidence refs и ограниченное описание исходной ошибки.
`READBACK_CONFIRMED` подтверждает original native/readback факт, а не сохранённый physical PASS: при
crash после readback до assessor физическая оценка остаётся `NOT_MEASURED`. Native qualification во
всех этих ответах — `NOT_MEASURED`. Ошибка native error journal сохраняет исходное исключение;
невалидный или потерянный private ответ не превращается в обычный production operation DTO.

Если original readback уже durable, pending slot пуст и `reconcile` отказывает. Нужно читать
исходные защищённые receipts/catalog и baseline через `inspect`, сохраняя исходный outcome;
повторный case либо скрытый replay пропущенного assessor недопустимы. `inspect` сам по себе не
заменяет доказательство outcome из original witness/readback. Если readback ещё не записан,
reconcile может подтвердить тот же original terminal без повторения C. Prepared-only или CLAIMED/
unknown slot остаётся HOLD, даже при совпавшем target.

`restore-full` может увеличить `G < V` только из фактического lower readback, подтверждённого
исходным receipt того же operation/binding. Проверяются host safety, все resident identities,
Source/foreign/full-paid и отсутствие заданий. Исключение относится только к выбранному finite
physical-fit predicate; missing accounting, неизвестный native outcome или другой pending effect не
разрешают restore. После restore обязательна обычная строгая физическая оценка. При `G = V`
используется строгий NO_OP: без mutation UUID, dispatch и transition PASS.

## Разные пространства памяти

Динамический допуск использует `G >= M + sum(D)` для native allocation и `T >= R + sum(D)` для
физической памяти гостя. Перед новым телом нужны также `A >= D_new` и фактические task limits
`L_i <= D_i`. Учитываются все ещё разрешённые, pending, неизвестные и живые commitments.

`R`, `K` и `T_max` принимаются только в явно измеренной области с исходными наблюдениями и Source
binding. Административный минимум не является измеренным резервом. Проверяется `M >= R + K` и
`S <= T_max - R`; текущая уменьшенная allocation не заменяет максимум Slurm capacity. См.
[полный контракт](host-resource-integration.md#два-пространства-памяти-и-измеренный-профиль).

Fixed lane отдельно требует полной allocation, actual PVE `balloon=0` либо полного libvirt target,
свежих guest/Source/runtime/registration facts и согласованного protected v1 profile. Dynamic
`NOT_MEASURED` не становится fixed qualification или unsupported автоматически. Изменение policy
digest требует согласованного owning lifecycle; переписывать policy и старый paid journal вручную
нельзя.

## Synthetic jobs и закрытый admission

`QualificationJobs` хранит конечный root-permitted набор исходных CalcJobs и их demands. Порядок:
disabled mirrors → authenticated held submit → original creator binding → release intent → enabled
mirror CAS/readback → release → original prolog/guard → revoke/readback → closure. Partial/unknown
response сохраняет intent, полный demand и fence; автоматического replay нет.

Private `qualification-gate` вызывается после фактической sudo-аутентификации только в роли guest.
Controller factory присоединяется после аутентификации socket peer. Отсутствующие actual factories
сохраняют отказ/CLOSED. Эти Source hooks не устанавливают collector, не выдают production RUN и не
подтверждают body readiness.

Actual mirrors, freshness, весь process subtree, loaded Source, task cgroups и genuine final должны
проверяться установленными владельцами. Пока эти producers и реальные launcher identities не
квалифицированы, synthetic job запускать нельзя. Текущий positive closure требует `COMPLETED` и
genuine final; иной исход не объявляется закрытым по одному exit code или отсутствующему PID.

## Завершение и установка

Source package включает capacity, qualification, gate, observations и runtime вместе с прежними
модулями. Nix и Ansible используют один состав. Runtime заново читает защищённый план и report в
native-exec child; у отсутствующего activation нет положительного default.

Для готовности нужны exact installed Source/entries, actual native и physical cases, проверенные
job/guard/sudo descendants, revoke, полное восстановление allocation и независимая приёмка report.
Только полный принятый report может дать candidate. Его установка и открытие production admission
остаются отдельной операцией. Научный solve и физическая приёмка исследования выполняются после
инженерной готовности с собственным frozen model/plan/criteria и независимым reference.
