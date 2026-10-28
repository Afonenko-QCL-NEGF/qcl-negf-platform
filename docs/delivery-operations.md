# Доставка: controller service и сверка незавершённых операций

P23-A реализует только **явную maintenance-доставку** заранее собранных APP и solver. Она требует
существующую полную границу остановки: все зарегистрированные узлы доступны, AiiDA workflow обоих
типов и CalcJob отсутствуют, Slurm queue пуста. Эта команда сама не отменяет исследование, не создаёт
новый расчёт и не является soft-update для web. Для `soft_application`, docs, OS, resource resize,
restore и scientific recovery нет fallback к maintenance.

## Установка и совместимость

Сначала оператор проверяет установленную closure средств управления и systemd units. Обычная
доставка APP/solver не обновляет старый baked CLI. `update-capabilities` должен вернуть точный
`qcl-negf-local-update-capability-v3` на каждом узле; это необходимое условие engine, но само по себе
оно ещё не доказывает установку новых controller service/request helpers. Root отдельно доставляет
проверенную заранее собранную management/NixOS role closure штатными средствами Nix и устанавливает
статические units. Новые аргументы нельзя посылать старому CLI в надежде обновить его через него же.
Ни доверие Nix/SSH, ни exact enrollment/metadata проверки при миграции не отключаются.

Source fixtures и Nix evaluation не подтверждают установленную службу. Native проверка должна
отдельно доказать disconnect, unit/cgroup lifetime, daemon restart/reboot, durable storage,
late NFS/secrets/PostgreSQL dependencies и original cleanup semantics. Bootstrap supervisor и
`application_release.command` не заменены. Сетевая доступность не равна готовности NFS.

Root assembler по-прежнему выпускает прежний manifest APP+solver с exact hashes; его output
совместим с входом request. По source inventory он не вызывает public `update/deliver`; отдельный
Root dispatch adapter здесь не требуется. Management/docs composition и совместимость нового APP
с выполняющимся старым scientific runtime этим контрактом не установлены.

## Отправка и статус

Заранее сохраните canonical non-nil UUID операции и точные manifest/pool/enrollment. Пример содержит
только синтетические пути и ID. Отправка выполняется локально на controller:

```console
sudo qcl-negf-release update --request-id d3986590-cf69-4ca8-af7c-c3e065241ad2 --procedure maintenance --manifest /private/release.json --pool /private/pool-v2.json --enrollment /operator-protected/enrollment.json
sudo qcl-negf-release delivery-status --request-id d3986590-cf69-4ca8-af7c-c3e065241ad2
```

`deliver` — такой же submit frontend, с теми же обязательными флагами. Отсутствие procedure/ID
отказывает до dispatch; foreground maintenance fallback удалён. Installed CLI использует только
статические runtime и shared gate. Python API допускают временные paths для source fixtures;
передача произвольного runtime/gate установленной службе не поддерживается.

Client записывает immutable request и единственный server-issued attempt, затем посылает
`systemctl start --no-block qcl-negf-delivery@<request-id>.service`. Ответ `queued` не означает
завершения, readiness или научной приёмки. Ordinary root service владеет **всей** операцией вне client
TTY; она не принадлежит API/AiiDA/bootstrap units, которые engine может остановить. Она использует
тот же delivery engine, lifecycle owner и native command cleanup. Нельзя подменять её client scope,
ручным `systemd-run` или вторым deployment engine.

Повтор exact request ID+body возвращает тот же attempt/status, в том числе после failure; он не
запускает service ещё раз. Изменение manifest, enrollment, pool или bounds с тем же ID — конфликт.
Для осознанной новой maintenance attempt после известной исправленной причины нужен новый UUID.
Unknown требует сначала trusted reconciliation. Потерянный ответ `systemctl` не доказывает, что
служба не стартовала. Даже crash между request и operation publication резервирует старый ID;
повтор не придумывает ему другой attempt. Старые IDs не имеют TTL или лимита числа попыток и не
удаляются по возрасту. Retention primary logs требует сохранения ссылок и uncertain evidence.

В пределах одной операции сохраняются defaults: 1800 s delivery, 360 s command, 1 MiB command
output и 8 MiB aggregate engine output; прежние CLI flags могут их задать. Это bounds операций и
метаданных, не campaign quota CPU/RAM/time/attempts. Service ожидание ownership также расходует её
исходный monotonic deadline; оно не выдаёт новый бюджет engine. Systemd не сокращает его отдельным
RuntimeMaxSec и не делает restart. Kernel-blocked fsync/NFS не обещаются прерываемыми.

## Защищённые записи и значение статуса

`runtime/delivery-requests/` и каждый `<request-id>/` имеют root0700; `request.json`, `operation.json`,
`commit.json` и lock files — root0600. Применяется fd-anchored no-symlink traversal; foreign/writable
paths не исправляются chmod. Эти записи не попадают в строгий старый glob `delivery-attempts/*.json`.
Request serialization не заменяет engine lifecycle capability; unknown другой операции блокирует
новый engine даже при утрате её primary receipt.

Python API:

```python
validate_update_request(value) -> dict
submit_update(value, *, runtime=RUNTIME, run=command) -> dict
read_update_status(request_id, *, runtime=RUNTIME) -> dict
run_update_service(request_id, *, runtime=RUNTIME, run=command) -> dict
reconcile_update_requests(*, runtime=RUNTIME, run=command) -> tuple[dict, ...]
```

Request `qcl-negf-delivery-request-v1` содержит exact keys `schema, request_id, procedure, manifest,
pool, enrollment, bounds`. Enrollment — `{path, sha256}`; pool — active-pool-v2; bounds — четыре
существующих command/delivery timeout/output keys. Fresh authority engine должна совпасть с
зафиксированным enrollment digest. Unknown/duplicate keys, неверные UUID/route/hash/procedure
отказывают до engine mutation. Request size ограничен 256 KiB, compact record — 16 KiB.

Operation `qcl-negf-delivery-operation-v1` содержит exact keys `schema, request_id, attempt_id,
request_sha256, procedure, revision, state, phase, service_generation, engine_receipt,
original_failure_log, admission_state, pending_mutation, requires_reconciliation, error_class`.
`service_generation` — null либо observed `{unit, boot_id, invocation_id, pid, start_ticks}`. Она
проверяется по native unit и proc/cgroup; caller/environment не выдают эту идентичность.

`pending_mutation` — bool **или null**, когда primary boundary неизвестна/утрачена. Null не
подменяется false. Engine progress после проверенного durable checkpoint содержит настоящий bool.
`admission_state` — последнее подтверждённое наблюдение `not_observed|open|closed|unknown`; status не
обещает текущую readiness и не выполняет native health/verify/self-check. Poll читает bounded
request/operation binding; completed дополнительно проверяет matching witness и bounded primary
JSON hash/identity. Это чтение operational metadata, без Nix verification или scientific arrays. Poll не пишет файлы и не меняет revision. Отсутствующий/неверный binding —
bounded ValueError, а не regenerated completed status. CLI возвращает bounded
`qcl-negf-delivery-response-error-v1` с exact keys `schema, request_id, error_class` и exit1;
невалидный UUID представлен null, raw body/argv/source paths не включаются.

Completion witness `qcl-negf-delivery-commit-v1` имеет exact keys `schema, request_id, attempt_id,
request_sha256, engine_receipt, engine_receipt_sha256, intent_cleanup_confirmed, admission`.
Он фиксирует durable terminal primary receipt того же request/attempt, отсутствие own intent и
existing lifecycle guards, fsync каталога intents, actual selected open admission readback.
Witness выполняется при ещё удержанном engine lifecycle lock. `admission` — `{release_id, open:true}`.
После него отдельно публикуется auxiliary operation projection. Это operational completion proof,
не artifact qualification и не научная приёмка.

Ошибка progress/witness/projection не выбрасывается в engine dispatch/recovery path и не стирает
original outcome. Особенно после engine commit она **не** делает recovery-close и не переписывает
primary completed как failed-known. Если auxiliary publication не подтверждена, operation становится
`outcome_unknown` с честным admission readback; surviving primary/witness сохраняются. Если storage
не принимает и этот статус, остаётся прежний durable running/pending record. Exit0 службы или
исчезновение PID никогда не заменяют witness.

## Reboot и ручная сверка

Boot reconcile unit выполняется до новых delivery instances; failed-unit reconciliation использует
отдельную oneshot. Они классифицируют stale queued/running и malformed/missing binding как
`reconciliation_required/outcome_unknown`, сохраняют оригиналы и никогда не вызывают delivery ещё
раз, не очищают intent, не откатывают artifact и не открывают admission. Живой matching unit/proc
не объявляется исчезнувшим по одному lock timeout. Не удаляйте записи ради обхода блокировки.

Сверка — отдельное действие уполномоченного оператора: установить primary request/attempt/generation,
исходный failure и cleanup certainty, фактическую activation/Slurm/NFS/admission identity и
сохранность intent. P23-A не добавляет force/replay/repair bypass. Реальный recovery owner P07,
resource/readback P20, returning worker P22, soft compatibility и native acceptance остаются
отдельными gates.

## Восстановление

P23-A не вызывает archive/restore и не экспортирует старые scientific данные. Будущий drill должен
использовать новый synthetic coordinated PostgreSQL/repository/NFS dataset в изолированных
paths/ports существующей CI VM. Нужен отдельный owning contract socket/port/profile/service и resource
admission; текущие live assumptions state_archive нельзя обходить новым неподдерживаемым argv.

После восстановления файлов и до requalification/activation/admission каждый восстановленный узел
должен выполнить [epoch invalidation hook](artifact-qualification.md#явный-аудит-и-инвалидация).
Полный rollback epoch невозможно вывести из тех же восстановленных файлов. APP rollback не
откатывает PostgreSQL/repository. Эта зависимость не превращает CSS/docs change в обязательную
отмену очереди или backup старого science dataset.
