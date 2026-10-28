# Наблюдение за кластером и best-effort telemetry

P31 foundation добавляет bounded readonly projection и независимый sampler. Это source/API для
будущего P32 backend; Portal/AiiDA/Runner пока к нему не подключены. Наблюдение не выдаёт разрешение
на запуск и не заменяет Slurm, P20 grants, qualification или научную приёмку.

Состояние реализации: source/L fixtures доступны, installed/native проверки отдельно. **Полный P31
открыт:** native producer, доказывающий backing/capacity/scientific reserve для persist, пока
отсутствует. Mount/statvfs показывает реальные доступные байты, но не доказывает эти свойства.
Поэтому installed persist остаётся disabled/unknown, включая отдельный mount; project quota —
explicit unsupported. Это source gap, а не только пропущенная N проверка. Новый filesystem не
является общим prerequisite: followup должен связать уже имеющуюся QCL allocation/native quota с
доказанным backing и резервом. Synthetic capacity oracle в тестах не доступен через config/CLI и не
является native producer.

## Два независимых пути

`qcl-negf-cluster-status --query-base64 TOKEN` запрашивает `qcl.cluster-query.v1` с exact fields:

```json
{ "schema": "qcl.cluster-query.v1", "request_id": null, "cursor": null, "limit": 64 }
```

Token — URL-safe base64 JSON, максимум 8 KiB; limit 1–128. Encoding не даёт полномочий. Отсутствуют
параметры tool/config/file path, SSH target, command, unit, cgroup и caller UID.
Неизвестные/duplicate fields, неверный role, environment-only identity и чужой cursor отвергаются.

Public Python APIs, installed flat ops layout:

```python
from cluster_projection import read_cluster_projection, validate_cluster_projection
read_cluster_projection(*, request_id=None, cursor=None, limit=64)  # -> dict
validate_cluster_projection(document)  # -> тот же dict или ValueError
from native_monitoring import read_native_status
read_native_status(*, cursor=None, limit=64)  # только сохранённый snapshot
from monitoring_runtime import sample_native_status, read_telemetry_storage, maintain_telemetry_storage
```

Readonly poll вызывает только public P20-B `read_resource_projection` и читает один protected P31
cache. Он не запускает sampler, facts/refresh/reconcile, `fleet_health`, qualify, verify-path,
release activation, NFS probe или solver. Нет scan receipt archives/history, сборки и записи cache
на poll. `request_id` передаётся в exact B lookup. B DTO валидируется offline по его опубликованной
schema и сохраняется целиком: P31 не открывает private owner/receipt JSON вторым путём.

Opt-in `qcl-negf-monitor-sample` — root systemd oneshot на existing enrolled host/guest. Он читает
ограниченный native window, обновляет один latest snapshot в `/run/qcl-negf-monitoring`, bounded OOM
ring и cursor. RuntimeDirectory не обещает сохранность после reboot. Ошибка/timeout оставляет
прежний snapshot; дальнейший poll показывает stale/unknown. P11 command engine возвращает
`CommandOutput(str)` с `output_bytes` (stdout + stderr); ошибка — `CommandFailure(record)`. Sampler
учитывает bytes и failed command, сохраняет исходный failure record и не принимает partial stdout.
SSH разбирает bounded typed error только после clean completed failure;
timeout/truncation/неподтверждённый cleanup не дают `stale_cursor` reply. Ни sampler, ни collector
не входят в Before/RequiredBy/PartOf solver/admission/release. Solver не ждёт telemetry
HTTP/cleanup/fsync.

## DTO, время, единицы и cursor

Output `qcl.cluster-projection.v1` описан в
[cluster-projection.schema.json](../schemas/cluster-projection.schema.json). Host row содержит
отдельные `resource`, `native`, `services`, `storage`, `graph_links`, `reasons`. `resource=null`
означает отсутствие чтения B, не нулевой grant. `native=null` означает недоступный observer, а
nullable measurements внутри native — отсутствие соответствующего измерения. Malformed observer
packet даёт partial row и не скрывает остальные hosts. Причины имеют только bounded
`{code,source_id}`; raw stderr, journal MESSAGE, argv, keys и private paths не выдаются.

`read_at` — UTC Unix seconds формирования cluster ответа. B `observed_at` тоже время чтения B;
policy/ledger RAM/H/F/O/pool не является текущим RAM measurement. Native/service/storage
`observed_at` сохраняется со времени sampler; poll его не обновляет. Native host RAM bytes, QEMU RSS
bytes, assigned/balloon bytes, configured bytes, configured maximum bytes и declared grant не
взаимозаменяемы. CPU weight — dimensionless native value; vCPU count/online nullable. Source и
protocol указаны защищённой enrollment, dynamic memory/CPU support из этих чисел не следует.

Freshness threshold берётся из protected config. Future native timestamp — inconsistent; старый
sample/service — stale. Public native read, local observer и cluster aggregate нормализуют
host/VM/OOM/service coverage на копии при каждом чтении; source timestamps, sample generation и
confidence исторических events сохраняются. Unknown/unsupported source не превращается в fresh от
чтения. Stale storage не сообщает persist permission. Wall-clock rollback, boot change и потеря
cursor не становятся «свежим отсутствием событий». Диагностика OOM разобрана в
[oom-diagnostics.md](oom-diagnostics.md).

Outer cursor связывает registry generation, host offset и, при продолжении B page, opaque B cursor,
B state generation и native sample generation. Изменение relevant generation требует restart page
(`stale_cursor`). Переход к следующему host — новое независимое наблюдение, не global atomic
snapshot всех hosts. Journal использует finite lookback/last-N и after-cursor; gap не запускает
полный history scan. Response bytes/count и command/sample deadlines ограничены независимо от
научных workloads. Это bounds telemetry buffers/processes, не campaign CPU/RAM/time/attempt quota.

## Runtime configuration и роли

[monitoring-config.json.example](../examples/monitoring-config.json.example) — только synthetic,
disabled/unqualified fixture, не рабочий inventory. Schema:
[monitoring-config.schema.json](../schemas/monitoring-config.schema.json). Root site готовит
`/etc/qcl-negf/monitoring/service.json` (root-owned, no symlink/writable parents, режим 0644, **без
secret values**). Ключи и known_hosts — отдельные root-protected files. Source/store не содержит
private inventory, credentials, qualification или measured native acceptance.

- `controller`: только выбранные logical targets; native VM/service/cgroup/journal scopes пусты.
- `native_host`: P20 public read плюс local native sampler, exact backend/node/UUID scopes.
- `worker`: guest services/cgroups; hypervisor VM inventory и P20 host reads отключены.

Configured reader/observer — distinct non-root UIDs и accounts, отдельно от grant authority. Local
reader sudo разрешает только fixed read helper; observer — только observer helper.
Sampler/maintenance не доступны через query. Реальная sudo process chain, executable, credentials,
PID birth/cgroup и повторное наблюдение связывают UID; одного `SUDO_UID` мало.

SSH key должен иметь `restrict,command=".../qcl-negf-monitor-ssh-observer"`. Exact original command:
fixed configured marker `.../qcl-negf-monitor-rpc observe TOKEN`. Ни PTY/forwarding, ни inherited
agent/interactive password, ни произвольный command не нужны. P11 strict trust transport
переиспользуется с root-protected preinstalled known_hosts; bytes/key проверяются до и после
roundtrip. Poll не создаёт trust snapshot. Native helper paths должны быть canonical executable
root-owned paths; Nix store поддерживает только узкое P12 sticky-store exception. Generic symlink
или writable tool path не принимается.

`graph_links` задаётся private config: HTTPS, exact same origin, без userinfo/query/fragment.
Оператор передаёт проверенный URL; P31 не угадывает PVE endpoints из VMID и не читает RRD history.
Публичные examples не содержат actual endpoint.

## NixOS и существующий native host

`qclNegf.monitoring.observation.enable` по умолчанию false. Package
[nix/monitoring.nix](../nix/monitoring.nix) co-locates P31 source/schemas и неизменённый published
resource source для P20/P11/P12 imports. Existing dedicated users, UID/config/key binding и forced
SSH key предоставляет site. Module не создаёт enrollment или доверенные credentials.

`observation.sampler.enable` включает только независимый timer/oneshot; `intervalSeconds` — site
setting. `storageMaintenance` — отдельный opt-in root retention unit. Sampler ограничен
MemoryMax/CPUQuota/TimeoutStartSec; его failure не становится зависимостью scientific services. Read
helper не запускает systemd/native commands.

[ansible/monitoring.yml](../ansible/monitoring.yml) — opt-in installation source для existing owned
hosts. Он требует уже установленные Python/jsonschema/referencing и опубликованный P20 source,
устанавливает own helpers/config и **disabled** unit. Не включает timer/service, не
bootstrap/install dependencies, не provision quota/disk, не меняет P20 roles/hooks. Playbook
копирует unchanged P11 protected-file dependency для unprivileged ingress; P20 public read
исполняется privileged observer из прежнего owning source. Apply, UID collisions, canonical tool
paths/permissions и SSH isolation проверяет infrastructure owner отдельно.

## Collector, reserve и retention

Existing optional node exporter остаётся отдельным readonly endpoint. Collector сохраняет
best-effort Vector JSON HTTP `/events`, event bound 16 KiB, memory buffer256/drop_newest/no ack,
service MemoryMax512M/CPUQuota100%. Это техническая telemetry, отдельная от scientific HDF5. Offline
exporter `qcl-negf-telemetry-export`/PyArrow продолжает работать с переданными ему данными.

QCL collector получает отдельный непривилегированный writer `qcl-monitoring`, state directory
`/var/lib/qcl-negf-monitoring-vector`, payload scope `/var/log/qcl-negf-monitoring`. Source
assertion отвергает объединение с unrelated Vector pipelines/journaldAccess. Existing unrelated
Vector instance следует привязать отдельно; P31 не берёт его cleanup scope. Root ExecCondition
разрешает этот file sink лишь после capacity gate и exact destination binding. **В текущем installed
producer gate unknown/false, поэтому collector persistence не стартует.** HTTP/collector absence
допустимо: producer не должен блокировать solver при telemetry failure.

Storage view раздельно показывает actual observed fs maximum/used/available/inodes и отсутствие
backing/reserve proof. JSON `qualified:true`, отдельный mount, свободные байты и age retention не
доказывают reserve. Project quota в этой версии не читается/не создаётся. Shared/thin backing и
scientific-output headroom требуют actual native source producer + review; это остаётся followup.
Новый обязательный filesystem или общий storage framework не вводится.

`read_telemetry_storage` не удаляет файлы. Maintenance при unknown/unqualified/full storage не
prune. В квалифицированной internal fixture ветви retention касается только finite
`events-YYYY-MM-DD.ndjson`: exact scope/owner, lstat/no symlink/hardlink, same inode/dev/mtime/size,
не текущий день, age из root config. Foreign sentinel/symlink остаются, truncated enumeration —
degraded. Runtime `storage.retention_seconds` — authority; старое `collector.retentionDays`
оставлено для compatibility и не является capacity/retention proof. Никакого global journald
vacuum/policy, scientific outputs/checkpoints/receipts или unrelated logs cleanup нет.

## Проверки и оставшиеся gates

L: три owning pytest files и targeted existing telemetry_export/status_journal/P20 projection; Nix
source evaluation `tests/infrastructure/monitoring.nix` на locked nixpkgs. Fixtures проверяют byte
units, identity/cursor drift, malformed/large packets, journal gaps, guest counter generation,
caller/role/token controls, shared/thin/unproved reserve и unrelated sentinel. Они не измеряют
installed/native tools, latency, resource readiness или OOM на реальной VM.

OPEN SOURCE followup: native capacity/backing/reserve producer; proven QEMU birth/death interval для
observed host-OOM join; supported Slurm current-context adapter (v1 его не опрашивает). N отдельно:
actual config/UID/SSH, versions/tool paths, measured assigned/RSS/CPU semantics, repeated-poll no
effects/self-cost, cache/journal continuity и owned safe ENOSPC/collector failure. Никакой real host
OOM/VM loss не провоцируется; full P31 acceptance остаётся pending.
