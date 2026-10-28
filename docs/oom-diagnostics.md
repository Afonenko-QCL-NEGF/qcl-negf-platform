# OOM: источники, привязка и пределы вывода

OOM DTO служит диагностике. Он не меняет grants/Slurm state, не возобновляет VM/job и не принимает
научный результат по exit code. `137`, исчезновение VM и слово qemu сами по себе не доказывают OOM.

| Cause                  | Необходимое первичное свидетельство                                                 | Что остаётся неизвестным                                      |
| ---------------------- | ----------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| `host_kernel_qemu_oom` | kernel OOM kill + enrolled VM/PID birth и доказанный interval в том же boot         | Guest memory/cgroup cause и scientific acceptance             |
| `guest_cgroup_oom`     | рост exact guest allocation `memory.events:oom_kill` в том же boot/inode/generation | Только baseline без previous snapshot не датирует OOM         |
| `systemd_oomd`         | native oomd event + exact bound target cgroup/VM                                    | Это отдельная userspace pressure action, не kernel OOM        |
| `unknown_vm_loss`      | ранее running VM больше не наблюдается и нет связанного kill evidence               | Это может быть observation failure/stop/reboot/другая причина |
| `unknown`              | событие видно, но identity/time/scope join не доказан                               | Не подменяется guessed VM identity                            |

Event содержит event_id, cause/scope, nullable
VM/workload/host_boot_id/guest_boot_id/time/generation, source_id, confidence и bounded reasons. Raw
journal MESSAGE, чужие argv/PID command lines, credentials и log storage paths не выходят наружу.
Kernel и oomd conflict в одном bound interval имеет confidence `indication`; отсутствие данных —
`unknown`.

## Реализованный native foundation

Host `/proc/meminfo` MemTotal/MemAvailable нормируется kB×1024, boot читается до/после. PVE config
memory/balloon — MiB×1048576; status balloon — bytes; `status.mem` не используется как RSS или
assigned bytes. Scoped PVE PID читается без /proc scan, UUID argv и start ticks проверяются
до/после. Libvirt XML units разбираются явно, UUID сверяется, DOCTYPE/ENTITY отвергается.
`dommemstat actual` и `rss` — KiB×1024; currentMemory и maximum остаются отдельными полями. Libvirt
PID/birth здесь не измеряется; vCPU online/hotplug completeness не предполагается.

Exact native protocol transcript/version и enrollment задаёт protected site config. Несовпадение
version даёт failure, missing qualification — unsupported. Services читаются только allowlisted
`systemctl show` с fixed property list. Guest cgroup — protected exact path, boot/inode/ctime и
allocation generation; baseline/counter reset/recreation не создаёт нового OOM event.

Journal query — current boot, kernel transport/oomd service, finite last-N и lookback +
after-cursor. Cursor vacuum/error даёт `journal_gap`, без полного history fallback. Initial/gap
window не объявляет всю историю полной. Ring bounded, volatile snapshot теряется после reboot;
telemetry retention не обещает incident evidence вне наблюдавшегося window.

**В v1 runtime нет producer доказанного PID death interval.** Последний sampled start tick не
исключает reuse PID между samples. Поэтому runtime не передаёт такой guessed interval как proof в
journal classifier: host QEMU kernel/OOMD события остаются identity-unbound/unknown, VM
disappearance — unknown_vm_loss. Classifier observed/indication ветви покрыты literal fixtures с
явным interval; это не N acceptance и не автоматический диагноз настоящего инцидента. Нужен узкий
owning followup с native interval source; reading private P20 receipt или whole process/history scan
не заменяет его.

## Безопасная последовательность N acceptance

Infrastructure owner сверяет installed source с опубликованным freeze и actual protected config:
logical host/VM UUID, machine/boot, native tool/version, reader/observer UID и SSH restrictions.
Затем на owned disposable scope измеряет byte mapping, repeated-poll latency/no effects, journal
cursor/gaps и guest cgroup identity. Failure-control collector ENOSPC требует отдельного owned
telemetry allocation и backing/reserve producer; чужие/shared logs не используются как fixture.

Сопоставление настоящего OOM допустимо по уже согласованному bounded incident evidence или
безопасному disposable fixture. Synthetic logs не доказывают runtime. Не провоцировать host OOM,
QEMU kill, stop occupied worker или потерю старых scientific outputs ради этой проверки.

| Утверждение                                              | Свидетельство                             | Ограничение                                | Решение                |
| -------------------------------------------------------- | ----------------------------------------- | ------------------------------------------ | ---------------------- |
| RSS/balloon/config/grant можно сравнивать как одно число | Разные native byte sources и B ledger     | Разная семантика и timestamps              | изменить               |
| Исчезновение VM доказывает kernel OOM                    | Только last-seen/observation loss         | Cause не связан первичным evidence         | данных недостаточно    |
| Guest OOM delta доступна без history scan                | Exact same-generation memory.events delta | Baseline/reboot/reset не датирует событие  | сохранить              |
| Host-QEMU diagnosis полностью реализован                 | Literal classifier + sampled PID birth    | Proven death interval producer отсутствует | дополнительно измерить |
