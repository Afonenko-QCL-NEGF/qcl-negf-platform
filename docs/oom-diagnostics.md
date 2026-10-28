# OOM: источники, привязка и пределы вывода

OOM DTO диагностический: он не меняет grants/Slurm, не возобновляет VM/job и не принимает научный
результат. Exit137, исчезновение VM, слово qemu и matching PID/unit сами по себе OOM не доказывают.

| Cause                    | Первичное свидетельство                                                | Предел вывода                                                                 |
| ------------------------ | ---------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| `native_unit_kernel_oom` | Trusted systemd manager MESSAGE_ID + boot/UNIT/INVOCATION_ID           | Kernel oom_kill затронул unit; victim process/global host pressure неизвестны |
| `native_unit_oomd`       | Отдельный structured unit OOMD MESSAGE_ID                              | Userspace pressure action в unit, не kernel OOM/QEMU victim                   |
| `guest_cgroup_oom`       | Рост exact guest memory.events oom_kill в том же boot/inode/generation | Baseline/reset/reboot не датируют новый OOM                                   |
| `host_kernel_qemu_oom`   | Exact durable QEMU lifetime + kernel victim join                       | Current native profile **unsupported**, runtime не производит этот диагноз    |
| `systemd_oomd`           | Exact bound victim cgroup/lifetime                                     | Current exact QEMU join unsupported; unit event имеет отдельный cause выше    |
| `unknown_vm_loss`        | Running VM перестала наблюдаться без bound kill evidence               | Может быть failure observation/stop/reboot/другая причина                     |
| `unknown`                | Journal indication без доказанного identity/time join                  | VM/victim не угадываются                                                      |

Native v2 `capabilities` раздельно сообщает `systemd_manager_unit_oom` и `kernel_qemu_victim_join`.
Последняя explicit unsupported/`lifetime_protocol_unavailable` для текущих PVE/libvirt profiles.
Internal qmeventd peer PIDFD не durable public lifetime; PVE scope может содержать helpers. Scope
end/MainPID/last sampled start tick не исключают PID reuse и не доказывают QEMU birth/death
interval. Positive literal interval classifier — test oracle, не native producer. Это оставшийся
SOURCE gap полной P31, а не только пропущенная N проверка.

## Structured unit protocol

Supported manager profile — systemd257.13 с exact expected installed version transcript в private
config. Source upstream version сам по себе installed binary/patch mapping не квалифицирует. Native
sampler читает fixed `systemctl --version` и выбранные `show` Id/ControlGroup/InvocationID до/после
journal window; missing/mismatch/cycle drift закрывают current association. Root-protected unit
bindings указывают logical unit/native unit/expected manager executable и optional enrolled VM.
Current VM association требует отдельного valid native VM observation; она не делает killed process
QEMU.

Journal поля bounded: MESSAGE_ID, UNIT, INVOCATION_ID, _PID/_UID/_COMM/_EXE, _BOOT_ID,
__MONOTONIC_TIMESTAMP, __REALTIME_TIMESTAMP, __CURSOR. Нужны manager PID1/root/systemd, exact
configured executable/boot/unit, valid invocation и monotonic time не позже sample.
`_SYSTEMD_INVOCATION_ID` sender не заменяет target `INVOCATION_ID`.

`fe6faa94e7774663a0da52717891d8ef` — unit kernel oom_kill counter message;
`d989611b15e44c9dbf31e3c81256e4ed` — unit OOMD message. Historical invocation сохраняет observed
unit event с vm_id=null, если current association к нему не подтверждена. Event содержит nullable
unit_id/unit_invocation_id, victim_kind=unknown, boot/time/generation/confidence и fixed reasons.
Raw MESSAGE, argv, credentials/private paths не выдаются. Только trusted kernel record без lifetime
остаётся unknown; никакой matching PID/unit fallback не включается.

Journal query finite: current boot, last-N/lookback/after-cursor. Cursor vacuum/error → gap; нет
whole history fallback. Initial/truncated window не объявляется complete. Ring volatile;
restart/reboot/retention не обещают evidence за пределами наблюдавшегося window. Public чтение
демотирует stale/future coverage, сохраняет event timestamp/generation/confidence.

## Остальные native измерения и приёмка

Host MemTotal/MemAvailable — kB×1024, boot проверяется до/после. PVE config memory/balloon — MiB;
status balloon — bytes; mem не выдаётся как RSS/assigned. Scoped QEMU PID/UUID argv/start ticks
проверяются до/после без process scan. Libvirt XML units/UUID explicit, DOCTYPE/ENTITY rejected;
dommemstat actual/rss — KiB, current/max memory отдельно, PID lifetime неизвестен. Services — только
selected fixed properties. Guest cgroup baseline/delta связан с boot/inode/allocation.

Infrastructure owner отдельно проверяет installed source/config/version, manager journal trusted
fields и unit invocation. Literal fields не доказывают настоящий инцидент. Native acceptance
использует harmless own scope или уже согласованный bounded incident evidence; не провоцировать host
OOM/QEMU kill, не останавливать occupied worker, не читать scientific payload ради диагностики.
Collector reserve/ENOSPC — только own qualified allocation по [monitoring](monitoring.md).

| Утверждение                             | Свидетельство                             | Ограничение                                       | Решение             |
| --------------------------------------- | ----------------------------------------- | ------------------------------------------------- | ------------------- |
| Unit OOM можно наблюдать отдельно       | Structured manager message + invocation   | Installed mapping и N pending                     | сохранить           |
| Unit OOM доказывает QEMU victim         | Scope может содержать helpers             | Durable victim protocol отсутствует               | изменить            |
| Guest OOM delta не требует history scan | Exact same-generation counter delta       | Baseline не датирует событие                      | сохранить           |
| Полная host-QEMU attribution готова     | Только sampled birth и literal classifier | Runtime capability unsupported; SOURCE gap открыт | данных недостаточно |
