# Завершение native memory mutation

P20-C добавляет source producer для **успешно завершившегося синхронного native вызова**. Это
отдельный gate от достижения balloon allocation, guest admission, Slurm/cgroup limits, завершения
workload и сохранности outputs. Public API P20-B и read-only projection P31 сохранены. Fixed
full-max reservation не требует C config/profile/helper. Hyper-V здесь не реализован.

## Root boundary и данные

Динамический native-host factory читает дополнительный root-protected `native_cleanup` в
существующем `/etc/qcl-negf/host-resources/service.json`:

```json
{
  "schema": "qcl.host-resource-native-cleanup-config.v1",
  "helper": "/usr/local/libexec/qcl-negf-resource-native-exec",
  "qualification": "/etc/qcl-negf/host-resources/native-mutation-qualifications.json",
  "protocol_id": "pve-local-put-balloon-v1"
}
```

Только четыре точных поля. Второй protocol — `libvirt-local-setmem-v1`. Клиент передаёт demand и
native workload/build identity по P20-B; пути, argv, профили, proof и cleanup flags не принимаются.
Новый helper принимает только hex mutation UUID, только root и только как прямой дочерний процесс
актуального root worker с проверенными PID birth, systemd InvocationID и cgroup. `SUDO_UID` этого не
доказывает. Helper выполняет `execve` существующего CLI; новый supervisor, daemon, scheduler,
ledger, retry loop или native cancel не вводится. Выполнением и очисткой своей process group владеет
существующий P11 command engine через `NativeCommandRunner`.

Файл qualification — exact `{schema, profiles}` версии
`qcl.host-resource-native-mutation-qualifications.v1`. Непустой список содержит профили версии
`qcl.host-resource-native-mutation-qualification.v1`, с уникальным `binding.vm_id`. Каждый intent
выбирает точный current RuntimeBinding, protocol, host/owner/boot и policy digest. Профиль другой VM
или private `qualified: true` не подходит. Exact shapes:
[schema](../schemas/host-resource-native-cleanup-witness.schema.json), включая `$defs` для config,
profile, bundle, dispatch и witness;
[synthetic packet](../tests/fixtures/host-resources/synthetic-native-cleanup.json). Все значения
packet вымышленные; он не является installed qualification.

`source_ids` содержит `cli`, `client`, `driver`, `protocol` — `{path, sha256}` — и exact `support` с
reviewed source hashes из `PROTOCOL_SOURCE_DIGESTS`. Источники сравниваются со свежими файлами, а
peer — с актуальными kernel/QEMU/backend facts. PVE support обязан указывать настоящие
`/usr/share/perl5/PVE/...`; скопированный исходник не подтверждает установленный PVE. Для libvirt
`driver` обозначает исполняемый daemon; дополнительно проверяется hash его **running**
`/proc/PID/exe`. Client/driver/library package-to-source mapping и RPC semantics входят в native
qualification; наличия upstream files и совпадения версии недостаточно.

Общий trust validator P11/P12/B проверяет root ancestry и исполняемые пути. Для точного `/nix/store`
переиспользуется принятая P12 store boundary, включая sticky root; произвольные writable ancestors
не разрешены. Private JSON остаётся вне store, root-owned, без symlink/hardlink или group/world
write. Производственные Sources нельзя передать через job packet; injected Sources в Python tests
явно synthetic.

## Durable ordering и witness

Host state/archive остаются **v3**. UUID grow и shrink различаются. Перед native dispatch controller
сохраняет полный округлённый charge, UNKNOWN, UUID, native context и
`native_cleanup_confirmed=false`. Затем root worker O_EXCL создаёт и fsync-ит attached
`native-mutations/<UUID>.intent.json` с original intent, **original before_revision** и worker
birth. Helper сравнивает его со свежими facts и текущим UNKNOWN. Изменённую CAS revision нельзя
заменить новым чтением. Перед exec helper O_EXCL/fsync создаёт `<UUID>.json` в фазе `CLAIMED`.
Prepared/claimed intent после crash не переисполняется.

Witness хранит nested `intent`, `intent_sha256`, phase, worker/CLI birth, cgroup, exact source_ids,
native_peer, claimed_at, terminal_at, local_cleanup_confirmed и result_sha256. `CLAIMED` не является
proof. `RETURNED_SUCCESS` записывается атомарно с fsync только после qualified synchronous return,
P11 owned cleanup, свежего отсутствия exact CLI/descendants и backend lock completion. Текущий
worker может ещё жить; cgroup должна содержать только его, без nested cgroups. Завершившийся worker
требует отсутствия его прежнего birth и cgroup. Чужие процессы/VM/locks не завершаются и не
меняются. Эти bounded metadata reads не ограничивают количество завершённых resource requests.

Proof reader сопоставляет latest request/UUID/operation/old+target/full binding/boot/policy/context,
original dispatch и digest профиля, затем повторяет свежие source/peer/owned absence checks. Только
после этого facts provider производит существующий `NativeCleanupEvidence`. RAM readback никогда не
создаёт cleanup proof. `validate_state` не усыновляет старую v3 строку с локальным cleanup=True без
exact C witness; charge и idempotency сохраняются, допуск блокируется. No-op resize остаётся
metadata-only: mutation_id=None, без dispatch/claim. Status/projection witness не открывает, не
обновляет факты и не пишет store.

## Выбранные native protocols

| Backend | Qualified healthy chain                                                                                                                                                                          | Дополнительные отказы                                                                                                                                             |
| ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| PVE     | `pvesh --noproxy set /nodes/<node>/qemu/<vmid>/config --balloon <MiB> --digest <original> --output-format json`: direct local PUT → updatefn под lock_config → matched QMP reply → return/unlock | Любой pending/delete, cloudinit/unknown hotplug, shares≠0, disabled balloon, другой digest/source/node/QEMU birth; занятый или неизвестный native config lock     |
| libvirt | Fixed root-profile `qemu+unix:///system?socket=<percent-encoded protected socket>`; `virsh setmem <UUID> <KiB> --live --config` → synchronous RPC/monitor response → EndJob → return             | Другой endpoint/daemon/socket inode/InvocationID/birth/source; отсутствующий точный listening FD в текущем root daemon; иной namespace/URI; неоднозначный маршрут |

PVE lock проверяется nonblocking на **существующем** root-protected inode
`/var/lock/qemu-server/lock-<vmid>.conf`. Файл не создаётся, не удаляется и чужой lock не снимается.
PUT не даёт UPID; PVE POST/fork_worker и remote proxy здесь не квалифицируются. UPID не
придумывается по VM/time/user. QMP timeout может оставить server tail; свободный lock и подходящая
RAM этого не опровергают.

Libvirt обычный `qemu:///system` может автоматически выбрать другой существующий socket. Поэтому C
использует **один и тот же explicit protected endpoint для inventory, readback и mutation**. URI
составляется только из двух разрешённых root-profile sockets; server/port/session/command/прочие
query параметры запрещены. Native namespace остаётся system; старые constructor callers сохраняют
`qemu:///system` default. Upstream `remote_driver.c` проверяет explicit sockname до
`remoteGetUNIXSocket`; `remote_sockets.c` показывает AUTO selection и отсутствие autospawn для root
system URI. Root-owned listening socket связывается через `/proc/net/unix` и bounded daemon fd
metadata с actual daemon PID birth. Код не выполняет domain abort/job cancel: такие команды не
идентифицируют exact setmem RPC.

## Failure/reconcile

| Ситуация                                                                           | Состояние и разрешённое продолжение                                                                            |
| ---------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| Успешный qualified return и terminal witness, RAM ещё старая                       | Полный charge; GROW/SHRINK_UNKNOWN до полного assigned readback. Без повторного native call                    |
| Crash после terminal witness, до owner metadata save                               | Durable UNKNOWN+полный charge; fresh exact witness/cleanup + readback позволяют existing reconcile без replay  |
| Потерян **server reply**, timeout/disconnect/nonzero/CLI exit без terminal witness | UNKNOWN+cleanup=false и полный charge. RAM, CLI code0, inactive unit, lock-free или elapsed time не дают proof |
| Живой owned descendant / busy native lock / неподтверждённый source/peer           | Hold; никаких foreign kills, автоматического shrink/release или TTL                                            |
| I/O до dispatch/claim                                                              | Native вызов не начинается. Повторное использование prepared/claimed intent запрещено                          |
| Proof/journal I/O после native                                                     | Полный charge. Original native exception/record остаётся primary; secondary journal error не маскирует его     |
| Reboot/config/image/kernel/QEMU/backend change                                     | Qualification и exact proof перестают подходить; fail closed                                                   |

**Recovery после lost server reply остаётся обязательным OPEN source/operational gate P20.** C не
имеет exact server-side terminal producer для такого случая и не предлагает admin true override.
Нужен отдельный reviewed recovery contract; текущий hold является безопасным отказом, а не успешным
fault recovery. Отсутствие producer и неизвестная native capability — разные состояния.

## Приёмка и установка

| Gate                              | Что есть в source                                                                                                                       | Что ещё требуется                                                                                                                                                                                      |
| --------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| L healthy sync producer           | PVE/libvirt codec, owner/proof/source/peer checks, immutable dispatch, packaging source, synthetic fault/reload/multi-workload fixtures | Independent review и publication                                                                                                                                                                       |
| N installed protocol              | Строгий opt-in dynamic assembly                                                                                                         | Root installation/package-to-source mapping; actual daemon/CLI/OS/image/balloon readback/floor protection qualification                                                                                |
| N low-idle/pressure/startup       | Existing P19 budget и B startup/full-floor guard сохранены                                                                              | Grow grant до guest Slurm/MemAvailable rejection, свежий полный assigned readback, protected aggregate floors, Slurmd deadlock/pressure checks без host OOM; foreign bounds и admin capacity agreement |
| SOURCE lost-server-reply recovery | Durable UNKNOWN/полный charge/без replay                                                                                                | Отдельный обязательный terminal/recovery producer contract                                                                                                                                             |
| SOURCE completion/build/launch    | B public boundary сохранена                                                                                                             | Owning P04/P07 output/staging completion producer и consumer wiring; C их не реализует                                                                                                                 |

Nix package и opt-in Ansible source устанавливают root helper рядом с прежним command engine; ни
sudo rule, forced SSH role, новый unit, install/start/VM mutation самим C tests не добавлены.
Ansible `qcl_resource_dynamic=false` по умолчанию; explicit true копирует внешний reviewed bundle,
не создаёт qualification. Service config должен указывать фактические installed helper и private
bundle paths. Source Nix eval не выполняет build/install. Первый fixed lane не закрывает full
dynamic P20.

Для Nix `native_cleanup.helper` должен указывать на canonical regular executable
`${hostResources.nativeExec}/bin/qcl-negf-resource-native-exec` (package passthru), а не symlink из
symlinkJoin или `/run/current-system/sw`. Strict store reader намеренно отвергает symlink
descendants. C не добавляет автоматическую запись private config в NixOS module; выбор конкретного
installed canonical output и внешний reviewed bundle остаются административным installation gate.

PVE native lock использует отдельную **фиксированную** descriptor boundary: `/`, `/var`, `/run`
root-owned и без writable ancestors; единственный compatibility link — root-owned
`/var/lock -> /run/lock`. `/run/lock` может быть root sticky writable directory, но его child
`qemu-server` обязан быть root-owned non-writable directory, без symlink. Sticky semantics защищает
именно этот root child. Lock открывается относительно held child fd с O_NOFOLLOW/O_NONBLOCK, без
O_CREAT; требует regular UID0 non-writable single-link inode. До успешного возврата повторно
сверяются held/named ancestor device+inode, ownership/mode и compatibility link. Другой link,
отсутствие sticky у writable lock root, writable child, подменённый inode, отсутствующий lock или
foreign contention дают hold. Это не расширяет общий P11/P12/B trust validator и не делает lock-free
самостоятельным доказательством завершения native команды.
