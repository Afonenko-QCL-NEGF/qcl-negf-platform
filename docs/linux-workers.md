# Первый внешний worker на Linux x86_64

Этот guide описывает путь **Linux x86_64 → libvirt/KVM → NixOS worker** и отдельную квалификацию
Arch/CachyOS adapter на фактическом host. Arch остаётся ОС физического хоста. Application и solver
работают в госте; установка не переустанавливает хост, не меняет его разделы и не создаёт LAN
bridge. Другие дистрибутивы Linux x86_64 требуют отдельной проверки host adapter: одной архитектуры
CPU недостаточно для заявления о поддержке.

Это инструкция подготовки и установки, а не свидетельство выполненного onboarding. Реальные image
bytes, checksum, адрес получения и результаты boot/enrollment/smoke оператор получает вместе с
конкретным выпуском. В этом repository нет универсального готового Linux installer или постоянного
URL на проверенный worker image.

## Что передают оператору

Publisher и оператор связывают один выбранный source graph, release и назначенный worker. До
изменения гипервизора нужны следующие входы:

| Вход          | Что должно быть указано явно                                                                                                                                             |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Выпуск        | Root Git revision и выбранные gitlinks, release manifest, immutable application/solver paths и оба `narHash`; совместимый controller release                             |
| Доставка      | Реальный URL, private file transfer или offline medium; имя файла, размер и SHA256; manifest и его ожидаемый SHA256 по независимому trusted channel                      |
| Image         | Выбранный `arch-worker` QCOW2, producer/build receipt, точные firmware/partition/root bus; для текущего пути кандидат BIOS/legacy/virtio, не UEFI image по предположению |
| Профиль image | `site_bound_private` только назначенному доверенному получателю; `reusable_base` допустим лишь с отдельными content/first-boot evidence                                  |
| Host          | Arch x86_64, KVM, фактические версии QEMU/libvirt, проверенный system URI, оператор SSH agent, существующий wired LAN bridge, storage pool и его свободные bytes/inodes  |
| Guest         | Уникальные MAC/IP/CIDR, gateway/DNS, hostname/Slurm NodeName, VM UUID, root/scratch identities, измеренные vCPU/RAM/диски и host reserve                                 |
| Cluster       | Адреса controller и storage, разрешённые NFS clients, UID/GID научного пользователя, общий jobs path, scratch path, time service, Slurm partition и callback range       |
| Trust         | Независимо подтверждённые SSH host fingerprints, protected enrollment/known_hosts paths, уже доверенные Nix cache/signing keys и scoped sudo policy                      |
| План          | Named target, отдельный private state и saved plan, install/smoke budget, место для исходных логов и порядок сохранения данных при неудаче                               |

Числа из [provider input example](../tofu/arch-libvirt/site-base.json.example) (4 GiB RAM, 2 vCPU,
32 GiB scratch и documentation IP) — synthetic fixture, а не defaults или измерение нового хоста.
RAM, vCPU, корневой диск и scratch задаются явно; исторические потолки одного ноутбука больше не
ограничивают adapter. Учитывайте существующие VM, QEMU overhead, физическую свободную память и место
под image, root overlay, scratch и результаты. Sparse capacity не резервирует реальное место.
Успешная validation не означает capacity admission.

## Профиль первого дополнительного production worker

Экспорт `platform.nixosModules.linuxWorker` включает существующие `default` и `image` modules,
разрешает только worker role и требует обычный release guard, initial application/solver closures и
явные runtime secret units. Он не включает controller, Portal, storage или CI на ноутбуке.
[`local_lab.py`](../ops/local_lab.py) и `mkLocalLab` создают отдельный четырёхмашинный engineering
lab и для этого install не используются. Сам CachyOS не становится Slurm worker.

[Worker flake template](../examples/linux-worker/flake.nix.template) и
[worker configuration](../examples/linux-worker/worker.nix.example) копируются в private site как
`flake.nix` и `worker.nix`. Возьмите accepted root revision и reviewed `flake.lock`, совместимый с
существующим controller, а также действующий `solver-depot.json` с проверенным происхождением.
Template использует Platform и Nixpkgs из того же root input, не выбирает независимый latest.
Замените synthetic hosts/nodes/partition/UID/runtime-secret path согласованными private значениями;
измеренный `RealMemory` должен укладываться в fixed guest grant с OS reserve. Controller получает
тот же node/partition contract в отдельном maintenance packet.

Без build и host mutation проверяется source:

```sh
nix eval --no-update-lock-file --raw \
  "$PRIVATE/worker-site#nixosConfigurations.arch-worker.config.system.build.toplevel.drvPath"
```

Здесь `$PRIVATE/worker-site` — подготовленный private flake, а не recipe для автоматической
установки. Eval не доказывает, что image создан или boot выполнен. Publisher отдельно проходит fresh
builder/resource/ownership checks и дешёвый four-role/strict-nginx preflight существующего
production site перед тяжёлым build. После этого в назначенном image packet строится явный output
`$PRIVATE/worker-site#packages.x86_64-linux.arch-worker-image` через
`nix build
--no-update-lock-file --no-link --json`, с исходными build logs, source и byte hashes.
Это отдельная подготовка artifact, а не скрытый шаг recipient install.

`mkImages` сохраняет текущий QCOW2/legacy partition/GRUB `/dev/vda` contract. Adapter использует
q35/x86_64, VirtIO root+scratch, SATA NoCloud seed, VirtIO NIC на существующем LAN bridge, serial
console и guest-agent channel. Locked Nixpkgs QEMU guest profile предоставляет `virtio_blk`,
`virtio_pci`, `virtio_net` и `virtio_balloon`. Смена firmware на UEFI, CPU architecture или backend
требует отдельного boot/driver evidence. При подготовке нового image не переносите machine-id,
private SSH host keys, enrollment/gate/ready records; отсутствие этих данных подтверждается
content/first-boot проверкой, не одним импортом module.

Guest-agent channel объявляет UNIX source и virtio target `org.qemu.guest_agent.0`, оставляя socket
mode/path за libvirt. В inactive XML libvirt может убрать source mode/path; pinned provider 0.9.9
возвращает отсутствующий mode как `null`. Поэтому module не задаёт `mode = "bind"` или runtime path
и не скрывает drift через `ignore_changes`. Schema/mock plan checks не заменяют actual inactive
apply/readback. Если прежний apply завершился inconsistent result после определения domain, сначала
сохраните и сопоставьте actual UUID/XML/state; не повторяйте apply или замену ресурсов вслепую.

Профиль допускает private site-bound image, но не содержит Munge/SSH private key bytes. Пример
secret unit ожидает отдельно доставленный `/var/lib/qcl-negf-secrets/munge.key` и копирует его в
`/run/secrets` с owner munge, mode 0400. До такой доставки unit и Slurm остаются закрыты. Никаких
keys через `builtins.readFile`, `environment.etc.*.source`, NoCloud user-data, tofu vars/state или
image bundle. Не объявляйте site-bound образ reusable без отдельной проверки.

## Resident memory: сначала conservative reservation

Первый профиль поддерживает только `conservative_reservation`:
`resident_memory.minimum_mib = startup_mib = maximum_mib = memory_mib`. Все значения — полная guest
RAM в целых MiB, не память одного job. Текущая VM остаётся resident и autostart; RAM не возвращается
автоматически в idle. `memory` и `current_memory` в domain равны этому значению. Balloon device
включён с `auto_deflate = off`; наличие устройства и guest driver не разрешает online shrink/grow и
не создаёт active grant protection.

`memory_capability` output явно возвращает `dynamic_supported:false` с причиной
`native_active_grant_not_qualified`; unequal min/start/max отвергаются на plan. Поля
`current_memory`/`devices.mem_balloon` и object-form `os.boot_devices` проверяются против schema
pinned
[libvirt provider 0.9.9](https://github.com/dmacvicar/terraform-provider-libvirt/blob/v0.9.9/docs/resources/domain.md#schema).
Смысл устройства задаёт
[native libvirt contract](https://libvirt.org/formatdomain.html#memory-balloon-device); он не
доказывает physical reservation или сохранность active grant. Отдельный private
[host resource policy](resident-memory-policy.md) задаёт reserves, overhead, owned pool/agreement и
полный resident grant в bytes (MiB × 1048576). Нужны свежие actual host facts и внешнее grant
admission перед apply/новой нагрузкой. `ownership_verified` и `capacity_verified` по умолчанию
false: после review оператор явно подтверждает соответствующий private packet. True означает
acknowledgement, не измерение, не enforceable reservation и не native PASS.

Без защищённого owned pool и учтённых host/foreign reserves новая нагрузка ждёт или отвергается.
Dynamic mode остаётся unsupported до отдельной квалификации host mutation/readback, guest capacity и
запрета shrink ниже active grant на фактическом NixOS image. Не заменяйте physicalRAM на configured
maximum, `MemAvailable` или Slurm RealMemory. Общих campaign CPU/RAM/time/attempt quotas этот
профиль не задаёт; ресурсы измеряют для конкретного install/job packet.

### Где искать artifact и что проверять

У publisher запросите release-specific handoff directory или его byte-identical copy. Контракт
worker distribution предусматривает `worker-distribution.json`, `SHA256SUMS`,
`images/worker-root.qcow2`, nonsecret source/release/build records и recipes. Локальные
assembler/verifier находятся в [worker_distribution.py](../ops/worker_distribution.py); точный
контракт входов и publisher boundary — [worker distribution](worker-distribution.md). Это source
tool для private engineering candidate; его наличие не означает, что реальный image уже подготовлен,
выдан или принят на native host.

Если publisher передаёт такой bundle, он обязан приложить проверку schema/source/ closure/backend
binding и actual delivery receipt. Получатель сверяет полный исходный manifest с independently
supplied hash, затем его file references и `SHA256SUMS`. Используйте verifier из отдельно
полученного доверенного Platform source/hash; не запускайте его копию из ещё не проверенного bundle:

```sh
python3 "$TRUSTED_PLATFORM/ops/worker_distribution.py" verify "$BUNDLE" \
  --expected-manifest-sha256 "$EXPECTED_MANIFEST_SHA256" --timeout-seconds 600
```

`TRUSTED_PLATFORM`, `BUNDLE` и `EXPECTED_MANIFEST_SHA256` — реальные входы handoff, не значения из
guide. Timeout относится только к этой локальной проверке; full-image read требует отдельно
измеренного конечного I/O бюджета до начала операции. Состав checksums должен совпадать с manifest:
относительные payload paths, bytes и SHA256, без `..`, absolute paths, links и устройств. Проверка
checksum не устанавливает доверие к самому manifest и не доказывает boot, отсутствие secrets или
уникальность machine-id/SSH keys. Нет фактического файла/маршрута или build/content receipt —
доставка ещё не готова; не подставляйте выдуманный hash.

Существующий [image producer](../tofu/build-images.ts) выдаёт private `images.json` с `image_path`,
`image_sha256`, `image_bytes` и generated provider inputs. Это не полный distribution manifest. Для
уже подготовленного private site-bound image publisher передаёт эти фактические байты и недостающие
release/source/content свидетельства отдельно. Не публикуйте private inventory, raw preflight,
provider inputs, credentials или protected known_hosts вместе с public templates.

Не запускайте full image build на recipient как скрытую часть установки. Если подходящего образа
нет, publisher готовит отдельный конечный image packet с
[четырьмя role/nginx preflight](nginx-preflight.md). Создание образов и
[image transport](image-transfer.md) имеют свои admission и evidence; имеющийся four-role staging
interface нельзя вызывать с придуманной one-worker map.

## Private site и карантин до первого boot

Используйте [private-site example](../examples/private-site/flake.nix.template),
[host composition](../examples/private-site/hosts.nix) и
[site settings](../examples/private-site/site.nix.example). Hostname mappings должны разрешаться
одинаково на controller, storage, submit host и worker; controller/NFS endpoints не выводятся из
текущей сети автоматически. Общий jobs path — `/srv/qcl-negf/jobs`, локальный scratch —
`/scratch/qcl-negf`, научный UID по умолчанию 3000. Проверяйте фактические UID/GID на NFS, а не
только имена пользователей.

В текущем adapter domain, cloud-init hostname/instance-id и volume names фиксированы как
`arch-worker`/`qcl-negf`; это один предусмотренный worker. Отдельный state не устраняет коллизию с
такими же remote names. Если они уже заняты, остановитесь: параметризация нового имени/второго
worker требует owning adapter change. Не переиспользуйте foreign domain, pool, root или scratch и не
импортируйте их в новый state.

До регистрации гостя держите его вне допуска работ: NodeName либо отсутствует на controller, либо
явно **DRAIN** в согласованной конфигурации controller/worker. Новый worker-only пример содержит
`State=DRAIN`; прежний full-site example содержит `State=UNKNOWN`, поэтому quarantine не возникает
автоматически: задайте начальный DRAIN и собственную причину в private `slurm.nodes` до build/boot.
Не включайте guest submit role. Сохраните `ReturnToService=0`, `JobRequeue=0` и штатный boot
`node-check`; последний проверяет release, но сам по себе не доказывает trusted enrollment.

Root и scratch различаются: libvirt задаёт VirtIO serial `qcl-root` и `qcl-scratch`, worker mount
использует `/dev/disk/by-id/virtio-qcl-scratch`. Форматирование выключено по умолчанию. **Новый
пустой scratch ещё не boot-ready:** до обычного boot требуется отдельно подготовленный ext4
filesystem на доказанно принадлежащем вам volume либо согласованный first-install image с
worker-specific `qclNegf.cluster.initializeBlankScratch = true`. Во втором случае перед первым boot
проверьте actual disk identity/serial и отсутствие чужого filesystem/data; после успешной
инициализации верните `false` в постоянный профиль. Оба варианта — явное native действие в отдельном
packet, а не команда, исполненная этим guide. Не включайте общий example-параметр
`initializeBlankDisks` для уже существующих storage/control: он также связан с их data/state disks.
Существующий scratch, host filesystem, scientific data/state disks не форматируются.

Runtime Munge key доставляется отдельно принятым secret provisioning, совпадает с cluster key и
имеет требуемые owner/mode; не помещайте его в Nix store, image bundle, OpenTofu vars/state или
логи. SSH private keys остаются у оператора. Nix signatures, SSH host verification и TLS
verification остаются включёнными. `ssh-keyscan` без независимой проверки не создаёт trust.

## Подготовить существующий Arch host

Все команды ниже — действия оператора в отдельном согласованном install packet, а не команды,
выполненные при написании guide. `PLATFORM` — абсолютный путь к полному выбранному Platform
checkout, `PRIVATE` — защищённый каталог конкретной установки. В примерах они уже заданы;
`umask 077` защищает новые state, plans и logs.

Подготовьте private Ansible inventory с группой `arch_hypervisors`. В group/host vars укажите
`qcl_cluster_bridge`, непустой `qcl_libvirt_users`, `qcl_storage_directory`, `qcl_guest_memory_mib`,
`qcl_guest_vcpus` и измеренные reserves. Значения памяти, CPU, bridge и storage должны совпасть с
reviewed provider vars. Зависимости берутся из [pinned requirements](../ansible/requirements.yml) в
подготовленном ops environment.

```sh
umask 077
ansible-playbook -i "$PRIVATE/inventory.ini" "$PLATFORM/ansible/arch-libvirt.yml" --check
ansible-playbook -i "$PRIVATE/inventory.ini" "$PLATFORM/ansible/arch-libvirt.yml"
```

Применяйте после review check-output и host admission. Существующий
[playbook](../ansible/arch-libvirt.yml) проверяет именно Arch x86_64, измеренную RAM/CPU, `/dev/kvm`
и выбранный Linux bridge; устанавливает libvirt/QEMU tools, запускает libvirt, создаёт выделенный
storage directory и добавляет только названных пользователей в группу libvirt. Он не обновляет
дистрибутив целиком и не настраивает network manager. Это optional Arch helper, не универсальный
CachyOS bootstrap: он проверяет exact Ansible distribution `Archlinux` и ожидает `libvirtd.service`.
На derivative или modular-daemon host сначала read-only проверьте actual distribution, уже
установленные executable paths и доступный `qemu:///system` socket/units (`virtqemud` либо
`libvirtd`); не запускайте два конфликтующих daemon stack. Отсутствие system libvirt socket или
административного доступа блокирует host preparation/import/boot, но не source/image definition и
mock/eval tests. Не запрашивайте sudo password в логах и не меняйте host network без его владельца.
NAT-only default network не подходит: нужны прямые LAN routes между guest, controller, storage и
submit hosts. Bridge готовится заранее штатным network manager хоста.

### Отдельный LAN address и маршрут к cluster

Адрес физического host остаётся у host/его bridge; worker получает собственные проверенные LAN IP и
MAC. Для guest на LAN с обычным gateway и отдельным маршрутом к cluster private input поддерживает
`additional_routes`:

```hcl
address = "192.0.2.14/24"
gateway = "192.0.2.1"
additional_routes = [
  { to = "198.51.100.0/24", via = "192.0.2.201" }
]
```

Это synthetic адреса. Список по умолчанию пуст; существующий default route остаётся первым и не
меняется. Дополнительные `to` должны быть уникальными canonical IPv4 CIDR с prefix 1–32; новый
default route и IPv6 здесь не поддержаны. `via` — bare IPv4 непосредственно в connected subnet
гостя, отличный от самого guest, network/broadcast. Для этого варианта guest prefix должен быть не
больше 30. Некорректные значения отвергаются до provision. Input не назначает адрес, не доказывает
доступность next hop и не разрешает изменение host network.

NoCloud seed задаёт MAC-matched `cluster0`, address, оба вида routes и DNS через
cloud-init/networkd. Не добавляйте параллельную static NIC configuration в private Nix и не
поддерживайте отдельную копию полного `network_config`: это создаёт второго владельца guest network.
До apply проверьте decoded seed в plan; после first boot и reboot отдельно проверьте effective
address/routes/DNS и trusted SSH.

Маршрут через PVE должен сохранять source IP новых connections в обе стороны. Обычный cluster egress
masquerade может переписать source нового controller→worker callback, даже если NFS established
replies работают. Для явно выбранного external worker существует opt-in
[NAT exception](host-network.md#external-lan-worker-без-переписывания-cluster-source). Он не
открывает firewall ports: нужны actual return routes, NFS client allowlist, принятый Slurm NodeAddr,
interface-scoped daemon/callback ports и time/Munge/UID identity. Пустой список или успешный plan не
означают network acceptance.

Перед boot владелец host проверяет allocation/DHCP exclusion и duplicate address; молчание ARP не
исключает выключенный чужой узел. Quarantine готовят до apply, разрешающего start/autostart: node
DRAIN, без automatic enrollment, jobs и RESUME. Network checks и последующая P11/P22 enrollment —
разные gates.

## Reviewed OpenTofu plan и один named guest

Private `arch-libvirt.tfvars.json` должен содержать поля из
[variables](../tofu/arch-libvirt/variables.tf): system `uri` через существующий SSH agent, LAN
`bridge`, `pool_path`, actual `image_path`/`image_sha256`, root/scratch GiB, RAM MiB, равные
resident min/start/max, vCPU, уникальный MAC, guest CIDR, gateway/DNS, явные desired power flags
`start_worker`/`autostart_worker` и административные public keys. Ownership/capacity acknowledgement
оставляют false до сверки соответствующих actual private facts и policy/grant. Generated input
publisher можно использовать только для того же site/image binding. Provider проверяет локальные
image bytes перед upload. Сохраните полный Platform checkout и его provider lock; копирование одного
`.tf` теряет контекст.

В выбранном `tofu/arch-libvirt` нет backend declaration. Один `TF_DATA_DIR` переносит
plugins/metadata, но не устанавливает private state. Поэтому создайте **новый** защищённый working
directory с копией полного tracked module из exact selected commit (включая `.terraform.lock.hcl` и
все его assets/templates) и явным private backend overlay. `EXPECTED_PLATFORM_REV` берётся из
gitlink выбранного trusted root release, а не из произвольного latest checkout. Следующий блок —
Bash; ошибка или существующий `WORK` останавливает процедуру, без удаления/перезаписи.

```sh
set -euo pipefail
: "${EXPECTED_PLATFORM_REV:?Supply the selected Platform gitlink}"
umask 077
WORK="$PRIVATE/arch-worker-install1"
mkdir -m 0700 "$WORK"
git -C "$PLATFORM" archive "$EXPECTED_PLATFORM_REV" tofu/arch-libvirt | tar -x -C "$WORK"
printf '%s\n' "$EXPECTED_PLATFORM_REV" > "$WORK/platform-source.txt"
MODULE="$WORK/tofu/arch-libvirt"
cat > "$MODULE/qcl-private-backend.tf" <<'BACKEND'
terraform {
  backend "local" {}
}
BACKEND
sha256sum "$MODULE/qcl-private-backend.tf" > "$WORK/private-backend.sha256"
mkdir -m 0700 "$WORK/state"
export TF_DATA_DIR="$WORK/provider-data"
tofu -chdir="$MODULE" init \
  -backend-config="path=$WORK/state/arch-libvirt.tfstate"
tofu -chdir="$MODULE" validate
tofu -chdir="$MODULE" plan \
  -var-file="$PRIVATE/arch-libvirt.tfvars.json" -out="$WORK/worker.tfplan"
tofu -chdir="$MODULE" show -no-color "$WORK/worker.tfplan" \
  > "$WORK/worker-plan.txt"
```

`PRIVATE` должен быть уже защищённым абсолютным каталогом оператора. Git archive берёт только
tracked source указанного commit: чужие local state, `.terraform` и untracked files из checkout в
копию не переносятся. В install receipt сохраните `platform-source.txt`, overlay/hash и selected
root source binding. Это record конкретной установки, не второй revision lock. Overlay добавляет
только local backend; продуктовый `versions.tf` не меняется. Все дальнейшие OpenTofu-команды
используют этот `MODULE`, его же private state и provider metadata. Если target уже имеет
state/владельца, **не создавайте для него новый WORK**: сначала отдельный reviewed
ownership/migration. Новый directory сам по себе не разрешает коллизии remote domain/pool/disk
names.

Проверьте URI/bridge, domain/MAC/UUID, source image hash, root overlay, отдельный scratch и только
новые назначенные ресурсы. Не должно быть удаления, замены или изменения чужих VM/дисков.
Существующий pool и scratch защищены `prevent_destroy`; отказ не исправляется снятием защиты. Для
прежнего state сначала согласуйте ownership/migration, не создавайте параллельный пустой state. При
первой установке в private provider inputs явно задают `start_worker = false` и
`autostart_worker = false`. Это намерение создать выключенное определение, не reservation или native
proof. Значения по умолчанию остаются `true` ради прежнего resident-профиля; новый install не должен
полагаться на них. Пример `site-base.json.example` явно задаёт оба `false`.

После review применяют **этот saved plan**:

```sh
tofu -chdir="$MODULE" apply "$WORK/worker.tfplan"
tofu -chdir="$MODULE" output -json > "$WORK/worker-output.json"
```

Первый apply с обоими `false` создаёт pool, volumes, seed и выключенное определение domain. Он всё
равно меняет storage и libvirt, поэтому ownership/capacity review, image trust и initial quarantine
нужны до apply. На этом этапе capacity acknowledgement относится к подготовке storage/definition и
не заменяет будущий resident grant. Перед boot отдельно подготовьте и проверьте принадлежащий этому
domain scratch, сохраните actual domain UUID, static definition и полный stopped inventory. Штатный
host resource owner выполняет `qcl-negf-resource-admin prepare` по защищённой private policy и
полному maximum всех resident VM; protected native start hook должен быть установлен и привязан к
этому domain. Новые UUID и поля provider inputs сами по себе не создают permit.

Только после фактического cold reservation/hook readback обновите оба desired power flags в
сохранённом private inputs файле до `true`, создайте **новый** saved plan и проверьте, что он
включает только ожидаемый power/autostart transition без замены UUID, root или scratch. Применяют
именно новый plan. Не оставляйте persisted inputs с `false` после намеренного перехода к resident:
следующий apply снова запросит выключение. `start_worker` и `autostart_worker` независимы, поэтому
для явно согласованного временного boot без host autostart можно задать `true`/`false`.

Apply с `start_worker = true` запускает guest, с `autostart_worker = true` включает autostart; флаги
не доказывают host grant или его защиту. Это не dry run. При неизвестном результате сохраните state,
plan, actual domain/disk identities и исходные logs; сначала reconcile, не повторяйте apply/destroy
вслепую. Root replacement должен сохранять проверенный scratch; scratch всё равно не является
резервной копией.

## Первый boot, enrollment и допуск

Оператор сохраняет provider output, console/boot receipts и следующие факты до допуска:

1. Через trusted provisioning/console наблюдает VM UUID, `/etc/machine-id`,
   `/proc/sys/kernel/random/boot_id`, hostname/NodeName и fingerprints SSH host keys. UUID,
   machine-id, host keys и NodeName не должны быть клонами другой машины; cloud-init/image
   declaration не заменяет эту проверку. Новый root не должен наследовать чужие enrollment, gate или
   runtime ready markers; это отдельная content/first-boot проверка publisher и оператора.
2. Проверяет clock/time sync, DNS/host mappings, NFS source/mount и read/write как научный UID,
   отдельно от root (NFS root_squash ожидаем). `findmnt` и `df` должны показывать реальный NFS jobs
   mount и отдельный `/scratch`, а не root fallback. Нужны свободные bytes/inodes на host, scratch и
   NFS с запасом под выбранные работы.
3. Проверяет `slurmd -C` в госте и заносит фактическую topology/CPUs и меньший `RealMemory` с OS
   reserve в согласованный private Slurm config. Сверяет cgroup v2, CPU/RAM/swap enforcement, Munge
   и callback reachability. Daemon ports 6817/6818 недостаточны:
   [network contract](operations.md#identity-networks-and-storage) включает
   `qclNegf.cluster.srunPortRange` (default 60001–60128) на private interface.
4. Привязывает guest/provider/host-key observations к защищённому enrollment v1; существующие
   validators — `enrollment_records`, `validate_enrollment`, `preflight_controller_authority` в
   [application_release.py](../ops/application_release.py). Проверка охватывает полный registry и
   исключает duplicate identities/targets. CLI `enroll` здесь нет: protected registry, trust
   snapshot и pool v2 меняются принятым операторским процессом, не саморегистрацией guest.
5. В maintenance window обновляет согласованные controller/worker Slurm config, NFS client allowlist
   и полный enrolled pool. Во время действующего исследования не перезагружает/reload controller
   ради onboarding и не отменяет чужие jobs. Сверяет текущие immutable app/solver, release ID,
   closure `narHash`, runtime ready и обычный job guard. Процедуры доставки —
   [application CD](application-cd.md).

Штатный controller lifecycle допускает только привязанный, проверенный worker:

```sh
sudo qcl-negf-worker-lifecycle startup --node arch-worker \
  --target "$WORKER_TARGET" --enrollment "$ENROLLMENT"
```

Команду выполняет уполномоченный оператор на enrolled controller; `WORKER_TARGET` и `ENROLLMENT` —
реальные protected inputs. Она проверяет authority/release/health и штатный переход DRAIN→RESUME; не
открывайте gate или не делайте manual RESUME вместо неудавшейся проверки. Для first enrollment не
выдумывают предшествующий shutdown receipt; для возврата существующей машины нужны её реальные
durable lifecycle records. Неизвестный transition сохраняет закрытый допуск и требует
reconciliation.

Обычный enrolled `startup` требует современный полный release envelope с closure hashes; four-field
controller record отвергается до DRAIN/copy. Source/closure/solver-build metadata сохраняется
целиком в snapshot и remote activation/check. Текущий enrollment UUID берётся из защищённого
registry и передаётся P11 qualification на activate и оба check пути, включая повтор уже resumed
boot. При той же permanent identity, enrollment, артефакте и kernel/modules/restore environment
новый boot получает актуальную activation health с повторным использованием solver proof. Check не
восстанавливает missing/corrupt proof и не запускает full verify/self-check. Metadata drift, stale
identity или неизвестный intent не разрешают RESUME. Явный локальный P11 bootstrap остаётся
отдельным путём. Эти source fixtures не заменяют native boot/enrollment/grant acceptance; P20/P14 и
полный P22 onboarding квалифицируются отдельно.

## Конечный smoke и нормальный shutdown/return

После native admission выполните отдельно назначенный non-scientific smoke с ресурсами и timeout из
свежего host/cluster packet. Числа команд ниже иллюстрируют малую synthetic работу; это не общая
campaign quota и не разрешение занять ресурсы без admission. Сохраните job ID, output и исходные
failures.

На controller как `qcl-negf`, из нового принадлежащего ему каталога внутри jobs:

```sh
sbatch --wait --partition=compute --nodelist=arch-worker --nodes=1 --ntasks=1 \
  --cpus-per-task=2 --mem=2G --time=00:10:00 --output=batch.stdout --wrap=hostname
timeout 90s srun --partition=compute --nodelist=arch-worker --nodes=1 --ntasks=1 \
  --cpus-per-task=1 --mem=128M --time=00:01:00 hostname
```

Здесь `compute` должен быть реально согласованной partition. Эти проверки повторяют форму
[существующего VM smoke](../tests/slurm-vm.nix); подтвердите actual NodeName и worker→submit
callback, а не только exit code. В том же выделенном smoke scope создайте tiny marker на настоящем
worker scratch, скопируйте в принадлежащий этому smoke NFS каталог и независимо сравните
bytes/SHA256 с controller. Сохраните stat, mount/source и readback: один `hostname` не проверяет
staging. Эта инженерная copy не заменяет acceptance Runner checkpoint/result-staging и не читает
научные массивы. SCBA, Poisson, solver benchmarks и scientific acceptance в этот smoke не входят.

Для выключения guest сначала используйте controller lifecycle и дождитесь его
`safe_to_shutdown:true` для данного NodeName/boot/enrollment:

```sh
sudo qcl-negf-worker-lifecycle shutdown --node arch-worker \
  --target "$WORKER_TARGET" --enrollment "$ENROLLMENT"
```

Только затем выполняют обычный shutdown назначенного guest, сохраняя host/network до подтверждения.
Нормальный shutdown может ждать всех владельцев работ; истечение smoke budget не разрешает force
poweroff. Если ожидание выходит за packet, сохраните состояние и передайте оператору, не отменяйте
чужое исследование. После нового boot той же permanent machine повторяют штатный `startup` с
protected enrollment. Fault/power-loss recovery и сохранность staged результатов проверяются
отдельно; не имитируйте их на занятом worker без отдельного scope.

## Обновление, rollback и чистая переустановка

Обновление следует [application CD](application-cd.md) и барьеру I14 для всего pool. Оператор
сначала вручную останавливает принадлежащие ему AiiDA workflows и retries, затем соответствующие
Slurm jobs, сохраняет доказательство пустого pool и останавливает всех workers. Только после этого
выполняются штатные deliver → fleet health → admission. Новый image/toolkit и успешный один worker
не разрешают обойти этот барьер. Во время занятого исследования onboarding, controller/NFS reload и
новая activation ждут отдельного безопасного maintenance window.

Rollback требует exact previous application/solver closure identities и совместимого OS/runtime, а
также повторного whole-pool health/admission. Откат OS не откатывает PostgreSQL, AiiDA repository
или schema. При несовместимом DB/state schema требуется отдельный согласованный isolated restore и
проверка согласованности dataset; не запускайте старое приложение поверх несовместимых данных.

Чистая переустановка заменяет только назначенный root по измеренной disk identity. Постоянный
отдельный scratch и data сохраняют свои serial/ownership и `prevent_destroy`. После первого
форматирования доказанно пустого scratch выключите format flag; не переносите initial format в
routine reinstall. Новые UUID/machine-id/SSH host keys снова проходят quarantine и protected
enrollment. Это процедура, а не выполненный rollback/reinstall receipt; native проверки остаются
отдельными клетками.

## Что считается завершённым

| Утверждение                             | Свидетельство                                                                                                                              | Ограничение                                                                  | Решение                              |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------- | ------------------------------------ |
| Источник и доставка известны            | Exact source/release/closure records, manifest hash, image bytes/SHA и recipient readback                                                  | Checksum не доказывает guest boot                                            | сохранить binding                    |
| Linux worker profile проверен по source | Реальная NixOS evaluation в `tests/test_linux_worker_profile.py`; pinned-provider mock plans в `tofu/arch-libvirt/tests/worker.tftest.hcl` | Fixtures synthetic; image build/boot и actual host grants отсутствуют        | сохранить раздельные gates           |
| Arch/libvirt host подходит              | Measured versions, KVM/bridge/capacity, reviewed saved plan                                                                                | Другие Linux distros не проверены этим adapter                               | дополнительно измерить новый backend |
| Resident RAM защищена на actual host    | Private administrator policy, полный fixed grant, native readback и guest OS reserve                                                       | Balloon device/acknowledgement не доказывают grant; dynamic пока unsupported | дополнительно измерить               |
| Worker допускается к работам            | Unique trusted identity, protected enrollment, DRAIN→health→owning admission, current release/cgroups/NFS                                  | Ни boot, ни source tests не заменяют native receipt                          | сохранить карантин до evidence       |
| Onboarding smoke выполнен               | Tiny batch+srun, scratch→NFS/readback, normal shutdown/return receipts                                                                     | Не научная сходимость и не full fault/restore acceptance                     | сохранить раздельные gates           |

Без actual artifact location/checksum/build/content/first-boot и target receipts статус
соответствующей клетки остаётся `not_measured` или `blocked`; этот guide не присваивает ей PASS и не
заявляет готовность Proxmox/Hyper-V. Их installation/native gates отдельны.

### Native NetworkManager: PORT-first DHCP и ограниченный guard

[Отдельный playbook](../ansible/networkmanager-bridge.yml) создаёт **только private staging
bundle**. Он не загружает profiles, не активирует connections и не меняет работающую сеть.
Потребуются существующие Python 3 с GI/libnm и NetworkManager 1.58.x; установка зависимостей в
playbook не скрыта. На целевом host конкретная версия и поведение Reapply ещё требуют native
qualification. Эта SOURCE/L реализация не является разрешением установки или boot worker.

В private inventory создайте `qcl_nm_bridge_hosts` и явно задайте `qcl_nm_stage: true`, новый
`qcl_nm_stage_directory: /var/lib/qcl-negf/nm-bridge-stage/<packet>`, `qcl_nm_bridge_name`, разные
`qcl_nm_bridge_uuid` и `qcl_nm_port_uuid`, `qcl_nm_permanent_mac`. Например, synthetic имя
`br-example`, UUID `11111111-1111-4111-8111-111111111111` и `22222222-2222-4222-8222-222222222222`,
MAC `02:00:00:00:00:01`. Real inventory в Git не хранится. Запуск `--check` проверяет inputs и
свободный stage; обычный opt-in запуск только записывает bundle. Существующий stage не заменяется.
HOME, VPN, Docker и другие profiles не являются inputs для записи.

PORT сопоставляется permanent MAC без имени USB interface; `autoconnect=true`, priority100,
retries1, controller — точный UUID MASTER. У PORT нет IPv4/IPv6 settings. MASTER имеет
`autoconnect=false`, `autoconnect-ports=0`, IPv4 DHCP с явным client-id `01:<permanent MAC>`, IPv6
auto, metric600, DHCP timeout30. Поэтому пустой мост не выбирает stale static host IP при reboot, а
IP/lease изменения обслуживает NM. Scoped `ignore-carrier=no` — дополнительная защита; carrier моста
с TAP не доказывает наличие физического uplink. Priority/timeout и native boot selection принимаются
только в отдельных native cases.

Минимальный post-event dispatcher вызывает один bounded guard для `up`, `down`, `reapply`,
`dhcp4-change`, `dhcp6-change` только на собственном MASTER или physical NIC с указанным permanent
MAC. Аргументы события — hints; решение всегда использует actual owner/kernel state. Guard не
активирует HOME/PORT, не down/delete bridge, не трогает VM/TAP и не запускает monitor daemon. Он
меняет только applied IPv4/IPv6 MASTER и runtime metadata ключ
`user.data["org.qcl-negf.bridge-guard.operation"]`, сохраняя остальные settings и user keys. Saved
profiles не переписываются. При HOME либо пропавшем физическом carrier собственный L3 отключается;
возвращение PORT позволяет restore только доказанной собственной suspension того же saved profile.
Просто `disabled` не даёт authority. DHCP/up с уже правильным profile — NOOP.

Будущий Root install packet должен под общим lock `/run/lock/qcl-negf-nm-bridge.lock` установить
ровно следующие owned объекты, сохранив rollback прежнего содержимого/отсутствия каждого:

| Staged source              | Будущий installed path                                           | Owner / mode    |
| -------------------------- | ---------------------------------------------------------------- | --------------- |
| `linux_bridge_nm.py`       | `/usr/local/libexec/linux_bridge_nm.py`                          | root:root /0600 |
| `qcl-negf-nm-bridge-guard` | `/usr/local/libexec/qcl-negf-nm-bridge-guard`                    | root:root /0700 |
| `bridge.nmconnection`      | `/etc/NetworkManager/system-connections/qcl-bridge.nmconnection` | root:root /0600 |
| `uplink.nmconnection`      | `/etc/NetworkManager/system-connections/qcl-uplink.nmconnection` | root:root /0600 |
| `bridge-device.conf`       | `/etc/NetworkManager/conf.d/90-qcl-bridge.conf`                  | root:root /0600 |
| `dispatcher-guard`         | `/etc/NetworkManager/dispatcher.d/90-qcl-bridge-guard`           | root:root /0700 |
| private binding            | `/etc/qcl-negf/nm-bridge/binding.json`                           | root:root /0600 |

Непроверенное существующее имя/path не считается owned. Installer должен проверять symlink/owner
всех parent directories и существующих destinations до любой записи; staging playbook этим installer
не является. Новые private directories `nm-bridge` имеют0700. Guard runtime:
`/var/lib/qcl-negf/nm-bridge/state.json` — один WAL, `/run/qcl-negf/nm-bridge/pending.json` —
coalesced wake nonce, файлы0600. WAL записывается atomic replace с fsync файла и parent **до** RPC.
Lock installer и guard общий. Не смешивайте profiles из разных packets и не меняйте installer/source
во время handler. Публикация dispatcher раньше module/binding/profiles запрещена.

Binding — JSON с точными ключами: `schema: "qcl.nm-bridge.v1"`, `bridge_name`, `bridge_uuid`,
`port_uuid`, canonical lowercase `permanent_mac`, exact `nm_version`, `source_sha256` module и
`profile_sha256`, `port_profile_sha256`. Последние — `profile_hash(from_variant(settings))` **actual
saved GetSettings** в принятой версии NM: исключается только `connection.timestamp`. Нельзя считать
hash текста keyfile эквивалентным native settings hash. Получение и review этих private hashes,
отсутствие runtime operation token в saved profile и явный rebind при source/profile upgrade входят
в будущий installation packet. Привязка не строится из старого WAL/версии state. `GetSecrets` не
используется.

`--status` читает fresh NM/kernel/per-link DNS и marker, не создавая directories, lock, wake или
receipt и не выполняя repair. Только `worker_ready=true` означает свежий локальный predicate; exit0
включает также absent/suspended и сам по себе готовность не означает. Этот predicate не сертификат
полного DNS/Internet, VM, memory admission или научной приёмки. `--reconcile` — Root one-shot с
actual unique D-Bus destination, nonzero applied-version CAS и флагом `preserve-external-ip=1`; в
SOURCE/L проверках он допускается только с injected fake adapter и private fixture directories.
Реальный запуск здесь не выполнен.

WAL связывает operation nonce, boot/bus/NM unique-owner epoch, source/binding/profile/object
identity, actual physical owner, before version/hash и exact typed payload. Void Reapply reply не
означает settlement. Потеря reply/cancellation оставляет unresolved marker; accepted state требует
своего nonce, payload и ровно before-version+1. Собственная suspension не наследуется после epoch,
profile/source edit или внешнего version jump. Late older CAS ограждается fresh runtime token с
новой CAS version, а не no-diff Reapply. Не более2 RPC за wake; максимум один unresolved
predecessor. Перед RPC проверяется actual physical owner, независимо от версии MASTER; после RPC
проверяются owner, собственный L3, kernel addresses/routes/rules, NM per-link DNS и сохранность
L2/foreign. Изменившийся attachment PORT между отдельными wakes допускает новое current-state
решение; изменение L2/foreign во время операции закрывает её результат без попытки исправить чужую
сеть.

Если post-RPC readback уже обнаружил нарушение protected L2/foreign, guard сохраняет в WAL
`invariant_failure` с operation/context и hashes ожидаемой/наблюдаемой проекции. Этот факт остаётся
closed при следующих wakes и RO status; ни новый owner, ни возврат MTU, ни новый dirty nonce не
заменяют его свежим baseline. Это относится к уже обнаруженному нарушению собственной операции;
здоровый физический attachment change между отдельными wakes сохраняется. Automatic repair чужой
сети или общий sticky-error framework не добавляются.

Сброс этого факта — отдельный explicit Root rebind под тем же lock, с сохранением исходного WAL и
доказательства нарушения. Сначала нужны выясненная причина и принятая текущая L2/foreign projection,
исключённые unresolved/late CAS, actual saved/applied/profile/source/epoch binding и fresh native
activation/readback, соответствующий принятому profile. Лишь затем Root создаёт новый private
baseline без authority старой failed chain. Обычный `--reconcile`/restart/silent удаление marker
rebind не выполняют; нового автоматического reset command нет. Эта SOURCE/L правка rebind или native
действия не исполняет.

Own address identity сопоставляется с NM только после usability checks: tentative, dadfailed,
optimistic, deprecated, expired lifetime либо неподдержанный state/flag закрывают settled.
Projection сохраняет эти признаки, нормализуя лишь положительные lifetime countdowns; zero lifetime
не маскируется как обычный отсчёт. Healthy IPv6/DHCP и стандартные безопасные address flags
сохраняются.

Каждый relevant event до попытки lock публикует новый dirty nonce. Consumer запоминает generation
**до** readback. Busy owner не стирает notification; pending/unknown закрывает ready. Следующий NM
event либо отдельный Root one-shot подхватывает marker. Без нового wake фонового исполнения нет.
Статус не обещает liveness после последнего busy event. Это одноразовый guard, не служба.

Отдельные native gates перед installation/qualification: local console и checkpoint rollback, actual
typed Reapply/version/token, DHCP stage3 и IPv4/IPv6 DNS removal/restore, ручной HOME, lease/IP
change, reboot/NM restart, USB replug, physical loss при живом TAP, MTU/VLAN/TAP/foreign invariance,
crash/unknown/late CAS/busy pickup. Projection консервативна: unsupported native properties,
extra/unattributed bridge address, policy-route attributes или неизвестная own rule дают closed.
Маршруты и DNS других links не flush/repair; global resolver byte equality и DNS доступность не
сертифицируются. Результаты fake/offline tests не заменяют эти cases.
