# Первый внешний worker на Linux x86_64

Этот guide описывает существующий путь **Arch Linux → libvirt/KVM → NixOS worker**.
Arch остаётся ОС физического хоста. Application и solver работают в госте; установка
не переустанавливает хост, не меняет его разделы и не создаёт LAN bridge.
Другие дистрибутивы Linux x86_64 требуют отдельной проверки host adapter: одной
архитектуры CPU недостаточно для заявления о поддержке.

Это инструкция подготовки и установки, а не свидетельство выполненного onboarding.
Реальные image bytes, checksum, адрес получения и результаты boot/enrollment/smoke
оператор получает вместе с конкретным выпуском. В этом repository нет универсального
готового Linux installer или постоянного URL на проверенный worker image.

## Что передают оператору

Publisher и оператор связывают один выбранный source graph, release и назначенный
worker. До изменения гипервизора нужны следующие входы:

| Вход | Что должно быть указано явно |
| --- | --- |
| Выпуск | Root Git revision и выбранные gitlinks, release manifest, immutable application/solver paths и оба `narHash`; совместимый controller release |
| Доставка | Реальный URL, private file transfer или offline medium; имя файла, размер и SHA256; manifest и его ожидаемый SHA256 по независимому trusted channel |
| Image | Выбранный `arch-worker` QCOW2, producer/build receipt, точные firmware/partition/root bus; для текущего пути кандидат BIOS/legacy/virtio, не UEFI image по предположению |
| Профиль image | `site_bound_private` только назначенному доверенному получателю; `reusable_base` допустим лишь с отдельными content/first-boot evidence |
| Host | Arch x86_64, KVM, фактические версии QEMU/libvirt, проверенный system URI, оператор SSH agent, существующий wired LAN bridge, storage pool и его свободные bytes/inodes |
| Guest | Уникальные MAC/IP/CIDR, gateway/DNS, hostname/Slurm NodeName, VM UUID, root/scratch identities, измеренные vCPU/RAM/диски и host reserve |
| Cluster | Адреса controller и storage, разрешённые NFS clients, UID/GID научного пользователя, общий jobs path, scratch path, time service, Slurm partition и callback range |
| Trust | Независимо подтверждённые SSH host fingerprints, protected enrollment/known_hosts paths, уже доверенные Nix cache/signing keys и scoped sudo policy |
| План | Named target, отдельный private state и saved plan, install/smoke budget, место для исходных логов и порядок сохранения данных при неудаче |

Дефолты из [provider input example](../tofu/arch-libvirt/site-base.json.example)
(30 GiB RAM, 12 vCPU, 512 GiB scratch и documentation IP) не являются измерением
нового хоста. Учитывайте существующие VM, QEMU overhead, физическую свободную память
и место под image, root overlay, scratch и результаты. Sparse capacity не резервирует
реальное место. Пределы текущих variables также не означают поддержку хоста иной ёмкости.

### Где искать artifact и что проверять

У publisher запросите release-specific handoff directory или его byte-identical copy.
Контракт worker distribution предусматривает `worker-distribution.json`, `SHA256SUMS`,
`images/worker-root.qcow2`, public source/release/build records и recipes. Этот layout
и schema `qcl-negf-worker-distribution-v1` — контракт доставки; выбранный baseline
ещё не предоставляет `ops/worker_distribution.py` или установленную команду проверки.
Не выполняйте будущий CLI из проектных описаний как существующий инструмент.

Если publisher передаёт такой bundle, он обязан приложить проверку schema/source/
closure/backend binding и actual delivery receipt. Получатель сверяет полный исходный
manifest с independently supplied hash, затем его file references и `SHA256SUMS`.
Например, из **уже проверенного по составу** каталога без links и посторонних paths:

```sh
cd "$BUNDLE"
printf '%s  worker-distribution.json\n' "$EXPECTED_MANIFEST_SHA256" | sha256sum --check --strict
sha256sum --check --strict SHA256SUMS
```

`BUNDLE` и `EXPECTED_MANIFEST_SHA256` — реальные входы handoff, не значения из guide.
Состав checksums должен совпадать с manifest: относительные payload paths, bytes и
SHA256, без `..`, absolute paths, links и устройств. Проверка checksum не устанавливает
доверие к самому manifest и не доказывает boot, отсутствие secrets или уникальность
machine-id/SSH keys. Нет фактического файла/маршрута или build/content receipt —
доставка ещё не готова; не подставляйте выдуманный hash.

Существующий [image producer](../tofu/build-images.ts) выдаёт private `images.json`
с `image_path`, `image_sha256`, `image_bytes` и generated provider inputs. Это не
полный distribution manifest. Для уже подготовленного private site-bound image
publisher передаёт эти фактические байты и недостающие release/source/content
свидетельства отдельно. Не публикуйте private inventory, raw preflight, provider
inputs, credentials или protected known_hosts вместе с public templates.

Не запускайте full image build на recipient как скрытую часть установки. Если
подходящего образа нет, publisher готовит отдельный конечный image packet с
[четырьмя role/nginx preflight](nginx-preflight.md). Создание образов и
[image transport](image-transfer.md) имеют свои admission и evidence; имеющийся
four-role staging interface нельзя вызывать с придуманной one-worker map.

## Private site и карантин до первого boot

Используйте [private-site example](../examples/private-site/flake.nix.template),
[host composition](../examples/private-site/hosts.nix) и
[site settings](../examples/private-site/site.nix.example). Hostname mappings должны
разрешаться одинаково на controller, storage, submit host и worker; controller/NFS
endpoints не выводятся из текущей сети автоматически. Общий jobs path —
`/srv/qcl-negf/jobs`, локальный scratch — `/scratch/qcl-negf`, научный UID по умолчанию
3000. Проверяйте фактические UID/GID на NFS, а не только имена пользователей.

В текущем adapter domain, cloud-init hostname/instance-id и volume names фиксированы
как `arch-worker`/`qcl-negf`; это один предусмотренный worker. Отдельный state не
устраняет коллизию с такими же remote names. Если они уже заняты, остановитесь:
параметризация нового имени/второго worker требует owning adapter change. Не
переиспользуйте foreign domain, pool, root или scratch и не импортируйте их в новый state.

До регистрации гостя держите его вне допуска работ: NodeName либо отсутствует на
controller, либо явно **DRAIN** в согласованной конфигурации controller/worker.
Пример site содержит `State=UNKNOWN`, поэтому quarantine не возникает автоматически:
для этого onboarding задайте начальный DRAIN и собственную причину в private
`slurm.nodes` до build/boot. Не включайте guest submit role. Сохраните
`ReturnToService=0`, `JobRequeue=0` и штатный boot `node-check`; последний проверяет
release, но сам по себе не доказывает trusted enrollment.

Root и scratch различаются: libvirt задаёт VirtIO serial `qcl-root` и `qcl-scratch`,
worker mount использует `/dev/disk/by-id/virtio-qcl-scratch`. Форматирование выключено
по умолчанию. Только для явно нового пустого scratch разрешается согласованный
worker-specific `qclNegf.cluster.initializeBlankScratch = true`; после инициализации
верните `false`. Не включайте общий example-параметр `initializeBlankDisks` для уже
существующих storage/control: он также связан с их data/state disks. Существующий
scratch, host filesystem, scientific data/state disks не форматируются.

Runtime Munge key доставляется отдельно принятым secret provisioning, совпадает с
cluster key и имеет требуемые owner/mode; не помещайте его в Nix store, image bundle,
OpenTofu vars/state или логи. SSH private keys остаются у оператора. Nix signatures,
SSH host verification и TLS verification остаются включёнными. `ssh-keyscan` без
независимой проверки не создаёт trust.

## Подготовить существующий Arch host

Все команды ниже — действия оператора в отдельном согласованном install packet,
а не команды, выполненные при написании guide. `PLATFORM` — абсолютный путь к полному
выбранному Platform checkout, `PRIVATE` — защищённый каталог конкретной установки.
В примерах они уже заданы; `umask 077` защищает новые state, plans и logs.

Подготовьте private Ansible inventory с группой `arch_hypervisors`. В group/host vars
укажите `qcl_cluster_bridge`, непустой `qcl_libvirt_users`, `qcl_storage_directory`,
`qcl_guest_memory_mib`, `qcl_guest_vcpus` и измеренные reserves. Значения памяти,
CPU, bridge и storage должны совпасть с reviewed provider vars. Зависимости берутся
из [pinned requirements](../ansible/requirements.yml) в подготовленном ops environment.

```sh
umask 077
ansible-playbook -i "$PRIVATE/inventory.ini" "$PLATFORM/ansible/arch-libvirt.yml" --check
ansible-playbook -i "$PRIVATE/inventory.ini" "$PLATFORM/ansible/arch-libvirt.yml"
```

Применяйте после review check-output и host admission. Существующий
[playbook](../ansible/arch-libvirt.yml) проверяет именно Arch x86_64, измеренную RAM/CPU,
`/dev/kvm` и выбранный Linux bridge; устанавливает libvirt/QEMU tools, запускает libvirt,
создаёт выделенный storage directory и добавляет только названных пользователей в
группу libvirt. Он не обновляет дистрибутив целиком и не настраивает network manager.
NAT-only default network не подходит: нужны прямые LAN routes между guest, controller,
storage и submit hosts. Bridge готовится заранее штатным network manager хоста.

## Reviewed OpenTofu plan и один named guest

Private `arch-libvirt.tfvars.json` должен содержать поля из
[variables](../tofu/arch-libvirt/variables.tf): system `uri` через существующий SSH
agent, LAN `bridge`, `pool_path`, actual `image_path`/`image_sha256`, root/scratch GiB,
RAM MiB, vCPU, уникальный MAC, guest CIDR, gateway/DNS и административные public keys.
Generated input publisher можно использовать только для того же site/image binding.
Provider проверяет локальные image bytes перед upload. Сохраните полный Platform
checkout и его provider lock; копирование одного `.tf` теряет контекст.

В выбранном `tofu/arch-libvirt` нет backend declaration. Один `TF_DATA_DIR`
переносит plugins/metadata, но не устанавливает private state. Поэтому создайте
**новый** защищённый working directory с копией полного tracked module из exact
selected commit (включая `.terraform.lock.hcl` и все его assets/templates) и явным
private backend overlay. `EXPECTED_PLATFORM_REV` берётся из gitlink выбранного
trusted root release, а не из произвольного latest checkout. Следующий блок — Bash;
ошибка или существующий `WORK` останавливает процедуру, без удаления/перезаписи.

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

`PRIVATE` должен быть уже защищённым абсолютным каталогом оператора. Git archive
берёт только tracked source указанного commit: чужие local state, `.terraform` и
untracked files из checkout в копию не переносятся. В install receipt сохраните
`platform-source.txt`, overlay/hash и selected root source binding. Это record
конкретной установки, не второй revision lock. Overlay добавляет только local
backend; продуктовый `versions.tf` не меняется. Все дальнейшие OpenTofu-команды
используют этот `MODULE`, его же private state и provider metadata. Если target
уже имеет state/владельца, **не создавайте для него новый WORK**: сначала отдельный
reviewed ownership/migration. Новый directory сам по себе не разрешает коллизии
remote domain/pool/disk names.

Проверьте URI/bridge, domain/MAC/UUID, source image hash, root overlay, отдельный scratch
и только новые назначенные ресурсы. Не должно быть удаления, замены или изменения
чужих VM/дисков. Существующий pool и scratch защищены `prevent_destroy`; отказ не
исправляется снятием защиты. Для прежнего state сначала согласуйте ownership/migration,
не создавайте параллельный пустой state. После review применяют **этот saved plan**:

```sh
tofu -chdir="$MODULE" apply "$WORK/worker.tfplan"
tofu -chdir="$MODULE" output -json > "$WORK/worker-output.json"
```

Apply запускает guest и включает autostart. Поэтому capacity admission, image trust
и initial quarantine нужны до apply. Это не dry run. При неизвестном результате
сохраните state, plan, actual domain/disk identities и исходные logs; сначала
reconcile, не повторяйте apply/destroy вслепую. Root replacement должен сохранять
проверенный scratch; scratch всё равно не является резервной копией.

## Первый boot, enrollment и допуск

Оператор сохраняет provider output, console/boot receipts и следующие факты до допуска:

1. Через trusted provisioning/console наблюдает VM UUID, `/etc/machine-id`,
   `/proc/sys/kernel/random/boot_id`, hostname/NodeName и fingerprints SSH host keys.
   UUID, machine-id, host keys и NodeName не должны быть клонами другой машины;
   cloud-init/image declaration не заменяет эту проверку. Новый root не должен
   наследовать чужие enrollment, gate или runtime ready markers; это отдельная
   content/first-boot проверка publisher и оператора.
2. Проверяет clock/time sync, DNS/host mappings, NFS source/mount и read/write как
   научный UID, отдельно от root (NFS root_squash ожидаем). `findmnt` и `df` должны
   показывать реальный NFS jobs mount и отдельный `/scratch`, а не root fallback.
   Нужны свободные bytes/inodes на host, scratch и NFS с запасом под выбранные работы.
3. Проверяет `slurmd -C` в госте и заносит фактическую topology/CPUs и меньший
   `RealMemory` с OS reserve в согласованный private Slurm config. Сверяет cgroup v2,
   CPU/RAM/swap enforcement, Munge и callback reachability. Daemon ports 6817/6818
   недостаточны: [network contract](operations.md#identity-networks-and-storage) включает
   `qclNegf.cluster.srunPortRange` (default 60001–60128) на private interface.
4. Привязывает guest/provider/host-key observations к защищённому enrollment v1;
   существующие validators — `enrollment_records`, `validate_enrollment`,
   `preflight_controller_authority` в [application_release.py](../ops/application_release.py).
   Проверка охватывает полный registry и исключает duplicate identities/targets.
   CLI `enroll` здесь нет: protected registry, trust snapshot и pool v2 меняются
   принятым операторским процессом, не саморегистрацией guest.
5. В maintenance window обновляет согласованные controller/worker Slurm config,
   NFS client allowlist и полный enrolled pool. Во время действующего исследования
   не перезагружает/reload controller ради onboarding и не отменяет чужие jobs.
   Сверяет текущие immutable app/solver, release ID, closure `narHash`, runtime ready
   и обычный job guard. Процедуры доставки — [application CD](application-cd.md).

Штатный controller lifecycle допускает только привязанный, проверенный worker:

```sh
sudo qcl-negf-worker-lifecycle startup --node arch-worker \
  --target "$WORKER_TARGET" --enrollment "$ENROLLMENT"
```

Команду выполняет уполномоченный оператор на enrolled controller; `WORKER_TARGET` и
`ENROLLMENT` — реальные protected inputs. Она проверяет authority/release/health и
штатный переход DRAIN→RESUME; не открывайте gate или не делайте manual RESUME вместо
неудавшейся проверки. Для first enrollment не выдумывают предшествующий shutdown
receipt; для возврата существующей машины нужны её реальные durable lifecycle records.
Неизвестный transition сохраняет закрытый допуск и требует reconciliation.

## Конечный smoke и нормальный shutdown/return

После native admission выполните отдельно назначенный non-scientific smoke: install
не более 90 минут; smoke/fault — до 45 минут, один engineering job не более
2 CPU/2 GiB/10 минут и до 1 GiB staged bytes. Это envelope, а не разрешение занять
ресурсы без свежего host/cluster admission. Сохраните job ID, output и исходные failures.

На controller как `qcl-negf`, из нового принадлежащего ему каталога внутри jobs:

```sh
sbatch --wait --partition=compute --nodelist=arch-worker --nodes=1 --ntasks=1 \
  --cpus-per-task=2 --mem=2G --time=00:10:00 --output=batch.stdout --wrap=hostname
timeout 90s srun --partition=compute --nodelist=arch-worker --nodes=1 --ntasks=1 \
  --cpus-per-task=1 --mem=128M --time=00:01:00 hostname
```

Здесь `compute` должен быть реально согласованной partition. Эти проверки повторяют
форму [существующего VM smoke](../tests/slurm-vm.nix); подтвердите actual NodeName и
worker→submit callback, а не только exit code. В том же выделенном smoke scope
создайте tiny marker на настоящем worker scratch, скопируйте в принадлежащий этому
smoke NFS каталог и независимо сравните bytes/SHA256 с controller. Сохраните stat,
mount/source и readback: один `hostname` не проверяет staging. Эта инженерная copy
не заменяет acceptance Runner checkpoint/result-staging и не читает научные массивы.
SCBA, Poisson, solver benchmarks и scientific acceptance в этот smoke не входят.

Для выключения guest сначала используйте controller lifecycle и дождитесь его
`safe_to_shutdown:true` для данного NodeName/boot/enrollment:

```sh
sudo qcl-negf-worker-lifecycle shutdown --node arch-worker \
  --target "$WORKER_TARGET" --enrollment "$ENROLLMENT"
```

Только затем выполняют обычный shutdown назначенного guest, сохраняя host/network
до подтверждения. Нормальный shutdown может ждать всех владельцев работ; истечение
smoke budget не разрешает force poweroff. Если ожидание выходит за packet, сохраните
состояние и передайте оператору, не отменяйте чужое исследование. После нового boot
той же permanent machine повторяют штатный `startup` с protected enrollment.
Fault/power-loss recovery и сохранность staged результатов проверяются отдельно;
не имитируйте их на занятом worker без отдельного scope.

## Что считается завершённым

| Утверждение | Свидетельство | Ограничение | Решение |
| --- | --- | --- | --- |
| Источник и доставка известны | Exact source/release/closure records, manifest hash, image bytes/SHA и recipient readback | Checksum не доказывает guest boot | сохранить binding |
| Arch/libvirt host подходит | Measured versions, KVM/bridge/capacity, reviewed saved plan | Другие Linux distros не проверены этим adapter | дополнительно измерить новый backend |
| Worker допускается к работам | Unique trusted identity, protected enrollment, DRAIN→health→owning admission, current release/cgroups/NFS | Ни boot, ни source tests не заменяют native receipt | сохранить карантин до evidence |
| Onboarding smoke выполнен | Tiny batch+srun, scratch→NFS/readback, normal shutdown/return receipts | Не научная сходимость и не full fault/restore acceptance | сохранить раздельные gates |

Без actual artifact location/checksum/build/content/first-boot и target receipts статус
соответствующей клетки остаётся `not_measured` или `blocked`; этот guide не присваивает
ей PASS и не заявляет готовность Proxmox/Hyper-V. Их installation/native gates отдельны.
