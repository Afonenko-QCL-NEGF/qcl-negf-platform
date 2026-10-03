# Локальный KVM lab

Локальный lab использует четыре NixOS VM: `control`, `storage`, `worker-1`,
`worker-2`. `tofu/local-lab` — отдельный контракт от production
`tofu/arch-libvirt` и Proxmox. Начальный профиль занимает 7424 MiB guest RAM и
7 vCPU; фактически свободные host RAM, disk и доступ к `/dev/kvm` проверяются
перед созданием ресурсов и каждой большой сборкой. Логическая ёмкость sparse
QCOW2 не равна доступному месту: начальные 24 GiB root и 8 GiB durable на VM
не резервируют это место и не заменяют admission по свободному диску.

## Private caller и интерфейсы

Храните state, inventory, ключи, ISO, образы и результаты в ignored private
каталоге. Образ не содержит secret bytes. Import
`nix/local-lab.nix { inherit nixpkgs platform site; }` принимает public `site`:
`hosts` (IP → список hostnames), `sshPublicKey`, `nodes`, `partitions`,
`initializeBlankDisks` (по умолчанию false). Пример —
[site.nix.example](../examples/local-lab/site.nix.example). Возвращаются:

- `configurations`: четыре настоящие role NixOS configurations;
- `systems`: exact `system.build.toplevel` для каждой роли;
- `bootstrap`: platform-only configuration с SSH, Python, cloud-init и guest agent;
- `image`: один QCOW2, содержащий все четыре role closures через
  `system.extraDependencies`. Это не четыре независимо собранных root images.

`platform` может быть pinned platform flake либо attrset с `outPath` и
`nixosModules.default`. `platform.lib.mkLocalLab { inherit site; }` экспортирует тот же constructor. Гость имеет одну
virtio NIC; `net.ifnames=0` и `eth0` одинаковы во всех ролях и bootstrap.
NoCloud может включать DHCP для `eth0`; адреса закрепляет DHCP network по MAC.
Не задавайте второе конфликтующее имя `cluster0` в seed.

OpenTofu 1.12+ использует зафиксированный `dmacvicar/libvirt` 0.9.9. Private caller
передаёт `namespace` (`qcl-…`), `pool_path`, `bootstrap_image`, проверенный
`bootstrap_sha256`, public `ssh_public_key`, `seed_images` (четыре ISO), optional
`network_cidr`, `resources`. Образ — **файл QCOW2**, не каталог результата Nix.
Для NAT по умолчанию используется `192.168.231.0/24`: gateway .1, control .10,
storage .11, workers .21/.22. MAC выводится из namespace SHA256 и host suffix.
Outputs: `inventory`, `resource_names`, public-only `nocloud` с `meta_data` и
`user_data`. Caller записывает эти данные в ISO label `cidata` до apply;
instance ID и hostname должны соответствовать namespace/role. Никаких Munge,
SSH private key или токенов в seed/OpenTofu variables/state.

До `ownership_verified=true` caller сверяет реальные `virsh` network/pool/domain
names и pool directory с exact private state. Новый lab допускает лишь отсутствие
этих ресурсов и пустой owned directory; повторный apply — лишь ресурсы,
отслеживаемые этим state. Чужое совпадение имени/пути или host route overlap
должно остановить caller. Сам boolean не является доказательством владения.
`pool_path` должен быть доступен qemu/libvirt daemon: нужны права прохода всех
parent directories и записи в pool, с учётом host ACL/SELinux/AppArmor. Не
используйте недоступный daemon private home или общий production pool.

## Bootstrap и долговечные данные

Root overlays имеют один immutable backing volume. Отдельный durable volume
подключён как `vdb`: serial `qcl-state` на control, `qcl-data` на storage и
`qcl-scratch` на workers. NixOS использует соответствующие
`/dev/disk/by-id/virtio-*`. Все durable volumes, pool и backing image имеют
`prevent_destroy`; обычный destroy/replacement не является разрешением удалить
данные. Их удаление требует отдельного решения, резервной копии и явного
изменения lifecycle. Root images обновляются отдельно; смена защищённого backing
образа требует спланированного перехода, а не скрытого replacement.

`initializeBlankDisks=true` разрешён только для назначенных lab-owned пустых
дисков после ownership proof. Owning modules форматируют только диск без
filesystem signature. Повторный bootstrap не меняет filesystem UUID и данные.
Ansible не запускает installer и не форматирует root. Runtime secret unit
проверяет непустой `/var/lib/qcl-lab-secrets/munge.key` и копирует его в
`/run/secrets/munge.key` с владельцем munge/mode0400; отсутствие ключа приводит
к отказу зависимого `munged`, не к генерации разных ключей на узлах.

Передайте private inventory как в
[inventory.yml.example](../examples/local-lab/inventory.yml.example), сохранив
host `storage` и группу `local_lab`. Каждый host имеет `qcl_lab_role` и точный
`qcl_lab_system`, присутствующий в общем образе. Caller заранее проверяет host
keys и задаёт `StrictHostKeyChecking=yes` с private known_hosts. Запустите:

```sh
ansible-playbook -i /absolute/private/inventory.yml ansible/local-lab.yml
```

Playbook сначала проверяет существующий non-root host KVM/libvirt API без
изменения ОС хоста, затем запускает storage, затем control/workers. Он передаёт
общий Munge key из `qcl_lab_munge_key_file` вне Git/store/state, выбирает system
profile и активирует exact closure через `switch-to-configuration switch`.
Повторный bootstrap сравнивает current/boot paths и пропускает неизменённую
активацию. Новый ключ перезапускает runtime secret, Munge и cluster daemon.
Persistent secret находится на guest root и повторно provisioned Ansible при
замене root; это не научные данные на state/data disks.

Application installation — отдельная стадия после SSH/NFS/Slurm/cgroup proof.
`site.application` и `site.solver` должны задаваться вместе как immutable
packages; `serviceEmail` обязателен для controller bootstrap. Используются
те же owning application/release modules: release guard и worker `node-check`
сохраняются. Контроллеру передайте `qcl_lab_api_token_file` для private runtime API token.
API включается с lab budget: 2 CPU, max RAM1792 MiB, default1024 MiB и
export disk512 MiB; `site.api` может задавать подходящие измеренной системе
параметры. Token передаётся Ansible в persistent private path до activation,
а secret unit проверяет наличие и копирует его в `/run/secrets`.
Application stage closures можно `nix copy` отдельно перед
повторным Ansible; не требуется импортировать новый защищённый backing image.

## Ограниченная проверка

```sh
tofu -chdir=tofu/local-lab init -backend=false -input=false
tofu -chdir=tofu/local-lab fmt -check -recursive
tofu -chdir=tofu/local-lab validate
tofu -chdir=tofu/local-lab test
nix --extra-experimental-features 'nix-command flakes' eval --impure --expr \
  'let platform = builtins.getFlake (toString ./.); in import ./tests/infrastructure/local-lab.nix { nixpkgs = platform.inputs.nixpkgs; inherit platform; }'
```

`validate` использует настоящий provider; `test` проверяет mocked plan без
создания VM. После перезапуска host NAT-сеть и VM с `autostart=false` нужно явно запустить
через lab-owned orchestration. Nix test оценивает реальные owning modules, роли, disk identities,
UID3000 и secret ordering. Эти проверки не подтверждают boot, NFS root_squash,
Slurm execution, repeat UUID retention, application imports или scientific
acceptance. Caller сохраняет реальные команды и наблюдения отдельно; отсутствие
измерения остаётся `not_measured`. Solver в этих platform проверках не запускается.
