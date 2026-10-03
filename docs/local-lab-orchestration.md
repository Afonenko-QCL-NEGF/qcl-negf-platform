# Host orchestration локального KVM lab

`ops/local_lab.py` — stdlib Python CLI для отдельного lab из четырёх VM.
Контракты ролей, OpenTofu и Ansible описаны в
[local-lab.md](local-lab.md). CLI не запускает solver, не использует host sudo,
не меняет default network и не принимает namespace как доказательство владения.

Храните runtime в Git-ignored абсолютном каталоге, например
`qcl-negf/.build/local-lab`. Нужны доступ пользователя к `/dev/kvm` и выбранному
libvirt API, OpenTofu 1.12+, virsh, ip, ssh-keygen, SSH, Ansible и
`cloud-localds` либо `genisoimage`. Общий образ и четыре role closures должны
быть уже построены. `systems.json` содержит ровно `control`, `storage`,
`worker-1`, `worker-2`, каждому соответствует точный NixOS toplevel store path.

```sh
python3 ops/local_lab.py prepare \
  --directory /ABS/qcl-negf/.build/local-lab \
  --namespace qcl-lab --network-cidr 192.168.231.0/24 \
  --image /nix/store/BUILD/nixos.qcow2 \
  --systems /ABS/systems.json \
  --pool-path /var/tmp/qcl-negf-qcl-lab \
  --libvirt-uri qemu:///system
python3 ops/local_lab.py apply --directory /ABS/qcl-negf/.build/local-lab
python3 ops/local_lab.py inventory --directory /ABS/qcl-negf/.build/local-lab --enroll
python3 ops/local_lab.py bootstrap --directory /ABS/qcl-negf/.build/local-lab
python3 ops/local_lab.py probe --directory /ABS/qcl-negf/.build/local-lab
```

`prepare` создаёт private configuration, public-only NoCloud ISO и provider
variables. Существующие `private/id_ed25519`, `id_ed25519.pub`, `munge.key`
сохраняются; Munge key имеет 1024 bytes. SSH private key и Munge bytes никогда
не входят в seed, OpenTofu inputs или state. При повторном prepare namespace,
network, pool, bootstrap hash и libvirt URI должны совпасть. `systems.json`
можно обновить для отдельной application stage, не меняя backing image.
Optional `private/api-token` передаётся только Ansible на controller.

`apply` сначала измеряет KVM access, logical CPU, MemAvailable и free disk в
целевом filesystem. По умолчанию требуется guest RAM 7424 MiB, 7 vCPU,
дополнительно 1024 MiB/1 CPU для host и место под image плюс 2 GiB disk reserve.
`--resources JSON_PATH`, `--host-reserve-mib`, `--host-reserved-cpus`,
`--disk-reserve-bytes` задаются на prepare. Уже работающие owned VM не
списываются с MemAvailable второй раз; CPU других running VM учитываются.
Sparse capacities 24 GiB root / 8 GiB durable не являются резервированием
свободного места или гарантией достаточного бюджета будущего solver.

Actual domain/network/pool UUID должны совпадать с именем и ID из exact
`tofu/terraform.tfstate`. Это позволяет восстановить partial apply лишь для
ресурсов, уже отражённых в state. Чужой совпавший namespace, pool path,
untracked volume/file или перекрывающий host/libvirt subnet останавливает
apply. Owned bridge исключается из overlap лишь для своего точного /24.
`ownership_verified=true` записывается после фактического preflight.
Module копируется в private `tofu/`, затем выполняются init, saved plan и
apply; планы с delete/replacement отклоняются. После apply сохраняется
`private/ownership.json` с actual UUID и state IDs. Нет автоматического destroy,
adopt, очистки pool, изменения host firewall или закрытия чужой VM.

`inventory` берёт реальные OpenTofu outputs и сверяет domain/role/IP/MAC и
actual ownership до SSH. `--enroll` применяет `accept-new` один раз на
записанную domain identity, затем `StrictHostKeyChecking=yes`. Host keys
сохраняются в private `known_hosts`; смена ключа отклоняется. Ansible inventory
JSON задаёт root SSH и точную closure каждой роли; локальный localhost использует
Python хоста, гостевые узлы — NixOS Python. `bootstrap` вызывает owning
`ansible/local-lab.yml`: storage раньше остальных VM; existing disks сохраняются.

`probe` действительно подключается к четырём owned VM. Он проверяет active
system/hostname/resolution, UID3000, cgroup v2, отдельные state/data/scratch
устройства по serial и filesystem UUID, настоящий NFS, root write denial и
запись UID3000. На controller отправляются два последовательных коротких
`sbatch --wait` jobs, закреплённых за worker-1/worker-2: hostname и job cgroup
должны совпасть. Каждый job ограничен одной минутой, 1 CPU и 64 MiB; ID
записывается в owned NFS probe directory перед ожиданием. Долговечные receipts
и UUID сравниваются при повторном probe. Сам CLI не перезагружает controller:
после отдельно разрешённого reboot повторный probe измеряет смену boot ID и
сохранность receipts/UUID. Непроведённый reboot остаётся `not_measured`.

Каждая host-команда передаётся literal argv с `shell=False`; timeout по
умолчанию 300 seconds, apply/bootstrap commands 1800 seconds. Опции
`--timeout` и `--operation-timeout` ограничены 1..7200 seconds. Captured output
ограничен 1 MiB на команду; в журнал идут только первые 32 KiB stdout/stderr,
статус, время, argv и source commit/file hashes. Evidence находится в
`evidence/commands.jsonl` и private admission/bootstrap/probe JSON. Ошибка или
timeout не становится pass; evidence не доказывает научную сходимость,
cancellation или backup/restore. На timeout Slurm probe нужно читать только
его сохранённые job IDs; scheduler wall limit остаётся конечным.

```sh
python3 -m pytest -q tests/ops/test_local_lab.py
```

Unit tests проверяют admission shortfalls, foreign/partial ownership, CIDR
overlap, secret exclusion, сохранение keys, literal argv, destructive plan
rejection, strict repeated SSH enrollment и root-backed durable mount rejection.
Они не подтверждают boot, реальную libvirt/SSH/NFS/Slurm работу: эти свидетельства
создаются только фактически выполненными CLI commands.
