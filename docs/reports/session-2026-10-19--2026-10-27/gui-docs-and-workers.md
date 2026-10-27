# GUI, справка и выдаваемые worker

Пользователь потребовал видеть ход исследования в **светлом** веб-интерфейсе. Новый Portal/AiiDA
source решает обнаруженную реальную дыру: SCI6 — standalone `execution_restart` WorkChain, не
потомок PlanWorkChain, поэтому существующий список `/runs` не показывал его через Plan ancestry.
Отдельный `GET /api/v1/recovery-executions` и detail сохраняют типы: root/child UUID, process/Slurm
state, Plan fingerprint и recovery association без фиктивного Plan-parent, submit, kill или обхода
saved-results reader. Native8 на инженерном APP проверил установленный backend и Portal actor против
фактического AiiDA provenance. Это сильнее AST/source projection, но ещё не authenticated deployed
HTTP/UI. [Source catalog](evidence/source-catalog.md) ·
[APP native ledger](evidence/operation-ledger-3.md).

Frontend candidate закрепил `color-scheme: light` и светлые таблицы/формы/состояния. При локальной
проверке повторно используемого browser origin сначала отдалась старая закэшированная HTML entry;
запрос с уникальным query увидел новые хэшированные CSS/JS и светлую тему. Поэтому source поправка
обязала HTML entry к `no-cache, must-revalidate`, сохранив fingerprinted asset caching. Полезный
вывод — не считать старый DOM доказательством новой сборки и не считать исправленный source
доказательством поведения production cache. После release нужны прямой refresh старого URL,
auth/TLS, dark/light OS preference при **неизменной светлой теме**, ошибки/loading, keyboard/focus и
реальный UI SCI6.

DOC04 — отдельный справочный bundle. На выбранном GUI root подготовлены public source graph,
reviewed associations, 49 page routes/261 outputs, exact immutable inputs и шесть инструментов на
controller; полная native Documenter/Node/Python сборка **не выполнялась**, candidate1 остаётся 0/1.
Значит `/docs/` пока нельзя обозначить доступным: Portal требует exact bundle и его hash при
startup, а browser journeys/search/math/fonts/light проверяются позднее. Выбранный engineering
envelope — 3 GiB unit + 1 GiB fresh guest reserve, то есть `MemAvailable≥4 GiB`. У controller
`MemTotal≈3.824 GiB` и available≈2.76 GiB на последнем capacity read; даже завершение SCI в другой
VM не сделает **неизменный** controller eligible. Безопасный уменьшенный peak не измерен. Пока SCI
активна, арифметический остаток host MemTotal после максимальных распределений VM лишь на ≈0.409 GiB
выше обязательного 4 GiB резерва; это не физически гарантированная свободная RAM и не допуск к
resize. После SCI выбран путь контролируемого перераспределения QCL ресурсов; иной подготовленный
target тоже возможен только после собственных bindings и fresh admission. Затем — одна native
попытка, не «пробный» render. [Ресурсный разбор](resource-control-and-cost.md) ·
[DOC task](evidence/task-register.md) · [native gate readback](evidence/gate-excerpts.md).

Worker distribution продвинулся на уровне исходников: Linux guide и toolkit с конкретными
bootstrap/network/trust/rollback инструкциями подготовлены; локальная проверка CachyOS показала
доступный KVM и ожидаемое Ansible `Archlinux` условие. Но native Nix daemon/root execution на
локальном PC недоступны текущему автоматическому исполнителю, подтверждённого LAN bridge/route и
image transfer нет. Для первого worker ещё нужны exact image/closure, ownership и network authority,
host-key/enrollment, установка, initial DRAIN, затем bounded Slurm/NFS/scratch/scheduler smoke.
Второй worker на Proxmox — отдельная установка и acceptance, не вывод из готового source kit. Не
подставлять вымышленные IP, DHCP или VPN как готовый binding.
[Linux worker guide](../../linux-workers.md) ·
[backend plan](https://github.com/Afonenko-QCL-NEGF/qcl-negf/blob/d395044ac09b28c2ff573724f8911d625df43bf5/docs/implementation/review-closure-2026-10-19/platform-worker.md).

Полный исходный scope также включает Linux/libvirt и два Windows/Hyper-V backend. Source
contracts/recipes не заменяют native boot, disk/secret/trust, enrollment, ordinary job,
fault/rollback receipts каждого backend. На срезе нет оснований утверждать, что все они готовы или
что source kit уже является пользовательским установочным дистрибутивом.
[Task register](evidence/task-register.md) различает подготовку и выполненную native проверку.

| Утверждение                          | Свидетельство                                | Ограничение                                    | Решение                |
| ------------------------------------ | -------------------------------------------- | ---------------------------------------------- | ---------------------- |
| SCI6 можно видеть в новом backend    | Native8 exact recovery read                  | Production API/browser ещё не обновлены        | сохранить              |
| DOC04 уже опубликован                | Source/inputs verified, candidate0/1         | Нет bundle/render/browser и RAM admission      | данных недостаточно    |
| Новый worker можно подключить сейчас | Guide/toolkit и локальный metadata preflight | Нет image, route/trust/enrollment/native smoke | дополнительно измерить |
