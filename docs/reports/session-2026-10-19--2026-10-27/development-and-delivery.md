# Разработка, проверка исходников и граница доставки

Работа велась в восьми owning компонентах, сохраняя их ответственность: Core — физика и in-memory
расчёт; Runner — frozen plan, файлы, checkpoint/recovery; Contracts — форматы; Results — независимое
чтение; Research — постановка; AiiDA — provenance; Platform/Slurm — ресурсы и узлы; Portal —
представление. Компонентные PR и их проверки предшествовали изменению root gitlink. Точный выбранный
состав определяется Git дерева, а не вручную обновляемой таблицей SHA.
[PR index](evidence/pr-index.md) · [source catalog](evidence/source-catalog.md) ·
[архитектура](https://github.com/Afonenko-QCL-NEGF/qcl-negf/blob/d395044ac09b28c2ff573724f8911d625df43bf5/docs/architecture.md).

За сессию закрывались конкретные технические seam: точный CalcJob при экспорте и восстановлении,
сохранение original failed raw, unknown outcome после удалённого эффекта, version/source binding,
finite IO/RAM admissions, timestamp/progress telemetry, безопасные native/toolchain границы и явные
ошибки UI/help. Подтверждать **все** RV/SI как закрытые по числу PR нельзя:
[task register](evidence/task-register.md) различает source implemented, targeted/native tested,
runtime admitted, deployed и scientific evidence. Старый review bundle и текущая научная попытка
имеют другие источники. В частности, scientific runtime root
`cb1bae7ffdbb977f33d81e05b8ebd50afb4177ee` остаётся отдельным от более нового GUI/docs root
`d395044ac09b28c2ff573724f8911d625df43bf5`; новый UI не менял работающий solver.

Проверенный после CP70 [PR-срез](evidence/pr-index.md) уточняет уровень публикации: root GUI
candidate [#35](https://github.com/Afonenko-QCL-NEGF/qcl-negf/pull/35) оставался draft/open;
platform [#31](https://github.com/Afonenko-QCL-NEGF/qcl-negf-platform/pull/31) был merged в ветку
интеграции, на которой основан этот отчёт. Это не означает обновления default `main` или развёрнутых
VM. Сам исходный root [#22](https://github.com/Afonenko-QCL-NEGF/qcl-negf/pull/22) оставался open;
позже данное пользователем EXEC-поручение определяло рабочие полномочия, а не статус этого PR.

Платформа сохранила контроль четырёх ролей, immutable Nix/store inputs, source/installer identities,
владельца Git indexes и строгий nginx preflight как отдельные gates. Реальный работающий
Slurm/AiiDA/совместный storage путь подтверждён SCI job; это **не** доказывает, что новый release
image, backup/restore или каждый worker backend уже прошёл acceptance. Проверка native обязана
связывать boot/VM, source, derivation, contents, cgroup/unit, persistent state и stage. При ошибках
исходные stderr/receipts остаются доступными для cause-specific review.
[Platform guide](https://github.com/Afonenko-QCL-NEGF/qcl-negf-platform/blob/1b1370d2b8e83a267a97c8d49df14db220123478/docs/infrastructure.md)
· [delivery procedure](../../application-cd.md).

На GUI candidate был построен один ordinary engineering APP output
`/nix/store/65hkmrfyvlziwf7rhzhxnafqfxaj20qj-qcl-negf-application-0.2.0`: build 47.165 s, cgroup
peak 983,105,536 B, OOM 0; frontend bundle/light CSS проверялись отдельно. Это не новая «четвёртая
heavy build» и не final CI. Native8 уже из **установленного этого output** прочитал текущий
standalone recovery Root132, CalcJob134/Slurm7 и exact frozen Plan metadata через Portal actor →
AiiDA: 20 PostgreSQL read-only checkouts, два SQLite `query_only` readbacks, clean actor close.
Перед этим четыре APP smoke invocations были failed; причиной оказались несоответствия
изолированного harness штатным AiiDA profile log/PID и SQLite WAL/SHM, а не доказанный дефект Portal
или scientific model. Broad profile RW в финальном smoke не является криптографическим
доказательством неизменности всего repository; применялись только audited read getters, DB read-only
guards и RO scientific jobs mount. [APP evidence](evidence/operation-ledger-3.md).

Остались обязательные границы доставки. Engineering `path:`-source APP build надо сопоставить с
**единственным final Git-ref CI** на финальном опубликованном source: равенство версии или Git tree
не гарантирует равенства Nix derivation при другом `self.outPath`. Затем нужны sign/stage обеих
immutable closures (APP и solver), actual site/pool/trust binding, native backup/restore и штатный
`qcl-negf-release update`. Updater требует пустые AiiDA/Slurm queues и согласованный fleet; активная
SCI6 запрещает сейчас обычное обновление. После него отдельно проверяются службы, auth/TLS, светлая
тема, recovery view, сохранённые данные и help в реальном браузере.
[Application CD](../../application-cd.md) не считает source build завершённым release.

Результат сессии поэтому точен: часть source fixes опубликована и проверена на своих уровнях, native
APP metadata bridge работает на кандидате, но полный release pipeline и научная приёмка не
завершены. Старые passes не переносились на другой root; failed attempts не удалялись ради «зелёной»
истории.

| Утверждение                                      | Свидетельство                                                                 | Ограничение                                                | Решение             |
| ------------------------------------------------ | ----------------------------------------------------------------------------- | ---------------------------------------------------------- | ------------------- |
| APP candidate собирается и читает SCI6 recovery  | Engineering build/native8 receipts в [ledger](evidence/operation-ledger-3.md) | Не финальный Git-ref CI, release или браузер               | сохранить           |
| Работающий SCI job доказывает весь новый кластер | Slurm/AiiDA provenance и storage readback                                     | Не проверены новый image, worker, restore и release update | данных недостаточно |
| Можно обновить GUI сейчас                        | [Application CD](../../application-cd.md) требует drained fleet               | SCI6 ещё RUNNING                                           | сохранить           |
