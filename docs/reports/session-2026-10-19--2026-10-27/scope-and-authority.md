# Исходная задача, приоритеты и полномочия

Исторический review archive от 14 октября и опубликованный 19 октября в 10:55:52 UTC handoff
[root PR #22](https://github.com/Afonenko-QCL-NEGF/qcl-negf/pull/22) предшествовали измеренному
началу активной EXEC-сессии **19 октября в 11:57:19.876 UTC**. Пользователь поручил довести находки
до проверенной системы для исследования квантового транспорта. Публичный handoff различал RV00–RV19,
28 исходных fixcards, SI01–SI07 и исторические требования; общий маршрут включал DEV01–25, OPS01–17,
SCI01–15, DOC01–07, SI01–07 и интеграционные шаги. Эти карточки были **планом покрытия**, не
счётчиком готовых результатов. Исходный dirty checkout `e48e5b2…` и review archive сохранялись без
reset; выбранные новые commits публиковались через owning component PR и затем root Gitlinks.
[Исторический handoff](https://github.com/Afonenko-QCL-NEGF/qcl-negf/tree/e0f244d075dd49874ba4f3847f4efa693f3b3622/docs/implementation/review-closure-2026-10-19)
·
[coverage](https://github.com/Afonenko-QCL-NEGF/qcl-negf/blob/e0f244d075dd49874ba4f3847f4efa693f3b3622/docs/implementation/review-closure-2026-10-19/coverage.md).

После отдельного пользовательского старта работали активированные классы **B/G1/S1**: разработка и
ограниченные native действия на проверенных QCL targets, публикация/review/разрешённое слияние,
научная постановка 0 mV/period при 70 K без electron–electron и с LO/acoustic/impurity/IFR/alloy.
Подтверждение политики не заменяло технический `BIND/READY`: перед эффектом требовались actual
source, host/VM/диск/queue/credentials scope, ресурсы, provenance и конечный budget. Изменение
модели, сетки, базиса, scattering, окна, критериев ради экономии/«зелёного» результата запрещалось.
Внутренние обратимые решения решались без повторных вопросов; неопознанные диски, чужие VM/jobs,
новые trust roots и публичный релиз оставались за пределами автоматического grant.
[Принятый permission contract](https://github.com/Afonenko-QCL-NEGF/qcl-negf/blob/d395044ac09b28c2ff573724f8911d625df43bf5/docs/implementation/review-closure-2026-10-19/operator-permissions.md).

Приоритет пользователя сместился к реальному исследованию и читаемому GUI, но это не отменило
научную честность и безопасные границы. Поэтому можно было продолжать frozen scientific plan после
конкретно диагностированных отказов, не ожидая не относящихся к этому этапу browser/help/Windows
checks. Нельзя было объявить SCI6 научно принятой из-за движения SCBA или применить новый GUI во
время активного job: owning release update требует пустую очередь и согласованное состояние всего
pool. Снятие защиты с чужих ресурсов ради DOC04/CI не входит в это решение.

Пользователь отдельно разрешил cause-specific SCI4/R3, SCI5/R4, затем пять дополнительных
SCI6–SCI10/R5–R9; к срезу SCI6 использовала первую из пяти, четыре оставались. Это **не**
auto-retry: каждому следующему submit предшествуют preserved failure, exact checkpoint/recovery
identity, fresh admission и уникальный intent. Общий scientific cap и ограничения физики
сохранялись; scientific submits=6. Engineering heavy build slots исчерпаны 3/3, единственный final
full CI ещё 0/1. [Science ledger](evidence/science-snapshots.md) ·
[metrics](evidence/metrics-ledger.md).

Отдельная поправка пользователя от 24 октября упростила первоначальную громоздкую политику RAM/CPU:
использовать свежий безопасный ресурсный максимум на допустимом builder, общий resident cap и защиту
гипервизора/других VM, не превратив это в бесконечный цикл предварительных «разрешений». Она не
ослабила source, capacity, stop, scientific или CI gates.
[Ресурсная поправка](https://github.com/Afonenko-QCL-NEGF/qcl-negf/blob/d395044ac09b28c2ff573724f8911d625df43bf5/docs/implementation/review-closure-2026-10-19/resource-policy-2026-10-24.md).

| Утверждение                                  | Свидетельство                                                           | Ограничение                                                               | Решение             |
| -------------------------------------------- | ----------------------------------------------------------------------- | ------------------------------------------------------------------------- | ------------------- |
| Вся программа завершена, раз опубликованы PR | [Task register](evidence/task-register.md) и исходный coverage contract | Source review, native, CI, deploy и science — разные уровни               | данных недостаточно |
| Следующие SCI attempts разрешены             | CP70 slots R6–R9 доступны, R5 consumed                                  | Каждый вызов требует нового технического допуска, не blind retry          | сохранить           |
| Ресурсы можно менять ради работы             | Упрощённая политика 24 октября                                          | Только после fresh reserve/ownership/queue checks; SCI и foreign защищены | сохранить           |
