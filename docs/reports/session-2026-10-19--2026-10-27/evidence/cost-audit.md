# Публикуемая проекция независимого аудита

[Общий отчёт](../README.md) · [Метод](README.md)

Исходный авторский audit SHA256 `eba12e85a3a726badea3647d4aa2179e9b74fe1036b2acec7952f1dd4d232a18`,
34826B. Ниже текстовая проекция: приватные абсолютные пути и физическая boot identity скрыты;
исходные raw bytes этим текстом не подменяются. Данные остаются историческим срезом CP70, не новой
live проверкой. Аудиты не запускали solver/build/profiler.

---

# QCL-NEGF, 19–27 октября 2026: время, стоимость и границы свидетельств

**Основной вывод.** До первого научного запуска прошло около пяти календарных суток инженерной
подготовки. Крупнейшие доказанные категории затрат — раздробленная координация и подготовка native
resource/runtime пути; затем длительные научные попытки без принятой точки. Непосредственно три
учтённые тяжёлые сборки заняли суммарно **473,46 s**, а не несколько суток. Точную долю каждой
причины в полном календарном времени, полную CPU-стоимость и денежную стоимость имеющиеся данные не
устанавливают.

Срез завершён **27.10.2026 06:46:18 UTC**. SCI6 / Slurm job 7 ещё работал; последняя memory-sample
содержит outer 9, inner 269, `fixed_point_passed=false`. Это не итог научного исследования. Все
времена ниже UTC, если не оговорено иначе. Счётчики попыток, process completion, сходимость,
физическая приёмка, дискретизация и экспериментальная валидация разделены.

## Источники и способ проверки

В отчёте используются логические имена артефактов; приватный checkpoint и адреса хостов не
публикуются. `N/` обозначает закрытое хранилище сохранённых evidence, доступное координатору.
Локатор `P#/key` означает JSON pointer в фиксированном checkpoint P. Источники не исполнялись.

| ID | Фиксированный источник                                                                | Проверенные bytes / SHA-256                                                  |
| -- | ------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| P  | `QCL-ORDINARY-PROGRESS70-SCI6-MEMORY-AUDIT/after.json`                                | 3268633 / `eba940738fdaceaf34366ca05aa85597e003d4f982a88856b1676b41c5b44600` |
| O  | `QCL-OPERATIONAL-PROGRESS38/operations-prefix-original.json`, журнал операций         | 763997 / `e61b01d842ae5d5d6ed89c0635cd33b63753bd59edda0e31ceba3bdb2dda75a9`  |
| H  | `QCL-CHECKPOINT-HISTORY-PROGRESS1-48-ARCHIVE1/historical-progress.json`               | 28801 / `7b9a4927dbd02eab9f961113bcf72700afaa5083836c6b0a61989e84a9353e0b`   |
| A  | `preparation-audit-and-runner111-preconsume1/case/report.md`, ранний аудит подготовки | 23382 / `ddfc838d7b0de87b7c95da3dcd4234a90bc12cbd8adff31c4784556c14487d0a`   |
| B2 | `QCL-ORDINARY-RUNTIME-BUILD2-STATUS3/receipt.json`                                    | 42897 / `ef8892dbc001a7191f315131bac302e088b8e8fbf787a21c4cf3008b3d28af89`   |
| B3 | `QCL-ORDINARY-RUNTIME-BUILD3-STATUS2/receipt.json`                                    | 42909 / `c4bfa8c2b68e674e8f69fee471033a4dd01db258da24715a8a9020edb447f646`   |
| B4 | `QCL-SCI6-RUNTIME-PACKAGE4-PROGRESS2/receipt.json`                                    | 60214 / `51d0c677f90e5ccb713e38240e7c5a6d7a3c970e8ff0b0b162e5d5149aabba4e`   |
| Q6 | `QCL-SCI6-RUNTIME-QUAL1-STATUS1/receipt.json`                                         | 118838 / `5741a62ad700e8512f4e482f5390ea049e1fc15769a788d7af26e423c4ac1d8e`  |
| S5 | `QCL-SCI5-R4-TERMINAL-ACCOUNTING1/receipt.json`                                       | 5528 / `94a2ceef50bf4fe8a21077411010be00c7d3272a5db5ffb6bc285b41b9e470bd`    |
| S6 | `QCL-SCI6-R5-HEALTH-PROGRESS-READ26/receipt.json`                                     | 69164 / `f366b25ca641f48309fad57d982f4489dcc95f6ccf59a17edd694ba9a3617d03`   |

P содержит 1445 записей `operations`; первые 862 восстановлены по `archived_operation.file/index` из
O. Это **записи координации/проверок/действий**, не 1445 сборок, тестов или научных запусков. Две
старые записи O[368]/O[370] используют ключ `operation` вместо `id`; это учтено при чтении, а не
признано пропажей операции. H содержит 45 исторических progress-значений; архивные ссылки рекурсивно
разрешены, размеры и SHA проверены, суммарно прочитано 247858 bytes. Старые состояния не объявляются
текущими.

Выполнено только чтение выбранных JSON/text и простая арифметика. Не выполнялись solver, тесты,
сборки, установка, profiler, remote actions, изменение checkpoint, чтение SSH/config/key bytes или
private inventories. Никакие raw scientific arrays не читались. Приведённые test/build/runtime
результаты — сохранённые свидетельства исторических действий, не проверки, заново пройденные этим
аудитом.

## Хронология и изменение приоритетов

| Время / окно                                                 | Что установлено                                                                                                                                                                                                                                                   | Локатор и практический смысл                                                                                                                                                  |
| ------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 19.10 11:57:19.876                                           | Начало измеренного main-session окна; принята широкая EXEC задача: несколько компонентов, физические oracle, native platform/install/restore, workers, GUI и отдельная scientific acceptance                                                                      | A §1, §5; `P#/campaign_id=review-closure-2026-10-19-exec`. Это шире установки одного solver                                                                                   |
| 19.10 12:38:16; 20.10 13:48:20                               | Пользователь разрешил использовать доступные ресурсы разработки/развёртывания и менять параметры VM серии 7**                                                                                                                                                     | A §5; `P#/operator_resource_update`, `P#/user_VM_7xx_parameter_authority`. Разрешение не отменяет scientific budget/защиту чужих jobs                                         |
| 19.10 →21.10 10:43:07.466                                    | Первый отдельный аудит зафиксировал 46,7632 h elapsed, многочисленные parallel tasks, попытки native guard/resource квалификации и статусные расхождения                                                                                                          | A §2, §6; `P#/preparation_cost_audit`. Нет временного разложения на CPU/idle/ожидание                                                                                         |
| 21–22.10                                                     | Продолжались native routing/TLS/tooling/Julia/HDF5/resource guard задачи, source corrections и DOC/GUI работа; научный запуск ещё не создан                                                                                                                       | `P#/user_status_report`, `P#/current_recovery_status_20261022`; это исторические срезы, не состояние 27.10                                                                    |
| 23.10                                                        | Прямой приоритет: получить результат одного разрешённого P0/B0 исследования; full GUI/Windows/final CI не являются общим предварительным условием раннего научного запуска                                                                                        | `P#/user_research_priority_20261023`: `ONE_AUTHORIZED_P0_B0_RESEARCH_RESULT;CONTINUE_REQUIRED_CRITICAL_PATH_ONLY`. Сохранённое там SCI=0 относится к тому моменту             |
| 24.10                                                        | Пользователь существенно упростил обязательный resource mechanism: снял bespoke HDF5 VFD, controller NBD и исчерпывающий per-effect accounting с критического пути; оставил обычные cgroup/Slurm/systemd/storage bounds, provenance, recovery и неизменную физику | `P#/operator_resource_policy_simplification_20261024`; `P#/B0_resource_mechanism_reconsideration1`. Это принятое изменение инженерного контракта, не научной модели           |
| 24.10 10:07:52.933                                           | Admission перед ordinary runtime build1; далее три короткие тонкие native сборки, квалификации, подписи/переносы и корректировки deployment/admission                                                                                                             | `P#/operations/478`; `P#/ordinary_runtime_ready`; B2/B3. Сами сборки короткие, остальной pipeline шире build wall                                                             |
| 24.10 12:16:21.897732 →12:17:24.644773                       | Первая SCI1 завершилась до SCBA; верхняя граница её charge — 63 s                                                                                                                                                                                                 | `P#/scientific_resource_measurement_current`; `P#/ordinary_B0_submit1`; actual Slurm job 2. От старта сессии до этого прошло около 120,32 h, но это не 120 h непрерывного CPU |
| 24.10, после build2                                          | SCI2 / R1 дошла до одной опубликованной SCBA строки и остановилась из-за scope-return ошибки history writer                                                                                                                                                       | `P#/ordinary_B0_submit2`; H→progress11, конечный SHA `6c3cf7962b29ec1a4a1bf1d1a6a203e9002c9f4dbce61db5fca77c1f6e941aca`                                                       |
| 24.10 15:47:32.974276; terminal прочитан 16:06:11.315        | SCI3 / R2: 96 published SCBA rows, затем operational recovery budget 8 GiB исчерпан; строгого принятия нет                                                                                                                                                        | `P#/ordinary_B0_submit3`; H→progress20. Это не ENOSPC и не доказанная физическая невозможность сходимости                                                                     |
| 24.10 17:25:44 →25.10 07:06:07, scheduler display            | SCI4 / R3, 49223 s: дошла до outer 3, terminal научно failed/invalid при Slurm `COMPLETED 0:0`                                                                                                                                                                    | `P#/ordinary_B0_submit4/science_nodeh_settlement`; H→progress33/34. Эта попытка дала 13,6731 node-h без принятой точки                                                        |
| 25.10, после SCI4                                            | Анализ phase-admission отказа; memory resource profile увеличен, checkpoint44 SHA/header/restore проверены отдельно; GUI изменения продолжались независимо                                                                                                        | H→progress34–46; metadata/source поддерживают первичный отказ по памяти embedding, замаскированный stale phase end, но исходный exception backtrace/OOM не установлен         |
| 25.10 16:53:48.042846 →16:58:37.027099, WorkChain timestamps | SCI5 / R4: restart с checkpoint44, затем отказ до recovery load/SCBA на `Base.cp`/sendfile пути                                                                                                                                                                   | S5 `#/result/aiida/data/rows/0`; `P#/SCI5_R4_terminal_actual`. Native elapsed нижняя/верхняя границы 142–228 s; причина нижнего слоя неизвестна                               |
| 25.10, позднее                                               | Выдано ещё пять cause-specific restart slots; из них к срезу использован один, четыре остались. Frozen physics, 72 h/attempt и shared 936 node-h сохранены                                                                                                        | `P#/operator_SCI6_SCI10_five_restart_amendment`. Не следует повторно считать этот grant пятью actual attempts                                                                 |
| 25.10 21:20:21.635, intent                                   | Для SCI6 собран отдельный cached solver package4, 155,6431 s; последующая qualification 41,6290 s. Выбор корректного builder/cache устранил план из 889 derivations на неподходящем compute target                                                                | B4, Q6; `P#/ordinary_operational_progress50-52`; build4 — engineering package, heavy counter остаётся 3                                                                       |
| 26.10 07:14:51.623                                           | Preconsume SCI6 / R5; один actual job7 после штатного deployment/admission. Нет cold fallback, checkpoint44 переиспользован                                                                                                                                       | `P#/operator_SCI6_SCI10_five_restart_amendment/slots/0`; `P#/operations/1300`; receipt SHA `f6011f274bc432ebe60c827d7da2ca1c605b8fb74b043f73f64e352b7e69388a`                 |
| 26.10 параллельно science                                    | Новый GUI engineering APP построен; 24 уникальные transitive derivation builds, observed build wall 47,166 s. Несколько metadata-readiness corrections; финальный installed actor metadata read прошёл, service не активирован                                    | `P#/ordinary_operational_progress67/APP`; source root GUI `d395044ac09b28c2ff573724f8911d625df43bf5` отличается от science runtime root                                       |
| 27.10 06:28:57.890                                           | SCI6 Slurm elapsed `23:13:02`, outer9/inner255, strict fixed point false; cumulative job CPU counters сохранены                                                                                                                                                   | S6 `#/result/health`, `P#/ordinary_operational_progress69`                                                                                                                    |
| 27.10 06:46:18                                               | Memory audit: job продолжает работать, outer9/inner269; no OOM/kill observed; accepted point нет                                                                                                                                                                  | `P#/ordinary_operational_progress70`. Final full CI=0; heavy attempts=3; scientific submits=6                                                                                 |

Полное elapsed окно 19.10 11:57:19.876→27.10 06:46:18 равно **672538,124 s =186,8161 h**. Нельзя
складывать с ним 46,7632 h раннего аудита, время SCI4/SCI6 или lifetimes дочерних агентов: эти
интервалы находятся внутри общего окна и перекрываются. Начало окна и текущий snapshot задают
календарное время сессии, а не подтверждённое active working time.

## Что действительно измерено о стоимости

| Категория                            |                                                                                           Число / время | Scope, смысл и ограничение                                                                                                                                                                                             |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------: | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Учтённые heavy thin builds1–3        |                       3; 161,511403 +155,861150074 +156,087053677 =**473,459606751 s**, 0,13151655743 h | `P#/counters/heavy_build_attempts`, `heavy_build_wall_hours`; build1 из `ordinary_runtime_ready`, B2/B3 `#/result/files/terminal-receipt.json/wall_seconds`. Wall, не CPU; не весь native setup/install pipeline       |
| Cached solver package4               |                                                                                     **155,643112318 s** | B4 `#/result/package/terminal-receipt.json/data/wall_seconds`; terminal SHA `07dcd4cf89c4c0c277c7558b9f46a55709ff071c04d11f9eb59150b635819798`. Не включает соседние preflight/sign/transfer/admission                 |
| SCI6 C01/C02 qualification           |                                **41,628958761 s**, CPU delta **45,244457 s**, mem peak **1290661888 B** | Q6 terminal `resources_before/after` cpu.stat. Это bounded qualification без SCBA; не научная приёмка                                                                                                                  |
| GUI APP engineering realization      |                          **47,165762301 s**, mem peak **983105536 B**, 24 unique transitive derivations | `P#/ordinary_operational_progress67/APP`; `build_unit_attempts_actual=2`, `APP_realise_CLI_actual=1`. Unit entries не равны 2 полным builds; heavy3 counter не означает отсутствие этого engineering build             |
| Local Julia preparation              |                                                                         3 attempts; **424,094642401 s** | `P#/counters/local_julia_preparation_*`; INT01-JULIA-PREP-1 184,830804110 s, IMPORT-2 128,419805288 s, BOUNDS-3 110,844033003 s. Не прибавлять повторно cumulative field последней операции                            |
| Старый census targeted checks        |                                                                             91 receipts; **1080,902 s** | `P#/targeted_receipt_census`; census SHA `7aea935b4c9aaf79b4e6d74ea3834c3d08db4857796adf6afbefc4dff8780710`. Включает RED/failed/projection, не «91 успешный тест»                                                     |
| Поздние targeted counter aliases     | `targeted_test_total_calls=117`; `targeted_test_calls_total=217`; wall aliases оба **1316,055875824 s** | `P#/counters`. Counters покрывают разные серии/этапы; комментарий scope прямо говорит historical/incomplete. Не суммировать 117+217 и не приписывать 217 проверкам полное wall 1316 s без per-operation reconciliation |
| Пример отдельного GUI focused budget |                                                        7 actual calls; **46,428418276 s** при 240 s cap | H→progress46; `P#/counters/GUI_live_performance_common_*`. Это одна серия, перекрывается другими census/GUI counters, не независимое дополнение ко всем aggregates                                                     |
| SCI1–5 terminal charges              |                                                                           **14,649936510833331 node-h** | `P#/counters/scientific_execution_node_hours`; смесь conservative bounds/actual scheduler elapsed. Это charged completed attempts, не полная стоимость работающей SCI6                                                 |
| SCI6 active reservation              |                                                    **72 node-h**, 1 node ×72 h, 12 CPU, 33 GiB, no swap | `P#/counters/scientific_execution_node_hours_reserved`; не уже израсходованные 72 h. На момент S6 observed elapsed=23,217222 h                                                                                         |
| Final full CI                        |                                                                                   **0 dispatches из 1** | `P#/counters/final_full_ci_dispatches`; scientific/runtime/GUI focused checks не подменяют этот gate                                                                                                                   |

В operations много `wall_seconds=60/90/120/...` в prebook/coordination записи, где это **лимит**, а
в observer receipt `wall_seconds≈1–5 s` — время команды чтения, не длительность job/build. Есть
cumulative wall snapshots и повторные status reads. Поэтому механическая сумма всех 974 полей
`wall_seconds` в журнале дала бы заведомо неверный total. Аналогично нельзя складывать CPU/RSS
родительского cgroup, job, step и task: они включают одну работу иерархически.

### Научные попытки и время без принятой точки

| Attempt       | Historical terminal status                                         |                                                           Charge / факт | Ограничение                                                                                           |
| ------------- | ------------------------------------------------------------------ | ----------------------------------------------------------------------: | ----------------------------------------------------------------------------------------------------- |
| SCI1=B0, job2 | Failed before SCBA: progress writer scope-return `target`          |                                                    ≤63 s =0,0175 node-h | Conservative creation→terminal bound, не exact scheduler accounting                                   |
| SCI2=R1, job3 | History writer `destination` scope-return; один published SCBA row |                                            ≤151 s =0,04194444444 node-h | Conservative upper; published row не принятие                                                         |
| SCI3=R2, job4 | 8 GiB recovery guard; 96 rows, strict not reached                  | scheduler runtime 2845 s; **charge 3074,771439 s =0,8541031775 node-h** | Charge root creation→terminal включает retrieval; эти два числа не складывать                         |
| SCI4=R3, job5 | Slurm `COMPLETED 0:0`, science failed/invalid                      |    **49223 s =13,67305555556 node-h**; allocated core-hours=164,0766667 | CPU usage не измерен этим scheduler elapsed; primary memory pressure и masked phase error различаются |
| SCI5=R4, job6 | Failed before recovery load/SCBA on copy path                      |                                    **upper228 s =0,06333333333 node-h** | Last observed native elapsed142 s; sacct disabled, expired scontrol; lower-layer cause не установлена |
| SCI6=R5, job7 | RUNNING, strict unresolved                                         |                       elapsed23:13:02 при S6; 72 h reservation остаётся | Terminal costs/acceptance ещё не закрыты; нет нового restart по этому observation                     |

SCI4 составляет около **93,33%** накопленного terminal charge SCI1–5. Это измеренное ранжирование
**terminal node-hours**, не доля всей задержки проекта. В S6 накопленная CPU job7=`436338421774 µs`
=**436338,421774 CPU-s =121,2051172 core-h**; user=213014,718828 s, system=223323,702946 s. При
observed elapsed23:13:02 это около **5,2205 одновременно занятых logical CPUs**, или **43,50%** от
12 выделенных, усреднённо за весь этот interval. В знаменатель входит
startup/I/O/checkpoints/ожидание; это не scaling benchmark и не доказанная избыточность 12 threads.
Доля system CPU сама по себе не устанавливает NFS/GC/kernel bottleneck.

S6 `/result/health/cgroups/.../job_7/cpu.stat` и `step_batch/.../task_0/cpu.stat` почти одинаковы,
что соответствует nesting; в расчёт взят **один job scope**. Lifetime system.slice и nix-daemon CPU
totals без matching begin/end нельзя выдавать за CPU одного выбранного build. В B4 worker cgroup
показывает около0,96 CPU-s, а daemon/slice — сотни cumulative CPU-s: это разные scopes, которые
наглядно показывают ошибку учёта native build только по client process.

На срез S6 арифметика «14,64994 prior terminal charge +23,21722 active elapsed» даёт **37,86716
node-h provisional booked-plus-observed**, но это смешение консервативных завершённых charges и
незавершённой текущей длительности. Оно не является точным общим расходом или счётом; окончательный
SCI6 charge надо закрыть один раз по terminal evidence. Shared cap936 node-h — бюджет, а не время
гарантированной сходимости и не обещание39 суток serial исполнения.

## Агентные затраты: что известно и чего нельзя восстановить

Ранний A покрывает только **19.10 11:57:19.876→21.10 10:43:07.466 UTC**, original main cutoff37765.
`P#/preparation_cost_audit` сохраняет:

- Root output **2763743 tokens**; validated child output lower bound **9073765 tokens**; вместе
  **≥11837508 output tokens** в том раннем окне. Три child identities unresolved не считаются нулём;
  grandchildren не покрыты полностью.
- **252 spawn**, **618 followup**, **383 send_message**, **27 compactions**. Это ранние counts, не
  полная статистика до27.10.
- Крупнейшие отдельные output streams: Root2763743; sci05_core_reviewer300189; doc03_design299163;
  reviewer257931; sci03_current_bound_review209542; tls_crypto_i2_review188670. Ранг по output, не
  по billed dollars, CPU или active hours.
- Два видимых gaps около6,25 h: 19.10 21:39:43.827→20.10 03:54:12.826 и 20.10 21:37:59.428→21.10
  03:54:14.949. Причины не установлены. Safe timeline не содержит все raw record types, поэтому это
  не доказанный idle или ожидание пользователя.

Денежная стоимость в A/P — `NOT_AVAILABLE`. Сохранённые cached-input/output counters не являются
billing invoice. Нельзя умножать на произвольно выбранный тариф, смешивать cached и uncached input,
выдавать output за все tokens или переносить ранние11,84M на весь8-дневный период. Нет свежего
полного token/billing census на21→27.10, точного active-agent-time breakdown, времени ожидания
network/operator/model или полного причинного latency graph. Этому аудиту не поручалось читать raw
чаты или получать счёт.

## Причины затрат: факт, вывод и гипотеза

**ФАКТ:** большой согласованный scope включает самостоятельные gates нескольких repositories, native
release/trust/platform/runtime, worker, GUI/docs, научные oracle и recovery. **ВЫВОД:** часть
сложности необходима; «пять суток = solver компилировался пять суток» противоречит measured build
durations. **ОГРАНИЧЕНИЕ:** точная доля необходимой и избыточной работы в часах неизвестна.

**ФАКТ:** ранний аудит уже обнаружил чрезмерную дробность координации, статус DEV02 оставался open
после принятого scope; foundation independence противоречила одной summary table; errors107/110/111
касались authority window/driver125/outer identity до полезного scientific runtime. **ВЫВОД:** часть
повторных source/qualification/preconsume пакетов вызвана реальными дефектами инженерной обвязки и
восстановлением контекста. **ОГРАНИЧЕНИЕ:** численные «потерянные часы» конкретной ошибке не
приписаны; многократное чтение навыка не доказывает повтор реализации.

**ФАКТ:** до24.10 обязательный нестандартный resource путь включал VFD/NBD/exhaustive-effect proof;
23.10 отдельный audit закрепил early-science priority, 24.10 пользователь снял эти механизмы с
критического пути. **ВЫВОД:** проект тратил существенное организационное/агентное усилие на
механизм, который позднее был признан необязательным; выбранный механизм был шире практической
потребности раннего B0 результата. **ОГРАНИЧЕНИЕ:** нет основания заявлять, что все эти работы
бесполезны или что их удаление единолично сэкономило точное число суток. Приоритеты изменились явно
и датированы.

**ФАКТ:** после упрощения SCI1/2 выявили scope-return ошибки writer; SCI3 остановлена storage
policy; SCI4 отработала13,67 h и научно failed; SCI5 остановлена copy path; SCI6 продолжает работу.
**ВЫВОД:** длительное время до accepted solution теперь обусловлено не только подготовкой среды, но
и реальной неудачей/стоимостью execution/recovery/численного решения. **ОГРАНИЧЕНИЕ:** не получено
положительной научной приёмки, нельзя вычислять time-to-accepted-solution, speedup или ETA
сходимости.

**ФАКТ:** поздние engineering задержки включали GitHub/cache connectivity; Head-only mirror с
`allRefs=true` оказался причиной двух source-fetch отрицательных исходов, а не «просто offline»;
корректный builder использовал cache вместо плана889 derivations. GUI APP потребовал network route и
corrections overly strict profile filesystem probes. После build47 s прошли пять actual APP metadata
entries этого series, с сохранением отрицательных исходов. **ВЫВОД:** инженерная turnaround
стоимость определяется ещё source acquisition, admission, identity и observer correctness, а не
одним `nix build` wall. Локаторы: `P#/ordinary_operational_progress51/network`,
`P#/ordinary_operational_progress67/APP/technical_cost_causes`, `.../native_read8`.

**ФАКТ:** science и GUI/docs выполнялись параллельно; SCI6 держит compute36GiB/12CPU, CI выключен в
production profile, controller4GiB. DOC04 выбранный guard требует4GiB available (3GiB cap+1GiB
reserve), недостижимый на занятом4GiB guest. **ВЫВОД:** выбранная безопасная последовательность
ограничивает параллельный native DOC04/deploy capacity. **ОГРАНИЧЕНИЕ:** ждать окончания SCI —
выбранный путь, не доказанная единственная возможность; source/docs работа и подготовка другого
admitted target не были вообще запрещены. «MemTotal минус configured VM RAM» не равно физически
свободной RAM. Локатор: `P#/ordinary_operational_progress69/progress68_interpretation_corrections`.

## RAM/I/O и ограничения будущего прогноза

`P#/ordinary_operational_progress70` разделяет numerical estimate **13806384496 B=12,858 GiB**,
process high-water **25962893312 B=24,180 GiB**, cgroup cap **33 GiB**. Это разные scopes;
универсального коэффициента1,88 для будущих запусков отсюда не следует. File cache в двух свежих
snapshots ≈10,612 GiB; anon за5,15 s уменьшился≈1,154 GiB; OOM/kill=0, cap/reclaim events ранее
накапливались. Происхождение cache и причина освобождения anon не установлены; это не доказательство
GC и не доказанное отсутствие leak.

Текущий собственный tree в S6: logical11745472831 B, allocated11748487168 B, complete
walk1341files/1356entries. Это размер имеющихся файлов в одном scope, **не cumulative read/write
traffic**, не all copies и не RAM. Top-level `scientific_read_bytes`, `scientific_written_bytes`,
`scientific_resident_bytes` — null; ранние SCI=0 и historical unknowns не превращаются в нулевой
I/O. Для NFS разные syscall/logical/physical counters не взаимозаменяемы. Сохранённые proc/io
partial counters из memory audit не закрывают общий cumulative NFS accounting.

История на memory snapshot: 2431 SCBA rows,6outer rows,1301segments, index194196B, сумма segment
files327235936B. Source audit установил O(total history) temporary materialization и I/O при каждом
checkpoint; raw selected witness payload≤23,37MiB, две raw generations≤46,74MiB, metadata/allocator
overhead отдельно unknown. Это реальный future growth path, но не объяснение уже наблюдавшихся
гигабайт одной лишь величиной matrices. Для multi-day RAM/стоимости нужны phase-specific anon
baseline, штатный checkpoint peak, history/segment rate, native overhead и file-cache budget;
линейно экстраполировать memory.current по дням нельзя.

## Актуальные ограничения и действия после этого аудита

На срезе P: scientific submits6, accepted points0, extra restart slots4, running SCI6 immutable;
heavy attempts3; final fullCI0/1. P поля `scientific_resource_measurement_current`,
`resource_current`, `user_status_report`, `selected_source_current` и часть task statuses содержат
более ранние состояния. Текущую истину следует брать из прогресса69→70 плюс immutable identities, а
не считать все верхнеуровневые «current» поля одинаково свежими. Science runtime root
`cb1bae7ffdbb977f33d81e05b8ebd50afb4177ee`, Core `5b1cdd458eb07ff8c7c792642eda58d9061e1017`, Runner
`4609c2e0837df92a831a265f006bc3262b1ae875` не равны GUI candidate root
`d395044ac09b28c2ff573724f8911d625df43bf5`; Git ancestry не является численной/native приёмкой.

Научное terminal accounting/acceptance надо закрыть один раз после terminal; до него продолжать уже
разрешённое наблюдение без restart, изменения модели/допусков или нового расчёта ради аудита. Для
разработки полезно сохранять один краткий ledger «действие/исход/actual wall/CPU/scope/hash»,
отделять cap/reservation от actual, подключать async status reads к исходной операции и компактно
отражать только изменившиеся readiness gates. Полный fresh token/billing census и
streaming/incremental history consolidation — отдельные инженерные задачи; здесь они не выполнялись.

| Утверждение                                                                      | Свидетельство                                                               | Ограничение                                                | Решение                |
| -------------------------------------------------------------------------------- | --------------------------------------------------------------------------- | ---------------------------------------------------------- | ---------------------- |
| До first science было около5 календарных суток подготовки                        | A start; SCI1 creation/terminal; приоритет23.10 и amendment24.10            | Нет полного active-time causal breakdown                   | дополнительно измерить |
| Три counted heavy builds не объясняют несколько суток                            | exact473,4596s и matched heavy wall counter; B2/B3                          | Это узкая build category, не весь native engineering       | сохранить              |
| Большие агентные накладные расходы подтверждены в раннем окне                    | A/P preparation counters≥11,8375M output,252spawn/618followup/27compactions | Не всё8-дневное окно, нет billing                          | изменить               |
| SCI4 дала основной terminal node-h расход без научного принятия                  | 49,223s;13,6731 из14,64994node-h; process0≠acceptance                       | Нет полного measured CPU SCI4                              | сохранить              |
| Активная SCI6 не включена в terminal charge14,64994h                             | reservation72; S6 elapsed23:13:02 и CPU121,205core-h                        | Terminal ещё не наступил; предварительная сумма не invoice | дополнительно измерить |
| Истории и native metadata путь требуют контроля future peak/I/O                  | P progress70, exact-source memory audit                                     | Глобальные NFS/allcopies totals unknown                    | дополнительно измерить |
| Полная CPU/денежная/active-agent стоимость сессии известна                       | Полных counters/invoice нет                                                 | Missing не равно0; parallel/ancestors нельзя суммировать   | данных недостаточно    |
| Научная приёмка и fullrelease остаются отдельными от source/qualification checks | Результат отсутствует; job7 running; fullCI0                                | Отдельные gates не взаимозаменяемы                         | сохранить              |
