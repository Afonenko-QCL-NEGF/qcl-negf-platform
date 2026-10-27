# Научные попытки, recovery и граница вывода

Исследовательский вопрос оставался прежним: квантовый транспорт для frozen модели при **0 mV/period,
70 K**, с LO/acoustic/impurity/IFR/alloy и **без electron–electron**. Для текущего SCI6:
`N_E=30 721`, `N_k=11`, `N_b=5`, `basis_periods=3`, linear mixing, 12 Julia threads/BLAS1, job cap33
GiB и wall≤72 h. `N_b` определяется `basis_states=5`, а не произведением на число периодов. Это
паспорт попытки, не физический вывод. Runtime root `cb1bae7ffdbb977f33d81e05b8ebd50afb4177ee`, Core
`5b1cdd458eb07ff8c7c792642eda58d9061e1017`, Runner `4609c2e0837df92a831a265f006bc3262b1ae875`; более
поздний GUI root к ней не приписан. [Source catalog](evidence/source-catalog.md) ·
[science snapshots](evidence/science-snapshots.md).

| Submit / logical slot | Наблюдаемое исполнение и outcome                                                                                                                                               | Научный статус на terminal/срезе                                   |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------ |
| SCI1 / B0, job2       | CalcJob завершился до SCBA; original raw/provenance сохранены (`QCL-ORDINARY-B0-SUBMIT1`).                                                                                     | Результат не получен, strict acceptance `not_measured`.            |
| SCI2 / R1, job3       | Одна опубликованная SCBA строка, затем terminal failure history writer (`QCL-ORDINARY-B0-SUBMIT2`); без auto-retry.                                                            | Нет принятого состояния.                                           |
| SCI3 / R2, job4       | SCBA публиковала 96 строк, затем исчерпан recovery budget; Slurm `0:0` при AiiDA/operational failure (`QCL-ORDINARY-B0-SUBMIT3`).                                              | Exit 0 не является scientific pass.                                |
| SCI4 / R3, job5       | Отдельно разрешённый cause-specific restart; scheduler exit0, но scientific terminal invalid: `phase ended without begin: candidate_scattering` (`QCL-ORDINARY-B0-SUBMIT4`).   | Scientific failure, accepted points 0.                             |
| SCI5 / R4, job6       | Проверенный checkpoint оставлен; копирование остановилось **до** recovery load и SCBA; точная нижнеуровневая причина не доказана (`QCL-SCI5-R4-TERMINAL-ACCOUNTING1`).         | Нет научного результата; failed receipt сохранён.                  |
| SCI6 / R5, job7       | Одна восстановленная попытка из verified generation44/bundle105; на CP70 `RUNNING`, SCBA outer9/inner269, без restart/requeue/OOM/kill (`QCL-SCI6-R5-MEMORY-BREAKDOWN-READ2`). | `fixed_point_passed=false`; terminal/physical verdict отсутствует. |

SCI6 использует одно настоящее AiiDA root WorkChain/CalcJob/Slurm job; у root нет входящего
`CALL_WORK` от PlanWorkChain, зато есть прямой `CALL_CALC` к CalcJob. Поэтому старый `/runs`
Plan-view не открывал этот standalone recovery; новый GUI ввёл отдельное read-only представление, не
синтетический parent и не повторный submit. Recovery association и общий Plan input доказывают
происхождение данных, но не завершённость уравнений. Перенос checkpoint был проверен по исходной
generation; «восстановлено» означает выбранное durable состояние, а не новую физику или принятую
стационарность. [GUI view](gui-docs-and-workers.md).

Состояние вычисления надо разложить по уровням:

| Уровень                     | Критерий/свидетельство                                                                           | Вывод к CP70                                                                                |
| --------------------------- | ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------- |
| Исполнение                  | AiiDA process, Slurm allocation, живой Julia PID и обновление saved point                        | SCI6 действительно работала; предыдущие terminal failures сохранены                         |
| Численная сходимость        | Frozen strict SCBA/Poisson/fixed-point gates на подходящем final state                           | Не достигнута: `fixed_point_passed=false`; текущий mixed step не заменяет fresh final audit |
| Физические проверки         | Сохранённые исходные массивы, нормировки, веса, единицы, PSD/ток/continuity и независимый reader | Финальный набор ещё не существует; статус `not_measured`                                    |
| Достаточность дискретизации | Сопоставимые проверки сетки/базиса/окна при том же вопросе                                       | Не установлена; текущая единственная сетка не доказывает convergence                        |
| Экспериментальная валидация | Сопоставимый внешний набор и неопределённости                                                    | Вне полученного свидетельства; не заявлена                                                  |

В READ26 (более ранняя точка outer9/inner255) были `rΣ=0.00100837`, `rK=0.000205945`,
`rJchange=0.000344105`, `failed_gate_count=4`; главный строгий ограничитель `rΣ` был в 100837 раз
выше своего допуска. Эти числа не переносятся на более поздний CP70 inner269 и не дают линейной
траектории по разным внешним потенциалам. Источник —
[снимки с точным временем](evidence/science-snapshots.md). Slurm deadline 72 h не предсказывает
convergence.

На срезе завершённые attempts уже учтены консервативно в 14.649936510833331 node·h; текущая 72
node·h — **reservation**, не израсходованные часы. Для job7 требуются terminal `sacct`/AiiDA
reconciliation и затем независимое чтение небольших метаданных/выборок результата; cumulative I/O и
окончательная стоимость пока неизвестны. Новые четыре grant-slots не используются автоматически.
Нельзя исправлять расход памяти или residual сменой scattering/grid/basis/window/допуска без
отдельного научного решения. [Метрики](evidence/metrics-ledger.md) ·
[ресурсы](resource-control-and-cost.md).

| Утверждение                             | Свидетельство                                   | Ограничение                                 | Решение             |
| --------------------------------------- | ----------------------------------------------- | ------------------------------------------- | ------------------- |
| SCI6 выполнялась и продвигалась         | CP70/job7, outer9/inner269, no OOM              | Terminal и strict final audit ещё нет       | сохранить           |
| SCI4/job5 был успешен, потому что exit0 | Scientific failure `candidate_scattering`       | Scheduler проверяет другую границу          | изменить            |
| SCI6 уже даёт физический ответ          | `fixed_point_passed=false`; нет terminal result | Discretization/validation также не измерены | данных недостаточно |
