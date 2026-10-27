# Реестр численных счётчиков

[Общий отчёт](../README.md) · [Пояснение времени и затрат](../resource-control-and-cost.md)

Это буквальные поля frozen checkpoint70, а не полная сверенная бухгалтерия. Не суммировать
пересекающиеся aliases или reservation со spent. `null` означает неизвестно, не0.

| Ключ counters                               |            Значение | Обязательная квалификация                                                           |
| ------------------------------------------- | ------------------: | ----------------------------------------------------------------------------------- |
| heavy_build_attempts                        |                   3 | Локатор поля, scope пояснён в cost-and-time.                                        |
| heavy_build_wall_hours                      | 0.13151655743083335 | Узкие три heavy attempts:473.459606751s; не весь elapsed bootstrap.                 |
| preflight_attempts                          |                   3 | Локатор поля, scope пояснён в cost-and-time.                                        |
| scientific_submits                          |                   6 | Локатор поля, scope пояснён в cost-and-time.                                        |
| scientific_extra_R5_R9_granted              |                   5 | Локатор поля, scope пояснён в cost-and-time.                                        |
| scientific_extra_R5_R9_consumed             |                   1 | Локатор поля, scope пояснён в cost-and-time.                                        |
| scientific_extra_R5_R9_remaining            |                   4 | Локатор поля, scope пояснён в cost-and-time.                                        |
| scientific_execution_node_hours             |  14.649936510833331 | Charged terminal SCI1–5; текущий SCI6 сюда ещё не включён.                          |
| scientific_execution_node_hours_reserved    |                  72 | Reservation72node·h, не уже потраченное время.                                      |
| final_full_ci_dispatches                    |                   0 | Локатор поля, scope пояснён в cost-and-time.                                        |
| setup_attempts                              |                   7 | Локатор поля, scope пояснён в cost-and-time.                                        |
| targeted_test_calls_total                   |                 217 | Исторические aliases117/217 расходятся; не складывать и не объявлять полным census. |
| targeted_test_total_calls                   |                 117 | Исторические aliases117/217 расходятся; не складывать и не объявлять полным census. |
| targeted_test_total_wall_seconds            |   1316.055875824009 | Исторические aliases117/217 расходятся; не складывать и не объявлять полным census. |
| scientific_read_bytes                       |                null | Неизвестно; не заменять0/успехом.                                                   |
| scientific_written_bytes                    |                null | Неизвестно; не заменять0/успехом.                                                   |
| scientific_resident_bytes                   |                null | Неизвестно; не заменять0/успехом.                                                   |
| GUI_APP_ordinary_realizations_actual        |                   1 | Локатор поля, scope пояснён в cost-and-time.                                        |
| GUI_APP_build_unit_attempts_actual          |                   2 | Локатор поля, scope пояснён в cost-and-time.                                        |
| GUI_APP_native_installed_invocations_actual |                   5 | Локатор поля, scope пояснён в cost-and-time.                                        |
| GUI_APP_native_metadata_passes_actual       |                   1 | Локатор поля, scope пояснён в cost-and-time.                                        |

## Различимые границы времени

READ26: elapsed SCI6=23:13:02=23.217222 node·h на одном node. `cpu.stat:usage_usec=436338421774`
соответствует121.205117 core·h процесса cgroup; 12CPU×elapsed=278.606667 allocated core·h. Эти три
величины различаются; деление CPU/elapsed даёт около5.22 busy logical CPU в среднем за покрытый
interval, не фазовый профиль и не абсолютный scaling verdict. Частичная сумма
terminal14.64993651+live23.217222≈37.867159 node·h на срез READ26 — observation, не выполненное
terminal reconciliation SCI6 и не полное billing.

См. cost-and-time: ранняя статистика agent output/calls относится к другому ограниченному cutoff.
Денежная стоимость и полные CPU/token totals всей сессии неизвестны.
