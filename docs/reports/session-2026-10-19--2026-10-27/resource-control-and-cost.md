# Ресурсы, время и стоимость: измеренное и неизвестное

Ресурсная политика охватывала **всех** агентов и native попытки вместе. Научный job использовал 12
CPU, 33 GiB cgroup cap, swap0 и предел72 h; protected foreign VM/jobs не вытеснялись. Для build
действовал finite allowance: три различающиеся heavy attempts, 12 h каждая/36 h вместе, один Nix job
и общий дополнительный resident peak cap100 GiB с сохранением failed outputs. Эти пределы — бюджет и
stop, а не фактическое потребление. На срезе heavy attempts **3/3**, их суммарное зафиксированное
wall time **473.46 s** (`counters.heavy_build_wall_hours≈0.1315166`), final full CI **0/1**. APP
engineering realization 47.165 s и native8 metadata probe — отдельные ordinary actions; их нельзя
задним числом объявлять четвёртой heavy build или финальным CI.
[Метрики](evidence/metrics-ledger.md) · [операции](evidence/operation-ledger-3.md).

| Время/стоимость                             |                                                                                 Подтверждённое значение | Почему это не полный итог                                                                                                                 |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------: | ----------------------------------------------------------------------------------------------------------------------------------------- |
| Scientific terminal charge до SCI6          |                                                                               14.649936510833331 node·h | Относится к уже закрытым попыткам; terminal job7 ещё не reconciled                                                                        |
| SCI4/job5                                   | 13.673055555555555 node·h — около 93.33% учтённых terminal SCI1–5; 164.0767 allocated core·h при 12 CPU | Slurm exit0 сопровождался scientific failure; доля относится только к раннему terminal charge, core·h и node·h не складываются            |
| SCI5/job6                                   |                   ≤0.06333333333333334 node·h консервативная верхняя граница по dispatch→AiiDA terminal | `sacct` unavailable, не точная native wall                                                                                                |
| SCI6/job7                                   |            72 node·h текущая reservation; в READ26 прошло 23:13:02 ≈23.217 node·h календарного job wall | Reservation не charge; после terminal нужна одноразовая `sacct`/AiiDA сверка                                                              |
| SCI6/job7 CPU в READ26                      | `cpu.stat:usage_usec=436338421774`, то есть 121.205 core·h; 12 CPU × elapsed = 278.607 allocated core·h | Эти значения описывают разные знаменатели; средние ≈5.22 занятых logical CPU не являются фазовым профилем или вердиктом о масштабировании |
| Heavy builds                                |                                                        3 попытки, суммарно 473.46 s measured build wall | Не включает source/review, cache preparation, APP ordinary build, ожидание                                                                |
| Дополнительный cached solver package4       |                                                               155.643 s, qualification C01/C02 41.629 s | Отдельные последующие engineering действия для SCI6, не четвёртая counted heavy attempt и не solver wall                                  |
| Локальная Julia preparation                 |                                                                  3 bounded attempts, суммарно 424.095 s | Узкая категория подготовки, не весь научный runtime и не добавка к каждой cumulative строке                                               |
| APP engineering                             |                                                                       47.165 s, peak983,105,536 B, OOM0 | Не deployed run/CI; зафиксирован отдельным native receipt                                                                                 |
| Денежная стоимость, общие token/agent-hours |                                                                        `not_available` / `not_measured` | Нет полного биллинга и непрерывного, неперекрывающегося учёта                                                                             |

От измеренного начала EXEC **19.10 11:57:19.876 UTC** до CP70 **27.10 06:46:18 UTC** прошло
**≈186.8161 календарных часа**. Это интервал между двумя метками, а не активное внимание
человека/агентов, занятость хоста, последовательный critical path или оплаченная работа. Ранняя
частичная перепись **91** сохранённого operation receipt дала 1080.902 s суммы их wall, но она не
охватывает все вызовы и включает пересечения; это **не** длительность сессии и не CPU-hours.
Исторический preparation snapshot давал 46.763 h своего окна; его нельзя переносить как финальный
интервал до CP70. Поздний реестр [времени](evidence/metrics-ledger.md) и
[независимый аудит](evidence/cost-audit.md) показывают источник каждого числа. Нет основания
выводить стоимость в валюте из API токенов, VM часов или reservation.

Если сложить 14.6499365 node·h учёта закрытых SCI1–5 и 23.217222 node·h **прошедшего wall SCI6 на
READ26**, получится ≈37.867159 node·h. Это неполная смешанная учётная оценка booked-plus-observed:
SCI1/2/5 включают консервативные верхние границы, SCI3 — retrieval, а SCI6 ещё не завершилась. Сумма
не задаёт гарантированной нижней или верхней границы фактического расхода, не является settled
charge SCI6, полным job accounting или стоимостью всей сессии. После terminal нужна одноразовая
сверка. CPU121.205 core·h нельзя прибавлять к node·h, а 278.607 allocated core·h — только
произведение выделенных 12 CPU на тот же прошедший интервал.

Ранний аудит `preparation-audit-and-runner111-preconsume1/case/report.md` (SHA-256
`ddfc838d7b0de87b7c95da3dcd4234a90bc12cbd8adff31c4784556c14487d0a`) покрывал только **19.10
11:57→21.10 10:43 UTC**: root output 2,763,743 токена и подтверждённая нижняя граница child output
9,073,765, вместе ≥11,837,508 output tokens. Он также зафиксировал 252 spawn, 618 follow-up и 27
compactions. Это свидетельство затрат на координацию в **первых ≈46.763 h**, не полный token census
до 27 октября, не billable total и не доказательство причины каждого ожидания. Поздние
`targeted_test_total_calls=117` и `targeted_test_calls_total=217` — расходящиеся исторические
aliases; их нельзя складывать или автоматически связывать с 1316.056 s cumulative targeted wall.
`wall_seconds` в части operation entries обозначает prebook limit, поэтому механическая сумма всего
журнала тоже не является длительностью кампании. [Counter keys](evidence/metrics-ledger.md) ·
[метод](method-and-limits.md).

Память SCI6 требует разделения разных scope. В двух native snapshots 27.10 06:35:50→06:35:55 UTC
`memory.current` упала **30.647→29.490 GiB**; `memory.stat:anon` **19.908→18.754 GiB**; `file`
оставалась ≈**10.612 GiB**, почти вся inactive/clean, `kernel` ≈0.12 GiB. Julia `smaps_rollup:Rss`
**20.139→19.045 GiB**, тогда как VmHWM ≈**24.180 GiB** оставался неизменным около9.2 h. Это
доказывает существенный file cache и изменение anonymous resident памяти, но не «весь рост был
кэшем»: более ранний RSS/HWM тоже увеличивался. Ни непрерывная утечка, ни её отсутствие на будущих
фазах не доказаны. Cgroup cap33GiB уже вызывал reclaim/refault (`memory.events:max≈57,574`),
OOM/kill0; cap цензурирует дальнейший возможный peak.
[Научный аудит памяти](evidence/science-snapshots.md) · [метрики](evidence/metrics-ledger.md).

Численный estimator дал **12.858 GiB**, измеренный Julia HWM — **24.180 GiB**. Это разные величины:
estimator описывает часть численного resident набора, не runtime/JIT/GC/native workspaces, временные
checkpoint tables, file cache и весь cgroup. Ratio≈1.88 не является универсальным коэффициентом
исправления формулы или доказательством leak. Source audit не нашёл per-iteration накопления полных
Green/self-energy arrays, но установил синхронное объединение всей истории на каждом checkpoint:
`2431` SCBA rows, `1301` segments, текущие выбранные witness payloads ≤**23.37 MiB** (две raw
generations ≤46.74 MiB). Это пока не объясняет гигабайты само по себе; будущие O(total history)
время/пики надо измерять по одинаковым фазам, а не экстраполировать linearly от одного графика.
[Core/Runner source refs](evidence/source-catalog.md).

DOC04 capacity — отдельная практическая граница. Выбранная одна native попытка требует
`MemoryMax=3 GiB` **и** fresh reserve1 GiB, то есть `MemAvailable≥4,294,967,296 B`. У неизменной
controller VM usable `MemTotal=4,105,854,976 B` — сам максимум гостя ниже порога на189,112,320 B;
окончание job в другой VM не исправит этот факт для **неизменного controller**. На PVE host
`MemTotal=67,011,194,880 B`, сумма max allocations работающих VM `62,277,025,792 B`; арифметический
остаток распределений `4,734,169,088 B`, лишь `439,201,792 B` сверх требуемых4 GiB host reserve. Это
**не** гарантированно свободная RAM. Фактический host `MemAvailable≈9.2 GiB` — отдельная моментная
метрика, тоже не заменяющая fresh admission. При работающей SCI и защищённых foreign VM расширение
controller/включение CI не было допущено; после SCI выбран путь ресурсного перераспределения QCL VM.
Другой подготовленный и квалифицированный target логически возможен, но на срезе его bindings не
были доказаны. Профиль3+1 GiB выбран инженерно, не доказан как физический минимум Documenter; 2 GiB
peak не измерен. [DOC state](gui-docs-and-workers.md).

Диск и I/O описаны тем же принципом. Текущий job tree около10.94 GiB — занятые файлы, **не**
cumulative reads/writes. Исторический index имел327,235,936 B сегментов; это текущий retained volume
и source для bounded metadata audit, а не весь сетевой transfer.
`scientific_read_bytes`/`scientific_written_bytes` в CP70 неизвестны, поэтому ни соблюдение полного
I/O cap, ни нулевой расход не заявлены. Сводные metrics не заменяют raw terminal receipts и AiiDA
provenance.

| Утверждение                                 | Свидетельство                                     | Ограничение                                                                                      | Решение                |
| ------------------------------------------- | ------------------------------------------------- | ------------------------------------------------------------------------------------------------ | ---------------------- |
| SCI6 memory growth — доказанная leak        | anon/file/HWM и независимые source/runtime аудиты | Sparse phase snapshots, GC/native heap не покрыты                                                | данных недостаточно    |
| Можно обещать 72 h и конечный RAM peak      | Снимки и cap33GiB                                 | Future outer/checkpoint фазы не измерены                                                         | дополнительно измерить |
| DOC04 сейчас проходит RAM admission         | VM MemTotal < выбранный available threshold       | Для неизменной controller VM условие false и после SCI; другой target требует своей квалификации | сохранить              |
| Полная денежная/трудовая стоимость известна | Частичные operation/node counters                 | Billing и полное неперекрывающееся время отсутствуют                                             | данных недостаточно    |
