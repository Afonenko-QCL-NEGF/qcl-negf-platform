# Публикуемая проекция независимого аудита

[Общий отчёт](../README.md) · [Метод](README.md)

Исходный авторский audit SHA256 `e45acbcf2eb1cc5f7ec4570f789e361c10b601f11ce483e883279fdd2cd93472`,
9550B. Ниже текстовая проекция: приватные абсолютные пути и физическая boot identity скрыты;
исходные raw bytes этим текстом не подменяются. Данные остаются историческим срезом CP70, не новой
live проверкой. Аудиты не запускали solver/build/profiler.

---

# Независимый HIGH: память SCI6/job7

Данных достаточно, чтобы разделить anonymous RSS, file cache и cgroup charge; недостаточно для
доказательства утечки, её отсутствия на многодневном горизонте или точного эффекта добавления RAM.
Новых solver/remote/GC/cache-flush/signals/build/CP действий, чтения HDF5 массивов или
credentials/config не было. Source attribution Julia/Core/Runner — отдельный аудит.

Источники под `[private-path]`, далее N:

| Artifact                                          | SHA-256                                                            |
| ------------------------------------------------- | ------------------------------------------------------------------ |
| N/QCL-SCI6-R5-MEMORY-BREAKDOWN-READ2/receipt.json | `71b94d7d8636b460bdd955a28a251b3a46051ec045d2b226c92b69c388bdfa07` |
| N/QCL-SCI6-R5-HEALTH-PROGRESS-READ8/receipt.json  | `5b5d12b920f14b9d865908f62d3e24d8df8f27e0498105b893f320c2c2aead62` |
| N/QCL-SCI6-R5-HEALTH-PROGRESS-READ24/receipt.json | `cf2efc31c37432025fa27727fbb984ca3f532a4f873f96f78acad59e639dc82a` |
| N/QCL-SCI6-R5-HEALTH-PROGRESS-READ26/receipt.json | `f366b25ca641f48309fad57d982f4489dcc95f6ccf59a17edd694ba9a3617d03` |
| [private-path]                                    | `eee094a51f89083c9a8e62dc1ded67164efd146b6db5ecbf75bd5814e3a35aeb` |

Все18 строк compact extraction независимо сверены с raw READ8…24/26: outer/inner/RSS/HWM/cgroup/cap
совпали. Identity согласована: job7, Julia PID2692, guest boot [private-machine-identity], один
executable и configuration_hash1a541530…4085a2. В свежем breakdown start_ticks1067610; исторические
snapshots не являются continuous heap trace. READ1, остановившийся на root-squash metadata read, не
превращён в нулевое измерение.

## Что измерено

READ2 samples[0/1], 27.10.2026 06:35:50→06:35:55 UTC, интервал5.15026s:

| Scope/поле               | Первый срез, GiB | Второй, GiB |
| ------------------------ | ---------------: | ----------: |
| cgroup memory.current    |           30.647 |      29.490 |
| memory.stat anon         |           19.908 |      18.754 |
| memory.stat file         |        10.612312 |   10.612320 |
| memory.stat kernel       |            0.124 |       0.122 |
| process smaps_rollup Rss |           20.139 |      19.045 |
| process Pss_Anon         |           19.957 |      18.863 |
| process Pss_File         |            0.179 |       0.179 |
| VmHWM                    |        24.179829 |   24.179829 |

File charge ≈99.80% inactive_file; file_dirty/file_writeback/shmem/swap=0. Это крупный чистый
преимущественно неотображённый в RSS page cache, а не ещё10.6GiB Julia heap. Конкретные файлы
происхождения cache не идентифицированы; нельзя объявлять его целиком HDF5/checkpoint cache. Kernel
≈0.12GiB не объясняет основной объём. Clean inactive cache — кандидат на reclaim, но не
гарантированно бесплатная память без I/O последствий.

Cgroup уменьшился на1241636864B; anon — на1238953984B, file вырос лишь8192B. Следовательно, в этом
окне anonymous resident memory существенно освобождалась/убывала, а не только менялся file cache.
Это **не доказательство вызова Julia GC**: нет GC/live-heap/allocation telemetry. Proc status и
smaps читаются последовательно; capture0.149/0.231s, поля не атомарны, поэтому не следует добиваться
точного равенства сумм/RSS/cgroup вычитанием.

## История, давление и пределы прогноза

READ8→26: process RSS14.127→20.374GiB, HWM16.295→24.180GiB. Значит объяснение «весь рост RAM —
только filesystem cache» опровергнуто: сам процесс раньше увеличивал resident/high-water footprint.
Но RSS колеблется и убывает; READ24→26 за9.204h RSS20.351→20.374GiB при неизменном HWM24.179829GiB.
Линейная неограниченная утечка этими данными не доказана; её отсутствие, включая будущие outer
phases, тоже не доказано. HWM по определению не убывает и сам по себе не является индикатором leak.

Hard job cap33GiB, peak упирался в33GiB, swap запрещён. memory.events:max325→57408→57574,
OOM/oom_kill0. Свежие memory.stat содержат накопленные pgscan/pgsteal93072949 и
workingset_refault_file85621768: reclaim/refault уже происходили. За свежие5s эти три counters и max
не выросли; memory PSI avg10/60/300=0, cumulative total6.108192s не изменился. Поэтому прежние
касания cap не доказывают сильную текущую memory-stall фазу; отсутствие OOM не означает отсутствия
давления или стоимости cache churn. IO PSI имеет отдельные накопленные stalls; bottleneck/его доля
этим коротким окном не установлены.

FD17→17, deleted descriptors0/HDF descriptors0 в обоих срезах: нет наблюдаемого разрастания
открытых/deleted файлов в эти моменты. Это не исключает heap/native/HDF5-library cache retention или
короткоживущие открытия между срезами.

## Estimator и решение о RAM

READ26.progress.small_metadata[`result/executions/execution-1/scientific_memory_reservation.json`],
embedded SHA `5189c3481b0ed8fbc2eae4515c8445daeff07521c60618475578625b76747090` независимо проверен.
Numeric estimate13806384496B=12.858GiB; measured process HWM25962893312B=24.180GiB, ratio1.8805. Это
опровергает интерпретацию numeric estimate как **полного runtime RSS bound**, но не доказывает
ошибку оценки её собственных численных массивов или leak. Coverage estimator/JIT/allocator/native
workspaces/checkpoint phases требует отдельного source audit. Cgroup peak33GiB тем более нельзя
сравнивать с numeric estimate как с одинаковым scope: он включает file cache и kernel. Записанный
memory_budget24184012800B также не является фактическим kernel limit; kernel limit33GiB.

Дополнительная RAM может дать запас для будущих live allocations и cache, но необходимость/ускорение
и величина прибавки не измерены. Простое увеличение VM RAM не меняет автоматически job
memory.max33GiB. Решение должно различать VM/Slurm-cgroup/Julia scopes и сохранять научную
постановку; новый многодневный peak нельзя достоверно прогнозировать линейной экстраполяцией этих
sparse, phase-dependent и ограниченных cap наблюдений. Никакого изменения RAM этот audit не
выполняет.

Для более сильного заключения нужны одинаково размеченные фазы нескольких outer cycles и
live-heap/GC/native coverage, сопоставленные с anon/file/PSI/reclaim. Это предложение будущей
телеметрии, не измеренный факт и не разрешение запускать profiler/принудительный GC. Текущий point
outer9/inner269 остаётся running/fixed_point_passed=false; память не доказывает scientific
acceptance или ETA.

| Утверждение                                 | Вердикт / свидетельство                         | Ограничение                              | Решение                |
| ------------------------------------------- | ----------------------------------------------- | ---------------------------------------- | ---------------------- |
| Сейчас есть крупный file cache              | Подтверждено memory.stat:file≈10.612GiB         | Происхождение файлов не установлено      | сохранить              |
| Весь рост — cache / «процесс не рос»        | Опровергнуто историческим RSS/HWM               | Новейший HWM стабилен≈9.2h               | изменить               |
| Утечка доказана / утечки точно нет          | Оба неизвестны; RSS/anon колеблются             | Нет live heap, GC и phase-complete trace | дополнительно измерить |
| Давления на limit не было, раз OOM0         | Опровергнуто max/reclaim/refault                | Свежая5s memory PSI спокойна             | изменить               |
| 12.858GiB гарантирует полный peak RSS       | Опровергнуто scope и HWM24.180GiB               | Numeric-estimator correctness отдельна   | изменить               |
| Можно обещать RAM peak через несколько дней | Данных недостаточно; cap цензурирует cache/peak | Будущие фазы не наблюдались              | данных недостаточно    |
