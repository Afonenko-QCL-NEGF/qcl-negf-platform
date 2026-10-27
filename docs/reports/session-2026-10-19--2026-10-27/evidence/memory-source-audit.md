# Публикуемая проекция независимого аудита

[Общий отчёт](../README.md) · [Метод](README.md)

Исходный авторский audit SHA256 `fc0bb248e00d69c142130c3e96c77cef0d9ab195e18f1313b5ac3295bc317063`,
22526B. Ниже текстовая проекция: приватные абсолютные пути и физическая boot identity скрыты;
исходные raw bytes этим текстом не подменяются. Данные остаются историческим срезом CP70, не новой
live проверкой. Аудиты не запускали solver/build/profiler.

---

# SCI6 / job 7: независимый статический аудит памяти

**Вывод:** в просмотренном production-пути нет обнаруженного владельца, который на каждой
SCBA-итерации добавлял бы полные Green/self-energy массивы в бесконечную коллекцию. Основной рабочий
набор ограничен размерами задачи, текущим/предыдущим состоянием, кандидатами и рабочими буферами. Но
память и I/O не обязаны быть постоянными: скалярные истории и индекс сегментов растут, а каждый
checkpoint заново материализует всю накопленную историю с выбранными матричными свидетельствами. Это
проверяемый источник растущих временных пиков, который численный оценщик памяти не покрывает.
Фактическую причину наблюдаемого роста RSS/cgroup этот статический аудит без runtime counters не
устанавливает.

## Паспорт и границы

- Фаза: read-only анализ исходников. Не запускались Julia, solver, tests, build, imports научных
  библиотек, profiler, network/SSH или чтение массивов результатов. Использованы
  `git show/grep/ls-tree` точных объектов и небольшая арифметика Python. Никакие
  исходники/результаты не изменены; этот отчёт записан в `/tmp`.
- Обозначение **C** далее: Core `5b1cdd458eb07ff8c7c792642eda58d9061e1017`; **R**: Runner
  `4609c2e0837df92a831a265f006bc3262b1ae875`. Runtime superproject от координатора:
  `cb1bae7ffdbb977f33d81e05b8ebd50afb4177ee`.
- Все локаторы ниже — строки `git show <C|R>:<path>`, а не текущие рабочие файлы. В `ls-tree -r`
  этих двух refs нет `AGENTS.md`, в том числе вложенных.
- Текущий исходный checkout отдельно: HEAD `e48e5b2ef16d3e6f1d633dd29c95f94d60ca8cc1`; изменены
  AGENTS.md, README.md, TODO.md, docs/architecture.md, docs/single-server-deployment.md; есть
  untracked docs/implementation и docs/system. Его Core/Runner gitlinks `3108150…` / `0c53c6d…`
  **не** использованы как источник runtime-реализации. Полный текущий submodule status был прочитан
  и не менялся этим аудитом.
- Научный контракт от координатора: 0 mV/period, 70 K; LO/acoustic/impurity/IFR/alloy, без
  electron–electron; один Julia процесс, 12 threads, BLAS=1, cap 33 GiB, предел 72 h; без
  cancel/restart и изменения физики/сетки/допусков.
- Frozen configuration, переданная координатором: `N_E=30721`, `N_k=11`, `basis_states=5`,
  `basis_periods=3`, linear mixing, максимум 2048 SCBA ×128 outer; checkpoint_every_scba=32. **ФАКТ
  по R** `src/infrastructure/config/configuration.jl:533-534`: basis_states задаёт `N_b`, P_basis
  задаётся отдельно. Поэтому здесь `N_b=5`, не 15. Неиспользуемый Anderson depth=6 не даёт
  Anderson-массивов при linear.

## Время жизни численных данных

**ФАКТ — постоянный cache.** C `src/numerics/optimized/production_cache.jl:688-745`:
`build_production_cache` держит production kernels, четыре shift plan, FFT plan, исходные grids и
kernel arrays. `_validated_production_cache` в `:816-850` возвращает новый небольшой aggregate с
теми же массивами/планом; новых FFT-буферов на каждой итерации здесь нет. C
`fft_parallel.jl:28-48,75-109,112-143`: отдельный `L × columns` buffer и FFTW plans на worker, при
verify_roundoff ещё набор с 2L. Это конечный cache на grid/options; размер native FFTW plans функция
`production_fft_workspace_bytes` в `:305-314` не считает, она суммирует только kernel_fft и Julia
buffers.

**ФАКТ — большой оборот выделений внутри SCBA.** C `production_state.jl:14-19,54-73` формирует total
self-energy, новые Gᴿ/Gˡ/Gᵍ и spectral state. C `production_solver.jl:432-605`: текущая Green
заменяется, затем создаются кандидаты всех механизмов, embedding и total. C
`production_operators.jl:1181-1230` создаёт новый `Dict{Symbol,SelfEnergyFamily}` на вызов с
конечным числом ключей; `:1370-1389` выделяет total family. Linear mixing в `:1392-1434` пишет в
существующие Σ массивы. Это большой cumulative allocation traffic даже при постоянном live set.
Allocation counter нельзя читать как retained bytes.

**ФАКТ — истории имеют разные payload.** C `production_solver.jl:55-56,625-656`: SCBA history
добавляет одну строку на итерацию; при новом outer без resume создаётся новая history. C
`production_iteration.jl:144-199` свидетельство содержит только выбранные `N_b×N_b` блоки и
eigenvector. `:202-260` сохраняет matrix payload только first/worst/last; старый row заменяется
скалярным witness с пустыми matrices/vector. Полные `N_E×N_k×N_b²` массивы в history не помещаются.

**ФАКТ — outer history растёт по числу outer, не внутренних итераций.** C
`production_solver.jl:965-975,1112-1127`: каждая строка хранит scalar metrics плюс copies
populations (`N_b`) и density (`N_z`), а также отдельные небольшие warning/policy dictionaries.
`:1070-1073` освобождает owner previous_scba перед передачей; `:340-342` очищает initial внутри
SCBA. Старое aggregate `scba` или последний checkpoint-local `aligned` могут продлить жизнь одной
предыдущей Green/history до следующего присваивания; статически это конечное число состояний, а не
список всех итераций. Точный liveness/JIT после возврата callback статическим чтением не измерен.

**ФАКТ — Anderson ограничен и здесь не выбран.** C `production_mixing.jl:188-233`: eviction до
materialization, recycle free_states/free_residuals, clear переносит пары в pool. C
`production_solver.jl:830-869` растит history только при `mixing===:anderson`. При другом запуске
заполнение глубины может дать ступени памяти, но для данного linear это объяснение неприменимо.

## Сохранение: реальные растущие владельцы и временные копии

**ФАКТ — recorder не полностью scalar-only.** R `scientific_history.jl:1-18,92-127` держит полные
SCBAIteration rows, включая их маленькие witness matrix payloads, до flush: ≥1000 rows либо ≥30 s,
проверка времени только при приходе очередного row. После успешного flush `:267-268` очищает
scba/outer vectors. Это конечный буфер до 1000 witness payloads; при итерациях дольше 30 s обычно
flush после каждой строки. Recorder также держит последний `problem` (`:114-115`), а
`segments::Vector{Dict}` не очищается: `:234-255` добавляет по descriptor на segment. Это доказанный
малый retained growth O(segments), не полные Green-состояния.

**ФАКТ — checkpoint работает синхронно и не складывает solution в массив.** R
`scientific_execution.jl:1089-1149,1169-1205`: `durable_state` пишет, latest_commit хранит String
path, callback возвращает nothing. C `production_solver.jl:747-761` передаёт borrowed arrays с
copy(history), C `:996-1037` создаёт aggregate для callback без deep-copy больших Green/Σ.
Синхронность и ownership явно описаны C `:10-15`.

**ФАКТ — основная HDF5 сериализация bounded.** R `hdf5.jl:65-143`: `_write_slab_array` использует
один backing buffer ≤1 MiB на dataset, lazy permutation/project и синхронную запись;
`_write_complex` обрабатывает real/imag последовательно и закрывает dataset. Это не создание двух
полных real/imag копий каждого большого поля. Запись включает полные kernels и state (R
`point_artifacts.jl:855-866`; R `hdf5.jl:467-515`). Native HDF5 compression/chunk caches/handles и
освобождение их памяти после file close в этом аудите не измерены; нельзя объявить их утечкой по
одному наличию writer.

**ФАКТ — вся история объединяется заново на каждом checkpoint.** R
`scientific_execution.jl:1095-1105`: flush и сбор всех source history paths; R
`point_artifacts.jl:911-914`: `consolidate_scientific_history`. R `scientific_history.jl:329-384`
читает scalar datasets всех segments, append в общие vectors, sortperm и `values[order]`, затем
PSD/physical-markers consolidation. R `physics_diagnostics.jl:202-247` также собирает все выбранные
packed witness records. R `packed_witnesses.jl:188-232` читает payload_values и копирует slices в
records; `:149-165` при записи собирает ещё один общий Float64 payload vector. R
`physical_markers.jl:407-424` собирает markers/sequences всей истории и новые column vectors. Это
O(total rows + selected payloads) временная память и чтение/запись за один checkpoint, не O(last
segment). При неизменном числе итераций между checkpoint суммарная работа этого пути может расти
квадратично по числу checkpoint; это вывод об алгоритме, не измеренное доминирование над solver.

**ФАКТ — другие коллекции ограничены либо привязаны к attempts.** R
`native_phase_telemetry.jl:8-12,53-62,106`: active admissions pop при end, stack ограничен nesting;
globals journals/admissions остаются по directory, а не по iteration. R
`telemetry/progress.jl:97-113,861-865`: timing samples максимум 100000 на metric, а scientific
reporter по умолчанию имеет timing_summary=false (constructor `:126`; scientific_execution
`:942-946` не задаёт csv_io). R `telemetry/sender.jl:20-49,79-100`: scalar-only bounded queue,
arrays отвергаются. Глобальные recorder IdDicts R `scientific_history.jl:20-21,83` удерживают
recorder для non-standalone policy; данный путь `campaign_strict` дополнительно отказан до запуска R
`native_phase_telemetry.jl:237-244`. Это потенциальный lifecycle-review объект для других режимов, а
не доказанная причина роста текущего standalone job.

## Масштаб и покрытие оценщика

Пусть `B=16 N_E N_k N_b²`. Здесь B=135172400 bytes=0.125889 GiB. Для M=5:

| Численный компонент                                  |                                Формула / размер | Локатор C production_cache.jl |
| ---------------------------------------------------- | ----------------------------------------------: | ----------------------------- |
| Green+stored scattering+embedding                    | (4+3M+9)B=28B=3.524895 GiB + diagnostic scalars | :512-517                      |
| Candidate generation                                 |                       (3M+15)B=30B=3.776673 GiB | :518-521                      |
| Transform temporaries                                |                                 6B=0.755335 GiB | :556                          |
| Retained warm state budget                           |                                28B=3.524895 GiB | :522-526                      |
| FFT/residual/Dyson/contraction/cavity/kernel storage |  отдельные formulas; зависят от options/workers | :495-555                      |

R scientific-memory estimate выбирает conservative all-dense kernel count и
worker_capacity=Sys.CPU_THREADS (`definitions.jl:465-481`), а не измеряет runtime RSS. Переданный
фактический estimated_peak_bytes=13806384496=12.858198 GiB и budget=24184012800 bytes относятся к
admission numerical estimate. Это не прогноз всего cgroup RSS/cache и не гарантия peak при
checkpoint. В estimator C `production_cache.jl:495-593` нет Julia runtime/JIT/GC-retained garbage,
allocator fragmentation, native library metadata/workspaces сверх явных formulas, total scalar
history, growing recorder manifests, consolidation tables/packed history, filesystem page cache,
kernel memory или других процессов cgroup. Некоторые численные компоненты консервативны; их сумма не
измеряет одновременный RSS.

Один witness payload имеет `H=16[(15+2M)N_b²+N_b]=10080 bytes` из C
`production_iteration.jl:153-198`. Core держит ≤3H; recorder ≤1000H≈9.61 MiB raw payload, плюс Julia
object/Dict/string headers. R `physics_diagnostics.jl:53-60,123-127` пишет ≤4 selected witnesses на
source segment; consolidation сохраняет union всех source payloads (`:233`). При S segments
`W≤min(total_rows,4S)` и raw bytes `P=W×10080` для полноразмерных witnesses этой постановки. При
одной строке на segment W обычно близок числу rows, если witness доступен. На 1000 таких witnesses
P≈9.61 MiB; это само по себе не объясняет гигабайты роста за десятки/сотни итераций. При полном
максимуме 2048×128=262144 rows верхняя raw payload сумма ≈2.46094 GiB; records+repacked values дают
не менее двух payload generations (~4.92188 GiB) в фазе consolidation, сверх scalar tables и
объектных metadata. Этот максимум по итерационному бюджету не прогноз числа итераций за 72 h.

**Переданное координатором manifest evidence, независимо не перечитано:**
`N/QCL-SCI6-R5-MEMORY-HISTORY-METADATA-READ1/receipt.json` сообщает generation=1301, S=1301
segments, 2431 SCBA rows +6 outer rows, index.json=194196 bytes, сумма файлов segments=327235936
bytes. Поэтому текущий upper bound W≤min(2431,5204)=2431, P≤24504480 bytes≈23.37 MiB; две raw
payload generations ≤46.74 MiB. Это upper bounds только raw witness data, не metadata/total
temporary RSS. Размеры файлов включают HDF5 layout/compression/metadata и не заменяют logical
dataset sizes. Row count может включать импортированную историю и не обозначает число новых итераций
текущего attempt. Julia runtime без `--heap-size-hint` по переданному runtime evidence; из одного
отсутствия флага нельзя предсказать фактическую политику GC или diagnose leak.

## Прогноз и самое дешёвое различающее свидетельство

**Модель прогноза, не наблюдение:**
`M_cgroup(t)=A_fixed + A_history(Ninner,Nouter,S) + U_GC/native(t) + T_checkpoint(Ntotal,W) + F_cache(t) + K(t)`.
Численная часть A_fixed при фиксированных dimensions/channels/linear не должна линейно расти со
временем после освоения тех же фаз. История зависит от числа итераций/segments, а не часов.
T_checkpoint растёт с историей и достигается во время checkpoint. F_cache может меняться с
чтением/записью файлов независимо от Julia live objects. `U_GC/native` неизвестен без runtime
evidence. Суммировать RSS и cgroup anon/file как независимые составляющие нельзя — scope/overlap
различаются.

Минимальное будущее измерение без вмешательства в solver: на 2–3 одинаковых SCBA фазах и одном
очередном штатном checkpoint сохранить timestamp/point/outer/inner/phase; cgroup memory.current и
memory.stat anon,file,shmem,file_dirty,file_writeback,kernel; process RssAnon/RssFile/RssShmem или
smaps_rollup RSS/PSS/private dirty; memory.events; existing producer allocated/gc totals и admission
before/after GC. Не форсировать GC, не drop_caches, не менять cadence. Достаточны read-only редкие
snapshots; желательно охватить естественный GC и выход checkpoint. В native telemetry R
`native_phase_telemetry.jl:195-215` full GC вызывается только при `current+burst>limit`; clean-cache
credit=0. Если давление сохранится, source предусматривает pause_before_allocation (`:216-234`;
scientific_execution `:1390-1395`), а не гарантию продолжения до 72 h. Поля
memory_stat_before/after_gc перечислены у writer, но permit в этой ревизии их не заполняет:
отсутствие не равно нулю.

Читать только HDF metadata/shape, без payload arrays: attempt/history/index.json
(`segments[*].path/bytes/scba_rows/outer_rows`); в closed segment или latest committed history.h5 —
`/scba/sequence`, `/outer/sequence`, `/psd_history/selected_blocks/record_sequence`,
`/psd_history/selected_blocks/payload_values` (8×length=raw P),
payload_offsets/record_index/metadata_index,
record_attributes_json/group_metadata_json/dataset_metadata_json; shapes таблиц `/physical_markers`.
Суммировать source segments, не повторные recovery generations той же истории.

Для многодневного прогноза надо оценить скорость новых rows и segments в сопоставимых фазах. Тогда
`P(t)=10080×W(t)` и linear history cost можно экстраполировать по progress; отдельно нужен
измеренный ratio временного checkpoint peak к P/числу rows. Для OOM-прогноза использовать нижнюю
огибающую **anon в одинаковой фазе после наблюдённых GC**, плюс peak штатного checkpoint и
заявленный burst. Стабильный anon при растущем file поддержит cache-гипотезу; растущая нижняя
огибающая anon после GC, непропорциональная истории и тому же phase, потребует поиска
retention/native allocation. Одного возрастающего memory.current или VmHWM недостаточно ни для
утечки, ни для безопасного прогноза на 72 h.

## Решения

| Утверждение                                             | Свидетельство                                                                                | Ограничение                                                 | Решение                |
| ------------------------------------------------------- | -------------------------------------------------------------------------------------------- | ----------------------------------------------------------- | ---------------------- |
| Основные state/candidate arrays имеют конечный размер   | C production_solver.jl:432-605; production_operators.jl:1181,1392                            | GC/native lifetime runtime не измерены                      | сохранить              |
| Linear mixing не заполняет Anderson history             | C production_solver.jl:830-869; frozen configuration                                         | При смене метода вывод меняется                             | сохранить              |
| Source не доказывает утечку полных SCBA массивов        | ограниченные owners/циклы и witness stripping C production_iteration.jl:202-260              | Статический аудит не доказывает отсутствие любой утечки     | данных недостаточно    |
| Checkpoint history temporaries и I/O растут             | R scientific_history.jl:329-384; physics_diagnostics.jl:202-247; packed_witnesses.jl:149-165 | Доминирование/байты metadata и allocator не измерены        | дополнительно измерить |
| Numerical estimate не является total cgroup peak        | C production_cache.jl:495-593; R definitions.jl:465-481                                      | Есть консервативные компоненты, нет полной runtime модели   | дополнительно измерить |
| FS cache против leak нельзя выбрать по source           | требуется anon/file split + сопоставимая phase + GC/history                                  | Live counters намеренно не предоставлялись этому рецензенту | данных недостаточно    |
| Сокращать физику/сетки/допуски для памяти оснований нет | Текущий научный контракт не менялся                                                          | Научное принятие решения этим аудитом не проверялось        | сохранить              |
