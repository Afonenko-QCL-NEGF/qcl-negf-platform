# Трудности, блокеры и направление следующего этапа

Главная трудность не сводилась к одной ошибке solver. После широкого review одновременно
существовали source bugs, реальные ограничения изолированного native окружения, неполные site
bindings и долгая SCBA. Сессия разделяла их по владельцам и сохраняла исходные failed receipts. Это
увеличило число небольших source/metadata операций и время координации, но позволило не переписать
scientific provenance и не повторять expensive solve без причины.
[Операционный реестр](evidence/README.md) · [task register](evidence/task-register.md).

| Проблема, проявившаяся в сессии     | Что установлено                                                                                                                                                                             | Что остаётся                                                                                                                                                                      |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Научный запуск и recovery           | SCI1/2 остановились до результата, SCI3 исчерпал recovery budget, SCI4 имел scientific failure при Slurm exit0, SCI5 остановился на копировании, SCI6 действительно продолжает frozen state | Terminal SCI6 и независимая классификация сходимости/физики; если новый failure — cause-specific review перед следующим слотом                                                    |
| Долгая работа и память              | SCI6 прогрессирует, OOM0; file cache≈10.6 GiB, anon≈18.8–19.9 GiB, HWM24.18 GiB; source history consolidation повторно обходит всё накопленное                                              | Нет phase-complete GC/live-heap/native telemetry и доказанного будущего peak/ETA; проектное улучшение incremental/streaming history должно сохранять provenance и scientific bits |
| Граница native GUI                  | Новый APP собран, native8 прочитал recovery; четыре ранних smoke были неудачны из-за неверно стеснённого AiiDA profile log/PID/SQLite WAL harness                                           | Final Git-ref CI, exact closure identity, safe release update, production auth/browser acceptance                                                                                 |
| Документация                        | Public source/associations/tools готовы; native DOC04 0/1                                                                                                                                   | Выбранный 3+1 GiB admission невозможен в неизменной 4 GiB controller VM; нужен resource rebalance/qualified target, затем один render и browser review                            |
| Worker delivery                     | Toolkit/guide/локальные capabilities описаны                                                                                                                                                | Нет готового подписанного image, проверенных root/Nix/network/trust bindings, install/enrollment/Slurm smoke для первого и второго worker; Windows backends также pending         |
| Публикация и системная безопасность | Owning PR/gitlinks и immutable receipts дают source identity; protected foreign VM/jobs/disks сохранены                                                                                     | Не считать merged PR всем релизом; backup/restore, full CI 0/1, empty fleet и release dossier ещё обязательны                                                                     |

Несколько уроков имеют прямое инженерное следствие. Слишком подробные предварительные
resource/harness правила сами создавали ложные отказы: APP metadata probe не мог писать обычный
profile log и SQLite WAL, хотя product read path был правильным. Исправление стало узкой,
документированной настройкой trusted execution, без изменения Portal/физики. С другой стороны,
уменьшать DOC04 RAM только ради запуска единственного candidate было бы не подтверждённой измерением
гипотезой. Унификация подобных решений — не новый orchestration framework, а короткая проверяемая
последовательность `source → fresh admission → one action → raw receipt → independent review`.

До поправки пользователя 24 октября подготовка раннего B0 включала собственные HDF5 VFD, controller
NBD и подробный учёт каждого эффекта. **Обычный HDF5 на Linux уже работал**: эти дополнительные
Linux/kernel зависимости возникли из выбранного контракта атомарного I/O и доказательства resource
bounds, а не из необходимости «заставить HDF5 работать на Linux». Их снятие с критического пути
сохранило штатные ресурсные ограничения, durability и provenance; нельзя ретроспективно приписать
всему этому механизму точное число «потерянных суток». После упрощения реальные отказы SCI1/SCI2
writer, SCI3 recovery guard, SCI4 scientific terminal и SCI5 copy path показали, что задержку
результата нельзя объяснить одной только подготовкой. В SCI4 данные поддерживают
memory-pressure/embedding гипотезу первичного отказа, но исходный низкоуровневый exception не
восстановлен; stale phase error — сохранённый terminal симптом, не установленная первопричина.
[Научная хронология](science-and-recovery.md) · [стоимость](resource-control-and-cost.md).

Пользователь также отмечал недоступность модели в отдельные периоды, перезапуски рабочих сессий и
очистку временных каталогов. Это создавало работу по восстановлению контекста: сверить сохранённый
checkpoint, идентичности source/attempt, archived operation receipts и неопределённые исходы перед
продолжением, не считать их новым запуском. Для этих перерывов нет полного журнала причин и
продолжительности; приписывать им конкретные часы, сбой продукта или долю всех затрат нельзя. Именно
поэтому частичные промежуточные файлы не были единственным носителем provenance, а исходные
failed/unknown outcomes сохранялись.

**Дальнейшая зависимая последовательность в действующих полномочиях:**

1. Пока SCI6 активна — только bounded read-only наблюдения без signal/GC/cache flush/resize. При
   terminal один раз сверить AiiDA/Slurm/Results provenance и charged node·h/I/O по доступным
   counters; разделить execution, strict convergence, physical checks, discretization и external
   validation. Если failed, сохранять original raw и перед следующим из четырёх слотов доказать
   конкретный новый путь recovery; никакого blind rerun.
2. После освобождения compute window — выбрать безопасное перераспределение ресурсов только
   QCL-owned VM с host reserve≥4 GiB и fresh disk/boot/queue readbacks. DOC04 должен пройти свой
   **существующий** 4 GiB available guard либо получить отдельно квалифицированный target, затем
   одну native Documenter сборку и independent browser journeys. Новый docs bundle не подменяет GUI
   release.
3. Довести worker image/closure и private network/trust authority до actual installation: первый
   локальный Linux worker, затем Proxmox worker, для каждого DRAIN→enroll→ordinary
   Slurm/NFS/scratch/fault receipt. Невыполненные Windows/Hyper-V backends и restore rehearsal
   сохранять в full-scope матрице, а не вычёркивать из неё.
4. На одном final ready Git ref сверить инженерную и Git-ref derivation/contents, выполнить один
   разрешённый full CI и required native backup/restore. Затем, при пустой AiiDA/Slurm очереди и
   полном enrolled pool, выполнить owning release update с rollback evidence; проверить API/TLS,
   светлую тему, SCI6 recovery UI, saved data и docs в настоящем браузере. Public release требует
   собственного решения, отдельного от G1.
5. После терминального научного анализа рассмотреть source change для incremental history
   consolidation и более полного resident peak estimator с независимыми oracle/фазовой телеметрией.
   Цель — уменьшить повторное чтение и неопределённость RAM, **не** менять SCBA, scattering, grid,
   basis или frozen acceptance. Результат такого будущего изменения требует собственного PR и
   проверок; нынешний отчёт его не реализует.

Ни один из этих шагов нельзя объявить завершённым по текущему тексту или старому status. Его
выполнение устанавливает только новый exact receipt на новом времени; CP70 остаётся историческим
срезом.

| Утверждение                                                              | Свидетельство                                                        | Ограничение                                               | Решение                |
| ------------------------------------------------------------------------ | -------------------------------------------------------------------- | --------------------------------------------------------- | ---------------------- |
| Основной следующий ход — сохранить SCI6 и дождаться её terminal evidence | CP70 `RUNNING`, fixed-point false, no OOM/restart                    | Будущая причина terminal пока неизвестна                  | сохранить              |
| DOC04/GUI/worker можно считать готовыми по source                        | Source/build/native subset                                           | Render, deployment, image/enrollment и CI отсутствуют     | данных недостаточно    |
| Улучшать производительность можно без смены физики                       | Исторический source checkpoint O(total history), estimator scope gap | Нужны phase measurements и независимые correctness checks | дополнительно измерить |
