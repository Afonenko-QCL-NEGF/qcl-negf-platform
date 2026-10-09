# Защищённый additive host swap

`ansible/proxmox-host-swap.yml` принадлежит Platform и включается только отдельным
private `qcl_host_storage.swap.enabled=true`. Default disabled не делает probes;
`preflight_only=true, apply=false` делает ограниченные read-only проверки. Apply
требует accepted native final ext4 cutover, точной host/boot identity, свежего
admission и отдельного физического reservation ledger. Этот playbook не исполняет
cutover и не управляет VM, Slurm, MemorySwapMax, swappiness или научной моделью.

Private target задаётся положительным integer `target_mib` и независимым
`authorized_cap_mib`; public hardware defaults отсутствуют. Header UUID задаётся
явно, никогда не генерируется при retry. `known_header_uuids` содержит известные
root/final/старые swap UUID; новый UUID не может совпадать с ними. Measured support
включает PAGE_SIZE, bounds обычного regular swap header без bad pages, ext4/FIEMAP,
DD direct и native versions/features. Source execution не устанавливает tools.

Mount policy читается `systemctl show`; swap policy использует native typed
`busctl --json=short` свойства Unit/Swap. Native JSON findmnt/lvs/swapon/wipefs
проверяется strict decoder без duplicate keys. Точные final mount/device/rdev/UUID, ordinary mount
policy, pool LV/VG identities и reserves проверяются до allocation и повторно
перед/после activation. Data и metadata physical backing проверяются отдельно от
filesystem available bytes и st_blocks. FIEMAP не является thin reservation.
Ledger `incremental_swap_bytes` задаёт оставшуюся admitted стоимость, без двойного
учёта ранее принятого full-image envelope. Growth/reserves остаются защищёнными.
После durable current full allocation payload backing учитывается один раз;
postchecks сохраняют остальные growth/reserve/overhead predicates.

Parent, file, receipts и `.swap` unit имеют lifetime
`protected-host-infrastructure`. Их запрещено включать в QCL wipe/VM teardown,
включая failed/inactive состояние. Пути canonical, без symlink components; parent
и receipts должны быть отсутствующими либо совпадать с original durable binding.
Существующий неизвестный объект не становится owned по имени или UID. Необходим
private `binding_sha256` канонического original binding на resume. Управление
содержимым protected directory имеет одного владельца для exact file/unit.

Создание использует mkdir0700 и O_CREAT|O_EXCL|O_NOFOLLOW0600. Fsync containing
parent нового directory выполняется до fsync нового directory. File и его parent
fsync предшествуют durable binding. Binding/phase records — immutable v2 envelopes: bounded standard-library
exclusive temporary inode, atomic no-replace publication, file+parent fsync
и exact canonical JSON readback. Crash между
creation и binding оставляет неизвестный orphan, который не перезаписывается.
Receipts directory заранее выделяется private attempt и сохраняется целиком.

Один bounded DD пишет весь target из /dev/zero: bs=1M, count=target_mib,
conv=nocreat,notrunc,fsync, oflag=direct,nofollow. Buffered/sparse fallback отсутствует.
Receipt-bound inactive partial без signature получает один новый admitted fill;
complete allocation с durable receipt может format без refill. FIEMAP helper
читает только exact file: bounded extent buffer и header-sized sample; stable
stat/named inode, dense contiguous clipped coverage, ordinary supported flags и
st_blocks проверяются независимо. SEEK_HOLE вспомогательный. Native blkid owns
signature; неоднозначный status не считается blank. Format-intent записывается
до native mkswap --uuid/--pagesize; exact observed TYPE/UUID/layout проверяются после него.

Own inactive header не перезаполняется и не форматируется повторно. Existing
active exact own file только наблюдается и получает optional boot enable при
точной loaded policy. Changed inode/nlink/header/unit/mount — отказ; никаких
chmod/repair/reload/start активного unit. Unknown unit отказывается до allocation.
Loaded declaration использует What=file, RequiresMountsFor и mount condition,
конечный TimeoutSec, обычные default dependencies и WantedBy=swap.target.
Explicit Priority/Options отсутствуют; kernel priority наблюдается, не задаётся.

Перед start записывается durable sticky activation_intent. После unknown/timeout
outcome только trusted updated BudgetState допускает одну bounded read-only последовательность:
actual kernel table и три scalar unit properties; затем обязательный отказ. Unknown,
expired или exhausted usage не допускает native child; rejected wrapper не является
выполненным native read. Observed active не отменяет исходную start failure. Late activation и failed
completion не разрешают refill, format, delete, stop/restart или swapoff. Sticky
intent при текущем inactive состоянии также требует отдельного reconciliation,
не нового automatic start. Оригинальные failed receipts сохраняются.

Успех требует kernel usable size = file bytes минус одна измеренная PAGE_SIZE,
active exact unit, unchanged old static NAME/TYPE/SIZE/PRIO, observed boot enable,
mount/file/layout/pool guards и durable completion. USED старых областей динамичен
и не входит в equality. Swap не physical RAM. Boot declaration не доказывает
проверенный reboot, pressure/performance или scientific acceptance.

Каждая native command/primitive имеет own process group, finite phase time,
aggregate native-clock deadline и bounded combined stdout/stderr. Private record
байты и extent/sample/output caps независимы от target allocation bytes. Нет
automatic rerun/cleanup. Native apply, reboot, pressure и SCI — отдельные gates.
Synthetic tests используют actual cached Ansible engine и fake native boundary;
helper проверяется исключительно на owned small files с injected ioctl/hole.


## Immutable v2 context and bounded IO

The v2 binding retains the complete original static active swap set, canonical identities,
accepted final filesystem block identity, target/page/header UUID and exact rendered unit
hash. USED and row order are dynamic observations. Every present phase is validated before
any mutation; legacy or incomplete predecessor chains refuse read-only without migration.
File, parent and nearest existing ancestor must have the final mounted filesystem device
pair. The longest mount for the actual target must be the exact final mount; foreign
submounts and same-filesystem bind mounts refuse before exclusive creation or fill.

`maximum_write_bytes` covers payload, measured header page and own metadata. A fresh
attempt requires at least target + header + `maximum_metadata_write_bytes`; each action
reserves its full finite cost before execution, and failures do not refund reservations.
Atomic metadata publication reserves twice the serialized payload plus a finite namespace
allowance, uses an exclusive no-follow temporary inode, no-replace link publication,
containing-directory fsync and exact readback. Failed own temporary links remain evidence.
New directories fsync both their containing parent and themselves. This is a logical
requested-write contract, not measurement of journal, SSD, thin-pool or snapshot/COW IO;
those require the separate admitted physical overhead and metadata reserves.

A single host-monotonic BudgetState spans native observations, controller latency and
writes, with phase and aggregate deadlines, epoch admission/ledger expiry, cumulative
serialized response bytes (including base64), payload and metadata precharges. Read-only
expiry or exhausted counters refuse before Popen or IO mutation. A small synchronous
session anchor retains its original PID/start-time/PGID/SID until the native leader and
all synchronous members complete. Numeric `/proc` metadata is queried only to identify
members of this retained own group: at most 8192 entries, 2048 bytes per stat and 100 ms
per membership observation. Foreign metadata is discarded and no foreign FD/cwd/jobs
are inspected. TERM/KILL target only the continuously verified original group within a
one-second cleanup reserve. Ownership/observation uncertainty refuses further writes;
this does not prove that a real kernel DD or filesystem syscall is interruptible.

Current free space already includes a fully allocated file. After current dense/stable
FIEMAP and durable matching allocation proof, this file's remaining payload backing is
zero; later capacity observations retain all other growth, reserve and overhead terms.
This applies to validated v2 full-file resumes as well as fresh successful allocation.

Native `blkid --probe --output export`, `wipefs --no-act --json` and stable first-page
observations precede successful preflight, DD, mkswap and activation. Only exact blank
or matching TYPE=swap/UUID/VERSION=1 evidence is supported; ambiguous signatures or an
existing format intent with blank header refuse. The measured page must match support
and the full stable header sample. systemd 257 may internally invoke `swapon --fixpgsz`;
this role does not authorize a header repair, and mismatched PAGE/header evidence refuses
before start. Direct own file probes remain read-only and never allocate.

Unit admission checks the real root:root 0644, single-link regular fragment and exact
rendered bytes, and native typed D-Bus properties (including RequiresMountsFor, the single
ConditionPathIsMountPoint tuple, ConditionResult, Options and TimeoutUSec) before start,
resume, enable and poststate. A healthy open thin pool `twi-aotz--` is accepted alongside
`twi-a-tz--`; all ten semantic attribute positions, health and finite geometry remain
strict. No stop, swapoff, restart, swappiness, VM, Slurm or scientific model changes are
part of this operation.


## F1–F6: exact producer, entry decisions and authoritative ledger

Declared fragment bytes contain exactly one final U+000A from the actual template lookup.
Faulty old fragments/contexts refuse; this operation never rewrites or migrates them.
The four creation decisions are plain booleans frozen after entry validation, before
writes. Durable allocation and activation intent do not turn off later guards within
that entry. A fresh successful allocation retains its exact dense/stable proof before
remaining backing becomes zero; an existing full allocation needs the same current proof.
Sticky inactive intent never permits an automatic start retry.

Initial B_entry is the independently known `ledger.incremental_swap_bytes`, a non-boolean
integer from0 through2^63−1. It may be explicitly admitted above or below file target size;
unknown is never zero. Target bytes still determine the full DD/header/file geometry.
Physical free-space checks include B_entry plus all protected growth/reserve/overhead;
after proven full durable allocation, current free measurements already include backing
and only B_entry becomes zero. No repeated target subtraction or inference from FIEMAP.

Attempt and boot BudgetState identities are nonempty strings of at most128 UTF-8 bytes.
A canonical worst-case minimal response uses maximum-width counters and maximally escaped
identities to prove the4096-byte reserve. Serialization converges in at most8 steps or
refuses. Before capture no-child certainty may be true; on entering capture it becomes
false and only observed completion may replace it. Finish/fallback errors preserve false
certainty and the primary failure. If a minimal truthful result cannot fit, outer125 has
no serialized result and is unknown downstream; no cap bypass or fabricated completion.

Failed start handling is local to the one start command. Its complete raw response is
retained. Only structurally valid canonical updated usage with exact original identity,
limits, clocks and cumulative counters can fund at most swapon table then minimal
systemctl show of LoadState/ActiveState/UnitFileState. Every read uses the same current
native guard; failure of the first excludes the second. No enable, completion, retry or
other mutation follows either known or unknown failed outcome. The observations remain
ephemeral facts; no eighth durable record is created. Unit typed policy and native support
are still admission gates, independent of outcome diagnostics.

`completion.payload.budget_usage` is the snapshot before its own publication. The final
transported write-completion usage includes its precharges, bounded output and elapsed
own capture/readback; immutable completion is not rewritten to contain itself. Final
controller latency, physical journal I/O and concurrent tree RSS remain unmeasured.
Local synthetic source tests do not grant native/boot/pressure/SCI acceptance.
