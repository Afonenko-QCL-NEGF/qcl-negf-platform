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

Настоящие systemd properties читаются `systemctl show`; JSON используется только
для native findmnt/lvs/swapon. Точные final mount/device/rdev/UUID, ordinary mount
policy, pool LV/VG identities и reserves проверяются до allocation и повторно
перед/после activation. Data и metadata physical backing проверяются отдельно от
filesystem available bytes и st_blocks. FIEMAP не является thin reservation.
Ledger `incremental_swap_bytes` задаёт оставшуюся admitted стоимость, без двойного
учёта ранее принятого full-image envelope. Growth/reserves остаются защищёнными.
Postchecks консервативно требуют тот же запас; admission должен это учитывать.

Parent, file, receipts и `.swap` unit имеют lifetime
`protected-host-infrastructure`. Их запрещено включать в QCL wipe/VM teardown,
включая failed/inactive состояние. Пути canonical, без symlink components; parent
и receipts должны быть отсутствующими либо совпадать с original durable binding.
Существующий неизвестный объект не становится owned по имени или UID. Необходим
private `binding_sha256` канонического original binding на resume. Управление
содержимым protected directory имеет одного владельца для exact file/unit.

Создание использует mkdir0700 и O_CREAT|O_EXCL|O_NOFOLLOW0600. Fsync containing
parent нового directory выполняется до fsync нового directory. File и его parent
fsync предшествуют durable binding. Binding/phase records — immutable builtin
copy `force=false`, затем file+parent fsync и exact JSON readback. Crash между
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
до native mkswap --uuid; exact observed TYPE/UUID/layout проверяются после него.

Own inactive header не перезаполняется и не форматируется повторно. Existing
active exact own file только наблюдается и получает optional boot enable при
точной loaded policy. Changed inode/nlink/header/unit/mount — отказ; никаких
chmod/repair/reload/start активного unit. Unknown unit отказывается до allocation.
Loaded declaration использует What=file, RequiresMountsFor и mount condition,
конечный TimeoutSec, обычные default dependencies и WantedBy=swap.target.
Explicit Priority/Options отсутствуют; kernel priority наблюдается, не задаётся.

Перед start записывается durable sticky activation_intent. После unknown/timeout
outcome actual kernel table и unit читаются до отказа. Late activation и failed
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
