# Ordinary native attempts

`ops/native_attempt.py` is an opt-in operational owner for one existing CalcJob
UUID. It does not construct an AiiDA process, accept science, cancel jobs or retry
a scientific failure. The ordinary scheduler lifecycle remains the only attempt
owner. The published AiiDA native actor supplies immutable INPUT/CALL/CREATE
joins through its public `launch` and `execution` reads.

`NativeSources.preflight` binds the actual request UUID/action to two fixed
`APP/bin/qcl-negf-native-actor --profile PROFILE` queries as qcl-negf. It uses the
existing profile and authentic G-selected APP, compares exact public Launch and
original execution bytes, full input references, Code/release/source-graph and
storage identity, then reviews original uploaded metadata/script before the first
durable claim. Access/build/retention strings remain locators. A request dict or
Python constructor never qualifies a native backend. SOURCE/L tests do not prove
installed APP, caller qualification, DB latency, import RSS or operational fit.
Missing/unqualified sources remain HOLD; this is not installed qualification.

## Fixed ingress and ownership

The package `nix/native-attempt.nix` supplies three fixed executables:

| Entry | Input | Boundary |
| --- | --- | --- |
| `qcl-negf-native-attempt-client ACTION` | One request JSON on stdin | Unprivileged; no config/source/fake overrides |
| `qcl-negf-native-attempt-serve` | One accepted AF_UNIX socket on stdin/stdout; no arguments | Root socket-template service |
| `qcl-negf-native-attempt-hook prolog\|epilog` | Actual Slurmd environment, job ID only as selector | Authenticated root ancestry, never a caller certificate |

The controller option `qclNegf.application.nativeAttempts.enable` defaults to
false. Enabling it requires the existing API, the exact private runtime
`policyFile = "/etc/qcl-negf/native-attempt/policy.json"` and one new owned
`resultPrefix` under the existing jobs mount (default `native`). The module does
not copy policy contents or credentials into the Nix store. Root separately
prepares the regular protected runtime file and the new result directory.
Worker hooks have their own default-disabled
`qclNegf.cluster.nativeAttempts.enable` and the same fixed policy endpoint with
worker-role contents. Foreign Prolog/Epilog settings conflict explicitly.

The socket `/run/qcl-negf/native-attempt.sock` is root:qcl-negf 0660. A single
connection creates `qcl-negf-native-attempt@.service`: root, no restart, 90 s,
128 MiB, 16 tasks, `KillMode=control-group`, and write access to the two local
attempt directories plus the existing profile's access-record subdirectory and
reviewed log directory. Existing daemon/API `NoNewPrivileges=true` remains.
Both controller services get a read-only view of the new canonical result
prefix; uploads use distinct existing workdirs. NFS exports and `root_squash`
are unchanged.

Authentication joins `SO_PEERCRED` through an actual bounded PPID/birth chain:
fixed generated Python-I-c client, optional exact S1 Bash hop, APP daemon worker,
circus and the qualified daemon MainPID/Invocation. Kernel executable origins,
exact role argv and selected AIIDA_PATH/jobs-root environment are read twice;
stable generations are compared independently of raw CPU/context counters.
Pinned AiiDA 2.9.2 starts MainPID with the configured AIIDA_PATH base and passes
the config directory `base/.aiida` to circus/worker and inherited shell/client.
Those exact values follow the authenticated roles; arbitrary path normalization
or aliases are refused. Jobs root stays exactly the generated value for all roles.
It rejects an API, manual shell or reused process with the same UID.
Native daemon startup resolves the existing root profile once, then execs
immutable APP/bin/verdi and puts that immutable bin directory first on PATH.
The live MainPID/circus/worker argv must name this APP; a current profile alias
or shared canonical core script cannot certify an already-loaded APP after a
profile retarget. Unknown wrapper/title forms remain HOLD. Native-off startup
keeps the original launch behavior.
The root helper rechecks its own template invocation and paid limits. Under
socket activation client-observed peer PID1 is legitimate; UID0 and the
protected socket inode/ancestry matter. A root-owned JSON expectation is not
sufficient by itself.
Original command failures before owner construction, including the unit
Environment query, retain a bounded original-record prefix/hash/length and cleanup
uncertainty on protected stderr/journal. The public reply stays HOLD without
diagnostic contents, attempt creation or retry. If the diagnostic sink itself
fails, it cannot replace the primary HOLD; delivery is not claimed in that case.

The same Nix generator produces the client expression and private actor launch
configuration; no manual source-hash registry or API launch-envelope extension
is used. The qualified root unit selects this immutable file. The daemon gets
QCL_NEGF_NATIVE_JOBS_ROOT from cluster.jobDirectory only when native is enabled;
actual selected environment and private policy must agree. Mutable service.env
does not become authority.

Read-only actor queries allow standard existing-profile PID access records and
file-log open/rotation. There is no profile bootstrap, maintenance, unknown-lock
deletion or whole-profile RW. The selected config.json is mounted read-only in
server/daemon/API views; bounded FD/hash readback joins the actual namespaces.
The default log directory is shared; its directory RW scope for rotation is
explicit, not per-file kernel confinement. Its existing membership/ownership,
actual profile generation and logging DB effects need native qualification.
Unexpected DB-data writes require HOLD and an owning logging/read-loader port.
No SQL-enforced read-only claim is made. Standard access/log growth, rotation,
import RSS and DB latency must be measured before installed acceptance.

Only a finite stock Slurm script subset is admitted: fixed interpreter/original
release guard, reviewed unique stock headers, two thread exports, one literal
solver argv and fixed redirections. Extra shell, custom directives or free flags
are refused. Output is exactly policy.jobs_root/original relative root. Optional
scratch remains HOLD until its original INPUT has an explicit public port.
The literal `run-plan` arguments admit exactly two classes: the original seven
arguments through `--source-graph source-graph.json`, or those same arguments
followed, in order, by `--native-execution native-execution.json
--native-calcjob-uuid UUID`. The latter has exactly eleven arguments; UUID must
equal the actual authenticated request CalcJob UUID passed by
`NativeSources.preflight`, independently of Launch file/hash assertions. Both
classes retain the release guard and `unset QCL_NEGF_CAPTURE_SPEC`. Path aliases,
alternate quoting, reordered/duplicate/missing flags, substitutions and extra
shell remain refused. The original seven-argument class stays unmapped and
receives no creator attribution. Accepting the new literal establishes only its
join to the authenticated request and original submitted bytes; actual producer,
virgin output/no-reuse, writer and source-origin qualification remain separate
gates. The original plan role permits up to 1 MiB, matching the existing capture
plan allowance; source graph/native execution remain at 64 KiB and submit script
retains its policy cap, at most 64 KiB. Both actor input claims and the uploaded
original reader apply these role limits. This Platform allowance alone does not
qualify the owning AiiDA actor, installed producer or joined native input path.
Resource admission remains Slurm's responsibility. New submit needs current
ready release/admission; reconcile/status/start can observe a retained attempt
with admission closed. Lost ACK never dispatches again. End-to-end Q1 retrieval
needs the separate AiiDA consumer; cancel remains a separate HOLD gate.

## Durable dispatch and uncertainty

Requests have exact keys `version,action,calcjob_uuid,launch,controls`. Actions
are `submit,reconcile,start,close,status`; operational transport attempt integers
never become a native scientific attempt identity. `launch` fixes the original
Code/release/input-node UUID expectations, plan/graph/execution/script byte
claims, canonical output domain and upload workdir. These assertions remain
untrusted until their owning actor source joins the actual inputs.

Root-local `/var/lib/qcl-negf-native-attempt` is 0700. Exclusive durable records
retain the original claim, dispatch intent (actual argv, script digest, root
process/unit/host), ACK, native binding, worker allocation and failures. Files
use `O_EXCL`, `O_NOFOLLOW`, single-link checks, stable-FD/named-inode readback,
file/directory fsync and short metadata locks. An output-domain admission record
also excludes another CalcJob with an intersecting declared domain. It is not
automatically deleted or reclaimed. Future recovery/continuation ownership
requires its separate grant.

The fixed credential-drop child clears supplementary groups and reads uploaded
files as the existing UID/GID3000. This works with NFS `root_squash`; root-only
journals never go on NFS. It walks stable directory FDs, requires regular
single-link owner files, checks bounded original hashes and preserves an exact
script snapshot in `/var/lib/qcl-negf-native-spool` (root:qcl-negf, script 0440).
No numerical arrays are copied. `sbatch` reopens only this protected snapshot.

After durable dispatch intent, exactly one fixed argv uses immutable `runuser`
and `sbatch --parsable --no-requeue --chdir ... --comment ... SNAPSHOT`, with a
sanitized environment. A trustworthy ACK has strict ASCII job/cluster grammar
and its length equals the command engine's total output byte count; stderr or
discarded non-ASCII bytes cannot masquerade as a clean ACK. ACK is fsynced before
BOUND. The actual `scontrol` join checks owner, SubmitTime, original workdir,
protected snapshot Command and dispatch marker, and refuses requeue/arrays or
multiple nodes/tasks. Comments/names/IDs alone are not causal proof.

Any partial claim, lost ACK, client death, timeout or ambiguous write consumes
the key and returns HOLD; a repeated key never issues another `sbatch`.
Reconciliation can use a durable original ACK. No comment-only/lost-ACK causal
fallback is qualified here. Empty `squeue`/`sacct`, elapsed time and local child
cleanup never prove that a remote submit did not happen. A later trustworthy
ID belongs to this same CalcJob; the published AiiDA adapter pauses ordinary
backoff on HOLD and lets existing `execmanager` set that ID after same-UUID play.

## Start, stop and finite writer closure

Root Prolog/Epilog records verify actual ancestry to the current immutable
Slurmd unit. Environment variables are selectors only. Foreign jobs are not
enrolled or failed by the global hook. Missing hook evidence blocks managed
start/close. Prolog is lifecycle provenance before tasks; Epilog/COMPLETING
does not prove a stopped job.

The only new facts action is `attempt-facts` on the existing forced facts-root
route. It accepts exactly
`version,calcjob_uuid,dispatch_id,job_id,generation,phase`. It cannot request a
resource mutation. Native reads are read-only; local privileged evidence is
persisted. Existing `classify_before` and `verify_after` predicates remain
unchanged. A real live task and exact root stepd are required; a fast job with
no captured before gives `native_start_not_observed`. Allocation attachment
retains the original generation and never replaces a previous worker boot.

W1 covers a finite trusted-team managed domain: enrolled controller, workers,
storage, admitted launchers and declared canonical output domains. It is not a
universal detector for hostile root or arbitrary malicious same-UID programs.
Current facts must join every allowed UID3000 workload; unknown/manual writers,
missing hosts, changed boot/unit/mount/storage or overlapping live managed
domains give `writer_domain_not_closed`. Known disjoint domains can coexist.
Shared UID and empty job cgroup alone do not close the allowed writer set.
The controller rechecks actual service mount namespaces and all enrolled worker
facts; Root still must qualify the actual site writer/storage/retention boundary.

The version 1 `qualify_close` closes four fixed byte claims after physical stop and W1. The
close request and closed reply carry exactly these ordered `{path,bytes,sha256}`
rows: `series_result.json`, `native-selection.json`, `_scheduler-stdout.txt` and
`_scheduler-stderr.txt`. Their respective byte ceilings are 32 MiB, 256 KiB,
64 KiB and 64 KiB; the unchanged aggregate operation budget can refuse a smaller
packet. Boolean lengths, aliases, reordered/extra claims and a missing mandatory
log are refused. Empty stock logs are allowed. Request claims remain untrusted
expectations. The helper does not parse scientific schemas or accept results,
selected sources, checkpoints or creator provenance.

The first two files come only from the authenticated original launch's canonical
result root; logs come from its separate original upload workdir. The same
credential-drop child clears groups and reads all four via stable directory FDs,
`O_NOFOLLOW`, regular single-link owner files without group/other write, exact
length/hash and named-inode/ancestor readback. Root never opens their NFS payloads.
Private observations retain the actual roots, FD signatures and read accounting;
these observations add no public certificate or root-selection field.

Close requires the existing claim, dispatch, trustworthy ACK, original allocation
and captured live-before plus authenticated stop evidence. W1 runs before and
after the four reads; current host, server/caller, worker boot, unit generation,
storage and selected RO mount view must still agree. Changed, missing or unknown
writers and replaced files/directories give HOLD. Close does not claim a new
attempt, dispatch, repair partial records or retry a scientific failure.

Under the existing metadata lock, exclusive `close-observation.json` is synced
and read back before exclusive `close.json` is synced and read back. Each record
keeps the existing 64 KiB ceiling. This ordered publication is not an atomic
transaction across storage domains. Complete lost-ACK repetition requalifies
current W1/generations and the same four bytes, then returns the unchanged stored
reply. Observation-only, partial or conflicting publication gives HOLD without
overwrite or blind repair. Original publication/read failures retain bounded
protected diagnostics; a diagnostic sink failure cannot replace the primary HOLD.

The version 1 transfer packet is five files in total: the four named files plus
`native-close.json`. The latter is a projection of the protected Reply7 with
receipt `UUID/close.json`, not an NFS input or a fifth claim: there is no selfhash.
Stored/socket reply bytes use the existing canonical encoding without LF; the
fixed client adds exactly one transport LF. The AiiDA consumer must authenticate
and decode that closed reply and remove only this framing LF to retain the
original payload. Partial/extra output is HOLD, never reserialized authority.

Before forking, the original ledger prepays bounded copies and directory/file
operations for both derived roots and the asserted four lengths. The child
inherits the same deadline; credits are never reset or refunded. Actual read
bytes are recorded separately. Neither the per-file ceiling nor a source fixture
raises the original aggregate budget or proves native RSS/latency fit.

A closed reply is operational byte/stop evidence, not a lease or a future-write
certificate. The permanent managed output-domain claim and current W1 require
Root's separately qualified finite writer/storage/RO/no-reuse retention boundary.
`retention_ref` is a locator. Current access failure cannot turn a retained closed
record into a fresh access pass. AiiDA getter lifetime, original creator joins,
retained/cross-root sources, scientific acceptance and optional capture remain
separate owning gates.

## Q1T: optional technical metadata, версия 2

Версия 2 расширяет только существующий parser `close`. Запрос имеет ровно поля
`version,action,calcjob_uuid,launch,controls,technical_control`, где `version=2`,
`action="close"`, а `launch` сохраняет исходную форму. Успешный ответ имеет ровно
`version,state,calcjob_uuid,receipt_ref,job,controls,technical_control,reason`.
Четыре scientific controls, их порядок, integer lengths и потолки остаются прежними.
Другие actions используют версию 1; нового daemon или UI close нет.

`technical_control` — одна из двух закрытых форм:

```json
{"status":"present","path":"performance-source.json","bytes":"123","sha256":"<64 lowercase hex>"}
{"status":"absent","path":"performance-source.json","reason":"not_published"}
```

Для `present` поле `bytes` — каноническая десятичная строка UInt64 от `"0"` до
`"1048576"`: без знака, пробелов и ведущих нулей. JSON number и boolean не
допускаются. Это длина целого исходного файла, а hash относится к тем же полным
байтам. Пустой существующий файл имеет `present` с `bytes="0"`; отсутствие не
означает нулевую нагрузку или нулевые метрики. `absent` подтверждается только
реальным отсутствием фиксированного leaf в исходном workdir после W1. Оно не
препятствует закрытию и последующему scientific/control retrieval по прежним
четырём controls.

Ожидания caller не являются доказательством. Credential-drop child читает
`performance-source.json` только из отдельного исходного `remote_workdir`, рядом
с scheduler logs. Путь нельзя выбрать клиентом или перенести в result root.
Применяются тот же `O_NOFOLLOW`, regular/single-link/owner/permissions контроль,
удержанные directory FDs, полная длина/hash, named-inode и ancestor readback.
Leaf и его родители должны оставаться стабильными; неизвестные writers,
изменённые bytes, symlink, hardlink, чужой owner и несоответствие
`present/absent` дают HOLD. W1 и generation/readback проверки выполняются до и
после общего чтения. Private witness сохраняет technical observation, root/FD
signatures и фактический I/O вместе с прежними controls.

Platform рассматривает payload как непрозрачные bytes: schema/index semantics,
CREATE/INPUT provenance и producer origin проверяют Contracts/AiiDA. Совпадение
hash само по себе их не устанавливает. Отсутствующий optional leaf не заменяет
обязательные scientific files и не скрывает ошибку их чтения.

Невалидная или неподдерживаемая версия запроса отвергается до durable effects.
Валидный v2 close получает exact8 reply; при `hold/rejected` оба поля `controls`
и `technical_control` равны `null`. Здесь `null` означает «не подтверждено», а
не наблюдённое отсутствие. Fixed client требует совпадения версии reply с
версией запроса и не принимает v1 как v2. Encoding без LF и единственный
transport LF сохраняются.

Прежние v1 requests и scientific close receipts сохраняют исходную семантику.
Старый `close.json` никогда не переименовывается и не становится technical
authority: запрос иной версии к уже закрытому attempt даёт HOLD с сохранением
обоих исходных records. Повтор того же v2 close заново проверяет W1 и полный
technical file либо отсутствие, затем возвращает неизменённый receipt. Поздняя
публикация после сохранённого `absent`, смена bytes или partial publication не
перезаписывает прежнее свидетельство. Порядок exclusive observation → receipt,
fsync/readback, потолки records 64 KiB, сохранение первичной ошибки и отказ от
ремонта неопределённого publication остаются прежними.

Technical read, workspace/copies и дополнительные file operations оплачиваются
из исходного невозвратного ledger до fork. Потолок leaf 1 MiB не увеличивает
aggregate metadata/memory/deadline limits: даже допустимый файл может не
поместиться в текущий operation budget и дать HOLD до child/read. Cleanup
uncertainty сохраняет primary failure и не разрешает closed reply.

SOURCE/L проверка: подготовленный Python environment, команда
`python -m pytest -p no:cacheprovider tests/test_native_attempt.py -q` с
`PYTHONDONTWRITEBYTECODE=1`. Fixtures выполняют owner/store/credential-drop
fork/FD путь только на собственных temporary files с подставленными OS/RPC
наблюдениями; реального backend close, DB/ORM, NFS или services здесь нет.
AiiDA exact-v2 consumer/retrieval, installed/native qualification, R5 и все
научные gates остаются отдельными проверками Root.

## Accounting and qualification

One operation starts its monotonic deadline once. Policy can only tighten that
original deadline and finite byte/file/PID/command limits. Reads/hashes, JSON,
base64, journals, command buffers and facts RPC copies consume inherited,
nonrefundable metadata accounting; slabs are at most 64 KiB. Policy memory must
fit the observed root service limit. This is accounting, not a RAM grant.
Before each fixed actor query, the same operation prepays its existing query
workspace plus eight times each declared original length rounded through the
4096-byte read/EOF request, bounded by that role limit plus one byte. The command
response charge remains separate. Failure or cancellation cannot refund these
charges. The aggregate workspace remains 8 MiB (or a tighter policy); a plan at
the 1 MiB role ceiling can exceed that aggregate and must HOLD before the actor
command. File bytes and charged workspace are not physical I/O or measured RSS.
Hard-NFS/fsync can be uninterruptible: the helper does not claim safe remote
cleanup merely because its local deadline expired.

`trusted_rpc(..., trust_snapshot_root=None, existing_budget=None)` preserves old
default callers. P07 supplies only its protected local `trust-snapshots` child
and the original ledger (`before`, `reserve`, `actual_bytes`); G's snapshot
implementation is unchanged. The run callback clamps the legacy 120 s request
to the original operation's remaining command/deadline/output limits.

The private policy has schema `qcl-negf.native-attempt-policy.v1`. Native
qualification expects protocol `p07-ordinary-slurm-v1`, exact policy SHA,
observed machine/boot/image bindings, immutable unit fragment paths/hashes and
tool origins, and the finite write-domain/retention expectations. Every live
observation is rechecked. A receipt locator, `pass=true`, source tests or module
installation alone never qualify this protocol.

Before activation Root separately evaluates the actual roles/Nix oracle,
builds the package, checks installed caller/socket/service generations and
native hook/ACK causality, admits resources and qualifies synthetic lost-ACK,
live-before, stop, overlapping-writer, NFS and mount-view negatives. AiiDA actor
loading, end-to-end Q1 retrieval, recovery, release readiness and all scientific
gates remain separate. No old results/history/checkpoint read or new solve is
part of this backend's SOURCE/L verification.
