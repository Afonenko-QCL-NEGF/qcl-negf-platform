# Ordinary native attempts

`ops/native_attempt.py` is an opt-in operational owner for one existing CalcJob
UUID. It does not construct an AiiDA process, accept science, load a DB profile,
cancel jobs or retry a scientific failure. The ordinary scheduler lifecycle
remains the only attempt owner. The published AiiDA component still needs its
separate scheduler/transport and authenticated actor-input integration.

The current production `NativeSources.preflight` deliberately ends with
`actor_input_binding_unavailable` after checking the native environment and G
retained source records. No actor loader exists at this boundary yet. A request
dictionary, protected policy, qualification receipt or Python constructor does
not replace that loader. Consequently this source is **not an installed or
production-qualified submission path**. SOURCE/L fixtures exercise the actual
fixed adapters with explicit synthetic kernel/command observations.

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
128 MiB, 16 tasks, `KillMode=control-group`, and write access only to the two
local attempt directories. Existing daemon/API `NoNewPrivileges=true` remains.
Both controller services get a read-only view of the new canonical result
prefix; uploads use distinct existing workdirs. NFS exports and `root_squash`
are unchanged.

Authentication compares `SO_PEERCRED` with double kernel PID/birth/UID/cgroup
captures, actual daemon unit InvocationID/ControlGroup/MainPID and immutable APP
launch origin. It rejects an API, shell or reused process with the same UID.
The root helper rechecks its own template invocation and paid limits. Under
socket activation client-observed peer PID1 is legitimate; UID0 and the
protected socket inode/ancestry matter. A root-owned JSON expectation is not
sufficient by itself.

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
ID belongs to this same CalcJob; the future AiiDA adapter must pause ordinary
backoff on HOLD and let existing `execmanager` set that ID after same-UUID play.

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

Even after physical stop and W1, `qualify_close` returns
`q1_controls_unavailable`: agreed durable Q1 transfer-close controls and the
actor/getter integration are not implemented in this scope. Supplied controls
cannot mint CLOSED or scientific/creator acceptance. The close request allows
at most five bounded control byte claims, never a directory/archive traversal.

## Accounting and qualification

One operation starts its monotonic deadline once. Policy can only tighten that
original deadline and finite byte/file/PID/command limits. Reads/hashes, JSON,
base64, journals, command buffers and facts RPC copies consume inherited,
nonrefundable metadata accounting; slabs are at most 64 KiB. Policy memory must
fit the observed root service limit. This is accounting, not a RAM grant.
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
loading, Q1 transfer closure, recovery, release readiness and all scientific
gates remain separate. No old results/history/checkpoint read or new solve is
part of this backend's SOURCE/L verification.
