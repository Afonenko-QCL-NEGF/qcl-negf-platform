# Windows CPU worker lifecycle

Both Windows machines host the same Linux/NixOS worker role and
[application gate](application-cd.md). Measure CPU/RAM, LAN/NFS and scratch disk per guest. Hyper-V
and outer-hypervisor virtualization extensions for the Windows VM require separate checks; inside
Administrator rights alone do not prove them.

Deploy `windows/Start-QclWorker.ps1` and `Shutdown-QclWorker.ps1` through local computer-policy
PowerShell Startup/Shutdown scripts. Supply private VM/node/SSH targets and a protected SSH key
readable by the policy identity. Controller sudo access permits only reviewed lifecycle commands for
that node. Actual access details belong in the protected private site, never source or Nix inputs.

Startup starts the existing guest and requests controller delivery/check of the selected release
before Slurm resume. It creates neither VM nor recovery attempt. Shutdown keeps waiting while
Hyper-V/VMMS, guest and network must remain running.

The controller drains the node and snapshots **all** RUNNING/COMPLETING jobs with all owners
(`squeue --all`, no user filter). The small persisted snapshot survives SSH interruption, including
a job disappearing before acknowledgment. Each AiiDA-managed job has Slurm comment
`qcl-negf-attempt-v1:<URLSAFE_BASE64_JSON>`; decoded fields are
`{execution_id,attempt,output_directory,solver_executable}`. Output is relative to Slurm WorkDir
within the shared jobs filesystem, attempt is positive and solver path immutable. Unmanaged jobs
block with a reason for manual resolution instead of being ignored.

As each job owner, the permanent controller executes the pinned Runner:

```console
/nix/store/SOLVER/bin/qcl-negf pause SHARED_OUTPUT --execution-id ID --attempt N
/nix/store/SOLVER/bin/qcl-negf verify-stop SHARED_OUTPUT --execution-id ID --attempt N
```

Runner independently verifies the scoped durable pause bundle/receipt or a terminal archive if
completion raced pause. The adapter also waits for that job to leave RUNNING/COMPLETING. Queue
disappearance, telemetry and an unverified JSON flag are not durable proof. Nonconverged terminal
work can be safe to stop without scientific acceptance. Requests are attempt-scoped/idempotent.

Idle shutdown returns after durable intent/capture/finalize and drain. The v2 intent remains
inhibiting delivery after the safe response and after client death. Busy shutdown waits for
**every** captured job, including other owners, and does not wait for a successor allocation or free
worker. Storage/controller/network errors retain the wait with a reason. Force shutdown/power
loss/crash bypass the hook and use periodic recovery.

## Candidate policy and hardware status

Set `MaxGPOScriptWaitPolicy=0` under Computer Configuration → System → Scripts → “Specify maximum
wait time for Group Policy scripts”.
[Microsoft documents zero as unlimited script waiting](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-scripts#maxgposcriptwaitpolicy).
This does not prove actual Hyper-V/network shutdown ordering. Check ordinary Start → Shutdown on
**both** machines with idle/repeated shutdown, several owners, slow checkpoint, temporary storage
loss, completed-job race, no free worker, return on a changed release and force loss. Read the
confirmed bundle on the permanent node before Windows finishes and record event ordering/timestamps.

Hyper-V/nested virtualization, GPO ordering and these machine tests are **not_verified**. Follow the
installed versions'
[nested virtualization requirements](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/enable-nested-virtualization).
If GPO stops VMMS/guest/network too early, evaluate a stable native service preshutdown wrapper; its
finite timeout cannot certify unlimited waiting by choosing an arbitrary 10/60 minutes. Local
parser/fake-command tests exercise adapter flow, not real Windows/Hyper-V acceptance.

## Startup enrollment migration (CR03)

Controller startup now requires protected `--enrollment` in addition to explicit `--node` and
`--target`, for example with synthetic placeholders:

```console
sudo qcl-negf-worker-lifecycle startup --node worker --target admin@worker.invalid --enrollment /operator-protected/enrollment.json
```

The actual local controller must be the sole enrolled controller, including its current boot, and
the returning guest must match enrolled UUID/machine-id/hostname/ Slurm NodeName. A new guest boot
is accepted only for the same permanent machine; boot UUID alone never proves a replacement is
authorized. Startup freezes protected known_hosts and uses that snapshot for every late SSH/Nix
call, verifies bound release checks, and rechecks before RESUME. Unknown delivery receipts remain
blocking.

The coordinated wrappers require `Enrollment`, `EnrollmentId` and `WorkerTarget` for both hooks.
`Enrollment` is a protected absolute controller path, not registry content uploaded by Windows;
`EnrollmentId` checks the scoped output. Legacy callers without those inputs fail closed. Provision
actual identity-capable guest tooling, provider/guest/host-key evidence and scoped sudo policy
separately. No inventory, credentials or machine trust are invented by these scripts.

## Durable normal lifecycle (CR02)

`shutdown --node N --target ROUTE --enrollment PATH` creates private mode-0600
`runtime/shutdown/N.json` (`qcl-negf-shutdown-intent-v2`) before DRAIN. It retains captured
owner/execution/attempt/solver/output descriptors until pinned Runner stop proof **and** actual
allocation exit. `safe_to_shutdown:true` includes shutdown/enrollment ID, observed NodeName/boot and
`phase:safe_to_power_off`; the record persists and delivery checks all shutdown records, including
workers omitted from its active pool. Normal idle or completed shutdown does not close admission for
independent healthy workers or cancel workflows.

Capture/finalize use the existing common delivery lock for short regions. Runner waiting and
unlimited outer polling release that lock; a separate per-node owner prevents duplicate shutdown. An
orphan incomplete capture, v1 snapshot (exact original bytes retained in v2), malformed state,
missing boot or unknown mutation requires explicit trusted reconciliation. Empty queues, elapsed
wait or a new boot cannot erase unknown scope. Client death never clears inhibition.

Normal return requires a controller-authenticated privileged operator invocation (actual root
identity through reviewed scoped sudo), separately from guest health. No caller `trusted:true` or
event UUID grants authority. It requires the same enrolled permanent machine/NodeName and a **new**
boot after completed normal safe stop; all later observations must equal that new boot. First
enrollment has no fabricated prior shutdown/boot proof. An identical resumed retry checks saved
admitted boot and current full release health without another RESUME. State stays on disk as
`resumed` evidence after success.

Before RESUME, startup durably creates its own unique existing CR04 admission-intent-v1 marker. Only
that newly created marker is removed after a durable resumed write, as the last fallible success
action. Collision, terminal fsync/replace failure, unlink failure or an unknown outcome retains
reconciliation inhibition. Existing CR04 receipts/markers are never overwritten or cleared; retries
reject them before snapshot creation/SSH. Health or new boot cannot resolve them. Normal inhibit is
node scoped; uncertain mutating startup retains the existing fail-closed gate recovery path. It does
not implement a full-cluster update or automatic deployment.

Windows/GPO actor mapping, actual enrollment/SSH trust, Hyper-V shutdown ordering and machine
runtime acceptance remain **not_verified**. These coordinated source wrappers do not establish those
facts. Running guest status is never an automatic clear. Whole-cluster I14 cancellation, complete
worker inventory and VM-stop/start barrier adapters remain a separate unimplemented gate; any
durable unknown update ownership blocks ordinary startup.
