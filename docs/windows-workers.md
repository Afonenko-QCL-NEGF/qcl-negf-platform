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

Idle shutdown returns immediately after drain. Busy shutdown waits for **every** captured job,
including other owners, and does not wait for a successor allocation or free worker.
Storage/controller/network errors retain the wait with a reason. Force shutdown/power loss/crash
bypass the hook and use periodic recovery.

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

Existing Windows wrappers which omit enrollment now fail closed. Provision the verified
identity-capable guest tooling/role metadata through separately authorized bootstrap, enroll actual
provider/guest/host-key evidence, and explicitly update site startup invocation to pass protected
registry. This source change does not rewrite Windows/GPO wrappers or invent inventory/credentials.
Unsupported identity probe/Slurm adapter receives no automatic preflight copy or permissive
fallback. Normal shutdown's unlimited safe-stop polling is unchanged. CR02 shutdown intent, new-boot
reconciliation and shared owner coordination are not implemented by CR03; production lifecycle
readiness cannot be inferred from synthetic startup tests.
