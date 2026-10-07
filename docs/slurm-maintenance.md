# Return a registered node after controlled maintenance

`ReturnToService=0` deliberately keeps a previously unresponsive node DOWN,
even after `slurmd` registers again. Starting the daemon or switching an OS
generation does not authorize new jobs. Keep admission closed, verify the
selected release and both cold OS identities, then explicitly resume the
known node before reopening admission. Do not suppress configuration hash
warnings; diagnose differing configurations separately.

`ops/slurm_maintenance.py` is a source-only controller command for this one
transition. It neither installs packages nor activates a release. Existing
Windows worker startup remains the separate delivery flow in
`worker_lifecycle.py`. The maintenance helper does not resume arbitrary
failures, modify `ReturnToService`, requeue jobs, or retry an update.

The operator supplies two root-owned regular JSON files, each at most 64 KiB,
not writable by group or others, and pins their SHA256 digests. Capture an
actual readonly worker receipt under schema
`qcl-negf.slurm-maintenance-worker-readonly.v1`. It contains:

- `source_revision`, the verified release source revision;
- `observed_epoch`, the actual observation time, at most 60 seconds old;
- `identity_before` and `identity_after`: measured `machine_id`, `boot_id`,
  `current_system` and `booted_system` (the latter two must agree);
- `runtime_sha256`, the measured worker release JSON hash;
- `services_before` and `services_after`, exact properties for `slurmd` and
  `munged`: `LoadState`, `ActiveState`, `MainPID`, `InvocationID`;
- `registration`, measured `scontrol --oneliner show node NODE` fields
  `NodeName`, `CPUTot`, `RealMemory`, `Version`, `BootTime`, `SlurmdStartTime`.

Retain the raw worker identity/service/registration reads beside that receipt.
A prepared identity, boolean, stale service report or guessed timestamp does
not constitute this observation. Registration may use hostnames chosen by
private inventory; no public address or hostname is embedded here.

The frozen expected JSON has `operator_GO: true`, `node`, `source_revision`,
`worker_identity`, `worker_runtime_sha256`, the exact `registration` tuple,
`controller_identity` in the same identity format,
`controller_runtime_sha256`, `gate_sha256`, `release_id`, and `down_reason`.
Only the exact observed `Not responding [slurm@TIMESTAMP]` reason is accepted.
A low-memory, configuration, manual-drain or other DOWN reason needs its own
diagnosis and is rejected. The full controller queue must be empty, including
pending jobs and jobs of other owners.

Run the controller command once with measured immutable executable paths:

```sh
python3 ops/slurm_maintenance.py \
  --expected EXPECTED.json --expected-sha256 EXPECTED_SHA \
  --worker WORKER.json --worker-sha256 WORKER_SHA \
  --scontrol /nix/store/SLURM/bin/scontrol \
  --squeue /nix/store/SLURM/bin/squeue \
  --systemctl /nix/store/SYSTEMD/bin/systemctl \
  --runtime-json /protected/runtime/release.json \
  --gate /shared/admission.json --lock /protected/delivery.lock \
  --out NEW_ATTEMPT_DIRECTORY
```

The output directory is exclusive; the whole attempt is limited to 20 seconds
and 128 KiB, using the existing durable job-evidence logger. Controller raw
queue, node, configuration, services and identities are saved before checks.
Only after all guards does it issue one `State=RESUME`. That update can
invalidate registration temporarily: `IDLE+NOT_RESPONDING` with unset
registration timestamps is not readiness. A bounded readonly poll allows
that transient while rejecting changed resources, allocations, jobs or a
different boot. Success requires final exact `IDLE`, zero allocation, the
same registration tuple, unchanged controller services/configuration and
unchanged release/gate. Admission remains closed.

Any error, timeout or output cap leaves original evidence and no implicit
retry. A successful update exit code alone is not acceptance. The receipt
proves this administrative transition only, not scientific convergence,
checkpoint validity, or complete release readiness. Reopening admission is a
separate owning release operation after this and the other deployment gates.
