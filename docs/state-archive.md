# Coordinated controller state staging and restore

Enable `qclNegf.stateArchive.enable` on the controller to install
`qcl-negf-state-archive`. It is a manual CLI, with no timer, automatic upload or
automatic deletion. The AiiDA `qcl-negf` profile and Slurm state must reside on
the separate mounted controller state disk. The tool refuses a state directory
on the OS root filesystem, a missing repository, a different database/repository
identity, symlinks or unsupported filesystem entries. It never omits such
entries silently.

One local archive contains the complete AiiDA profile directory (including its
disk-objectstore repository), a PostgreSQL custom dump and Slurm controller
state. Every regular file appears in `manifest.json` with its SHA-256 and byte
count. Tar preserves directories, including empty ones. The manifest records
the deployed root revision, PostgreSQL version, source paths, runtime secret
references and the NFS dataset reference. Secret references contain paths, not
secret bytes. Preserve the actual Munge/API/SSH secrets through the site's
separate secret-recovery procedure. AiiDA UUIDs are database identities and are
restored from that database rather than recreated from labels.

Before create, pause **all** submission paths and other database/repository
writers, finish the existing queue, and keep that maintenance state through
completion. `--writers-paused` is the operator's explicit declaration of this
prerequisite. The CLI stops the API and AiiDA daemon, verifies the Slurm queue is
empty, and stops Slurm before taking its state. PostgreSQL stays up for a local
socket dump. Previously active services restart in reverse order on completion
or an ordinary error. An externally killed process or host failure may leave
services stopped; inspect them explicitly before resuming maintenance.

Create a dedicated mode0700 staging directory with enough free space outside
all source trees. Set a finite disk budget using the measured database and
repository sizes; the tool also checks free space. Default retention is **one**
archive in that directory. A second archive fails admission until the older one
has been explicitly copied, verified and reviewed for local removal, or a
larger retention count and disk budget have been authorized. Existing archives
are never overwritten or deleted by the CLI.

```sh
qcl-negf-state-archive create /absolute/staging/controller-001.tar.gz \
  --source-revision ROOT_GIT_REVISION \
  --disk-budget-bytes DECLARED_BYTES --writers-paused
qcl-negf-state-archive verify /absolute/staging/controller-001.tar.gz
```

The archive and `.sha256` sidecar are mode0600. Publication follows complete
packing; a crash before sidecar publication leaves an unverifiable archive,
which is not a successful backup. Copy **both** files manually to the external
disk, then run `verify` on the copied archive and record its SHA-256, medium,
copy time and verification outcome in the private recovery log. Until that
external copy is verified, the manifest's `offhost_backup: not_copied` describes
same-server staging, which does not survive loss of that server/disk. The
sidecar detects corruption; retain its trusted value in that recovery log.

The NFS scientific dataset is deliberately separate: its status is
`nfs_data: not_included`. Copy it to the external medium under a separately
declared space/time budget, preserve its ownership and all files, and record a
file/dataset hash manifest. Do not claim a complete scientific backup from a
controller-state archive alone. No NFS array is committed to Git or read into
memory by this tool.

For restore, prepare an isolated replacement controller with the same pinned
OS/application versions and service UID. Provision a separate empty state disk
and an **empty** `qcl-negf` database owned by `qcl-negf`. Keep automatic bootstrap,
API, daemon and Slurm startup disabled during this preparation; even a fresh
controller may create state if those services start. Provide empty destination
profile/Slurm directories and enough space for temporary extraction plus the
restored files. Reprovision the referenced secrets separately. Verify the copied
archive first, then run:

```sh
qcl-negf-state-archive restore /absolute/external/controller-001.tar.gz \
  --disk-budget-bytes DECLARED_BYTES --writers-paused
```

Restore rejects a different PostgreSQL major, a different database name,
nonempty destination database/directories, bad hashes, duplicate members,
links or archive path traversal. PostgreSQL restore uses one transaction; file
copy may fail separately, so failed targets remain offline and require a new
empty target or explicitly reviewed cleanup before retry. The command leaves
all application/Slurm services stopped even on success. It never resets an
existing database or deletes existing provenance to make a restore succeed.

Before startup, run AiiDA status/storage checks with the restored profile as
the service account, compare the Computer/Code UUIDs with the backup identity,
and verify representative repository objects against the archive manifest.
Confirm the NFS dataset was restored separately and the expected job paths are
present. Re-enable the repeatable bootstrap: it must retain the existing UUIDs
and reject mismatched solver paths. Start only one authoritative controller.
Record the result of a bounded restore rehearsal on a separate VM before
relying on this backup. Byte-for-byte fixture extraction is covered by unit
tests; it is not a live AiiDA/PostgreSQL recovery test or scientific validation.

PostgreSQL major changes, AiiDA schema migrations, relocation of the repository
and active-job recovery require separate reviewed procedures. An OS generation
rollback does not revert database contents. Neither NFS nor the local staging
archive is an independent backup medium.
