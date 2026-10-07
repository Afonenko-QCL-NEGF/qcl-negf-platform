# Bounded status and large public metadata

`ops/status_journal.py` provides a source-only journal primitive for an
operator's bounded supervisor. It contains no scheduler, AiiDA, submission,
cancellation, result parser or scientific acceptance rule. The caller owns
those policies and supplies the exact scoped cleanup callback.

Create one exclusive attempt directory with explicit positive byte caps:

```python
from status_journal import StatusJournal, cleanup_once

journal = StatusJournal(attempt_directory, status_cap=131072,
                        blob_cap=2 * 1024**2, total_cap=2 * 1024**2)

# original_public_metadata is the exact bounded response bytes, not a pretty
# encoding of a growing aggregate status. The caller selects compact fields.
status_path = journal.save(
    {"status": "observed", "owned_uuid": owned_uuid},
    {"response": original_public_metadata},
)
```

The caps are separate, explicit limits inside the caller's authorized total
budget; they do not allocate more transport, wall time or physical storage.
A caller should reserve room for compact terminal/error statuses. Every blob
and status is exclusively created, mode 0600, fsynced along with the 0700
attempt directory. Identical complete byte blobs share one hash-addressed
file. Status entries remain separate immutable files; prior entries are never
replaced. Their `metadata_blobs` references contain relative filename,
SHA256, original/retained byte counts and `complete`. Verify that hash and the
complete flag before using a referenced original as evidence.

A blob or status exceeding its per-file or remaining total budget keeps its
original bounded prefix and raises `JournalLimit`. The exception's `evidence`
reference has `complete: false`; it is not a complete JSON object or a success
receipt. An exhausted aggregate cap creates no further files. Files already
written remain for diagnosis; no automatic retry, pruning or rollover occurs.
An I/O error also propagates, and cannot produce a complete reference.

Logging is not permission to omit terminal reconciliation. Put caller-owned
cleanup behind the primitive's `finally` boundary, preserving an original
failure when there is one:

```python
try:
    supervise_owned_work()  # existing caller, with its own finite deadline
except Exception as primary:
    # save_compact_status may fail again. That cannot prevent the one cleanup
    # call. cleanup_owned_work must independently check exact ownership and
    # observed terminal state; it must not submit/retry or cancel terminal work.
    cleanup_once(save_compact_status, cleanup_owned_work, primary_error=primary)
    raise  # defensive; a supplied primary is always re-raised by the wrapper
else:
    cleanup_once(save_compact_status, reconcile_owned_terminal_work)
```

The wrapper attempts a journal save before and after exactly one cleanup call.
It interprets neither the cleanup's opaque return value nor process/scientific
status. If the original caller, either save, or cleanup fails, it raises
`FinalizationError`, preserving `primary_error`, `logging_errors`,
`cleanup_error` and `cleanup_result`. A journal failure does not become a
scientific failure, and a cleanup return does not imply physical terminal or
scientific acceptance. Retain the exception and the original raw witnesses;
never label an unmeasured outcome as pass.

Use only public operational metadata here. Do not journal tokens, private
keys, profile credentials or arbitrary environment dumps. The caller is
responsible for that boundary and for ownership-scoped callbacks.
