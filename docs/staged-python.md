# Staged Python readiness checks

A process scanner passed as `python -c CHECKER_SOURCE` can match its own command line: its search
patterns occur in `CHECKER_SOURCE`. That is evidence about the transport, not evidence of an active
build. Use the same frozen checker bytes in a separately staged file instead.

`ops/staged_python.py::staged_python_argv` constructs an exec argv without local I/O. Its short
loader binds a protected absolute script path, SHA256, byte cap and owner UID. The default owner is
root (`0`); the immediate parent must have mode `0700`, and the script must be a canonical,
non-symlink regular file with mode `0400`. The loader checks the opened inode and bounded bytes,
then runs the same interpreter with `-I -B SCRIPT_PATH`. Checker source is never embedded in the
process command line.

```python
argv = staged_python_argv(
    measured_python_path,
    protected_remote_script_path,
    reviewed_script_sha256,
    owner_uid=0,
    max_bytes=65536,
)
```

The caller must stage the public file once with exclusive creation, retain its original bytes/hash,
and prevent writes or replacement during verification and execution. This does not defend against
the trusted owner changing the directory or script. It does not validate the interpreter, stage a
file, open SSH, execute anything locally, stop processes or handle credentials. The caller must
provide the measured interpreter, quote argv appropriately for any SSH shell boundary, enforce
wall/output limits and retain original stdout/stderr before interpreting the result. Choose a staged
path that itself does not match the scanner patterns.

The focused tests launch only local stdlib Python checkers. They reproduce the inline self-match
with identical checker bytes, verify isolated staged execution, and reject wrong hashes, ownership,
modes, symlinks and oversized files before checker output. They establish neither remote staging nor
deployment acceptance.
