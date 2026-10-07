"""Finite public metadata journal; no model, process-status or cleanup policy.

Large original metadata remains a separate immutable blob. Caller-owned compact
status references its hash/size. Cleanup is a caller callback, never a built-in
submission, cancellation, signal or scientific acceptance decision.
"""
import hashlib
import json
import os
from pathlib import Path
import re


class JournalLimit(ValueError):
    def __init__(self, message, evidence=None):
        self.evidence = evidence
        super().__init__(message)


class StatusJournal:
    def __init__(self, directory, *, status_cap, blob_cap, total_cap):
        if any(type(x) is not int or x <= 0 for x in (status_cap, blob_cap, total_cap)):
            raise ValueError('Explicit positive finite journal caps required')
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700)  # exclusive whole attempt, never resume/overwrite
        self.status_cap, self.blob_cap, self.total_cap = status_cap, blob_cap, total_cap
        self.used = 0
        self.sequence = 0
        self.blobs = {}
        self._sync_directory()

    def _sync_directory(self):
        descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)

    def _write(self, name, raw, cap):
        remaining = self.total_cap - self.used
        if remaining <= 0:
            raise JournalLimit('Journal aggregate cap exhausted; prior files retained')
        retained = raw[:min(cap, remaining)]
        path = self.directory / name
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                               0o600), 'wb') as stream:
            # Charge the accepted prefix even if a later write/fsync fails.
            self.used += len(retained)
            stream.write(retained); stream.flush(); os.fsync(stream.fileno())
        self._sync_directory()
        evidence = {'path': name, 'sha256': hashlib.sha256(retained).hexdigest(),
                    'original_bytes': len(raw), 'retained_bytes': len(retained),
                    'complete': len(raw) == len(retained)}
        if not evidence['complete']:
            raise JournalLimit('Journal cap exceeded; original bounded prefix retained', evidence)
        return evidence

    def save(self, compact_status, metadata=None):
        """Append a compact caller status and immutable original byte blobs."""
        if not isinstance(compact_status, dict) or 'metadata_blobs' in compact_status:
            raise ValueError('Caller status object must not replace journal references')
        refs = {}
        for label, raw in (metadata or {}).items():
            if not isinstance(label, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', label):
                raise ValueError('Safe metadata label required')
            if not isinstance(raw, bytes):
                raise ValueError('Original metadata bytes required; caller controls serialization')
            # Do not hash an over-budget original. Preserve only its bounded prefix.
            if len(raw) > self.blob_cap:
                name = 'overflow-' + str(self.sequence) + '-' + label + '.raw'
                self.sequence += 1
                self._write(name, raw, self.blob_cap)
                raise AssertionError('Unreachable overflow')
            digest = hashlib.sha256(raw).hexdigest()
            if digest not in self.blobs:
                self.blobs[digest] = self._write('blob-' + digest + '.raw', raw, self.blob_cap)
            refs[label] = dict(self.blobs[digest])
        payload = dict(compact_status, metadata_blobs=refs)
        raw = (json.dumps(payload, sort_keys=True, separators=(',', ':')) + '\n').encode()
        name = 'status-' + str(self.sequence) + '.json'; self.sequence += 1
        self._write(name, raw, self.status_cap)
        return self.directory / name


class FinalizationError(RuntimeError):
    """Keep original caller, logging and cleanup exceptions without a success claim."""
    def __init__(self, primary_error, logging_errors, cleanup_error, cleanup_result):
        self.primary_error = primary_error
        self.logging_errors = tuple(logging_errors)
        self.cleanup_error = cleanup_error
        self.cleanup_result = cleanup_result
        super().__init__('Finalization failed or uncertain; inspect original and journal errors')


def cleanup_once(save, cleanup, *, primary_error=None):
    """Run caller-owned cleanup once even when before/after journal writes fail.

    The return value is opaque; no interpretation of terminal or scientific
    status is made. A supplied original failure is always re-raised in the
    aggregate error after cleanup, along with all logging/cleanup failures.
    """
    logging_errors = []
    cleanup_error = None
    result = None
    try:
        try: save()
        except BaseException as error: logging_errors.append(error)
    finally:
        try: result = cleanup()
        except BaseException as error: cleanup_error = error
        finally:
            try: save()
            except BaseException as error: logging_errors.append(error)
    if primary_error is not None or logging_errors or cleanup_error is not None:
        failure = FinalizationError(primary_error, logging_errors, cleanup_error, result)
        raise failure from (primary_error or cleanup_error or logging_errors[0])
    return result
