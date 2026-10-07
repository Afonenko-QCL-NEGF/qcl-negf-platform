"""Journal preservation and caller-owned cleanup; no services or calculations."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).parents[1]


class StatusJournalTests(unittest.TestCase):
    def setUp(self):
        path = ROOT / 'ops/status_journal.py'
        self.assertTrue(path.is_file(), 'Bounded large-metadata journal primitive is absent')
        spec = importlib.util.spec_from_file_location('status_journal', path)
        self.ops = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.ops)
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name) / 'attempt'

    def test_metadata_larger_than_old_status_cap_is_preserved_as_blob_with_compact_ref(self):
        journal = self.ops.StatusJournal(self.directory, status_cap=1024, blob_cap=262144, total_cap=300000)
        raw = json.dumps({'get_run': 'x' * 140000}).encode()
        saved = journal.save({'status': 'observed', 'uuid': 'owned'}, {'get_run': raw})
        compact = json.loads(saved.read_bytes()); ref = compact['metadata_blobs']['get_run']
        self.assertLess(saved.stat().st_size, 1024)
        self.assertEqual((self.directory / ref['path']).read_bytes(), raw)
        self.assertEqual(ref['sha256'], hashlib.sha256(raw).hexdigest())
        self.assertTrue(ref['complete'])
        self.assertEqual(ref['original_bytes'], len(raw))

    def test_blob_overflow_preserves_original_prefix_without_complete_claim(self):
        journal = self.ops.StatusJournal(self.directory, status_cap=1024, blob_cap=10, total_cap=2000)
        with self.assertRaises(self.ops.JournalLimit) as caught:
            journal.save({'status': 'observed'}, {'raw': b'abcdefghijklmnop'})
        ref = caught.exception.evidence
        self.assertEqual((self.directory / ref['path']).read_bytes(), b'abcdefghij')
        self.assertEqual(ref['original_bytes'], 16)
        self.assertEqual(ref['retained_bytes'], 10)
        self.assertFalse(ref['complete'])
        self.assertEqual(ref['sha256'], hashlib.sha256(b'abcdefghij').hexdigest())

    def test_total_cap_retains_prior_status_and_same_blob_is_not_duplicated(self):
        journal = self.ops.StatusJournal(self.directory, status_cap=1024, blob_cap=100, total_cap=1000)
        first = journal.save({'status': 'one'}, {'raw': b'original'})
        first_raw = first.read_bytes()
        journal.save({'status': 'two'}, {'raw': b'original'})
        self.assertEqual(len(list(self.directory.glob('blob-*'))), 1)
        with self.assertRaises(self.ops.JournalLimit):
            journal.save({'status': 'x' * 2000})
        self.assertEqual(first.read_bytes(), first_raw)
        self.assertLessEqual(sum(p.stat().st_size for p in self.directory.iterdir()), 1000)
        with self.assertRaises(FileExistsError):
            self.ops.StatusJournal(self.directory, status_cap=1024, blob_cap=100, total_cap=1000)

    def test_logging_failure_cannot_skip_exactly_once_cleanup_and_primary_error_survives(self):
        journal = self.ops.StatusJournal(self.directory, status_cap=10, blob_cap=100, total_cap=1000)
        marker = Path(self.tmp.name) / 'cleanup-once'
        def save(): journal.save({'too_large': 'x' * 100})
        def cleanup():
            with marker.open('x') as stream: stream.write('caller-owned-cleanup')
            return 'caller-return-value'
        primary = RuntimeError('original caller failure')
        with self.assertRaises(self.ops.FinalizationError) as caught:
            self.ops.cleanup_once(save, cleanup, primary_error=primary)
        self.assertIs(caught.exception.primary_error, primary)
        self.assertEqual(len(caught.exception.logging_errors), 2)
        self.assertIsNone(caught.exception.cleanup_error)
        self.assertEqual(caught.exception.cleanup_result, 'caller-return-value')
        self.assertEqual(marker.read_text(), 'caller-owned-cleanup')

    def test_falsey_primary_exception_is_preserved_as_cause_with_successful_logging_cleanup(self):
        class FalseyError(RuntimeError):
            def __bool__(self): return False
        primary = FalseyError('original failure')
        with self.assertRaises(self.ops.FinalizationError) as caught:
            self.ops.cleanup_once(lambda: None, lambda: 'cleanup-returned', primary_error=primary)
        self.assertIs(caught.exception.primary_error, primary)
        self.assertIs(caught.exception.__cause__, primary)
        self.assertEqual(caught.exception.logging_errors, ())
        self.assertEqual(caught.exception.cleanup_result, 'cleanup-returned')

    def test_falsey_cleanup_exception_is_preserved_as_cause_with_successful_logging(self):
        class FalseyError(RuntimeError):
            def __bool__(self): return False
        failure = FalseyError('cleanup failed')
        def cleanup(): raise failure
        with self.assertRaises(self.ops.FinalizationError) as caught:
            self.ops.cleanup_once(lambda: None, cleanup)
        self.assertIs(caught.exception.cleanup_error, failure)
        self.assertIs(caught.exception.__cause__, failure)
        self.assertEqual(caught.exception.logging_errors, ())

    def test_cleanup_error_and_logging_errors_are_both_retained_without_success(self):
        log_error = OSError('log storage unavailable'); cleanup_error = ValueError('unknown terminal')
        def save(): raise log_error
        def cleanup(): raise cleanup_error
        with self.assertRaises(self.ops.FinalizationError) as caught:
            self.ops.cleanup_once(save, cleanup)
        self.assertEqual(caught.exception.logging_errors, (log_error, log_error))
        self.assertIs(caught.exception.cleanup_error, cleanup_error)


if __name__ == '__main__': unittest.main()
