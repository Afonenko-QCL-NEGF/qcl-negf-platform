"""Owned temporary native I/O; injected syscall failures are not native coverage proof.

These tests must run only under an explicit finite native-I/O test grant.
"""
import os
import tempfile
import time
import unittest
from unittest.mock import patch

from ops.scientific_local_io import (
    LocalSlotIO, NativeBackend, Capsule, Bound, PathGrant, IssuerAuthorization,
    LocalIORefusal, FileHandle,
)


class LocalSlotIOTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.open(self.tmp.name, os.O_RDONLY | os.O_DIRECTORY)
        s = os.fstat(self.root)
        self.identity = (s.st_dev, s.st_ino, s.st_uid)
        names = ('campaign_id', 'slot_id', 'plan_digest', 'criteria_digest',
                 'source_graph_digest', 'release_id', 'runtime_id', 'execution_id',
                 'attempt_id', 'point_id', 'admission_id', 'job_id', 'step_id',
                 'owner_uid', 'pid', 'start_ticks', 'host_id', 'machine_id', 'boot_id',
                 'mount_namespace', 'cgroup_namespace', 'vm_id', 'hypervisor_id',
                 'resource_epoch', 'storage_epoch')
        self.binding = tuple((name, 'bound-' + name) for name in names)
        self.capsule = Capsule(self.binding, self.identity,
                               Bound(64, 64, 64, 64, 8, 64, 128),
                               time.monotonic_ns() + 10_000_000_000,
                               'trusted-escrow', 'native-all-alias-admission')
        self.ios = []

    def tearDown(self):
        # No test helper is added to the production lifecycle.
        for io in self.ios:
            io.freeze('test cleanup')
            for handle in getattr(io, '_files', {}).copy():
                try:
                    io.close(handle)
                except LocalIORefusal:
                    pass
        os.close(self.root)
        self.tmp.cleanup()

    def issuer(self, capsule):
        return IssuerAuthorization(capsule, self.binding, self.identity,
                                   'existing-authority-verification')

    def slot(self, **kwargs):
        io = LocalSlotIO(self.capsule, self.root, kwargs.pop('issuer', self.issuer),
                         kwargs.pop('backend', NativeBackend()), **kwargs)
        self.ios.append(io)
        return io

    def bound(self, *, read=0, write=8, log=0, calls=30, path=('out',), access='pending'):
        return Bound(read, write, log, 8, 1, 8, calls,
                     (PathGrant(path, access, 8),))

    def test_default_backend_denies_without_open(self):
        with patch('os.open', side_effect=AssertionError('native open')):
            with self.assertRaises(LocalIORefusal):
                LocalSlotIO(self.capsule, self.root, self.issuer, None)

    def test_boolean_issuer_is_not_authority(self):
        with self.assertRaises(LocalIORefusal):
            self.slot(issuer=lambda _: True)

    def test_real_write_read_flush_and_immutable_receipt(self):
        io = self.slot()
        op = io.reserve('copy', 0, self.bound(read=8))
        f = io.create_pending(op, ('out',))
        self.assertEqual(io.write_at(f, 0, b'abcdefgh'), 8)
        io.flush(f)
        io.close(f)
        with open(self.tmp.name + '/out', 'rb') as stream:
            self.assertEqual(stream.read(), b'abcdefgh')
        receipt = io.receipt()
        self.assertEqual(receipt.operations[0].write_requested, 8)
        self.assertEqual(receipt.operations[0].write_actual, 8)
        with self.assertRaises((AttributeError, TypeError)):
            receipt.sequence = 42

    def test_read_five_then_four_charges_only_first_native_read(self):
        with open(self.tmp.name + '/in', 'wb') as stream:
            stream.write(b'abcdefgh')
        io = self.slot()
        op = io.reserve('read', 0, self.bound(read=8, write=0, path=('in',), access='read'))
        f = io.open_read(op, ('in',))
        self.assertEqual(io.read_at(f, 0, 5), b'abcde')
        with patch('os.pread', side_effect=AssertionError('second read')):
            with self.assertRaises(LocalIORefusal):
                io.read_at(f, 0, 4)
        self.assertEqual(io.receipt().operations[0].read_requested, 5)

    def test_real_read_round_trip(self):
        with open(self.tmp.name + '/in', 'wb') as stream:
            stream.write(b'abcdefgh')
        io = self.slot()
        op = io.reserve('read-real', 0, self.bound(read=8, write=0, path=('in',), access='read'))
        f = io.open_read(op, ('in',))
        self.assertEqual(io.read_at(f, 0, 8), b'abcdefgh')
        io.close(f)
        row = io.receipt().operations[0]
        self.assertEqual((row.read_requested, row.read_actual), (8, 8))

    def test_escrow_exhaustion_before_any_open(self):
        io = self.slot()
        io.reserve('parent-includes-child', 0, self.bound())
        self.assertEqual(io.receipt().reserved.write, 8)
        with patch('os.open', side_effect=AssertionError('unreserved native open')):
            with self.assertRaises(LocalIORefusal):
                io.reserve('overshoot', 1, Bound(0, 64, 0, 0, 0, 0, 0,
                                               (PathGrant(('x',), 'pending', 0),)))
        self.assertEqual(io.receipt().sequence, 1)

    def test_offset_extent_rejects_before_write(self):
        io = self.slot()
        f = io.create_pending(io.reserve('extent', 0, self.bound()), ('out',))
        with patch('os.pwrite', side_effect=AssertionError('write')):
            with self.assertRaises(LocalIORefusal):
                io.write_at(f, 1, b'abcdefgh')

    def test_partial_requested_debit_is_not_refunded(self):
        io = self.slot()
        f = io.create_pending(io.reserve('partial', 0, self.bound()), ('out',))
        with patch('os.pwrite', return_value=3):
            self.assertEqual(io.write_at(f, 0, b'abcdefgh'), 3)
        row = io.receipt().operations[0]
        self.assertEqual((row.write_requested, row.write_actual), (8, 3))
        with self.assertRaises(LocalIORefusal):
            io.write_at(f, 0, b'x')

    def test_error_debit_sticky_primary_and_safe_close(self):
        io = self.slot()
        f = io.create_pending(io.reserve('error', 0, self.bound()), ('out',))
        with patch('os.pwrite', side_effect=OSError('P')):
            with self.assertRaises(LocalIORefusal):
                io.write_at(f, 0, b'abcdefgh')
        primary = io.receipt().primary
        native_close = os.close
        def close_then_error(fd):
            native_close(fd)
            raise OSError('S')
        with patch('os.close', side_effect=close_then_error):
            with self.assertRaises(LocalIORefusal):
                io.close(f)
        self.assertEqual(io.receipt().primary, primary)
        self.assertEqual(io.receipt().operations[0].write_requested, 8)
        self.assertTrue(io.receipt().unknowns)
        # Unknown close is not retried: the numeric fd may already be reused.
        with patch('os.close', side_effect=AssertionError('retry close')):
            with self.assertRaises(LocalIORefusal):
                io.close(f)

    def test_log_debits_write_once_and_log_once(self):
        io = self.slot()
        f = io.create_pending(io.reserve('log', 0, self.bound(log=8, access='log')), ('out',))
        io.write_at(f, 0, b'abcdefgh')
        row = io.receipt().operations[0]
        self.assertEqual((row.write_requested, row.log_requested), (8, 8))
        self.assertEqual(io.receipt().reserved.write, 8)

    def test_replay_skip_bool_and_overflow_are_denied(self):
        for seq in (True, 1, 2**64):
            io = self.slot()
            with self.assertRaises(LocalIORefusal):
                io.reserve('bad', seq, self.bound())
        io = self.slot()
        io.reserve('same', 0, self.bound())
        with self.assertRaises(LocalIORefusal):
            io.reserve('same', 1, self.bound())

    def test_path_handle_epoch_and_symlink_refusals(self):
        for path in (('..', 'x'), ('a/b',), ('',), ('x\0',)):
            io = self.slot()
            with self.assertRaises(LocalIORefusal):
                io.reserve('badpath', 0, self.bound(path=path))
        io = self.slot()
        op = io.reserve('path', 0, self.bound())
        with self.assertRaises(LocalIORefusal):
            io.create_pending(op, ('other',))
        io = self.slot()
        with self.assertRaises(LocalIORefusal):
            io.write_at(FileHandle(), 0, b'x')
        io = self.slot()
        op = io.reserve('epoch', 0, self.bound())
        self.binding = (('attempt', 'different'),)
        with self.assertRaises(LocalIORefusal):
            io.create_pending(op, ('out',))
        self.binding = self.capsule.binding
        os.symlink('/etc/passwd', self.tmp.name + '/link')
        io = self.slot()
        op = io.reserve('link', 0, self.bound(read=8, write=0, path=('link',), access='read'))
        with self.assertRaises(LocalIORefusal):
            io.open_read(op, ('link',))

    def test_nested_symlink_and_existing_output_are_not_followed(self):
        os.symlink(self.tmp.name, self.tmp.name + '/alias')
        io = self.slot()
        op = io.reserve('alias', 0, self.bound(path=('alias', 'out')))
        with self.assertRaises(LocalIORefusal):
            io.create_pending(op, ('alias', 'out'))
        with open(self.tmp.name + '/out', 'wb') as stream:
            stream.write(b'original')
        io = self.slot()
        op = io.reserve('existing', 0, self.bound())
        with self.assertRaises(LocalIORefusal):
            io.create_pending(op, ('out',))
        with open(self.tmp.name + '/out', 'rb') as stream:
            self.assertEqual(stream.read(), b'original')

    def test_boolean_offset_overflow_and_expired_epoch_refuse_before_native(self):
        for offset in (True, 2**64):
            io = self.slot()
            path = ('bad' + str(offset),)
            f = io.create_pending(io.reserve('bad-offset', 0, self.bound(path=path)), path)
            with patch('os.pwrite', side_effect=AssertionError('invalid offset write')):
                with self.assertRaises(LocalIORefusal):
                    io.write_at(f, offset, b'x')
        io = self.slot()
        op = io.reserve('deadline', 0, self.bound())
        with patch('ops.scientific_local_io.time.monotonic_ns', return_value=self.capsule.deadline_ns):
            with patch('os.open', side_effect=AssertionError('expired open')):
                with self.assertRaises(LocalIORefusal):
                    io.create_pending(op, ('out',))

    def test_issuer_freeze_before_open_blocks_native_creation(self):
        countdown = [0]
        def issuer(capsule):
            if countdown[0]:
                countdown[0] -= 1
                if countdown[0] == 0:
                    io.freeze('P')
            return self.issuer(capsule)

        io = self.slot(issuer=issuer)
        op = io.reserve('reentrant-open', 0, self.bound())
        # _open entry, root fstat, then authorization immediately before open.
        countdown[0] = 3
        with patch('os.open', side_effect=AssertionError('open after freeze')) as native_open:
            with self.assertRaises(LocalIORefusal):
                io.create_pending(op, ('out',))
        self.assertEqual(native_open.call_count, 0)
        self.assertFalse(os.path.exists(self.tmp.name + '/out'))
        self.assertEqual(io.receipt().primary, 'P')
        self.assertEqual(io.receipt().sequence, 1)
        self.assertEqual(io.receipt().reserved.write, 8)

    def test_issuer_freeze_before_pwrite_blocks_write_and_allows_safe_close(self):
        countdown = [0]
        def issuer(capsule):
            if countdown[0]:
                countdown[0] -= 1
                if countdown[0] == 0:
                    io.freeze('P')
            return self.issuer(capsule)

        io = self.slot(issuer=issuer)
        f = io.create_pending(io.reserve('reentrant-write', 0, self.bound()), ('out',))
        # write_at entry, pinned fstat, then authorization before pwrite.
        countdown[0] = 3
        with patch('os.pwrite', side_effect=AssertionError('pwrite after freeze')) as native_write:
            with self.assertRaises(LocalIORefusal):
                io.write_at(f, 0, b'abcdefgh')
        self.assertEqual(native_write.call_count, 0)
        with open(self.tmp.name + '/out', 'rb') as stream:
            self.assertEqual(stream.read(), b'')
        row = io.receipt().operations[0]
        self.assertEqual((row.write_requested, row.write_actual), (8, 0))
        self.assertEqual(row.outstanding, 1)
        io.close(f)
        self.assertEqual(io.receipt().primary, 'P')
        self.assertEqual(io.receipt().operations[0].outstanding, 0)

    def test_freeze_retains_first_and_stops_normal_work(self):
        io = self.slot()
        io.freeze('P')
        io.freeze('S')
        with self.assertRaises(LocalIORefusal):
            io.reserve('late', 0, self.bound())
        self.assertEqual(io.receipt().primary, 'P')

    def test_no_shrink_credit_and_call_limit(self):
        io = self.slot()
        f = io.create_pending(io.reserve('truncate', 0, self.bound()), ('out',))
        io.truncate(f, 8)
        io.truncate(f, 0)
        self.assertEqual(io.receipt().operations[0].growth_requested, 8)
        with self.assertRaises(LocalIORefusal):
            io.truncate(f, 8)
        io = self.slot()
        # Cleanup must fit too: with two slots, refuse before leaf open.
        with patch('os.open', side_effect=AssertionError('unbudgeted open')):
            with self.assertRaises(LocalIORefusal):
                io.create_pending(io.reserve('calls', 0, self.bound(calls=2, path=('out2',))), ('out2',))
        self.assertEqual(io.receipt().operations[0].calls, 1)


if __name__ == '__main__':
    unittest.main()
