"""Literal M1 source controls. Not run by the source-authoring ticket.

Mocks exercise record/state guards only, never fabricate native qualification.
No solver, Slurm, namespace, mount, privileged helper or live CP is started.
"""
import copy
from dataclasses import replace
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zlib

OPS = Path(__file__).parents[1] / 'ops'
sys.path.insert(0, str(OPS))
for name in ('scientific_b0_provider', 'scientific_b0_site'):
    spec = importlib.util.spec_from_file_location(name, OPS / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
site = sys.modules['scientific_b0_site']
b0 = sys.modules['scientific_b0_provider']

# Independent literal bytes, including duplicate-key, noncanonical and wrong
# uint representation controls. No native observation is inferred from these.
GOOD_HEADER = b'{"args":{},"attempt":"attempt1","nonce":"nonce1","opcode":"issuer","sequence":0,"slot":"slot1"}'
BAD_JSON = (
    b'{"sequence":0,"sequence":1}',
    b'{"sequence":0.0}', b'{"sequence":NaN}', b'{ "sequence":0}',
    b'{"sequence":0}\n', b'[]',
)
ONCE_BODY = b'{"boot":"boot1","facts":{},"nonce":"nonce1","sequence":0,"state":"PRECONSUMED"}'


def capacity_rows():
    # Four scopes x three independent views. Exact fit logical128, allocation64,
    # inode8; no sum across alias roots can create another headroom.
    return [dict(scope=scope, domain='fs1', view=view, E=existing, U=2, P=3, S=1,
                 A=existing+6, H=6)
            for scope in ('attempt', 'owner', 'filesystem', 'campaign')
            for view, existing in (('logical_bytes', 122), ('allocated_bytes', 58), ('inodes', 2))]


class CanonicalControls(unittest.TestCase):
    def test_literal_header_and_invalid_json(self):
        self.assertEqual(site.decode(GOOD_HEADER)['opcode'], 'issuer')
        for raw in BAD_JSON:
            with self.subTest(raw=raw), self.assertRaises(b0.ProviderRefusal):
                site.decode(raw)

    def test_uint_bool_overflow_and_slot_escape(self):
        for value in (True, False, -1, 1 << 64, 0.0):
            with self.subTest(value=value), self.assertRaises(b0.ProviderRefusal):
                site._uint(value)
        for value in ('../slot', '/tmp/slot', 'slot;exec', '', 'a'*97, '-first'):
            with self.subTest(value=value), self.assertRaises(b0.ProviderRefusal):
                site.token(value)

    def test_capacity_exact_fit_one_byte_short_missing_view_and_alias(self):
        rows = capacity_rows()
        site.finite_views(rows)
        short = copy.deepcopy(rows); short[0]['A'] -= 1
        duplicate = copy.deepcopy(rows); duplicate.append(copy.deepcopy(rows[0]))
        for invalid in (short, rows[1:], duplicate):
            with self.assertRaises(b0.ProviderRefusal):
                site.finite_views(invalid)

    def test_no_boolean_controller_or_native_receipt_can_open_activation(self):
        binding = object.__new__(site.SiteNativeBinding)
        binding.intent_raw = b'consumed'
        with self.assertRaisesRegex(b0.ProviderRefusal, 'controller_induced_bound_missing'):
            binding.authenticate_consume(b'consumed')
        self.assertIs(site.CONTROLLER_IMPLEMENTED, False)
        self.assertIs(site.NATIVE_ATTACH_IMPLEMENTED, False)

    def test_unknown_opcode_freezes_and_no_callback_runs(self):
        binding = object.__new__(site.SiteNativeBinding)
        binding.intent = dict(slot_id='slot1', attempt_id='attempt1', nonce='nonce1')
        binding._rpc_sequence = 0
        binding.capsule = object()
        with patch.object(binding, 'freeze_normal') as freeze:
            packet = site.decode(GOOD_HEADER)
            packet['opcode'] = 'caller_callback'
            reply = binding.dispatch(packet)
            self.assertIsNone(reply['result'])
            self.assertIn('unavailable', reply['error'])
            freeze.assert_called_once()


class OnceControls(unittest.TestCase):
    def fixture(self, directory, raw):
        path = Path(directory) / 'once'
        path.write_bytes(raw)
        os.chmod(path, 0o600)
        return os.open(path, os.O_RDWR | os.O_CLOEXEC)

    def initial(self):
        row = json.loads(ONCE_BODY)
        row['crc32'] = zlib.crc32(ONCE_BODY)
        return site.canonical(row) + b'\n'

    def test_empty_torn_bad_crc_boot_and_new_worker_are_not_fresh(self):
        for raw in (b'', self.initial()[:-1], self.initial().replace(b'boot1', b'boot2')):
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as directory:
                fd = self.fixture(directory, raw)
                try:
                    # UID is deliberately mocked. This is a sequence guard test,
                    # not a native claim that a user-owned fixture has root custody.
                    with patch.object(site, 'root_file', return_value=os.fstat(fd)):
                        with self.assertRaises(b0.ProviderRefusal):
                            site.DurableOnce(fd, (os.fstat(fd).st_dev, os.fstat(fd).st_ino), 'nonce1', 'boot1')
                finally:
                    os.close(fd)

    def test_durable_capsule_sent_precedes_claim_and_duplicate_is_spent(self):
        with tempfile.TemporaryDirectory() as directory:
            fd = self.fixture(directory, self.initial())
            identity = (os.fstat(fd).st_dev, os.fstat(fd).st_ino)
            try:
                with patch.object(site, 'root_file', return_value=os.fstat(fd)):
                    once = site.DurableOnce(fd, identity, 'nonce1', 'boot1')
                    for old, new in (('PRECONSUMED', 'CONTROLLER_BOUND'),
                                     ('CONTROLLER_BOUND', 'NODES_BOUND'),
                                     ('NODES_BOUND', 'WORKER_CLAIMED'),
                                     ('WORKER_CLAIMED', 'CAPSULE_SENT'),
                                     ('CAPSULE_SENT', 'AUTHORITY_CLAIMED')):
                        once.advance(old, new, {})
                    lines = os.pread(fd, 65536, 0).splitlines()
                    self.assertEqual([json.loads(line)['state'] for line in lines],
                        ['PRECONSUMED', 'CONTROLLER_BOUND', 'NODES_BOUND', 'WORKER_CLAIMED',
                         'CAPSULE_SENT', 'AUTHORITY_CLAIMED'])
                    with self.assertRaises(b0.ProviderRefusal):
                        once.advance('CAPSULE_SENT', 'AUTHORITY_CLAIMED', {})
                    # New object cannot adopt the already claimed S/C lifecycle.
                    with self.assertRaisesRegex(b0.ProviderRefusal, 'replay'):
                        site.DurableOnce(fd, identity, 'nonce1', 'boot1')
            finally:
                os.close(fd)

    def test_fsync_unknown_never_releases_cas(self):
        with tempfile.TemporaryDirectory() as directory:
            fd = self.fixture(directory, self.initial())
            try:
                with patch.object(site, 'root_file', return_value=os.fstat(fd)):
                    once = site.DurableOnce(fd, (os.fstat(fd).st_dev, os.fstat(fd).st_ino), 'nonce1', 'boot1')
                with patch.object(site.os, 'fsync', side_effect=OSError('unknown fsync')):
                    with self.assertRaises(OSError):
                        once.advance('PRECONSUMED', 'CONTROLLER_BOUND', {})
                self.assertEqual(once.state, 'SPENT_UNKNOWN')
                with self.assertRaises(b0.ProviderRefusal):
                    once.advance('PRECONSUMED', 'CONTROLLER_BOUND', {})
            finally:
                os.close(fd)


class BootstrapSourceControls(unittest.TestCase):
    def test_containment_hooks_precede_fork_and_drop(self):
        source = (OPS / 'scientific_b0_provider.py').read_text()
        self.assertLess(source.index('self.backend.prepare_launch(consume)'), source.index('pid = os.fork()'))
        self.assertLess(source.index('self.backend.prepare_child(child.fileno())'),
                        source.index('os.setgroups([]); os.setgid(3000); os.setuid(3000)'))

    def test_package_is_narrow_and_module_default_off(self):
        root = OPS.parent
        module = (root / 'modules/scientific-b0.nix').read_text()
        package = (root / 'nix/scientific-b0-helper.nix').read_text()
        self.assertIn('lib.mkEnableOption', module)
        self.assertIn('lib.mkIf cfg.enable', module)
        self.assertIn('doCheck = false', package)
        self.assertIn('controller_native_attach', package)
        self.assertNotIn('nixos-rebuild', package)


class ReviewRoundOneControls(unittest.TestCase):
    """Literal failure fixtures; all native observation calls below are mocked.

    They test ownership and error ordering, not a native pass for a fake fd.
    The source-authoring ticket does not import or execute this file.
    """
    def custody(self, owner):
        owner.adopt((81, 82, 83, 84, 85, 86, 87))
        return site.RootCustody(object(), 81, 82, 83, 84, (85,), (86,), (87,), owner)

    def test_high_fd_and_lowered_hard_limit_cannot_enter_enosys_fallback(self):
        # Counterexample is literal: fd1000 remains open after hard limit64.
        inherited_fd, lowered_hard_limit = 1000, 64
        self.assertGreater(inherited_fd, lowered_hard_limit)
        source = (OPS.parent / 'native/b0_trampoline.c').read_text()
        body = source.split('static int close_inherited(void) {', 1)[1].split('\n}\n', 1)[0]
        self.assertIn('syscall(SYS_close_range, 3U, UINT_MAX, 0U)', body)
        self.assertIn('return -1;', body)
        self.assertNotIn('getrlimit(', body)
        self.assertNotIn('for (', body)
        self.assertNotIn('return 0;', body.split('#endif', 1)[1])
        self.assertLess(source.index('close_inherited()) return 126'), source.index('execve('))

    def test_constructor_admission_once_and_pidfd_failures_close_all_once(self):
        publisher = b0.ProcessIdentity(17, 18, 0, 'boot1', (1, 2), 3, 4)
        for stage in ('admission', 'once', 'after_pidfd'):
            with self.subTest(stage=stage):
                owner = site.DescriptorCustody(); custody = self.custody(owner)
                original = b0.ProviderRefusal(stage + ' rejected')
                def reject(_self, _custody, _publisher):
                    if stage == 'after_pidfd':
                        owner.adopt((88,))
                    raise original
                with patch.object(site.SiteNativeBinding, '_initialize', reject), \
                     patch.object(site.os, 'close') as close:
                    with self.assertRaises(b0.ProviderRefusal) as raised:
                        site.SiteNativeBinding(custody, publisher)
                    self.assertIs(raised.exception, original)
                    owner.close()  # caller/finally may safely tear down again
                expected = list(range(81, 89 if stage == 'after_pidfd' else 88))
                self.assertEqual([call.args[0] for call in close.call_args_list], expected)
                self.assertEqual(owner.state, 'closed')
                self.assertIs(original.b0_custody, owner)

    def test_close_uncertainty_is_retained_and_never_retried(self):
        owner = site.DescriptorCustody(); owner.adopt((91, 92))
        with patch.object(site.os, 'close', side_effect=[OSError('uncertain close'), None]) as close:
            first = owner.close(); second = owner.close()
        self.assertEqual(close.call_count, 2)
        self.assertEqual(first, second)
        self.assertEqual(second['state'], 'close_unknown')
        self.assertEqual(second['descriptors'][0],
                         dict(fd=91, state='close_unknown', error='OSError'))
        with self.assertRaises(b0.ProviderRefusal):
            owner.adopt((93,))

    def test_malformed_receive_retains_close_unknown_in_callers_owner(self):
        from unittest.mock import MagicMock
        owner = site.DescriptorCustody()
        publisher = b0.ProcessIdentity(17, 18, 0, 'boot1', (1, 2), 3, 4)
        channel = MagicMock()
        channel.getsockopt.return_value = site.struct.pack('3i', 17, 0, 0)
        channel.recvmsg.return_value = (b'bad', [(site.socket.SOL_SOCKET, site.socket.SCM_RIGHTS,
            site.array.array('i', [91, 92]).tobytes())], site.socket.MSG_CTRUNC, None)
        with patch.object(site, 'live_identity', return_value=publisher), \
             patch.object(site.os, 'close', side_effect=[OSError('close uncertain'), None]) as close:
            with self.assertRaisesRegex(b0.ProviderRefusal, 'truncated/unknown') as raised:
                site.receive_custody(channel, publisher, owner)
            owner.close()
        self.assertEqual(close.call_count, 2)
        self.assertIs(raised.exception.b0_custody, owner)
        self.assertEqual(owner.receipt()['state'], 'close_unknown')
        channel.close.assert_not_called()

    def test_possible_live_child_retains_explicit_finite_owner(self):
        owner = site.DescriptorCustody(); custody = self.custody(owner)
        binding = object.__new__(site.SiteNativeBinding)
        binding.custody = custody; binding._launch_started = True
        original = b0.ProviderRefusal('unknown payload')
        with patch.object(site.os, 'close') as close:
            receipt = binding.close(original)
            owner.close()
        close.assert_not_called()
        self.assertEqual(receipt['state'], 'retained_unknown')
        self.assertEqual(len(receipt['descriptors']), 7)
        self.assertIs(original.b0_custody, owner)
        with self.assertRaises(b0.ProviderRefusal):
            owner.adopt((88,))

    def test_slot_failure_finally_closes_transferred_custody_borrows_channel(self):
        owner = site.DescriptorCustody()
        custody = site.RootCustody(object(), 81, 82, 83, 84, (85,), (86,), (87,), owner)
        binding = object.__new__(site.SiteNativeBinding)
        binding.custody = custody; binding._launch_started = False
        binding.intent = dict(slot_id='other_slot')
        publisher = b0.ProcessIdentity(17, 18, 0, 'boot1', (1, 2), 3, 4)
        channel = object()  # borrowed; no close method deliberately available
        def receive(*_args):
            owner.adopt((81, 82, 83, 84, 85, 86, 87))
            return custody
        with patch.object(site, 'root_file'), \
             patch.object(site, 'read_fd', return_value=site.canonical(dict(publisher=site.asdict(publisher)))), \
             patch.object(site, 'receive_custody', side_effect=receive), \
             patch.object(site, 'SiteNativeBinding', return_value=binding), \
             patch.object(site.os, 'close') as close:
            with self.assertRaisesRegex(b0.ProviderRefusal, 'slot mismatch'):
                site.fixed_entry('slot1', 70, channel, owner)
        self.assertEqual([call.args[0] for call in close.call_args_list], list(range(81, 88)))
        self.assertNotIn(70, [call.args[0] for call in close.call_args_list])

    def test_rpc_failure_plus_freeze_persist_failure_keeps_primary_and_cleans(self):
        from unittest.mock import MagicMock
        binding = object.__new__(site.SiteNativeBinding)
        worker = b0.ProcessIdentity(27, 28, 3000, 'boot1', (5, 6), 3, 4)
        binding.worker = worker
        binding.capsule = MagicMock(deadline_ns=1000, stop=b0.Budget(wall_ns=100))
        channel = MagicMock()
        # Invalid peer packet creates original ProviderRefusal before dispatch.
        channel.recvmsg.return_value = (b'', [], 0, None)
        with patch.object(site, 'live_identity', return_value=worker), \
             patch.object(site.time, 'monotonic_ns', return_value=10), \
             patch.object(site.os, 'waitpid', return_value=(0, 0)), \
             patch.object(binding, 'freeze_normal', side_effect=OSError('fsync failed')), \
             patch.object(site, '_cleanup_owned_child') as cleanup:
            with self.assertRaisesRegex(b0.ProviderRefusal, 'RPC peer/EOF/rights') as raised:
                binding.supervise_child(27, 97, 98, channel)
        cleanup.assert_called_once_with(27, 97, 28, 110)
        self.assertIn('freeze persistence unknown: OSError', raised.exception.__notes__)

    def test_durable_freeze_failure_still_latches_siblings(self):
        from unittest.mock import MagicMock
        binding = object.__new__(site.SiteNativeBinding)
        binding.capsule = object(); binding.primary = None
        binding._ledger = b0._Ledger(b0.Budget(), b0.Budget())
        binding._registry = {'sibling1': {'frozen': False}}
        binding.once = MagicMock(state='NORMAL')
        binding.once.advance.side_effect = OSError('fsync failed')
        with self.assertRaises(OSError):
            binding.freeze_normal(binding.capsule, 'original RPC failure')
        self.assertEqual(binding.primary, 'original RPC failure')
        self.assertEqual(binding._ledger.primary, 'original RPC failure')
        self.assertIs(binding._registry['sibling1']['frozen'], True)

    def test_secondary_note_failure_does_not_escape(self):
        class BrokenNote(b0.ProviderRefusal):
            def add_note(self, _note):
                raise OSError('note failed')
        original = BrokenNote('primary remains')
        site._secondary(original, 'freeze persistence unknown', OSError('fsync failed'))
        self.assertEqual(str(original), 'primary remains')


if __name__ == '__main__':
    unittest.main()
