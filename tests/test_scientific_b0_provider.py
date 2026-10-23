"""Source-authored literal controls; executing these requires a separate grant."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('b0', Path(__file__).parents[1] / 'ops/scientific_b0_provider.py')
b0 = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = b0
spec.loader.exec_module(b0)


class ProviderTests(unittest.TestCase):
    def test_unavailable_is_default(self):
        with self.assertRaisesRegex(b0.ProviderRefusal, 'unavailable'):
            b0.bind_single_b0(3, None, None)

    def test_boolean_is_never_a_native_proof(self):
        with self.assertRaises(b0.ProviderRefusal):
            b0.validate_domains(True, ())

    def test_checked_uint_rejects_bool_and_overflow(self):
        for value in (True, -1, 1 << 64):
            with self.assertRaises(b0.ProviderRefusal):
                b0.Budget(read=value)

    def test_exact_fit_and_one_byte_short(self):
        total = b0.Budget(read=4, write=8, scopes=3)
        stop = b0.Budget(read=1, write=2, scopes=1)
        ledger = b0._Ledger(total, stop)
        ledger.reserve(b0.Budget(read=3, write=6, scopes=2))
        with self.assertRaises(b0.ProviderRefusal):
            ledger.reserve(b0.Budget(write=1))
        self.assertEqual(ledger.used.write, 6)  # rejected reservation has no effects

    def test_alias_dedup_and_missing_controller_role(self):
        domain = b0.DomainProof('disk', (1, 2), 'fixed_thick', 100, 10, 7,
                                ('worker', 'controller'), 'native-record')
        placements = (('output', 'disk'), ('aiida_repository', 'disk'))
        self.assertEqual(b0.validate_domains((domain,), placements), ('disk',))
        with self.assertRaises(b0.ProviderRefusal):
            b0.validate_domains((domain,), placements + (('aiida_wal', 'other'),))

    def test_stop_retains_first_failure(self):
        ledger = b0._Ledger(b0.Budget(write=8), b0.Budget(write=2))
        ledger.freeze('first'); ledger.freeze('later')
        self.assertEqual(ledger.primary, 'first')
        with self.assertRaises(b0.ProviderRefusal):
            ledger.reserve(b0.Budget(write=1))

    def test_bad_delegate_partition(self):
        parent = b0.Budget(write=7)
        with self.assertRaises(b0.ProviderRefusal):
            b0.partition_budget(parent, (b0.Budget(write=4), b0.Budget(write=4)))


class IssuerFixture(b0.NativeBinding):
    """Finite fake issuer only; never a production authentication boundary."""
    def __init__(self):
        import hashlib
        self.issuer = b0.ProcessIdentity(17, 18, 0, 'boot', (1, 2), 3, 4)
        self.worker = b0.ProcessIdentity(27, 28, 3000, 'boot', (5, 6), 3, 4)
        domain = b0.DomainProof('disk', (1, 2), 'fixed_thick', 100, 10, 3,
                                ('worker', 'controller'), 'native-record')
        self.capsule = b0.AuthenticatedCapsule(
            hashlib.sha256(b'capsule').hexdigest(), 'consume', 'cp-revision', 'slot',
            'attempt', 'nonce', self.issuer, self.worker, (('job', '42'),),
            1000, b0.Budget(read=8, write=8), b0.Budget(read=1, write=1),
            (domain,), (('output', 'disk'), ('aiida_repository', 'disk')),
            'frozen-profile', 'controller-prepermit-receipt')
        self.claimed = False
        self.effects = []

    def issuer_identity(self):
        return self.issuer

    def verify_capsule(self, raw, envelope, issuer, worker):
        if envelope != ('cp-revision', self.capsule.attempt_id):
            raise b0.ProviderRefusal('CP refinement mismatch')
        return self.capsule

    def claim_once(self, capsule):
        if self.claimed:
            raise b0.ProviderRefusal('replay')
        self.claimed = True
        return capsule

    def collect_bound_domain(self, capsule):
        self.effects.append('domain-readback')
        return capsule.domains

    def reserve_stop(self, capsule):
        self.effects.append('reserve-stop')
        return b0.Settlement(0, capsule.stop, b0.Budget(), (), 'stop-reserved')


class IssuerBindingTests(unittest.TestCase):
    def controls(self, backend):
        from unittest.mock import patch
        from contextlib import ExitStack
        controls = ExitStack()
        controls.enter_context(patch.object(b0, '_capsule_bytes', return_value=b'capsule'))
        controls.enter_context(patch.object(b0, 'live_identity', return_value=backend.worker))
        controls.enter_context(patch.object(b0.os, 'getppid', return_value=backend.issuer.pid))
        controls.enter_context(patch.object(b0.time, 'monotonic_ns', return_value=100))
        return controls

    def test_replayed_fd_cannot_reserve_stop_twice(self):
        backend = IssuerFixture()
        with self.controls(backend):
            b0.bind_single_b0(3, backend, ('cp-revision', 'attempt'))
            before = tuple(backend.effects)
            with self.assertRaisesRegex(b0.ProviderRefusal, 'replay'):
                b0.bind_single_b0(3, backend, ('cp-revision', 'attempt'))
            self.assertEqual(tuple(backend.effects), before)

    def test_wrong_revision_or_worker_identity_has_zero_effects(self):
        from dataclasses import replace
        for mode in ('revision', 'uid', 'boot', 'new-process'):
            backend = IssuerFixture()
            envelope = ('wrong', 'attempt') if mode == 'revision' else ('cp-revision', 'attempt')
            if mode == 'uid':
                backend.worker = replace(backend.worker, uid=3001)
            elif mode == 'boot':
                backend.worker = replace(backend.worker, boot='other')
            elif mode == 'new-process':
                backend.worker = replace(backend.worker, pid=29, start_ticks=30)
            with self.controls(backend), self.assertRaises(b0.ProviderRefusal):
                b0.bind_single_b0(3, backend, envelope)
            self.assertEqual(backend.effects, [])


class BootstrapCleanupTests(unittest.TestCase):
    def launch_failure(self, mode):
        from unittest.mock import MagicMock, patch
        from contextlib import ExitStack
        backend = IssuerFixture()
        backend.authenticate_consume = lambda record: b'authenticated'
        parent, child = MagicMock(), MagicMock()
        if mode == 'timeout':
            parent.recvmsg.side_effect = TimeoutError('hello deadline')
        else:
            parent.recvmsg.return_value = (b'WRONG', [(b0.socket.SOL_SOCKET,
                b0.socket.SCM_RIGHTS, b0.array.array('i', [91]).tobytes())], 0, None)
        with ExitStack() as controls:
            controls.enter_context(patch.object(b0.socket, 'socketpair', return_value=(parent, child)))
            controls.enter_context(patch.object(b0.os, 'geteuid', return_value=0))
            controls.enter_context(patch.object(b0.os, 'fork', return_value=127))
            controls.enter_context(patch.object(b0, '_start_ticks', return_value=28))
            opener = controls.enter_context(patch.object(b0.os, 'pidfd_open', return_value=99))
            if mode == 'pidfd-failure':
                opener.side_effect = OSError('pidfd unavailable')
            wait = controls.enter_context(patch.object(b0.os, 'waitpid', side_effect=[(0, 0), (127, 9)]))
            kill = controls.enter_context(patch.object(b0.os, 'kill'))
            pidkill = controls.enter_context(patch.object(b0.signal, 'pidfd_send_signal'))
            close = controls.enter_context(patch.object(b0.os, 'close'))
            order = MagicMock()
            order.attach_mock(wait, 'wait'); order.attach_mock(kill, 'kill')
            order.attach_mock(pidkill, 'pidkill')
            controls.enter_context(patch.object(b0.time, 'monotonic_ns', return_value=100))
            launcher = b0.FixedRootSupervisor(backend, ('/nix/store/fixed/bin/solver',), (), 1, (5, 6))
            with self.assertRaises((b0.ProviderRefusal, TimeoutError, OSError)):
                launcher.launch(b'receipt')
            self.assertEqual(wait.call_count, 2)
            self.assertEqual([call[0] for call in order.mock_calls],
                             ['wait', 'kill' if mode == 'pidfd-failure' else 'pidkill', 'wait'])
            if mode == 'pidfd-failure':
                kill.assert_called_once_with(127, b0.signal.SIGKILL)
                pidkill.assert_not_called()
            else:
                pidkill.assert_called_once_with(99, b0.signal.SIGKILL)
            if mode == 'invalid':
                self.assertIn(((91,),), [(call.args,) for call in close.call_args_list])
            with self.assertRaises(b0.ProviderRefusal):
                launcher.launch(b'receipt')

    def test_failed_hello_timeout_kills_and_reaps(self):
        self.launch_failure('timeout')

    def test_invalid_hello_closes_rights_kills_and_reaps(self):
        self.launch_failure('invalid')

    def test_pidfd_open_failure_uses_owned_start_checked_fallback(self):
        self.launch_failure('pidfd-failure')

    def test_bounded_reap_timeout_remains_unknown(self):
        from unittest.mock import patch
        with patch.object(b0.os, 'waitpid', return_value=(0, 0)), \
             patch.object(b0.signal, 'pidfd_send_signal'), \
             patch.object(b0.time, 'monotonic_ns', return_value=11):
            with self.assertRaisesRegex(b0.ProviderRefusal, 'cleanup unknown'):
                b0._cleanup_owned_child(127, 99, 28, 10)


class ReceivedRightsTests(unittest.TestCase):
    def rejected_reply(self, marker, flags, prefix):
        from unittest.mock import MagicMock, patch
        channel = MagicMock()
        rights = (b0.socket.SOL_SOCKET, b0.socket.SCM_RIGHTS,
                  b0.array.array('i', [81, 82]).tobytes())
        channel.recvmsg.return_value = (marker, prefix + [rights], flags, None)
        with patch.object(b0.os, 'dup', return_value=19), \
             patch.object(b0.socket, 'socket', return_value=channel), \
             patch.object(b0.os, 'close') as close:
            with self.assertRaises(b0.ProviderRefusal):
                b0.receive_job_capsule(3, IssuerFixture())
            self.assertEqual(sorted(call.args[0] for call in close.call_args_list), [81, 82])
            self.assertEqual(channel.recvmsg.call_args.args[2], b0.socket.MSG_CMSG_CLOEXEC)

    def test_wrong_marker_closes_all_delivered_rights(self):
        self.rejected_reply(b'X', 0, [])

    def test_unknown_ancillary_before_rights_still_closes_them(self):
        self.rejected_reply(b'B', 0, [(0, 0, b'unknown')])

    def test_truncated_reply_closes_complete_received_descriptors(self):
        self.rejected_reply(b'B', b0.socket.MSG_CTRUNC, [])


class AuthorityFixture(IssuerFixture):
    def __init__(self):
        super().__init__()
        self.frozen = []
        self.freeze_error = False

    def check_current(self, capsule):
        return capsule

    def verify_descriptor(self, capsule, descriptor):
        return descriptor

    def delegate(self, capsule, permit, index, bound):
        return b0.NativeDelegation(capsule.attempt_id, 'descriptor', index, bound, object(), 'child')

    def freeze_normal(self, capsule, primary):
        self.frozen.append(primary)
        if self.freeze_error:
            raise b0.ProviderRefusal('native revoke unknown')

    def quiesce_job(self, capsule, permit, primary):
        return b0.StopResult('paused', primary, None, 'quiescent',
                            b0.Settlement(0, capsule.stop, b0.Budget(), (), 'stop'))


class NativeSiblingFreezeTests(unittest.TestCase):
    controls = IssuerBindingTests.controls

    def test_every_normal_error_revokes_native_sibling_and_retains_stop(self):
        for operation in ('reserve', 'capture', 'delegate', 'settle'):
            backend = AuthorityFixture()
            with self.controls(backend):
                authority = b0.bind_single_b0(3, backend, ('cp-revision', 'attempt'))
                descriptor = b0.CaptureDescriptor('descriptor', 'profile', (),
                    b0.Budget(read=1, write=1), (b0.Budget(read=1), b0.Budget(write=1)))
                permit = authority.reserve_before_capture(descriptor, 0)
                authority.delegate_native(permit, 0)  # existing issued sibling
                with self.assertRaises(b0.ProviderRefusal):
                    if operation == 'reserve':
                        authority.reserve_before_capture(descriptor, 0)
                    elif operation == 'capture':
                        authority.bind_captured_content(object(), None)
                    elif operation == 'delegate':
                        authority.delegate_native(permit, 0)
                    else:
                        authority.settle_native(permit, 0, None)
                self.assertEqual(len(backend.frozen), 1)
                first = authority._ledger.primary
                stop = authority.freeze_normal('secondary')
                self.assertIs(stop, authority._stop)
                self.assertEqual(authority._ledger.primary, first)
                self.assertTrue(all(reason == first for reason in backend.frozen))

    def test_native_freeze_failure_cannot_be_paused_pass(self):
        backend = AuthorityFixture(); backend.freeze_error = True
        with self.controls(backend):
            authority = b0.bind_single_b0(3, backend, ('cp-revision', 'attempt'))
            with self.assertRaises(b0.ProviderRefusal):
                authority.delegate_native(object(), 0)
            stop = authority.freeze_normal('secondary')
            self.assertEqual(authority._freeze_unknown, 'native revoke unknown')
            with self.assertRaisesRegex(b0.ProviderRefusal, 'unproved STOP'):
                authority.quiesce_job(stop)


class AggregateAttemptTests(unittest.TestCase):
    def sample(self, pending, attempt_limit=128):
        import copy
        helper_spec = importlib.util.spec_from_file_location('capacity_fixture',
            Path(__file__).with_name('test_scientific_resource_admission.py'))
        helper = importlib.util.module_from_spec(helper_spec)
        helper_spec.loader.exec_module(helper)
        cap = helper.capacity
        facts, request = helper.sample()
        def mutable(item):
            from collections.abc import Mapping
            if isinstance(item, Mapping):
                return {key: mutable(value) for key, value in item.items()}
            if isinstance(item, tuple):
                return [mutable(value) for value in item]
            return item
        observations = mutable(facts.observations)
        storage = observations['storage']['value']; authority = observations['authority']
        root = storage['roots'][0]
        second = copy.deepcopy(root)
        second.update(role='controller', domain='controller', backing_id='controller-fs',
                      inode_domain='controller-inodes')
        storage['roots'].append(second)
        request['root_roles'].append('controller')
        gib = 1024 ** 3
        for scope in storage['scopes']:
            for name, row in scope['views'].items():
                row.update(E=60 * gib if name != 'inodes' else 10, U=0, S=0,
                           A=256 * gib if name != 'inodes' else 1000,
                           H=256 * gib if name != 'inodes' else 1000)
        more = copy.deepcopy(storage['scopes'])
        for scope in more:
            scope['domain'] = 'controller'
        storage['scopes'].extend(more)
        for domain in ('domain', 'controller'):
            request['storage_growth'][domain] = {'logical_bytes': pending * gib,
                'physical_bytes': pending * gib, 'inodes': 1}
        for name in ('C1', 'enforcer'):
            authority[name]['domains'].append('controller')
        aggregate = []
        for kind in ('attempt', 'owner', 'campaign'):
            aggregate.append({'scope': kind, 'scope_id': 'attempt' if kind == 'attempt' else kind,
                'units': 'logical_bytes;physical_bytes;inodes', 'epoch': 'epoch',
                'baseline_id': 'baseline', 'views': {name: {'E': 120 * gib if name != 'inodes' else 20,
                    'U': 0, 'P': 0, 'S': 0,
                    'A': (attempt_limit if kind == 'attempt' else 256) * gib if name != 'inodes' else 1000,
                    'H': 256 * gib if name != 'inodes' else 1000}
                    for name in ('logical_bytes', 'physical_bytes', 'inodes')}})
        authority['aggregate_storage'] = cap.AggregateStorageProof(helper.BINDING, 'baseline',
            'operation', 'd' * 64,
            (('domain', ('filesystem', 'inode-domain')),
             ('controller', ('controller-fs', 'controller-inodes'))),
            (('scratch', 'domain'), ('controller', 'controller')), tuple(aggregate), ('native-proof',))
        return cap, cap.ScienceCapacityFacts(helper.BINDING, observations, facts.evidence), request, helper

    def test_typed_two_domain_attempt_exact_fit(self):
        cap, facts, request, helper = self.sample(4)
        self.assertIsInstance(helper.admit(facts, request), cap.ScienceCapacityDecision)

    def test_attempt_128gib_plus_one_rejected(self):
        cap, facts, request, helper = self.sample(4)
        request['storage_growth']['controller']['logical_bytes'] += 1
        self.assertEqual(helper.admit(facts, request).reason, 'aggregate_total_capacity')

    def test_attempt_136gib_rejected_even_with_larger_owner_campaign(self):
        cap, facts, request, helper = self.sample(8)
        self.assertEqual(helper.admit(facts, request).reason, 'aggregate_total_capacity')

    def test_attempt_cannot_claim_global_ceiling_above_128gib(self):
        cap, facts, request, helper = self.sample(4, attempt_limit=256)
        self.assertEqual(helper.admit(facts, request).reason, 'aggregate_attempt_slot_ceiling')


class HandshakeFlagsTests(unittest.TestCase):
    def parent_case(self, flags, success, extra_rights=False):
        from unittest.mock import MagicMock, patch
        from contextlib import ExitStack
        backend = IssuerFixture()
        backend.authenticate_consume = lambda record: b'authenticated'
        backend.capsule_for_child = MagicMock(return_value=b'capsule')
        from dataclasses import replace
        backend.worker = replace(backend.worker, pid=127, start_ticks=28)
        terminal = b0.ChildTerminalReceipt(127, 28, 9, 'whole-job-quiescent')
        backend.supervise_child = MagicMock(return_value=terminal)
        parent, child = MagicMock(), MagicMock()
        ancillary = [(b0.socket.SOL_SOCKET, b0.socket.SCM_CREDENTIALS,
                      b0.struct.pack('3i', 127, 3000, 3000))]
        if extra_rights:
            ancillary.append((b0.socket.SOL_SOCKET, b0.socket.SCM_RIGHTS,
                              b0.array.array('i', [91, 92]).tobytes()))
        parent.recvmsg.return_value = (b'HELLO', ancillary, flags, None)
        with ExitStack() as controls:
            controls.enter_context(patch.object(b0.socket, 'socketpair', return_value=(parent, child)))
            controls.enter_context(patch.object(b0.os, 'geteuid', return_value=0))
            controls.enter_context(patch.object(b0.os, 'fork', return_value=127))
            controls.enter_context(patch.object(b0, '_start_ticks', return_value=28))
            controls.enter_context(patch.object(b0.os, 'pidfd_open', return_value=99))
            waits = [(127, 9), ChildProcessError()] if success else [(0, 0), (127, 9)]
            controls.enter_context(patch.object(b0.os, 'waitpid', side_effect=waits))
            controls.enter_context(patch.object(b0.signal, 'pidfd_send_signal'))
            close = controls.enter_context(patch.object(b0.os, 'close'))
            controls.enter_context(patch.object(b0.time, 'monotonic_ns', return_value=100))
            controls.enter_context(patch.object(b0, 'seal_job_capsule', return_value=77))
            controls.enter_context(patch.object(b0, 'live_identity', side_effect=[backend.issuer, backend.worker]))
            launcher = b0.FixedRootSupervisor(backend, ('/nix/store/fixed/bin/solver',), (), 1, (5, 6))
            if success:
                self.assertIs(launcher.launch(b'receipt'), terminal)
                backend.supervise_child.assert_called_once()
            else:
                with self.assertRaises(b0.ProviderRefusal):
                    launcher.launch(b'receipt')
                backend.capsule_for_child.assert_not_called()
                backend.supervise_child.assert_not_called()
            if extra_rights:
                self.assertEqual(sum(call.args == (91,) for call in close.call_args_list), 1)
                self.assertEqual(sum(call.args == (92,) for call in close.call_args_list), 1)

    def worker_case(self, flags, success):
        from unittest.mock import MagicMock, patch
        channel = MagicMock(); backend = IssuerFixture()
        channel.recvmsg.return_value = (b'B', [
            (b0.socket.SOL_SOCKET, b0.socket.SCM_CREDENTIALS, b0.struct.pack('3i', 17, 0, 0)),
            (b0.socket.SOL_SOCKET, b0.socket.SCM_RIGHTS, b0.array.array('i', [81]).tobytes())], flags, None)
        with patch.object(b0.os, 'dup', return_value=19), \
             patch.object(b0.socket, 'socket', return_value=channel), \
             patch.object(b0.os, 'close') as close, \
             patch.object(b0.os, 'getppid', return_value=17), \
             patch.object(b0, '_capsule_bytes', return_value=b'capsule') as verify:
            if success:
                self.assertEqual(b0.receive_job_capsule(3, backend), 81)
                verify.assert_called_once_with(81)
                close.assert_not_called()  # one validated fd transferred to caller
            else:
                with self.assertRaises(b0.ProviderRefusal):
                    b0.receive_job_capsule(3, backend)
                close.assert_called_once_with(81)
                verify.assert_not_called()

    def test_parent_accepts_cloexec_only_credentialled_hello(self):
        self.parent_case(b0.socket.MSG_CMSG_CLOEXEC, True)

    def test_worker_accepts_cloexec_only_sealed_authority(self):
        self.worker_case(b0.socket.MSG_CMSG_CLOEXEC, True)

    def test_parent_rejects_each_truncation_or_unknown_flag_and_closes_rights(self):
        for flag in (b0.socket.MSG_TRUNC, b0.socket.MSG_CTRUNC, 1 << 29):
            self.parent_case(b0.socket.MSG_CMSG_CLOEXEC | flag, False)
            self.parent_case(b0.socket.MSG_CMSG_CLOEXEC | flag, False, extra_rights=True)

    def test_worker_rejects_each_truncation_or_unknown_flag_and_closes_rights(self):
        for flag in (b0.socket.MSG_TRUNC, b0.socket.MSG_CTRUNC, 1 << 29):
            self.worker_case(b0.socket.MSG_CMSG_CLOEXEC | flag, False)


if __name__ == '__main__':
    unittest.main()
