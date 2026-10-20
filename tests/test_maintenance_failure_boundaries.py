"""OPS08 whole-route boundaries; only host/syscall facts are synthetic.

The existing command/scheduler model is shared fixture infrastructure, not an
independent native oracle. Authority validators, owner, activation, publishers,
node checks, finalization and high-level delivery remain production functions.
"""
import json
import os
from pathlib import Path
import shlex
import stat
import tempfile
import unittest
from unittest.mock import patch

import test_application_release as fixtures
from test_node_enrollment import CONTROLLER, TRUST, FakeProtectedFS, pool, registry


class MaintenanceFailureBoundaries(unittest.TestCase):
    setUpClass = classmethod(fixtures.I14UpdateTests.setUpClass.__func__)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.runtime, self.gate = self.root / 'runtime', self.root / 'gate'
        self.gate.write_text('{"open":true,"release_id":"old"}')
        fixtures.install_controller_config_io(self, self.root)
        self.pool = pool()
        self.calls, self.stopped = [], set()
        self.active, self.offline = False, None
        self.model = fixtures.NativeUpdateModel()
        self.local_commands = fixtures.Commands()
        self.clock = [100.0]
        self.injected = []
        self.fs = FakeProtectedFS()
        self.fs.serial = 1000000  # Never alias a live real descriptor.
        self.fs.nodes['/protected/enrollment.json'] = {
            'mode': stat.S_IFREG | 0o600, 'uid': 0,
            'bytes': json.dumps(registry()).encode()}
        snapshot = str(self.ops.TRUST_SNAPSHOTS)
        for ancestor in reversed((Path(snapshot), *Path(snapshot).parents)):
            self.fs.nodes.setdefault(str(ancestor), {'mode': stat.S_IFDIR | 0o700, 'uid': 0})
        # Route protected namespace descriptors only; lifecycle/runtime I/O is real.
        for name in ('open', 'fstat', 'read', 'write', 'mkdir', 'close', 'fsync'):
            original = getattr(os, name)
            fake = getattr(self.fs, name)
            def boundary(*args, _name=name, _real=original, _fake=fake, **kwargs):
                descriptor = kwargs.get('dir_fd')
                synthetic = descriptor in self.fs.fds
                if _name == 'open':
                    synthetic = synthetic or str(args[0]) == '/'
                elif _name not in ('mkdir',):
                    synthetic = synthetic or args[0] in self.fs.fds
                return _fake(*args, **kwargs) if synthetic else _real(*args, **kwargs)
            hook = patch.object(os, name, boundary)
            hook.start()
            self.addCleanup(hook.stop)
        generation = self.ops._process_generation
        for name, value in (
            ('_process_generation', lambda: (*generation()[:2], CONTROLLER['boot_id'])),
            ('observe_node_identity', lambda **_: dict(CONTROLLER)),
        ):
            hook = patch.object(self.ops, name, value)
            hook.start()
            self.addCleanup(hook.stop)

    def commands(self, args):
        # Adapt only the existing external-command fixture to a real fresh
        # frozen trust pathname; production trust validation is not replaced.
        if args[0] == 'ssh':
            option = next(a for a in args if a.startswith('-oUserKnownHostsFile='))
            selected = option.split('=', 1)[1]
            self.assertEqual(self.fs.nodes[selected]['bytes'], b'independent synthetic key bytes')
            with patch.dict(TRUST, {'path': selected}):
                return fixtures.I14UpdateTests.commands(self, args)
        return fixtures.I14UpdateTests.commands(self, args)

    def deliver(self, run=None):
        return self.ops.deliver_cli(fixtures.delivery_manifest(), self.pool,
            run=run or self.commands, enrollment='/protected/enrollment.json',
            runtime=self.runtime, gate=self.gate)

    def outcome(self, run=None):
        try:
            return self.deliver(run)
        except (ValueError, RuntimeError, OSError) as error:
            if not hasattr(error, 'delivery_summary'):
                raise
            return error.delivery_summary

    def test_healthy_whole_route_opens_and_removes_owned_intents(self):
        result = self.deliver()
        self.assertEqual(result['status'], 'completed')
        self.assertIs(result['open'], True)
        self.assertEqual(json.loads(self.gate.read_text()), {'open': True, 'release_id': 'release-a'})
        self.assertEqual([n for n, fields in self.model.transitions if fields['State'] == 'RESUME'], ['worker', 'second'])
        self.assertFalse(list((self.runtime / 'delivery-attempts').glob('*.lifecycle-intent.json')))
        self.assertFalse(list((self.runtime / 'delivery-attempts').glob('*.admission-intent.json')))

    def semantic_check(self, fault, uncertain=False):
        def command(args):
            raw = self.commands(args)
            if args[0] == 'ssh':
                words = shlex.split(args[-1])
                if args[-2] == 'admin@worker.invalid' and words[3] == 'check':
                    self.assertTrue(any(a[0] == 'nix-env' for a in self.calls))
                    self.assertTrue(any(a[0] == 'ssh' and a[-2] == 'admin@worker.invalid'
                        and shlex.split(a[-1])[3] == 'activate' for a in self.calls))
                    value = json.loads(raw)
                    if fault == 'ready_false': value['release']['ready'] = False
                    elif fault == 'ready_missing': del value['release']['ready']
                    elif fault == 'wrong_release': value['release']['release_id'] = 'release-b'
                    elif fault == 'wrong_schema': value['schema'] = 'unbound'
                    elif fault == 'wrong_node': value['node_identity'] = dict(CONTROLLER)
                    else: raise AssertionError('unknown fixture')
                    self.injected.append(len(self.calls))
                    return json.dumps(value)
            return raw
        result = self.outcome(command)
        self.assertEqual(len(self.injected), 1)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['nodes']['controller']['status'], 'verified')
        self.assertEqual(result['nodes']['worker']['status'], 'failed')
        # This literal is the R1 RED: known release negatives must stop too.
        self.assertEqual(result['nodes']['second']['status'], 'not_attempted')
        later = self.calls[self.injected[0]:]
        self.assertEqual(later, [], 'failed required check dispatched another command')
        self.assertFalse(any(a[:3] == ['nix', 'copy', '--to'] or 'State=RESUME' in a
            or a[0] == 'ssh' and shlex.split(a[-1])[3] in ('activate', 'check', 'finish-update')
            for a in later))
        self.assertIs(json.loads(self.gate.read_text())['open'], False)
        self.assertIs(result.get('requires_reconciliation', False), uncertain)
        if uncertain: self.assertEqual(result['remote_outcome'], 'unknown')
        else: self.assertNotEqual(result.get('remote_outcome'), 'unknown')

    def test_ready_false_stops_later_dispatch(self): self.semantic_check('ready_false')
    def test_ready_missing_stops_later_dispatch(self): self.semantic_check('ready_missing')
    def test_wrong_valid_release_stops_later_dispatch(self): self.semantic_check('wrong_release')
    def test_wrong_schema_preserves_existing_uncertainty(self): self.semantic_check('wrong_schema', True)
    def test_wrong_node_preserves_existing_uncertainty(self): self.semantic_check('wrong_node', True)

    def finalization_fault(self, fault):
        publish, unlink, admission = self.ops.publish_json, Path.unlink, self.ops.publish_admission
        retained = []
        def reached():
            self.assertIs(json.loads(self.gate.read_text())['open'], True)
            self.assertEqual([n for n, f in self.model.transitions if f['State'] == 'RESUME'], ['worker', 'second'])
            self.assertEqual([a[-2] for a in self.calls if a[0] == 'ssh'
                and shlex.split(a[-1])[3] == 'finish-update'], ['admin@worker.invalid', 'admin@second.invalid'])
            intents = list((self.runtime / 'delivery-attempts').glob('*.lifecycle-intent.json'))
            self.assertEqual(len(intents), 1)
            retained.append((intents[0], intents[0].read_bytes()))
            self.injected.append(len(self.calls))
        def local_publish(path, value, **kwargs):
            if value.get('operation') == 'whole_update' and value.get('status') == 'completed' and not self.injected and fault != 'unlink':
                reached()
                if fault == 'deadline':
                    self.clock[0] = 1901.0
                    return publish(path, value, **kwargs)
                if fault == 'journal_after_replace': publish(path, value, **kwargs)
                raise OSError('OPS08 local journal publication failure')
            return publish(path, value, **kwargs)
        def local_unlink(path, *args, **kwargs):
            if fault == 'unlink' and str(path).endswith('.lifecycle-intent.json') and not self.injected:
                reached()
                raise PermissionError('OPS08 own local intent unlink failure')
            return unlink(path, *args, **kwargs)
        def gate_publish(path, value, **kwargs):
            if fault == 'close_failure' and self.injected and value['open'] is False:
                raise OSError('OPS08 recovery close publication failure')
            return admission(path, value, **kwargs)
        with patch.object(self.ops.time, 'monotonic', lambda: self.clock[0]), \
             patch.object(self.ops, 'publish_json', local_publish), \
             patch.object(Path, 'unlink', local_unlink), \
             patch.object(self.ops, 'publish_admission', gate_publish):
            result = self.outcome()
        self.assertEqual(len(self.injected), 1)
        self.assertEqual(result['status'], 'failed')
        self.assertIs(result.get('requires_reconciliation'), True)
        if fault in ('deadline', 'close_failure'):
            self.assertIs(result.get('open'), None)
            self.assertEqual(result.get('admission_state'), 'unknown')
            self.assertIs(result.get('critical_admission_failure'), True)
            self.assertIs(json.loads(self.gate.read_text())['open'], True)
        else:
            self.assertIs(result.get('open'), False)
            self.assertEqual(result.get('admission_state'), 'closed')
            self.assertIs(json.loads(self.gate.read_text())['open'], False)
        self.assertEqual(retained[0][0].read_bytes(), retained[0][1])
        # Retry remains inhibited by actual durable intent, before any new child.
        before = len(self.calls)
        with self.assertRaises((ValueError, RuntimeError, OSError)):
            self.deliver()
        self.assertEqual(len(self.calls), before)

    def test_final_journal_oserror_recovers_closed_gate(self): self.finalization_fault('journal')
    def test_final_journal_after_replace_recovers_closed_gate(self): self.finalization_fault('journal_after_replace')
    def test_final_intent_unlink_failure_recovers_closed_gate(self): self.finalization_fault('unlink')
    def test_finalization_deadline_reports_unknown_admission(self): self.finalization_fault('deadline')
    def test_finalization_recovery_close_failure_reports_unknown(self): self.finalization_fault('close_failure')
