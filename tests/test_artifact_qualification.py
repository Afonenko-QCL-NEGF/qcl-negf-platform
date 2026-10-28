"""Artifact receipts are engineering proofs, independent from mutable health.

Commands are a closed synthetic Nix/systemd boundary; no solver or service runs.
The tests retain real profile switches, lifecycle ownership and receipt files.
"""
import copy
import importlib.util
import inspect
import json
import os
import stat
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from test_node_enrollment import WORKER, ENROLL_IDS
from test_application_release import Commands, delivery_manifest, HASH, OTHER_HASH

SPEC = importlib.util.spec_from_file_location(
    'qualification_application_release', Path(__file__).parents[1] / 'ops/application_release.py')
ENV = {'kernel_release': '6.12-fixture', 'kernel_path': '/nix/store/kernel',
       'modules_path': '/nix/store/modules',
       'restore_epoch': '44444444-4444-4444-4444-444444444444'}
ARTIFACT = {'path': '/nix/store/solver', 'nar_hash': HASH, 'drv_path': '/nix/store/solver.drv'}


class QualificationAPI(unittest.TestCase):
    def setUp(self):
        self.ops = importlib.util.module_from_spec(SPEC)
        SPEC.loader.exec_module(self.ops)

    def api(self, name):
        function = getattr(self.ops, name, None)
        self.assertTrue(callable(function), 'Missing P11 qualification API: ' + name)
        return function

    def key(self, **changes):
        values = dict(node_identity=WORKER, artifact=ARTIFACT, environment=ENV,
                      enrollment_id=ENROLL_IDS[1])
        values.update(changes)
        return self.api('qualification_key')(**values)

class QualificationTests(QualificationAPI):
    def test_solver_key_ignores_release_application_activation_and_boot_generations(self):
        # Adding a mutable generation to the key breaks reuse across compatible APP changes.
        key = self.key()
        changed = {**WORKER, 'boot_id': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                   'release_id': 'portal-b', 'application_path': '/nix/store/portal-b',
                   'activation_revision': 'new-activation', 'service_generation': 'new-service'}
        self.assertEqual(self.key(node_identity=changed), key)
        self.assertNotIn('boot_id', key['node_identity'])

    def test_relevant_environment_enrollment_artifact_and_contract_changes_invalidate(self):
        key = self.key()
        candidates = [
            dict(node_identity={**WORKER, 'machine_id': '4' * 32}),
            dict(enrollment_id=ENROLL_IDS[2]),
            dict(artifact={**ARTIFACT, 'nar_hash': OTHER_HASH}),
            dict(artifact={**ARTIFACT, 'drv_path': '/nix/store/other.drv'}),
            dict(contract_version='qcl-negf-native-artifact-v2'),
        ]
        candidates.extend(dict(environment={**ENV, field: changed}) for field, changed in (
            ('kernel_release', '6.13-fixture'), ('kernel_path', '/nix/store/kernel-b'),
            ('modules_path', '/nix/store/modules-b'),
            ('restore_epoch', '55555555-5555-5555-5555-555555555555')))
        receipt = self.api('qualification_receipt')(key, {'integrity': True, 'solver_self_check': True})
        for changed in candidates:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                self.api('require_qualification')(receipt, self.key(**changed))

    def test_nixos_kernel_file_subpath_is_a_valid_immutable_environment(self):
        key = self.key(environment={**ENV, 'kernel_path': '/nix/store/kernel/bzImage'})
        self.assertEqual(key['environment']['kernel_path'], '/nix/store/kernel/bzImage')
        with self.assertRaises(ValueError):
            self.key(environment={**ENV, 'kernel_path': '/nix/store/kernel/../other'})

    def test_unknown_missing_corrupt_and_wrong_receipts_fail_closed(self):
        key = self.key()
        receipt = self.api('qualification_receipt')(key, {'integrity': True, 'solver_self_check': True})
        broken = [None, {}, {**receipt, 'status': 'not_measured'},
                  {**receipt, 'unknown': True}, {**receipt, 'key_sha256': '0' * 64},
                  {**receipt, 'evidence': {'integrity': True, 'solver_self_check': False}}]
        for value in broken:
            with self.subTest(receipt=value), self.assertRaises(ValueError):
                self.api('require_qualification')(value, key)
        self.assertEqual(self.api('require_qualification')(receipt, key), receipt)


class QualifiedActivationTests(QualificationAPI):
    def setUp(self):
        super().setUp()
        temporary = tempfile.TemporaryDirectory(prefix='p11-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.runtime = self.root / 'runtime'
        self.runtime.mkdir()
        self.gate = self.root / 'gate.json'
        self.profile = self.root / 'profile'
        self.value = delivery_manifest(False)
        self.commands = Commands()
        self.environment = dict(ENV)
        self.native_calls = []
        generation = self.ops._process_generation
        for name, replacement in (
            ('_process_generation', lambda: (*generation()[:2], WORKER['boot_id'])),
            ('observe_node_identity', lambda **_: dict(WORKER)),
            ('read_protected_file', lambda path, limit=65536, **_: Path(path).read_bytes()),
        ):
            hook = patch.object(self.ops, name, replacement)
            hook.start(); self.addCleanup(hook.stop)

    def native(self, argv):
        self.native_calls.append(list(argv))
        if argv[:3] == ['nix', 'path-info', '--json']:
            return json.dumps({row['path']: {'narHash': row['narHash']} for row in self.value['closures']})
        return self.commands(argv)

    def activate(self):
        self.assertIn('enrollment_id', inspect.signature(self.ops.activate).parameters,
                      'Activation must explicitly bind the enrollment receipt')
        observer = self.api('observe_qualification_environment')
        self.gate.write_text(json.dumps({'open': False, 'release_id': self.value['release_id']}))
        with patch.object(self.ops, 'observe_qualification_environment', lambda **_: dict(self.environment)):
            return self.ops.activate(self.value, profile=self.profile, runtime=self.runtime,
                gate=self.gate, run=self.native, expected_node_identity=WORKER,
                enrollment_id=ENROLL_IDS[1], deadline=time.monotonic() + 30)

    def check(self, **kwargs):
        with patch.object(self.ops, 'observe_qualification_environment', lambda **_: dict(self.environment)):
            return self.ops.check(self.value, profile=self.profile, runtime=self.runtime,
                run=self.native, expected_node_identity=WORKER, enrollment_id=ENROLL_IDS[1], **kwargs)

    def test_qualification_directory_remains_traversable_under_restrictive_umask(self):
        # File0644 cannot compensate for a root-owned parent without other+x.
        previous = os.umask(0o077)
        try:
            record = self.activate()
        finally:
            os.umask(previous)
        directory = self.runtime / 'qualifications'
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o755)
        for reference in record['artifact_qualifications'].values():
            self.assertEqual(stat.S_IMODE((self.runtime / reference).stat().st_mode), 0o644)
        self.assertEqual(directory.stat().st_uid, os.geteuid())

    def test_existing_private_qualification_directory_is_repaired_without_requalification(self):
        first = self.activate()
        directory = self.runtime / 'qualifications'
        receipts = {name: (self.runtime / reference).read_bytes()
                    for name, reference in first['artifact_qualifications'].items()}
        directory.chmod(0o700)
        self.native_calls.clear()
        previous = os.umask(0o077)
        try:
            repeated = self.activate()
        finally:
            os.umask(previous)
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o755)
        self.assertEqual(repeated['artifact_qualifications'], first['artifact_qualifications'])
        for name, reference in repeated['artifact_qualifications'].items():
            self.assertEqual((self.runtime / reference).read_bytes(), receipts[name])
        self.assertFalse(any(call[0] in ('nix', 'nix-store') or 'self-check' in call for call in self.native_calls))

    def test_qualification_directory_symlink_never_chmods_its_target(self):
        target = self.root / 'unrelated'
        target.mkdir(mode=0o700)
        link = self.runtime / 'qualifications'
        link.symlink_to(target, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            self.activate()
        self.assertTrue(link.is_symlink())
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
        self.assertEqual(list(target.iterdir()), [])
        self.assertFalse(self.native_calls)

    def test_untrusted_qualification_directory_is_refused_without_chmod(self):
        for fault in ('foreign-owner', 'group-writable', 'other-writable'):
            with self.subTest(fault=fault):
                self.runtime = self.root / ('runtime-' + fault)
                self.runtime.mkdir()
                directory = self.runtime / 'qualifications'
                directory.mkdir(mode=0o700)
                mode = {'foreign-owner': 0o700, 'group-writable': 0o770,
                        'other-writable': 0o707}[fault]
                directory.chmod(mode)
                original_stat = os.fstat
                selected = directory.stat()
                def observe(descriptor):
                    info = original_stat(descriptor)
                    if fault == 'foreign-owner' and (info.st_dev, info.st_ino) == (selected.st_dev, selected.st_ino):
                        fields = list(info); fields[4] = os.geteuid() + 1
                        return os.stat_result(fields)
                    return info
                with patch.object(self.ops.os, 'fstat', observe), self.assertRaises((ValueError, OSError)):
                    self.activate()
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), mode)
                self.assertEqual(list(directory.iterdir()), [])

    def test_compatible_application_change_reuses_solver_proof_and_status_is_cheap(self):
        first = self.activate()
        solver_ref = first['artifact_qualifications']['solver']
        first_solver_bytes = (self.runtime / solver_ref).read_bytes()
        self.native_calls.clear()
        self.value = {**self.value, 'release_id': 'portal-b', 'application_path': '/nix/store/portal-b',
                      'closures': [{'path': '/nix/store/portal-b', 'narHash': OTHER_HASH},
                                   {'path': '/nix/store/solver', 'narHash': HASH}]}
        second = self.activate()
        self.assertEqual(second['artifact_qualifications']['solver'], solver_ref)
        self.assertEqual((self.runtime / solver_ref).read_bytes(), first_solver_bytes)
        self.assertFalse(any('self-check' in call for call in self.native_calls))
        verify = [call for call in self.native_calls if call[:2] == ['nix-store', '--verify-path']]
        self.assertEqual(verify, [['nix-store', '--verify-path', '/nix/store/portal-b']])
        self.native_calls.clear()
        self.assertEqual(self.check()['release']['release_id'], 'portal-b')
        self.assertEqual(self.check()['release']['release_id'], 'portal-b')
        self.assertFalse(any(call[0] in ('nix', 'nix-store') or 'self-check' in call for call in self.native_calls))

    def test_environment_change_receipt_loss_and_corruption_block_cheap_status(self):
        first = self.activate()
        receipt = self.runtime / first['artifact_qualifications']['solver']
        original = receipt.read_bytes()
        for failure in ('environment', 'loss', 'corrupt', 'identity', 'duplicate'):
            with self.subTest(failure=failure):
                self.environment = {**ENV, 'kernel_release': 'changed'} if failure == 'environment' else dict(ENV)
                receipt.write_bytes(original)
                if failure == 'loss': receipt.unlink()
                if failure == 'corrupt': receipt.write_text('{}')
                if failure == 'duplicate': receipt.write_text('{"schema":"bad",' + original.decode().lstrip()[1:])
                if failure == 'identity':
                    value = json.loads(original); value['key']['node_identity']['machine_id'] = '9' * 32
                    receipt.write_text(json.dumps(value))
                self.native_calls.clear()
                with self.assertRaises((ValueError, FileNotFoundError)):
                    self.check()
                self.assertFalse(any('self-check' in call or call[0] == 'nix-store' for call in self.native_calls))
        receipt.write_bytes(original)
        self.environment = dict(ENV)
        self.check()

    def test_modern_job_guard_refuses_missing_proof_without_running_native_commands(self):
        first = self.activate()
        self.gate.write_text(json.dumps({'open': True, 'release_id': self.value['release_id']}))
        with patch.object(self.ops, 'observe_qualification_environment', lambda **_: dict(self.environment)):
            self.ops.guard(self.value['release_id'], self.value['solver_executable'],
                           self.runtime / 'release.json', self.gate)
            generation = self.ops._process_generation
            with patch.object(self.ops, '_process_generation', lambda: (*generation()[:2], 'cccccccc-cccc-cccc-cccc-cccccccccccc')):
                with self.assertRaisesRegex(ValueError, 'boot generation'):
                    self.ops.guard(self.value['release_id'], self.value['solver_executable'],
                                   self.runtime / 'release.json', self.gate)
            self.assertEqual((self.runtime / first['artifact_qualifications']['solver']).stat().st_mode & 0o777, 0o644)
            (self.runtime / first['artifact_qualifications']['solver']).unlink()
            self.native_calls.clear()
            with self.assertRaises((ValueError, FileNotFoundError)):
                self.ops.guard(self.value['release_id'], self.value['solver_executable'],
                               self.runtime / 'release.json', self.gate)
        self.assertFalse(self.native_calls)

    def test_local_health_cannot_adopt_enrollment_from_unprotected_release_record(self):
        self.activate()
        protected_read = self.ops.read_protected_file
        def deny_record(path, *args, **kwargs):
            if Path(path) == self.runtime / 'release.json':
                raise ValueError('Unprotected release record')
            return protected_read(path, *args, **kwargs)
        with patch.object(self.ops, 'read_protected_file', deny_record), \
             patch.object(self.ops, 'observe_qualification_environment', lambda **_: dict(self.environment)):
            with self.assertRaisesRegex(ValueError, 'Unprotected release record'):
                self.ops.check(self.value, profile=self.profile, runtime=self.runtime, run=self.native)

    def test_current_service_failure_never_triggers_expensive_requalification(self):
        self.activate()
        self.native_calls.clear()
        self.commands.failure = 'slurmd.service'
        with self.assertRaisesRegex(RuntimeError, 'injected'):
            self.check()
        self.assertFalse(any(call[0] in ('nix', 'nix-store') or 'self-check' in call for call in self.native_calls))

    def test_new_boot_needs_fresh_activation_health_but_reuses_solver_qualification(self):
        first = self.activate()
        next_boot = {**WORKER, 'boot_id': 'cccccccc-cccc-cccc-cccc-cccccccccccc'}
        generation = self.ops._process_generation
        with patch.object(self.ops, 'observe_node_identity', lambda **_: next_boot), \
             patch.object(self.ops, '_process_generation', lambda: (*generation()[:2], next_boot['boot_id'])), \
             patch.object(self.ops, 'observe_qualification_environment', lambda **_: dict(self.environment)):
            with self.assertRaisesRegex(ValueError, 'boot generation'):
                self.ops.check(self.value, profile=self.profile, runtime=self.runtime, run=self.native,
                    expected_node_identity=next_boot, enrollment_id=ENROLL_IDS[1])
            self.native_calls.clear()
            after = self.ops.activate(self.value, profile=self.profile, runtime=self.runtime, gate=self.gate,
                run=self.native, expected_node_identity=next_boot, enrollment_id=ENROLL_IDS[1],
                deadline=time.monotonic() + 30)
        self.assertEqual(after['artifact_qualifications'], first['artifact_qualifications'])
        self.assertEqual(after['node_identity']['boot_id'], next_boot['boot_id'])
        self.assertFalse(any('self-check' in call or call[0] == 'nix-store' for call in self.native_calls))

    def test_failed_new_application_integrity_never_executes_or_starts_it(self):
        self.activate()
        self.value = {**self.value, 'release_id': 'portal-b', 'application_path': '/nix/store/portal-b',
                      'closures': [{'path': '/nix/store/portal-b', 'narHash': OTHER_HASH},
                                   {'path': '/nix/store/solver', 'narHash': HASH}]}
        self.native_calls.clear()
        self.commands.failure = '--verify-path'
        with self.assertRaisesRegex(RuntimeError, 'injected'):
            self.activate()
        self.assertFalse(any(call[0] in ('nix-env', 'runuser') or
            call[:2] in (['systemctl', 'start'], ['systemctl', 'restart']) for call in self.native_calls))
        record = self.runtime / 'release.json'
        self.assertTrue(not record.exists() or json.loads(record.read_bytes()).get('ready') is not True)

    def test_integrity_audit_failure_invalidates_previous_ready_proof(self):
        first = self.activate()
        self.commands.failure = '--verify-path'
        with patch.object(self.ops, 'observe_qualification_environment', lambda **_: dict(self.environment)):
            with self.assertRaisesRegex(RuntimeError, 'injected'):
                self.api('qualify')(self.value, profile=self.profile, runtime=self.runtime,
                    role='worker', run=self.native, expected_node_identity=WORKER,
                    enrollment_id=ENROLL_IDS[1], deadline=time.monotonic() + 30, integrity_audit=True)
        self.commands.failure = None
        with self.assertRaises((ValueError, FileNotFoundError)):
            self.check()

    def test_modern_activation_without_enrollment_never_publishes_ready(self):
        self.gate.write_text(json.dumps({'open': False, 'release_id': self.value['release_id']}))
        with self.assertRaisesRegex(ValueError, 'enrollment'):
            self.ops.activate(self.value, profile=self.profile, runtime=self.runtime, gate=self.gate,
                run=self.native, expected_node_identity=WORKER, deadline=time.monotonic() + 30)
        self.assertFalse((self.runtime / 'release.json').exists())
        self.assertFalse(self.native_calls)

    def test_wrong_node_never_creates_qualification_receipts(self):
        self.api('observe_qualification_environment')
        with patch.object(self.ops, 'observe_node_identity', lambda **_: {**WORKER, 'machine_id': '9' * 32}):
            with self.assertRaisesRegex(ValueError, 'identity'):
                self.activate()
        self.assertEqual(list(self.runtime.glob('qualifications/*.json')), [])
        self.assertEqual(self.native_calls, [])

    def test_restore_invalidation_rotates_epoch_without_claiming_ready(self):
        self.activate()
        result = self.api('invalidate_qualification')(runtime=self.runtime, reason='restore',
                                                       deadline=time.monotonic() + 30)
        self.assertEqual(result['reason'], 'restore')
        self.assertNotEqual(result['restore_epoch'], ENV['restore_epoch'])
        value = json.loads((self.runtime / 'release.json').read_bytes())
        self.assertIs(value['ready'], False)
        self.environment['restore_epoch'] = result['restore_epoch']
        self.native_calls.clear()
        renewed = self.activate()
        self.assertNotEqual(renewed['artifact_qualifications'], value['artifact_qualifications'])
        self.assertTrue(any('self-check' in call for call in self.native_calls))
