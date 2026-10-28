"""Modern enrolled startup consumes real P11 receipts, with closed native I/O."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / 'ops'))
import application_release as release
import worker_lifecycle as worker
from test_node_enrollment import CONTROLLER, WORKER, ENROLL_IDS, TRUST, registry
from test_worker_shutdown_intent import authorized_event
from worker_startup_fixtures import ControllerFixture, WorkerFixture, StartupTransport, modern_manifest


class StartupQualificationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='p22-startup-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.runtime = self.root / 'controller'
        self.value = modern_manifest()
        self.controller = ControllerFixture(release, self.runtime, self.value)
        self.gate = self.runtime / 'gate'
        self.gate.write_text(json.dumps({'open': True, 'release_id': self.value['release_id']}))
        self.guest = WorkerFixture(self.root / 'guest', self.value)
        self.run = StartupTransport(self.guest)
        context = self.controller.patches()
        context.__enter__(); self.addCleanup(context.__exit__, None, None, None)
        for name, callback in [
            ('load_enrollment', lambda _: {'registry': registry(), 'registry_sha256': 'e' * 64,
                                         'known_hosts_bytes': b'synthetic'}),
            ('observe_node_identity', lambda **_: dict(CONTROLLER)),
            ('freeze_ssh_trust', lambda *a, **_: TRUST),
        ]:
            p = patch.object(release, name, callback)
            p.start(); self.addCleanup(p.stop)
        p = patch.object(worker, '_authorized_startup_event', authorized_event)
        p.start(); self.addCleanup(p.stop)

    def startup(self):
        return worker.startup('worker', 'admin@worker.invalid', enrollment='/protected/enrollment.json',
                              runtime=self.runtime, gate=self.gate, run=self.run)

    def no_resume(self):
        self.assertFalse(any('State=RESUME' in call for call in self.run.calls))

    def changed_metadata(self):
        value = copy.deepcopy(self.value)
        value['sources']['revision'] = 'f' * 40
        value['solver_build']['source_graph_sha256'] = hashlib.sha256(
            release.sorted_ascii_json(value['sources'])).hexdigest()
        return value

    def test_full_metadata_and_current_enrollment_reach_activation_and_both_check_sites(self):
        self.assertEqual(self.startup()['phase'], 'resumed')
        self.assertEqual(self.startup()['phase'], 'resumed')
        self.assertEqual([a[0] for a in self.run.actions], ['activate', 'check', 'check'])
        for action, envelope, enrollment, node in self.run.actions:
            self.assertEqual(envelope, self.value)
            self.assertEqual(enrollment, ENROLL_IDS[1])
            self.assertEqual(node, WORKER)
        self.assertEqual(sum('State=RESUME' in c for c in self.run.calls), 1)

    def test_cr04_marker_keeps_existing_compact_owner_identity(self):
        original = worker._exclusive_attempt_json
        identities = []
        def publish(path, value, **kwargs):
            if value.get('schema') == 'qcl-negf-admission-intent-v1':
                identities.append(value['identity'])
            return original(path, value, **kwargs)
        with patch.object(worker, '_exclusive_attempt_json', publish):
            self.startup()
        self.assertEqual(identities, [release.manifest(self.value)])

    def test_missing_modern_metadata_rejects_before_lifecycle_mutation(self):
        path = self.runtime / 'release.json'
        path.write_text(json.dumps({**release.manifest(self.value), 'ready': True}))
        before = self.gate.read_bytes()
        with self.assertRaisesRegex(ValueError, 'modern release metadata'):
            self.startup()
        self.no_resume()
        self.assertFalse(any(c[0] in ('nix', 'scontrol') for c in self.run.calls))
        self.assertFalse((self.runtime / 'shutdown').exists())
        self.assertEqual(self.gate.read_bytes(), before)

    def test_new_boot_reuses_solver_proof_and_idempotent_check_is_cheap(self):
        first = self.guest.action('activate', self.value, WORKER, ENROLL_IDS[1])
        proof = self.guest.runtime / first['artifact_qualifications']['solver']
        before = proof.read_bytes()
        self.guest.identity['boot_id'] = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
        self.guest.calls.clear()
        self.startup()
        self.startup()
        self.assertEqual(proof.read_bytes(), before)
        self.assertFalse(any(c[0] in ('nix', 'nix-store') or 'self-check' in c for c in self.guest.calls))
        current = json.loads((self.guest.runtime / 'release.json').read_bytes())
        self.assertEqual(current['activation_health']['boot_id'], self.guest.identity['boot_id'])

    def test_idempotent_check_refuses_lost_proof_without_requalification_or_resume(self):
        self.startup()
        current = json.loads((self.guest.runtime / 'release.json').read_bytes())
        (self.guest.runtime / current['artifact_qualifications']['solver']).unlink()
        self.guest.calls.clear(); self.run.calls.clear(); self.run.actions.clear()
        with self.assertRaises(FileNotFoundError):
            self.startup()
        self.no_resume()
        self.assertEqual([a[0] for a in self.run.actions], ['check'])
        self.assertFalse(any(c[0] in ('nix', 'nix-store') or 'self-check' in c for c in self.guest.calls))

    def test_idempotent_check_uses_current_authoritative_enrollment(self):
        self.startup()
        self.run.enrollment_override = ENROLL_IDS[2]
        self.run.calls.clear(); self.guest.calls.clear()
        with self.assertRaisesRegex(ValueError, 'enrollment differs'):
            self.startup()
        self.no_resume()
        self.assertFalse(any(c[0] in ('nix', 'nix-store') or 'self-check' in c for c in self.guest.calls))

    def test_same_four_fields_with_metadata_drift_before_resume_is_rejected(self):
        changed = self.changed_metadata()
        def drift(argv):
            if argv[0] == 'ssh' and ' check ' in argv[-1]:
                self.controller.seed(self.runtime, changed)
        self.run.on_call = drift
        with self.assertRaisesRegex(ValueError, 'Release changed'):
            self.startup()
        self.no_resume()
        intent = json.loads((self.runtime / 'shutdown/worker.json').read_bytes())
        self.assertTrue(intent['requires_reconciliation'])

    def test_metadata_drift_between_snapshot_and_common_owner_precedes_drain(self):
        original = worker._startup_release
        count = 0
        def read(runtime):
            nonlocal count
            value = original(runtime)
            count += 1
            if count == 1:
                self.controller.seed(self.runtime, self.changed_metadata())
            return value
        with patch.object(worker, '_startup_release', read), self.assertRaisesRegex(ValueError, 'Release changed'):
            self.startup()
        self.no_resume()
        self.assertFalse(any(c[0] in ('nix', 'scontrol') for c in self.run.calls))
        self.assertFalse((self.runtime / 'shutdown').exists())

    def test_idempotent_return_detects_same_identity_metadata_drift(self):
        self.startup()
        intent = self.runtime / 'shutdown/worker.json'
        before = intent.read_bytes()
        self.run.calls.clear(); self.run.actions.clear()
        def drift(argv):
            if argv[0] == 'ssh' and ' check ' in argv[-1]:
                self.controller.seed(self.runtime, self.changed_metadata())
        self.run.on_call = drift
        with self.assertRaisesRegex(ValueError, 'Release changed'):
            self.startup()
        self.no_resume()
        self.assertEqual(intent.read_bytes(), before)
        self.assertEqual([a[0] for a in self.run.actions], ['check'])

    def test_corrupt_receipt_environment_and_service_failure_do_not_requalify_check(self):
        self.startup()
        current = json.loads((self.guest.runtime / 'release.json').read_bytes())
        path = self.guest.runtime / current['artifact_qualifications']['solver']
        proof = path.read_bytes()
        original_environment = dict(self.guest.environment)
        for fault in ('corrupt', 'kernel', 'modules', 'restore', 'service'):
            with self.subTest(fault=fault):
                path.write_bytes(proof)
                self.guest.environment = dict(original_environment)
                self.guest.failure = None
                if fault == 'corrupt': path.write_text('{}')
                if fault == 'kernel': self.guest.environment['kernel_release'] = 'changed'
                if fault == 'modules': self.guest.environment['modules_path'] = '/nix/store/other-modules'
                if fault == 'restore': self.guest.environment['restore_epoch'] = '55555555-5555-5555-5555-555555555555'
                if fault == 'service': self.guest.failure = 'slurmd.service'
                self.guest.calls.clear(); self.run.calls.clear(); self.run.actions.clear()
                with self.assertRaises((ValueError, RuntimeError)):
                    self.startup()
                self.no_resume()
                self.assertEqual([a[0] for a in self.run.actions], ['check'])
                self.assertFalse(any(c[0] in ('nix', 'nix-store') or 'self-check' in c for c in self.guest.calls))
        self.assertEqual(path.read_bytes(), proof)

    def test_changed_boot_or_machine_cannot_use_resumed_intent(self):
        self.startup()
        original = dict(self.guest.identity)
        for field, value in [('boot_id', 'dddddddd-dddd-dddd-dddd-dddddddddddd'),
                             ('machine_id', '9' * 32)]:
            with self.subTest(field=field):
                self.guest.identity = {**original, field: value}
                self.run.calls.clear(); self.run.actions.clear()
                with self.assertRaises(ValueError): self.startup()
                self.no_resume()
                self.assertEqual(self.run.actions, [])

    def test_duplicate_and_oversized_controller_metadata_fail_before_mutation(self):
        path = self.runtime / 'release.json'
        original = path.read_bytes()
        for raw in (b'{"schema":"bad",' + original.lstrip()[1:], b' ' * 65537):
            with self.subTest(size=len(raw)):
                path.write_bytes(raw)
                self.run.calls.clear()
                with self.assertRaises(ValueError): self.startup()
                self.no_resume()
                self.assertFalse(any(c[0] in ('nix', 'scontrol') for c in self.run.calls))
        path.write_bytes(original)

    def test_unprotected_source_is_rejected_by_real_reader(self):
        # Leave the actual /tmp ownership/mode intact and do not inject trust.
        from release_trust import read_protected_file
        with patch.object(release, 'read_protected_file', read_protected_file), \
             self.assertRaisesRegex(ValueError, 'Unprotected namespace'):
            self.startup()
        self.no_resume()
        self.assertFalse(any(c[0] in ('nix', 'scontrol') for c in self.run.calls))

    def test_legacy_remote_ready_response_cannot_authorize_resume(self):
        self.run.response = lambda result: {**result, 'release': {
            **release.manifest(result['release']), 'ready': True}}
        with self.assertRaisesRegex(ValueError, 'verification'):
            self.startup()
        self.no_resume()


if __name__ == '__main__':
    unittest.main()
