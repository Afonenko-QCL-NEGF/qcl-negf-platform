"""Source-authored delivery contract controls; no native solver is invoked."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import test_application_release as support
from test_application_release import Commands, delivery_manifest


LITERAL = '{"components":[{"path":"components/QCLNEGF.jl","revision":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","url":"https://github.com/Afonenko-QCL-NEGF/QCLNEGF.jl"}],"format":"qcl-negf.git-graph.v1","revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'


def quantum_manifest():
    value = delivery_manifest(cache=False)
    value['sources'] = json.loads(LITERAL)
    value['sources']['components'].append({
        'path': 'components/QCLNEGFRunner.jl', 'revision': 'c' * 40,
        'url': 'https://github.com/Afonenko-QCL-NEGF/QCLNEGFRunner.jl'})
    value['solver_build'] = {
        'source_graph_sha256': hashlib.sha256(json.dumps(value['sources'], sort_keys=True,
            separators=(',', ':'), ensure_ascii=True).encode()).hexdigest(),
        'julia_manifest_sha256': hashlib.sha256(b'manifest\n').hexdigest(),
        'drv_path': '/nix/store/solver.drv', 'output_path': '/nix/store/solver'}
    return value


class QuantumDeliveryTests(unittest.TestCase):
    setUpClass = support.ApplicationReleaseTests.__dict__['setUpClass']
    setUp = support.ApplicationReleaseTests.setUp
    def test_cross_language_literal_survives_sorted_publication(self):
        value = json.loads(LITERAL)
        self.assertEqual(self.ops.sorted_ascii_json(value), LITERAL.encode())
        self.assertEqual(self.ops.sorted_ascii_json(json.loads(json.dumps(value, indent=2))), LITERAL.encode())

    def test_full_envelope_projection_preserves_metadata_but_not_lifecycle_identity(self):
        value = quantum_manifest()
        self.assertEqual(self.ops.release_envelope(value), value)
        self.assertEqual(set(self.ops.manifest(value)),
            {'schema', 'release_id', 'application_path', 'solver_executable'})
        context = self.ops.quantum_context(value)
        self.assertEqual(len(context), 10)
        unsigned = {k: v for k, v in context.items() if k != 'context_sha256'}
        self.assertEqual(context['context_sha256'], hashlib.sha256(
            self.ops.sorted_ascii_json(unsigned)).hexdigest())
        self.assertIsNone(self.ops.quantum_context(delivery_manifest(False)))

    def test_reject_unbound_graph_output_and_unknown_metadata(self):
        for mutate in (
            lambda v: v['sources'].update(revision='bad'),
            lambda v: v['sources'].update(extra='ignored'),
            lambda v: v['sources']['components'][0].update(path='components/../escape'),
            lambda v: v['sources']['components'][0].update(url='https://github.com/é/x'),
            lambda v: v['sources']['components'].append(v['sources']['components'][0]),
            lambda v: v['sources']['components'].reverse(),
            lambda v: v['solver_build'].update(output_path='/nix/store/other'),
            lambda v: v['solver_build'].update(extra=True),
            lambda v: v['closures'][1].update(narHash='invalid'),
        ):
            value = quantum_manifest(); mutate(value)
            with self.assertRaises(ValueError): self.ops.release_envelope(value)

    def test_association_checks_available_deriver_and_installed_manifest(self):
        value = quantum_manifest()
        def run(argv):
            if argv[:3] == ['nix', 'path-info', '--json']:
                return json.dumps({item['path']: {'narHash': item['narHash'],
                    'deriver': value['solver_build']['drv_path'] if item['path'] == '/nix/store/solver' else None}
                    for item in value['closures']})
            if '--deriver' in argv: return value['solver_build']['drv_path'] + '\n'
            if '--outputs' in argv: return '/nix/store/solver\n'
            raise AssertionError(argv)
        with patch.object(self.ops, 'installed_manifest_sha256', return_value=value['solver_build']['julia_manifest_sha256']):
            self.ops.prefetch_controller_closures(value, run)
            def wrong(argv):
                data = json.loads(run(argv))
                data['/nix/store/solver']['deriver'] = '/nix/store/wrong.drv'
                return json.dumps(data)
            with self.assertRaises(ValueError): self.ops.prefetch_controller_closures(value, wrong)
            def substituted(argv):
                data = json.loads(run(argv))
                data['/nix/store/solver'].pop('deriver')
                return json.dumps(data)
            self.ops.prefetch_controller_closures(value, substituted)
        with patch.object(self.ops, 'installed_manifest_sha256', return_value='0' * 64):
            with self.assertRaises(ValueError): self.ops.prefetch_controller_closures(value, run)

    def test_same_identity_different_metadata_is_not_retry(self):
        value = quantum_manifest()
        other = copy.deepcopy(value)
        other['solver_build']['julia_manifest_sha256'] = 'd' * 64
        with self.assertRaises(ValueError): self.ops.require_same_metadata(value, other)

    def test_prepare_activate_ready_preserve_context_and_remote_json(self):
        value = quantum_manifest()
        with patch.object(self.ops, 'prefetch_controller_closures', return_value={}), \
             patch.object(self.ops, 'verify_solver_build', return_value=None):
            # The inherited fixture exercises real publication/profiles/lifecycle,
            # mocking only OS commands, as in existing activation controls.
            commands = Commands()
            profile = self.runtime.parent / 'profile'
            self.gate.write_text(json.dumps({'open': False, 'release_id': value['release_id']}))
            prepared = self.ops.prepare_initial(value, profile=profile, runtime=self.runtime,
                gate=self.gate, run=commands)
            self.assertFalse(prepared['ready'])
            self.assertEqual(prepared['quantum_runtime_context'], self.ops.quantum_context(value))
            before = (self.runtime / 'release.json').read_bytes()
            self.ops.prepare_initial(value, profile=profile, runtime=self.runtime,
                gate=self.gate, run=commands)
            self.assertEqual((self.runtime / 'release.json').read_bytes(), before)
            result = self.ops.activate(value, profile=profile, runtime=self.runtime,
                gate=self.gate, run=commands)
        record = json.loads((self.runtime / 'release.json').read_text())
        self.assertTrue(record['ready'])
        self.assertEqual(record['sources'], value['sources'])
        self.assertEqual(record['solver_build'], value['solver_build'])
        self.assertEqual(record['quantum_runtime_context'], self.ops.quantum_context(value))
        self.assertEqual(json.loads(base64.urlsafe_b64decode(base64.urlsafe_b64encode(
            json.dumps(self.ops.release_envelope(record)).encode()))), self.ops.release_envelope(value))
        self.assertIn('QCL_NEGF_QUANTUM_RUNTIME_CONTEXT_SHA256=' + record['quantum_runtime_context']['context_sha256'],
            (self.runtime / 'service.env').read_text())
        self.assertEqual(result, record)
        self.assertEqual(self.ops.node_check(self.runtime / 'release.json', self.gate,
            profile, run=commands), record)
        record['quantum_runtime_context']['context_sha256'] = '0' * 64
        (self.runtime / 'release.json').write_text(json.dumps(record))
        with self.assertRaises(ValueError):
            self.ops.node_check(self.runtime / 'release.json', self.gate, profile, run=commands)

    def test_record_readable_without_granting_service_write_access(self):
        self.runtime.mkdir()
        record = self.runtime / 'release.json'
        self.ops.publish_json(record, {'public': True})
        self.assertEqual(record.stat().st_mode & 0o777, 0o644)
        self.assertEqual(record.stat().st_uid, __import__('os').geteuid())
        rules = (Path(__file__).parents[1] / 'modules/release.nix').read_text()
        self.assertIn('d /var/lib/qcl-negf-admin 0755 root root -', rules)
        self.assertIn('d /var/lib/qcl-negf-admin/runtime 0755 root root -', rules)
