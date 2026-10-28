"""Closed startup fixtures: synthetic OS/trust facts, real P11 files and validators.

The controller receipt evidence is handwritten. Worker receipts are produced by
the actual P11 activation API against a closed Nix/systemd command boundary.
No directory below /tmp is represented as trusted by production source.
"""
import base64
from contextlib import contextmanager
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shlex
import time
from unittest.mock import patch

from test_node_enrollment import CONTROLLER, WORKER, ENROLL_IDS, manifest_fixture

ENVIRONMENT = {'kernel_release': '6.12-startup-fixture', 'kernel_path': '/nix/store/kernel/bzImage',
               'modules_path': '/nix/store/modules',
               'restore_epoch': '44444444-4444-4444-4444-444444444444'}


def modern_manifest():
    value = manifest_fixture()
    value['sources'] = {'format': 'qcl-negf.git-graph.v1', 'revision': 'a' * 40,
                        'components': [
                            {'path': 'components/QCLNEGF.jl', 'revision': 'b' * 40,
                             'url': 'https://github.com/QCL/Core'},
                            {'path': 'components/QCLNEGFRunner.jl', 'revision': 'c' * 40,
                             'url': 'https://github.com/QCL/Runner'}]}
    value['solver_build'] = {
        'source_graph_sha256': hashlib.sha256(json.dumps(value['sources'], sort_keys=True,
            separators=(',', ':'), ensure_ascii=True).encode()).hexdigest(),
        'julia_manifest_sha256': 'd' * 64, 'drv_path': '/nix/store/solver.drv',
        'output_path': '/nix/store/solver'}
    return value


class ControllerFixture:
    """Explicit synthetic controller environment and protected-file observations."""
    def __init__(self, ops, runtime, value=None):
        self.ops, self.roots = ops, []
        self.seed(runtime, value or manifest_fixture())

    def seed(self, runtime, value=None):
        runtime = Path(runtime)
        runtime.mkdir(parents=True, exist_ok=True)
        self.roots.append(runtime)
        value = self.ops.release_envelope(value or manifest_fixture())
        current = {**value, 'ready': True, 'node_identity': dict(CONTROLLER),
                   'activation_health': self.ops.activation_health(CONTROLLER,
                       'aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb'),
                   'qualification_enrollment_id': ENROLL_IDS[0], 'artifact_qualifications': {}}
        (runtime / 'qualifications').mkdir(exist_ok=True)
        hashes = {row['path']: row['narHash'] for row in value['closures']}
        for kind, path in [('application', value['application_path']),
                           ('solver', str(Path(value['solver_executable']).parents[1]))]:
            key = self.ops.qualification_key(CONTROLLER, {'kind': kind, 'path': path,
                'nar_hash': hashes[path],
                'drv_path': value.get('solver_build', {}).get('drv_path') if kind == 'solver' else None},
                ENVIRONMENT, enrollment_id=ENROLL_IDS[0])
            reference = 'qualifications/' + self.ops.qualification_digest(key) + '.json'
            current['artifact_qualifications'][kind] = reference
            receipt = self.ops.qualification_receipt(key, {'integrity': True,
                                                         'solver_self_check': kind == 'solver'})
            (runtime / reference).write_text(json.dumps(receipt))
        context = self.ops.quantum_context(value)
        if context is not None:
            current['quantum_runtime_context'] = context
        (runtime / 'release.json').write_text(json.dumps(current))
        return current

    @contextmanager
    def patches(self):
        original_read, generation = self.ops.read_protected_file, self.ops._process_generation
        def read(path, limit=65536, **kwargs):
            path = Path(path)
            if not any(path.is_relative_to(root) for root in self.roots):
                return original_read(path, limit, **kwargs)
            data = path.read_bytes()
            if len(data) > limit:
                raise ValueError('Synthetic protected metadata exceeds bound')
            return data
        with patch.object(self.ops, 'read_protected_file', read), \
             patch.object(self.ops, '_process_generation', lambda: (*generation()[:2], CONTROLLER['boot_id'])), \
             patch.object(self.ops, 'observe_qualification_environment', lambda **_: dict(ENVIRONMENT)):
            yield self


class WorkerFixture:
    """Real P11 local activation/check, explicit synthetic OS and native commands.

The local API uses its required closed guest gate; returning-worker CLI's open
shared-gate exception remains covered by its existing owning release tests.
"""
    def __init__(self, root, value):
        spec = importlib.util.spec_from_file_location('startup_worker_release',
            Path(__file__).parents[1] / 'ops/application_release.py')
        self.ops = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.ops)
        self.runtime, self.profile = Path(root) / 'runtime', Path(root) / 'profile'
        self.runtime.mkdir(parents=True)
        self.gate = Path(root) / 'gate'
        self.value = copy.deepcopy(value)
        self.identity, self.environment = dict(WORKER), dict(ENVIRONMENT)
        self.calls = []
        self.failure = None

    def native(self, argv):
        self.calls.append(list(argv))
        if self.failure and self.failure in argv:
            raise RuntimeError('Synthetic worker native failure: ' + self.failure)
        if argv[:3] == ['nix', 'path-info', '--json']:
            return json.dumps({row['path']: {'narHash': row['narHash']} for row in self.value['closures']})
        if argv[0] == 'nix-env':
            profile = Path(argv[argv.index('--profile') + 1])
            profile.unlink(missing_ok=True)
            profile.symlink_to(argv[-1])
            return ''
        if 'self-check' in argv:
            return json.dumps({'schema': 'qcl-negf-self-check-v1', 'status': 'completed',
                               'scientific_accepted': False})
        if argv[0] == 'nix-store' or argv[:2] in (['systemctl', 'is-active'],
                ['systemctl', 'start'], ['systemctl', 'restart']):
            return ''
        raise AssertionError('Unexpected non-fake worker command: ' + repr(argv))

    @contextmanager
    def patches(self):
        generation = self.ops._process_generation
        def read(path, limit=65536, **_):
            path = Path(path)
            if not path.is_relative_to(self.runtime):
                raise AssertionError('Unexpected synthetic worker protected path')
            raw = path.read_bytes()
            if len(raw) > limit:
                raise ValueError('Synthetic worker metadata bound')
            return raw
        with patch.object(self.ops, 'read_protected_file', read), \
             patch.object(self.ops, 'observe_node_identity', lambda **_: dict(self.identity)), \
             patch.object(self.ops, '_process_generation', lambda: (*generation()[:2], self.identity['boot_id'])), \
             patch.object(self.ops, 'observe_qualification_environment', lambda **_: dict(self.environment)), \
             patch.object(self.ops, 'installed_manifest_sha256', lambda _: self.value.get('solver_build', {}).get('julia_manifest_sha256')):
            yield

    def action(self, action, expected, node, enrollment):
        self.gate.write_text(json.dumps({'open': False, 'release_id': expected['release_id']}))
        with self.patches():
            if action == 'activate':
                return self.ops.activate(expected, profile=self.profile, runtime=self.runtime,
                    gate=self.gate, run=self.native, expected_node_identity=node,
                    enrollment_id=enrollment, deadline=time.monotonic() + 30)
            return self.ops.check(expected, profile=self.profile, runtime=self.runtime,
                run=self.native, expected_node_identity=node, enrollment_id=enrollment)


class StartupTransport:
    """Only source/API execution; SSH, Slurm and Nix copy never leave this object."""
    def __init__(self, worker):
        self.worker, self.calls, self.actions = worker, [], []
        self.on_call = None
        self.response = None
        self.enrollment_override = None
    def __call__(self, argv):
        self.calls.append(list(argv))
        if self.on_call:
            self.on_call(argv)
        if argv[0] == 'ssh':
            words = shlex.split(argv[-1])
            if words[-1] == 'identity':
                return json.dumps(CONTROLLER if 'controller' in argv[-2] else self.worker.identity)
            action = next((name for name in ('activate', 'check') if name in words), None)
            if action is None:
                raise AssertionError('Unexpected fake SSH action')
            expected = json.loads(base64.urlsafe_b64decode(words[words.index('--manifest-base64') + 1]))
            node = json.loads(base64.urlsafe_b64decode(words[words.index('--expected-node-identity-base64') + 1]))
            enrollment = words[words.index('--qualification-enrollment-id') + 1] if '--qualification-enrollment-id' in words else None
            self.actions.append((action, expected, enrollment, node))
            result = self.worker.action(action, expected, node, self.enrollment_override or enrollment)
            if action == 'check' and self.response:
                result = self.response(result)
            return json.dumps(result)
        if argv[0] == 'squeue' or argv[0] == 'scontrol' or argv[:2] == ['nix', 'copy']:
            return ''
        raise AssertionError('Unexpected non-fake controller command: ' + repr(argv))
