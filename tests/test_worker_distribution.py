"""Literal filesystem oracles only; no Nix, images, services or network.

The 128-byte QCOW2 fixture is a header test, never a boot/content measurement.
Removing a join, exact-file check or publication barrier must fail these controls.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

OPS = Path(__file__).parents[1] / 'ops'
sys.path.insert(0, str(OPS))
spec = importlib.util.spec_from_file_location('worker_distribution', OPS / 'worker_distribution.py')
wd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wd)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


class DistributionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = self.base / 'input'
        self.source.mkdir()
        self.out = self.base / 'bundle'
        self.files = {}
        self.image = b'QFI\xfb\x00\x00\x00\x03' + bytes(120)
        self.graph = {'format': 'qcl-negf.git-graph.v1', 'revision': '1'*40,
                      'components': [{'path': 'components/Platform', 'revision': '2'*40,
                                      'url': 'https://github.com/example/platform.git'}]}
        self.app = '/nix/store/' + '0'*32 + '-app'
        self.solver = '/nix/store/' + '1'*32 + '-solver'
        closures = [{'path': self.app, 'narHash': 'sha256-' + 'A'*43 + '='},
                    {'path': self.solver, 'narHash': 'sha256-' + 'B'*43 + '='}]
        release = {'schema': 'qcl-negf-release-v1', 'release_id': 'a'*64,
                   'sources': self.graph, 'application_path': self.app,
                   'solver_executable': self.solver + '/bin/qcl-negf', 'closures': closures}
        source_ref = self.put('records/source-graph.json', self.graph)
        release_ref = self.put('records/release.json', release)
        image_ref = self.put('images/worker-root.qcow2', self.image)
        row = {'image_path': '/nix/store/' + '2'*32 + '-image/nixos.qcow2',
               'image_sha256': image_ref['sha256'], 'image_bytes': 128}
        images_ref = self.put('records/images.json', {r: row for r in
                              ('storage', 'control', 'compute', 'ci', 'arch-worker')})
        locks = [self.put('records/locks/flake.lock', b'{"fixture":true}\n'),
                 self.put('records/locks/uv.lock', b'version = 1\n'),
                 self.put('records/locks/Manifest.toml', b'# literal Julia lock\n')]
        depot = {'format': 'qcl-negf.julia-depot.v1', 'julia': '1.13.0', 'sources': self.graph,
                 'juliaManifest': locks[2]['sha256'], 'url': 'https://example.invalid/depot.tar',
                 'hash': 'sha256-' + 'C'*43 + '='}
        depot_ref = self.put('records/depot.json', depot)
        identity = {'release_id': 'a'*64, 'source_graph_sha256': source_ref['sha256'],
                    'release_manifest_sha256': release_ref['sha256'], 'image_sha256': image_ref['sha256'],
                    'image_bytes': 128, 'derivation': '/nix/store/' + '3'*32 + '-image.drv',
                    'output': '/nix/store/' + '2'*32 + '-image', 'nar_hash': 'sha256-' + 'D'*43 + '=',
                    'closures': closures}
        contract = {'source_sha256': source_ref['sha256'], 'test_sha256': 'b'*64,
                    'factory_sha256': 'c'*64, 'profile': 'production-build', 'args': ['--fixture'],
                    'julia': '1.13.0', 'blas': 'fixture-blas',
                    'phases': ['instantiate', 'import'], 'imports': ['QCLNEGF']}
        build = {'schema': 'qcl-negf-worker-build-projection-v1', 'original_receipt_sha256': 'd'*64,
                 'identity': identity, 'depot_sha256': depot_ref['sha256'],
                 'lock_artifacts': locks, 'julia_manifest_sha256': locks[2]['sha256'],
                 'native_contract': contract}
        build_ref = self.put('records/image-build.json', build)
        content = {'schema': 'qcl-negf-worker-content-projection-v1', 'original_receipt_sha256': 'e'*64,
                   'identity': identity, 'format': 'qcow2', 'boot_mode': 'legacy-bios',
                   'partition_table': 'legacy', 'root_filesystem': 'ext4', 'root_bus': 'virtio',
                   'external_backing': False, 'external_data_file': False, 'secret_bytes': False,
                   'machine_id': False, 'ssh_host_keys': False, 'enrollment': False,
                   'runtime_ready': False, 'runtime_closures_present': True,
                   'observations': ['literal fixture only; not a native observation']}
        content_ref = self.put('records/image-content.json', content)
        kit_names = ['docs/linux-workers.md', 'ansible/arch-libvirt.yml', 'ansible/requirements.yml',
                     'tofu/arch-libvirt/main.tf', 'tofu/arch-libvirt/variables.tf',
                     'tofu/arch-libvirt/versions.tf', 'tofu/arch-libvirt/outputs.tf',
                     'tofu/arch-libvirt/site-base.json.example', 'examples/private-site/flake.nix.template',
                     'ops/worker_distribution.py', 'ops/application_release.py', 'ops/image_stage.py']
        kit = [self.put('recipes/platform/' + name, b'# independent tiny fixture\n') for name in kit_names]
        self.put('recipes/platform/source-kit.json', {'schema': 'qcl-negf-worker-source-kit-v1',
                 'platform_revision': 'f'*40, 'files': kit,
                 'original_receipt_sha256': '8'*64, 'public_tracked_only': True, 'secrets_absent': True})
        self.put('README.md', b'Private engineering fixture. Delivery route blocked.\n')
        self.m = {'schema': 'qcl-negf-worker-distribution-v1', 'purpose': 'private_engineering_candidate',
                  'profile': 'site_bound_private', 'architecture': 'x86_64-linux', 'role': 'worker',
                  'backend': 'arch-libvirt', 'release_id': 'a'*64, 'source_graph': source_ref,
                  'release_manifest': release_ref, 'image_manifest': images_ref,
                  'image': {'file': image_ref, 'producer_role': 'arch-worker', 'format': 'qcow2',
                            'boot_mode': 'legacy-bios', 'hyperv_generation': None,
                            'partition_table': 'legacy', 'root_filesystem': 'ext4', 'root_bus': 'virtio',
                            'derivation': identity['derivation'], 'output': identity['output'],
                            'nar_hash': identity['nar_hash'], 'build_evidence': build_ref,
                            'content_evidence': content_ref},
                  'runtime_evidence': {'lock_artifacts': locks, 'depot': depot_ref,
                                       'native_reuse': None, 'native_status': 'not_measured'},
                  'installation_kit': {'platform_revision': 'f'*40, 'files': kit,
                       'guide': kit[0]['path'], 'template': kit[8]['path'], 'recipe': kit[3]['path']},
                  'controller': {'release_schema': 'qcl-negf-release-v1', 'release_id': 'a'*64,
                       'enrollment': 'existing protected enrollment v1; provisioned separately',
                       'first_boot': 'DRAIN/no-submit before trust+release+health'},
                  'host_requirements': {'host_adapter': 'Arch Linux x86_64; measured versions required',
                       'virtualization': 'KVM', 'network': 'existing LAN bridge; no NAT',
                       'libvirt_provider': 'dmacvicar/libvirt=0.9.9', 'opentofu': '>=1.10,<2.0',
                       'scratch': 'separate stable-identity disk; actual capacity/reserve required'},
                  'acceptance': {'image_first_boot': {'status': 'not_measured', 'receipt': None},
                       'backend_install': {'status': 'not_measured', 'receipt': None},
                       'final_source': 'not_claimed', 'final_ci': 'not_claimed', 'full_release': 'not_claimed'}}
        self.refresh()

    def put(self, name, value):
        data = value if isinstance(value, bytes) else encoded(value)
        path = self.source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        ref = {'path': name, 'bytes': len(data), 'sha256': digest(data)}
        self.files[name] = ref
        return ref

    def refresh(self):
        self.m['files'] = sorted(self.files.values(), key=lambda x: x['path'])

    def assemble(self, **kw):
        return wd.assemble(self.source, self.m, self.out, disk_budget_bytes=70*1024**2,
                           timeout_seconds=30, **kw)

    def test_candidate_roundtrip_preserves_originals_and_missing_native(self):
        sha = self.assemble()
        result = wd.verify(self.out, sha)
        self.assertEqual(result['runtime_evidence']['native_status'], 'not_measured')
        self.assertEqual(result['acceptance']['full_release'], 'not_claimed')
        self.assertEqual((self.out / 'records/release.json').read_bytes(),
                         (self.source / 'records/release.json').read_bytes())
        self.assertNotEqual(result['installation_kit']['platform_revision'], self.graph['revision'])
        self.assertEqual((self.out / 'images/worker-root.qcow2').read_bytes(), self.image)

    def test_trusted_manifest_hash_and_extra_payload_are_required(self):
        sha = self.assemble()
        with self.assertRaises(ValueError):
            wd.verify(self.out, '0'*64)
        (self.out / 'extra').write_text('unlisted')
        with self.assertRaises(ValueError):
            wd.verify(self.out, sha)

    def test_rehashed_wrong_source_nar_role_and_content_are_refused(self):
        cases = [('records/release.json', lambda v: v['sources'].update(revision='9'*40)),
                 ('records/image-build.json', lambda v: v['identity'].update(nar_hash='sha256-'+'Z'*43+'=')),
                 ('records/images.json', lambda v: v.pop('ci')),
                 ('records/image-content.json', lambda v: v.update(external_backing=True)),
                 ('records/image-content.json', lambda v: v.update(secret_bytes=True)),
                 ('records/depot.json', lambda v: v.update(juliaManifest='0'*64))]
        for name, change in cases:
            with self.subTest(name=name):
                original = (self.source / name).read_bytes()
                ref = self.files[name]
                value = json.loads(original)
                change(value)
                new = self.put(name, value)
                ref.update(new)
                self.files[name] = ref
                self.refresh()
                with self.assertRaises(ValueError):
                    self.assemble()
                self.assertFalse(self.out.exists())
                restored = self.put(name, original)
                ref.update(restored)
                self.files[name] = ref
                self.refresh()

    def test_native_label_without_receipt_and_final_release_claim_refused(self):
        for change in (lambda m: m['runtime_evidence'].update(native_status='verified_for_exact_contract'),
                       lambda m: m['acceptance'].update(final_ci='pass'),
                       lambda m: m['acceptance']['backend_install'].update(status='measured')):
            m = copy.deepcopy(self.m)
            change(m)
            with self.assertRaises(ValueError):
                wd.assemble(self.source, m, self.out, disk_budget_bytes=70*1024**2, timeout_seconds=30)
            self.assertFalse(self.out.exists())

    def test_paths_links_and_duplicate_refs_refused_before_copy(self):
        m = copy.deepcopy(self.m)
        m['files'][0]['path'] = '../escape'
        with self.assertRaises(ValueError):
            wd.assemble(self.source, m, self.out, disk_budget_bytes=70*1024**2, timeout_seconds=30)
        m = copy.deepcopy(self.m)
        m['files'].append(m['files'][0])
        with self.assertRaises(ValueError):
            wd.assemble(self.source, m, self.out, disk_budget_bytes=70*1024**2, timeout_seconds=30)
        path = self.source / 'README.md'
        path.unlink()
        path.symlink_to('/etc/passwd')
        with self.assertRaises(ValueError):
            self.assemble()
        path.unlink()
        path.write_bytes(b'Private engineering fixture. Delivery route blocked.\n')
        os.link(path, self.base / 'hardlink')
        with self.assertRaises(ValueError):
            self.assemble()
        self.assertFalse(self.out.exists())

    def test_short_budget_existing_output_and_interrupted_copy(self):
        with self.assertRaises(ValueError):
            wd.assemble(self.source, self.m, self.out, disk_budget_bytes=1, timeout_seconds=30)
        self.assertFalse(self.out.exists())
        self.out.mkdir()
        with self.assertRaises(FileExistsError):
            self.assemble()
        self.out.rmdir()
        with mock.patch.object(wd, 'copy_file', side_effect=OSError('injected interrupted copy')):
            with self.assertRaises(OSError):
                self.assemble()
        self.assertFalse((self.out / 'worker-distribution.json').exists())
        self.assertTrue((self.out / '.incomplete').is_file())

    def test_strict_json_refuses_duplicate_nonfinite_and_unknown_keys(self):
        for data in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}'):
            with self.assertRaises(ValueError):
                wd.decode_json(data)
        self.m['unexpected'] = True
        with self.assertRaises(ValueError):
            self.assemble()

    def add_native(self, mutate=None):
        build = json.loads((self.source / 'records/image-build.json').read_bytes())
        contract = build['native_contract']
        native = {'schema': 'qcl-negf-worker-native-projection-v1',
                  'original_receipt_sha256': '6'*64, 'identity': build['identity'],
                  'native_contract': copy.deepcopy(contract), 'observations': ['fixture only'],
                  'measurements': {kind: [{'name': name, 'status': 'passed', 'receipt_sha256': '7'*64}
                                          for name in contract[kind]] for kind in ('phases', 'imports')}}
        if mutate:
            mutate(native)
        item = self.put('records/native-reuse.json', native)
        self.m['runtime_evidence'].update(native_reuse=item, native_status='verified_for_exact_contract')
        self.refresh()

    def test_exact_native_contract_with_original_phase_receipts(self):
        self.add_native()
        sha = self.assemble()
        result = wd.verify(self.out, sha)
        self.assertEqual(result['runtime_evidence']['native_status'], 'verified_for_exact_contract')
        self.assertEqual(result['acceptance']['image_first_boot']['status'], 'not_measured')

    def test_coherent_build_and_native_julia_must_match_depot(self):
        name = 'records/image-build.json'
        build = json.loads((self.source / name).read_bytes())
        build['native_contract']['julia'] = '1.12.0'
        item = self.files[name]
        item.update(self.put(name, build))
        self.files[name] = item
        # add_native reads the rebound build, so both contracts are 1.12.0;
        # depot and original runtime still require 1.13.0. All file hashes agree.
        self.add_native()
        with self.assertRaisesRegex(ValueError, 'Native Julia contract differs from depot'):
            self.assemble()
        self.assertFalse(self.out.exists())

    def test_native_reuse_refuses_changed_factory_profile_args_or_missing_import(self):
        changes = [lambda n: n['native_contract'].update(factory_sha256='0'*64),
                   lambda n: n['native_contract'].update(profile='local-debug'),
                   lambda n: n['native_contract'].update(args=['--different']),
                   lambda n: n['measurements'].update(imports=[]),
                   lambda n: n['measurements']['phases'][0].update(status='not_measured')]
        for change in changes:
            with self.subTest(change=change):
                self.add_native(change)
                with self.assertRaises(ValueError):
                    self.assemble()
                self.assertFalse(self.out.exists())

    def test_raw_image_tamper_is_refused(self):
        bad = b'NOTQCOW2' + self.image[8:]
        (self.source / 'images/worker-root.qcow2').write_bytes(bad)
        with self.assertRaises(ValueError):
            self.assemble()
        self.assertFalse((self.out / 'worker-distribution.json').exists())

    def test_coherently_rehashed_bad_header_reaches_header_barrier(self):
        name = 'images/worker-root.qcow2'
        image_ref = self.files[name]
        image_ref.update(self.put(name, b'NOTQCOW2' + self.image[8:]))
        self.files[name] = image_ref
        images_name = 'records/images.json'
        images = json.loads((self.source / images_name).read_bytes())
        images['arch-worker']['image_sha256'] = image_ref['sha256']
        images_ref = self.files[images_name]
        images_ref.update(self.put(images_name, images))
        self.files[images_name] = images_ref
        for name in ('records/image-build.json', 'records/image-content.json'):
            value = json.loads((self.source / name).read_bytes())
            value['identity']['image_sha256'] = image_ref['sha256']
            item = self.files[name]
            item.update(self.put(name, value))
            self.files[name] = item
        self.refresh()
        # Byte counts, source/release/depot/closure identities and every SHA join
        # remain coherent. Removing the header validators must break this oracle.
        with self.assertRaisesRegex(ValueError, 'Expected a QCOW2 version'):
            self.assemble()
        self.assertFalse((self.out / 'worker-distribution.json').exists())

    def test_disk_free_and_publication_failures_do_not_complete(self):
        usage = type('Usage', (), {'free': 1})()
        with mock.patch.object(wd.shutil, 'disk_usage', return_value=usage):
            with self.assertRaises(ValueError):
                self.assemble()
        self.assertFalse(self.out.exists())
        with mock.patch.object(wd.os, 'replace', side_effect=OSError('publish failed')):
            with self.assertRaises(OSError):
                self.assemble()
        self.assertFalse((self.out / 'worker-distribution.json').exists())
        self.assertTrue((self.out / '.incomplete').exists())

    def test_fsync_failure_leaves_no_completed_manifest(self):
        with mock.patch.object(wd.os, 'fsync', side_effect=OSError('fsync failed')):
            with self.assertRaises(OSError):
                self.assemble()
        self.assertFalse((self.out / 'worker-distribution.json').exists())
        self.assertTrue((self.out / '.incomplete').exists())

    def test_directory_fsync_after_manifest_publication_retains_partial(self):
        original_sync = wd.sync_directory
        original_failure = OSError('directory fsync after publication failed')
        reached_publication = []

        def fail_once_after_publication(path):
            if (Path(path) == self.out
                    and (self.out / 'worker-distribution.json').exists()
                    and not reached_publication):
                reached_publication.append(True)
                raise original_failure
            return original_sync(path)

        with mock.patch.object(wd, 'sync_directory', side_effect=fail_once_after_publication):
            with self.assertRaises(OSError) as raised:
                self.assemble()
        self.assertIs(raised.exception, original_failure)
        self.assertEqual(reached_publication, [True])
        self.assertFalse((self.out / 'worker-distribution.json').exists())
        self.assertTrue((self.out / '.incomplete').is_file())
        self.assertTrue((self.out / '.manifest.partial').is_file())
        self.assertEqual((self.out / 'images/worker-root.qcow2').read_bytes(), self.image)
        self.assertEqual((self.out / 'records/release.json').read_bytes(),
                         (self.source / 'records/release.json').read_bytes())

    def test_recipe_tamper_and_missing_content_receipt_fail_closed(self):
        path = self.source / 'recipes/platform/tofu/arch-libvirt/main.tf'
        path.write_bytes(b'tampered recipe')
        with self.assertRaises(ValueError):
            self.assemble()
        self.assertFalse(self.out.exists())
        path.write_bytes(b'# independent tiny fixture\n')
        (self.source / 'records/image-content.json').unlink()
        with self.assertRaises(ValueError):
            self.assemble()
        self.assertFalse(self.out.exists())

    def test_timeout_refuses_before_output_and_bad_toolkit_export_is_not_trusted(self):
        with mock.patch.object(wd.time, 'monotonic', side_effect=[0, 31]):
            with self.assertRaises(TimeoutError):
                self.assemble()
        self.assertFalse(self.out.exists())
        name = 'recipes/platform/source-kit.json'
        item = self.files[name]
        value = json.loads((self.source / name).read_bytes())
        value['public_tracked_only'] = False
        item.update(self.put(name, value))
        self.files[name] = item
        self.refresh()
        with self.assertRaises(ValueError):
            self.assemble()
        self.assertFalse(self.out.exists())


if __name__ == '__main__':
    unittest.main()
