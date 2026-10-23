"""Independent literal P1 controls; source-only authoring, no native authority claims."""
import copy
from collections.abc import Mapping
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from contextlib import contextmanager

SPEC = importlib.util.spec_from_file_location(
    'scientific_resource_admission', Path(__file__).parents[1] / 'ops/scientific_resource_admission.py')
capacity = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = capacity
SPEC.loader.exec_module(capacity)

BINDING = {
    'campaign_id': 'campaign', 'slot_id': 'slot', 'plan_digest': 'a' * 64,
    'criteria_digest': 'b' * 64, 'source_graph_digest': 'c' * 64,
    'release_id': 'release', 'runtime_id': 'runtime', 'execution_id': 'execution',
    'attempt_id': 'attempt', 'point_id': 'point', 'admission_id': 'admission',
    'job_id': '42', 'step_id': 'batch', 'owner_uid': 3000, 'pid': 1234,
    'start_ticks': 991, 'host_id': 'host', 'machine_id': 'a' * 32,
    'boot_id': '9ee23feb-d94c-4888-b83a-7c14e2921611',
    'mount_namespace': 11, 'cgroup_namespace': 12, 'vm_id': 710,
    'hypervisor_id': 'hypervisor', 'resource_epoch': 'resource-epoch', 'storage_epoch': 'epoch',
}


def observation(value, units):
    return {'status': 'observed', 'reason': None, 'value': value, 'units': units,
            'subject': 'attempt', 'scope': 'attempt', 'path': '/evidence/public',
            'tool': 'fixture-only-independent-oracle', 'version': '1',
            'capture_begin_ns': 900, 'capture_end_ns': 950, 'coverage': 'complete',
            'identity': copy.deepcopy(BINDING), 'evidence': ('raw-sha256-and-path',)}


def sample():
    # These are facts authenticated by a fixture-only injected boundary, never a native signer.
    cpu = {'scheduler_ids': [0, 1], 'affinity_ids': [0, 1], 'owned_ids': [0, 1],
           'protected_ids': [], 'pool_ids': [0, 1], 'hierarchy_coverage': 'complete',
           'ancestors': [{'path': '/', 'inode': 1, 'epoch': 'resource-epoch', 'cpu_ids': [0, 1], 'quota': 'max'},
                         {'path': '/job', 'inode': 2, 'epoch': 'resource-epoch', 'cpu_ids': [0, 1], 'quota': [2, 1]}]}
    ram = {'baseline_id': 'baseline', 'inventory_complete': True, 'phase_burst_bounded': True,
           'obligations': [{'owner': 'foreign', 'scope': 'host', 'id': 'protected',
                            'baseline_id': 'baseline', 'units': 'bytes', 'unmaterialized_upper': 0}],
           'total_authorities': [{'scope': 'slurm', 'id': 'slurm-allocation', 'bytes': 1073741824},
                                 {'scope': 'vm', 'id': 'VM-allocation', 'bytes': 1073741824},
                                 {'scope': 'host', 'id': 'host-after-obligations', 'bytes': 1073741824}],
           'remaining_headroom': 536870912,
           'ancestors': [{'path': '/', 'inode': 1, 'epoch': 'resource-epoch', 'max': 'max', 'high': 'max',
                          'current': 0, 'peak': 0, 'events': {'oom': 0}, 'swap': 0},
                         {'path': '/job', 'inode': 2, 'epoch': 'resource-epoch', 'max': 1073741824,
                          'high': 1073741824, 'current': 100, 'peak': 100, 'events': {'oom': 0}, 'swap': 0}]}
    views = {'logical_bytes': {'E': 96636764160, 'U': 4294967296, 'P': 0, 'S': 3221225472,
                               'A': 112742891520, 'H': 42949672960},
             'physical_bytes': {'E': 90, 'U': 4, 'P': 0, 'S': 3, 'A': 105, 'H': 40},
             'inodes': {'E': 90, 'U': 4, 'P': 0, 'S': 3, 'A': 105, 'H': 40}}
    storage = {'baseline_id': 'baseline', 'operation_id': 'operation', 'operation_digest': 'd' * 64,
               'state': 'pre_descriptor', 'roots': [{'role': 'scratch', 'domain': 'domain',
                'backing_id': 'filesystem', 'mount_namespace': 11, 'mount_id': 7,
                'directory_identity': [1, 2], 'owner_scope': 'attempt', 'uid': 3000,
                'gid': 3000, 'project': 42, 'inode_domain': 'inode-domain',
                'canonical_descriptor_bound': True, 'containment_enforced': True,
                'protected_or_foreign': False, 'filesystem': 'ext4'}],
               'scopes': [{'domain': 'domain', 'scope': kind, 'scope_id': kind,
                           'epoch': 'epoch', 'baseline_id': 'baseline', 'views': copy.deepcopy(views)}
                          for kind in ('attempt', 'owner', 'filesystem', 'campaign')]}
    authority = {'binding': copy.deepcopy(BINDING), 'max_age_ns': 1000, 'stop_lag_ns': 10,
                 'estimator_digest': 'e' * 64,
                 'evidence': ('verified-boundary-reference',),
                 'C1': {'id': 'sole-C1', 'baseline_id': 'baseline', 'domains': ['domain'],
                        'atomic_all_scopes': True, 'reconcile_required_on_unknown': True},
                 'enforcer': {'id': 'independent-native-fixture', 'domains': ['domain'],
                              'physical_hard_bound': True, 'inode_hard_bound': True,
                              'all_roots_and_external_logs': True, 'evidence': ('enforcer-proof',)}}
    facts = capacity.ScienceCapacityFacts(copy.deepcopy(BINDING),
        {'authority': authority, 'cpu': observation(cpu, 'cpu_ids;quota_ticks'),
         'ram': observation(ram, 'bytes'),
         'storage': observation(storage, 'logical_bytes;physical_bytes;inodes')}, ('raw-reference',))
    request = {'binding': copy.deepcopy(BINDING), 'workers': 1, 'blas_threads': 1,
               'memory_costs': {'numerical': 100, 'runtime': 10, 'native': 10, 'allocator': 10,
                                'HDF5': 10, 'serialization': 10, 'audit': 10, 'stop': 10},
               'memory_mode': 'allocation', 'incremental_memory': 10, 'unmaterialized_stop': 10,
               'estimator_digest': 'e' * 64, 'baseline_id': 'baseline',
               'operation_id': 'operation', 'operation_digest': 'd' * 64, 'root_roles': ['scratch'],
               'storage_growth': {'domain': {'logical_bytes': 8589934592, 'physical_bytes': 8, 'inodes': 8}}}
    return facts, request


def authenticated_fixture(facts, *, expected, now_ns):
    """Test-only trust boundary. Returning caller facts is NOT a deployment verifier."""
    return facts


def admit(facts, request, verify=authenticated_fixture):
    return capacity.admit_scientific_capacity(facts, request, expected=BINDING,
                                             now_ns=1000, verify_authority=verify)


class ScientificCapacityTests(unittest.TestCase):
    def mutate(self, facts, callback):
        def mutable(item):
            if isinstance(item, Mapping):
                return {key: mutable(value) for key, value in item.items()}
            if isinstance(item, tuple):
                return [mutable(value) for value in item]
            return item
        value = mutable(facts.observations)
        callback(value)
        return capacity.ScienceCapacityFacts(BINDING, value, facts.evidence)

    def test_no_authority_and_caller_boolean_never_become_a_grant(self):
        facts, request = sample()
        for verifier in (None, lambda *args, **kwargs: True):
            result = admit(facts, request, verifier)
            self.assertIsInstance(result, capacity.ScienceCapacityRefusal)
            self.assertEqual(result.status, 'needs_admission')

    def test_literal_total_boundary_and_headroom_are_independent(self):
        facts, request = sample()
        result = admit(facts, request)
        self.assertIsInstance(result, capacity.ScienceCapacityDecision)
        self.assertEqual(result.storage_bounds[0]['logical_bytes'], (16106127360, 112742891520))
        bad = self.mutate(facts, lambda x: x['storage']['value']['scopes'][0]['views']['logical_bytes'].__setitem__('A', 112742891519))
        self.assertEqual(admit(bad, request).status, 'refused')
        exact = self.mutate(facts, lambda x: x['storage']['value']['scopes'][0]['views']['logical_bytes'].update(A=137438953472, H=16106127360))
        self.assertIsInstance(admit(exact, request), capacity.ScienceCapacityDecision)
        short = self.mutate(exact, lambda x: x['storage']['value']['scopes'][0]['views']['logical_bytes'].__setitem__('H', 16106127359))
        self.assertEqual(admit(short, request).status, 'refused')

    def test_net_headroom_addback_never_credits_materialized_bytes(self):
        facts, request = sample()
        def net(x):
            row = x['storage']['value']['scopes'][0]['views']['logical_bytes']
            row.pop('H'); row['net'] = {'Hnet': 11811160064, 'corrected': False,
                'reservations': [{'id': 'lease-U', 'amount': 4294967296, 'kind': 'U', 'scope_id': 'attempt',
                                  'epoch': 'epoch', 'baseline_id': 'baseline', 'materialized': False}]}
        facts = self.mutate(facts, net)
        self.assertIsInstance(admit(facts, request), capacity.ScienceCapacityDecision)
        bad = self.mutate(facts, lambda x: x['storage']['value']['scopes'][0]['views']['logical_bytes']['net']['reservations'][0].__setitem__('materialized', True))
        self.assertEqual(admit(bad, request).status, 'refused')

    def test_equal_cpu_counts_do_not_replace_intersection(self):
        facts, request = sample()
        bad = self.mutate(facts, lambda x: x['cpu']['value'].__setitem__('affinity_ids', [2, 3]))
        self.assertEqual(admit(bad, request).status, 'refused')
        available_pool = self.mutate(facts, lambda x: x['cpu']['value'].__setitem__('pool_ids', [1]))
        self.assertEqual(admit(available_pool, request).cpu_ids, (1,))
        for quota, workers in (([3, 2], 2), ([1, 2], 1)):
            bad = self.mutate(facts, lambda x: x['cpu']['value']['ancestors'][1].__setitem__('quota', quota))
            request['workers'] = workers
            self.assertEqual(admit(bad, request).status, 'refused')

    def test_physical_and_inode_one_short_are_separate_views(self):
        facts, request = sample()
        for name in ('physical_bytes', 'inodes'):
            bad = self.mutate(facts, lambda x: x['storage']['value']['scopes'][0]['views'][name].__setitem__('A', 104))
            self.assertEqual(admit(bad, request).status, 'refused')
            exact = self.mutate(facts, lambda x: x['storage']['value']['scopes'][0]['views'][name].update(A=128, H=15))
            self.assertIsInstance(admit(exact, request), capacity.ScienceCapacityDecision)
            short = self.mutate(exact, lambda x: x['storage']['value']['scopes'][0]['views'][name].__setitem__('H', 14))
            self.assertEqual(admit(short, request).status, 'refused')

    def test_refusal_produces_no_files_or_mutation_authority(self):
        facts, request = sample()
        events = []
        def forbidden(*args, **kwargs):
            events.append('filesystem_open')
            raise AssertionError('pure refusal attempted filesystem activity')
        with patch('builtins.open', forbidden), patch.object(capacity.os, 'open', forbidden), \
             patch.object(capacity, '_metadata_link', forbidden):
            result = admit(facts, request, None)
            self.assertEqual(result.status, 'needs_admission')
            self.assertFalse(hasattr(result, 'lease'))
        self.assertEqual(events, [])

    def test_missing_C1_and_enforcer_have_distinct_fail_closed_status(self):
        facts, request = sample()
        bad = self.mutate(facts, lambda x: x['authority'].pop('C1'))
        self.assertEqual(admit(bad, request).status, 'needs_admission')
        bad = self.mutate(facts, lambda x: x['authority'].pop('enforcer'))
        self.assertEqual(admit(bad, request).status, 'needs_guard')

    def test_missing_ancestor_identity_epoch_and_scalar_types_refuse(self):
        facts, request = sample()
        changes = [lambda x: x['cpu']['value']['ancestors'].pop(0),
                   lambda x: x['ram']['value']['ancestors'][1].pop('current'),
                   lambda x: x['storage']['value']['scopes'][0].__setitem__('epoch', 'changed'),
                   lambda x: x['ram'].__setitem__('capture_end_ns', 1001),
                   lambda x: x['cpu']['identity'].__setitem__('start_ticks', 992),
                   lambda x: x['cpu']['value']['ancestors'][1].__setitem__('inode', True)]
        for change in changes:
            with self.subTest(change=change):
                self.assertIsInstance(admit(self.mutate(facts, change), request), capacity.ScienceCapacityRefusal)
        for value in (True, -1, 18446744073709551616):
            request['memory_costs']['numerical'] = value
            self.assertIsInstance(admit(facts, request), capacity.ScienceCapacityRefusal)

    def test_phase_current_is_not_added_to_total_estimator_twice(self):
        facts, request = sample()
        facts = self.mutate(facts, lambda x: x['ram']['value'].__setitem__('remaining_headroom', 1073741824))
        request.update(memory_mode='phase', incremental_memory=1073741700, unmaterialized_stop=24)
        self.assertIsInstance(admit(facts, request), capacity.ScienceCapacityDecision)
        request['incremental_memory'] += 1
        self.assertEqual(admit(facts, request).status, 'refused')

    def test_unbounded_phase_burst_and_stop_expiry_remain_closed(self):
        facts, request = sample(); request['memory_mode'] = 'phase'
        bad = self.mutate(facts, lambda x: x['ram']['value'].__setitem__('phase_burst_bounded', False))
        self.assertEqual(admit(bad, request).status, 'needs_guard')
        result = capacity.admit_scientific_capacity(facts, request, expected=BINDING,
            now_ns=1900, verify_authority=authenticated_fixture)
        self.assertEqual(result.status, 'needs_admission')

    def test_reader_refuses_replay_and_wrong_PID_paths_before_capture(self):
        expected, paths = collector_input()
        for wrong in ('/tmp/replay/stat', '/proc/9999/stat'):
            bad = dict(paths, stat=wrong)
            with patch.object(capacity, '_open_metadata', side_effect=AssertionError('replay opened')):
                result = capacity.collect_job_capacity(expected, bad, COLLECT_BUDGET)
            self.assertIsInstance(result, capacity.ScienceCapacityRefusal)
            self.assertEqual(result.status, 'needs_admission')

    def test_reader_healthy_mock_capture_uses_existing_membership_validator(self):
        expected, paths = collector_input()
        with collector_IO() as _:
            result = capacity.collect_job_capacity(expected, paths, COLLECT_BUDGET)
        self.assertIsInstance(result, capacity.ScienceCapacityFacts)
        self.assertEqual(result.observations['job_membership']['processes'][0]['pid'], 1234)
        self.assertIsNone(result.observations['authority'])

    def test_reader_changed_PID_start_boot_or_cgroup_keeps_partial_refusal(self):
        expected, paths = collector_input()
        faults = ({'stat': [proc_stat(1234, 991), proc_stat(1234, 992)]},
                  {'stat': [proc_stat(9999, 991)]},
                  {'boot_id': [BINDING['boot_id'].encode(), b'00000000-0000-0000-0000-000000000000']},
                  {'cgroup': [b'0::/slurm/job_43/step_batch/task\n']})
        for fault in faults:
            with self.subTest(fault=fault), collector_IO(fault):
                result = capacity.collect_job_capacity(expected, paths, COLLECT_BUDGET)
            self.assertIsInstance(result, capacity.ScienceCapacityRefusal)
            self.assertTrue(result.evidence)

    def test_reader_slurm_binding_mismatch_is_closed_before_capture(self):
        expected, paths = collector_input()
        for key, value in (('job_id', '43'), ('owner_uid', 0), ('identity', {'machine_id': 'b' * 32, 'boot_id': BINDING['boot_id']})):
            bad = copy.deepcopy(expected); bad['slurm'][key] = value
            with patch.object(capacity, '_open_metadata', side_effect=AssertionError('unbound identity opened')):
                result = capacity.collect_job_capacity(bad, paths, COLLECT_BUDGET)
            self.assertIsInstance(result, capacity.ScienceCapacityRefusal)

    def test_two_distinct_domains_105_113_peak_never_gets_positive_decision(self):
        facts, request = sample()
        def two(x):
            storage = x['storage']['value']; extra_root = copy.deepcopy(storage['roots'][0])
            extra_root.update(role='retrieval', domain='domain2', backing_id='other-filesystem', inode_domain='other-inodes')
            storage['roots'].append(extra_root)
            for row in list(storage['scopes']):
                extra = copy.deepcopy(row); extra['domain'] = 'domain2'; storage['scopes'].append(extra)
            x['authority']['C1']['domains'].append('domain2'); x['authority']['enforcer']['domains'].append('domain2')
        facts = self.mutate(facts, two); request['root_roles'].append('retrieval')
        request['storage_growth']['domain2'] = {'logical_bytes': 8589934592, 'physical_bytes': 8, 'inodes': 8}
        # Independent literals: 90+4+8+8+3=113; each isolated domain incorrectly appears105.
        result = admit(facts, request)
        self.assertIsInstance(result, capacity.ScienceCapacityRefusal)
        self.assertEqual(result.reason, 'aggregate_capacity_proof_unavailable')
        for bound in (121332826112, 120259084288):  # 113GiB exact /112GiB one-short still lack aggregate proof.
            adjusted = self.mutate(facts, lambda x: [row['views']['logical_bytes'].update(A=bound, H=24696061952)
                for row in x['storage']['value']['scopes'] if row['scope'] == 'campaign'])
            self.assertIsInstance(admit(adjusted, request), capacity.ScienceCapacityRefusal)


COLLECT_BUDGET = {'max_bytes': 8192, 'max_entries': 16, 'max_seconds': 2}


def collector_input():
    expected = {'binding': copy.deepcopy(BINDING),
        'slurm': {'job_id': '42', 'owner_uid': 3000, 'cgroup_scope': '/slurm',
                  'slurmstepd_executable': '/nix/store/' + '0' * 32 + '-slurm/bin/slurmstepd',
                  'identity': {'machine_id': BINDING['machine_id'], 'boot_id': BINDING['boot_id']}},
        'slurm_listpids': {'rc': 0, 'rows': [{'pid': 1234, 'job_id': '42', 'step_id': 'batch'}]}}
    paths = {name: '/proc/1234/' + name for name in ('stat', 'status', 'cgroup', 'exe')}
    paths.update(machine_id='/etc/machine-id', boot_id='/proc/sys/kernel/random/boot_id',
                 mount_namespace='/proc/1234/ns/mnt', cgroup_namespace='/proc/1234/ns/cgroup')
    return expected, paths


def proc_stat(pid, ticks):
    return (str(pid) + ' (julia) S ' + '0 ' * 18 + str(ticks) + ' 0\n').encode()


@contextmanager
def collector_IO(faults=None):
    """Fixture seam is below production canonical-path validation; no product fake roots."""
    faults = faults or {}; expected, paths = collector_input()
    raw = {'stat': [proc_stat(1234, 991)], 'status': [b'Pid:\t1234\nUid:\t3000\t3000\t3000\t3000\n'],
           'cgroup': [b'0::/slurm/job_42/step_batch/task\n'],
           'machine_id': [BINDING['machine_id'].encode()], 'boot_id': [BINDING['boot_id'].encode()]}
    raw.update(faults); counts = {}
    with tempfile.TemporaryDirectory() as directory:
        files = {}
        for name, variants in raw.items():
            files[name] = []
            for index, body in enumerate(variants):
                path = Path(directory) / (name + str(index)); path.write_bytes(body); files[name].append(path)
        actual_open = os.open
        def open_capture(path):
            name = next(key for key in raw if str(path) == paths[key]); index = counts.get(name, 0); counts[name] = index + 1
            return actual_open(files[name][min(index, len(files[name]) - 1)], os.O_RDONLY)
        def namespace_capture(path, pid, kind):
            if pid != 1234 or str(path) != '/proc/1234/ns/' + kind:
                raise AssertionError('unbound namespace')
            return b'4:11' if kind == 'mnt' else b'4:12'
        with patch.object(capacity, '_open_metadata', open_capture), \
             patch.object(capacity, '_metadata_link', lambda path: b'/nix/store/fixture/bin/julia'), \
             patch.object(capacity, '_namespace_metadata', namespace_capture):
            yield counts


if __name__ == '__main__':
    unittest.main()
