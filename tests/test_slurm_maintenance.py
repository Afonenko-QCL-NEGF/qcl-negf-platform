"""Finite source-only maintenance guards; no daemon, scheduler or jobs."""
import copy
import importlib.util
from pathlib import Path
import unittest
import sys

ROOT = Path(__file__).parents[1]
IDENTITY = {'machine_id': '1' * 32, 'boot_id': '11111111-1111-4111-8111-111111111111',
            'current_system': '/nix/store/' + '0' * 32 + '-nixos-system-worker',
            'booted_system': '/nix/store/' + '0' * 32 + '-nixos-system-worker'}
TUPLE = {'NodeName': 'worker', 'CPUTot': '24', 'RealMemory': '34816', 'Version': '25.11.8',
         'BootTime': '2026-10-07T19:03:12', 'SlurmdStartTime': '2026-10-07T21:15:16'}
REASON = 'Not responding [slurm@2026-10-07T21:15:16]'


def witnesses():
    expected = {'operator_GO': True, 'node': 'worker', 'source_revision': 'a' * 40,
                'worker_identity': IDENTITY, 'worker_runtime_sha256': 'b' * 64,
                'registration': TUPLE, 'down_reason': REASON}
    service = {'LoadState': 'loaded', 'ActiveState': 'active', 'MainPID': '20', 'InvocationID': 'c' * 32}
    worker = {'schema': 'qcl-negf.slurm-maintenance-worker-readonly.v1', 'source_revision': 'a' * 40,
              'observed_epoch': 95, 'identity_before': copy.deepcopy(IDENTITY), 'identity_after': copy.deepcopy(IDENTITY),
              'runtime_sha256': 'b' * 64, 'registration': TUPLE,
              'services_before': {'slurmd': service, 'munged': service},
              'services_after': {'slurmd': service, 'munged': service}}
    node = {**TUPLE, 'State': 'DOWN', 'CPUAlloc': '0', 'AllocMem': '0', 'Reason': REASON}
    return expected, worker, node


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        path = ROOT / 'ops/slurm_maintenance.py'
        self.assertTrue(path.is_file(), 'Explicit post-maintenance resume guard is absent')
        self.addCleanup(lambda: sys.path.remove(str(ROOT / 'ops')))
        sys.path.insert(0, str(ROOT / 'ops'))
        spec = importlib.util.spec_from_file_location('slurm_maintenance', path)
        self.ops = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.ops)

    def test_registered_known_node_only_with_explicit_operator_GO(self):
        e, w, n = witnesses()
        self.assertEqual(self.ops.resume_argv(e, w, n, '', now=100),
                         ['update', 'NodeName=worker', 'State=RESUME'])
        e['operator_GO'] = False
        with self.assertRaises(ValueError): self.ops.resume_argv(e, w, n, '', now=100)

    def test_foreign_or_busy_queue_and_any_allocation_block_resume(self):
        for text in ['77|foreign|RUNNING|other\n', '78|owner|PENDING|(null)\n']:
            e, w, n = witnesses()
            with self.assertRaises(ValueError): self.ops.resume_argv(e, w, n, text, now=100)
        for key in ['CPUAlloc', 'AllocMem']:
            e, w, n = witnesses(); n[key] = '1'
            with self.assertRaises(ValueError): self.ops.resume_argv(e, w, n, '', now=100)

    def test_other_DOWN_reason_or_unregistered_tuple_block_resume(self):
        for key, value in [('Reason', 'Low RealMemory'), ('Version', ''), ('SlurmdStartTime', 'None'),
                           ('NodeName', 'other'), ('CPUTot', '2'), ('State', 'IDLE')]:
            e, w, n = witnesses(); n[key] = value
            with self.assertRaises(ValueError): self.ops.resume_argv(e, w, n, '', now=100)

    def test_incomplete_changed_or_stale_worker_identity_blocks_resume(self):
        for kind in ['partial', 'changed', 'stale', 'service', 'source']:
            e, w, n = copy.deepcopy(witnesses())
            if kind == 'partial': del w['identity_after']['boot_id']
            if kind == 'changed': w['identity_after']['machine_id'] = '2' * 32
            if kind == 'stale': w['observed_epoch'] = 39
            if kind == 'service': w['services_after']['slurmd']['MainPID'] = '0'
            if kind == 'source': w['source_revision'] = 'd' * 40
            with self.assertRaises(ValueError): self.ops.resume_argv(e, w, n, '', now=100)

    def test_resume_transient_is_not_ready_and_only_exact_registration_finishes(self):
        e, w, n = witnesses()
        transient = {**n, 'State': 'IDLE+NOT_RESPONDING', 'BootTime': 'None'}
        self.assertFalse(self.ops.registration_ready(e, transient, ''))
        final = {**n, 'State': 'IDLE'}
        self.assertTrue(self.ops.registration_ready(e, final, ''))
        for bad in [{**transient, 'CPUAlloc': '1'}, {**transient, 'State': 'IDLE+DRAIN'},
                    {**final, 'BootTime': '2026-10-08T00:00:00'}]:
            with self.assertRaises(ValueError): self.ops.registration_ready(e, bad, '')
        with self.assertRaises(ValueError): self.ops.registration_ready(e, transient, 'foreign-job')

    def test_raw_one_line_Reason_preserved_for_exact_comparison(self):
        text = 'NodeName=worker State=DOWN CPUAlloc=0 Reason=Not responding [slurm@2026-10-07T21:15:16]'
        self.assertEqual(self.ops.node_fields(text)['Reason'], REASON)
        with self.assertRaises(ValueError): self.ops.node_fields(text + ' State=IDLE')


if __name__ == '__main__': unittest.main()
