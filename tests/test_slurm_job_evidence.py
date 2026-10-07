"""Sanitized job membership witnesses; no Slurm, processes or server actions."""
import copy
import importlib.util
import pathlib
import tempfile
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).parents[1]
STEPD = '/nix/store/' + '0' * 32 + '-slurm/bin/slurmstepd'
IDENTITY = {'machine_id': '1' * 32, 'boot_id': '11111111-1111-4111-8111-111111111111'}
JOB_ROOT = '/system.slice/slurmstepd.scope/job_7'
EXPECTED = {'identity': IDENTITY, 'job_id': '7', 'owner_uid': 3000,
            'slurmstepd_executable': STEPD, 'cgroup_scope': '/system.slice/slurmstepd.scope'}


def sample():
    rows = [{'pid': 101, 'job_id': '7', 'step_id': 'batch'},
            {'pid': 102, 'job_id': '7', 'step_id': 'batch'}]
    processes = [dict(pid=101, start_ticks=10, uids=[3000] * 4,
                      exe='/nix/store/' + '0' * 32 + '-bash/bin/bash',
                      cgroup=JOB_ROOT + '/step_batch/user/task_0', error=None),
                 dict(pid=102, start_ticks=11, uids=[0] * 4, exe=STEPD,
                      cgroup=JOB_ROOT + '/step_batch/slurm', error=None)]
    return {'identity_before': IDENTITY, 'identity_after': IDENTITY,
            'listpids': {'rc': 0, 'rows': rows}, 'processes': processes}


class JobEvidenceTests(unittest.TestCase):
    def setUp(self):
        path = ROOT / 'ops/slurm_job_evidence.py'
        self.assertTrue(path.is_file(), 'Owning classifier is missing; root Slurm supervisor cannot be observed')
        spec = importlib.util.spec_from_file_location('slurm_job_evidence', path)
        self.ops = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.ops)

    def test_owner_tasks_and_exact_root_stepd_are_both_in_whole_job_evidence(self):
        proof = self.ops.classify_before(sample(), EXPECTED)
        self.assertEqual(proof['status'], 'pass_live_job_membership')
        self.assertEqual(proof['job_cgroup'], JOB_ROOT)
        self.assertEqual([p['start_ticks'] for p in proof['processes']], [10, 11])

    def test_root_supervisor_without_any_owner_task_is_not_live_owner_proof(self):
        s = sample(); s['listpids']['rows'] = s['listpids']['rows'][1:]; s['processes'] = s['processes'][1:]
        with self.assertRaises(ValueError): self.ops.classify_before(s, EXPECTED)

    def test_unknown_root_foreign_uid_executable_job_or_step_is_rejected(self):
        mutations = [('uids', [0, 0, 3000, 0]), ('uids', [1] * 4),
                     ('exe', '/nix/store/' + '0' * 32 + '-other/bin/slurmstepd'),
                     ('cgroup', JOB_ROOT + '0/step_batch/slurm'),
                     ('cgroup', JOB_ROOT + '/step_other/slurm')]
        for key, value in mutations:
            with self.subTest(key=key, value=value):
                s = sample(); s['processes'][1][key] = value
                with self.assertRaises(ValueError): self.ops.classify_before(s, EXPECTED)

    def test_missing_ticks_partial_capture_and_changed_boot_are_not_membership(self):
        for kind in ('ticks', 'partial', 'boot'):
            with self.subTest(kind=kind):
                s = copy.deepcopy(sample())
                if kind == 'ticks': del s['processes'][0]['start_ticks']
                if kind == 'partial': s['processes'][0]['error'] = 'vanished'
                if kind == 'boot': s['identity_after'] = {**IDENTITY, 'boot_id': 'foreign'}
                with self.assertRaises(ValueError): self.ops.classify_before(s, EXPECTED)

    def test_stop_requires_terminal_owner_and_empty_whole_subtree(self):
        before = self.ops.classify_before(sample(), EXPECTED)
        current = {'identity_before': IDENTITY, 'identity_after': IDENTITY,
                   'processes': [{'pid': 101, 'absent': True}, {'pid': 102, 'absent': True}],
                   'job_cgroup': {'path': JOB_ROOT, 'absent': True, 'populated': None},
                   'scheduler': {'rc': 0, 'job_id': '7', 'owner_uid': 3000, 'state': 'CANCELLED'}}
        self.assertEqual(self.ops.verify_after(before, current, EXPECTED)['status'], 'pass_physical_job_stop')

        for key in ('owner', 'populated', 'same_pid', 'missing_pid'):
            c = copy.deepcopy(current)
            if key == 'owner': c['scheduler']['owner_uid'] = 1
            if key == 'populated': c['job_cgroup'].update(absent=False, populated=1)
            if key == 'same_pid': c['processes'][0] = {'pid': 101, 'absent': False, 'start_ticks': 10}
            if key == 'missing_pid': c['processes'].pop()
            with self.subTest(key=key), self.assertRaises(ValueError): self.ops.verify_after(before, c, EXPECTED)
        current['processes'][0] = {'pid': 101, 'absent': False, 'start_ticks': 999}
        self.assertEqual(self.ops.verify_after(before, current, EXPECTED)['status'], 'pass_physical_job_stop')

    def test_foreign_before_subtree_cannot_be_read_during_after_capture(self):
        before = self.ops.classify_before(sample(), EXPECTED)
        before['job_cgroup'] = '/../../etc'
        with tempfile.TemporaryDirectory() as directory:
            ledger = self.ops.Ledger(pathlib.Path(directory) / 'capture')
            with patch.object(self.ops, 'identity', return_value=IDENTITY), patch.object(self.ops, 'command', return_value=(0, 'JobId=7 UserId=qcl-negf(3000) JobState=CANCELLED')):
                with self.assertRaises(ValueError):
                    self.ops.capture_after(before, EXPECTED, '/not-executed/scontrol', ledger)
            self.assertEqual(list(ledger.path.iterdir()), [])

    def test_all_raw_pid_captures_survive_rejected_privileged_membership(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = self.ops.Ledger(pathlib.Path(directory) / 'capture')
            listing = 'PID JOBID STEPID LOCALID GLOBALID\n101 7 batch 0 0\n102 7 batch - -\n'
            def capture(pid, sink):
                sink.put(str(pid) + '.stat', b'original-stat')
                row = copy.deepcopy(next(p for p in sample()['processes'] if p['pid'] == pid))
                row['uids'] = [1] * 4
                return row
            with patch.object(self.ops, 'identity', return_value=IDENTITY), \
                 patch.object(self.ops, 'command', return_value=(0, listing)), \
                 patch.object(self.ops, 'capture_process', side_effect=capture):
                snapshot = self.ops.capture_before(EXPECTED, '/not-executed/scontrol', ledger)
            with self.assertRaises(ValueError): self.ops.classify_before(snapshot, EXPECTED)
            self.assertEqual((ledger.path / '101.stat').read_bytes(), b'original-stat')
            self.assertEqual((ledger.path / '102.stat').read_bytes(), b'original-stat')

    def test_readonly_command_timeout_retains_durable_partial_output(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = self.ops.Ledger(pathlib.Path(directory) / 'capture')
            argv = [sys.executable, '-c', 'import time;print("original-prefix",flush=True);time.sleep(1)']
            with self.assertRaises(TimeoutError): self.ops.command(argv, ledger, 'read', timeout=0.2)
            self.assertEqual((ledger.path / 'read.stdout').read_bytes(), b'original-prefix\n')
            self.assertEqual(__import__('json').loads((ledger.path / 'read.result.json').read_text())['rc'], 'not_measured_timeout')



if __name__ == '__main__': unittest.main()
