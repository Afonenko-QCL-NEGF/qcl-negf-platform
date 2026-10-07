"""One explicit post-maintenance Slurm RESUME; no jobs, release or policy changes.

A fresh, protected worker readonly receipt is supplied by the operator. It is
not inferred from an active controller or from a successful OS switch.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import time
from uuid import UUID

from slurm_job_evidence import Ledger, command, frozen, identity, need

REGISTRATION = ('NodeName', 'CPUTot', 'RealMemory', 'Version', 'BootTime', 'SlurmdStartTime')
STORE = re.compile(r'/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[^/]+/bin/[^/]+\Z')


def node_fields(raw):
    need(len(raw.splitlines()) == 1, 'One exact node record required')
    rows = re.findall(r'(?:^|\s)(\w+)=(.*?)(?=\s\w+=|$)', raw.strip())
    need(len(rows) == len({k for k, _ in rows}), 'Duplicate node field')
    return dict(rows)


def valid_identity(value):
    try:
        need(re.fullmatch(r'[0-9a-f]{32}', value['machine_id']), 'Machine required')
        UUID(value['boot_id'])
        need(re.fullmatch(r'/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[^/]+',
                          value['current_system']), 'Selected immutable OS required')
        need(value['booted_system'] == value['current_system'], 'Cold selected OS required')
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError('Incomplete current worker identity') from error


def resume_argv(expected, worker, node, queue, *, now):
    """Validate observations and return the sole permitted mutation argument vector."""
    try:
        need(expected['operator_GO'] is True, 'Explicit operator GO required')
        name = expected['node']
        need(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', name),
             'Exact known node required')
        need(re.fullmatch(r'[0-9a-f]{40}', expected['source_revision']), 'Source revision required')
        valid_identity(expected['worker_identity'])
        valid_identity(worker['identity_before']); valid_identity(worker['identity_after'])
        need(worker['schema'] == 'qcl-negf.slurm-maintenance-worker-readonly.v1'
             and worker['source_revision'] == expected['source_revision'], 'Matching worker source required')
        need(worker['identity_before'] == worker['identity_after'] == expected['worker_identity'],
             'Worker boot or selected OS changed')
        need(type(worker['observed_epoch']) in (int, float) and 0 <= now-worker['observed_epoch'] <= 60,
             'Fresh worker capture required')
        need(re.fullmatch(r'[0-9a-f]{64}', expected['worker_runtime_sha256'])
             and worker['runtime_sha256'] == expected['worker_runtime_sha256'], 'Worker release changed')
        need(worker['services_before'] == worker['services_after']
             and set(worker['services_before']) == {'slurmd', 'munged'}, 'Stable worker/auth services required')
        for service in worker['services_before'].values():
            need(service['LoadState'] == 'loaded' and service['ActiveState'] == 'active'
                 and int(service['MainPID']) > 0 and re.fullmatch(r'[0-9a-f]{32}', service['InvocationID']),
                 'Registered worker/auth service not active')
        registration = expected['registration']
        need(set(registration) == set(REGISTRATION) and registration['NodeName'] == name,
             'Exact registered tuple required')
        need(int(registration['CPUTot']) > 0 and int(registration['RealMemory']) > 0,
             'Positive configured resources required')
        need(re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', registration['Version']), 'Registered Slurm version required')
        for field in ('BootTime', 'SlurmdStartTime'):
            need(re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d', registration[field]),
                 'Actual registration timestamp required')
        need(worker['registration'] == registration
             and {k: node[k] for k in REGISTRATION} == registration, 'Registration changed or incomplete')
        need(not queue.strip() and node['CPUAlloc'] == '0' and node['AllocMem'] == '0',
             'Any queue entry or allocation blocks maintenance resume')
        reason = expected['down_reason']
        need(re.fullmatch(r'Not responding \[slurm@\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\]', reason),
             'Only retained not-responding maintenance reason is supported')
        need(node['State'] == 'DOWN' and node['Reason'] == reason,
             'Unknown failure or different node state requires manual diagnosis')
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError('Incomplete maintenance evidence') from error
    return ['update', 'NodeName=' + name, 'State=RESUME']


def registration_ready(expected, node, queue):
    """Only a bounded re-registration transient may wait; never another update."""
    try:
        need(not queue.strip() and node['CPUAlloc'] == '0' and node['AllocMem'] == '0',
             'Job or allocation appeared during registration')
        wanted = expected['registration']
        need(all(node[k] == wanted[k] for k in ('NodeName', 'CPUTot', 'RealMemory', 'Version')),
             'Registered node/resources/version changed')
        if node['State'] == 'IDLE+NOT_RESPONDING':
            need(all(node[k] in ('None', wanted[k]) for k in ('BootTime', 'SlurmdStartTime')),
                 'Different boot observed during registration')
            return False
        need(node['State'] == 'IDLE' and {k: node[k] for k in REGISTRATION} == wanted,
             'Final same-boot registration not established')
        return True
    except (KeyError, TypeError) as error:
        raise ValueError('Incomplete registration observation') from error


def selected_identity():
    return {**identity(), 'current_system': os.path.realpath('/run/current-system'),
            'booted_system': os.path.realpath('/run/booted-system')}


def snapshot(a, ledger, stem):
    raw = {}
    calls = {'node': [a.scontrol, '--oneliner', 'show', 'node', a.node],
             'queue': [a.squeue, '--all', '--noheader', '--format', '%i|%u|%T|%N'],
             'config': [a.scontrol, 'show', 'config'],
             'services': [a.systemctl, 'show', 'slurmctld.service', 'munged.service',
                          '-pId', '-pLoadState', '-pActiveState', '-pMainPID', '-pInvocationID']}
    first = selected_identity(); ledger.put(stem + '.identity-before.json', first)
    for key, argv in calls.items():
        rc, text = command(argv, ledger, stem + '.' + key)
        need(rc == 0, 'Metadata command failed; original raw retained')
        raw[key] = text
    last = selected_identity(); ledger.put(stem + '.identity-after.json', last)
    need(first == last, 'Controller changed during capture')
    return first, raw


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for key in ('expected', 'expected-sha256', 'worker', 'worker-sha256', 'scontrol',
                'squeue', 'systemctl', 'runtime-json', 'gate', 'lock', 'out'):
        p.add_argument('--' + key, required=True)
    a = p.parse_args()
    def timeout(_signum, _frame): raise TimeoutError('Whole maintenance attempt exceeded 20 seconds')
    signal.signal(signal.SIGALRM, timeout); signal.alarm(20)
    need(os.geteuid() == 0, 'Root operator required')
    ledger = Ledger(a.out)
    # Original supplied input bytes are durable before interpreting any approval.
    for key in ('expected', 'worker'):
        path = Path(getattr(a, key)); need(path.is_file() and not path.is_symlink()
            and path.stat().st_size <= 65536 and path.stat().st_uid == 0
            and not path.stat().st_mode & 0o022, 'Protected bounded Root input required')
        ledger.put(key + '.original.json', path.read_bytes())
    expected = frozen(a.expected, a.expected_sha256); worker = frozen(a.worker, a.worker_sha256)
    a.node = expected['node']
    need(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', a.node), 'Exact known node required')
    for exe in (a.scontrol, a.squeue, a.systemctl):
        need(STORE.fullmatch(exe) and Path(exe).is_file() and os.access(exe, os.X_OK),
             'Exact existing immutable executable required')
    from application_release import read_admission
    with os.fdopen(os.open(a.lock, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600), 'wb') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        runtime = Path(a.runtime_json).read_bytes(); gate = read_admission(Path(a.gate))
        ledger.put('runtime.original.json', runtime); ledger.put('gate.original.json', gate)
        controller, before = snapshot(a, ledger, 'before')
        valid_identity(expected['controller_identity'])
        need(controller == expected['controller_identity'], 'Controller identity changed')
        need(hashlib.sha256(runtime).hexdigest() == expected['controller_runtime_sha256']
             and hashlib.sha256(gate).hexdigest() == expected['gate_sha256'], 'Release/gate changed')
        need(json.loads(gate) == {'open': False, 'release_id': expected['release_id']},
             'Close admission before explicit maintenance resume')
        need(re.search(r'^ReturnToService\s*=\s*0\s*$', before['config'], re.MULTILINE),
             'ReturnToService policy must remain zero')
        service_records = before['services'].strip().split('\n\n')
        need({dict(line.split('=', 1) for line in r.splitlines()).get('Id')
              for r in service_records} == {'slurmctld.service', 'munged.service'},
             'Both owning controller/auth services required')
        for record in service_records:
            fields = dict(line.split('=', 1) for line in record.splitlines())
            need(fields['LoadState'] == 'loaded' and fields['ActiveState'] == 'active'
                 and int(fields['MainPID']) > 0, 'Controller/auth service unavailable')
        argv = resume_argv(expected, worker, node_fields(before['node']), before['queue'], now=time.time())
        rc, _ = command([a.scontrol, *argv], ledger, 'one-resume')
        need(rc == 0, 'Resume command failed or uncertain; never retry implicitly')
        # RESUME invalidates cached registration temporarily. Poll reads only,
        # within the original 20-second attempt; never repeat the update.
        end = time.monotonic() + 10
        index = 0
        while True:
            rc, raw_node = command([a.scontrol, '--oneliner', 'show', 'node', a.node],
                                   ledger, 'registration-' + str(index) + '-node', timeout=2)
            need(rc == 0, 'Registration read failed; never repeat RESUME')
            rc, raw_queue = command([a.squeue, '--all', '--noheader', '--format', '%i|%u|%T|%N'],
                                    ledger, 'registration-' + str(index) + '-queue', timeout=2)
            need(rc == 0, 'Queue read failed; never repeat RESUME')
            if registration_ready(expected, node_fields(raw_node), raw_queue):
                break
            need(time.monotonic() < end, 'Registration deadline exceeded; original raw retained')
            time.sleep(0.25); index += 1
        controller_after, after = snapshot(a, ledger, 'after')
        node = node_fields(after['node'])
        need(controller_after == controller and after['config'] == before['config']
             and after['services'] == before['services'], 'Controller/config changed')
        need(node['State'] == 'IDLE' and node['CPUAlloc'] == '0' and node['AllocMem'] == '0'
             and not after['queue'].strip()
             and {k: node[k] for k in REGISTRATION} == expected['registration'],
             'Node did not return idle with the same registration; raw retained')
        need(Path(a.runtime_json).read_bytes() == runtime and read_admission(Path(a.gate)) == gate,
             'Release/admission changed during resume')
        ledger.put('proof.json', {'schema': 'qcl-negf.slurm-maintenance-resume.v1',
                   'status': 'pass_explicit_registered_idle_node_resume_only',
                   'node': a.node, 'source_revision': expected['source_revision'],
                   'controller_identity': controller, 'worker_identity': worker['identity_after'],
                   'registration': expected['registration'], 'worker_proof_sha256': a.worker_sha256,
                   'expected_sha256': a.expected_sha256, 'resume_calls': 1,
                   'scientific_submissions': 0, 'release_gate_opened': False,
                   'ReturnToService_changed': False, 'observed_epoch': time.time()})


if __name__ == '__main__': main()
