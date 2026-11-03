"""Source/L: real local P11 subprocesses; no sudo, VM, scientific workload.

The consumer fixture below labels its protected role/credential/cgroup views as
synthetic. Child PID, PPID, birth, argv, execution and reap remain real.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import time

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ops'))
import application_release as engine
import native_attempt as native


def invoke(run, argv, callback):
    try:
        return run(argv, process_observer=callback)
    except TypeError as error:
        if 'process_observer' in str(error):
            pytest.fail('Original P11 owned child cannot reach its census consumer: observer port absent')
        raise


def bounded(argv, **kwargs):
    return engine.command(argv, timeout_seconds=2, cleanup_seconds=.3, **kwargs)


def thaw(value):
    from collections.abc import Mapping
    if isinstance(value, Mapping):
        return {key: thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [thaw(item) for item in value]
    return value


def stat_identity(pid):
    path = Path('/proc') / str(pid)
    fields = (path/'stat').read_text().rsplit(')', 1)[1].split()
    return dict(pid=pid, ppid=int(fields[1]), start_ticks=int(fields[19]),
        uids=list(map(int, next(line for line in (path/'status').read_text().splitlines()
            if line.startswith('Uid:')).split()[1:])),
        cgroup=(path/'cgroup').read_text().strip()[3:], executable=os.readlink(path/'exe'))


def test_real_child_birth_reaches_observer_before_probe_and_terminal_distinguishes_absence(tmp_path):
    """Without original child birth, a listpids row cannot be excluded safely."""
    release = tmp_path/'release'
    secret = 'private-argument-not-an-anchor'
    argv = [sys.executable, '-c',
        'import os,sys,time; from pathlib import Path; p=Path(sys.argv[1]); '
        'print(os.getpid(),flush=True); '
        'exec("while not p.exists(): time.sleep(.002)")', str(release), secret]
    events = []
    observed = []
    def callback(event):
        if event['phase'] == 'spawned':
            actual = stat_identity(event['child']['pid'])
            observed.append(actual)
            assert event['child']['ppid'] == os.getpid()
            assert thaw(event['child']) == actual
            assert thaw(event['command_owner']) == stat_identity(os.getpid())
            # The receiving consumer can inspect its original live child here.
            assert not release.exists()
            with pytest.raises(TypeError): event['phase'] = 'forged'
            with pytest.raises(TypeError): event['child']['pid'] = 1
            with pytest.raises(TypeError): event['child']['uids'][0] = 0
            release.touch()
        events.append(thaw(event))
    result = invoke(bounded, argv, callback)
    assert len(observed) == 1
    assert result.strip() == str(observed[0]['pid'])
    assert [event['phase'] for event in events] == ['spawned', 'terminal']
    assert events[0]['child'] == events[1]['child'] == observed[0]
    assert events[1]['current_child'] == {'status': 'absent'}
    assert secret not in json.dumps(events)
    assert events[0]['argv_sha256'] == hashlib.sha256(b'\0'.join(os.fsencode(x) for x in argv)+b'\0').hexdigest()
    assert events[0]['argv_sha256'] == events[1]['argv_sha256']


def test_spawned_callback_error_keeps_original_exception_and_reaps_real_child():
    original = RuntimeError('consumer observation failed')
    pids = []
    def callback(event):
        if event['phase'] == 'spawned':
            pids.append(event['child']['pid'])
            raise original
    with pytest.raises(RuntimeError) as caught:
        invoke(bounded, [sys.executable, '-c', 'import time; time.sleep(10)'], callback)
    assert caught.value is original
    assert pids and caught.value.command_record['cleanup_confirmed'] is True
    assert not Path('/proc', str(pids[0])).exists()
    with pytest.raises(ChildProcessError): os.waitpid(pids[0], os.WNOHANG)


def test_terminal_callback_failure_cannot_mask_original_nonzero():
    def callback(event):
        if event['phase'] == 'terminal': raise ValueError('terminal callback failed')
    with pytest.raises(engine.CommandFailure) as caught:
        invoke(bounded, [sys.executable, '-c', 'import sys,time; time.sleep(.05); sys.exit(7)'], callback)
    assert caught.value.record['failure'] == 'nonzero'
    assert caught.value.record['returncode'] == 7
    assert caught.value.record['cleanup_confirmed'] is True


def test_native_sources_run_reaches_same_real_command_owner(tmp_path):
    from test_native_attempt import limits
    ns = native.NativeSources({'slurm': {'config_file': '/synthetic/slurm.conf'}}, native.Operation(limits()))
    release = tmp_path/'release'
    events = []
    def callback(event):
        events.append(thaw(event))
        if event['phase'] == 'spawned': release.touch()
    result = invoke(ns.run, [sys.executable, '-c',
        'import os,time,sys; from pathlib import Path; p=Path(sys.argv[1]); '
        'exec("while not p.exists(): time.sleep(.002)"); print(os.getpid())', str(release)], callback)
    assert ns.budget.calls == 1
    assert result.strip() == str(events[0]['child']['pid'])
    assert events[0]['command_owner']['pid'] == os.getpid()
    assert events[-1]['current_child'] == {'status': 'absent'}


def consumer_fixture(tmp_path, monkeypatch, *, foreign=False):
    """Protected Source/role/credentials are synthetic; P11 child is real.

    The sole mapping of real /proc identities changes only credentials/cgroup
    for owner+child. PID, PPID, birth, executable and actual child argv are real.
    This fixture cannot authenticate a Native root/sudo or installed Source.
    """
    from test_host_resource_qualification_sources import fixture_role
    from test_host_resource_qualification_gate import gate_fixture
    m, view, _, selector, permit, creator, *_ = fixture_role(tmp_path, monkeypatch)
    _, _, _, _, _, gate_sources = gate_fixture()
    base = gate_sources.batch_membership(creator)
    core = {row['pid']+90000000: dict(row, pid=row['pid']+90000000, ppid=row['ppid']+90000000,
        executable=row['exe']) for row in base['processes']}
    own_pid, sudo_pid = os.getpid(), os.getppid()
    sudo_stat = Path('/proc', str(sudo_pid), 'stat').read_text().rsplit(')', 1)[1].split()
    guard_pid = int(sudo_stat[1])
    group = permit['cgroup_scope']+'/job_42/step_batch/user/task_0'
    own = stat_identity(own_pid); own.update(uids=[0]*4, cgroup=group)
    sudo = dict(pid=sudo_pid, ppid=guard_pid, start_ticks=min(own['start_ticks'], int(sudo_stat[19])),
        uids=[0]*4, cgroup=group, executable='/synthetic/protected/sudo')
    guard = dict(pid=guard_pid, ppid=1, start_ticks=1, uids=[3000]*4,
        cgroup=group, executable=permit['guard']['executable'])
    # No supplied PID/certificate enters the production command API.
    metadata = engine.process_metadata
    def labelled_metadata(budget, path):
        value, raw = metadata(budget, path)
        stat = raw['stat'].rsplit(')', 1)[1].split()
        if value['pid'] == own_pid or int(stat[1]) == own_pid:
            value = dict(value, uids=[0]*4, cgroup=group)
        return value, raw
    monkeypatch.setattr(engine, 'process_metadata', labelled_metadata)
    ns = native.NativeSources({**view.sources.policy, 'slurm': {'config_file': '/synthetic/slurm.conf'},
        'tools': {'scontrol': sys.executable}}, view.sources.budget)
    actual_process = ns.process
    extra = {**core, sudo_pid: sudo, guard_pid: guard}
    if foreign:
        extra[99999991] = dict(pid=99999991, ppid=1, start_ticks=1,
            uids=[0]*4, cgroup=group, executable='/nix/store/unowned-root', state='S')
    def process(pid):
        if pid in extra: return copy.deepcopy(extra[pid])
        return actual_process(pid)
    ns.process = process
    ns.host = view.sources.host
    ns.origin = lambda path: own['executable'] if path == sys.executable else path
    view.sources = ns
    permit['client_root']['executable'] = own['executable']
    permit['client_root']['argv_prefix'][0] = sys.executable
    guest = m.GuestGateSources(view, type('Local', (), {'config': {'role': 'guest',
        'sudo_executables': [sudo['executable']], 'client_uid': 3000}})())
    monkeypatch.setenv('SUDO_UID', '3000')
    monkeypatch.setattr(guest, 'root_ingress', lambda: dict(process=process(own_pid),
        argv=permit['client_root']['argv_prefix']+['qualification-gate', 'original-request'],
        source=dict(path=permit['client_root']['source_path'], sha256=permit['client_root']['source_sha256'])))
    monkeypatch.setattr(guest, 'command_line', lambda pid: ['sudo', '--', 'original-fixed-root'] if pid==sudo_pid else ['original'])
    # Existing canonical permit reader remains used (new bytes, not cached view).
    permit_path = view.root/'qualification'/permit['operation_id']/'permit.json'
    from test_host_resource_qualification_sources import raw
    permit_path.write_bytes(raw(permit))
    selector['permit_sha256'] = hashlib.sha256(raw(permit)).hexdigest()
    view.current_path.write_bytes(raw(selector))
    listed = list(core) + [own_pid, sudo_pid] + ([99999991] if foreign else [])
    # Fixed argument vector is real Python('listpids','42') in this private cwd.
    monkeypatch.chdir(tmp_path)
    (tmp_path/'listpids').write_text('import os,time\nprint("PID JOBID STEPID",flush=True)\n'
        + ''.join(f'print("{pid} 42 batch",flush=True)\n' for pid in listed)
        + 'print(str(os.getpid())+" 42 batch",flush=True)\ntime.sleep(.1)\n')
    return guest, creator, set(core), own_pid, sudo_pid


def test_actual_caller_child_census_projection_retains_raw_absent_child(tmp_path, monkeypatch):
    guest, creator, core, own, sudo = consumer_fixture(tmp_path, monkeypatch)
    try:
        result = guest.batch_membership(creator)
    except Exception as error:
        pytest.fail('Real P11 child/census join missing: '+type(error).__name__+': '+str(error))
    assert {row['pid'] for row in result['processes']} == core
    raw = guest.membership_observations[-1]
    assert {row['pid'] for row in raw['listpids']['rows']} > core|{own, sudo}
    events = raw['command_observations']
    child = events[0]['child']
    assert child['ppid'] == own
    assert events[-1]['current_child'] == {'status': 'absent'}
    assert any(row['pid']==child['pid'] and row['absent'] is True for row in raw['processes'])
    assert {row['pid'] for row in raw['exclusion_witness']['excluded']} == {own, sudo, child['pid']}
    assert {row['pid'] for row in raw['projection']['processes']} == core
    assert 'original-request' not in json.dumps(raw)


def test_unknown_privileged_row_still_denies_and_raw_is_complete(tmp_path, monkeypatch):
    guest, creator, core, own, sudo = consumer_fixture(tmp_path, monkeypatch, foreign=True)
    with pytest.raises(native.Hold, match='qualification_membership_owner_required'):
        guest.batch_membership(creator)
    raw = guest.membership_observations[-1]
    assert any(row['pid']==99999991 for row in raw['processes'])
    assert any(row['pid']==99999991 for row in raw['listpids']['rows'])


def test_terminal_callback_error_after_success_still_has_reaped_child():
    original = RuntimeError('terminal observation failed')
    pids = []
    def callback(event):
        if event['phase'] == 'spawned': pids.append(event['child']['pid'])
        if event['phase'] == 'terminal': raise original
    with pytest.raises(RuntimeError) as caught:
        invoke(bounded, [sys.executable, '-c', 'import time; time.sleep(.05)'], callback)
    assert caught.value is original
    assert caught.value.command_record['cleanup_confirmed'] is True
    assert pids and not Path('/proc', str(pids[0])).exists()


def test_original_spawned_callback_error_survives_second_terminal_error():
    original = RuntimeError('original callback failure')
    def callback(event):
        if event['phase'] == 'spawned': raise original
        raise SystemExit('secondary terminal callback failure')
    with pytest.raises(RuntimeError) as caught:
        invoke(bounded, [sys.executable, '-c', 'import time; time.sleep(10)'], callback)
    assert caught.value is original
    assert caught.value.command_record['cleanup_confirmed'] is True
    assert caught.value.command_record['observer_failure'] == 'SystemExit'


def test_no_observer_default_has_no_proc_anchor_reads(monkeypatch):
    def forbidden(*args): raise AssertionError('default command gained observer reads')
    monkeypatch.setattr(engine, '_command_anchor', forbidden)
    assert bounded([sys.executable, '-c', 'print("default")']) == 'default\n'


def test_observer_workspace_is_prepaid_before_native_child_effect(tmp_path):
    from test_native_attempt import limits
    cfg = limits(); cfg['metadata_bytes'] = 524288
    ns = native.NativeSources({'slurm': {'config_file': '/synthetic/slurm.conf'}}, native.Operation(cfg))
    effect = tmp_path/'must-not-exist'
    with pytest.raises(native.Hold, match='operation_bound'):
        ns.run([sys.executable, '-c', 'from pathlib import Path; import sys; Path(sys.argv[1]).touch()', str(effect)],
            process_observer=lambda event: None)
    assert not effect.exists()


def test_sudo_auth_uses_stable_birth_fields_despite_retained_volatile_raw(tmp_path, monkeypatch):
    guest, _, _, _, sudo = consumer_fixture(tmp_path, monkeypatch)
    original = guest.sources.process
    serial = 0
    def rich(pid):
        nonlocal serial
        value = original(pid); serial += 1
        return dict(value, observations={'counter': serial}, state='R' if serial%2 else 'S', comm='sudo')
    guest.sources.process = rich
    caller = guest.authenticated_caller()
    assert caller['pid'] == original(sudo)['ppid']
    assert caller['uids'] == [3000]*4


@pytest.mark.parametrize('fault', ['birth', 'ppid', 'uids', 'cgroup', 'executable', 'argv', 'source', 'sudo-birth', 'sudo-argv'])
def test_changed_exact_cohort_cannot_be_projected_after_real_census(tmp_path, monkeypatch, fault):
    from host_resource_operations import ResourceError
    guest, creator, _, own, sudo = consumer_fixture(tmp_path, monkeypatch)
    completed = False
    run, ingress, process, command_line = guest.sources.run, guest.root_ingress, guest.sources.process, guest.command_line
    def observed_run(argv, **kwargs):
        nonlocal completed
        result = run(argv, **kwargs); completed = True
        return result
    def changed_ingress():
        value = copy.deepcopy(ingress())
        if completed:
            if fault == 'birth': value['process']['start_ticks'] += 1
            if fault == 'ppid': value['process']['ppid'] += 100
            if fault == 'uids': value['process']['uids'] = [3000]*4
            if fault == 'cgroup': value['process']['cgroup'] += '/other'
            if fault == 'executable': value['process']['executable'] = '/nix/store/foreign-python'
            if fault == 'argv': value['argv'][-1] = 'foreign-request'
            if fault == 'source': value['source']['sha256'] = '9'*64
        return value
    def changed_process(pid):
        value = process(pid)
        if completed and fault == 'sudo-birth' and pid == sudo: value['start_ticks'] += 1
        return value
    def changed_argv(pid):
        value = command_line(pid)
        return value+['foreign'] if completed and fault == 'sudo-argv' and pid == sudo else value
    guest.sources.run, guest.root_ingress = observed_run, changed_ingress
    guest.sources.process, guest.command_line = changed_process, changed_argv
    with pytest.raises((native.Hold, ResourceError)):
        guest.batch_membership(creator)
    raw = guest.membership_observations[-1]
    assert len(raw['command_observations']) == 2
    assert raw['listpids']['rc'] == 0 and raw['listpids']['rows']
    assert not raw.get('projection')


@pytest.mark.parametrize('fault', ['reused-birth', 'unknown-presence', 'same-argv-unowned-root'])
def test_terminal_absence_never_authenticates_foreign_or_unobserved_current_pid(tmp_path, monkeypatch, fault):
    from host_resource_operations import ResourceError
    guest, creator, _, _, _ = consumer_fixture(tmp_path, monkeypatch, foreign=fault=='same-argv-unowned-root')
    original, stat = guest.sources.process, guest.sources.budget.stat
    def changed_process(pid):
        events = guest.membership_observations[-1]['command_observations']
        child = events[0]['child'] if events else None
        if child and fault == 'same-argv-unowned-root' and pid == 99999991:
            return dict(child, pid=pid, state='S', comm='scontrol')
        if child and pid == child['pid']:
            if fault == 'reused-birth':
                return dict(child, start_ticks=child['start_ticks']+1, state='S', comm='scontrol')
            if fault == 'unknown-presence': raise PermissionError('unmeasured child visibility')
        return original(pid)
    def changed_stat(path, **kwargs):
        events = guest.membership_observations[-1]['command_observations']
        if fault == 'unknown-presence' and events and str(path) == '/proc/'+str(events[0]['child']['pid']):
            raise PermissionError('unmeasured process directory')
        return stat(path, **kwargs)
    guest.sources.process, guest.sources.budget.stat = changed_process, changed_stat
    with pytest.raises((native.Hold, ResourceError)):
        guest.batch_membership(creator)
    raw = guest.membership_observations[-1]
    assert raw['listpids']['rows'] and len(raw['processes']) == len(raw['listpids']['rows'])
    child = raw['command_observations'][0]['child']
    actual = next(row for row in raw['processes'] if row['pid']==child['pid'])
    if fault == 'reused-birth': assert actual['start_ticks'] != child['start_ticks']
    if fault == 'unknown-presence': assert actual['absent'] is None and actual['presence_error']=='PermissionError'
    if fault == 'same-argv-unowned-root':
        assert any(row['pid']==99999991 for row in raw['projection']['processes'])


def test_native_default_preserves_original_budget_command_signature():
    from test_native_attempt import limits
    class OriginalBudget(native.Operation):
        def command(self, argv, *, env=None, run=engine.command, output_bytes=None):
            return super().command(argv, env=env, run=run, output_bytes=output_bytes)
    ns = native.NativeSources({'slurm': {'config_file': '/synthetic/slurm.conf'}}, OriginalBudget(limits()))
    assert ns.run([sys.executable, '-c', 'print("original-default")']) == 'original-default\n'


def test_observer_work_uses_original_timeout_failure_and_cleanup_reserve():
    def callback(event):
        if event['phase'] == 'spawned': time.sleep(.45)
    with pytest.raises(engine.CommandFailure) as caught:
        engine.command([sys.executable, '-c', 'import time; time.sleep(10)'],
            timeout_seconds=.6, cleanup_seconds=.2, process_observer=callback)
    assert caught.value.record['failure'] == 'timeout'
    assert caught.value.record['child_started'] is True
    assert caught.value.record['cleanup_confirmed'] is True
