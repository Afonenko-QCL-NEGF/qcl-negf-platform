"""Source/L: real bounded files and adapters; synthetic protected OS/RPC seams.

No test authenticates a QGA installation, invokes sudo or mutates a live owner.
"""
import copy
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ops'))
from test_host_resource_qualification_gate import fixture, OP, CALC, SECOND, BOOT
from test_native_attempt import limits


def sources():
    assert importlib.util.find_spec('host_resource_qualification_sources') is not None, 'actual role readers/CAS Source is absent'
    import host_resource_qualification_sources as module
    return module


def raw(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def fixture_role(tmp_path, monkeypatch, *, role='worker'):
    import native_attempt as native
    m = sources()
    root = tmp_path / 'private'
    root.mkdir(mode=0o700)
    monkeypatch.setattr(m, 'PRIVATE_ROOT', root)
    # Explicit unprivileged namespace seam; real nofollow/inode/mode/links/read
    # and actual AttemptStore flock/fsync/rename remain exercised below.
    @contextmanager
    def directory(path, *, budget=None):
        path = Path(path)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            yield fd
        finally:
            os.close(fd)
    monkeypatch.setattr(native, 'protected_directory', directory)
    monkeypatch.setattr(native, 'trusted_stat', lambda info, **kw: None)
    monkeypatch.setattr(m, '_protected_owner_uid', lambda: os.geteuid())
    permit, actor, creator, fields, intent = fixture()
    plan = {'original': 'plan'}
    fence = {'original': 'active-fence'}
    report = {'original': 'retained-report'}
    permit.update(parent_plan_sha256=hashlib.sha256(raw(plan)).hexdigest(),
        fence_sha256=hashlib.sha256(raw(fence)).hexdigest(),
        capacity_report_sha256=hashlib.sha256(raw(report)).hexdigest())
    selector = dict(schema='qcl.host-resource-calibration-role-view.v1', role=role,
        operation_id=OP, permit_sha256=hashlib.sha256(raw(permit)).hexdigest(),
        parent_plan_sha256=permit['parent_plan_sha256'], fence_sha256=permit['fence_sha256'],
        capacity_report_sha256=permit['capacity_report_sha256'], source_graph_sha256=permit['source_graph_sha256'],
        native_host=dict(host_id='host-a', host_boot_id=BOOT, policy_sha256='5'*64, baseline_state_sha256='6'*64),
        receiver=dict(native_id='77777777-7777-4777-8777-777777777777', machine_id='b'*32,
            boot_id=BOOT, native_policy_sha256='7'*64),
        reader_source=dict(path='/nix/store/synthetic-source/ops/host_resource_qualification_sources.py', sha256='8'*64))
    qualification = root / 'qualification'
    qualification.mkdir(mode=0o700)
    folder = qualification / OP
    folder.mkdir(mode=0o700)
    (folder / 'mirrors').mkdir(mode=0o700)
    for name, value in [('permit.json', permit), ('parent-plan.json', plan), ('parent-fence.json', fence),
            ('capacity-report.json', report)]:
        path = folder / name
        path.write_bytes(raw(value)); path.chmod(0o600)
    current = qualification / 'current.json'
    current.write_bytes(raw(selector)); current.chmod(0o600)
    budget = native.Operation(limits())
    ns = SimpleNamespace(policy=dict(role=role, private_root=str(root), _policy_sha256='7'*64,
            worker_routes={'worker': {'enrolled': 'synthetic-rpc'}},
            tools={'scontrol': '/nix/store/scontrol'}, slurmd_unit='slurmd.service', limits=limits()), budget=budget,
        host=lambda: dict(machine_id='b'*32, boot_id=BOOT, image_id='/nix/store/image'))
    installed_source = copy.deepcopy(selector['reader_source'])
    monkeypatch.setattr(m, '_reader_source', lambda budget: copy.deepcopy(installed_source))
    monkeypatch.setattr(m, '_receiver_native_id', lambda source: selector['receiver']['native_id'])
    return m, m.RoleView(ns), ns, selector, permit, creator, fields, intent, folder


def test_read_view_joins_original_raw_leaves_and_detects_replacement(tmp_path, monkeypatch):
    m, view, ns, selector, permit, *_ = fixture_role(tmp_path, monkeypatch)
    assert view.current_permit() == permit
    path = Path(ns.policy['private_root']) / 'qualification' / OP / 'parent-plan.json'
    path.write_bytes(raw({'different': 'plan'}))
    with pytest.raises(Exception, match='qualification_parent'):
        view.current_permit()


@pytest.mark.parametrize('fault', ['unknown', 'duplicate', 'mode', 'symlink', 'hardlink', 'boot', 'source'])
def test_invalid_present_selector_never_falls_back_open(tmp_path, monkeypatch, fault):
    m, view, ns, selector, permit, *_ = fixture_role(tmp_path, monkeypatch)
    path = Path(ns.policy['private_root']) / 'qualification/current.json'
    if fault == 'unknown': selector['enabled'] = True
    if fault == 'boot': selector['receiver']['boot_id'] = '99999999-9999-4999-8999-999999999999'
    if fault == 'source': selector['reader_source']['sha256'] = '9'*64
    path.write_bytes(raw(selector))
    if fault == 'duplicate': path.write_bytes(raw(selector)[:-1] + b',"role":"worker"}')
    if fault == 'mode': path.chmod(0o644)
    if fault == 'symlink':
        old = path.with_suffix('.original'); path.rename(old); path.symlink_to(old)
    if fault == 'hardlink': os.link(path, path.with_suffix('.link'))
    with pytest.raises(Exception): view.current_permit()


def test_canonical_cas_revisions_and_revoke_readback_are_real_files(tmp_path, monkeypatch):
    m, view, ns, selector, permit, creator, fields, intent, folder = fixture_role(tmp_path, monkeypatch)
    import host_resource_qualification_gate as gate
    stage = gate.mirror_record(permit, CALC, None, revision=0, enabled=False)
    bound = gate.check_held(permit, CALC, dict(creator=creator, fields=fields, intent=intent))
    store = m.CanonicalMirrorStore(view)
    assert view.mirror_read(CALC) is None
    store.cas(CALC, None, stage)
    assert view.mirror_read(CALC) == stage
    with pytest.raises(Exception, match='qualification_cas'): store.cas(CALC, None, stage)
    store.cas(CALC, stage, bound)
    revoked = {**bound, 'revision': 2, 'enabled': False}
    store.cas(CALC, bound, revoked)
    assert json.loads((folder/'mirrors'/f'{CALC}.json').read_bytes()) == revoked
    with pytest.raises(Exception, match='qualification_cas'): store.cas(CALC, revoked, bound)
    assert view.mirror_read(CALC) == revoked


def test_canonical_cas_allows_only_exact_disabled_staged_zero_to_two(tmp_path, monkeypatch):
    m, view, ns, selector, permit, *rest = fixture_role(tmp_path, monkeypatch)
    import host_resource_qualification_gate as gate
    stage = gate.mirror_record(permit, CALC, None, revision=0, enabled=False)
    store = m.CanonicalMirrorStore(view); store.cas(CALC, None, stage)
    forged = {**stage, 'revision': 2, 'enabled': False, 'command': '/invented'}
    with pytest.raises(Exception, match='qualification_cas'): store.cas(CALC, stage, forged)
    revoked = {**stage, 'revision': 2, 'enabled': False}
    store.cas(CALC, stage, revoked)
    assert view.mirror_read(CALC) == revoked


def test_controller_reads_canonical_worker_mirror_afresh_and_no_mutable_replica(tmp_path, monkeypatch):
    m, view, ns, selector, permit, creator, fields, intent, folder = fixture_role(tmp_path, monkeypatch, role='controller')
    import host_resource_qualification_gate as gate
    mirror = gate.check_held(permit, CALC, dict(creator=creator, fields=fields, intent=intent))
    worker_selector = {**selector, 'role': 'worker'}
    worker_selector['receiver'] = {**selector['receiver'], 'machine_id': permit['jobs'][CALC]['worker_machine_id'],
        'boot_id': permit['jobs'][CALC]['worker_boot_id']}
    packet = dict(schema='qcl.host-resource-calibration-role-subset.v1', selector=worker_selector,
        selector_sha256=hashlib.sha256(raw(worker_selector)).hexdigest(), permit=permit,
        permit_sha256=selector['permit_sha256'], mirrors={CALC: mirror, SECOND: None},
        capture_clock=dict(clock='CLOCK_BOOTTIME', boot_id=BOOT, nanoseconds=1,
            reader_source=selector['reader_source']))
    monkeypatch.setattr(m, '_worker_role_packet', lambda native_sources, row: copy.deepcopy(packet))
    controller = m.ControllerQualificationView(view)
    assert controller.mirror_read(CALC)['enabled'] is True
    packet['mirrors'][CALC] = {**mirror, 'revision': 2, 'enabled': False}
    assert controller.mirror_read(CALC)['enabled'] is False
    assert not list(folder.glob('mirrors/*.json'))


def test_receiver_clock_is_role_correct_and_preserves_original_boot_time(tmp_path, monkeypatch):
    m, view, ns, selector, permit, *_ = fixture_role(tmp_path, monkeypatch, role='controller')
    monkeypatch.setattr(m.time, 'clock_gettime_ns', lambda clock: 123456789)
    stamp = view.capture_clock()
    assert stamp == dict(clock='CLOCK_BOOTTIME', boot_id=BOOT, nanoseconds=123456789,
        reader_source=selector['reader_source'])
    # No slurmd, capture_guest_facts, arrival time or worker accounting required.
    subset = view.readonly_subset()
    assert subset['capture_clock'] == stamp
    assert subset['mirrors'] == {}


def test_undesignated_root_shell_cannot_open_native_writer_or_import(monkeypatch):
    m = sources()
    with pytest.raises(Exception, match='qualification_worker_phase_required'):
        m.open_native_jobs(SimpleNamespace())
    with pytest.raises(Exception, match='qualification_root_transport_required'):
        m.import_role_snapshot({})
    with pytest.raises(Exception, match='qualification_root_transport_required'):
        m.cas_worker_mirror(CALC, None, {})


def test_guest_guard_uses_original_process_selector_not_environment(tmp_path, monkeypatch):
    m, view, ns, selector, permit, creator, fields, intent, folder = fixture_role(tmp_path, monkeypatch)
    import host_resource_qualification_gate as gate
    bound = gate.check_held(permit, CALC, dict(creator=creator, fields=fields, intent=intent))
    m.CanonicalMirrorStore(view).cas(CALC, None, gate.mirror_record(permit, CALC, None, revision=0, enabled=False))
    m.CanonicalMirrorStore(view).cas(CALC, view.mirror_read(CALC), bound)
    ns.native_job = lambda job: dict(fields={**fields, 'JobState': 'RUNNING', 'NodeList': 'worker',
        'StartTime': '2026-11-03T12:00:01'})
    hook = dict(phase='prolog', identity={'identity': {'machine_id': 'b'*32, 'boot_id': BOOT}},
        job=ns.native_job('42'), context={'original': 'root-slurmd'})
    hookpath = Path(ns.policy['private_root'])/'hooks'
    hookpath.mkdir(mode=0o700)
    p = hookpath/f'42-{creator["dispatch_id"]}-prolog.json'
    p.write_bytes(raw(hook)); p.chmod(0o600)
    caller = dict(pid=10, ppid=11, start_ticks=1, uids=[3000]*4,
        cgroup=permit['cgroup_scope']+'/job_42/step_batch/user/task_0', executable=permit['guard']['executable'])
    ns.process = lambda pid: copy.deepcopy(caller)
    monkeypatch.setenv('SLURM_JOB_ID', '999')
    guest = m.GuestGateSources(view, SimpleNamespace(config={'role': 'guest'}))
    assert guest.guard_context(caller) == dict(permit=permit, scheduler=ns.native_job('42')['fields'], original_hook=hook)
    caller['cgroup'] = permit['cgroup_scope']+'/job_999/step_batch/user/task_0'
    with pytest.raises(Exception, match='qualification_mirror'): guest.guard_context(caller)


def test_membership_unknown_root_denial_retains_complete_original_census(tmp_path, monkeypatch):
    m, view, ns, selector, permit, creator, fields, intent, folder = fixture_role(tmp_path, monkeypatch)
    from test_host_resource_qualification_gate import gate_fixture
    p, cr, scheduler, hook, caller, gate_sources = gate_fixture()
    membership = gate_sources.batch_membership(cr)
    process_rows = {row['pid']: {**row, 'executable': row['exe']} for row in membership['processes']}
    # An extra root member may be own sudo, own observer, or foreign root. Until
    # exact owner anchors are available it must remain visible and be rejected.
    process_rows[999] = dict(pid=999, ppid=1, start_ticks=1, uids=[0]*4,
        cgroup=p['cgroup_scope']+'/job_42/step_batch/user/task_0', executable='/nix/store/unknown-root',
        state='S', comm='unknown')
    ns.run = lambda argv, **kwargs: 'PID JOBID STEPID\n'+'\n'.join(f'{pid} 42 batch' for pid in process_rows)
    ns.process = lambda pid: copy.deepcopy(process_rows[pid])
    guest = m.GuestGateSources(view, SimpleNamespace(config={'role': 'guest'}))
    with pytest.raises(Exception, match='qualification_membership_owner_required'):
        guest.batch_membership(creator)
    assert {row['pid'] for row in guest.membership_observations[-1]['processes']} == set(process_rows)
    assert any(row['pid'] == 999 for row in guest.membership_observations[-1]['listpids']['rows'])


def test_actual_task_limit_reads_full_ancestor_chain_and_refuses_unenforced_max(tmp_path, monkeypatch):
    m, view, ns, selector, permit, creator, fields, intent, folder = fixture_role(tmp_path, monkeypatch)
    candidate = dict(pid=10, ppid=11, start_ticks=1, uids=[3000]*4,
        cgroup='/jobs/job_42/step_batch/user/task_0', executable='/nix/store/guard')
    files = {'/sys/fs/cgroup/cgroup.controllers': b'cpu memory pids'}
    for group in ('/jobs', '/jobs/job_42', '/jobs/job_42/step_batch', '/jobs/job_42/step_batch/user',
            '/jobs/job_42/step_batch/user/task_0'):
        files['/sys/fs/cgroup'+group+'/memory.max'] = b'max'
        files['/sys/fs/cgroup'+str(Path(group).parent).rstrip('/')+'/cgroup.subtree_control'] = b'cpu memory'
    files['/sys/fs/cgroup/jobs/job_42/memory.max'] = b'131072'
    ns.process = lambda pid: copy.deepcopy(candidate)
    monkeypatch.setattr(ns.budget, 'read', lambda path, limit=65536: files[str(path)])
    guest = m.GuestGateSources(view, SimpleNamespace(config={'role': 'guest'}))
    assert guest.actual_task_limit(10, 131072) == 131072
    files['/sys/fs/cgroup/jobs/job_42/memory.max'] = b'max'
    with pytest.raises(Exception, match='qualification_actual_limit'): guest.actual_task_limit(10, 131072)


def test_factory_absence_keeps_closed_but_present_corrupt_selector_refuses(tmp_path, monkeypatch):
    m, view, ns, selector, permit, creator, fields, intent, folder = fixture_role(tmp_path, monkeypatch, role='controller')
    import native_attempt as native
    ns.qualification = {}; ns._caller = {'already': 'socket-authenticated'}; ns._server_unit = 'original-server'
    assert isinstance(native.NativeSources.qualification_jobs_owner(ns), m.ControllerQualificationView)
    current = view.current_path; current.unlink()
    assert native.NativeSources.qualification_jobs_owner(ns) is None
    current.write_bytes(b'{"corrupt":true}'); current.chmod(0o600)
    with pytest.raises(Exception): native.NativeSources.qualification_jobs_owner(ns)


def test_installed_qga_status_int_flags_and_plain_stdout_preserve_original_bytes():
    m = sources()
    status = '{"exited":1,"exitcode":0,"out-data":"{\\n\\"clock\\":\\"CLOCK_BOOTTIME\\"}","err-data":"","out-truncated":0}'
    observed = m.decode_qga_status(status)
    assert observed['out-data'] == '{\n"clock":"CLOCK_BOOTTIME"}'
    assert m.decode_qga_started('{"pid":123}') == 123
    assert m.decode_qga_status('{"exited":0}') == {'exited': 0}


@pytest.mark.parametrize('status', ['{"exited":true,"exitcode":0}', '{"exited":1}',
    '{"exited":1,"exitcode":0,"signal":9}', '{"exited":1,"exitcode":0,"out-truncated":1}',
    '{"exited":1,"exitcode":0,"unexpected":true}', '{"exited":1,"exitcode":0,"out-data":12}'])
def test_qga_unknown_or_truncated_status_is_not_success(status):
    m = sources()
    with pytest.raises(Exception): m.decode_qga_status(status)


def test_actual_batch_script_requires_held_matching_inode_not_same_hash_file(tmp_path, monkeypatch):
    import subprocess
    m, view, ns, selector, permit, creator, fields, intent, folder = fixture_role(tmp_path, monkeypatch)
    script = tmp_path/'slurm_script'; script.write_bytes(b'#!/bin/bash\nexit 0\n')
    same = tmp_path/'same'; same.write_bytes(script.read_bytes())
    child = subprocess.Popen([sys.executable, '-c',
        'import sys,time; f=open(sys.argv[1],"rb"); print("ready",flush=True); time.sleep(30)', str(script)],
        stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == 'ready'
        process = dict(pid=child.pid, ppid=os.getpid(), start_ticks=1, uids=[3000]*4,
            cgroup='/jobs/job_42/step_batch/user/task_0', executable=permit['bash_executable'])
        ns.process = lambda pid: copy.deepcopy(process)
        ns.command_line = lambda pid: [permit['bash_executable'], str(script)]
        guest = m.GuestGateSources(view, SimpleNamespace(config={'role': 'guest'}))
        assert guest.batch_script(child.pid) == dict(path=str(script), sha256=hashlib.sha256(script.read_bytes()).hexdigest())
        ns.command_line = lambda pid: [permit['bash_executable'], str(same)]
        with pytest.raises(Exception, match='qualification_script'): guest.batch_script(child.pid)
    finally:
        child.kill(); child.wait(timeout=5)


def test_freshness_uses_original_receiver_before_never_import_time(tmp_path, monkeypatch):
    m, view, ns, selector, permit, *_ = fixture_role(tmp_path, monkeypatch, role='controller')
    before = dict(clock='CLOCK_BOOTTIME', boot_id=BOOT, nanoseconds=100,
        reader_source=selector['reader_source'])
    monkeypatch.setattr(m.time, 'clock_gettime_ns', lambda clock: 30_000_000_100)
    assert m.validate_receiver_age(view, before, 30) == 30_000_000_000
    monkeypatch.setattr(m.time, 'clock_gettime_ns', lambda clock: 30_000_000_101)
    with pytest.raises(Exception, match='qualification_stale_host'): m.validate_receiver_age(view, before, 30)
    reboot = {**before, 'boot_id': '99999999-9999-4999-8999-999999999999'}
    with pytest.raises(Exception, match='qualification_stale_host'): m.validate_receiver_age(view, reboot, 30)
    future = {**before, 'nanoseconds': 40_000_000_000}
    with pytest.raises(Exception, match='qualification_stale_host'): m.validate_receiver_age(view, future, 30)


def test_qga_fixed_argv_uses_repeated_equal_form_and_bounds_before_dispatch():
    m = sources()
    role = dict(python_executable='/nix/store/python/bin/python3',
        reader_source=dict(path='/nix/store/task3/ops/host_resource_qualification_sources.py', sha256='8'*64))
    argv = m.qga_exec_arguments('proxmox', 712, role, 'clock', {})
    assert argv[:2] == ['create', '/nodes/proxmox/qemu/712/agent/exec']
    assert argv[2:5] == ['--command=/nix/store/python/bin/python3', '--command=-I', '--command=-c']
    assert argv[-3:] == ['--command=clock', '--input-data', '{}']
    assert 'host_resource_qualification_sources' in argv[5]
    with pytest.raises(Exception, match='output_bound'):
        m.qga_exec_arguments('proxmox', 712, role, 'clock', {'large': 'x'*65536})
    with pytest.raises(Exception, match='qualification_qga'):
        m.qga_exec_arguments('proxmox', 712, role, 'shell', {})


def test_qga_single_exec_original_intent_survives_unknown_and_is_not_replayed(tmp_path):
    m = sources()
    from test_host_resource_qualification_gate import setup_jobs
    jobs, obs, permit, original = setup_jobs(tmp_path)
    role = dict(vm_id=712, native_id='77777777-7777-4777-8777-777777777777', machine_id='a'*32, boot_id=BOOT,
        python_executable='/nix/store/python/bin/python3', python_origin=dict(path='/nix/store/python/bin/python3.14', sha256='1'*64),
        reader_source=dict(path='/nix/store/task3/ops/host_resource_qualification_sources.py', sha256='8'*64),
        native_policy_sha256='7'*64, agent=dict(unit='qemu-guest-agent.service', executable='/nix/store/qga/bin/qemu-ga',
            fragment_path='/nix/store/unit/qemu-guest-agent.service', fragment_sha256='9'*64))
    calls = []
    class Backend:
        node = 'proxmox'
        def _run(self, argv, timeout=30):
            calls.append(argv)
            raise TimeoutError('original QGA request unknown')
    transport = m.RootQgaTransport(jobs.parent, Backend(), {'controller': role})
    request_id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
    with pytest.raises(TimeoutError): transport.execute('controller', 'clock', {}, 'stage', request_id)
    with pytest.raises(FileExistsError): transport.execute('controller', 'clock', {}, 'stage', request_id)
    assert len(calls) == 1
    receipts = list((jobs.repo.folder(OP)/'source-observations').glob('*.json'))
    assert any(json.loads(p.read_bytes()).get('schema') == 'qcl.host-resource-calibration-qga-intent.v1' for p in receipts)
    assert any(json.loads(p.read_bytes()).get('schema') == 'qcl.host-resource-calibration-qga-unknown.v1' for p in receipts)


def test_role_import_installs_originals_before_selector_and_never_overwrites_old_operation(tmp_path, monkeypatch):
    m, view, ns, selector, permit, creator, fields, intent, folder = fixture_role(tmp_path, monkeypatch)
    payload = dict(schema='qcl.host-resource-calibration-role-import.v1', selector=selector,
        documents={name: (folder/name).read_text() for name in
            ('permit.json', 'parent-plan.json', 'parent-fence.json', 'capacity-report.json')})
    for path in folder.glob('*.json'): path.unlink()
    folder.joinpath('mirrors').rmdir(); folder.rmdir(); view.current_path.unlink()
    # Actual ingress authentication is a distinct OS seam. Import file locking,
    # validation, exclusive creates, ordering, rereads and refusal remain real.
    ingress = SimpleNamespace(sources=ns, view=view, receiver=selector['receiver'],
        reader_source=selector['reader_source'])
    monkeypatch.setattr(m, '_admit_root_transport', lambda: ingress)
    assert m.import_role_snapshot(payload)['permit_sha256'] == selector['permit_sha256']
    assert view.current_permit() == permit
    with pytest.raises(Exception, match='qualification_operation_exists'): m.import_role_snapshot(payload)
    assert view.current_permit() == permit


def test_root_transport_pin_rejects_manual_root_before_any_payload_or_write(tmp_path, monkeypatch):
    m, view, ns, selector, permit, creator, fields, intent, folder = fixture_role(tmp_path, monkeypatch)
    monkeypatch.setattr(m, '_transport_sources', lambda: ns)
    pin = dict(schema='qcl.host-resource-calibration-root-transport.v1', role='worker',
        receiver=selector['receiver'], python_executable='/nix/store/python/bin/python3',
        python_origin=dict(path='/nix/store/python/bin/python3.14', sha256='9'*64),
        reader_source=selector['reader_source'], agent=dict(unit='qemu-guest-agent.service',
            executable='/nix/store/qga/bin/qemu-ga', fragment_path='/nix/store/qga-unit/qemu-guest-agent.service', fragment_sha256='1'*64))
    path = view.root/'qualification/root-transport.json'
    path.write_bytes(raw(pin)); path.chmod(0o600)
    ns.process = lambda pid: dict(pid=pid, ppid=1, start_ticks=10, uids=[0]*4,
        cgroup='/user.slice/manual-shell', executable=pin['python_origin']['path'])
    with pytest.raises(Exception, match='qualification_root_transport_required'):
        m._admit_root_transport()


def _host_source_fixture(tmp_path, monkeypatch):
    """Actual parent/repository/paid invariants, synthetic OS and QGA endpoints."""
    m = sources()
    from test_host_resource_qualification_gate import setup_jobs
    from host_resource_service import NativeResourceService
    from host_resource_backends import fingerprint
    from dataclasses import asdict
    jobs, obs, permit, paid = setup_jobs(tmp_path)
    # Prepare a new internally coherent synthetic host identity before freezing
    # this fixture; production readers continue to require canonical boot UUIDs.
    state = jobs.parent.store.load(); state['host_boot_id'] = BOOT; jobs.parent.store.save(state)
    paid = jobs.parent.store.state_path.read_bytes()
    plan = jobs.repo.plan(OP); plan.update(host_boot_id=BOOT, baseline_state_sha256=hashlib.sha256(paid).hexdigest())
    (jobs.repo.folder(OP)/'plan.json').write_bytes(raw(plan))
    permit['parent_plan_sha256'] = jobs.repo.digest(jobs.repo.folder(OP)/'plan.json')
    fence = dict(schema='qcl.host-resource-calibration-fence.v1', operation_id=OP,
        plan_sha256=permit['parent_plan_sha256'], baseline_state_sha256=plan['baseline_state_sha256'])
    # Preserve the owner schema from its original fence.
    fence['schema'] = jobs.repo.read(jobs.repo.directory/'active.json')['schema']
    (jobs.repo.directory/'active.json').write_bytes(raw(fence))
    permit['fence_sha256'] = jobs.repo.digest(jobs.repo.directory/'active.json')
    events = []
    report = {'original': 'measurement report'}
    permit['capacity_report_sha256'] = hashlib.sha256(raw(report)).hexdigest()
    jobs.stage(permit)
    role = dict(vm_id=712, native_id='77777777-7777-4777-8777-777777777777', machine_id='a'*32, boot_id=BOOT,
        python_executable='/nix/store/python/bin/python3', python_origin=dict(path='/nix/store/python/bin/python3.14', sha256='1'*64),
        reader_source=dict(path='/nix/store/task3/ops/host_resource_qualification_sources.py', sha256='8'*64),
        native_policy_sha256='7'*64, agent=dict(unit='qemu-guest-agent.service', executable='/nix/store/qga/bin/qemu-ga',
            fragment_path='/nix/store/unit/qemu-guest-agent.service', fragment_sha256='9'*64))
    roles = {'controller': role, 'worker': {**role, 'vm_id': 713, 'machine_id': 'b'*32,
        'native_id': '88888888-8888-4888-8888-888888888888'}}
    class Provider:
        native_proofs = jobs.parent.proofs
        backend = SimpleNamespace(native_backend=SimpleNamespace(node='proxmox'))
        config = dict(enrollment={vm.vm_id: dict(machine_id='b'*32) for vm in jobs.parent.policy.vms})
        sources = SimpleNamespace(processes=lambda: [])
        def _host_inventory(self):
            events.append('host')
            return dict(boot_id=jobs.parent.repository.plan(OP)['host_boot_id'], MemTotal=jobs.parent.policy.physical_ram_bytes,
                MemAvailable=jobs.parent.policy.physical_ram_bytes), [], {'original': 'actual-agreement'}
        def _calibration_pair(self, ctx):
            events.append('pair-'+ctx['binding']['vm_id'])
            binding = ctx['binding']
            read = jobs.parent.proofs.backend.rows[binding['vm_id']]
            guest = dict(identity_before={'machine_id': ctx['worker_machine_id'], 'boot_id': binding['guest_boot_id']},
                identity_after={'machine_id': ctx['worker_machine_id'], 'boot_id': binding['guest_boot_id']}, jobs={}, groups={})
            return read, guest, {'actual': 'paired native/guest raw'}
    provider = Provider()
    service = NativeResourceService(SimpleNamespace(policy=jobs.parent.policy, store=jobs.parent.store, backend=jobs.parent.proofs.backend), provider)
    inventory = dict(schema='qcl.host-resource-calibration-role-inventory.v1', operation_id=OP,
        parent_plan_sha256=permit['parent_plan_sha256'], native_host=dict(host_id=jobs.parent.policy.host_id,
            host_boot_id=jobs.parent.repository.plan(OP)['host_boot_id'], policy_sha256=jobs.parent.repository.plan(OP)['policy_sha256'],
            baseline_state_sha256=hashlib.sha256(paid).hexdigest()), roles=roles,
        source_refs={'collector': {'path': '/protected/synthetic-collector.py', 'sha256': 'a'*64}})
    base = jobs.repo.folder(OP)/'source-context'; base.mkdir(mode=0o700)
    jobs.repo.exclusive(base/'roles.json', inventory)
    jobs.repo.exclusive(base/'capacity-report.json', report)
    monkeypatch.setattr(m, '_validate_role_inventory_current', lambda *args: inventory)
    monkeypatch.setattr(m, '_host_capture_owner', lambda *args: dict(
        process=dict(pid=101, ppid=1, start_ticks=10, uids=[0]*4, cgroup='/system.slice/synthetic',
            executable='/nix/store/python/bin/python3.14'), collector=inventory['source_refs']['collector'],
        native_host_boot_id=BOOT))
    packets = {}
    for role_name, selected in roles.items():
        packet = dict(schema='qcl.host-resource-calibration-role-clock.v1',
            receiver={key:selected[key] for key in ('native_id', 'machine_id', 'boot_id')},
            reader_source=selected['reader_source'], clock=dict(clock='CLOCK_BOOTTIME', boot_id=selected['boot_id'],
                nanoseconds=100, reader_source=selected['reader_source']), ingress={'original': 'synthetic-QGA-OS'})
        packet['receiver']['native_policy_sha256'] = selected['native_policy_sha256']
        packets[selected['vm_id']] = packet
    class Backend:
        node = 'proxmox'
        def _run(self, argv, timeout=30):
            vmid = int(argv[1].split('/')[4])
            if argv[0] == 'create':
                assert not any(e == 'host' or e.startswith('pair-') for e in events)
                events.append('clock-controller' if vmid == 712 else 'clock-worker')
                return json.dumps({'pid': vmid})
            assert argv[:2] == ['get', f'/nodes/proxmox/qemu/{vmid}/agent/exec-status']
            assert argv[2:] == ['--pid', str(vmid)]
            return json.dumps({'exited': 1, 'exitcode': 0, 'out-data': json.dumps(packets[vmid]), 'err-data': ''})
    provider.backend.native_backend = Backend()
    retained = m.capture_host_proof(service, permit, 'stage')
    assert events[:2] == ['clock-controller', 'clock-worker']
    proof_path = Path(retained['path'])
    proof = json.loads(proof_path.read_bytes())
    assert proof['receiver_before']['controller']['clock']['nanoseconds'] == 100
    assert proof['captured_host']['paid_state_sha256'] == hashlib.sha256(paid).hexdigest()
    assert proof['authorized_demand_set'] == {calc: row['demand_bytes'] for calc,row in permit['jobs'].items()}
    assert set(proof['captured_guests']) == {vm.vm_id for vm in jobs.parent.policy.vms}
    assert jobs.parent.store.state_path.read_bytes() == paid
    assert retained['sha256'] == hashlib.sha256(proof_path.read_bytes()).hexdigest()
    return m, jobs, permit, retained, proof, roles, paid


def test_wholehost_capture_orders_authenticated_receiver_clocks_before_actual_readers_and_retains_raw(tmp_path, monkeypatch):
    _host_source_fixture(tmp_path, monkeypatch)


def test_controller_view_matches_existing_native_submit_and_historical_argv_api(tmp_path, monkeypatch):
    m, view, ns, selector, permit, creator, fields, intent, folder = fixture_role(tmp_path, monkeypatch, role='controller')
    import native_attempt as native
    import host_resource_qualification_gate as gate
    stage = gate.mirror_record(permit, CALC, None, revision=0, enabled=False)
    mirrors = {calc: gate.mirror_record(permit, calc, None, revision=0, enabled=False) for calc in permit['jobs']}
    controller = m.ControllerQualificationView(view)
    monkeypatch.setattr(controller, 'mirror_read', lambda calc: copy.deepcopy(mirrors[calc]))
    launch = permit['jobs'][CALC]['launch']
    actor = dict(calcjob_uuid=CALC, action='submit', launch=launch, execution_sha256=launch['files']['native_execution']['sha256'])
    with pytest.raises(Exception, match='qualification_host_source_required'):
        controller.submit_permit(launch, calcjob_uuid=CALC, actor=actor, fixture='native-publication-v1')
    mirrors[CALC] = gate.check_held(permit, CALC, dict(creator=creator, fields=fields, intent=intent))
    ns._qualification_jobs = controller
    ns.policy['tools'].update(runuser=permit['submit']['runuser'], sbatch=permit['submit']['sbatch'])
    argv = native.NativeSources._argv(ns, launch, intent['snapshot'], creator['dispatch_id'])
    assert argv == intent['native']['argv']
    mirrors[CALC] = {**mirrors[CALC], 'revision': 2, 'enabled': False}
    assert native.NativeSources._argv(ns, launch, intent['snapshot'], creator['dispatch_id']) == argv


def test_existing_local_facts_exposes_only_fixed_bounded_subset_without_host_raw(tmp_path, monkeypatch):
    m, view, ns, selector, permit, creator, fields, intent, folder = fixture_role(tmp_path, monkeypatch)
    import host_resource_facts as facts
    monkeypatch.setattr(m, '_open_role_sources', lambda role: ns)
    local = facts.LocalSources({'role': 'guest'}, None)
    subset = local.qualification_subset()
    assert subset['permit'] == permit and subset['mirrors'] == {CALC: None, SECOND: None}
    assert set(subset) == {'schema', 'selector', 'selector_sha256', 'permit', 'permit_sha256', 'mirrors', 'capture_clock'}
    assert len(raw(subset)) <= 65536
    view.current_path.unlink()
    assert local.qualification_subset() is None


def test_guest_facts_packet_includes_actual_canonical_subset_with_whole_packet_bound(tmp_path, monkeypatch):
    m, view, ns, selector, permit, creator, fields, intent, folder = fixture_role(tmp_path, monkeypatch)
    import host_resource_facts as f
    import native_attempt as n
    from test_native_attempt import p20_worker
    worker = p20_worker()
    identity = {**worker['identity'], 'machine_id': selector['receiver']['machine_id'], 'boot_id': BOOT,
        'dmi_uuid': selector['receiver']['native_id']}
    class Local(f.LocalSources):
        def host(self): return {**identity, 'MemTotal': 1024**3, 'MemAvailable': 512*1024**2}
        def processes(self): return [dict(worker['unit']['main'])]
        def run(self, argv): return 'RealMemory=512 State=IDLE'
    config = dict(role='guest', node='worker', client_uid=3000, slurm_cgroup_root='/jobs', infrastructure_processes=[],
        slurmd_executable=worker['unit']['main']['executable'], guest_protocol='synthetic', scontrol='/fixed/scontrol', systemctl='/fixed/systemctl')
    monkeypatch.setattr(m, '_open_role_sources', lambda role: ns)
    monkeypatch.setattr(n, '_worker_output_sources', lambda: None)
    monkeypatch.setattr(f, 'capture_scheduler', lambda *args: {})
    monkeypatch.setattr(n.engine, 'unit_state', lambda *args, **kwargs: {**worker['unit']['state'], 'LoadState': 'loaded'})
    monkeypatch.setattr(f.os.path, 'realpath', lambda path: '/nix/store/synthetic-image')
    monkeypatch.setattr(f, 'trusted_root_path', lambda path, **kwargs: Path(path))
    local = Local(config, None)
    packet = f.capture_guest_facts(config, local, clock=lambda: 100)
    assert packet['qualification']['permit'] == permit
    assert packet['qualification']['mirrors'] == {CALC: None, SECOND: None}
    assert len(raw(packet)) <= f.MAX_OUTPUT_BYTES


def _receiver_with_host_proof(tmp_path, monkeypatch):
    rootdir = tmp_path/'native'; rootdir.mkdir()
    m, jobs, permit, retained, proof, roles, paid = _host_source_fixture(rootdir, monkeypatch)
    roledir = tmp_path/'receiver'; roledir.mkdir()
    m, view, ns, selector, oldpermit, *rest = fixture_role(roledir, monkeypatch, role='controller')
    selector.update({key: permit[key] for key in ('parent_plan_sha256', 'fence_sha256', 'capacity_report_sha256', 'source_graph_sha256')})
    selector['permit_sha256'] = jobs.repo.digest(jobs.folder/'permit.json')
    selected = roles['controller']
    selector['receiver'] = {key: selected[key] for key in ('native_id', 'machine_id', 'boot_id', 'native_policy_sha256')}
    selector['reader_source'] = selected['reader_source']; selector['native_host'] = proof['native_host_context']['roles']['native_host']
    ns.host = lambda: dict(machine_id=selected['machine_id'], boot_id=selected['boot_id'], image_id='/nix/store/image')
    monkeypatch.setattr(m, '_reader_source', lambda budget: copy.deepcopy(selected['reader_source']))
    monkeypatch.setattr(m, '_receiver_native_id', lambda source: selected['native_id'])
    folder = view.root/'qualification'/OP
    originals = {'permit.json': (jobs.folder/'permit.json').read_bytes(),
        'parent-plan.json': (jobs.repo.folder(OP)/'plan.json').read_bytes(),
        'parent-fence.json': (jobs.repo.directory/'active.json').read_bytes(),
        'capacity-report.json': (jobs.repo.folder(OP)/'source-context/capacity-report.json').read_bytes()}
    for name, data in originals.items(): (folder/name).write_bytes(data)
    view.current_path.write_bytes(raw(selector))
    (folder/'host-proofs').mkdir(mode=0o700)
    (folder/'source-observations').mkdir(mode=0o700)
    for ref in proof['original_transcript_refs']:
        for name in (ref['request_id']+'-intent.json', ref['request_id']+'-started.json', ref['status_name']):
            path = folder/'source-observations'/name
            path.write_bytes((jobs.repo.folder(OP)/'source-observations'/name).read_bytes()); path.chmod(0o600)
    data = Path(retained['path']).read_bytes(); digest = hashlib.sha256(data).hexdigest()
    path = folder/'host-proofs'/(digest+'.json'); path.write_bytes(data); path.chmod(0o600)
    current = dict(schema='qcl.host-resource-calibration-host-current.v1', operation_id=OP,
        permit_sha256=selector['permit_sha256'], proof_sha256=digest)
    path = folder/'host-current.json'; path.write_bytes(raw(current)); path.chmod(0o600)
    monkeypatch.setattr(m.time, 'clock_gettime_ns', lambda clock: 200)
    return m, view, permit, proof, folder


def test_local_host_proof_reads_original_transcripts_and_preserves_receiver_before(tmp_path, monkeypatch):
    m, view, permit, proof, folder = _receiver_with_host_proof(tmp_path, monkeypatch)
    observed = m.read_host_proof(view, permit)
    assert observed == proof
    assert observed['receiver_before']['controller']['clock']['nanoseconds'] == 100


@pytest.mark.parametrize('fault', ['paid', 'allD', 'restamp', 'missing_transcript'])
def test_local_host_proof_cannot_be_renewed_or_substituted_at_import(tmp_path, monkeypatch, fault):
    m, view, permit, proof, folder = _receiver_with_host_proof(tmp_path, monkeypatch)
    if fault == 'paid': proof['captured_host']['paid_state_raw'] = '{}'
    if fault == 'allD': proof['authorized_demand_set'][SECOND] += 1
    if fault == 'restamp': proof['receiver_before']['controller']['clock']['nanoseconds'] = 199
    if fault == 'missing_transcript':
        (folder/'source-observations'/proof['original_transcript_refs'][0]['status_name']).unlink()
    data = raw(proof); digest = hashlib.sha256(data).hexdigest()
    path = folder/'host-proofs'/(digest+'.json'); path.write_bytes(data); path.chmod(0o600)
    path = folder/'host-current.json'; value=json.loads(path.read_bytes()); value['proof_sha256']=digest; path.write_bytes(raw(value))
    with pytest.raises(Exception): m.read_host_proof(view, permit)


def test_bounded_host_import_preserves_original_clock_and_atomically_publishes_after_transcripts(tmp_path, monkeypatch):
    m, view, permit, proof, folder = _receiver_with_host_proof(tmp_path, monkeypatch)
    observations = {path.name: path.read_text() for path in (folder/'source-observations').iterdir()}
    payload = dict(schema='qcl.host-resource-calibration-host-import.v1', expected=None,
        proof_raw=raw(proof).decode(), observations=observations)
    for path in (folder/'source-observations').iterdir(): path.unlink()
    for path in (folder/'host-proofs').iterdir(): path.unlink()
    (folder/'host-current.json').unlink()
    selector = view._selector()[0]
    ingress = SimpleNamespace(sources=view.sources, view=view, receiver=selector['receiver'], reader_source=selector['reader_source'])
    monkeypatch.setattr(m, '_admit_root_transport', lambda: ingress)
    result = m.import_role_snapshot(payload)
    assert result['proof_sha256'] == hashlib.sha256(raw(proof)).hexdigest()
    assert m.read_host_proof(view, permit)['receiver_before']['controller']['clock']['nanoseconds'] == 100
    with pytest.raises(Exception, match='qualification_cas'): m.import_role_snapshot(payload)
    assert m.read_host_proof(view, permit) == proof


def test_oversized_import_refuses_before_transport_and_never_invents_freshness(tmp_path, monkeypatch):
    m, view, ns, selector, permit, creator, fields, intent, folder = fixture_role(tmp_path, monkeypatch)
    ingress=SimpleNamespace(view=view, sources=ns, receiver=selector['receiver'], reader_source=selector['reader_source'])
    monkeypatch.setattr(m, '_admit_root_transport', lambda: ingress)
    with pytest.raises(Exception, match='output_bound'):
        m.import_role_snapshot(dict(schema='qcl.host-resource-calibration-host-import.v1', expected=None,
            proof_raw='x'*65536, observations={}))
    assert not (folder/'host-current.json').exists()


def _reservation_identity_fixture():
    """Synthetic measured consumer inputs; derived from the independent control.

    Every mutation below exercises the real consumer. No reader/capacity bool
    is replaced, and actual inventory/accounting validators remain active.
    """
    from test_host_resource_qualification_observations import permit as measured_permit, os_accounting
    from test_native_attempt import p20_worker, p20_runner
    MiB = 1024**2
    m=sources();report={'permit':measured_permit()};ctx=report['permit']['context'];vm=ctx['binding']['vm_id']
    selector={'native_host':{k:ctx[k]for k in ('host_id','host_boot_id','policy_sha256','baseline_state_sha256')},
      'capacity_report_sha256':'7'*64}
    p=fixture()[0];p['source_graph_sha256']=ctx['source_graph_sha256']
    for row,value in zip(p['jobs'].values(),report['permit']['authorized_demands'].values()):
        row.update(vm_id=vm,demand_bytes=value,worker_machine_id=ctx['worker_machine_id'],worker_boot_id=ctx['binding']['guest_boot_id'])
    plan={'bindings':{vm:copy.deepcopy(ctx['binding'])}}
    policy={'vms':[dict(vm_id=vm,minimum_bytes=100*MiB,maximum_bytes=1000*MiB,overhead_bytes=10*MiB)],
      'reserves':dict(host_services_bytes=10*MiB,control_plane_bytes=5*MiB,safety_bytes=5*MiB,foreign_max_bytes=0),
      'physical_ram_bytes':2048*MiB,'owned_pool':{'agreement_ref':'same'}}
    worker=p20_worker();worker['identity']={
      'machine_id':ctx['worker_machine_id'],'boot_id':ctx['binding']['guest_boot_id'],
      'kernel':ctx['binding']['guest_kernel_id'],'dmi_uuid':ctx['binding']['native_id']}
    runner=p20_runner();runner['source_graph_sha256']=ctx['source_graph_sha256']
    guest=dict(identity_before=dict(machine_id=ctx['worker_machine_id'],boot_id=ctx['binding']['guest_boot_id']),
      identity_after=dict(machine_id=ctx['worker_machine_id'],boot_id=ctx['binding']['guest_boot_id']),jobs={},groups={},
      calibration_accounting=os_accounting(),output_generation=dict(worker=worker,runner=runner),
      memory=dict(MemTotal=980*MiB,MemAvailable=900*MiB),slurm_memory_bytes=900*MiB,slurm_registered=True)
    read={'running':True,'assigned_bytes':1000*MiB,'configured_bytes':1000*MiB,
      'native_id':ctx['binding']['native_id'],'process_id':ctx['binding']['process_id'],
      'config_fingerprint':ctx['binding']['config_fingerprint'],'vm_id':vm,'revision':'same'}
    proof=dict(native_host_context=dict(policy=policy,policy_sha256=ctx['policy_sha256']),
      parent_refs={'baseline_state_sha256':ctx['baseline_state_sha256']},captured_host=dict(
      paid_state_raw=json.dumps({'grants':[dict(vm_id=vm,guest_bytes=1000*MiB)]}),
      host={'MemTotal':2048*MiB,'MemAvailable':1024*MiB},agreement=dict(policy_sha256=ctx['policy_sha256'],agreement_ref='same',foreign={}),
      inventory=[dict(native_id=ctx['binding']['native_id'],maximum_bytes=1000*MiB,kind='qemu',running=True,process_id=ctx['binding']['process_id'],config_fingerprint=ctx['binding']['config_fingerprint'])],
      processes=[dict(pid=int(ctx['binding']['process_id']),executable='/usr/bin/qemu-system-x86_64')],child_jobs=None),
      captured_guests={vm:dict(context=ctx,readback=read,guest=guest)})
    view=SimpleNamespace(snapshot=lambda:(selector,p,None,{'parent-plan.json':plan,'capacity-report.json':report}))
    return m,view,p,proof,vm


@pytest.mark.parametrize('field', ['vm_id', 'native_id', 'process_id', 'config_fingerprint'])
@pytest.mark.parametrize('mutation', ['missing', 'null'])
def test_reservation_readback_identity_unknown_never_uses_paid_bytes_as_binding(field, mutation):
    m, view, permit, proof, vm = _reservation_identity_fixture()
    m._validate_reservation_capacity(view, permit, proof)
    if mutation == 'missing':
        del proof['captured_guests'][vm]['readback'][field]
    else:
        proof['captured_guests'][vm]['readback'][field] = None
    with pytest.raises(Exception):
        m._validate_reservation_capacity(view, permit, proof)


@pytest.mark.parametrize('field,value', [('boot_id', '99999999-9999-4999-8999-999999999999'),
    ('kernel', 'different-kernel'), ('dmi_uuid', '99999999-9999-4999-8999-999999999999')])
def test_reservation_output_worker_identity_joins_accounting_and_original_binding(field, value):
    m, view, permit, proof, vm = _reservation_identity_fixture()
    m._validate_reservation_capacity(view, permit, proof)
    proof['captured_guests'][vm]['guest']['output_generation']['worker']['identity'][field] = value
    with pytest.raises(Exception):
        m._validate_reservation_capacity(view, permit, proof)


@pytest.mark.parametrize('field,value', [('kernel', 'different-kernel'),
    ('dmi_uuid', '99999999-9999-4999-8999-999999999999'), ('image_id', '/nix/store/different-image'),
    ('unknown_field', 'not-an-identity-field')])
def test_reservation_supplied_guest_identity_fields_cannot_disagree_with_complete_actual_accounting(field, value):
    m, view, permit, proof, vm = _reservation_identity_fixture()
    m._validate_reservation_capacity(view, permit, proof)
    for side in ('identity_before', 'identity_after'):
        proof['captured_guests'][vm]['guest'][side][field] = value
    with pytest.raises(Exception):
        m._validate_reservation_capacity(view, permit, proof)
