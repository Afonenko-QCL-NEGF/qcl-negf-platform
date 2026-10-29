"""SOURCE/L fixtures. Synthetic observations never qualify an installed backend."""
import copy
import hashlib
import importlib.util
import json
import os
import socket
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ops'))


def module():
    assert importlib.util.find_spec('native_attempt'), 'ordinary attempt owner is missing'
    import native_attempt
    return native_attempt


def request(action='submit'):
    claim = {'bytes': 3, 'sha256': hashlib.sha256(b'abc').hexdigest()}
    return {'version': 1, 'action': action, 'calcjob_uuid': '11111111-1111-4111-8111-111111111111',
            'launch': {'request_id': '22222222-2222-4222-8222-222222222222',
                       'run_uuid': '33333333-3333-4333-8333-333333333333', 'execution_id': 'execution-1',
                       'transport_attempt': 1, 'code_uuid': '44444444-4444-4444-8444-444444444444',
                       'release_id': 'release-1', 'native_execution_uuid': '55555555-5555-4555-8555-555555555555',
                       'input_plan_uuid': '66666666-6666-4666-8666-666666666666',
                       'source_graph_uuid': '77777777-7777-4777-8777-777777777777',
                       'relative_execution_root': 'native/run-1/execution-1',
                       'remote_workdir': '/srv/qcl-negf/jobs/upload/one',
                       'files': {name: copy.deepcopy(claim) for name in
                                 ('plan', 'source_graph', 'native_execution', 'submit_script')}},
            'controls': None}


def limits():
    return dict(request_bytes=65536, response_bytes=262144, script_bytes=65536,
                metadata_bytes=4 * 1024 * 1024, memory_bytes=134217728,
                operation_seconds=30, command_seconds=10, cleanup_seconds=1,
                maximum_pids=256, maximum_calls=64, maximum_files=128)


class Observations:
    """Private seam: production NativeSources body is tested separately."""
    def __init__(self, m):
        self.m, self.calls, self.fault = m, [], None

    def preflight(self, launch, budget):
        budget.before()
        if self.fault == 'policy':
            raise self.m.Hold('native_qualification_missing')
        return {'machine_id': 'a' * 32, 'boot_id': '88888888-8888-4888-8888-888888888888'}

    def snapshot(self, launch, dispatch, budget):
        budget.reserve(3)
        return {'script_path': '/nix/store/' + 'a' * 32 + '-fixture/script',
                'script_sha256': launch['files']['submit_script']['sha256']}

    def dispatch(self, launch, snapshot, dispatch, budget):
        self.calls.append(dispatch)
        if self.fault == 'lost_ack':
            raise self.m.engine.CommandFailure({'failure': 'timeout', 'child_started': True,
                                               'cleanup_confirmed': True, 'stderr': 'original'})
        result = self.m.engine.CommandOutput('42;cluster\n')
        result.output_bytes = len(result) + (1 if self.fault == 'extra_bytes' else 0)
        return result

    def _intent(self, launch, snapshot, dispatch):
        return {'argv': ['fixture-sbatch', snapshot['script_path']], 'script_sha256': snapshot['script_sha256'],
                'owner': {'fixture_only': 'not native authority'}}

    def bind_job(self, ack, launch, dispatch, context, budget):
        return {'job_id': ack['job_id'], 'cluster': ack['cluster'], 'submit_time': '2026-10-29T01:00:00',
                'controller_machine_id': context['machine_id'], 'controller_boot_id': context['boot_id'],
                'dispatch_id': dispatch, 'generation': 'b' * 64, 'node_name': None, 'start_time': None,
                'worker_machine_id': None, 'worker_boot_id': None}


class MemoryConnection:
    """Bounded byte stream; sandbox socket IO is a separate native gate."""
    def __init__(self, raw):
        self.raw = raw

    def recv(self, size):
        result, self.raw = self.raw[:size], self.raw[size:]
        return result

    def settimeout(self, timeout):
        assert timeout > 0


def owner(tmp_path, observations=None):
    m = module()
    policy = {'private_root': str(tmp_path), 'limits': limits()}
    sources = observations or Observations(m)
    return m.OrdinaryAttemptOwner(policy, m.AttemptStore(tmp_path), sources, m.Operation(limits())), sources


def test_one_dispatch_durable_ack_and_fresh_owner_same_key(tmp_path):
    m = module()
    first, sources = owner(tmp_path)
    result = first.submit(request())
    assert result['state'] == 'bound' and result['job']['job_id'] == '42'
    assert len(sources.calls) == 1
    again = m.OrdinaryAttemptOwner(first.policy, m.AttemptStore(tmp_path), sources, m.Operation(limits()))
    assert again.submit(request())['job'] == result['job']
    assert len(sources.calls) == 1
    directory = tmp_path / 'attempts' / request()['calcjob_uuid']
    assert (directory / 'dispatch.json').is_file() and (directory / 'ack.json').is_file()
    assert json.loads((directory / 'dispatch.json').read_bytes())['native']['argv'][1].endswith('/script')


def test_lost_ack_repeated_key_never_dispatches_again_and_retains_primary(tmp_path):
    m = module()
    first, sources = owner(tmp_path)
    sources.fault = 'lost_ack'
    result = first.submit(request())
    assert result['state'] == 'hold' and result['reason'] == 'dispatch_outcome_unknown'
    directory = tmp_path / 'attempts' / request()['calcjob_uuid']
    failure = (directory / 'failure.json').read_bytes()
    assert json.loads(failure)['stderr'] == 'original'
    sources.fault = None
    for action in ('submit', 'reconcile', 'status'):
        fresh = m.OrdinaryAttemptOwner(first.policy, m.AttemptStore(tmp_path), sources, m.Operation(limits()))
        assert getattr(fresh, action)(request(action))['state'] == 'hold'
    assert len(sources.calls) == 1 and (directory / 'failure.json').read_bytes() == failure


def test_conflicting_launch_and_missing_qualification_do_not_claim_or_dispatch(tmp_path):
    first, sources = owner(tmp_path)
    sources.fault = 'policy'
    assert first.submit(request())['reason'] == 'native_qualification_missing'
    assert not (tmp_path / 'attempts').exists() and not sources.calls
    sources.fault = None
    assert first.submit(request())['state'] == 'bound'
    other = request(); other['launch']['transport_attempt'] = 2
    assert first.submit(other)['reason'] == 'launch_conflict'
    assert len(sources.calls) == 1


@pytest.mark.parametrize('mutate', [
    lambda r: r.update(untrusted_authority=True),
    lambda r: r['launch'].update(transport_attempt=True),
    lambda r: r['launch'].update(relative_execution_root='../escape'),
    lambda r: r['launch']['files']['plan'].update(bytes=True),
    lambda r: r.update(controls=[]),
])
def test_closed_request_shapes_before_effects(tmp_path, mutate):
    first, sources = owner(tmp_path)
    document = request(); mutate(document)
    assert first.submit(document)['state'] == 'rejected'
    assert not sources.calls and not (tmp_path / 'attempts').exists()


@pytest.mark.parametrize('raw', [b'42;cluster\n', b'42\n'])
def test_ack_strict_positive(raw):
    m = module(); output = m.engine.CommandOutput(raw.decode()); output.output_bytes = len(raw)
    assert m.parse_ack(output, 'cluster') == {'job_id': '42', 'cluster': 'cluster'}


@pytest.mark.parametrize('raw,extra', [(b'0\n', 0), (b'42;other\n', 0), (b'42\nnoise', 0),
                                       (b'42\n', 1), ('42é\n'.encode(), 0)])
def test_ack_stderr_ignored_octets_and_ambiguous_output_hold(raw, extra):
    m = module(); output = m.engine.CommandOutput(raw.decode()); output.output_bytes = len(raw) + extra
    with pytest.raises(m.Hold):
        m.parse_ack(output, 'cluster')


@pytest.mark.parametrize('raw', [b'{"a":1,"a":2}', b'{"a":NaN}', b'{}{}', b'\xff'])
def test_strict_frame_rejects_duplicate_nonfinite_trailing_or_non_utf8(raw):
    m = module(); connection = MemoryConnection(struct.pack('!I', len(raw)) + raw)
    with pytest.raises(m.Hold):
        m.read_frame(connection, m.Operation(limits()), 65536)


def test_frame_positive_extra_frame_and_bound():
    m = module()
    for payload, accepted in [(struct.pack('!I', 2) + b'{}', True),
                              (struct.pack('!I', 2) + b'{}x', False),
                              (struct.pack('!I', 65537), False)]:
        connection = MemoryConnection(payload)
        if accepted:
            assert m.read_frame(connection, m.Operation(limits()), 65536) == {}
        else:
            with pytest.raises(m.Hold):
                m.read_frame(connection, m.Operation(limits()), 65536)


class PeerSources:
    def __init__(self):
        self.count = 0; self.fault = None

    def process(self, pid):
        self.count += 1
        return dict(pid=pid, start_ticks=55 + (self.fault == 'reuse' and self.count > 1),
                    uids=[3000] * 4, cgroup=('/system.slice/qcl-negf-api.service' if self.fault == 'api'
                                          else '/system.slice/qcl-negf-aiida.service/worker'),
                    executable='/nix/store/' + 'a' * 32 + '-python/bin/python3')

    def unit(self, name):
        return dict(InvocationID='a' * 32, ControlGroup='/system.slice/' + name,
                    MainPID='123', ActiveState='active')

    def application_origin(self, process):
        if self.fault == 'shell':
            raise module().Hold('application_origin')


@pytest.mark.parametrize('fault', [None, 'reuse', 'api', 'shell'])
def test_real_peer_observation_boundary_distinguishes_same_uid_and_pid_reuse(fault):
    m = module(); sources = PeerSources(); sources.fault = fault
    class Connection:
        def getsockopt(self, *args):
            return struct.pack('3i', 456, 3000, 3000)
    policy = dict(client_uid=3000, daemon_unit='qcl-negf-aiida.service')
    if fault:
        with pytest.raises(m.Hold):
            m.authenticate_socket_peer(Connection(), policy, sources)
    else:
        assert m.authenticate_socket_peer(Connection(), policy, sources)['pid'] == 456


def test_native_fixed_dispatch_uses_snapshot_and_shared_command_budget(monkeypatch):
    m = module(); calls = []
    policy = dict(client_uid=3000, tools={'runuser': '/nix/store/runuser', 'sbatch': '/nix/store/sbatch'},
                  slurm={'config_file': '/etc/slurm.conf'}, limits=limits())
    sources = m.NativeSources(policy, m.Operation(limits()))
    def run(argv, **kw):
        calls.append((argv, kw)); result = m.engine.CommandOutput('42\n'); result.output_bytes = 3
        return result
    monkeypatch.setattr(m.engine, 'command', run)
    monkeypatch.setattr(m, 'trusted_root_path', lambda path, **kw: Path(path))
    snapshot = {'script_path': '/var/lib/qcl-negf-native-spool/original.sh', 'script_sha256': 'a' * 64}
    monkeypatch.setattr(sources, '_check_snapshot', lambda snapshot: None)
    result = sources.dispatch(request()['launch'], snapshot, request()['calcjob_uuid'], sources.budget)
    argv, kw = calls[0]
    assert argv == ['/nix/store/runuser', '-u', 'qcl-negf', '--', '/nix/store/sbatch', '--parsable',
                    '--no-requeue', '--chdir', request()['launch']['remote_workdir'], '--comment',
                    request()['calcjob_uuid'], snapshot['script_path']]
    assert kw['deadline'] == sources.budget.deadline and kw['env']['SLURM_CONF'] == '/etc/slurm.conf'
    assert m.parse_ack(result, 'cluster')['job_id'] == '42' and sources.budget.calls == 1


def test_owner_file_reader_reads_original_bytes_and_rejects_aliases(tmp_path):
    m = module(); launch = request()['launch']; work = tmp_path / 'upload'; work.mkdir()
    launch['remote_workdir'] = str(work)
    for name in m.FILES.values():
        (work / name).write_bytes(b'abc')
    policy = dict(jobs_root=str(tmp_path), client_uid=os.getuid(), limits=limits())
    assert m._owner_read(policy, launch, m.Operation(limits()))['script'] == base64_script(b'abc')
    (work / 'plan.json').unlink(); (work / 'plan.json').symlink_to('source-graph.json')
    with pytest.raises((m.Hold, OSError)):
        m._owner_read(policy, launch, m.Operation(limits()))


def base64_script(raw):
    import base64
    return base64.b64encode(raw).decode()


def test_opt_in_package_and_module_source_envelopes():
    root = Path(__file__).resolve().parents[1]
    paths = ['nix/native-attempt.nix', 'tests/infrastructure/native-attempt.nix']
    for name in paths:
        assert (root / name).is_file(), name
    app = (root / 'modules/application.nix').read_text()
    cluster = (root / 'modules/cluster.nix').read_text()
    assert 'nativeAttempts' in app and 'NoNewPrivileges = true;' in app
    assert 'qcl-negf-native-attempt@' in app and 'Accept = true' in app
    assert 'nativeAttempts' in cluster and 'Prolog=' in cluster and 'Epilog=' in cluster


def test_distinct_calcjob_cannot_claim_overlapping_canonical_output_domain(tmp_path):
    first, sources = owner(tmp_path)
    assert first.submit(request())['state'] == 'bound'
    second = request(); second['calcjob_uuid'] = '99999999-9999-4999-8999-999999999999'
    second['launch']['relative_execution_root'] += '/child'
    assert first.submit(second)['reason'] == 'output_domain_claimed'
    assert len(sources.calls) == 1


def test_missing_policy_after_bound_preserves_original_trustworthy_job(tmp_path):
    first, sources = owner(tmp_path)
    original = first.submit(request())['job']; sources.fault = 'policy'
    result = first.status(request('status'))
    assert result['state'] == 'hold' and result['job'] == original


def test_partial_dispatch_record_never_becomes_an_authorization_to_repeat(tmp_path, monkeypatch):
    first, sources = owner(tmp_path); original = first.store.put
    def fault(calcjob, name, value, budget):
        if name == 'dispatch.json':
            (first.store.path(calcjob) / name).write_bytes(b'{partial')
            raise OSError('original fsync ambiguity')
        return original(calcjob, name, value, budget)
    monkeypatch.setattr(first.store, 'put', fault)
    assert first.submit(request())['state'] == 'hold'
    original_bytes = (first.store.path(request()['calcjob_uuid']) / 'dispatch.json').read_bytes()
    monkeypatch.setattr(first.store, 'put', original)
    assert first.submit(request())['state'] == 'hold' and not sources.calls
    assert (first.store.path(request()['calcjob_uuid']) / 'dispatch.json').read_bytes() == original_bytes


def test_original_ack_survives_failed_job_lookup_and_reconciles_same_key(tmp_path):
    first, sources = owner(tmp_path); original = sources.bind_job
    def missing(*args):
        raise module().Hold('native_job_changed')
    sources.bind_job = missing
    assert first.submit(request())['reason'] == 'native_job_changed'
    sources.bind_job = original
    assert first.reconcile(request('reconcile'))['state'] == 'bound' and len(sources.calls) == 1


@pytest.mark.parametrize('fault', ['extra_bytes', 'lost_ack'])
def test_unknown_dispatch_does_not_hide_original_marker(tmp_path, fault):
    first, sources = owner(tmp_path); sources.fault = fault
    assert first.submit(request())['state'] == 'hold'
    assert first.store.read(request()['calcjob_uuid'], 'dispatch.json', module().Operation(limits()))
    assert len(sources.calls) == 1


def writer_fixture():
    known = [dict(job_id='42', generation='b' * 64, dispatch_id='a', domain='native/run-1/execution-1', submit_time='today'),
             dict(job_id='43', generation='c' * 64, dispatch_id='b', domain='native/run-2/execution-1', submit_time='today')]
    inventory = dict(schema='qcl.host-resource-guest-facts.v1', identity_before={'boot_id': 'same'},
                     identity_after={'boot_id': 'same'}, slurm_registered=True,
                     jobs={'42': dict(owner_uid=3000, submit_time='today', terminal=True),
                           '43': dict(owner_uid=3000, submit_time='today', terminal=False)},
                     groups={'42': dict(populated=False, processes=[]), '43': dict(populated=True, processes=[1])})
    return known, inventory


@pytest.mark.parametrize('change', [None, 'overlap', 'unknown', 'populated', 'boot', 'submit', 'unregistered'])
def test_whole_writer_closure_finite_managed_domains(change):
    m = module(); known, inventory = writer_fixture()
    if change == 'overlap': known[1]['domain'] = known[0]['domain'] + '/child'
    if change == 'unknown': known.pop()
    if change == 'populated': inventory['groups']['42']['populated'] = True
    if change == 'boot': inventory['identity_after']['boot_id'] = 'new'
    if change == 'submit': inventory['jobs']['43']['submit_time'] = 'different'
    if change == 'unregistered': inventory['slurm_registered'] = False
    if change:
        with pytest.raises(m.Hold):
            m.enforce_writer_closure('native/run-1/execution-1', [inventory], known, 'b' * 64)
    else:
        m.enforce_writer_closure('native/run-1/execution-1', [inventory], known, 'b' * 64)


@pytest.mark.parametrize('kind', ['live', 'fast', 'unknown_root', 'same_pid', 'empty', 'completing'])
def test_worker_collector_reuses_original_before_and_whole_stop_oracles(tmp_path, monkeypatch, kind):
    m = module()
    from test_slurm_job_evidence import EXPECTED, sample
    identity = {'schema': 'qcl.host-resource-guest-identity.v1', 'identity': EXPECTED['identity']}
    document = dict(version=1, calcjob_uuid=request()['calcjob_uuid'], dispatch_id=request()['launch']['request_id'],
                    job_id='7', generation='b' * 64, phase='start')
    policy = dict(private_root=str(tmp_path), tools={'slurmstepd': EXPECTED['slurmstepd_executable'], 'scontrol': '/fixed/scontrol'},
                  slurm={'cgroup_scope': EXPECTED['cgroup_scope']}, limits=limits())
    sources = m.NativeSources(policy, m.Operation(limits())); samples = sample()['processes']
    def process(pid):
        old = copy.deepcopy(next(p for p in samples if p['pid'] == pid))
        if document['phase'] == 'close' and kind != 'same_pid':
            raise FileNotFoundError('original process absent')
        if kind == 'unknown_root': old['uids'] = [0] * 4
        return {**old, 'executable': old['exe']}
    monkeypatch.setattr(sources, 'process', process)
    monkeypatch.setattr(sources, 'host', lambda: EXPECTED['identity'])
    monkeypatch.setattr(sources, 'run', lambda argv: 'PID JOBID STEPID\n' + ('' if kind == 'fast' else '101 7 batch\n102 7 batch\n'))
    monkeypatch.setattr(sources.budget, 'read', lambda path, limit: (_ for _ in ()).throw(FileNotFoundError()))
    monkeypatch.setattr(m.Path, 'exists', lambda path: False if str(path).startswith(('/proc/', '/sys/fs/cgroup')) else original_exists(path))
    if kind in {'fast', 'unknown_root'}:
        with pytest.raises(m.Hold, match='native_start_not_observed'):
            m._worker_capture(sources, document, identity, {'fields': {} })
    else:
        before, after = m._worker_capture(sources, document, identity, {'fields': {}})
        assert before['status'] == 'pass_live_job_membership' and after is None
        document['phase'] = 'close'
        state = 'COMPLETING' if kind == 'completing' else 'COMPLETED'
        if kind in {'same_pid', 'completing'}:
            with pytest.raises(m.Hold, match='native_stop_not_observed'):
                m._worker_capture(sources, document, identity, {'fields': {'JobState': state}})
        else:
            _, after = m._worker_capture(sources, document, identity, {'fields': {'JobState': state}})
            assert after['status'] == 'pass_physical_job_stop' and after['scientific_accepted'] is False


original_exists = Path.exists


@pytest.mark.parametrize('manual', [False, True])
def test_hook_auth_requires_actual_slurmd_ancestry_not_root_or_environment(monkeypatch, manual):
    m = module()
    monkeypatch.setattr(m.os, 'getuid', lambda: 0); monkeypatch.setattr(m.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(m.os, 'getpid', lambda: 500)
    class Sources:
        policy = {'slurmd_unit': 'slurmd.service', 'tools': {'slurmd': '/nix/store/slurmd'}}
        def unit(self, name):
            return dict(MainPID='100', ControlGroup='/system.slice/slurmd.service',
                        InvocationID='a' * 32, ActiveState='active')
        def process(self, pid):
            return dict(pid=pid, ppid=(1 if manual else 100), start_ticks=pid, uids=[0] * 4,
                        cgroup=('/user.slice/shell' if manual else '/system.slice/slurmd.service'),
                        executable='/nix/store/slurmd' if pid == 100 else '/nix/store/python')
    if manual:
        with pytest.raises(m.Hold): m.authenticate_hook(Sources())
    else:
        assert [p['pid'] for p in m.authenticate_hook(Sources())['chain']] == [500, 100]


def test_native_job_parser_and_dispatch_join_positive_reused_generation_negative(monkeypatch):
    m = module(); launch = request()['launch']; dispatch = request()['calcjob_uuid']
    sources = m.NativeSources(dict(tools={'scontrol': '/fixed/scontrol'}, spool_root='/local/spool'), m.Operation(limits()))
    text = ('JobId=42 UserId=qcl-negf(3000) SubmitTime=2026-10-29T01:00:00 WorkDir=' + launch['remote_workdir'] +
            ' Comment=' + dispatch + ' Command=/local/spool/' + dispatch + '.sh Restarts=0 NumNodes=1 NumTasks=1')
    monkeypatch.setattr(sources, 'run', lambda argv: text)
    context = {'machine_id': 'a' * 32, 'boot_id': '88888888-8888-4888-8888-888888888888'}
    result = sources.bind_job(dict(job_id='42', cluster='cluster'), launch, dispatch, context, sources.budget)
    assert result['job_id'] == '42' and len(result['generation']) == 64
    text = text.replace('Restarts=0', 'Restarts=1')
    with pytest.raises(m.Hold):
        sources.bind_job(dict(job_id='42', cluster='cluster'), launch, dispatch, context, sources.budget)


def test_closed_native_stop_never_bypasses_missing_q1(tmp_path):
    m = module(); first, sources = owner(tmp_path)
    first.submit(request())
    sources.worker = lambda *args: {'before': {'measured': 'fixture'}, 'after': {'scientific_accepted': False}}
    sources.close_writers = lambda *args: None
    close = request('close'); close['controls'] = []
    result = first.qualify_close(close)
    assert result['state'] == 'hold' and result['reason'] == 'q1_controls_unavailable'
    assert result['controls'] is None and len(sources.calls) == 1


def test_limits_are_inherited_not_reset_and_debit_before_command(monkeypatch):
    m = module(); operation = m.Operation(limits()); calls = []
    def run(argv, **kw): calls.append(kw); return m.engine.CommandOutput('observed')
    operation.command(['/fixed/readonly'], run=run, output_bytes=100)
    first = operation.bytes
    operation.command(['/fixed/readonly'], run=run, output_bytes=100)
    assert operation.bytes == first * 2 and calls[0]['deadline'] == calls[1]['deadline']
    operation.bytes = operation.limits['metadata_bytes']
    with pytest.raises(m.Hold): operation.command(['/fixed/readonly'], run=run)
    assert len(calls) == 2
    operation.deadline = 0
    with pytest.raises(m.Hold): operation.command(['/fixed/readonly'], run=run)
    assert len(calls) == 2


@pytest.mark.parametrize('change', [None, 'boot', 'tool', 'version', 'cluster', 'storage', 'journal_nfs', 'pass_flag'])
def test_native_policy_qualification_joins_observed_host_tools_units_and_storage(monkeypatch, change):
    m = module(); host = dict(machine_id='a' * 32, boot_id=request()['launch']['request_id'], image_id='/nix/store/image')
    tools = {key: '/nix/store/' + key for key in ('systemctl', 'runuser', 'sbatch', 'scontrol', 'slurmd', 'slurmstepd', 'python')}
    policy = dict(role='controller', tools=tools, slurm=dict(cluster='cluster', version='slurm 1', config_file='/fixed/slurm.conf'),
                  private_root='/local/attempts', spool_root='/local/spool', jobs_root='/jobs', nfs_source='storage:/jobs',
                  qualification_file='/protected/qualification', storage_identity_file='/protected/storage',
                  _policy_sha256='b' * 64, daemon_unit='qcl-negf-aiida.service', server_unit_prefix='qcl-negf-native-attempt@')
    fragment = b'actual immutable unit source'
    qualification = dict(protocol_id='p07-ordinary-slurm-v1', policy_sha256='b' * 64,
                         controller_binding=copy.deepcopy(host), worker_bindings={}, tool_origins=copy.deepcopy(tools),
                         unit_origins={'qcl-negf-aiida.service': dict(fragment_path='/nix/store/unit',
                                      fragment_sha256=hashlib.sha256(fragment).hexdigest(), executable='/nix/store/python')},
                         write_domain={'storage_identity': 'actual-storage'}, qualification_receipt_ref='fixture-N-receipt')
    if change == 'boot': qualification['controller_binding']['boot_id'] = request()['calcjob_uuid']
    if change == 'tool': qualification['tool_origins']['sbatch'] += '-changed'
    if change == 'pass_flag': qualification['verified'] = True
    sources = m.NativeSources(policy, m.Operation(limits()))
    monkeypatch.setattr(sources, 'host', lambda: host)
    def mount(path):
        if path == '/jobs': return dict(fstype='nfs4', source='storage:/jobs', options={'hard'})
        return dict(fstype=('nfs4' if change == 'journal_nfs' else 'ext4'))
    monkeypatch.setattr(sources, 'mount', mount)
    monkeypatch.setattr(m, 'trusted_root_path', lambda path, **kw: Path(path))
    monkeypatch.setattr(m.engine, 'public_binary_origin', lambda budget, path, **kw: {'path': path})
    monkeypatch.setattr(m.engine, 'immutable_public_bytes', lambda *args: fragment)
    def read(path, *args):
        if str(path) == policy['qualification_file']: return m.encoded(qualification)
        if str(path) == policy['storage_identity_file']: return b'changed-storage' if change == 'storage' else b'actual-storage'
        if str(path) == policy['slurm']['config_file']: return b'ClusterName=other' if change == 'cluster' else b'ClusterName=cluster'
        raise AssertionError(path)
    monkeypatch.setattr(m, 'protected_read', read)
    calls = []
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        if '--version' in argv: text = 'slurm changed' if change == 'version' else 'slurm 1'
        else: text = ('InvocationID=' + 'a' * 32 + '\nControlGroup=/system.slice/qcl-negf-aiida.service\nMainPID=123\n'
                      'ActiveState=active\nFragmentPath=/nix/store/unit\nMemoryMax=134217728\nRuntimeMaxUSec=1min 30s\n')
        output = m.engine.CommandOutput(text); output.output_bytes = len(text); return output
    monkeypatch.setattr(m.engine, 'command', run)
    if change:
        with pytest.raises(m.Hold): sources.qualify()
    else:
        assert sources.qualify() == host and len(calls) == 2 and sources.budget.calls == 2


def test_attempt_facts_uses_existing_flat_guest_config_not_a_new_nested_policy(monkeypatch):
    m = module(); import host_resource_facts as facts
    document = dict(version=1, calcjob_uuid=request()['calcjob_uuid'], dispatch_id=request()['launch']['request_id'],
                    job_id='42', generation='b' * 64, phase='status')
    host = dict(machine_id='a' * 32, boot_id=request()['calcjob_uuid'], image_id='/nix/store/image')
    config = dict(schema='qcl.host-resource-service.v1', role='guest', client_uid=3000, node='node-a')
    policy = dict(facts_service_config='/protected/service.json', private_root='/local', spool_root='/spool')
    fields = dict(SubmitTime='today', Comment=document['dispatch_id'], Command='/spool/' + document['dispatch_id'] + '.sh', WorkDir='/jobs/upload')
    generation = hashlib.sha256(m.encoded(dict(controller=host, job_id='42', submit_time='today',
                               dispatch_id=document['dispatch_id'], command=fields['Command'], workdir=fields['WorkDir']))).hexdigest()
    document['generation'] = generation
    monkeypatch.setattr(m, '_load_policy', lambda *args: policy)
    monkeypatch.setattr(m.NativeSources, 'qualify', lambda self: setattr(self, 'qualification', {'controller_binding': host}) or host)
    monkeypatch.setattr(m.NativeSources, 'native_job', lambda *args: {'fields': fields, 'raw': 'original'})
    def read(path, *args):
        if str(path) == policy['facts_service_config']: return m.encoded(config)
        raise FileNotFoundError('hook absent on this unrelated status host')
    monkeypatch.setattr(m, 'protected_read', read)
    def identity(actual, sources):
        assert actual is config or actual == config
        return {'schema': 'qcl.host-resource-guest-identity.v1', 'identity': host}
    monkeypatch.setattr(facts, 'capture_guest_identity', identity)
    monkeypatch.setattr(m, '_capture_writer_snapshot', lambda actual, *args: {'flat_config': actual == config})
    result = m.read_attempt_facts(document)
    assert result['writer_snapshot']['flat_config'] is True and result['prolog_ref'] is None


def test_client_unknown_transport_returns_typed_hold_and_no_retry(monkeypatch, capsys):
    m = module(); calls = []
    def disconnected():
        calls.append('one'); raise OSError('lost response')
    monkeypatch.setattr(m, '_client_operation', disconnected, raising=False)
    assert m.client_main() == 75
    result = json.loads(capsys.readouterr().out)
    assert result['state'] == 'hold' and result['reason'] == 'transport_outcome_unknown' and calls == ['one']


def test_started_response_attaches_real_worker_without_replacing_native_generation(tmp_path):
    first, sources = owner(tmp_path); result = first.submit(request()); original = result['job']
    identity = dict(machine_id='c' * 32, boot_id=request()['launch']['run_uuid'])
    sources.worker = lambda *args: dict(before={'status': 'pass_live_job_membership'},
        identity={'identity': identity}, job={'fields': {'NodeList': 'node-a', 'StartTime': '2026-10-29T01:00:01'}})
    started = first.observe_start(request('start'))
    assert started['state'] == 'started' and started['job']['worker_machine_id'] == identity['machine_id']
    assert started['job']['node_name'] == 'node-a' and started['job']['generation'] == original['generation']
    original_bytes = (first.store.path(request()['calcjob_uuid']) / 'allocation.json').read_bytes()
    sources.worker = lambda *args: dict(before={'status': 'pass_live_job_membership'},
        identity={'identity': {**identity, 'boot_id': request()['launch']['request_id']}},
        job={'fields': {'NodeList': 'node-a', 'StartTime': '2026-10-29T01:00:01'}})
    assert first.observe_start(request('start'))['state'] == 'hold'
    assert (first.store.path(request()['calcjob_uuid']) / 'allocation.json').read_bytes() == original_bytes


def test_facts_command_failure_retains_bounded_original_and_known_job(tmp_path):
    m = module(); first, sources = owner(tmp_path); original = first.submit(request())['job']
    primary = {'failure': 'timeout', 'stdout': 'original facts prefix', 'child_started': True, 'cleanup_confirmed': False}
    def failed(*args): raise m.engine.CommandFailure(primary)
    sources.worker = failed
    result = first.observe_start(request('start'))
    assert result['state'] == 'hold' and result['job'] == original
    records = list(first.store.path(request()['calcjob_uuid']).glob('observation-failure-*.json'))
    assert len(records) == 1
    import base64
    retained = json.loads(records[0].read_bytes())
    assert json.loads(base64.b64decode(retained['original_prefix_base64'])) == primary


def test_policy_tightens_original_deadline_without_a_new_window(monkeypatch):
    m = module(); budget = m._bootstrap_operation(); initial = budget.deadline - budget.limits['operation_seconds']
    policy = dict(schema='qcl-negf.native-attempt-policy.v1', role='controller', private_root='/local/attempts',
        spool_root='/local/spool', socket_path=m.SOCKET, jobs_root='/jobs', native_result_prefix='native',
        nfs_source='storage:/jobs', storage_identity_file='/protected/storage', release_runtime='/protected/runtime',
        client_uid=3000, daemon_unit='qcl-negf-aiida.service', server_unit_prefix='qcl-negf-native-attempt@',
        slurmd_unit='slurmd.service', tools={key: '/nix/store/' + key for key in
            ('systemctl', 'runuser', 'sbatch', 'scontrol', 'slurmd', 'slurmstepd', 'python')},
        slurm=dict(cluster='cluster', version='slurm 1', config_file='/fixed/conf', cgroup_scope='/system.slice/slurmstepd.scope'),
        facts_service_config='/protected/facts', worker_routes={'worker': dict(target='facts@worker', known_hosts='/protected/hosts',
            identity_file='/protected/key', helper='/fixed/rpc', role='facts')}, qualification_file='/protected/qualification', limits=limits())
    monkeypatch.setattr(m.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(m, 'protected_read', lambda *args: m.encoded(policy))
    m._load_policy('controller', budget)
    assert budget.deadline <= initial + limits()['operation_seconds']


def test_protected_script_snapshot_positive_survives_original_upload_mutation(tmp_path, monkeypatch):
    from contextlib import contextmanager
    m = module(); work = tmp_path / 'upload'; work.mkdir(); spool = tmp_path / 'spool'; spool.mkdir()
    launch = request()['launch']; launch['remote_workdir'] = str(work)
    for name in m.FILES.values(): (work / name).write_bytes(b'abc')
    policy = dict(jobs_root=str(tmp_path), spool_root=str(spool), client_uid=3000, limits=limits())
    sources = m.NativeSources(policy, m.Operation(limits()))
    monkeypatch.setattr(m, '_read_submitted_files_as_owner', lambda p, l, b: m._owner_read({**p, 'client_uid': os.getuid()}, l, b))
    @contextmanager
    def fixture_directory(path, **kwargs):
        assert Path(path) == spool
        fd = os.open(spool, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: yield fd
        finally: os.close(fd)
    monkeypatch.setattr(m, 'protected_directory', fixture_directory)
    ownership = []
    monkeypatch.setattr(m.os, 'fchown', lambda fd, uid, gid: ownership.append((uid, gid)))
    monkeypatch.setattr(m, 'trusted_stat', lambda info, **kw: None)  # explicit unprivileged fixture namespace
    snapshot = sources.snapshot(launch, request()['calcjob_uuid'], sources.budget)
    assert ownership == [(0, 3000)] and Path(snapshot['script_path']).read_bytes() == b'abc'
    (work / '_aiidasubmit.sh').write_bytes(b'changed after upload hash')
    sources._check_snapshot(snapshot)
    assert Path(snapshot['script_path']).read_bytes() == b'abc'
    (work / '_aiidasubmit.sh').write_bytes(b'abc')
    with pytest.raises(FileExistsError): sources.snapshot(launch, request()['calcjob_uuid'], sources.budget)


@pytest.mark.parametrize('image_kind', ['nonexecuting', 'writable', 'foreign_origin', 'non_root'])
def test_f1_actual_host_reader_immutable_data_origin(tmp_path, monkeypatch, image_kind):
    """Actual host/helper bodies; only filesystem/kernel identity is projected.

    Mode/type/symlink metadata come from real temporary files. UID0 is an
    explicit private ownership fixture, never an observation of native NixOS.
    """
    import stat
    from types import SimpleNamespace
    m = module(); tree = tmp_path / 'filesystem'; tree.mkdir()
    image = ('/images/foreign' if image_kind == 'foreign_origin' else
             '/nix/store/' + 'a' * 32 + '-nixos-system-fixture')
    def physical(path): return tree / str(path).lstrip('/')
    for path in ('/run', '/etc', '/proc/sys/kernel/random', image):
        physical(path).mkdir(parents=True, exist_ok=True)
    physical('/run/current-system').symlink_to(image)
    marker = physical(image + '/nixos-version'); marker.write_bytes(b'fixture NixOS image data')
    marker.chmod(0o644 if image_kind == 'writable' else 0o444)
    assert not marker.stat().st_mode & 0o111
    physical('/etc/machine-id').write_text('a' * 32 + '\n')
    physical('/proc/sys/kernel/random/boot_id').write_text(request()['calcjob_uuid'] + '\n')
    budget = m.Operation(limits()); original_read, original_stat, original_link = budget.read, budget.stat, budget.link
    monkeypatch.setattr(budget, 'read', lambda path, limit=65536: original_read(physical(path), limit))
    def projected_stat(path, **kwargs):
        info = original_stat(physical(path), **kwargs)
        fields = {name: getattr(info, name) for name in dir(info) if name.startswith('st_')}
        fields['st_uid'] = 1000 if image_kind == 'non_root' and str(path) == image + '/nixos-version' else 0
        return SimpleNamespace(**fields)
    monkeypatch.setattr(budget, 'stat', projected_stat)
    monkeypatch.setattr(budget, 'link', lambda path: original_link(physical(path)))
    monkeypatch.setattr(m.engine, 'command', lambda *args, **kwargs: pytest.fail('host reader launched a command'))
    assert stat.S_ISREG(marker.stat().st_mode)
    sources = m.NativeSources({}, budget)
    if image_kind == 'nonexecuting':
        assert sources.host() == dict(machine_id='a' * 32, boot_id=request()['calcjob_uuid'], image_id=image)
    else:
        with pytest.raises(ValueError, match='Untrusted public executable origin'):
            sources.host()


@pytest.mark.parametrize('large', [False, True])
def test_f1_actual_hook_contains_original_command_failure_before_foreign_classification(monkeypatch, capsys, large):
    """Run actual hook -> qualification -> run/command boundary, without a job."""
    import base64
    m = module(); host = dict(machine_id='a' * 32, boot_id=request()['calcjob_uuid'], image_id='/nix/store/image')
    tools = {key: '/nix/store/' + key for key in ('systemctl', 'runuser', 'sbatch', 'scontrol', 'slurmd', 'slurmstepd', 'python')}
    policy = dict(role='worker', tools=tools, qualification_file='/protected/qualification', _policy_sha256='b' * 64,
                  slurm=dict(cluster='cluster', version='slurm 1', config_file='/fixed/slurm.conf'))
    qualification = dict(protocol_id='p07-ordinary-slurm-v1', policy_sha256='b' * 64,
                         controller_binding=host, worker_bindings={host['machine_id']: host},
                         unit_origins={}, tool_origins=tools, write_domain={}, qualification_receipt_ref='fixture-only')
    monkeypatch.setattr(m.sys, 'argv', ['qcl-negf-native-attempt-hook', 'prolog'])
    monkeypatch.setattr(m, '_load_policy', lambda role, budget: policy)
    monkeypatch.setattr(m, 'protected_read', lambda path, budget: m.encoded(qualification))
    monkeypatch.setattr(m.NativeSources, 'host', lambda self: host)
    monkeypatch.setattr(m.engine, 'public_binary_origin', lambda budget, path: {'path': path})
    record = dict(failure='timeout', returncode=None, elapsed_seconds=5.0,
                  stdout='original stdout' + ('X' * 20000 if large else ''), stderr='original stderr',
                  output_truncated=False, cleanup_confirmed=False, child_started=True, output_bytes=31)
    primary = m.engine.CommandFailure(record); original = copy.deepcopy(record); calls = []
    def failure(argv, **kwargs):
        calls.append((argv, kwargs)); raise primary
    monkeypatch.setattr(m.engine, 'command', failure)
    monkeypatch.setattr(m.NativeSources, 'native_job', lambda *args: pytest.fail('foreign classification happened after failed qualification'))
    monkeypatch.setattr(m, 'authenticate_hook', lambda *args: pytest.fail('fabricated hook proof'))
    monkeypatch.setattr(m.AttemptStore, 'put', lambda *args: pytest.fail('fabricated lifecycle journal'))
    assert m.hook_main() == 0
    captured = capsys.readouterr()
    assert captured.out == '' and len(captured.err.encode()) <= 4096
    diagnostic = json.loads(captured.err.split('native-attempt hook HOLD: ', 1)[1])
    raw = m.encoded(original); prefix = base64.b64decode(diagnostic['original_prefix_base64'], validate=True)
    assert diagnostic['reason'] == 'native_command_failed' and prefix == raw[:2048]
    assert diagnostic['original_bytes'] == len(raw) and diagnostic['original_sha256'] == hashlib.sha256(raw).hexdigest()
    assert diagnostic['truncated'] is (len(raw) > 2048) and primary.record is record and record == original
    assert len(calls) == 1 and calls[0][0] == [tools['scontrol'], '--version']
    assert calls[0][1]['deadline'] > 0 and calls[0][1]['output_bytes'] <= 262144


@pytest.mark.parametrize('phase,missing', [('start', 'native_prolog_not_observed'), ('close', 'native_epilog_not_observed')])
def test_f1_missing_hook_proof_still_holds_only_the_dependent_managed_attempt(tmp_path, monkeypatch, phase, missing):
    m = module(); import host_resource_facts as facts
    first, observed = owner(tmp_path); bound = first.submit(request())['job']
    host = dict(machine_id='c' * 32, boot_id=request()['calcjob_uuid'])
    packet = dict(version=1, identity={'schema': 'qcl.host-resource-guest-identity.v1', 'identity': host},
                  job={'fields': dict(SubmitTime=bound['submit_time'], Comment=bound['dispatch_id'])},
                  prolog_ref=None if phase == 'start' else 'hooks/original-prolog.json', epilog_ref=None,
                  before=None, after=None, writer_snapshot={})
    native = m.NativeSources({'worker_routes': {'node-a': {}}}, first.budget)
    native.qualification = {'worker_bindings': {host['machine_id']: host}}
    monkeypatch.setattr(native, 'native_job', lambda job: {'fields': dict(SubmitTime=bound['submit_time'],
                         Comment=bound['dispatch_id'], NodeList='node-a')})
    monkeypatch.setattr(native, '_trust_root', lambda: '/private/fixture-only')
    monkeypatch.setattr(facts, 'trusted_rpc', lambda *args, **kwargs: packet)
    observed.worker = native.worker
    document = request(phase); document['controls'] = [] if phase == 'close' else None
    result = first.observe_start(document) if phase == 'start' else first.qualify_close(document)
    assert result['state'] == 'hold' and result['reason'] == missing and result['job'] == bound
    assert result['controls'] is None and len(observed.calls) == 1
    assert not (first.store.path(document['calcjob_uuid']) / 'allocation.json').exists()
