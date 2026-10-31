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

    def preflight(self, launch, budget, *, calcjob_uuid=None, action=None):
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
        self.count = 0; self.fault = None; self.changing_counters = True
        self.policy = dict(client_uid=3000,daemon_unit='qcl-negf-aiida.service')
        self.python = '/nix/store/' + 'a'*32 + '-python/bin/python3'
        self.app = '/nix/store/application'; self.profile = '/nix/var/nix/profiles/qcl-negf-application'
        self.qualification = {'unit_origins': {self.policy['daemon_unit']: {'executable':self.python}}}
        self.configuration = dict(profile='qcl-negf',aiida_path='/var/lib/qcl-negf/aiida',
            application_profile=self.profile,jobs_root='/srv/qcl-negf/jobs',client=dict(
                entrypoint='/nix/store/client/bin/qcl-negf-native-attempt-client',
                argv_prefix=[self.python,'-I','-c','fixed generated source'],bash_executable='/nix/store/bash/bin/bash'))

    def process(self, pid):
        self.count += 1
        parent = {456:345,345:234,234:123,123:1}[pid]
        return dict(pid=pid,ppid=parent,start_ticks={456:40,345:30,234:20,123:10}[pid] + (self.fault == 'reuse' and self.count > 4),
                    uids=[3000] * 4, cgroup=('/system.slice/qcl-negf-api.service' if self.fault == 'api'
                                          else '/system.slice/qcl-negf-aiida.service/worker'),
                    executable=self.python, state='S',comm='python3',
                    observations={'raw_counter':self.count if self.changing_counters else 0})

    def unit(self, name):
        return dict(InvocationID='a' * 32, ControlGroup='/system.slice/' + name,
                    MainPID='123', ActiveState='active')

    def application_origin(self, process):
        if self.fault == 'shell':
            raise module().Hold('application_origin')

    def actor_context(self):return {'app':self.app,'configuration':self.configuration}
    def origin(self,path):return path
    def profile_view(self,pid,context):return {'fixture_metadata_only':'not native authority'}
    def command_line(self,pid):
        tails={345:['worker'],234:['start-circus','1','--foreground'],123:['start','--foreground']}
        if pid==456:return self.configuration['client']['argv_prefix']+['submit']
        if self.fault=='shell':return ['/bin/sh','unrelated']
        return [self.python,self.app+'/bin/verdi','-p','qcl-negf','daemon',*tails[pid]]
    def selected_environment(self,pid):return {'AIIDA_PATH':self.configuration['aiida_path']+('' if pid==123 else '/.aiida'),
                                            'QCL_NEGF_NATIVE_JOBS_ROOT':self.configuration['jobs_root']}


@pytest.mark.parametrize('fault', [None, 'reuse', 'api', 'shell'])
def test_real_peer_observation_boundary_distinguishes_same_uid_and_pid_reuse(fault):
    m = module(); sources = PeerSources(); sources.fault = fault
    class Connection:
        def getsockopt(self, *args):
            return struct.pack('3i', 456, 3000, 3000)
    policy = dict(client_uid=3000, daemon_unit='qcl-negf-aiida.service')
    if fault:
        with pytest.raises(m.Hold):
            m.authenticate_socket_peer(Connection(), policy, sources,action='submit')
    else:
        assert m.authenticate_socket_peer(Connection(), policy, sources,action='submit')['pid'] == 456


@pytest.mark.parametrize('fault',['action','parent','birth','worker_argv','environment','mainpid','loop','dead'])
def test_actual_causal_chain_rejects_each_unjoined_peer(fault):
    m=module();sources=PeerSources();sources.changing_counters=False
    original_process=sources.process;original_command=sources.command_line;original_unit=sources.unit
    def process(pid):
        row=original_process(pid)
        if fault=='parent' and pid==345:row['ppid']=123
        if fault=='loop' and pid==345:row['ppid']=456
        if fault=='birth' and pid==123:row['start_ticks']=99
        if fault=='dead' and pid==345:row['state']='Z'
        return row
    sources.process=process
    sources.command_line=lambda pid: ['/bin/sh','manual'] if fault=='worker_argv' and pid==345 else original_command(pid)
    if fault=='environment':sources.selected_environment=lambda pid: {'AIIDA_PATH':'/other'}
    if fault=='mainpid':sources.unit=lambda name:{**original_unit(name),'MainPID':'456'}
    class Connection:
        def getsockopt(self,*args):return struct.pack('3i',456,3000,3000)
    with pytest.raises(m.Hold):
        m.authenticate_socket_peer(Connection(),sources.policy,sources,action='status' if fault=='action' else 'submit')


def stock_aiida_descendant_environment(base,jobs_root):
    """Execute only two pinned upstream AST functions, without importing AiiDA."""
    import ast
    import importlib.metadata
    import types
    distribution=importlib.metadata.distribution('aiida-core')
    assert distribution.version=='2.9.2'
    class NoProfilePath(type(Path())):
        def is_dir(self):return False
    environment=types.SimpleNamespace(environ={'AIIDA_PATH':base,'PATH':'/APP/bin:/empty',
        'QCL_NEGF_NATIVE_JOBS_ROOT':jobs_root},path=os.path)
    def isolated(relative,name,namespace):
        path=distribution.locate_file(relative)
        tree=ast.parse(path.read_text())
        node=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name==name)
        node.decorator_list=[]
        exec(compile(ast.fix_missing_locations(ast.Module(body=[node],type_ignores=[])),str(path),'exec'),namespace)
        return namespace[name]()
    directory=isolated('aiida/manage/configuration/settings.py','_get_configuration_directory_from_envvar',
        {'os':environment,'pathlib':types.SimpleNamespace(Path=NoProfilePath),'sys':sys,
         'DEFAULT_AIIDA_PATH_VARIABLE':'AIIDA_PATH','DEFAULT_AIIDA_PATH':'/unused','DEFAULT_CONFIG_DIR_NAME':'.aiida'})
    child=isolated('aiida/engine/daemon/client.py','get_env',
        {'os':environment,'sys':sys,'get_config':lambda:types.SimpleNamespace(dirpath=str(directory))})
    assert str(directory)==base+'/.aiida' and child['AIIDA_PATH']==str(directory)
    return {key:child[key] for key in ('AIIDA_PATH','QCL_NEGF_NATIVE_JOBS_ROOT')}


@pytest.mark.parametrize('fault',[None,'main_derived','all_base','leaf_base','worker_base','circus_base','jobs',
    'changed','changed_main','changed_worker','changed_circus'])
def test_pinned_stock_aiida_role_environments_and_distinguishing_negatives(fault):
    m=module();sources=PeerSources();cfg=sources.configuration
    child=stock_aiida_descendant_environment(cfg['aiida_path'],cfg['jobs_root']);counts={}
    def environment(pid):
        counts[pid]=counts.get(pid,0)+1
        value={**child,'AIIDA_PATH':cfg['aiida_path']} if pid==123 else dict(child)
        if fault=='main_derived' and pid==123:value=dict(child)
        if fault=='all_base' or pid=={'leaf_base':456,'worker_base':345,'circus_base':234}.get(fault):
            value['AIIDA_PATH']=cfg['aiida_path']
        if fault=='jobs' and pid==345:value['QCL_NEGF_NATIVE_JOBS_ROOT']='/other'
        if pid=={'changed':456,'changed_main':123,'changed_worker':345,'changed_circus':234}.get(fault) and counts[pid]>1:
            value['AIIDA_PATH']='/changed/.aiida'
        return value
    sources.selected_environment=environment
    class Connection:
        def getsockopt(self,*args):return struct.pack('3i',456,3000,3000)
    if fault:
        with pytest.raises(m.Hold):m.authenticate_socket_peer(Connection(),sources.policy,sources,action='submit')
    else:
        packet=m.authenticate_socket_peer(Connection(),sources.policy,sources,action='submit')
        assert [entry['environment']['AIIDA_PATH'] for entry in packet['chain']]==[child['AIIDA_PATH']]*3+[cfg['aiida_path']]


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


def test_actor_preflight_receives_actual_calcjob_and_action_before_claim(tmp_path):
    m = module()
    class ActualRequest(Observations):
        def preflight(self, launch, budget, *, calcjob_uuid=None, action=None):
            self.observed = (calcjob_uuid, action)
            return super().preflight(launch, budget)
    sources = ActualRequest(m); selected, _ = owner(tmp_path, sources)
    assert selected.submit(request())['state'] == 'bound'
    assert sources.observed == (request()['calcjob_uuid'], 'submit')


def bridge_inputs():
    """Public actor output fixture, stock scheduler bytes; no ORM/profile load."""
    from aiida.schedulers.plugins.slurm import SlurmScheduler
    from aiida.schedulers.datastructures import JobTemplate, JobTemplateCodeInfo
    from aiida.common.datastructures import CodeRunMode
    from test_application_release import RetainedReleaseSourcesTests, delivery_manifest
    m = module(); document = request(); launch = document['launch']
    graph = RetainedReleaseSourcesTests.RAW
    value = {**delivery_manifest(False), 'sources': json.loads(graph), 'solver_build': {
        'source_graph_sha256': hashlib.sha256(graph).hexdigest(), 'julia_manifest_sha256': 'd'*64,
        'drv_path': '/nix/store/solver.drv', 'output_path': '/nix/store/solver'}}
    launch['release_id'] = value['release_id']; plan = b' \n{"original":"frozen-plan"}\n'
    def ref(node, raw): return dict(node_uuid=node, bytes=str(len(raw)), sha256=hashlib.sha256(raw).hexdigest())
    native = dict(schema='qcl-negf.aiida-native-execution.v1', request_id=launch['request_id'],
        execution_id=launch['execution_id'], input_plan=ref(launch['input_plan_uuid'], plan),
        source_graph=ref(launch['source_graph_uuid'], graph), access_receipt_ref='untrusted-locator',
        code=dict(code_uuid=launch['code_uuid'], computer_uuid=document['calcjob_uuid'],
            solver_executable=value['solver_executable'], release_id=value['release_id'], build_receipt_ref='locator'),
        storage=dict(namespace_id='managed', storage_identity='storage',
            relative_execution_root=launch['relative_execution_root'], computer_uuid=document['calcjob_uuid'],
            execution_binding_uuid=launch['native_execution_uuid'], retention_policy_id='retain',
            retention_owner_id='team', hold_ref='locator', access_binding_ref='locator'))
    raw_native = b' \n' + m.encoded(native) + b'\n'
    scheduler = SlurmScheduler(); template = JobTemplate()
    template.shebang = '#!/nix/store/bash/bin/bash'; template.rerunnable = False
    template.job_name = 'aiida-1'; template.import_sys_environment = True
    template.sched_output_path = '_scheduler-stdout.txt'; template.sched_error_path = '_scheduler-stderr.txt'
    template.job_resource = scheduler.create_job_resource(num_machines=1, num_mpiprocs_per_machine=1, num_cores_per_mpiproc=2)
    template.job_environment = {'JULIA_NUM_THREADS':'2', 'OPENBLAS_NUM_THREADS':'1'}
    template.prepend_text = ('/run/current-system/sw/bin/qcl-negf-release guard --release-id release-a '
                            '--solver-executable /nix/store/solver/bin/qcl-negf || exit 78\nunset QCL_NEGF_CAPTURE_SPEC')
    code = JobTemplateCodeInfo(); code.prepend_cmdline_params = [value['solver_executable']]
    code.cmdline_params = ['run-plan', 'plan.json', '/srv/qcl-negf/jobs/'+launch['relative_execution_root'],
                          '--execution-id', launch['execution_id'], '--source-graph', 'source-graph.json']
    code.use_double_quotes = [False,False]; code.stdout_name = 'solver.stdout'; code.stderr_name = 'solver.stderr'
    template.codes_info = [code]; template.codes_run_mode = CodeRunMode.SERIAL
    script = scheduler.get_submit_script(template).encode()
    files = dict(plan=plan, source_graph=graph, native_execution=raw_native, submit_script=script)
    launch['files'] = {key:dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()) for key,raw in files.items()}
    return document, value, files, native


@pytest.fixture
def actor_bridge(monkeypatch):
    m = module(); document, value, files, native = bridge_inputs(); launch = document['launch']
    policy = dict(jobs_root='/srv/qcl-negf/jobs',native_result_prefix='native',release_runtime='/protected/runtime',
        client_uid=3000, tools=dict(runuser='/nix/store/runuser'), limits={**limits(), 'metadata_bytes':8*1024*1024})
    sources = m.NativeSources(policy,m.Operation(policy['limits']))
    host = dict(machine_id='a'*32,boot_id=launch['request_id'],image_id='/nix/store/image')
    sources.qualification = dict(write_domain={'storage_identity':'storage'})
    monkeypatch.setattr(sources,'qualify',lambda:host)
    context = dict(app=value['application_path'],configuration=PeerSources().configuration)
    monkeypatch.setattr(sources,'_refresh_caller',lambda action: {'application':context},raising=False)
    def read(path,*args):
        path = str(path)
        if path.endswith('source-graph-'+hashlib.sha256(files['source_graph']).hexdigest()+'.json'):return files['source_graph']
        if '/records/release-' in path:return m.encoded({**value,'code_uuid':launch['code_uuid'],
            'quantum_runtime_context':m.engine.quantum_context(value)})
        if path.endswith('/release.json'):return m.encoded({**value,'ready':True,'code_uuid':launch['code_uuid']})
        raise AssertionError(path)
    monkeypatch.setattr(m,'protected_read',read)
    monkeypatch.setattr(m,'_read_submitted_files_as_owner',lambda *args:dict(files=launch['files'],script=base64_script(files['submit_script'])))
    monkeypatch.setattr(m.engine,'public_binary_origin',lambda budget,path,**kw: {'path':path})
    monkeypatch.setattr(m.engine,'admission_reader',lambda path: __import__('contextlib').nullcontext())
    monkeypatch.setattr(sources.budget,'read',lambda path,limit=65536:m.encoded(dict(open=True,release_id=value['release_id'])))
    calls=[]; actor_launch=copy.deepcopy(launch)
    state=dict(m=m,document=document,value=value,files=files,native=native,sources=sources,host=host,
               actor_launch=actor_launch,context=context,calls=calls,gate=True,ready=True,fault=None)
    def run(argv,**kw):
        calls.append((argv,kw))
        if state['fault']=='query':raise m.engine.CommandFailure(dict(failure='timeout',cleanup_confirmed=False,
            stdout='original actor prefix',stderr='original query failure',child_started=True))
        raw=m.encoded(actor_launch) if 'launch' in argv else files['native_execution']
        output=m.engine.CommandOutput(raw.decode());output.output_bytes=len(raw)+(1 if state['fault']=='partial' else 0)
        return output
    monkeypatch.setattr(m.engine,'command',run)
    def read_current(path,*args):
        if str(path).endswith('/release.json'):return m.encoded({**value,'ready':state['ready'],'code_uuid':launch['code_uuid']})
        return read(path,*args)
    monkeypatch.setattr(m,'protected_read',read_current)
    monkeypatch.setattr(sources.budget,'read',lambda path,limit=65536:m.encoded(dict(open=state['gate'],release_id=value['release_id'])))
    state['run']=run
    return state


def test_original_actor_launch_raw_bytes_and_stock_script_join_preflight(actor_bridge):
    state=actor_bridge;sources=state['sources'];document=state['document'];launch=document['launch'];calls=state['calls']
    assert sources.preflight(launch,sources.budget,calcjob_uuid=document['calcjob_uuid'],action='submit')==state['host']
    assert [row[0][-4] for row in calls]==['launch','execution']
    assert all(row[1]['deadline']==sources.budget.deadline for row in calls)


@pytest.mark.parametrize('fault',['launch','partial','raw','fullref','code','storage','legacy_attempt','extra_shell',
    'directive','duplicate_header','scratch','output','thread','unquoted','gate','ready','budget','query'])
def test_actor_script_reference_and_budget_negatives_precede_claim(actor_bridge,tmp_path,fault):
    state=actor_bridge;m=state['m'];document=state['document'];launch=document['launch'];files=state['files'];sources=state['sources']
    if fault=='launch':state['actor_launch']['transport_attempt']+=1
    if fault in {'partial','query'}:state['fault']=fault
    if fault=='raw':files['native_execution']+=b' '
    if fault in {'fullref','code','storage'}:
        native=state['native']
        if fault=='fullref':native['input_plan']['node_uuid']=document['calcjob_uuid']
        if fault=='code':native['code']['solver_executable']='/nix/store/foreign/bin/qcl-negf'
        if fault=='storage':native['storage']['storage_identity']='foreign'
        files['native_execution']=m.encoded(native)
    if fault in {'legacy_attempt','extra_shell','directive','duplicate_header','scratch','output','thread','unquoted'}:
        script=files['submit_script']
        if fault=='legacy_attempt':script=script.replace(b"  >",b" '--attempt' '1'  >")
        if fault=='extra_shell':script+=b'\necho unsafe\n'
        if fault=='directive':script=script.replace(b'#SBATCH --no-requeue',b'#SBATCH --wrap=unsafe')
        if fault=='duplicate_header':script=script.replace(b'#SBATCH --nodes=1',b'#SBATCH --nodes=1\n#SBATCH --nodes=1')
        if fault=='scratch':script=script.replace(b"  >",b" '--scratch-root' '/free/path'  >")
        if fault=='output':script=script.replace(b'/srv/qcl-negf/jobs/native/',b'/outside/native/')
        if fault=='thread':script=script.replace(b"JULIA_NUM_THREADS='2'",b"JULIA_NUM_THREADS='3'")
        if fault=='unquoted':script=script.replace(b"'run-plan'",b'run-plan')
        files['submit_script']=script
    if fault in {'fullref','code','storage','legacy_attempt','extra_shell','directive','duplicate_header','scratch','output','thread','unquoted'}:
        launch['files']={key:dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()) for key,raw in files.items()}
        state['actor_launch'].update(copy.deepcopy(launch))
    if fault=='gate':state['gate']=False
    if fault=='ready':state['ready']=False
    if fault=='budget':sources.budget.bytes=sources.budget.limits['metadata_bytes']
    selected=m.OrdinaryAttemptOwner(sources.policy,m.AttemptStore(tmp_path),sources,sources.budget)
    result=selected.submit(document)
    assert result['state']=='hold' and not (tmp_path/'attempts').exists()
    assert not any('--parsable' in row[0] for row in state['calls'])


# Exact synthetic presubmit bytes frozen by the AiiDA owner on 2026-10-30.
# This exercises its actual literal output without importing mutable producer source.
NATIVE_ORIGIN_SCRIPT = b"""#!/bin/bash
#SBATCH --no-requeue
#SBATCH --job-name="aiida-16"
#SBATCH --get-user-env
#SBATCH --output=_scheduler-stdout.txt
#SBATCH --error=_scheduler-stderr.txt
#SBATCH --nodes=1
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=1
#SBATCH --time=01:00:00

# ENVIRONMENT VARIABLES BEGIN ###
export JULIA_NUM_THREADS='1'
export OPENBLAS_NUM_THREADS='1'
# ENVIRONMENT VARIABLES END ###

/run/current-system/sw/bin/qcl-negf-release guard --release-id fixture-release --solver-executable /nix/store/synthetic/bin/qcl-negf || exit 78
unset QCL_NEGF_CAPTURE_SPEC

'/nix/store/synthetic/bin/qcl-negf' 'run-plan' 'plan.json' '/srv/qcl-negf/jobs/native/new-domain' '--execution-id' 'execution' '--source-graph' 'source-graph.json' '--native-execution' 'native-execution.json' '--native-calcjob-uuid' 'e3fd840b-a169-4061-ab35-0b68bd97215f'  > 'solver.stdout' 2> 'solver.stderr'
"""
NATIVE_ORIGIN_CALCJOB = 'e3fd840b-a169-4061-ab35-0b68bd97215f'


def test_native_origin_actual_frozen_presubmit_literal_and_legacy_unmapped(monkeypatch):
    m = module(); sources = m.NativeSources({'jobs_root':'/srv/qcl-negf/jobs'},m.Operation(limits()))
    monkeypatch.setattr(sources,'origin',lambda path:path)
    assert hashlib.sha256(NATIVE_ORIGIN_SCRIPT).hexdigest() == '4f15f14ac98ff6a5a7c38d2bc096ec4ee8165fa28052d12f372ac0eee8d05c6b'
    launch = request()['launch']
    launch.update(release_id='fixture-release',execution_id='execution',relative_execution_root='native/new-domain')
    assert m._review_native_script(NATIVE_ORIGIN_SCRIPT,launch,'/nix/store/synthetic/bin/qcl-negf',
        '/bin/bash',sources,calcjob_uuid=NATIVE_ORIGIN_CALCJOB) is None
    # The old seven-argument class remains accepted without an origin assertion.
    suffix = (" '--native-execution' 'native-execution.json' '--native-calcjob-uuid' '"+
              NATIVE_ORIGIN_CALCJOB+"'").encode()
    legacy = NATIVE_ORIGIN_SCRIPT.replace(suffix,b'')
    assert legacy != NATIVE_ORIGIN_SCRIPT
    assert m._review_native_script(legacy,launch,'/nix/store/synthetic/bin/qcl-negf',
        '/bin/bash',sources,calcjob_uuid=request()['calcjob_uuid']) is None
    assert not hasattr(sources,'_actor')


@pytest.mark.parametrize('calcjob',[
    NATIVE_ORIGIN_CALCJOB.upper(), NATIVE_ORIGIN_CALCJOB.replace('-',''),
    NATIVE_ORIGIN_CALCJOB+'\n', '00000000-0000-0000-0000-000000000000', None])
def test_native_origin_script_requires_canonical_authenticated_uuid(monkeypatch,calcjob):
    m = module(); sources = m.NativeSources({'jobs_root':'/srv/qcl-negf/jobs'},m.Operation(limits()))
    monkeypatch.setattr(sources,'origin',lambda path:path)
    launch = request()['launch']
    launch.update(release_id='fixture-release',execution_id='execution',relative_execution_root='native/new-domain')
    script = NATIVE_ORIGIN_SCRIPT.replace(NATIVE_ORIGIN_CALCJOB.encode(),str(calcjob).encode())
    with pytest.raises(m.Hold):
        m._review_native_script(script,launch,'/nix/store/synthetic/bin/qcl-negf',
            '/bin/bash',sources,calcjob_uuid=calcjob)


def native_origin_bridge_script(state):
    suffix = (" '--native-execution' 'native-execution.json' '--native-calcjob-uuid' '"+
              state['document']['calcjob_uuid']+"'  >").encode()
    return state['files']['submit_script'].replace(b'  >',suffix)


def replace_bridge_script(state,script):
    state['files']['submit_script'] = script
    claim = dict(bytes=len(script),sha256=hashlib.sha256(script).hexdigest())
    state['document']['launch']['files']['submit_script'] = claim
    state['actor_launch']['files']['submit_script'] = copy.deepcopy(claim)


@pytest.mark.parametrize('native_origin',[False,True])
def test_native_origin_preflight_passes_actual_request_uuid(actor_bridge,monkeypatch,native_origin):
    state=actor_bridge;m=state['m'];sources=state['sources'];document=state['document']
    if native_origin: replace_bridge_script(state,native_origin_bridge_script(state))
    original = m._review_native_script; observed=[]
    def review(*args,**kwargs):
        observed.append(kwargs.copy())
        return original(*args,**kwargs)
    monkeypatch.setattr(m,'_review_native_script',review)
    assert sources.preflight(document['launch'],sources.budget,
        calcjob_uuid=document['calcjob_uuid'],action='submit')==state['host']
    assert observed==[{'calcjob_uuid':document['calcjob_uuid']}]
    assert all(document['calcjob_uuid'] in row[0] for row in state['calls'])
    assert not any(document['launch'][key]==document['calcjob_uuid'] for key in
        ('request_id','native_execution_uuid','input_plan_uuid','source_graph_uuid','code_uuid'))


@pytest.mark.parametrize('fault',[
    'request_uuid','native_uuid','plan_uuid','missing_native','missing_calcjob','missing_value',
    'native_alias','native_absolute','extra','duplicate','reordered','unquoted','doublequoted',
    'substitution','extra_shell','environment','capture','scratch'])
def test_native_origin_script_controls_hold_before_claim(actor_bridge,tmp_path,fault):
    state=actor_bridge;m=state['m'];document=state['document'];launch=document['launch'];sources=state['sources']
    script=native_origin_bridge_script(state)
    native=b" '--native-execution' 'native-execution.json'"
    calcjob=(" '--native-calcjob-uuid' '"+document['calcjob_uuid']+"'").encode()
    if fault in {'request_uuid','native_uuid','plan_uuid'}:
        key={'request_uuid':'request_id','native_uuid':'native_execution_uuid','plan_uuid':'input_plan_uuid'}[fault]
        script=script.replace(calcjob,(" '--native-calcjob-uuid' '"+launch[key]+"'").encode())
    if fault=='missing_native':script=script.replace(native,b'')
    if fault=='missing_calcjob':script=script.replace(calcjob,b'')
    if fault=='missing_value':script=script.replace(calcjob,b" '--native-calcjob-uuid'")
    if fault=='native_alias':script=script.replace(b"'native-execution.json'",b"'./native-execution.json'")
    if fault=='native_absolute':script=script.replace(b"'native-execution.json'",b"'/srv/qcl-negf/jobs/upload/one/native-execution.json'")
    if fault=='extra':script=script.replace(b'  >',b" '--attempt' '1'  >")
    if fault=='duplicate':script=script.replace(calcjob,calcjob+calcjob)
    if fault=='reordered':script=script.replace(native+calcjob,calcjob+native)
    if fault=='unquoted':script=script.replace(b"'--native-execution'",b'--native-execution')
    if fault=='doublequoted':script=script.replace(b"'native-execution.json'",b'"native-execution.json"')
    if fault=='substitution':script=script.replace(b"'native-execution.json'",b'"$(echo native-execution.json)"')
    if fault=='extra_shell':script+=b'\necho unsafe\n'
    if fault=='environment':script=script.replace(b"'run-plan'",b"QCL_ORIGIN=1 'run-plan'")
    if fault=='capture':script=script.replace(b'unset QCL_NEGF_CAPTURE_SPEC',b"export QCL_NEGF_CAPTURE_SPEC='capture.json'")
    if fault=='scratch':script=script.replace(b'  >',b" '--scratch-root' '/free/path'  >")
    replace_bridge_script(state,script)
    selected=m.OrdinaryAttemptOwner(sources.policy,m.AttemptStore(tmp_path),sources,sources.budget)
    result=selected.submit(document)
    assert result['state']=='hold' and not (tmp_path/'attempts').exists()
    assert result['reason']==('native_scratch_binding_unavailable' if fault=='scratch' else
                             'native_script' if fault=='extra_shell' else
                             'native_script_guard' if fault=='capture' else 'native_script_argv')
    assert not any('--parsable' in row[0] for row in state['calls'])


@pytest.mark.parametrize('action',['reconcile','status','start','close'])
def test_operational_original_input_reads_remain_possible_with_admission_closed(actor_bridge,action):
    state=actor_bridge;state['gate']=state['ready']=False;sources=state['sources']
    assert sources.preflight(state['document']['launch'],sources.budget,
        calcjob_uuid=state['document']['calcjob_uuid'],action=action)==state['host']


def test_actor_query_failure_keeps_bounded_original_before_claim(actor_bridge,tmp_path,capsys):
    state=actor_bridge;m=state['m'];state['fault']='query';sources=state['sources']
    selected=m.OrdinaryAttemptOwner(sources.policy,m.AttemptStore(tmp_path),sources,sources.budget)
    assert selected.submit(state['document'])['state']=='hold'
    diagnostic=json.loads(capsys.readouterr().err.split('native-attempt preclaim HOLD: ',1)[1])
    import base64
    original=json.loads(base64.b64decode(diagnostic['original_prefix_base64']))
    assert original['stdout']=='original actor prefix' and original['cleanup_confirmed'] is False
    assert not (tmp_path/'attempts').exists()


@pytest.mark.parametrize('large',[False,True])
def test_actual_ingress_environment_command_failure_keeps_bounded_original(monkeypatch,capsys,large):
    import base64
    m=module();budget=m._bootstrap_operation();captured=[];commands=[]
    policy={'client_uid':3000,'daemon_unit':'qcl-negf-aiida.service',
        'tools':{'systemctl':'/nix/store/systemctl'},'limits':budget.limits}
    source=m.NativeSources(policy,budget);source._server_unit='qcl-negf-native-attempt@one.service'
    monkeypatch.setattr(source,'qualify',lambda:None)
    original={'failure':'timeout','returncode':None,'stdout':'unique-original-P3-prefix'+('x'*40000 if large else ''),
        'stderr':'original fixture diagnostic','cleanup_confirmed':False}
    primary=m.engine.CommandFailure(original)
    def failed(argv):
        commands.append(argv)
        assert argv==['/nix/store/systemctl','show',source._server_unit,'--property=Environment','--value']
        raise primary
    monkeypatch.setattr(source,'run',failed)
    monkeypatch.setattr(m,'_bootstrap_operation',lambda:budget)
    monkeypatch.setattr(m,'_load_policy',lambda *args:policy)
    monkeypatch.setattr(m,'_authenticate_server',lambda sources:None)
    monkeypatch.setattr(m,'NativeSources',lambda policy,budget:source)
    monkeypatch.setattr(m,'read_frame',lambda *args:request())
    monkeypatch.setattr(m,'write_frame',lambda connection,result,*args:captured.append(result))
    def no_owner(*args):raise AssertionError('preowner failure must not construct an AttemptStore')
    monkeypatch.setattr(m,'AttemptStore',no_owner)
    monkeypatch.setenv('QCL_NEGF_NATIVE_ACTOR_CONFIG','/nix/store/config/actor.json')
    class Connection:
        def getsockopt(self,*args):return struct.pack('3i',456,3000,3000)
    m.handle_connection(Connection())
    assert len(commands)==1 and captured==[m.reply({},'hold',reason='native_observation_failed')]
    assert 'unique-original-P3-prefix' not in json.dumps(captured)
    stderr=capsys.readouterr().err
    retained=json.loads(stderr.split('native-attempt preclaim HOLD: ',1)[1])
    raw=m.encoded(original)
    assert base64.b64decode(retained['original_prefix_base64'])==raw[:24576]
    assert retained=={'original_prefix_base64':base64.b64encode(raw[:24576]).decode('ascii'),
        'original_bytes':len(raw),'original_sha256':hashlib.sha256(raw).hexdigest(),'truncated':len(raw)>24576}
    assert primary.record is original and original['cleanup_confirmed'] is False and len(stderr)<34000


@pytest.mark.parametrize('secondary',[OSError('stderr unavailable'),KeyboardInterrupt('secondary write')])
def test_preclaim_diagnostic_write_failure_cannot_replace_primary_hold(monkeypatch,secondary):
    m=module();budget=m._bootstrap_operation();captured=[];calls=[]
    primary=m.engine.CommandFailure({'failure':'timeout','stdout':'original','cleanup_confirmed':False})
    def failed(*args,**kwargs):calls.append('original');raise primary
    monkeypatch.setattr(m,'_bootstrap_operation',lambda:budget)
    monkeypatch.setattr(m,'_load_policy',failed)
    monkeypatch.setattr(m,'write_frame',lambda connection,result,*args:captured.append(result))
    class BrokenStderr:
        def write(self,*args):raise secondary
        def flush(self):pass
    monkeypatch.setattr(m.sys,'stderr',BrokenStderr())
    m.handle_connection(object())
    assert calls==['original'] and captured==[m.reply({},'hold',reason='native_observation_failed')]
    assert primary.record=={'failure':'timeout','stdout':'original','cleanup_confirmed':False}


@pytest.mark.parametrize('scenario',['bound','lost_ack','withdraw_before_intent'])
def test_joined_native_owner_caller_actor_script_and_same_key_reentry(actor_bridge,tmp_path,monkeypatch,scenario):
    """Production owner/preflight/auth/intent/dispatch/join; OS/CLI facts are fixtures."""
    state=actor_bridge;m=state['m'];policy=state['sources'].policy
    policy.update(spool_root='/local/spool',daemon_unit='qcl-negf-aiida.service',server_unit_prefix='qcl-negf-native-attempt@',
                  slurm=dict(cluster='cluster',config_file='/etc/slurm.conf'))
    policy['tools'].update(sbatch='/nix/store/sbatch',scontrol='/nix/store/scontrol')
    dispatches=[];state['lost']=scenario=='lost_ack'
    root_executable='/nix/store/root-python';server_unit='qcl-negf-native-attempt@fixture.service'
    peers=PeerSources();current={'peer':456,'action':'submit'}
    qualification={'write_domain':{'storage_identity':'storage'},'unit_origins':{
        'server':{'executable':root_executable},policy['daemon_unit']:{'executable':peers.python}}}
    original_command=m.engine.command
    def command(argv,**kw):
        if '--parsable' in argv:
            dispatch=argv[argv.index('--comment')+1];dispatches.append((dispatch,argv[-1]))
            if state['lost']:raise m.engine.CommandFailure(dict(failure='timeout',cleanup_confirmed=False,
                child_started=True,stdout='lost original ACK',stderr=''))
            text='42;cluster\n'
        elif policy['tools']['scontrol'] in argv:
            dispatch,path=dispatches[0]
            text=('JobId=42 UserId=qcl-negf(3000) SubmitTime=2026-10-30T01:00:00 WorkDir='+state['document']['launch']['remote_workdir']+
                  ' Comment='+dispatch+' Command='+path+' Restarts=0 NumNodes=1 NumTasks=1')
        else:return original_command(argv,**kw)
        result=m.engine.CommandOutput(text);result.output_bytes=len(text);return result
    monkeypatch.setattr(m.engine,'command',command)
    monkeypatch.setattr(m,'trusted_root_path',lambda path,**kw:Path(path))
    class Connection:
        def getsockopt(self,*args):return struct.pack('3i',current['peer'],3000,3000)
    def fresh(action,pid):
        current.update(action=action,peer=pid)
        source=m.NativeSources(policy,m.Operation(policy['limits']));source.qualification=qualification
        monkeypatch.setattr(source,'qualify',lambda:state['host']);monkeypatch.setattr(source,'host',lambda:state['host'])
        monkeypatch.setattr(source,'actor_context',lambda:state['context'])
        monkeypatch.setattr(source,'profile_view',peers.profile_view);monkeypatch.setattr(source,'origin',lambda path:path)
        monkeypatch.setattr(source,'selected_environment',peers.selected_environment)
        def process(which):
            if which==os.getpid():return dict(pid=which,ppid=1,start_ticks=2,uids=[0]*4,state='S',comm='python',
                cgroup='/system.slice/'+server_unit,executable=root_executable,observations={'changing':peers.count})
            row=peers.process(456 if which==pid else which)
            if which==pid:row.update(pid=pid,start_ticks=50)
            return row
        monkeypatch.setattr(source,'process',process)
        monkeypatch.setattr(source,'command_line',lambda which:peers.configuration['client']['argv_prefix']+[action]
            if which==pid else peers.command_line(which))
        monkeypatch.setattr(source,'unit',lambda name:dict(MainPID=str(os.getpid()),ControlGroup='/system.slice/'+server_unit,
            InvocationID='b'*32,ActiveState='active',MemoryMax='134217728',RuntimeMaxUSec='90s')
            if name==server_unit else peers.unit(name))
        monkeypatch.setattr(source,'snapshot',lambda launch,dispatch,budget:dict(script_path='/local/spool/'+dispatch+'.sh',
            script_sha256=launch['files']['submit_script']['sha256']))
        monkeypatch.setattr(source,'_check_snapshot',lambda snapshot:None)
        monkeypatch.setattr(source.budget,'read',lambda path,limit=65536:m.encoded(dict(open=state['gate'],release_id=state['value']['release_id'])))
        m._authenticate_server(source)
        source._caller=m.authenticate_socket_peer(Connection(),policy,source,action=action)
        if scenario=='withdraw_before_intent' and action=='submit' and not (tmp_path/'attempts').exists():
            refresh=source._refresh_caller;calls=[0]
            def withdrawing(selected):
                calls[0]+=1
                if calls[0]==3:state['gate']=False
                return refresh(selected)
            monkeypatch.setattr(source,'_refresh_caller',withdrawing)
        return m.OrdinaryAttemptOwner(policy,m.AttemptStore(tmp_path),source,source.budget)
    first=fresh('submit',456).submit(state['document'])
    directory=tmp_path/'attempts'/state['document']['calcjob_uuid']
    assert (directory/'claim.json').is_file()
    if scenario=='withdraw_before_intent':
        assert first['state']=='hold' and dispatches==[]
        state['gate']=True
        again=fresh('reconcile',567).reconcile({**state['document'],'action':'reconcile'})
        assert again['state']=='hold' and again['reason']=='partial_claim' and dispatches==[]
    elif scenario=='lost_ack':
        assert first['reason']=='dispatch_outcome_unknown' and len(dispatches)==1
        original=(directory/'failure.json').read_bytes();state['lost']=False
        again=fresh('reconcile',567).reconcile({**state['document'],'action':'reconcile'})
        assert again['reason']=='dispatch_outcome_unknown' and len(dispatches)==1
        assert (directory/'failure.json').read_bytes()==original
    else:
        assert first['state']=='bound' and len(dispatches)==1
        state['ready']=state['gate']=False
        again=fresh('status',567).status({**state['document'],'action':'status'})
        assert again['state']=='bound' and again['job']==first['job'] and len(dispatches)==1
        retained=json.loads((directory/'dispatch.json').read_bytes())['native']['owner']
        assert retained['caller']['pid']==456 and retained['actor']['calcjob_uuid']==state['document']['calcjob_uuid']
        assert set(json.loads((directory/'claim.json').read_bytes())['context'])=={'machine_id','boot_id','image_id'}


@pytest.mark.parametrize('fault',[None,'alias_target','alias_owner','mutable_ancestor'])
def test_actor_app_selection_reuses_public_nix_origin_and_root_profile(monkeypatch,fault):
    m=module();from test_application_release import delivery_manifest
    sources=m.NativeSources({'release_runtime':'/protected/runtime'},m.Operation(limits()))
    cfg=PeerSources().configuration;value=delivery_manifest(False);app=value['application_path']
    monkeypatch.setattr(sources,'actor_configuration',lambda:cfg)
    monkeypatch.setattr(m,'protected_read',lambda *args:m.encoded(value))
    def info(mode,uid=0):return (1,1,mode,uid,0,0,0)
    chain=[('/nix',info(m.stat.S_IFDIR|0o755),None),('/nix/store',info(m.stat.S_IFDIR|0o1775),None),
        ('/nix/var/nix/profiles',info(m.stat.S_IFDIR|(0o777 if fault=='mutable_ancestor' else 0o755)),None),
        (cfg['application_profile'],info(m.stat.S_IFLNK|0o777,3000 if fault=='alias_owner' else 0),app),
        ('/nix/store/other' if fault=='alias_target' else app,info(m.stat.S_IFDIR|0o555),None)]
    monkeypatch.setattr(m.engine,'public_binary_origin',lambda budget,path,**kw:{'path':path,'chain':chain})
    if fault:
        with pytest.raises(m.Hold):sources.actor_context()
    else:assert sources.actor_context()['app']==app


def test_exact_s1_bash_hop_and_fixed_client_alias_are_joined():
    m=module();sources=PeerSources();original_process=sources.process;original_command=sources.command_line
    def process(pid):
        if pid==400:return dict(pid=400,ppid=345,start_ticks=35,uids=[3000]*4,state='S',comm='bash',
            cgroup='/system.slice/qcl-negf-aiida.service/worker',executable='/nix/store/bash/bin/bash',observations={})
        row=original_process(pid)
        if pid==456:row['ppid']=400
        return row
    sources.process=process
    sources.command_line=lambda pid:['bash','--noprofile','--norc','-c',
        '/run/current-system/sw/bin/qcl-negf-native-attempt-client submit'] if pid==400 else original_command(pid)
    sources.origin=lambda path:sources.configuration['client']['entrypoint'] if path=='/run/current-system/sw/bin/qcl-negf-native-attempt-client' else path
    class Connection:
        def getsockopt(self,*args):return struct.pack('3i',456,3000,3000)
    assert [row['process']['pid'] for row in m.authenticate_socket_peer(Connection(),sources.policy,sources,action='submit')['chain']]==[456,400,345,234,123]


def test_existing_journal_encoding_is_prepaid_for_long_original_transport_int():
    m=module();budget=m.Operation(limits());value={'transport_attempt':10**1000}
    m._reserve_private_record(value,budget)
    assert budget.bytes>=len(m.encoded(value))
    first=budget.bytes;m._reserve_private_record(value,budget)
    assert budget.bytes==2*first


def test_native_off_evaluator_preserves_two_coerced_script_identity_assertion():
    source=(Path(__file__).parent/'infrastructure/native-attempt.nix').read_text()
    assert 'assert toString off.systemd.services.qcl-negf-aiida.serviceConfig.ExecStart == toString originalDaemonStart;' in source


def test_current_profile_alias_argv_cannot_certify_already_loaded_app():
    m=module();sources=PeerSources();command=sources.command_line
    sources.command_line=lambda pid:[part.replace(sources.app+'/bin/verdi',sources.profile+'/bin/verdi')
                                     for part in command(pid)]
    class Connection:
        def getsockopt(self,*args):return struct.pack('3i',456,3000,3000)
    with pytest.raises(m.Hold,match='application_origin'):
        m.authenticate_socket_peer(Connection(),sources.policy,sources,action='submit')


def test_old_mainpid_immutable_argv_does_not_follow_retargeted_profile():
    m=module();sources=PeerSources();command=sources.command_line
    sources.actor_context=lambda:{'app':'/nix/store/new-application','configuration':sources.configuration}
    sources.command_line=command  # Actual old PID keeps the old immutable APP argv.
    class Connection:
        def getsockopt(self,*args):return struct.pack('3i',456,3000,3000)
    with pytest.raises(m.Hold,match='application_origin'):
        m.authenticate_socket_peer(Connection(),sources.policy,sources,action='submit')


@pytest.mark.parametrize('fault',[None,'unit_selection','extra','jobs_root'])
def test_fixed_actor_configuration_joins_qualified_unit_and_immutable_source(monkeypatch,fault):
    m=module();sources=m.NativeSources(dict(jobs_root='/srv/qcl-negf/jobs',tools={'systemctl':'/nix/store/systemctl'}),m.Operation(limits()))
    sources._server_unit='qcl-negf-native-attempt@one.service'
    config={'schema':'qcl-negf.native-actor-launch.v1','profile':'qcl-negf',
        'aiida_path':'/var/lib/qcl-negf/aiida','application_profile':'/nix/var/nix/profiles/qcl-negf-application',
        'jobs_root':'/srv/qcl-negf/jobs','client':PeerSources().configuration['client']}
    if fault=='extra':config['verified']=True
    if fault=='jobs_root':config['jobs_root']='/other'
    path='/nix/store/config/actor.json';monkeypatch.setenv('QCL_NEGF_NATIVE_ACTOR_CONFIG',path)
    monkeypatch.setattr(m.engine,'public_binary_origin',lambda budget,path,**kw:{'path':path})
    monkeypatch.setattr(m.engine,'immutable_public_bytes',lambda *args:m.encoded(config))
    monkeypatch.setattr(sources,'run',lambda argv:'QCL_NEGF_NATIVE_ACTOR_CONFIG='+('/other' if fault=='unit_selection' else path))
    if fault:
        with pytest.raises(m.Hold):sources.actor_configuration()
    else:assert sources.actor_configuration()==config


@pytest.mark.parametrize('fault',[None,'alias','writable','log_alias','config_rw','view_changed'])
def test_existing_profile_view_actual_fd_reads_no_bootstrap_or_lock_cleanup(tmp_path,monkeypatch,fault):
    m=module();config=PeerSources().configuration;root=tmp_path/'namespace'
    folder=root/'var/lib/qcl-negf/aiida/.aiida';(folder/'access/qcl-negf').mkdir(parents=True);(folder/'log').mkdir()
    (folder/'config.json').write_bytes(b'{"fixture":"not a real profile or credential"}')
    (folder/'access/qcl-negf/unknown.lock').write_bytes(b'unknown owner; preserve')
    if fault=='alias':(folder/'config.json').rename(folder/'original');(folder/'config.json').symlink_to('original')
    if fault=='writable':(folder/'config.json').chmod(0o666)
    if fault=='log_alias':(folder/'log/aiida-qcl-negf.log').symlink_to('../config.json')
    sources=m.NativeSources({'client_uid':os.getuid()},m.Operation(limits()));opened=os.open
    def namespace(path,*args,**kwargs):
        text=str(path)
        if text.startswith('/proc/') and text.endswith('/root'):return opened(root,*args,**kwargs)
        return opened(path,*args,**kwargs)
    monkeypatch.setattr(m.os,'open',namespace)
    def mountinfo(path,limit=65536):
        assert str(path).endswith('/mountinfo')
        if fault=='view_changed' and '/123/' in str(path):(folder/'config.json').write_bytes(b'changed')
        return ('1 0 0:1 / /var/lib/qcl-negf/aiida/.aiida/config.json '+
                ('rw' if fault=='config_rw' else 'ro')+' - ext4 /dev/fixture rw\n').encode()
    monkeypatch.setattr(sources.budget,'read',mountinfo)
    if fault:
        with pytest.raises((m.Hold,OSError)):sources.profile_view(123,{'configuration':config})
    else:
        result=sources.profile_view(123,{'configuration':config})
        assert result['sha256']==hashlib.sha256((folder/'config.json').read_bytes()).hexdigest()
    assert (folder/'access/qcl-negf/unknown.lock').read_bytes()==b'unknown owner; preserve'


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
    def disconnected(context):
        assert context=={}
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
    document = request(phase); document['controls'] = [dict(path=name,bytes=0,sha256=hashlib.sha256(b'').hexdigest())
        for name in ('series_result.json','native-selection.json','_scheduler-stdout.txt','_scheduler-stderr.txt')] if phase == 'close' else None
    result = first.observe_start(document) if phase == 'start' else first.qualify_close(document)
    assert result['state'] == 'hold' and result['reason'] == missing and result['job'] == bound
    assert result['controls'] is None and len(observed.calls) == 1
    assert not (first.store.path(document['calcjob_uuid']) / 'allocation.json').exists()


def q1_controls(root,launch):
    names=('series_result.json','native-selection.json','_scheduler-stdout.txt','_scheduler-stderr.txt')
    result=root/launch['relative_execution_root'];work=root/Path(launch['remote_workdir']).relative_to('/srv/qcl-negf/jobs')
    result.mkdir(parents=True);work.mkdir(parents=True)
    contents=(b'original failed result bytes\n',b'{"version":1,"selected_inputs":[]}',b'',b'original log\x00bytes')
    claims=[]
    for index,(name,raw) in enumerate(zip(names,contents)):
        path=(result if index<2 else work)/name;path.write_bytes(raw);path.chmod(0o640)
        claims.append(dict(path=name,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()))
    return claims,result,work


@pytest.fixture
def q1_joined(tmp_path,monkeypatch):
    """Actual owner/preflight/W1/reader/store; OS/RPC facts are SOURCE fixtures."""
    m=module();real_reader=m._read_submitted_files_as_owner
    state=actor_bridge.__wrapped__(monkeypatch);source=state['sources'];policy=source.policy
    journal=tmp_path/'journal';journal.mkdir(mode=0o700)
    namespace=tmp_path/'namespace';jobs=namespace/'srv/qcl-negf/jobs'
    controls,result,work=q1_controls(jobs,state['document']['launch'])
    policy.update(private_root=str(journal),spool_root='/local/spool',daemon_unit='qcl-negf-aiida.service',
        server_unit_prefix='qcl-negf-native-attempt@',worker_routes={'node-a':{'fixture':'authenticated RPC boundary'}},
        nfs_source='storage:/jobs',limits={**policy['limits'],'maximum_files':2048})
    source.budget=m.Operation(policy['limits']);host=state['host'];dispatch=state['document']['calcjob_uuid']
    store=m.AttemptStore(journal);launch=state['document']['launch']
    job=dict(job_id='42',cluster='cluster',submit_time='2026-10-30T01:00:00',controller_machine_id=host['machine_id'],
        controller_boot_id=host['boot_id'],dispatch_id=dispatch,generation='b'*64,node_name='node-a',
        start_time='2026-10-30T01:00:01',worker_machine_id='c'*32,worker_boot_id=dispatch)
    for name,value in [('claim.json',dict(launch=launch,dispatch_id=dispatch,context=host)),
        ('dispatch.json',dict(original='retained source fixture')),('ack.json',dict(job_id='42',cluster='cluster')),
        ('job.json',job),('allocation.json',job)]:store.put(dispatch,name,value,source.budget)
    source.qualification=dict(write_domain=dict(storage_identity='storage',native_prefix='native',retention_ref='qualified-site-locator',
        writer_hosts={'node-a':'c'*32},controller_units=['qcl-negf-aiida.service','qcl-negf-api.service']),
        worker_bindings={'c'*32:dict(machine_id='c'*32,boot_id=dispatch)},unit_origins={'server':{'executable':'/nix/store/root-python'}})
    monkeypatch.setattr(source,'host',lambda:host)
    monkeypatch.setattr(source,'native_job',lambda job_id:dict(fields=dict(SubmitTime=job['submit_time'],Comment=dispatch,NodeList='node-a')))
    server='qcl-negf-native-attempt@fixture.service'
    monkeypatch.setattr(source,'process',lambda pid:dict(pid=pid,ppid=1,start_ticks=2,uids=[0]*4,state='S',comm='python',
        cgroup='/system.slice/'+server,executable='/nix/store/root-python'))
    def unit(name):return dict(InvocationID='d'*32,ControlGroup='/system.slice/'+name,
        MainPID=str(os.getpid()) if name==server else ('123' if name==policy['daemon_unit'] else '124'),
        ActiveState='active',MemoryMax='134217728',RuntimeMaxUSec='90s')
    monkeypatch.setattr(source,'unit',unit)
    original_read=source.budget.read
    def read(path,limit=65536):
        if str(path).endswith('/mountinfo'):
            return ('1 0 0:1 / /srv/qcl-negf/jobs/native ro - nfs4 storage:/jobs rw\n').encode()
        return original_read(path,limit)
    monkeypatch.setattr(source.budget,'read',read)
    inventory=dict(schema='qcl.host-resource-guest-facts.v1',identity_before={'boot':'fixture'},identity_after={'boot':'fixture'},
        slurm_registered=True,jobs={},groups={})
    packet=dict(version=1,identity=dict(schema='qcl.host-resource-guest-identity.v1',identity=dict(machine_id='c'*32,boot_id=dispatch)),
        job=dict(fields=dict(SubmitTime=job['submit_time'],Comment=dispatch)),prolog_ref='prolog',epilog_ref='epilog',
        before={'original_live_before':'RPC fixture'},after={'whole_stop':'RPC fixture'},writer_snapshot=inventory)
    import host_resource_facts as facts
    monkeypatch.setattr(facts,'trusted_rpc',lambda *args,**kw:copy.deepcopy(packet))
    fake_reader=m._read_submitted_files_as_owner;uid=os.getuid();euid=os.geteuid()
    # This tests the production fork/FD code using only our synthetic child and
    # own temp files. Real UID3000/NFS qualification remains Root's native gate.
    def owner_reader(p,launch,budget,*,controls=None,technical_control=None):
        if controls is None:return fake_reader(p,launch,budget)
        opened=m.os.open
        child={'dropped':False}
        with monkeypatch.context() as patch:
            patch.setattr(m.os,'geteuid',lambda:uid if child['dropped'] else 0)
            patch.setattr(m.os,'setgroups',lambda groups:None if groups==[] else pytest.fail('groups'))
            patch.setattr(m.os,'setgid',lambda value:None)
            patch.setattr(m.os,'setuid',lambda value:child.update(dropped=True))
            def open_path(path,*args,**kw):
                if str(path)=='/':
                    assert child['dropped'],'root must not open NFS payload/ancestry'
                    return opened(namespace,*args,**kw)
                return opened(path,*args,**kw)
            patch.setattr(m.os,'open',open_path)
            options={} if technical_control is None else {'technical_control':technical_control}
            return real_reader({**p,'client_uid':uid},launch,budget,controls=controls,**options)
    monkeypatch.setattr(m,'_read_submitted_files_as_owner',owner_reader)
    state.update(store=store,controls=controls,result=result,work=work,packet=packet,job=job,journal=journal,unit=unit)
    state['owner']=m.OrdinaryAttemptOwner(policy,store,source,source.budget)
    return state


def q1t_document(state, raw=b'{"original":"technical index bytes"}\n'):
    document={**state['document'],'version':3,'action':'close','controls':copy.deepcopy(state['controls'])}
    if raw is None:
        document['technical_control']={'status':'absent','path':'performance-source.json','reason':'not_published'}
    else:
        path=state['result']/'performance-source.json';path.write_bytes(raw);path.chmod(0o640)
        document['technical_control']={'status':'present','path':'performance-source.json',
            'bytes':str(len(raw)),'sha256':hashlib.sha256(raw).hexdigest()}
    return document


@pytest.mark.parametrize('raw',[None,b'',b'{"original":"technical index bytes"}\n'])
def test_q1t_v3_closes_only_observed_present_whole_bytes_or_actual_absence(q1_joined,raw):
    s=q1_joined;m=s['m'];document=q1t_document(s,raw)
    closed=s['owner'].qualify_close(document)
    assert closed['state']=='closed' and closed['version']==3
    assert set(closed)=={'version','state','calcjob_uuid','receipt_ref','job','controls','technical_control','reason'}
    assert closed['technical_control']==document['technical_control'] and closed['controls']==s['controls']
    assert m.validate_reply(closed)==closed
    directory=s['store'].path(document['calcjob_uuid']);receipt=(directory/'close.json').read_bytes()
    witness=json.loads((directory/'close-observation.json').read_bytes())
    assert witness['control_read']['technical_control']==document['technical_control']
    assert witness['control_read']['io']['actual_bytes']==sum(c['bytes'] for c in s['controls'])+(0 if raw is None else len(raw))
    assert witness['reply_sha256']==hashlib.sha256(receipt).hexdigest()
    assert [r['root'] for r in witness['control_read']['files'] if r['path']=='performance-source.json']==([] if raw is None else ['result'])


@pytest.mark.parametrize('mutate',[
    lambda r:r.update(version=2),
    lambda r:r.update(version=True),
    lambda r:r.update(action='status',controls=None),
    lambda r:r['technical_control'].update(path='../performance-source.json'),
    lambda r:r['technical_control'].update(bytes=1),
    lambda r:r['technical_control'].update(bytes='01'),
    lambda r:r['technical_control'].update(bytes='1048577'),
    lambda r:r['technical_control'].update(bytes='18446744073709551616'),
    lambda r:r['technical_control'].update(verified=True),
    lambda r:r.update(technical_control={'status':'absent','path':'performance-source.json','reason':'zero'}),
    lambda r:r.update(technical_control=None),
    lambda r:r['controls'].reverse(),
])
def test_q1t_bad_wire_is_rejected_before_preflight_lock_or_durable_effects(tmp_path,monkeypatch,mutate):
    m=module();first,_=owner(tmp_path)
    document=request('close');document.update(version=3,
        controls=[dict(path=name,bytes=0,sha256='0'*64) for name in
            ('series_result.json','native-selection.json','_scheduler-stdout.txt','_scheduler-stderr.txt')],
        technical_control=dict(status='present',path='performance-source.json',bytes='1',sha256='0'*64))
    mutate(document)
    monkeypatch.setattr(first.sources,'preflight',lambda *a,**kw:pytest.fail('invalid wire reached preflight'))
    result=first.qualify_close(document)
    assert result['state']=='rejected' and not list(tmp_path.iterdir())


@pytest.mark.parametrize('valid',[True,False])
def test_q1t_socket_failure_preserves_v3_shape_only_after_valid_request(monkeypatch,valid):
    m=module();document=request('close');document.update(version=3,
        controls=[dict(path=name,bytes=0,sha256='0'*64) for name in
            ('series_result.json','native-selection.json','_scheduler-stdout.txt','_scheduler-stderr.txt')],
        technical_control=dict(status='absent',path='performance-source.json',reason='not_published'))
    if not valid:document['version']=2
    sources=type('SocketSources',(),{'qualify':lambda self:None})()
    monkeypatch.setattr(m,'_load_policy',lambda *a:{'limits':limits()})
    monkeypatch.setattr(m,'NativeSources',lambda *a:sources)
    monkeypatch.setattr(m,'_authenticate_server',lambda *a:None)
    monkeypatch.setattr(m,'read_frame',lambda *a:document)
    def peer(*args,**kwargs):raise m.Hold('peer_origin')
    monkeypatch.setattr(m,'authenticate_socket_peer',peer)
    captured=[];monkeypatch.setattr(m,'write_frame',lambda connection,result,*a:captured.append(result))
    m.handle_connection(object());result=captured[0]
    assert result['version']==(3 if valid else 1)
    assert result['state']==('hold' if valid else 'rejected')
    if valid:assert result['technical_control'] is None and result['controls'] is None


@pytest.mark.parametrize('version,state',[(True,'rejected'),(1.0,'rejected'),(False,'rejected'),
    (2.0,'rejected'),(3,'rejected'),('1','rejected'),(1,'hold')])
def test_q1t_server_classifies_only_integer_v1_as_legacy_before_authentication(monkeypatch,version,state):
    m=module();document=request('close');document['version']=version
    sources=type('SocketSources',(),{'qualify':lambda self:None})()
    monkeypatch.setattr(m,'_load_policy',lambda *a:{'limits':limits()})
    monkeypatch.setattr(m,'NativeSources',lambda *a:sources)
    monkeypatch.setattr(m,'_authenticate_server',lambda *a:None)
    monkeypatch.setattr(m,'read_frame',lambda *a:document)
    monkeypatch.setattr(m,'authenticate_socket_peer',lambda *a,**kw:pytest.fail('invalid request reached authentication'))
    monkeypatch.setattr(m,'AttemptStore',lambda *a:pytest.fail('invalid request reached durable store'))
    captured=[];monkeypatch.setattr(m,'write_frame',lambda connection,result,*a:captured.append(result))
    m.handle_connection(object());result=captured[0]
    assert result=={'version':1,'state':state,'calcjob_uuid':None,'receipt_ref':None,
        'job':None,'controls':None,'reason':'shape'}


@pytest.mark.parametrize('version',[1,3])
@pytest.mark.parametrize('fault',['namespace','connect','response_frame'])
def test_q1t_client_main_transport_errors_preserve_only_validated_v3_context(monkeypatch,capsys,version,fault):
    import io
    from contextlib import contextmanager
    m=module();document=request('close')
    document['controls']=[dict(path=name,bytes=0,sha256='0'*64) for name in
        ('series_result.json','native-selection.json','_scheduler-stdout.txt','_scheduler-stderr.txt')]
    if version==3:
        document.update(version=3,technical_control=dict(status='absent',path='performance-source.json',reason='not_published'))
    raw=m.encoded(document);stdin=io.BytesIO(raw);calls=[]
    monkeypatch.setattr(m.sys,'argv',['client','close'])
    monkeypatch.setattr(m.sys,'stdin',type('Input',(),{'buffer':stdin})())
    @contextmanager
    def directory(*args,**kw):
        if fault=='namespace':calls.append('namespace');raise OSError('primary synthetic namespace failure')
        yield 999
    class Connection:
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def settimeout(self,value):pass
        def connect(self,path):
            calls.append('connect')
            if fault=='connect':raise OSError('primary synthetic connect failure')
        def shutdown(self,how):pass
        def getsockopt(self,*args):return struct.pack('3i',1,0,0)
    info=os.stat_result((m.stat.S_IFSOCK|0o660,1,1,1,0,3000,0,1,1,1))
    monkeypatch.setattr(m,'protected_directory',directory)
    monkeypatch.setattr(m.os,'stat',lambda *a,**kw:info)
    monkeypatch.setattr(m.socket,'socket',lambda *a:Connection())
    monkeypatch.setattr(m,'write_frame',lambda *a:None)
    def failed_frame(*args):calls.append('response_frame');raise m.Hold('frame_bound')
    monkeypatch.setattr(m,'read_frame',failed_frame)
    assert m.client_main()==75
    output=capsys.readouterr().out;result=json.loads(output)
    expected={'version':version,'state':'hold','calcjob_uuid':document['calcjob_uuid'] if version==3 else None,
        'receipt_ref':None,'job':None,'controls':None,
        'reason':'frame_bound' if fault=='response_frame' else 'transport_outcome_unknown'}
    if version==3:expected['technical_control']=None
    assert result==expected and output.encode()==m.encoded(expected)+b'\n'
    assert stdin.tell()==len(raw) and calls==({'namespace':['namespace'],'connect':['connect'],
        'response_frame':['connect','response_frame']}[fault])


@pytest.mark.parametrize('raw',[b'{',b'\xff',b'{"version":2,"version":2}',
    b'{"version":true}',b'{"version":1.0}',b'{"version":2.0}',b'{"version":3}'])
def test_q1t_client_main_early_invalid_parse_never_gains_v3_context_or_transport(monkeypatch,capsys,raw):
    import io
    m=module();monkeypatch.setattr(m.sys,'argv',['client','close'])
    monkeypatch.setattr(m.sys,'stdin',type('Input',(),{'buffer':io.BytesIO(raw)})())
    monkeypatch.setattr(m,'protected_directory',lambda *a,**kw:pytest.fail('invalid input reached transport'))
    assert m.client_main()==75
    result=json.loads(capsys.readouterr().out)
    assert set(result)=={'version','state','calcjob_uuid','receipt_ref','job','controls','reason'}
    assert result['version']==1 and result['state']=='hold' and result['calcjob_uuid'] is None and result['controls'] is None


@pytest.mark.parametrize('fault',['hash','missing','unexpected_present','symlink','hardlink','writable','oversize','owner','ancestor'])
def test_q1t_technical_foreign_or_changed_file_never_publishes_receipt(q1_joined,monkeypatch,fault):
    s=q1_joined;m=s['m'];document=q1t_document(s);path=s['result']/'performance-source.json'
    if fault=='hash':document['technical_control']['sha256']='0'*64
    if fault=='missing':path.unlink()
    if fault=='unexpected_present':document['technical_control']={'status':'absent','path':'performance-source.json','reason':'not_published'}
    if fault=='symlink':path.rename(path.with_name('original'));path.symlink_to('original')
    if fault=='hardlink':os.link(path,path.with_name('alias'))
    if fault=='writable':path.chmod(0o666)
    if fault=='oversize':path.write_bytes(b'x'*1048577)
    inode=path.stat().st_ino if fault in ('owner','ancestor') else None;fstat=m.os.fstat;read=m.read_fd
    if fault=='owner':
        def info(fd):
            result=fstat(fd)
            if result.st_ino==inode:
                values=list(result);values[4]=os.getuid()+1;return os.stat_result(values)
            return result
        monkeypatch.setattr(m.os,'fstat',info)
    if fault=='ancestor':
        def reading(fd,limit,budget):
            result=read(fd,limit,budget)
            if fstat(fd).st_ino==inode:
                s['result'].rename(s['result'].with_name('retained'));s['result'].mkdir()
            return result
        monkeypatch.setattr(m,'read_fd',reading)
    result=s['owner'].qualify_close(document)
    assert result['version']==3 and result['state']=='hold' and result['technical_control'] is None
    assert result['controls'] is None and not (s['store'].path(document['calcjob_uuid'])/'close.json').exists()


@pytest.mark.parametrize('fault',['replace','tamper','absent_published','late_writer'])
def test_q1t_late_file_or_writer_change_cannot_certify_technical_context(q1_joined,monkeypatch,fault):
    s=q1_joined;m=s['m'];document=q1t_document(s,None if fault=='absent_published' else b'original')
    path=s['result']/'performance-source.json';read=m.read_fd;opened=m.os.open
    if fault=='absent_published':
        def open_path(name,*args,**kw):
            if name=='performance-source.json':
                path.write_bytes(b'late');path.chmod(0o640)
                raise FileNotFoundError('leaf was absent before late publish')
            return opened(name,*args,**kw)
        monkeypatch.setattr(m.os,'open',open_path)
    elif fault in ('replace','tamper'):
        inode=path.stat().st_ino
        def reading(fd,limit,budget):
            value=read(fd,limit,budget)
            if os.fstat(fd).st_ino==inode:
                if fault=='replace':path.unlink()
                path.write_bytes(value[0] if fault=='replace' else b'tampered');path.chmod(0o640)
            return value
        monkeypatch.setattr(m,'read_fd',reading)
    else:
        reader=m._read_submitted_files_as_owner
        def reading_owner(*args,**kwargs):
            value=reader(*args,**kwargs)
            if kwargs.get('technical_control') is not None:
                s['packet']['writer_snapshot']['jobs']['99']=dict(owner_uid=3000,submit_time='foreign',terminal=False)
            return value
        monkeypatch.setattr(m,'_read_submitted_files_as_owner',reading_owner)
    result=s['owner'].qualify_close(document)
    assert result['state']=='hold' and result['technical_control'] is None
    assert not (s['store'].path(document['calcjob_uuid'])/'close.json').exists()


@pytest.mark.parametrize('first_version,second_version,changed',[(3,3,False),(3,3,True),(1,3,False),(3,1,False)])
def test_q1t_retry_preserves_exact_receipts_and_never_relabels_v1(q1_joined,first_version,second_version,changed):
    s=q1_joined;m=s['m'];document=q1t_document(s)
    if first_version==1:document.pop('technical_control');document['version']=1
    closed=s['owner'].qualify_close(document);assert closed['state']=='closed'
    directory=s['store'].path(document['calcjob_uuid'])
    before={name:(directory/name).read_bytes() for name in ('close.json','close-observation.json')}
    document=q1t_document(s,b'changed' if changed else b'{"original":"technical index bytes"}\n')
    if second_version==1:document.pop('technical_control');document['version']=1
    source=copy.copy(s['sources']);source.budget=m.Operation(source.policy['limits']);source.budget.read=s['sources'].budget.read
    result=m.OrdinaryAttemptOwner(source.policy,s['store'],source,source.budget).qualify_close(document)
    if first_version==second_version and not changed:assert result==closed
    else:assert result['state']=='hold' and result['reason']=='q1_close_conflict'
    assert {name:(directory/name).read_bytes() for name in before}==before


def test_q1t_cleanup_uncertainty_retains_primary_failure_and_no_close(q1_joined,monkeypatch):
    s=q1_joined;m=s['m'];document=q1t_document(s)
    primary=dict(failure='timeout',stdout='original W1 prefix',cleanup_confirmed=False)
    def failed(*args):raise m.engine.CommandFailure(primary)
    monkeypatch.setattr(s['sources'],'close_writers',failed)
    result=s['owner'].qualify_close(document)
    assert result['state']=='hold' and result['technical_control'] is None
    directory=s['store'].path(document['calcjob_uuid']);failures=list(directory.glob('observation-failure-*.json'))
    import base64
    assert len(failures)==1 and json.loads(base64.b64decode(json.loads(failures[0].read_bytes())['original_prefix_base64']))==primary
    assert not (directory/'close.json').exists() and not (directory/'close-observation.json').exists()


def test_q1t_partial_publication_is_not_repaired_or_overwritten(q1_joined,monkeypatch):
    s=q1_joined;m=s['m'];document=q1t_document(s);put=s['store'].put
    def failed(calcjob,name,value,budget):
        put(calcjob,name,value,budget)
        if name=='close-observation.json':raise OSError('original v3 publication uncertainty')
    monkeypatch.setattr(s['store'],'put',failed)
    result=s['owner'].qualify_close(document)
    assert result['state']=='hold' and result['technical_control'] is None
    directory=s['store'].path(document['calcjob_uuid']);original=(directory/'close-observation.json').read_bytes()
    monkeypatch.setattr(s['store'],'put',put)
    monkeypatch.setattr(m.os,'fork',lambda:pytest.fail('partial publication must not reread'))
    result=s['owner'].qualify_close(document)
    assert result['state']=='hold' and result['reason']=='q1_close_publication_unknown'
    assert (directory/'close-observation.json').read_bytes()==original and not (directory/'close.json').exists()


@pytest.mark.parametrize('reply_version',[1,2,3])
def test_q1t_fixed_client_requires_exact_v3_reply_without_v1_fallback(q1_joined,monkeypatch,capsys,reply_version):
    import io
    from contextlib import contextmanager
    s=q1_joined;m=s['m'];document=q1t_document(s)
    result=s['owner'].qualify_close(document);assert result['state']=='closed'
    if reply_version!=3:
        if reply_version==1:result.pop('technical_control')
        result['version']=reply_version
    @contextmanager
    def directory(*args,**kwargs):yield 999
    class Connection:
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def settimeout(self,value):pass
        def connect(self,path):assert path=='/run/qcl-negf/native-attempt.sock'
        def shutdown(self,how):pass
        def getsockopt(self,*args):return struct.pack('3i',1,0,0)
    info=os.stat_result((m.stat.S_IFSOCK|0o660,1,1,1,0,3000,0,1,1,1))
    monkeypatch.setattr(m,'protected_directory',directory)
    monkeypatch.setattr(m.os,'stat',lambda *args,**kw:info)
    monkeypatch.setattr(m.socket,'socket',lambda *args:Connection())
    monkeypatch.setattr(m.sys,'argv',['client','close'])
    monkeypatch.setattr(m.sys,'stdin',type('Input',(),{'buffer':io.BytesIO(m.encoded(document))})())
    monkeypatch.setattr(m,'write_frame',lambda connection,value,*args:None)
    monkeypatch.setattr(m,'read_frame',lambda *args:result)
    if reply_version!=3:
        with pytest.raises(m.Hold,match='reply_shape' if reply_version==2 else 'reply_version'):m._client_operation()
        assert capsys.readouterr().out==''
    else:
        assert m._client_operation()==0
        assert capsys.readouterr().out.encode()==m.encoded(result)+b'\n'


@pytest.mark.parametrize('delta',[-1,0])
def test_q1t_technical_cap_keeps_original_full_byte_hash_with_sufficient_existing_credit(q1_joined,delta):
    s=q1_joined;m=s['m'];raw=b'x'*(1048576+delta);document=q1t_document(s,raw)
    source=s['sources'];source.policy['limits']['metadata_bytes']=32*1024*1024
    budget=m.Operation(source.policy['limits']);budget.read=source.budget.read;source.budget=budget
    result=m.OrdinaryAttemptOwner(source.policy,s['store'],source,budget).qualify_close(document)
    assert result['state']=='closed' and result['technical_control']==document['technical_control']


def test_q1t_technical_budget_is_charged_before_any_child_or_payload_open(monkeypatch):
    m=module();budget=m.Operation({**limits(),'maximum_files':2048})
    policy=dict(limits=budget.limits,jobs_root='/srv/qcl-negf/jobs')
    controls=[dict(path=name,bytes=0,sha256='0'*64) for name in
        ('series_result.json','native-selection.json','_scheduler-stdout.txt','_scheduler-stderr.txt')]
    technical=dict(status='present',path='performance-source.json',bytes='1048576',sha256='0'*64)
    monkeypatch.setattr(m.os,'geteuid',lambda:0)
    def forbidden(*args):pytest.fail('aggregate refusal must precede pipe/fork/payload open')
    monkeypatch.setattr(m.os,'pipe2',forbidden);monkeypatch.setattr(m.os,'fork',forbidden)
    with pytest.raises(m.Hold,match='operation_bound'):
        m._read_submitted_files_as_owner(policy,request()['launch'],budget,controls=controls,technical_control=technical)
    assert budget.bytes>budget.limits['metadata_bytes']


def test_q1t_additional_leaf_file_credit_is_charged_before_fork(monkeypatch):
    m=module();budget=m.Operation({**limits(),'maximum_files':152})
    policy=dict(limits=budget.limits,jobs_root='/srv/qcl-negf/jobs')
    controls=[dict(path=name,bytes=0,sha256='0'*64) for name in
        ('series_result.json','native-selection.json','_scheduler-stdout.txt','_scheduler-stderr.txt')]
    technical=dict(status='absent',path='performance-source.json',reason='not_published')
    monkeypatch.setattr(m.os,'geteuid',lambda:0)
    def forbidden(*args):pytest.fail('technical file debit must precede pipe/fork')
    monkeypatch.setattr(m.os,'pipe2',forbidden);monkeypatch.setattr(m.os,'fork',forbidden)
    with pytest.raises(m.Hold,match='operation_file_bound'):
        m._read_submitted_files_as_owner(policy,request()['launch'],budget,controls=controls,technical_control=technical)
    assert budget.files>152


def test_q1t_absence_retry_and_later_publication_preserve_original_absent_receipt(q1_joined):
    s=q1_joined;m=s['m'];document=q1t_document(s,None)
    first=s['owner'].qualify_close(document);assert first['state']=='closed'
    directory=s['store'].path(document['calcjob_uuid']);original=(directory/'close.json').read_bytes()
    for publish in (False,True):
        source=copy.copy(s['sources']);source.budget=m.Operation(source.policy['limits']);source.budget.read=s['sources'].budget.read
        if publish:q1t_document(s,b'late index')
        result=m.OrdinaryAttemptOwner(source.policy,s['store'],source,source.budget).qualify_close(document)
        if publish:assert result['state']=='hold' and result['technical_control'] is None
        else:assert result==first
        assert (directory/'close.json').read_bytes()==original


@pytest.mark.parametrize('mutate',[
    lambda r:r.update(version=True),
    lambda r:r.update(version=1),
    lambda r:r.update(state='bound'),
    lambda r:r.update(technical_control=None),
    lambda r:r['technical_control'].update(bytes=0),
    lambda r:r['technical_control'].update(bytes='00'),
    lambda r:r['technical_control'].update(path='/performance-source.json'),
    lambda r:r['technical_control'].update(extra=True),
    lambda r:r.update(technical_control={'status':'absent','path':'performance-source.json','reason':'not_published','bytes':'0'}),
    lambda r:r['controls'].reverse(),
])
def test_q1t_reply_rejects_malformed_or_v1_relabelled_technical_authority(q1_joined,mutate):
    s=q1_joined;m=s['m'];document=q1t_document(s,b'')
    result=s['owner'].qualify_close(document);assert result['state']=='closed'
    mutate(result)
    with pytest.raises(m.Hold):m.validate_reply(result)


def test_q1_actual_owner_w1_credential_fd_store_and_lost_close_ack(q1_joined):
    s=q1_joined;m=s['m'];document={**s['document'],'action':'close','controls':s['controls']}
    closed=s['owner'].qualify_close(document)
    assert closed['state']=='closed' and closed['controls']==s['controls'] and closed['job']==s['job']
    directory=s['store'].path(document['calcjob_uuid']);raw=(directory/'close.json').read_bytes()
    witness=(directory/'close-observation.json').read_bytes()
    assert raw==m.encoded(closed) and not raw.endswith(b'\n')
    retained=json.loads(witness);assert retained['reply_sha256']==hashlib.sha256(raw).hexdigest()
    assert retained['control_read']['controls']==s['controls'] and len(retained['control_read']['files'])==4
    assert retained['control_read']['io']['actual_bytes']==sum(row['bytes'] for row in s['controls'])
    source=copy.copy(s['sources']);source.budget=m.Operation(source.policy['limits'])
    source.budget.read=s['sources'].budget.read  # immutable fixture OS observations, not budget credit
    again=m.OrdinaryAttemptOwner(source.policy,s['store'],source,source.budget).qualify_close(document)
    assert again==closed and (directory/'close.json').read_bytes()==raw and (directory/'close-observation.json').read_bytes()==witness
    assert not any('--parsable' in call[0] for call in s['calls'])


def test_q1_native_tuple_observations_compare_exact_encoded_bytes(q1_joined):
    s=q1_joined;s['context']['profile_origin']={'chain':[('/nix/profile',(1,2,3,0,0,1,1,1,1),None)]}
    closed=s['owner'].qualify_close({**s['document'],'action':'close','controls':s['controls']})
    assert closed['state']=='closed'


def test_q1_original_publication_error_and_partial_observation_survive(q1_joined,monkeypatch,capsys):
    import base64
    s=q1_joined;m=s['m'];put=s['store'].put;original=OSError('unique original close sync failure')
    def failed(calcjob,name,value,budget):
        put(calcjob,name,value,budget)
        if name=='close-observation.json':raise original
    monkeypatch.setattr(s['store'],'put',failed)
    reply=s['owner'].qualify_close({**s['document'],'action':'close','controls':s['controls']})
    assert reply['state']=='hold' and reply['job']==s['job']
    path=s['store'].path(s['document']['calcjob_uuid'])
    assert (path/'close-observation.json').is_file() and not (path/'close.json').exists()
    diagnostic=json.loads(capsys.readouterr().err.split('native-attempt preclaim HOLD: ',1)[1])
    assert b'unique original close sync failure' in base64.b64decode(diagnostic['original_prefix_base64'])


def test_q1_real_observation_fsync_error_and_repeat_never_repair(q1_joined,monkeypatch,capsys):
    import base64
    s=q1_joined;m=s['m'];fsync=m.os.fsync;document={**s['document'],'action':'close','controls':s['controls']}
    def sync(fd):
        if os.readlink('/proc/self/fd/'+str(fd)).endswith('/close-observation.json'):
            raise OSError('unique original observation fsync error')
        return fsync(fd)
    monkeypatch.setattr(m.os,'fsync',sync)
    assert s['owner'].qualify_close(document)['state']=='hold'
    directory=s['store'].path(document['calcjob_uuid']);original=(directory/'close-observation.json').read_bytes()
    diagnostic=json.loads(capsys.readouterr().err.split('native-attempt preclaim HOLD: ',1)[1])
    assert b'unique original observation fsync error' in base64.b64decode(diagnostic['original_prefix_base64'])
    monkeypatch.setattr(m.os,'fsync',fsync)
    source=copy.copy(s['sources']);source.budget=m.Operation(source.policy['limits']);source.budget.read=s['sources'].budget.read
    monkeypatch.setattr(m.os,'fork',lambda:pytest.fail('partial publication must not reread/repair'))
    result=m.OrdinaryAttemptOwner(source.policy,s['store'],source,source.budget).qualify_close(document)
    assert result['state']=='hold' and result['reason']=='q1_close_publication_unknown'
    assert (directory/'close-observation.json').read_bytes()==original and not (directory/'close.json').exists()


@pytest.mark.parametrize('fault',['mount_source','mount_switch','mount_root_switch','mount_malformed','writer_after','unit_after','worker_boot'])
def test_q1_after_read_changes_are_not_a_closed_access_pass(q1_joined,monkeypatch,fault):
    import host_resource_facts as facts
    s=q1_joined;m=s['m'];source=s['sources'];reader=m._read_submitted_files_as_owner;read=source.budget.read
    reached={'read':False};unit=source.unit
    def read_controls(*args,**kwargs):
        value=reader(*args,**kwargs)
        if kwargs.get('controls') is not None:reached['read']=True
        return value
    monkeypatch.setattr(m,'_read_submitted_files_as_owner',read_controls)
    def mount(path,limit=65536):
        raw=read(path,limit)
        if str(path).endswith('/mountinfo') and (fault=='mount_source' or fault=='mount_switch' and reached['read']):
            raw=raw.replace(b'storage:/jobs',b'foreign:/jobs')
        if str(path).endswith('/mountinfo') and fault=='mount_root_switch' and reached['read']:
            raw=raw.replace(b' / /srv',b' /foreign /srv')
        if str(path).endswith('/mountinfo') and fault=='mount_malformed':raw=b'broken - nfs4 storage:/jobs rw\n'
        return raw
    monkeypatch.setattr(source.budget,'read',mount)
    def state(name):
        value=unit(name)
        if fault=='unit_after' and reached['read'] and name=='qcl-negf-api.service':value['InvocationID']='e'*32
        return value
    monkeypatch.setattr(source,'unit',state)
    def rpc(*args,**kwargs):
        packet=copy.deepcopy(s['packet'])
        if reached['read'] and fault=='writer_after':
            packet['writer_snapshot']['jobs']['99']=dict(owner_uid=3000,submit_time='unknown',terminal=False)
        if reached['read'] and fault=='worker_boot':
            packet['identity']['identity']['boot_id']=s['document']['launch']['request_id']
            source.qualification['worker_bindings']['c'*32]['boot_id']=packet['identity']['identity']['boot_id']
        return packet
    monkeypatch.setattr(facts,'trusted_rpc',rpc)
    reply=s['owner'].qualify_close({**s['document'],'action':'close','controls':s['controls']})
    assert reply['state']=='hold' and reply['controls'] is None
    assert not (s['store'].path(s['document']['calcjob_uuid'])/'close.json').exists()


@pytest.mark.parametrize('fault',['bytes','files','deadline'])
def test_q1_gross_child_debit_refuses_before_fork(monkeypatch,fault):
    m=module();budget=m.Operation({**limits(),'maximum_files':2048})
    policy=dict(limits=budget.limits,jobs_root='/srv/qcl-negf/jobs')
    claims=[dict(path=name,bytes=0,sha256=hashlib.sha256(b'').hexdigest())
        for name in ('series_result.json','native-selection.json','_scheduler-stdout.txt','_scheduler-stderr.txt')]
    if fault=='bytes':budget.bytes=budget.limits['metadata_bytes']
    if fault=='files':budget.files=budget.limits['maximum_files']
    if fault=='deadline':budget.deadline=0
    before=(budget.bytes,budget.files,budget.deadline)
    monkeypatch.setattr(m.os,'geteuid',lambda:0)
    def forbidden(*args):raise AssertionError('budget refusal must precede pipes/fork/NFS')
    monkeypatch.setattr(m.os,'pipe2',forbidden);monkeypatch.setattr(m.os,'fork',forbidden)
    with pytest.raises(m.Hold):m._read_submitted_files_as_owner(policy,request()['launch'],budget,controls=claims)
    assert budget.bytes>=before[0] and budget.files>=before[1] and budget.deadline==before[2]


@pytest.mark.parametrize('fault',['whitespace','observation_only','close_conflict','oversized','qualification'])
def test_q1_journal_partial_conflict_and_current_access_remain_hold(q1_joined,monkeypatch,fault):
    s=q1_joined;m=s['m'];document={**s['document'],'action':'close','controls':s['controls']}
    directory=s['store'].path(document['calcjob_uuid']);put=s['store'].put
    if fault in ('whitespace','observation_only'):
        def writing(calcjob,name,value,budget):
            put(calcjob,name,value,budget)
            if name=='close-observation.json':
                if fault=='whitespace':
                    with (directory/name).open('ab') as stream:stream.write(b' ')
                else:raise OSError('retained partial publication')
        monkeypatch.setattr(s['store'],'put',writing)
    if fault=='oversized':s['context']['bounded_raw_observation']='x'*70000
    if fault in ('close_conflict','qualification'):
        assert s['owner'].qualify_close(document)['state']=='closed'
        original=(directory/'close.json').read_bytes()
        source=copy.copy(s['sources']);source.budget=m.Operation(source.policy['limits']);source.budget.read=s['sources'].budget.read
        if fault=='close_conflict':
            value=json.loads(original);value['job']['submit_time']='foreign'
            (directory/'close.json').write_bytes(m.encoded(value));original=(directory/'close.json').read_bytes()
        else:
            def unavailable():raise m.Hold('native_qualification_missing')
            monkeypatch.setattr(source,'qualify',unavailable)
        s['owner']=m.OrdinaryAttemptOwner(source.policy,s['store'],source,source.budget)
    result=s['owner'].qualify_close(document)
    assert result['state']=='hold' and result['controls'] is None
    if fault in ('close_conflict','qualification'):assert (directory/'close.json').read_bytes()==original
    else:assert not (directory/'close.json').exists()


@pytest.mark.parametrize('fault',['hash','symlink','hardlink','writable','missing','order','extra','allocation','before','after','new_writer'])
def test_q1_close_negatives_never_publish_closed(q1_joined,fault):
    s=q1_joined;document={**s['document'],'action':'close','controls':copy.deepcopy(s['controls'])}
    if fault=='hash':document['controls'][0]['sha256']='0'*64
    if fault=='symlink':
        path=s['result']/'series_result.json';path.rename(s['result']/'original');path.symlink_to('original')
    if fault=='hardlink':os.link(s['result']/'series_result.json',s['result']/'alias')
    if fault=='writable':(s['result']/'series_result.json').chmod(0o666)
    if fault=='missing':(s['work']/'_scheduler-stderr.txt').unlink()
    if fault=='order':document['controls'].reverse()
    if fault=='extra':document['controls'].append(dict(path='native-close.json',bytes=0,sha256='0'*64))
    if fault=='allocation':(s['store'].path(document['calcjob_uuid'])/'allocation.json').unlink()
    if fault in ('before','after'):s['packet'][fault]=None
    if fault=='new_writer':s['packet']['writer_snapshot']['jobs']['99']=dict(owner_uid=3000,submit_time='foreign',terminal=False)
    reply=s['owner'].qualify_close(document)
    assert reply['state'] in ('hold','rejected') and reply['controls'] is None
    assert not (s['store'].path(document['calcjob_uuid'])/'close.json').exists()


@pytest.mark.parametrize('fault',['named_file','shrink','ancestor','directory_mode','file_owner'])
def test_q1_same_open_file_and_ancestor_replacements_hold(q1_joined,monkeypatch,fault):
    s=q1_joined;m=s['m'];read=m.read_fd;target=s['result']/'series_result.json'
    inode=target.stat().st_ino;fstat=m.os.fstat
    def reading(fd,limit,budget):
        value=read(fd,limit,budget)
        if fstat(fd).st_ino==inode:
            if fault=='named_file':
                target.unlink();target.write_bytes(value[0]);target.chmod(0o640)
            if fault=='shrink':target.write_bytes(b'')
            if fault=='ancestor':
                ancestor=s['result'].parent;ancestor.rename(ancestor.with_name('retained-original'))
                ancestor.mkdir();s['result'].mkdir()
            if fault=='directory_mode':s['result'].chmod(0o777)
        return value
    monkeypatch.setattr(m,'read_fd',reading)
    if fault=='file_owner':
        def info(fd):
            result=fstat(fd)
            if result.st_ino==inode:
                fields=list(result);fields[4]=os.getuid()+1;return os.stat_result(fields)
            return result
        monkeypatch.setattr(m.os,'fstat',info)
    result=s['owner'].qualify_close({**s['document'],'action':'close','controls':s['controls']})
    assert result['state']=='hold' and result['controls'] is None
    assert not (s['store'].path(s['document']['calcjob_uuid'])/'close.json').exists()


@pytest.mark.parametrize('fault',['boolean','negative','over_cap','relative_alias','absolute','row_extra'])
def test_q1_fixed_four_claim_domains_are_not_caller_authority(q1_joined,fault):
    s=q1_joined;controls=copy.deepcopy(s['controls']);row=controls[0]
    if fault=='boolean':row['bytes']=True
    if fault=='negative':row['bytes']=-1
    if fault=='over_cap':row['bytes']=33554433
    if fault=='relative_alias':row['path']='./series_result.json'
    if fault=='absolute':row['path']='/series_result.json'
    if fault=='row_extra':row['verified']=True
    result=s['owner'].qualify_close({**s['document'],'action':'close','controls':controls})
    assert result['state'] in ('hold','rejected') and result['controls'] is None
    assert not (s['store'].path(s['document']['calcjob_uuid'])/'close.json').exists()


@pytest.mark.parametrize('role,cap', [('plan',1048576),('source_graph',65536),
                                     ('native_execution',65536),('submit_script',65536)])
@pytest.mark.parametrize('delta', [-1,0,1])
def test_original_input_role_limits_and_full_raw_claims(tmp_path,role,cap,delta):
    """A global cap raise or a plan still capped at64KiB breaks this reader check."""
    m=module();launch=request()['launch'];work=tmp_path/'upload';work.mkdir()
    launch['remote_workdir']=str(work)
    for name,filename in m.FILES.items():
        raw=b'{"original":true}\n'
        if name==role:raw+=b' '*(cap+delta-len(raw))
        (work/filename).write_bytes(raw)
        launch['files'][name]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    policy=dict(jobs_root=str(tmp_path),client_uid=os.getuid(),limits={**limits(),'metadata_bytes':8*1024*1024})
    budget=m.Operation(policy['limits'])
    if delta>0:
        with pytest.raises(m.Hold,match='submitted_bound'):m._owner_read(policy,launch,budget)
    else:
        observed=m._owner_read(policy,launch,budget)
        assert observed['files']==launch['files']
        assert budget.actual_bytes==sum(row['bytes'] for row in launch['files'].values())
        assert all((work/name).is_file() for name in m.FILES.values())


@pytest.mark.parametrize('role,size,reason', [
    ('plan',1048575,'operation_bound'),('plan',1048576,'operation_bound'),('plan',1048577,'actor_input_bound'),
    ('source_graph',65537,'actor_input_bound'),('native_execution',65537,'actor_input_bound'),
    ('submit_script',65537,'actor_input_bound')])
def test_actor_role_limit_and_unchanged_outer_budget_hold_before_command(monkeypatch,role,size,reason):
    m=module();launch=request()['launch'];launch['files'][role]['bytes']=size
    policy=dict(tools={'runuser':'/nix/store/runuser'},limits={**limits(),'metadata_bytes':8*1024*1024})
    budget=m.Operation(policy['limits']);source=m.NativeSources(policy,budget)
    context=dict(app='/nix/store/app',configuration=dict(profile='existing',aiida_path='/existing'))
    def forbidden(*args,**kw):raise AssertionError('actor must not start beyond role/outer bound')
    monkeypatch.setattr(m.engine,'command',forbidden)
    with pytest.raises(m.Hold,match=reason):source._actor_read('launch',request()['calcjob_uuid'],launch,context)
    assert budget.calls==0
    assert (budget.bytes>8*1024*1024) if reason=='operation_bound' else budget.bytes==0


@pytest.mark.parametrize('outcome', ['success','failure','cancel'])
def test_actor_actual_sizes_eof_workspace_prepay_is_exact_nonrefundable(monkeypatch,outcome):
    """A stale64KiB min, missing EOF charge or postcommand reserve breaks accounting."""
    m=module();launch=request()['launch']
    for role,size in [('plan',113111),('source_graph',108),('native_execution',1048),('submit_script',4096)]:
        launch['files'][role]['bytes']=size
    policy=dict(tools={'runuser':'/nix/store/runuser'},limits={**limits(),'metadata_bytes':8*1024*1024})
    budget=m.Operation(policy['limits']);source=m.NativeSources(policy,budget)
    context=dict(app='/nix/store/app',configuration=dict(profile='existing',aiida_path='/existing'))
    # Hand-derived chunk/EOF workspace: plan29*4096, graph8192, native8192,
    # script8192, plus30 query slabs. Command has its separate fixed4*65536 debit.
    ceiling=1638400
    class Cancelled(BaseException):pass
    def command(argv,**kw):
        assert argv[-2:]==['--maximum-metadata-bytes',str(ceiling)]
        assert budget.bytes==ceiling+262144 and budget.calls==1
        assert kw['deadline']==budget.deadline
        if outcome=='failure':raise m.engine.CommandFailure(dict(failure='timeout',cleanup_confirmed=False))
        if outcome=='cancel':raise Cancelled()
        output=m.engine.CommandOutput('{}');output.output_bytes=2;return output
    monkeypatch.setattr(m.engine,'command',command)
    if outcome=='success':assert source._actor_read('launch',request()['calcjob_uuid'],launch,context)==b'{}'
    else:
        with pytest.raises(m.engine.CommandFailure if outcome=='failure' else Cancelled):
            source._actor_read('launch',request()['calcjob_uuid'],launch,context)
    assert budget.bytes==1900544 and budget.calls==1 and budget.actual_bytes==0
    # Exhaust the SAME nonrefundable ledger; no command or reset/refund follows.
    budget.reserve(8*1024*1024-budget.bytes)
    with pytest.raises(m.Hold,match='operation_bound'):
        source._actor_read('launch',request()['calcjob_uuid'],launch,context)
    assert budget.calls==1 and budget.bytes>8*1024*1024


@pytest.mark.parametrize('fault', ['unknown_role','missing_role','unknown_claim','missing_bytes','negative','bool'])
def test_launch12_invalid_claims_refuse_before_actor(monkeypatch,tmp_path,fault):
    m=module();document=request();files=document['launch']['files']
    if fault=='unknown_role':files['other']=copy.deepcopy(files['plan'])
    if fault=='missing_role':del files['plan']
    if fault=='unknown_claim':files['plan']['extra']=True
    if fault=='missing_bytes':del files['plan']['bytes']
    if fault=='negative':files['plan']['bytes']=-1
    if fault=='bool':files['plan']['bytes']=True
    def forbidden(*args,**kw):raise AssertionError('invalid Launch12 must not start actor')
    monkeypatch.setattr(m.engine,'command',forbidden)
    policy={'limits':limits()}
    budget=m.Operation(policy['limits']);sources=m.NativeSources(policy,budget)
    selected=m.OrdinaryAttemptOwner(policy,m.AttemptStore(tmp_path),sources,budget)
    assert selected.submit(document)['state']=='rejected'
    assert budget.calls==0 and not (tmp_path/'attempts').exists()


@pytest.mark.parametrize('raw',[None,b'original result technical bytes'])
def test_q1t_v3_result_is_only_technical_domain_even_with_workdir_decoy(q1_joined,raw):
    s=q1_joined;document=q1t_document(s,raw)
    (s['work']/'performance-source.json').write_bytes(b'foreign workdir decoy')
    result=s['owner'].qualify_close(document)
    assert result['state']=='closed' and result['version']==3
    assert result['technical_control']==document['technical_control']
    witness=json.loads((s['store'].path(document['calcjob_uuid'])/'close-observation.json').read_bytes())
    assert all(row['root']=='result' for row in witness['control_read']['files'] if row['path']=='performance-source.json')


@pytest.mark.parametrize('version',[1,2,3])
def test_q1t_historical_v2_close_is_immutable_and_never_migrated(q1_joined,monkeypatch,version):
    s=q1_joined;m=s['m'];document=q1t_document(s)
    old=dict(version=2,state='closed',calcjob_uuid=document['calcjob_uuid'],receipt_ref=document['calcjob_uuid']+'/close.json',
        job=s['job'],controls=s['controls'],technical_control=document['technical_control'],reason=None)
    witness=dict(reply_sha256=hashlib.sha256(m.encoded(old)).hexdigest(),
        control_read=dict(technical_control=document['technical_control'],roots=[dict(role='workdir',path=document['launch']['remote_workdir'])]))
    for name,value in [('close-observation.json',witness),('close.json',old)]:
        s['store'].put(document['calcjob_uuid'],name,value,s['sources'].budget)
    directory=s['store'].path(document['calcjob_uuid'])
    before={name:(directory/name).read_bytes() for name in ('close.json','close-observation.json')}
    document['version']=version
    if version==1:document.pop('technical_control')
    reader=m._read_submitted_files_as_owner
    def no_close_read(*args,**kwargs):
        if kwargs.get('controls') is not None:pytest.fail('version conflict must precede close payload read')
        return reader(*args,**kwargs)
    monkeypatch.setattr(m,'_read_submitted_files_as_owner',no_close_read)
    result=s['owner'].qualify_close(document)
    assert result['state']==('rejected' if version==2 else 'hold')
    if version!=2:assert result['reason']=='q1_close_conflict'
    assert {name:(directory/name).read_bytes() for name in before}==before


@pytest.mark.parametrize('mutate',[
    lambda d:d.update(root='native_execution'),lambda d:d.update(path='performance-source.json'),
    lambda d:d['technical_control'].update(root='result'),lambda d:d['technical_control'].update(provider='native_execution'),
])
def test_q1t_v3_has_no_caller_root_path_or_provider_selector(q1_joined,monkeypatch,mutate):
    s=q1_joined;document=q1t_document(s,None);mutate(document)
    monkeypatch.setattr(s['sources'],'preflight',lambda *a,**kw:pytest.fail('selector reached preflight'))
    assert s['owner'].qualify_close(document)['state']=='rejected'


@pytest.mark.parametrize('native',[True,False])
def test_native_capture_fixed_export_only_for_exact_native_argv(actor_bridge,tmp_path,native):
    s=actor_bridge;m=s['m'];script=native_origin_bridge_script(s) if native else s['files']['submit_script']
    script=script.replace(b'unset QCL_NEGF_CAPTURE_SPEC',
        b'export QCL_NEGF_CAPTURE_SPEC=capture-spec.json QCL_NEGF_NATIVE_CAPTURE_INPUT=native-execution.json')
    replace_bridge_script(s,script)
    if native:
        assert s['sources'].preflight(s['document']['launch'],s['sources'].budget,
            calcjob_uuid=s['document']['calcjob_uuid'],action='submit')==s['host']
    else:
        selected=m.OrdinaryAttemptOwner(s['sources'].policy,m.AttemptStore(tmp_path),s['sources'],s['sources'].budget)
        assert selected.submit(s['document'])['state']=='hold'
        assert not (tmp_path/'attempts').exists()


@pytest.mark.parametrize('change',[
    b'export QCL_NEGF_NATIVE_CAPTURE_INPUT=native-execution.json QCL_NEGF_CAPTURE_SPEC=capture-spec.json',
    b'export QCL_NEGF_CAPTURE_SPEC=capture-spec.json',
    b'export QCL_NEGF_CAPTURE_SPEC=./capture-spec.json QCL_NEGF_NATIVE_CAPTURE_INPUT=native-execution.json',
    b'export QCL_NEGF_CAPTURE_SPEC=capture-spec.json QCL_NEGF_NATIVE_CAPTURE_INPUT=./native-execution.json',
    b'export QCL_NEGF_CAPTURE_SPEC="capture-spec.json" QCL_NEGF_NATIVE_CAPTURE_INPUT=native-execution.json',
    b'export QCL_NEGF_CAPTURE_SPEC=capture-spec.json QCL_NEGF_NATIVE_CAPTURE_INPUT=native-execution.json OTHER=1',
    b'export QCL_NEGF_CAPTURE_SPEC=capture-spec.json QCL_NEGF_NATIVE_CAPTURE_INPUT=native-execution.json; printf x',
    b'export QCL_NEGF_CAPTURE_SPEC=capture-spec.json\nexport QCL_NEGF_NATIVE_CAPTURE_INPUT=native-execution.json',
])
def test_native_capture_export_rejects_grammar_variants_before_effects(actor_bridge,tmp_path,change):
    s=actor_bridge;m=s['m'];script=native_origin_bridge_script(s).replace(b'unset QCL_NEGF_CAPTURE_SPEC',change)
    replace_bridge_script(s,script)
    selected=m.OrdinaryAttemptOwner(s['sources'].policy,m.AttemptStore(tmp_path),s['sources'],s['sources'].budget)
    assert selected.submit(s['document'])['state']=='hold'
    assert not (tmp_path/'attempts').exists() and not any('--parsable' in row[0] for row in s['calls'])


@pytest.mark.parametrize('fault',['root_path','root_role','technical_role'])
def test_q1t_v3_retained_root_mismatch_is_not_reused_or_repaired(q1_joined,fault):
    s=q1_joined;m=s['m'];document=q1t_document(s)
    assert s['owner'].qualify_close(document)['state']=='closed'
    directory=s['store'].path(document['calcjob_uuid']);path=directory/'close-observation.json'
    witness=json.loads(path.read_bytes())
    if fault=='root_path':witness['control_read']['roots'][0]['path']=document['launch']['remote_workdir']
    if fault=='root_role':witness['control_read']['roots'][0]['role']='workdir'
    if fault=='technical_role':
        next(row for row in witness['control_read']['files'] if row['path']=='performance-source.json')['root']='workdir'
    path.write_bytes(m.encoded(witness))
    before={name:(directory/name).read_bytes() for name in ('close.json','close-observation.json')}
    source=copy.copy(s['sources']);source.budget=m.Operation(source.policy['limits']);source.budget.read=s['sources'].budget.read
    result=m.OrdinaryAttemptOwner(source.policy,s['store'],source,source.budget).qualify_close(document)
    assert result['state']=='hold' and result['reason']=='q1_close_conflict'
    assert {name:(directory/name).read_bytes() for name in before}==before


def test_q1t_v3_reduced_leaf_fits_existing_eight_mib_close_budget(q1_joined):
    s=q1_joined;m=s['m'];raw=b'r'*65536;document=q1t_document(s,raw)
    budget=s['sources'].budget
    assert budget.limits['metadata_bytes']==8*1024*1024
    result=s['owner'].qualify_close(document)
    assert result['state']=='closed' and result['technical_control']==document['technical_control']
    assert budget.bytes<=8*1024*1024 and budget.actual_bytes>=len(raw)


@pytest.mark.parametrize('delta',[-1,0])
def test_q1t_v3_prepaid_leaf_boundary_before_pipe_fork_or_read(monkeypatch,delta):
    m=module();controls=[dict(path=name,bytes=0,sha256='0'*64) for name in m.CLOSE_FILES]
    technical=dict(status='present',path='performance-source.json',bytes='65536',sha256='0'*64)
    launch=request()['launch'];jobs='/srv/qcl-negf/jobs'
    depth=sum(len(Path(path).parts)-1 for path in (jobs+'/'+launch['relative_execution_root'],launch['remote_workdir']))
    total=8*4+16*65536+4096*(depth+4)+8*len(m.encoded(controls))+8*(65536+1)+8*len(m.encoded(technical))+65536
    budget=m.Operation({**limits(),'metadata_bytes':total+delta,'maximum_files':2048})
    policy=dict(limits=budget.limits,jobs_root=jobs);reached=[]
    monkeypatch.setattr(m.os,'geteuid',lambda:0)
    class Prepaid(Exception):pass
    def pipe(*args):reached.append('pipe');raise Prepaid()
    monkeypatch.setattr(m.os,'pipe2',pipe)
    monkeypatch.setattr(m.os,'fork',lambda:pytest.fail('no fork before synthetic pipe'))
    with pytest.raises(m.Hold if delta<0 else Prepaid):
        m._read_submitted_files_as_owner(policy,launch,budget,controls=controls,technical_control=technical)
    assert reached==([] if delta<0 else ['pipe']) and budget.bytes==total and budget.actual_bytes==0


def test_q1t_v3_cancelled_technical_read_never_publishes_close(q1_joined,monkeypatch,capsys):
    s=q1_joined;m=s['m'];document=q1t_document(s);target=(s['result']/'performance-source.json').stat().st_ino
    read=m.read_fd
    def cancelled(fd,limit,budget):
        if os.fstat(fd).st_ino==target:raise OSError('synthetic cancelled technical read')
        return read(fd,limit,budget)
    monkeypatch.setattr(m,'read_fd',cancelled)
    result=s['owner'].qualify_close(document)
    assert result['state']=='hold' and result['technical_control'] is None
    diagnostics=capsys.readouterr().err.splitlines()
    import base64
    retained=[json.loads(line.split(': ',1)[1]) for line in diagnostics]
    assert any(b'synthetic cancelled technical read' in base64.b64decode(row['original_prefix_base64']) for row in retained)
    directory=s['store'].path(document['calcjob_uuid'])
    assert not (directory/'close.json').exists() and not (directory/'close-observation.json').exists()


def test_q1t_v3_root_replacement_between_retries_is_hold_even_with_same_bytes(q1_joined):
    s=q1_joined;m=s['m'];document=q1t_document(s)
    assert s['owner'].qualify_close(document)['state']=='closed'
    directory=s['store'].path(document['calcjob_uuid'])
    before={name:(directory/name).read_bytes() for name in ('close.json','close-observation.json')}
    s['result'].rename(s['result'].with_name('original-result'))
    s['result'].mkdir(mode=0o755)
    for path in s['result'].with_name('original-result').iterdir():
        target=s['result']/path.name;target.write_bytes(path.read_bytes());target.chmod(0o640)
    source=copy.copy(s['sources']);source.budget=m.Operation(source.policy['limits']);source.budget.read=s['sources'].budget.read
    result=m.OrdinaryAttemptOwner(source.policy,s['store'],source,source.budget).qualify_close(document)
    assert result['state']=='hold' and result['reason']=='q1_close_conflict'
    assert {name:(directory/name).read_bytes() for name in before}==before


def test_q1t_v3_retry_timestamps_do_not_change_original_domain_identity(q1_joined):
    s=q1_joined;m=s['m'];document=q1t_document(s)
    first=s['owner'].qualify_close(document);assert first['state']=='closed'
    for root in (s['result'],s['work']):
        info=root.stat();os.utime(root,ns=(info.st_atime_ns,info.st_mtime_ns+1000000))
    source=copy.copy(s['sources']);source.budget=m.Operation(source.policy['limits']);source.budget.read=s['sources'].budget.read
    result=m.OrdinaryAttemptOwner(source.policy,s['store'],source,source.budget).qualify_close(document)
    assert result==first


@pytest.mark.parametrize('fault',['read_null','roots_null','root_null','directory_null','files_null','file_null'])
def test_q1t_v3_malformed_retained_domain_is_hold_with_immutable_records(q1_joined,fault):
    s=q1_joined;m=s['m'];document=q1t_document(s)
    assert s['owner'].qualify_close(document)['state']=='closed'
    directory=s['store'].path(document['calcjob_uuid']);path=directory/'close-observation.json'
    witness=json.loads(path.read_bytes());prior=witness['control_read']
    if fault=='read_null':witness['control_read']=None
    if fault=='roots_null':prior['roots']=None
    if fault=='root_null':prior['roots'][0]=None
    if fault=='directory_null':prior['roots'][0]['directory']=None
    if fault=='files_null':prior['files']=None
    if fault=='file_null':prior['files'][0]=None
    path.write_bytes(m.encoded(witness))
    before={name:(directory/name).read_bytes() for name in ('close.json','close-observation.json')}
    source=copy.copy(s['sources']);source.budget=m.Operation(source.policy['limits']);source.budget.read=s['sources'].budget.read
    result=m.OrdinaryAttemptOwner(source.policy,s['store'],source,source.budget).qualify_close(document)
    assert result['state']=='hold' and result['reason']=='q1_close_conflict'
    assert {name:(directory/name).read_bytes() for name in before}==before


@pytest.mark.parametrize('version',[1,3])
@pytest.mark.parametrize('state',['hold',[],{},None,False,1,1.0])
def test_q1t_external_client_typed_state_refusal_preserves_exact_wire(monkeypatch,capsys,version,state):
    import io
    from contextlib import contextmanager
    from types import SimpleNamespace
    m=module();document=request('close')
    document['controls']=[dict(path=name,bytes=0,sha256='0'*64) for name in m.CLOSE_FILES]
    response=dict(version=version,state=state,calcjob_uuid=document['calcjob_uuid'],receipt_ref=None,
        job=None,controls=None,reason='synthetic_hold')
    if version==3:
        document.update(version=3,technical_control=dict(status='absent',path=m.TECHNICAL_FILE,reason='not_published'))
        response['technical_control']=None
    raw_response=m.encoded(response);connections=[]
    class Connection:
        def __init__(self):
            self.raw=struct.pack('!I',len(raw_response))+raw_response;self.sent=bytearray();connections.append(self)
        def recv(self,size):
            chunk=self.raw[:size];self.raw=self.raw[size:];return chunk
        def sendall(self,data):self.sent.extend(data)
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def settimeout(self,*args):pass
        def connect(self,path):assert path==m.SOCKET
        def shutdown(self,*args):pass
        def getsockopt(self,*args):return struct.pack('3i',1,0,0)
    @contextmanager
    def directory(*args,**kwargs):yield 999
    info=SimpleNamespace(st_dev=1,st_ino=2,st_uid=0,st_gid=3000,st_mode=m.stat.S_IFSOCK|0o660,
        st_nlink=1,st_size=0,st_mtime_ns=1,st_ctime_ns=1)
    original_stat=m.os.stat
    monkeypatch.setattr(m.os,'stat',lambda path,*a,**kw:info if path==Path(m.SOCKET).name else original_stat(path,*a,**kw))
    monkeypatch.setattr(m,'protected_directory',directory)
    monkeypatch.setattr(m.socket,'socket',lambda *a,**kw:Connection())
    monkeypatch.setattr(m.sys,'argv',['client','close'])
    monkeypatch.setattr(m.sys,'stdin',SimpleNamespace(buffer=io.BytesIO(m.encoded(document))))
    assert m.client_main()==75
    output=capsys.readouterr().out
    if state=='hold':expected=response
    else:
        context=dict(version=3,action='close',calcjob_uuid=document['calcjob_uuid']) if version==3 else {}
        expected=m.reply(context,'hold',reason='reply_shape')
    assert output.encode()==m.encoded(expected)+b'\n'
    assert set(json.loads(output))==set(expected) and expected['version']==version
    assert expected['job'] is expected['controls'] is expected['receipt_ref'] is None
    if version==3:assert expected['technical_control'] is None and expected['calcjob_uuid']==document['calcjob_uuid']
    raw_request=m.encoded(document)
    assert connections[0].sent==struct.pack('!I',len(raw_request))+raw_request
    assert connections[0].raw==b''
