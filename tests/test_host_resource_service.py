from dataclasses import replace
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'ops'))
from test_host_resource_operations import setup,guest,completion


def test_attempt_facts_is_the_only_new_readonly_root_fact_action(monkeypatch):
    import host_resource_service as s
    import native_attempt as n
    config = {'schema': 'qcl.host-resource-service.v1', 'role': 'guest', 'client_uid': 3000}
    monkeypatch.setattr(s.os, 'geteuid', lambda: 0)
    monkeypatch.delenv('SUDO_UID', raising=False)
    monkeypatch.setattr(s, 'read_root_json', lambda path: config)
    packet = {'version': 1, 'calcjob_uuid': '11111111-1111-4111-8111-111111111111',
              'dispatch_id': '22222222-2222-4222-8222-222222222222', 'job_id': '42',
              'generation': 'a' * 64, 'phase': 'status'}
    import base64
    import json
    token = base64.urlsafe_b64encode(json.dumps(packet).encode()).decode()
    calls = []
    monkeypatch.setattr(n, 'read_attempt_facts', lambda document: calls.append(document) or {'version': 1})
    assert s.root_main('facts', ['attempt-facts', token]) == {'version': 1}
    assert calls == [packet]
    with pytest.raises(s.ResourceError):
        s.root_main('facts', ['submit', token])
    assert calls == [packet]


@pytest.mark.parametrize('inherited', [False, True])
def test_rpc_trust_snapshot_root_and_shared_budget_preserve_default(monkeypatch, inherited):
    import host_resource_facts as f
    import native_attempt as n
    route = dict(target='facts@worker', known_hosts='/protected/hosts', identity_file='/protected/key',
                 helper='/fixed/qcl-negf-resource-rpc', role='facts')
    class Trusted:
        def __str__(self): return '/protected/key'
        def stat(self): return type('Info', (), {'st_mode': 0o600})()
    monkeypatch.setattr(f, 'trusted_root_path', lambda path, **kw: Trusted())
    events = []
    def read(path, **kwargs):
        events.append(('read', kwargs)); return b'host key\n'
    def freeze(raw, **kwargs):
        events.append(('freeze', kwargs)); return {'path': '/protected/snapshot', 'sha256': 'a' * 64}
    monkeypatch.setattr(f.command_engine, 'read_protected_file', read)
    monkeypatch.setattr(f.command_engine, 'freeze_ssh_trust', freeze)
    def ssh(target, argv, **kwargs):
        return kwargs['run'](['ssh', 'fixed-target'])
    monkeypatch.setattr(f.command_engine, 'ssh', ssh)
    calls = []
    def run(argv, **kwargs): calls.append(kwargs); return '{"observed":1}'
    budget = n.Operation(dict(limits_for_rpc()))
    extra = dict(trust_snapshot_root='/protected/local/trust-snapshots', existing_budget=budget) if inherited else {}
    assert f.trusted_rpc(route, 'attempt-facts', {'version': 1}, run=run, **extra) == {'observed': 1}
    assert events[0][1] == ({'budget': budget} if inherited else {})
    assert events[1][1] == ({'snapshot_root': '/protected/local/trust-snapshots'} if inherited else {})
    before = budget.bytes
    assert f.trusted_rpc(route, 'attempt-facts', {}, run=run, **extra) == {'observed': 1}
    assert (budget.bytes > before > 0) if inherited else budget.bytes == before == 0
    assert all(call == dict(timeout_seconds=120, output_bytes=f.MAX_OUTPUT_BYTES) for call in calls)


def limits_for_rpc():
    return dict(request_bytes=65536, response_bytes=262144, script_bytes=65536,
                metadata_bytes=8 * 1024 * 1024, memory_bytes=134217728,
                operation_seconds=30, command_seconds=10, cleanup_seconds=1,
                maximum_pids=256, maximum_calls=64, maximum_files=128)


@pytest.mark.parametrize('status',[0,7])
def test_forced_ssh_keeps_actual_python_parent_and_exact_streams(monkeypatch,capfd,status):
    """Real owned local child; the substituted argv is explicitly not sudo/N."""
    import host_resource_service as s
    import subprocess,json,os
    original=subprocess.Popen;seen=[]
    def child(argv,**kwargs):
        seen.append(argv)
        script=('import os,sys,json; print(json.dumps(dict(parent=os.getppid(),argv=sys.argv[1:]))); '
                'print("preserved stderr",file=sys.stderr);sys.exit('+str(status)+')')
        return original([sys.executable,'-c',script,*argv],**kwargs)
    monkeypatch.setattr(subprocess,'Popen',child)
    monkeypatch.setattr(s.os,'execvp',lambda *a:pytest.fail('fixed Python ingress parent disappeared'))
    monkeypatch.setenv('SSH_ORIGINAL_COMMAND','/fixed/qcl-negf-resource-rpc facts scheduler-facts e30=')
    with pytest.raises(SystemExit) as caught:s.ssh_main('facts',helper_prefix='/fixed')
    assert caught.value.code==status
    stdout,stderr=capfd.readouterr();packet=json.loads(stdout)
    assert packet['parent']==os.getpid()
    assert packet['argv']==seen[0]==['sudo','-n','/fixed/qcl-negf-resource-facts','scheduler-facts','e30=']
    assert stderr=='preserved stderr\n'


def test_forced_ssh_owned_timeout_is_bounded_and_reaped(monkeypatch):
    import host_resource_service as s
    import subprocess,os,time
    original=subprocess.Popen;children=[]
    def child(argv,**kwargs):
        process=original([sys.executable,'-c','import time;time.sleep(30)'],**kwargs)
        children.append(process);return process
    monkeypatch.setattr(subprocess,'Popen',child)
    started=time.monotonic()
    with pytest.raises(s.ResourceError,match='timeout'):
        s._wait_ssh_helper(['sudo','-n','fixed'],timeout_seconds=.3,cleanup_seconds=.15)
    assert time.monotonic()-started<2 and len(children)==1
    with pytest.raises(ChildProcessError):os.waitpid(children[0].pid,os.WNOHANG)


def test_forced_ssh_cancellation_keeps_primary_and_reaps_owned_child(monkeypatch):
    import host_resource_service as s
    import subprocess,os
    original=subprocess.Popen;children=[];primary=KeyboardInterrupt('original cancellation')
    def child(argv,**kwargs):
        process=original([sys.executable,'-c','import time;time.sleep(30)'],**kwargs)
        children.append(process);return process
    monkeypatch.setattr(subprocess,'Popen',child)
    original_status=s.engine._command_child_status;calls=[]
    def interrupted(process):
        calls.append(1)
        if len(calls)==1:raise primary
        return original_status(process)
    monkeypatch.setattr(s.engine,'_command_child_status',interrupted)
    with pytest.raises(KeyboardInterrupt) as caught:s._wait_ssh_helper(['sudo','-n','fixed'])
    assert caught.value is primary
    with pytest.raises(ChildProcessError):os.waitpid(children[0].pid,os.WNOHANG)


@pytest.fixture
def fixed_facts_ingress(monkeypatch):
    """Explicit SOURCE/L process/origin operands, not installed root authority."""
    import host_resource_service as s
    import native_attempt as n
    root='/nix/store/platform-source/ops';python='/nix/store/python/bin/python3'
    monkeypatch.setattr(s,'__file__',root+'/host_resource_service.py')
    monkeypatch.setattr(n,'__file__',root+'/native_attempt.py')
    monkeypatch.setattr(s.os,'getuid',lambda:0);monkeypatch.setattr(s.os,'geteuid',lambda:0)
    monkeypatch.setattr(s.os,'getpid',lambda:100);monkeypatch.setattr(s.os,'getppid',lambda:90)
    monkeypatch.setattr(s.sys,'executable',python);monkeypatch.setattr(s.sys,'argv',['-c','scheduler-facts','e30='])
    monkeypatch.setenv('SUDO_UID','3002')
    config=dict(role='controller',facts_uid=3002,sudo_executables=['/nix/store/sudo/bin/sudo'])
    rows={100:dict(pid=100,ppid=90,uids=[0]*4,start_ticks=30,cgroup='/ssh.session',executable=python),
        90:dict(pid=90,ppid=80,uids=[0]*4,start_ticks=20,cgroup='/ssh.session',executable=config['sudo_executables'][0]),
        80:dict(pid=80,ppid=70,uids=[3002]*4,start_ticks=10,cgroup='/ssh.session',executable=python)}
    for row in rows.values():row.update(state='S',comm='explicit fixture process')
    prefix="import sys; sys.path.insert(0, '"+root+"'); import host_resource_service as m; "
    argv={100:[python,'-I','-c',prefix+"sys.exit(m.main('facts'))",'scheduler-facts','e30='],
        90:['sudo','-n','/run/current-system/sw/bin/qcl-negf-resource-facts','scheduler-facts','e30='],
        80:[python,'-I','-c',prefix+"m.ssh_main('facts')"]}
    sources=n.NativeSources({},n._bootstrap_operation())
    monkeypatch.setattr(sources,'process',lambda pid:dict(rows[pid]))
    monkeypatch.setattr(sources,'command_line',lambda pid:list(argv[pid]))
    monkeypatch.setattr(s.engine,'public_binary_origin',lambda budget,path,**kw:dict(path=str(path),chain=[]))
    return s,sources,config,rows,argv


@pytest.mark.parametrize('fault',['none','literal_python_entry','same_uid_shell','root_shell','wrong_module','different_interpreter','sudo_argv','missing_sudo'])
def test_scheduler_ingress_requires_actual_retained_fixed_chain(fixed_facts_ingress,monkeypatch,fault):
    s,sources,config,rows,argv=fixed_facts_ingress
    if fault=='same_uid_shell':argv[80]=['/bin/sh','-c','pretend facts']
    if fault=='root_shell':argv[100]=[s.sys.executable,'-c','import host_resource_service']
    if fault=='wrong_module':argv[80][3]=argv[80][3].replace('platform-source','other-source')
    if fault=='different_interpreter':rows[80]['executable']='/nix/store/other/bin/python3'
    if fault=='sudo_argv':argv[90][2]='/different/root-helper'
    if fault=='missing_sudo':monkeypatch.delenv('SUDO_UID')
    if fault=='literal_python_entry':argv[100][0]=argv[80][0]='python3'
    if fault in ('none','literal_python_entry'):
        first=s._scheduler_facts_ingress(sources,config)
        assert first==s._scheduler_facts_ingress(sources,config)
    else:
        with pytest.raises((s.ResourceError,__import__('native_attempt').Hold)):
            s._scheduler_facts_ingress(sources,config)


def test_scheduler_ingress_snapshot_detects_current_helper_selector_switch(fixed_facts_ingress,monkeypatch):
    s,sources,config,rows,argv=fixed_facts_ingress
    selected={'output':'/nix/store/current-helper/bin/facts'}
    def origin(budget,path,**kw):
        return dict(path=selected['output'] if str(path).endswith('/qcl-negf-resource-facts') else str(path),chain=[])
    monkeypatch.setattr(s.engine,'public_binary_origin',origin)
    before=s._scheduler_facts_ingress(sources,config)
    selected['output']='/nix/store/replacement-helper/bin/facts'
    after=s._scheduler_facts_ingress(sources,config)
    assert before!=after


def test_rpc_inherited_limit_before_snapshot_and_primary_failure(monkeypatch):
    import host_resource_facts as f
    import native_attempt as n
    route = dict(target='facts@worker', known_hosts='/protected/hosts', identity_file='/protected/key',
                 helper='/fixed/qcl-negf-resource-rpc', role='facts')
    class Trusted:
        def stat(self): return type('Info', (), {'st_mode': 0o600})()
    monkeypatch.setattr(f, 'trusted_root_path', lambda path, **kw: Trusted())
    monkeypatch.setattr(f.command_engine, 'read_protected_file', lambda *a, **kw: b'host key\n')
    monkeypatch.setattr(f.command_engine, 'freeze_ssh_trust', lambda *a, **kw: pytest.fail('snapshot after exhausted budget'))
    budget = n.Operation(limits_for_rpc()); budget.bytes = budget.limits['metadata_bytes']
    with pytest.raises(n.Hold):
        f.trusted_rpc(route, 'attempt-facts', {}, run=lambda *a, **kw: pytest.fail('RPC after exhausted budget'),
                      trust_snapshot_root='/protected/local/trust-snapshots', existing_budget=budget)
    primary = OSError('original snapshot failure')
    monkeypatch.setattr(f.command_engine, 'freeze_ssh_trust', lambda *a, **kw: (_ for _ in ()).throw(primary))
    budget = n.Operation(limits_for_rpc())
    with pytest.raises(OSError) as captured:
        f.trusted_rpc(route, 'attempt-facts', {}, run=lambda *a, **kw: pytest.fail('RPC after failure'),
                      trust_snapshot_root='/protected/local/trust-snapshots', existing_budget=budget)
    assert captured.value is primary and budget.bytes > 0


@pytest.mark.parametrize('case',['exact','request_short','decoder_short','large','cancel'])
def test_inherited_rpc_prepays_new_request_and_decoder_not_another_transport(monkeypatch,case):
    import host_resource_facts as f,native_attempt as n
    route=dict(target='facts@worker',known_hosts='/protected/hosts',identity_file='/protected/key',helper='/fixed/rpc',role='facts')
    class Trusted:
        def __str__(self):return '/protected/key'
        def stat(self):return type('Info',(),{'st_mode':0o600})()
    monkeypatch.setattr(f,'trusted_root_path',lambda *a,**kw:Trusted())
    events=[];budget=n.Operation(limits_for_rpc());primary=KeyboardInterrupt('original RPC cancellation')
    monkeypatch.setattr(f.command_engine,'read_protected_file',lambda *a,**kw:events.append('trust-read') or b'key')
    monkeypatch.setattr(f.command_engine,'freeze_ssh_trust',lambda *a,**kw:events.append('snapshot') or {'path':'snapshot'})
    monkeypatch.setattr(f.command_engine,'ssh',lambda target,argv,**kw:kw['run'](['ssh','fixed']))
    raw='{"ok":1}' if case!='large' else '{"large":"'+'x'*200000+'"}'
    def run(*a,**kw):
        events.append('command')
        if case=='cancel':raise primary
        if case=='decoder_short':budget.bytes=budget.limits['metadata_bytes']-1
        return raw
    if case=='request_short':budget.bytes=budget.limits['metadata_bytes']-1
    parser=f.strict_json
    def parse(value):events.append('parse');return parser(value)
    monkeypatch.setattr(f,'strict_json',parse)
    if case=='exact':
        assert f.trusted_rpc(route,'attempt-facts',{'version':1},run=run,existing_budget=budget)=={'ok':1}
        # No command charge in this explicit transport seam. Its real caller
        # separately prepays four response caps before running the process.
        assert budget.bytes<200000 and events[-1]=='parse'
    else:
        with pytest.raises(KeyboardInterrupt if case=='cancel' else n.Hold) as caught:
            f.trusted_rpc(route,'attempt-facts',{'version':1},run=run,existing_budget=budget)
        if case=='cancel':assert caught.value is primary
        if case=='request_short':assert events==[]
        if case in ('large','decoder_short'):assert 'command' in events and 'parse' not in events


def test_scheduler_root_route_enters_single_operation_before_generic_config(monkeypatch):
    import host_resource_service as s,native_attempt as n
    monkeypatch.setattr(s.os,'geteuid',lambda:0)
    monkeypatch.setattr(s.sys,'argv',['-c','scheduler-facts','e30='])
    monkeypatch.setattr(s,'read_root_json',lambda *a:pytest.fail('configuration outside factory operation'))
    packet=dict(schema='qcl.host-resource-scheduler-facts.v1',jobs={},outputs={})
    monkeypatch.setattr(n,'capture_scheduler_output_facts',lambda:packet)
    assert s.root_main('facts') is packet


def service(tmp_path):
    from host_resource_service import NativeResourceService
    from host_resource_client import NativeWorkloadRef,NativeDemand
    m,c,b,store,e=setup(tmp_path)
    class Provider:
        native=dict(native_id='42',generation='g42',owner_uid=3000,node='node-a',limit_bytes=321,state='RUNNING',terminal=False)
        available=384;events=[]
        def resolve(self,ref):
            assert ref.native_id=='42';return self.native,'vm-a','slurm:g42','native-request-42-g42'
        def request_facts(self,demand,*,owner_state):
            assert store._lock_owner is not None
            self.events.append('host');return e
        def guest_admission(self,request_id,*,owner_state):
            self.events.append('guest');assert store.load()['grants'][0]['guest_bytes']==512
            return replace(guest(m,'slurm:g42',total=512,available=self.available),slurm_memory_bytes=384)
        def completion(self,request_id,*,owner_state):return completion(m,'slurm:g42')
        def cleanup(self,*a,**kw):return None
    p=Provider();s=NativeResourceService(c,p,clock=lambda:100)
    d=NativeDemand('qcl.host-resource-native-demand.v1',NativeWorkloadRef('slurm_allocation','42'),321)
    return s,d,m,c,b,store,e,p


def test_request_reaches_host_full_grant_before_guest_fit_and_duplicate_no_mutation(tmp_path):
    s,d,m,c,b,store,e,p=service(tmp_path);p.available=10
    view=s.request_native(d)
    assert view['phase']=='GUEST_ADMIT' and view['admission']=='resource_wait'
    assert p.events==['host','guest'] and b.calls==[('vm-a',512)]
    p.available=384;view=s.request_native(d)
    assert view['phase']=='RUN' and view['admission']=='ready'
    e.live_workloads['vm-a']=('slurm:g42',)
    assert s.request_native(d)['phase']=='RUN' and len(b.calls)==1
    before=store.state_path.read_bytes();s.read_native_status(d.workload)
    assert store.state_path.read_bytes()==before


@pytest.mark.parametrize('outcome',['success','recoverable','fatal','cancel'])
def test_service_discards_native_output_pending_at_every_invocation_exit(tmp_path,monkeypatch,outcome):
    """Typed SOURCE/L provider seam; seeded private maps carry no authority."""
    from host_resource_facts import NativeFactsProvider
    s,d,m,c,b,store,e,old=service(tmp_path);old.available=384
    provider=NativeFactsProvider(c.policy,{},b,None,sources=object());s.provider=provider
    error={'success':None,'recoverable':m.ResourceError('cleanup','synthetic incomplete output'),
        'fatal':MemoryError('original fatal'),'cancel':KeyboardInterrupt('original cancellation')}[outcome]
    def resolve(ref):
        provider._output_epoch=provider._joined_epoch=object()
        provider._pending_outputs={'synthetic':'pending'};provider._joined_outputs={'synthetic':'joined'}
        provider.last=('old','guest');return old.resolve(ref)
    def capture(*args,**kwargs):
        if error is not None:raise error
        return old.request_facts(*args,**kwargs)
    monkeypatch.setattr(provider,'resolve',resolve);monkeypatch.setattr(provider,'request_facts',capture)
    monkeypatch.setattr(provider,'guest_admission',old.guest_admission)
    if outcome in ('fatal','cancel'):
        with pytest.raises(type(error)) as caught:s.request_native(d)
        assert caught.value is error
    else:
        view=s.request_native(d)
        assert view['failure_code']==('cleanup' if outcome=='recoverable' else None)
    assert provider._output_epoch is provider._joined_epoch is provider.last is None
    assert provider._pending_outputs==provider._joined_outputs=={}


def test_unknown_never_replays_and_missing_generation_does_not_mint_identity(tmp_path):
    s,d,m,c,b,store,e,p=service(tmp_path);b.fault='native-cleanup-unconfirmed'
    assert s.request_native(d)['admission']=='reconciliation_required'
    assert s.request_native(d)['admission']=='reconciliation_required' and len(b.calls)==1
    assert s.reconcile_native(d.workload)['admission']=='reconciliation_required'
    before=store.state_path.read_bytes()
    def evicted(ref):raise m.ResourceError('native_generation','gone')
    p.resolve=evicted
    assert s.request_native(d)['failure_code']=='native_generation'
    assert store.state_path.read_bytes()==before and len(b.calls)==1


def test_finish_requires_actual_provider_completion_not_client_desire(tmp_path):
    s,d,m,c,b,store,e,p=service(tmp_path);s.request_native(d);e.live_workloads['vm-a']=('slurm:g42',)
    def completing(*a,**kw):raise m.ResourceError('cleanup','COMPLETING or gate is not terminal')
    p.completion=completing
    assert s.finish_native(d.workload)['admission']=='reconciliation_required'
    assert c.snapshot()[0].guest_bytes==512 and store.load()['receipts'][0]['phase']=='RUN'


def test_two_live_allocations_same_vm_finish_one_preserves_other_floor(tmp_path):
    from host_resource_service import NativeResourceService
    from host_resource_client import NativeWorkloadRef,NativeDemand
    m,c,b,store,e=setup(tmp_path)
    class Provider:
        def resolve(self,ref):
            return dict(generation='g'+ref.native_id,limit_bytes=100),'vm-a','slurm:g'+ref.native_id,'request-'+ref.native_id
        def request_facts(self,demand,*,owner_state):return e
        def guest_admission(self,request_id,*,owner_state):
            row=next(r for r in owner_state['receipts'] if r['request']['request_id']==request_id)
            grant=owner_state['grants'][0]
            return replace(guest(m,row['request']['workload_id'],live=e.live_workloads['vm-a'],
                total=grant['guest_bytes'],available=grant['guest_bytes']-128),task_limit_bytes=100,slurm_memory_bytes=grant['guest_bytes']-128)
        def completion(self,request_id,*,owner_state):
            return replace(completion(m,'slurm:g'+request_id.split('-')[1],live=e.live_workloads['vm-a']),total_bytes=b.rows['vm-a'].assigned_bytes,available_bytes=b.rows['vm-a'].assigned_bytes-128)
        def cleanup(self,*a,**k):return None
    s=NativeResourceService(c,Provider(),clock=lambda:100)
    one=NativeDemand('qcl.host-resource-native-demand.v1',NativeWorkloadRef('slurm_allocation','42'),100)
    two=replace(one,workload=NativeWorkloadRef('slurm_allocation','43'))
    assert s.request_native(one)['phase']=='RUN';e.live_workloads['vm-a']=('slurm:g42',)
    assert s.request_native(two)['phase']=='RUN';e.live_workloads['vm-a']=('slurm:g42','slurm:g43')
    full=c.snapshot()[0].guest_bytes;calls=list(b.calls)
    e.live_workloads['vm-a']=('slurm:g43',)
    assert s.finish_native(one.workload)['phase']=='RELEASE'
    assert c.snapshot()[0].guest_bytes==full and c.snapshot()[0].active_floor_bytes==228 and b.calls==calls
    assert s.request_native(two)['phase']=='RUN' and b.calls==calls
    assert len(store.load()['receipts'])==1


def test_reused_active_native_generation_is_closed_before_facts_or_charge_change(tmp_path):
    s,d,m,c,b,store,e,p=service(tmp_path);s.request_native(d)
    before=store.state_path.read_bytes();events=list(p.events)
    original=p.resolve
    def reused(ref):
        native,vm,wid,rid=original(ref)
        return {**native,'generation':'new-generation'},vm,'new-workload','new-request'
    p.resolve=reused
    view=s.request_native(d)
    assert view['admission']=='reconciliation_required' and view['failure_code']=='native_generation'
    assert store.state_path.read_bytes()==before and p.events==events and len(b.calls)==1


def test_native_invocation_context_durable_before_actual_mutator(tmp_path):
    from test_host_resource_operations import request
    m,c,b,store,e=setup(tmp_path)
    c.request(request(m),e);original=b.resize
    def prepare(row):return dict(unit='qcl-resource-'+'a'*32+'.service',invocation_id='b'*32,
        cgroup='/system.slice/qcl-resource.service',host_boot_id=e.host_boot_id,mutation_id=row['mutation_id'])
    def resize(*args):
        row=store.load()['receipts'][0]
        assert row['native_context']==prepare(row) and not row['native_cleanup_confirmed']
        return original(*args)
    b.prepare_mutation=prepare;b.resize=resize
    assert c.grow('request-1',e).phase=='GUEST_ADMIT'


def test_status_dispatch_does_not_open_writer_or_construct_backend(tmp_path,monkeypatch):
    import host_resource_service as s
    from dataclasses import asdict
    m,c,b,store,e=setup(tmp_path);s.NativeResourceService(c,None).controller.request(__import__('test_host_resource_operations').request(m),e)
    state=store.load();state['receipts'][0]['native_workload']={'kind':'slurm_allocation','native_id':'42','generation':'g42'};store.save(state)
    policy=__import__('json').loads(__import__('json').dumps({**asdict(c.policy),'schema':'qcl.host-resource-policy.v1'}))
    monkeypatch.setattr(s,'read_root_json',lambda path:({'role':'native_host','runtime':'runtime'} if path==s.CONFIG else {'policy':'policy','state_directory':str(store.directory)} if path=='runtime' else policy))
    monkeypatch.setattr(s,'trusted_root_path',lambda path,**kw:Path(path))
    monkeypatch.setattr(s,'open_service',lambda:pytest.fail('status opened writer'))
    original=s.FileReceiptStore.open_existing
    monkeypatch.setattr(s.FileReceiptStore,'open_existing',lambda directory:original(directory,owner_uid=__import__('os').getuid()))
    before=store.state_path.read_bytes()
    result=s.dispatch('status',{'schema':'qcl.host-resource-native-reference.v1','workload':{'kind':'slurm_allocation','native_id':'42'}})
    assert result['request_id']=='request-1' and store.state_path.read_bytes()==before


def test_readonly_status_does_not_reauthorize_run_from_unmeasured_readback(tmp_path):
    s,d,m,c,b,store,e,p=service(tmp_path);assert s.request_native(d)['admission']=='ready'
    before=store.state_path.read_bytes();p.events=[]
    view=s.read_native_status(d.workload)
    assert view['phase']=='RUN' and view['admission']=='reconciliation_required'
    assert view['failure_code']=='readback_not_measured' and p.events==[]
    assert store.state_path.read_bytes()==before


@pytest.mark.parametrize('action', ['request', 'launch-gate', 'reconcile', 'finish-noop'])
@pytest.mark.parametrize('changed,code', [
    ('healthy', None), ('host_boot', 'identity_mismatch'),
    ('policy', 'identity_mismatch'), ('runtime_binding', 'identity_mismatch'),
    ('startup_quarantine', 'startup_binding_required'), ('host_pressure', 'host_pressure'),
    ('stale', 'stale_evidence'), ('incomplete_workloads', 'incomplete_workloads'),
    ('missing_bindings', 'incomplete_bindings'),
    ('assigned_below_floor', 'identity_mismatch'), ('configured_below_floor', 'identity_mismatch'),
])
def test_every_existing_run_authorization_rechecks_full_owner_guard(tmp_path,monkeypatch,action,changed,code):
    from host_resource_service import NativeResourceService
    from host_resource_client import NativeDemand,NativeWorkloadRef
    m,c,b,store,e=setup(tmp_path,mechanism='conservative_reservation')
    class Provider:
        facts=e
        def resolve(self,ref):return dict(generation='g42',limit_bytes=321),'vm-a','slurm:g42','native-fixed-42'
        def request_facts(self,*a,**kw):return self.facts
        def guest_admission(self,*a,**kw):
            return replace(guest(m,'slurm:g42',total=1536,available=1408),slurm_memory_bytes=1408)
        def completion(self,*a,**kw):return completion(m,'slurm:g42')
        def cleanup(self,*a,**kw):return None
    p=Provider();s=NativeResourceService(c,p)
    demand=NativeDemand('qcl.host-resource-native-demand.v1',NativeWorkloadRef('slurm_allocation','42'),321)
    assert s.request_native(demand)['admission']=='ready'
    e.live_workloads['vm-a']=('slurm:g42',)
    if changed=='host_boot':p.facts=replace(e,host_boot_id='new-host-boot')
    if changed=='policy':p.facts=replace(e,policy_sha256='0'*64)
    if changed=='runtime_binding':
        binding=replace(e.bindings[0],guest_boot_id='new-boot')
        p.facts=replace(e,bindings=(binding,e.bindings[1]),qualifications=(replace(e.qualifications[0],binding=binding),e.qualifications[1]))
    if changed=='startup_quarantine':
        state=store.load();state['startups']['vm-a']['phase']='running_quarantined';store.save(state)
    if changed=='host_pressure':p.facts=replace(e,pressure_ok=False)
    if changed=='stale':p.facts=replace(e,observed_at=0)
    if changed=='incomplete_workloads':p.facts=replace(e,live_workloads={'vm-a':(),'vm-b':()})
    if changed=='missing_bindings':p.facts=replace(e,bindings=e.bindings[:1])
    if changed=='assigned_below_floor':b.rows['vm-a']=replace(b.rows['vm-a'],assigned_bytes=128)
    if changed=='configured_below_floor':b.rows['vm-a']=replace(b.rows['vm-a'],configured_bytes=128)
    before=store.state_path.read_bytes();request=store.load()['receipts'][0]['request']
    if action=='finish-noop':
        # A no-op completion adapter must not turn a held RUN into authorization.
        monkeypatch.setattr(c,'finish',lambda *a,**kw:None)
        view=s.finish_native(demand.workload)
    elif action=='reconcile':view=s.reconcile_native(demand.workload)
    else:view=s._invoke(action,demand)
    assert view['failure_code']==code
    assert view['admission']==('ready' if code is None else 'resource_wait' if code=='host_pressure' else 'rejected' if code=='stale_evidence' else 'reconciliation_required')
    assert view['charged_bytes']==1536 and view['phase']=='RUN' and not b.calls
    assert store.load()['receipts'][0]['request']==request
    if code is None:
        assert view['native_freshness']['status']=='fresh' and store.state_path.read_bytes()==before
    else:
        assert view['native_freshness']['status']=='not_measured'
        # A new service owner/reload cannot erase a failed authorization.
        reloaded=NativeResourceService(m.HostResourceController(c.policy,store,b,clock=lambda:100),p)
        assert reloaded.request_native(demand)['admission']!='ready' and not b.calls


@pytest.mark.parametrize('action', ['request', 'launch-gate', 'reconcile'])
def test_run_authorization_respects_other_vm_unknown_cleanup_without_replay(tmp_path,action):
    from test_host_resource_operations import request
    s,d,m,c,b,store,e,p=service(tmp_path)
    assert s.request_native(d)['admission']=='ready';e.live_workloads['vm-a']=('slurm:g42',)
    c.request(request(m,'other-request','other-work',321,vm='vm-b'),e);b.fault='process-crash'
    with pytest.raises(SystemExit):c.grow('other-request',e)
    before=store.state_path.read_bytes();calls=list(b.calls)
    view=s._invoke(action,d if action!='reconcile' else d.workload)
    assert view['admission']=='reconciliation_required' and view['failure_code']=='reconciliation_required'
    assert view['charged_bytes']==512 and view['phase']=='RUN'
    assert store.state_path.read_bytes()==before and b.calls==calls


def test_safe_finish_progresses_under_pressure_without_reauthorizing_run(tmp_path):
    s,d,m,c,b,store,e,p=service(tmp_path)
    assert s.request_native(d)['admission']=='ready'
    # Exact terminal/descendant/output proof is a synthetic fixture here.
    p.request_facts=lambda *a,**kw:replace(e,pressure_ok=False)
    p.completion=lambda *a,**kw:replace(completion(m,'slurm:g42'),total_bytes=b.rows['vm-a'].assigned_bytes,available_bytes=0)
    view=s.finish_native(d.workload)
    # The pre-shrink completion snapshot cannot prove the smaller allocation.
    assert view['phase']=='SHRINK_UNKNOWN' and view['failure_code']=='guest_readback'
    assert view['charged_bytes']==512 and view['admission']!='ready'
    view=s.reconcile_native(d.workload)
    assert view['phase']=='RELEASE' and view['admission']!='ready' and view['failure_code'] is None
    assert len(b.calls)==2


def test_completed_duplicate_never_becomes_fresh_run_or_replays_native(tmp_path):
    s,d,m,c,b,store,e,p=service(tmp_path)
    assert s.request_native(d)['admission']=='ready'
    p.completion=lambda *a,**kw:replace(completion(m,'slurm:g42'),total_bytes=b.rows['vm-a'].assigned_bytes,available_bytes=0)
    assert s.finish_native(d.workload)['phase']=='SHRINK_UNKNOWN'
    assert s.reconcile_native(d.workload)['phase']=='RELEASE'
    before=store.state_path.read_bytes();calls=list(b.calls)
    p.request_facts=lambda *a,**kw:pytest.fail('completed duplicate refreshed facts')
    view=s.request_native(d)
    assert view['phase']=='RELEASE' and view['admission']!='ready'
    assert view['native_freshness']['status']=='not_measured'
    assert store.state_path.read_bytes()==before and b.calls==calls
