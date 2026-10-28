from dataclasses import replace
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'ops'))
from test_host_resource_operations import setup,guest,completion


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
