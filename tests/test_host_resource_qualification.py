"""Attached calibration C ownership fixtures; no real native command/qualification."""
from dataclasses import asdict,replace
import copy,hashlib,json
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'ops'))
from test_host_resource_native_cleanup import fixture as production_fixture
OP='1b2f9137-3b02-4b3b-a38c-3cebb3a03f5b'

def calibration(tmp_path):
    import host_resource_qualification as q
    n,m,c,b,store,e,p,s,oldrunner,profiles=production_fixture(tmp_path)
    # Deliberate synthetic host capacity covers both full VM maxima.
    policy=replace(c.policy,physical_ram_bytes=8192,owned_pool=replace(c.policy.owned_pool,capacity_bytes=7168))
    c.policy=p.policy=policy
    for profile in profiles:profile['policy_sha256']=m.policy_digest(policy)
    e=replace(e,physical_ram_bytes=policy.physical_ram_bytes,policy_sha256=m.policy_digest(policy))
    state=store.load();state['policy_sha256']=m.policy_digest(policy)
    for g in state['grants']:
        vm=c._vm(g['vm_id']);g.update(guest_bytes=vm.maximum_bytes,active_floor_bytes=vm.minimum_bytes,state='idle')
        state['desired'][g['vm_id']]=g['guest_bytes'];state['startups'][g['vm_id']].update(phase='running_quarantined',reservation_id='original-synthetic-reservation')
        b.rows[g['vm_id']]=replace(b.rows[g['vm_id']],assigned_bytes=g['guest_bytes'],configured_bytes=g['guest_bytes'])
    store.save(state);raw=store.state_path.read_bytes()
    e=replace(e,qualifications=tuple(replace(x,qualified_dynamic=False,active_floor_protection=False,readback_verified=False,slurm_registration_verified=False)for x in e.qualifications))
    plan=dict(schema=q.PLAN_SCHEMA,operation_id=OP,host_id=c.policy.host_id,owner_id=c.policy.owner_id,host_boot_id=e.host_boot_id,policy_sha256=m.policy_digest(c.policy),baseline_state_sha256=hashlib.sha256(raw).hexdigest(),source_graph_sha256='a'*64,bindings=copy.deepcopy(state['bindings']),cases={'idle-shrink':{'vm_id':'vm-a','target_bytes':128},'idle-grow':{'vm_id':'vm-a','target_bytes':2048}})
    repo=q.CalibrationRepository(store);repo.directory.mkdir(mode=0o700);(repo.directory/OP).mkdir(mode=0o700);path=repo.directory/OP/'plan.json';path.write_text(json.dumps(plan,sort_keys=True));path.chmod(0o600)
    def guard(permit,current,before,target,*,case_name):
        # Explicit synthetic observation seam, never installed Root authority.
        assert permit['source_graph_sha256']=='a'*64 and before.running and target>=128 and case_name in permit['cases']
    s.calibration_guard=guard
    def settlement(permit,current,read,*,mutation_id):
        effect=p.owner_for(mutation_id).effect(current,mutation_id)
        assert read.running and read.assigned_bytes==read.configured_bytes==effect.target_bytes
    s.calibration_settlement_guard=settlement
    # Explicit pure injected Source/L ports; not installed native authority.
    s.calibration_assess_settled=lambda permit,current,*,mutation_id:None
    class Runner:
        fault=None
        def __init__(self):self.calls=[]
        def run(self,argv,**kw):
            self.calls.append(tuple(argv));assert p.claim(argv[1])[0]==b.tool
            effect=p.effect(store.load(),argv[1]);before=b.rows[effect.vm_id]
            b.rows[effect.vm_id]=replace(before,assigned_bytes=effect.target_bytes,configured_bytes=effect.target_bytes,revision='revision-'+str(effect.target_bytes))
            if self.fault=='crash':raise SystemExit(77)
            if self.fault=='timeout':raise m.ResourceError('native_timeout','synthetic server reply lost')
            return 'synthetic synchronous return'
    r=Runner();p.runner=r;service=q.NativeQualificationService(c.policy,store,p,operation_id=OP)
    return q,n,m,c,b,store,e,p,s,r,service,raw,plan


def test_idle_effect_preserves_literal_v3_without_fabricated_resource_request(tmp_path):
    q,n,m,c,b,store,e,p,s,r,v,raw,plan=calibration(tmp_path);result=v.run_case('idle-shrink')
    assert result['status']=='READBACK_CONFIRMED'and result['native_qualification']=='NOT_MEASURED'
    assert store.state_path.read_bytes()==raw and store.load()['receipts']==[] and c._load()['startups']['vm-a']['phase']=='running_quarantined'
    mid=result['mutation_id'];owner=p.owner_for(mid);assert isinstance(owner,q.CalibrationEffectOwner)
    assert p.read(mid)['phase']=='RETURNED_SUCCESS'and len(r.calls)==1 and b.rows['vm-a'].assigned_bytes==128
    assert set(p.dispatch(mid))=={'schema','intent','worker_birth'}
    intent=p.dispatch(mid)['intent'];assert (intent['operation'],intent['old_bytes'],intent['target_bytes'],intent['before_revision'])==('shrink',2048,128,'revision-1')
    assert 'workload_bytes'not in json.dumps(owner.record)


def test_noop_has_no_mutation_owner_claim_or_transition_pass(tmp_path):
    q,n,m,c,b,store,e,p,s,r,v,raw,plan=calibration(tmp_path);result=v.run_case('idle-grow')
    assert result['status']=='NO_OP'and result['mutation_id']is None and result['native_qualification']=='NOT_MEASURED'
    assert r.calls==[]and store.state_path.read_bytes()==raw and not list(p.directory.glob('*.owner.json'))


def test_production_owner_default_preserves_existing_phase_rules(tmp_path):
    n,m,c,b,store,e,p,s,r,profiles=production_fixture(tmp_path);req=__import__('test_host_resource_operations').request(m)
    c.request(req,e);c.grow(req.request_id,e);mid=store.load()['receipts'][0]['mutation_id']
    assert isinstance(p.owner_for(mid),n.ProductionEffectOwner)and p.read(mid)['phase']=='RETURNED_SUCCESS'and len(r.calls)==1


@pytest.mark.parametrize('fault',['unknown','wrong-hash','symlink'])
def test_owner_selector_corruption_never_falls_back(tmp_path,fault):
    q,n,m,c,b,store,e,p,s,r,v,raw,plan=calibration(tmp_path);mid=v.prepare_case('idle-shrink')['mutation_id'];path=p.owner_path(mid)
    if fault=='symlink':path.unlink();path.symlink_to('absent.json')
    else:
        doc=store._read(path);doc['kind'if fault=='unknown'else'effect_sha256']='unknown'if fault=='unknown'else'0'*64;store._atomic(path,json.dumps(doc).encode())
    with pytest.raises((m.ResourceError,OSError,ValueError)):p.owner_for(mid)
    assert r.calls==[]and store.state_path.read_bytes()==raw


def test_unmeasured_installed_guard_cannot_expose_operational_resize(tmp_path):
    q,n,m,c,b,store,e,p,s,r,v,raw,plan=calibration(tmp_path);del s.calibration_guard
    with pytest.raises(m.ResourceError,match='qualification_observations_required'):v.run_case('idle-shrink')
    assert r.calls==[]and store.state_path.read_bytes()==raw


@pytest.mark.parametrize('drift',['grant','policy','binding','quarantine','receipts'])
def test_baseline_or_full_charge_drift_refuses_before_native(tmp_path,drift):
    q,n,m,c,b,store,e,p,s,r,v,raw,plan=calibration(tmp_path);state=store.load()
    if drift=='grant':state['grants'][0]['guest_bytes']-=64
    if drift=='policy':state['policy_sha256']='0'*64
    if drift=='binding':state['bindings']['vm-a']['guest_boot_id']='other'
    if drift=='quarantine':state['startups']['vm-a']['phase']='binding_ready'
    if drift=='receipts':state['receipts']=[{}]
    store.save(state);changed=store.state_path.read_bytes()
    with pytest.raises((m.ResourceError,TypeError,KeyError)):v.run_case('idle-shrink')
    assert store.state_path.read_bytes()==changed and r.calls==[]


@pytest.mark.parametrize('fault',['timeout','crash'])
def test_unknown_keeps_original_fence_charge_and_prevents_replay(tmp_path,fault):
    q,n,m,c,b,store,e,p,s,r,v,raw,plan=calibration(tmp_path);r.fault=fault
    with pytest.raises((m.ResourceError,SystemExit)):v.run_case('idle-shrink')
    assert len(r.calls)==1 and store.state_path.read_bytes()==raw
    with pytest.raises(m.ResourceError):v.run_case('idle-shrink')
    with pytest.raises(m.ResourceError):v.reconcile()
    assert len(r.calls)==1 and store.state_path.read_bytes()==raw
    with pytest.raises(m.ResourceError,match='calibration_active'):q.require_no_active_calibration(store)


def test_terminal_witness_then_readback_failure_reconciles_same_uuid(tmp_path,monkeypatch):
    q,n,m,c,b,store,e,p,s,r,v,raw,plan=calibration(tmp_path);original=v.repository.record_readback
    monkeypatch.setattr(v.repository,'record_readback',lambda *a,**k:(_ for _ in ()).throw(OSError('synthetic fsync')))
    with pytest.raises(OSError):v.run_case('idle-shrink')
    assert len(r.calls)==1;monkeypatch.setattr(v.repository,'record_readback',original)
    assert v.reconcile()['status']=='READBACK_CONFIRMED'and len(r.calls)==1 and store.state_path.read_bytes()==raw
    with pytest.raises(m.ResourceError):v.run_case('idle-shrink')


def test_fence_blocks_production_guard_and_bind_without_paid_write(tmp_path):
    q,n,m,c,b,store,e,p,s,r,v,raw,plan=calibration(tmp_path);v.prepare_case('idle-shrink')
    with pytest.raises(m.ResourceError,match='calibration_active'):c._guard(store.load(),e)
    import host_resource_startup as startup
    with pytest.raises(m.ResourceError,match='calibration_active'):startup.StartupManager(c.policy,store,b).bind_running_startup(e.bindings[0].native_id,e)
    assert store.state_path.read_bytes()==raw


def test_wrong_actual_worker_refuses_preexec_claim(tmp_path):
    q,n,m,c,b,store,e,p,s,r,v,raw,plan=calibration(tmp_path);mid=v.prepare_case('idle-shrink')['mutation_id']
    effect=p.effect(store.load(),mid);intent=p.intent(effect,store.load(),b.rows['vm-a'])
    p.exclusive(p.dispatch_path(mid),dict(schema='qcl.host-resource-native-dispatch.v1',intent=asdict(intent),worker_birth=dict(pid=999,start_ticks=1,boot_id=e.host_boot_id)))
    with pytest.raises(m.ResourceError,match='native_owner'):p.claim(mid)
    assert store.state_path.read_bytes()==raw


def test_owner_publication_failure_retains_fence_and_refuses_adoption(tmp_path,monkeypatch):
    q,n,m,c,b,store,e,p,s,r,v,raw,plan=calibration(tmp_path);original=p.exclusive
    def failure(path,doc):
        if str(path).endswith('.owner.json'):raise OSError('synthetic owner fsync failure')
        return original(path,doc)
    monkeypatch.setattr(p,'exclusive',failure)
    with pytest.raises(OSError):v.prepare_case('idle-shrink')
    with pytest.raises(m.ResourceError):v.prepare_case('idle-shrink')
    assert store.state_path.read_bytes()==raw and r.calls==[]


@pytest.mark.parametrize('field,value',[('native_id','other'),('process_id','999'),('config_fingerprint','other'),('vm_id','other')])
def test_reconcile_rejects_new_native_identity_even_at_exact_target(tmp_path,monkeypatch,field,value):
    q,n,m,c,b,store,e,p,s,r,v,raw,plan=calibration(tmp_path)
    original=v.repository.record_readback
    monkeypatch.setattr(v.repository,'record_readback',lambda *a:(_ for _ in ()).throw(OSError('readback not published')))
    with pytest.raises(OSError):v.run_case('idle-shrink')
    monkeypatch.setattr(v.repository,'record_readback',original)
    b.rows['vm-a']=replace(b.rows['vm-a'],**{field:value})
    with pytest.raises(m.ResourceError,match='identity_mismatch'):v.reconcile()
    assert len(r.calls)==1 and store.state_path.read_bytes()==raw


@pytest.mark.parametrize('fault',['empty','wrong-effect','wrong-target'])
def test_existing_readback_must_rejoin_original_effect_before_next_case(tmp_path,fault):
    q,n,m,c,b,store,e,p,s,r,v,raw,plan=calibration(tmp_path)
    result=v.run_case('idle-shrink');path=v.repository.readback_path(OP,result['mutation_id'])
    doc=store._read(path)
    if fault=='empty':doc={}
    if fault=='wrong-effect':doc['effect_sha256']='0'*64
    if fault=='wrong-target':doc['readback']['assigned_bytes']+=64
    store._atomic(path,json.dumps(doc).encode())
    with pytest.raises(m.ResourceError):v.prepare_case('idle-grow')
    assert len(r.calls)==1 and store.state_path.read_bytes()==raw


def test_new_record_ancestry_is_synced_before_native_authority(tmp_path,monkeypatch):
    q,n,m,c,b,store,e,p,s,r,v,raw,plan=calibration(tmp_path);synced=[]
    original=store._sync_directory
    def sync(path):synced.append(Path(path));return original(path)
    monkeypatch.setattr(store,'_sync_directory',sync)
    v.prepare_case('idle-shrink')
    assert v.repository.folder(OP) in synced
    assert v.repository.folder(OP)/'cases' in synced and v.repository.folder(OP)/'effects' in synced
    assert r.calls==[] and store.state_path.read_bytes()==raw


def test_terminal_cannot_substitute_original_before_revision(tmp_path,monkeypatch):
    q,n,m,c,b,store,e,p,s,r,v,raw,plan=calibration(tmp_path);original=v.repository.record_readback
    monkeypatch.setattr(v.repository,'record_readback',lambda *a:(_ for _ in ()).throw(OSError('readback not published')))
    with pytest.raises(OSError):v.run_case('idle-shrink')
    monkeypatch.setattr(v.repository,'record_readback',original)
    marker=v.repository.read(v.repository.case_path(OP,'idle-shrink'));mid=marker['mutation_id']
    witness=p.read(mid);witness['intent']['before_revision']='different-original'
    witness['intent_sha256']=__import__('host_resource_backends').fingerprint(witness['intent'])
    dispatch=p.dispatch(mid);dispatch['intent']=witness['intent']
    store._atomic(p.path(mid),json.dumps(witness).encode());store._atomic(p.dispatch_path(mid),json.dumps(dispatch).encode())
    with pytest.raises(m.ResourceError,match='cleanup_evidence'):v.reconcile()
    assert len(r.calls)==1 and store.state_path.read_bytes()==raw



def test_public_ingress_is_fenced_before_resolve_or_facts_side_effect(tmp_path):
    q,n,m,c,b,store,e,p,s,r,v,raw,plan=calibration(tmp_path);v.prepare_case('idle-shrink')
    from host_resource_service import NativeResourceService
    from host_resource_client import NativeWorkloadRef
    class Provider:
        def resolve(self,*a):pytest.fail('fenced public ingress reached provider')
    result=NativeResourceService(c,Provider()).reconcile_native(NativeWorkloadRef('slurm_allocation','42'))
    assert result['failure_code']=='calibration_active'
    assert store.state_path.read_bytes()==raw and r.calls==[]


@pytest.mark.parametrize('boundary',['fence','case','effect','owner','dispatch','claim','terminal','readback'])
def test_original_durable_boundary_failure_retains_fence_and_never_replays(tmp_path,monkeypatch,boundary):
    q,n,m,c,b,store,e,p,s,r,v,raw,plan=calibration(tmp_path)
    repo_exclusive=v.repository.exclusive;proof_exclusive=p.exclusive;atomic=store._atomic
    def selected(path):
        path=Path(path)
        return {'fence':path.name=='active.json','case':path.name=='idle-shrink.json',
            'effect':path.parent.name=='effects'and path.name.endswith('.json')and not path.name.endswith('.readback.json'),
            'owner':path.name.endswith('.owner.json'),'dispatch':path.name.endswith('.intent.json'),
            'claim':path.parent==p.directory and path.suffix=='.json'and '.'not in path.stem,
            'terminal':path.parent==p.directory,'readback':path.name.endswith('.readback.json')}[boundary]
    def wrap(function):
        def publication(path,value):
            result=function(path,value)
            if boundary!='terminal'and selected(path):raise OSError('synthetic original publication/fsync interruption '+boundary)
            return result
        return publication
    # Each wrapper is local to the original repository/worker, with real files;
    # no replacement native command or replay is introduced for recovery.
    monkeypatch.setattr(v.repository,'exclusive',wrap(repo_exclusive))
    monkeypatch.setattr(p,'exclusive',wrap(proof_exclusive))
    if boundary=='terminal':
        def terminal(path,value):
            result=atomic(path,value)
            if selected(path):raise OSError('synthetic terminal file fsync interruption')
            return result
        monkeypatch.setattr(store,'_atomic',terminal)
    with pytest.raises(OSError):v.run_case('idle-shrink')
    calls=len(r.calls);assert calls<=1 and store.state_path.read_bytes()==raw
    monkeypatch.setattr(v.repository,'exclusive',repo_exclusive);monkeypatch.setattr(p,'exclusive',proof_exclusive);monkeypatch.setattr(store,'_atomic',atomic)
    if boundary!='fence':
        with pytest.raises(m.ResourceError):v.run_case('idle-shrink')
    # A fence-only interruption has not allocated a mutation UUID. It remains
    # closed with no inferred result; there is no original native effect to replay.
    assert len(r.calls)==calls and store.state_path.read_bytes()==raw
    with pytest.raises(m.ResourceError,match='calibration_active'):q.require_no_active_calibration(store)
    if boundary=='terminal':assert v.reconcile()['status']=='READBACK_CONFIRMED'
    elif boundary!='readback':
        with pytest.raises((m.ResourceError,OSError)):v.reconcile()
    assert len(r.calls)==calls and store.state_path.read_bytes()==raw


@pytest.mark.parametrize('fault',['unknown','missing','wrong-effect'])
def test_terminal_proof_reselects_original_calibration_owner(tmp_path,fault):
    q,n,m,c,b,store,e,p,s,r,v,raw,plan=calibration(tmp_path)
    result=v.run_case('idle-shrink');mid=result['mutation_id'];owner=p.owner_for(mid)
    effect=owner.effect(store.load(),mid)
    if fault=='missing':p.owner_path(mid).unlink()
    else:
        doc=store._read(p.owner_path(mid));doc['kind' if fault=='unknown' else 'effect_sha256']='unknown' if fault=='unknown' else '0'*64
        store._atomic(p.owner_path(mid),json.dumps(doc).encode())
    with pytest.raises(m.ResourceError):p._proof(effect,store.load(),e)
    assert len(r.calls)==1 and store.state_path.read_bytes()==raw


def test_production_terminal_proof_cannot_ignore_present_invalid_selector(tmp_path):
    n,m,c,b,store,e,p,s,r,profiles=production_fixture(tmp_path)
    req=__import__('test_host_resource_operations').request(m)
    c.request(req,e);c.grow(req.request_id,e);state=store.load();mid=state['receipts'][0]['mutation_id']
    p.exclusive(p.owner_path(mid),{'kind':'unknown'})
    assert p.cleanup(req.request_id,owner_state=state,evidence=e) is None
    with pytest.raises(m.ResourceError):p.validate_state(state,evidence=e)


def test_existing_fence_is_resynced_before_new_effect_after_interruption(tmp_path,monkeypatch):
    q,n,m,c,b,store,e,p,s,r,v,raw,plan=calibration(tmp_path)
    v.repository.activate(OP,plan);original=v.repository.sync_record;seen=[]
    def sync(path):
        seen.append(Path(path))
        if Path(path).name=='active.json':raise OSError('original fence durability unavailable')
        return original(path)
    monkeypatch.setattr(v.repository,'sync_record',sync)
    with pytest.raises(OSError,match='original fence durability'):v.prepare_case('idle-shrink')
    assert v.repository.directory/'active.json' in seen
    assert not v.repository.case_path(OP,'idle-shrink').exists() and r.calls==[]
    assert store.state_path.read_bytes()==raw


def test_unknown_preserves_original_native_command_failure_without_paid_rewrite(tmp_path):
    q,n,m,c,b,store,e,p,s,r,v,raw,plan=calibration(tmp_path)
    original=r.run
    error=m.ResourceError('native_timeout','synthetic original server reply lost')
    error.native_argv=('/protected/native-exec','original-bound-uuid')
    error.native_output='original bounded output'
    error.native_record={'failure':'timeout','cleanup_confirmed':True,'stdout':'original bounded output','stderr':'original error','output_bytes':43,'output_truncated':False,'child_started':True,'returncode':-9,'elapsed_seconds':1}
    def timeout(argv,**kwargs):
        original(argv,**kwargs)
        raise error
    r.run=timeout
    with pytest.raises(m.ResourceError) as caught:v.run_case('idle-shrink')
    assert caught.value is error
    records=[store._read(path) for path in store.directory.glob('failure-*.json')]
    assert len(records)==1 and records[0]['command_record']==error.native_record
    assert records[0]['argv']==list(error.native_argv)
    assert store.state_path.read_bytes()==raw and len(r.calls)==1
    with pytest.raises(m.ResourceError):v.run_case('idle-shrink')
    assert len(r.calls)==1



def test_record_durability_rejects_same_bytes_named_inode_replacement(tmp_path,monkeypatch):
    q,n,m,c,b,store,e,p,s,r,v,raw,plan=calibration(tmp_path)
    path=v.repository.folder(OP)/'plan.json';original=q.os.fsync;replaced=[]
    def fsync(fd):
        if Path(q.os.readlink('/proc/self/fd/'+str(fd)))==path and not replaced:
            replacement=path.with_suffix('.replacement');replacement.write_bytes(path.read_bytes());replacement.chmod(0o600)
            q.os.replace(replacement,path);replaced.append(True)
        return original(fd)
    monkeypatch.setattr(q.os,'fsync',fsync)
    with pytest.raises(m.ResourceError,match='trust'):v.repository.sync_record(path)
    assert replaced and r.calls==[] and store.state_path.read_bytes()==raw



def test_fifo_owner_selector_refuses_without_waiting_for_a_writer(tmp_path):
    import multiprocessing
    q,n,m,c,b,store,e,p,s,r,v,raw,plan=calibration(tmp_path)
    mid=v.prepare_case('idle-shrink')['mutation_id'];path=p.owner_path(mid);path.unlink();q.os.mkfifo(path,0o600)
    ctx=multiprocessing.get_context('fork');result=ctx.Queue()
    def read_owner():
        try:p.owner_for(mid)
        except (m.ResourceError,OSError,ValueError):result.put('refused')
        else:result.put('accepted')
    child=ctx.Process(target=read_owner);child.start();child.join(2)
    blocked=child.is_alive()
    if blocked:child.terminate();child.join(2)
    assert not blocked,'malformed FIFO owner selector blocked on open'
    assert child.exitcode==0 and result.get(timeout=1)=='refused'
    assert store.state_path.read_bytes()==raw and r.calls==[]


@pytest.mark.parametrize('boundary',['plan','fence','case','effect','owner','dispatch','claim','terminal','readback'])
def test_actual_file_fsync_fault_keeps_paid_baseline_and_original_dispatch(tmp_path,monkeypatch,boundary):
    q,n,m,c,b,store,e,p,s,r,v,raw,plan=calibration(tmp_path);original=q.os.fsync;failed=[]
    def fsync(fd):
        path=Path(q.os.readlink('/proc/self/fd/'+str(fd)))
        selected={'plan':path.name=='plan.json','fence':path.name=='active.json',
            'case':path.name=='idle-shrink.json','effect':path.parent.name=='effects' and not path.name.endswith('.readback.json'),
            'owner':path.name.endswith('.owner.json'),'dispatch':path.name.endswith('.intent.json'),
            'claim':path.parent==p.directory and path.suffix=='.json' and '.'not in path.stem,
            'terminal':path.name.startswith('.state-'),'readback':path.name.endswith('.readback.json')}[boundary]
        if selected and not failed:
            failed.append(str(path));raise OSError('actual fsync fault '+boundary)
        return original(fd)
    monkeypatch.setattr(q.os,'fsync',fsync)
    with pytest.raises(OSError,match='actual fsync fault'):v.run_case('idle-shrink')
    assert len(failed)==1 and store.state_path.read_bytes()==raw
    calls=len(r.calls);assert calls<=1
    monkeypatch.setattr(q.os,'fsync',original)
    if boundary not in {'plan','fence'}:
        with pytest.raises(m.ResourceError):v.run_case('idle-shrink')
    if boundary!='plan':
        with pytest.raises(m.ResourceError,match='calibration_active'):q.require_no_active_calibration(store)
    else:assert not (v.repository.directory/'active.json').exists()
    assert len(r.calls)==calls and store.state_path.read_bytes()==raw


@pytest.mark.parametrize('phase,extra',[('case',['idle-shrink']),('reconcile',[])])
def test_root_mutating_cli_uses_only_finite_private_dispatch(monkeypatch,phase,extra):
    import host_resource_qualification as q
    monkeypatch.setattr(q.os,'getuid',lambda:0);monkeypatch.setattr(q.os,'geteuid',lambda:0);monkeypatch.delenv('SUDO_UID',raising=False)
    calls=[]
    def dispatch(op,selected,case=None):
        calls.append((op,selected,case))
        raise q.ResourceError('qualification_observations_required','actual protected runtime absent')
    monkeypatch.setattr(q,'dispatch_calibration_worker',dispatch)
    with pytest.raises(q.ResourceError,match='qualification_observations_required'):q.admin_qualification_main([OP,phase,*extra])
    assert calls==[(OP,phase,extra[0] if extra else None)]
    with pytest.raises(q.ResourceError):q.admin_qualification_main([OP,'execute'])
    assert len(calls)==1


@pytest.mark.parametrize('uid,euid,sudo',[(1000,1000,None),(1000,0,None),(0,0,'1000')])
def test_calibration_admin_refuses_nonroot_or_client_sudo_origin(monkeypatch,uid,euid,sudo):
    import host_resource_qualification as q
    monkeypatch.setattr(q.os,'getuid',lambda:uid);monkeypatch.setattr(q.os,'geteuid',lambda:euid)
    if sudo is None:monkeypatch.delenv('SUDO_UID',raising=False)
    else:monkeypatch.setenv('SUDO_UID',sudo)
    with pytest.raises(q.ResourceError,match='root_required'):q.open_calibration(OP)
    monkeypatch.setattr(q,'open_calibration',lambda *args:pytest.fail('untrusted caller reached factory'))
    with pytest.raises(q.ResourceError,match='root_required'):q.admin_qualification_main([OP,'inspect'])


@pytest.mark.parametrize('action',['qualify','case','qualification-gate'])
def test_ordinary_public_action_cannot_route_calibration(action,monkeypatch):
    import host_resource_client as client
    import host_resource_service as service
    monkeypatch.setattr(service,'open_service',lambda:pytest.fail('private action reached service factory'))
    with pytest.raises(client.ResourceError,match='action'):service.dispatch(action,{'operation_id':OP,'case':'idle-shrink'})


def test_readonly_inspect_and_report_never_emit_candidate_or_rewrite_records(tmp_path):
    q,n,m,c,b,store,e,p,s,r,v,raw,plan=calibration(tmp_path)
    before={str(path.relative_to(store.directory)):path.read_bytes() for path in store.directory.rglob('*') if path.is_file()}
    assert v.inspect()['native_qualification']=='NOT_MEASURED'
    report=v.report();assert report['candidate'] is None and report['state']=='CALIBRATION_SOURCE_ONLY_NOT_QUALIFIED'
    after={str(path.relative_to(store.directory)):path.read_bytes() for path in store.directory.rglob('*') if path.is_file()}
    assert after==before and r.calls==[] and store.state_path.read_bytes()==raw


@pytest.mark.parametrize('fault',['remove','replace'])
def test_owner_selector_changed_during_actual_claim_cannot_return_native_argv(tmp_path,fault):
    q,n,m,c,b,store,e,p,s,r,v,raw,plan=calibration(tmp_path)
    mid=v.prepare_case('idle-shrink')['mutation_id'];state=store.load();effect=p.effect(state,mid)
    intent=p.intent(effect,state,b.rows['vm-a'])
    p.exclusive(p.dispatch_path(mid),dict(schema='qcl.host-resource-native-dispatch.v1',intent=asdict(intent),worker_birth=s.worker(intent.native_context)))
    original=s.claim_process
    def claim_process(context):
        value=original(context)
        if fault=='remove':p.owner_path(mid).unlink()
        else:store._atomic(p.owner_path(mid),b'{"kind":"unknown"}')
        return value
    s.claim_process=claim_process
    with pytest.raises(m.ResourceError):p.claim(mid)
    assert b.rows['vm-a'].assigned_bytes==2048 and store.state_path.read_bytes()==raw and r.calls==[]



def test_same_semantics_effect_revision_change_during_claim_is_not_original_owner(tmp_path):
    q,n,m,c,b,store,e,p,s,r,v,raw,plan=calibration(tmp_path)
    mid=v.prepare_case('idle-shrink')['mutation_id'];state=store.load();effect=p.effect(state,mid)
    intent=p.intent(effect,state,b.rows['vm-a'])
    p.exclusive(p.dispatch_path(mid),dict(schema='qcl.host-resource-native-dispatch.v1',intent=asdict(intent),worker_birth=s.worker(intent.native_context)))
    original=s.claim_process
    def claim_process(context):
        value=original(context);path=v.repository.effect_path(OP,mid)
        store._atomic(path,json.dumps(v.repository.read(path),indent=2).encode())
        selector=store._read(p.owner_path(mid));selector['effect_sha256']=v.repository.digest(path)
        store._atomic(p.owner_path(mid),json.dumps(selector).encode())
        return value
    s.claim_process=claim_process
    with pytest.raises(m.ResourceError,match='effect_owner'):p.claim(mid)
    assert b.rows['vm-a'].assigned_bytes==2048 and store.state_path.read_bytes()==raw and r.calls==[]


@pytest.mark.parametrize('corruption',['malformed-null','full-null','missing-case','null-no-effect','null-no-owner','null-c-only'])
def test_original_effect_catalog_blocks_next_dispatch_despite_hidden_marker(tmp_path,corruption):
    q,n,m,c,b,store,e,p,s,r,v,raw,plan=calibration(tmp_path);r.fault='timeout'
    with pytest.raises(m.ResourceError,match='native_timeout'):v.run_case('idle-shrink')
    marker=v.repository.case_path(OP,'idle-shrink');original=v.repository.read(marker);mid=original['mutation_id']
    if corruption=='missing-case':marker.unlink()
    else:store._atomic(marker,json.dumps({'mutation_id':None}if corruption=='malformed-null'else{**original,'mutation_id':None}).encode())
    if corruption in {'null-no-effect','null-c-only'}:v.repository.effect_path(OP,mid).unlink()
    if corruption in {'null-no-owner','null-c-only'}:p.owner_path(mid).unlink()
    r.fault=None
    with pytest.raises((m.ResourceError,OSError,ValueError)):v.run_case('idle-grow')
    assert p.read(mid)['phase']=='CLAIMED' and len(r.calls)==1 and store.state_path.read_bytes()==raw
    assert (v.repository.directory/'active.json').exists()


@pytest.mark.parametrize('field,value',[('schema','unknown'),('operation_id','1b2f9137-3b02-4b3b-a38c-3cebb3a03f5c'),('case','idle-shrink'),('mutation_id','not-a-uuid')])
def test_noop_case_marker_requires_exact_original_identity_before_another_case(tmp_path,field,value):
    q,n,m,c,b,store,e,p,s,r,v,raw,plan=calibration(tmp_path)
    assert v.run_case('idle-grow')['status']=='NO_OP'
    path=v.repository.case_path(OP,'idle-grow');doc=v.repository.read(path);doc[field]=value
    store._atomic(path,json.dumps(doc).encode())
    with pytest.raises((m.ResourceError,OSError,ValueError)):v.run_case('idle-shrink')
    assert r.calls==[] and store.state_path.read_bytes()==raw


def test_genuine_noop_catalog_does_not_occupy_a_native_effect_slot(tmp_path):
    q,n,m,c,b,store,e,p,s,r,v,raw,plan=calibration(tmp_path)
    assert v.run_case('idle-grow')['status']=='NO_OP'
    assert v.run_case('idle-shrink')['status']=='READBACK_CONFIRMED'
    assert len(r.calls)==1 and store.state_path.read_bytes()==raw



def test_duplicate_case_mutation_catalog_refuses_prepared_effect_before_dispatch(tmp_path):
    q,n,m,c,b,store,e,p,s,r,v,raw,plan=calibration(tmp_path)
    mid=v.prepare_case('idle-shrink')['mutation_id'];state=store.load();effect=p.effect(state,mid)
    intent=p.intent(effect,state,b.rows['vm-a'])
    marker=dict(schema=q.CASE_SCHEMA,operation_id=OP,case='idle-grow',mutation_id=mid)
    v.repository.exclusive(v.repository.case_path(OP,'idle-grow'),marker)
    with pytest.raises(m.ResourceError,match='calibration_catalog'):p.execute(intent,timeout_seconds=30)
    assert r.calls==[] and store.state_path.read_bytes()==raw


def test_dangling_readback_catalog_cannot_release_a_native_slot(tmp_path):
    q,n,m,c,b,store,e,p,s,r,v,raw,plan=calibration(tmp_path)
    assert v.run_case('idle-grow')['status']=='NO_OP'
    v.repository.exclusive(v.repository.readback_path(OP,'f'*32),{})
    with pytest.raises(m.ResourceError,match='calibration_catalog'):v.run_case('idle-shrink')
    assert r.calls==[] and store.state_path.read_bytes()==raw


def test_unknown_case_file_cannot_hide_outside_frozen_plan_catalog(tmp_path):
    q,n,m,c,b,store,e,p,s,r,v,raw,plan=calibration(tmp_path)
    assert v.run_case('idle-grow')['status']=='NO_OP'
    path=v.repository.folder(OP)/'cases'/'unknown.json';v.repository.exclusive(path,{'mutation_id':None})
    with pytest.raises(m.ResourceError,match='calibration_catalog'):v.run_case('idle-shrink')
    assert r.calls==[] and store.state_path.read_bytes()==raw
