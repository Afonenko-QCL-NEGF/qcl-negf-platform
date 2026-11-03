"""Private worker-route Source/L; no systemd/native commands or root files."""
import base64
import copy
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_host_resource_qualification import calibration, OP
from test_host_resource_qualification_runtime import idle


def request(phase='case', case='idle-shrink', digest='a'*64):
    return dict(schema='qcl.host-resource-calibration-worker-request.v1',
        operation_id=OP, plan_sha256=digest, phase=phase,
        case=case if phase=='case' else None)


def noop_reply():
    return dict(schema='qcl.host-resource-calibration-worker-response.v1',
        operation_id=OP, plan_sha256='a'*64, phase='case', case='idle-shrink',
        status='NO_OP', mutation_id=None, native_outcome='NOT_DISPATCHED_OR_UNPROVEN',
        physical_status='NOT_MEASURED', native_qualification='NOT_MEASURED',
        receipt_ref=dict(kind='case', sha256='b'*64), native_ref=None,
        evidence_refs=[], failure_code=None, failure_detail=None, capture_error=None)


def test_private_request_is_strict_and_never_a_public_action():
    import host_resource_qualification as q
    from host_resource_client import decode_action
    assert q.decode_calibration_worker_request(request()) == request()
    assert q.decode_calibration_worker_request(request('reconcile'))['case'] is None
    for bad in ({**request(), 'allow':True}, {**request(),'case':None},
                {**request(),'plan_sha256':'A'*64}, {**request(),'phase':'execute'},
                {**request('reconcile'),'case':'idle-shrink'}):
        with pytest.raises(q.ResourceError): q.decode_calibration_worker_request(bad)
    with pytest.raises(q.ResourceError): decode_action('qualification', request())


@pytest.mark.parametrize('mutation', [
    {'operation_id':'00000000-0000-4000-8000-000000000001'},
    {'physical_status':'PASS'}, {'native_qualification':'PASS'},
    {'mutation_id':'1'*32}, {'receipt_ref':None}, {'native_outcome':'RETURNED_SUCCESS'},
    {'extra':True}, {'capture_error':'x'*4097}, {'status':[]},
    {'native_outcome':{}}, {'physical_status':[]},
])
def test_private_reply_rejects_foreign_or_fabricated_success(mutation):
    import host_resource_qualification as q
    assert q.decode_calibration_worker_response(noop_reply(), request()) == noop_reply()
    with pytest.raises(q.ResourceError):
        q.decode_calibration_worker_response({**noop_reply(), **mutation}, request())


def test_worker_private_branch_precedes_public_decoder_without_opening_public(monkeypatch):
    import host_resource_service as service
    import host_resource_qualification as q
    config=dict(schema='qcl.host-resource-service.v1',role='native_host',client_uid=3000)
    monkeypatch.setattr(service.os,'geteuid',lambda:0)
    monkeypatch.setattr(service,'read_root_json',lambda _:config)
    result=noop_reply()
    monkeypatch.setattr(q,'calibration_worker_main',lambda document:result,raising=False)
    token=base64.urlsafe_b64encode(json.dumps(request()).encode()).decode()
    assert service.root_main('worker',['qualification',token]) == result
    with pytest.raises(service.ResourceError): service.dispatch('qualification',request())


@pytest.mark.parametrize('phase',['case','reconcile'])
def test_changed_plan_pin_fails_before_case_or_pending_selection(tmp_path, phase):
    q,n,m,c,b,store,e,p,s,r,parent,raw,plan=calibration(tmp_path)
    with pytest.raises(m.ResourceError, match='calibration_plan_changed'):
        if phase=='case':parent.run_case('idle-shrink',expected_plan_sha256='0'*64)
        else:parent.reconcile(expected_plan_sha256='0'*64)
    assert r.calls == [] and not parent.repository.case_path(OP,'idle-shrink').exists()
    assert store.state_path.read_bytes() == raw


def installed_boundary(idle, monkeypatch, *, main_pid=None, role='native_host'):
    """Only OS/root factory boundaries substituted; idle runtime/engine are real."""
    import host_resource_qualification as q
    import host_resource_qualification_runtime as runtime
    import host_resource_service as service
    import host_resource_facts as facts
    import host_resource_backends as backends
    idle.stage(); actual=runtime.open_native_runtime(idle.service)
    idle.attach(actual);idle.s.idle_qualification_runtime=actual
    own=os.getpid(); parent=os.getppid();unit='qcl-resource-'+'1'*32+'.service'
    scope='/system.slice/'+unit
    config=dict(schema='qcl.host-resource-service.v1',role=role,client_uid=3000,
        systemctl='/protected/systemctl',systemd_run='/protected/systemd-run',
        worker_helper='/protected/worker')
    class Local:
        def __init__(self,*args):pass
        def process(self,pid):
            return dict(pid=pid,ppid=parent,start_ticks=10 if pid==own else 9,
                uids=[0]*4,cgroup=scope,executable='/protected/python')
        def host(self):return {'boot_id':idle.e.host_boot_id}
        def run(self,argv):
            assert argv[:3] == ['/protected/systemctl','show',unit]
            values=dict(LoadState='loaded',ActiveState='active',MainPID=str(own if main_pid is None else main_pid),
                ControlGroup=scope,InvocationID='2'*32)
            return '\n'.join(k+'='+values[k] for k in values)
    monkeypatch.setattr(service.os,'getuid',lambda:0)
    monkeypatch.setattr(service.os,'geteuid',lambda:0)
    monkeypatch.setattr(backends.os,'geteuid',lambda:0)
    monkeypatch.delenv('SUDO_UID',raising=False)
    monkeypatch.setattr(service,'read_root_json',lambda _:config)
    monkeypatch.setattr(facts,'LocalSources',Local)
    monkeypatch.setattr(q,'open_calibration',lambda op:idle.parent)
    digest=idle.parent.repository.digest(idle.parent.repository.folder(OP)/'plan.json')
    return q,request(digest=digest),config


def test_real_idle_runtime_noop_uses_original_marker_without_mutation(idle,monkeypatch):
    q,doc,config=installed_boundary(idle,monkeypatch);doc['case']='idle-grow'
    result=q.calibration_worker_main(doc)
    assert result['status']=='NO_OP' and result['mutation_id'] is None
    assert result['receipt_ref']['kind']=='case' and result['native_ref'] is None
    assert result['native_qualification']==result['physical_status']=='NOT_MEASURED'
    assert idle.r.calls==[] and idle.store.state_path.read_bytes()==idle.raw


def test_non_mainpid_worker_refuses_before_any_case_or_C(idle,monkeypatch):
    q,doc,config=installed_boundary(idle,monkeypatch,main_pid=os.getpid()+100000)
    result=q.calibration_worker_main(doc)
    assert result['status']=='HOLD' and result['failure_code']=='native_owner'
    assert idle.r.calls==[] and not idle.parent.repository.case_path(OP,'idle-shrink').exists()


def test_native_success_physical_refusal_keeps_original_fact_and_refs(idle,monkeypatch):
    q,doc,config=installed_boundary(idle,monkeypatch)
    original=idle.r.run
    def run(argv,**kwargs):
        result=original(argv,**kwargs);idle.pairs['vm-a']['memory']['MemAvailable']=0
        return result
    idle.r.run=run
    result=q.calibration_worker_main(doc)
    assert result['status']=='HOLD' and result['failure_code']=='calibration_physical'
    assert result['native_outcome']=='RETURNED_SUCCESS' and result['physical_status']=='FAIL'
    assert result['receipt_ref']['kind']=='readback' and result['native_ref'] is not None
    assert result['evidence_refs'] and len(idle.r.calls)==1
    assert idle.p.read(result['mutation_id'])['phase']=='RETURNED_SUCCESS'
    assert idle.store.state_path.read_bytes()==idle.raw


def test_admin_dispatches_only_worker_and_rechecks_original_noop(idle,monkeypatch):
    q,doc,config=installed_boundary(idle,monkeypatch);calls=[]
    import host_resource_service as service
    def command(argv,**kwargs):
        calls.append(tuple(argv));assert argv[-2]=='qualification'
        packet=service.decode_token(argv[-1]);assert packet['case']=='idle-grow'
        return json.dumps(q.calibration_worker_main(packet))
    monkeypatch.setattr(service.engine,'command',command)
    result=q.admin_qualification_main([OP,'case','idle-grow'])
    assert result['status']=='NO_OP' and result['receipt_ref']['kind']=='case'
    assert len(calls)==1 and idle.r.calls==[]
    assert calls[0][0:4]==('/protected/systemd-run','--quiet','--wait','--pipe')
    assert idle.store.state_path.read_bytes()==idle.raw


def test_worker_requires_actual_runtime_before_case_or_native(idle,monkeypatch):
    q,doc,config=installed_boundary(idle,monkeypatch)
    del idle.s.idle_qualification_runtime
    result=q.calibration_worker_main(doc)
    assert result['status']=='HOLD' and result['failure_code']=='qualification_observations_required'
    assert not idle.parent.repository.case_path(OP,'idle-shrink').exists() and idle.r.calls==[]


def test_worker_success_is_readback_not_persisted_physical_pass(idle,monkeypatch):
    q,doc,config=installed_boundary(idle,monkeypatch)
    result=q.calibration_worker_main(doc)
    assert result['status']=='READBACK_CONFIRMED' and result['native_outcome']=='RETURNED_SUCCESS'
    assert result['physical_status']==result['native_qualification']=='NOT_MEASURED'
    assert result['receipt_ref']['kind']=='readback' and len(idle.r.calls)==1


def test_new_worker_reconciles_only_original_context_without_second_C(idle,monkeypatch):
    q,doc,config=installed_boundary(idle,monkeypatch)
    original=idle.parent.repository.record_readback
    monkeypatch.setattr(idle.parent.repository,'record_readback',lambda *a:(_ for _ in ()).throw(OSError('original fsync fault')))
    first=q.calibration_worker_main(doc)
    assert first['status']=='HOLD' and first['native_outcome']=='RETURNED_SUCCESS'
    assert first['receipt_ref'] is None and first['physical_status']=='NOT_MEASURED'
    mid=first['mutation_id'];original_context=copy.deepcopy(idle.p.dispatch(mid))
    monkeypatch.setattr(idle.parent.repository,'record_readback',original)
    monkeypatch.setattr(idle.s,'context',lambda *a:pytest.fail('new worker substituted original context'))
    second=q.calibration_worker_main(request('reconcile',digest=doc['plan_sha256']))
    assert second['status']=='READBACK_CONFIRMED' and second['mutation_id']==mid
    assert idle.p.dispatch(mid)==original_context and len(idle.r.calls)==1
    third=q.calibration_worker_main(request('reconcile',digest=doc['plan_sha256']))
    assert third['status']=='HOLD' and third['failure_code']=='calibration_pending' and len(idle.r.calls)==1


def test_prepared_slot_cannot_be_dispatched_by_reconcile(idle,monkeypatch):
    q,doc,config=installed_boundary(idle,monkeypatch)
    mid=idle.parent.prepare_case('idle-shrink')['mutation_id']
    result=q.calibration_worker_main(request('reconcile',digest=doc['plan_sha256']))
    assert result['status']=='HOLD' and result['mutation_id']==mid
    assert idle.r.calls==[] and not idle.p.dispatch_path(mid).exists()


def test_private_io_reply_keeps_bounded_original_primary(idle,monkeypatch):
    q,doc,config=installed_boundary(idle,monkeypatch)
    monkeypatch.setattr(idle.parent.repository,'record_readback',lambda *a:(_ for _ in ()).throw(OSError('original fsync boundary failed')))
    result=q.calibration_worker_main(doc)
    assert result['status']=='HOLD' and result['native_outcome']=='RETURNED_SUCCESS'
    assert result['failure_detail']==dict(type='OSError',message='original fsync boundary failed',truncated=False)
    assert len(idle.r.calls)==1


def test_secondary_readback_hash_failure_keeps_genuine_native_success(idle,monkeypatch):
    q,doc,config=installed_boundary(idle,monkeypatch);original_run=idle.r.run
    def run(*args,**kwargs):
        value=original_run(*args,**kwargs);idle.pairs['vm-a']['memory']['MemAvailable']=0
        return value
    idle.r.run=run;digest=idle.parent.repository.digest
    def failed_digest(path):
        if str(path).endswith('.readback.json'):raise OSError('secondary exact hash unavailable')
        return digest(path)
    monkeypatch.setattr(idle.parent.repository,'digest',failed_digest)
    result=q.calibration_worker_main(doc)
    assert result['status']=='HOLD' and result['native_outcome']=='RETURNED_SUCCESS'
    assert result['physical_status']=='FAIL' and result['capture_error']
    assert result['receipt_ref'] is None and len(idle.r.calls)==1
    assert idle.p.read(result['mutation_id'])['phase']=='RETURNED_SUCCESS'


def test_admin_authenticates_genuine_success_even_without_wire_native_ref(idle,monkeypatch):
    q,doc,config=installed_boundary(idle,monkeypatch);original_run=idle.r.run
    def run(*args,**kwargs):
        value=original_run(*args,**kwargs);idle.pairs['vm-a']['memory']['MemAvailable']=0
        return value
    idle.r.run=run;original=q._worker_native_ref;proof_calls=[]
    def proof(*args):
        proof_calls.append(args[1])
        if len(proof_calls)==1:raise OSError('secondary witness read unavailable')
        return original(*args)
    monkeypatch.setattr(q,'_worker_native_ref',proof)
    result=q.calibration_worker_main(doc);mid=result['mutation_id']
    assert result['native_outcome']=='RETURNED_SUCCESS' and result['physical_status']=='FAIL'
    assert result['native_ref'] is result['receipt_ref'] is None and result['capture_error']=='OSError'
    witness=idle.p.path(mid).read_bytes()
    assert q._verify_worker_reply(idle.parent,doc,result) is result
    assert proof_calls==[mid,mid] and len(idle.r.calls)==1
    assert idle.p.path(mid).read_bytes()==witness and idle.store.state_path.read_bytes()==idle.raw


def test_admin_proof_failure_retains_original_worker_wire_without_replay(idle,monkeypatch):
    q,doc,config=installed_boundary(idle,monkeypatch);original_run=idle.r.run
    import host_resource_service as service
    def run(*args,**kwargs):
        value=original_run(*args,**kwargs);idle.pairs['vm-a']['memory']['MemAvailable']=0
        return value
    idle.r.run=run;calls=[];wire=[];witness=[]
    primary=OSError('secondary witness read unavailable')
    def unavailable(*args):raise primary
    monkeypatch.setattr(q,'_worker_native_ref',unavailable)
    def command(argv,**kwargs):
        calls.append(tuple(argv));result=q.calibration_worker_main(service.decode_token(argv[-1]))
        assert result['native_outcome']=='RETURNED_SUCCESS' and result['native_ref'] is None
        wire.append(json.dumps(result));witness.append(idle.p.path(result['mutation_id']).read_bytes())
        return wire[0]
    monkeypatch.setattr(service.engine,'command',command)
    with pytest.raises(OSError) as caught:q.admin_qualification_main([OP,'case','idle-shrink'])
    assert caught.value is primary
    assert primary.calibration_worker_output==wire[0] and primary.calibration_worker_request==doc
    result=json.loads(primary.calibration_worker_output)
    assert result['native_outcome']=='RETURNED_SUCCESS' and result['physical_status']=='FAIL'
    assert result['failure_code']=='calibration_physical' and result['failure_detail'] is not None
    assert idle.p.path(result['mutation_id']).read_bytes()==witness[0]
    assert len(calls)==len(idle.r.calls)==1 and idle.store.state_path.read_bytes()==idle.raw


def test_unjoined_terminal_json_cannot_create_a_new_success_claim(idle,monkeypatch):
    q,doc,config=installed_boundary(idle,monkeypatch)
    first=q.calibration_worker_main(doc);mid=first['mutation_id']
    assert first['status']=='READBACK_CONFIRMED'
    # Valid witness syntax with the same MID, but not the original effect.
    witness=idle.p.read(mid);witness['intent']['target_bytes']+=64
    witness['intent_sha256']=idle.n.fingerprint(witness['intent'])
    idle.store._atomic(idle.p.path(mid),json.dumps(witness).encode())
    result=q.calibration_worker_main(doc)
    assert result['status']=='HOLD' and result['native_outcome']=='UNKNOWN'
    assert result['native_ref'] is None and result['capture_error']
    assert len(idle.r.calls)==1


def test_failed_native_error_journal_preserves_original_exception(idle,monkeypatch):
    q,doc,config=installed_boundary(idle,monkeypatch);original_run=idle.r.run
    primary=idle.m.ResourceError('native_timeout','original native reply lost')
    primary.native_argv=('/protected/native-exec','original')
    primary.native_output='original bounded response'
    def run(*args,**kwargs):
        original_run(*args,**kwargs);raise primary
    idle.r.run=run
    monkeypatch.setattr(idle.store,'save_failure',lambda *a:(_ for _ in ()).throw(OSError('original error journal fsync fault')))
    with pytest.raises(idle.m.ResourceError) as caught:q.calibration_worker_main(doc)
    assert caught.value is primary and primary.native_log_error=='OSError'
    assert len(idle.r.calls)==1


def test_admin_rejects_foreign_reply_without_redispatch(idle,monkeypatch):
    q,doc,config=installed_boundary(idle,monkeypatch);calls=[]
    import host_resource_service as service
    def command(*args,**kwargs):calls.append(args);return json.dumps(noop_reply())
    monkeypatch.setattr(service.engine,'command',command)
    with pytest.raises(q.ResourceError,match='calibration_reply'):
        q.admin_qualification_main([OP,'case','idle-grow'])
    assert len(calls)==1 and idle.r.calls==[]


def test_private_main_never_converts_malformed_request_to_public_DTO(monkeypatch,capsys):
    import host_resource_service as service
    config=dict(schema='qcl.host-resource-service.v1',role='native_host',client_uid=3000)
    monkeypatch.setattr(service.os,'geteuid',lambda:0)
    monkeypatch.setattr(service,'read_root_json',lambda _:config)
    token=base64.urlsafe_b64encode(b'{"allow":true}').decode()
    monkeypatch.setattr(service.sys,'argv',['-c','qualification',token])
    with pytest.raises(service.ResourceError):service.main('worker')
    assert capsys.readouterr().out==''


@pytest.mark.parametrize('parent_pid',[101,999])
def test_native_claim_real_reader_requires_direct_original_worker(parent_pid,monkeypatch):
    import host_resource_native_cleanup as n
    unit='qcl-resource-'+'1'*32+'.service';scope='/system.slice/'+unit
    source=object.__new__(n.NativeCleanupSources)
    source.config={'systemctl':'/protected/systemctl'}
    def process(pid):return dict(pid=pid,start_ticks=pid,uids=[0]*4,cgroup=scope,ppid=parent_pid)
    values=dict(LoadState='loaded',ActiveState='active',MainPID='101',ControlGroup=scope,InvocationID='2'*32)
    source.local=SimpleNamespace(process=process,host=lambda:{'boot_id':'original-boot'},
        run=lambda argv:'\n'.join(k+'='+v for k,v in values.items()))
    monkeypatch.setattr(n,'os',SimpleNamespace(getpid=lambda:102))
    context=dict(unit=unit,cgroup=scope,invocation_id='2'*32)
    if parent_pid==101:
        worker,child=source.claim_process(context)
        assert worker==dict(pid=101,start_ticks=101,boot_id='original-boot')
        assert child==dict(pid=102,start_ticks=102,boot_id='original-boot')
    else:
        with pytest.raises(n.ResourceError,match='native_owner'):source.claim_process(context)
